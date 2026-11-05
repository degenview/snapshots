package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/degenview/snapshots/internal/auth"
	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/settings"
	"github.com/degenview/snapshots/internal/storage"
)

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if !s.Configured() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.page(w, r, http.StatusOK, "admin", pageData{Title: "Admin", Heading: "Admin", Scripts: []string{"admin.js"}})
}

// Sessions ----------------------------------------------------------------

func (s *Server) cookieName() string {
	if s.secure() {
		return "__Host-dvs_session"
	}
	return "dvs_session"
}

func (s *Server) setSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the https public URL; localhost dev is http
		Name: s.cookieName(), Value: value, Path: "/", HttpOnly: true, Secure: s.secure(),
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.sessions.Absolute / time.Second),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the https public URL
		Name: s.cookieName(), Value: "", Path: "/", HttpOnly: true, Secure: s.secure(),
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

type adminHandler func(w http.ResponseWriter, r *http.Request, sess repo.Session)

// admin wraps a handler so it only runs for a logged-in administrator and, for
// anything that changes state, a valid CSRF token.
func (s *Server) admin(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.Configured() {
			apiFail(w, http.StatusNotFound, "not_found", "Not found.")
			return
		}
		c, err := r.Cookie(s.cookieName())
		if err != nil {
			apiFail(w, http.StatusUnauthorized, "unauthorized", "Sign in required.")
			return
		}
		sess, err := s.sessions.Validate(r.Context(), c.Value)
		if errors.Is(err, auth.ErrInvalid) {
			s.clearSessionCookie(w)
			apiFail(w, http.StatusUnauthorized, "unauthorized", "Sign in required.")
			return
		} else if err != nil {
			s.internal(w, r, "validating session", err)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := auth.CheckCSRF(r, sess); err != nil {
				apiFail(w, http.StatusForbidden, "csrf", "Cross-site request rejected. Reload the page and try again.")
				return
			}
		}
		h(w, r, sess)
	}
}

type loginRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.Configured() {
		apiFail(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	if err := auth.CheckSameOrigin(r); err != nil {
		apiFail(w, http.StatusForbidden, "forbidden", "Cross-site request rejected.")
		return
	}
	if ok, wait := s.limLogin.Allow(clientKey(r)); !ok {
		tooMany(w, wait)
		return
	}
	var in loginRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	hash, err := s.repo.AdminHash(r.Context())
	if err != nil {
		s.internal(w, r, "reading admin", err)
		return
	}
	if len(in.Password) > 256 || !auth.VerifyPassword(in.Password, hash) {
		s.log.Warn("failed admin login", "id", requestID(r), "ip", clientKey(r))
		apiFail(w, http.StatusUnauthorized, "invalid_credentials", "Incorrect password.")
		return
	}
	cookie, sess, err := s.sessions.Create(r.Context())
	if err != nil {
		s.internal(w, r, "creating session", err)
		return
	}
	s.setSessionCookie(w, cookie)
	writeJSON(w, http.StatusOK, map[string]any{"csrf": sess.CSRF})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, sess repo.Session) {
	writeJSON(w, http.StatusOK, map[string]any{"csrf": sess.CSRF, "version": s.version})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		s.sessions.Destroy(r.Context(), c.Value)
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

type passwordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	var in passwordRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if ok, wait := s.limLogin.Allow(clientKey(r)); !ok {
		tooMany(w, wait)
		return
	}
	hash, err := s.repo.AdminHash(r.Context())
	if err != nil {
		s.internal(w, r, "reading admin", err)
		return
	}
	if len(in.Current) > 256 || !auth.VerifyPassword(in.Current, hash) {
		apiFail(w, http.StatusUnauthorized, "invalid_credentials", "The current password is incorrect.")
		return
	}
	if err := auth.ValidatePassword(in.New); err != nil {
		apiFail(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	newHash, err := auth.HashPassword(in.New)
	if err != nil {
		s.internal(w, r, "hashing password", err)
		return
	}
	if err := s.repo.SetAdminHash(r.Context(), newHash); err != nil {
		s.internal(w, r, "saving password", err)
		return
	}
	// A password change signs everyone out, including whoever knew the old one.
	if err := s.repo.DeleteAllSessions(r.Context()); err != nil {
		s.internal(w, r, "ending sessions", err)
		return
	}
	cookie, sess, err := s.sessions.Create(r.Context())
	if err != nil {
		s.internal(w, r, "creating session", err)
		return
	}
	s.setSessionCookie(w, cookie)
	s.log.Info("admin password changed", "id", requestID(r))
	writeJSON(w, http.StatusOK, map[string]any{"csrf": sess.CSRF})
}

// Overview and images -----------------------------------------------------

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	st := s.state.Load()
	stats, err := s.repo.ImageStats(r.Context())
	if err != nil {
		s.internal(w, r, "stats", err)
		return
	}
	toks, err := s.repo.ListTokens(r.Context())
	if err != nil {
		s.internal(w, r, "tokens", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.version, "images": stats.Images, "bytes": stats.Bytes, "tokens": len(toks),
		"storage_kind": st.set.StorageKind, "retention_days": st.set.RetentionDays,
		"max_total_bytes": st.set.MaxTotalBytes, "public_url": st.set.PublicURL,
		"upload_url": st.set.PublicURL + "/api/v1/images", "auth_required": st.set.AuthRequired,
	})
}

type imageView struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	Size      int64  `json:"size"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Token     string `json:"token,omitempty"`
}

const imagesPageSize = 24

func (s *Server) handleAdminImages(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 0 || page > 100000 {
		page = 0
	}
	imgs, err := s.repo.ListImages(r.Context(), imagesPageSize+1, page*imagesPageSize)
	if err != nil {
		s.internal(w, r, "listing images", err)
		return
	}
	more := len(imgs) > imagesPageSize
	if more {
		imgs = imgs[:imagesPageSize]
	}
	names := map[string]string{}
	if toks, err := s.repo.ListTokens(r.Context()); err == nil {
		for _, t := range toks {
			names[t.ID] = t.Name
		}
	}
	base := s.state.Load().set.PublicURL
	out := make([]imageView, 0, len(imgs))
	for _, i := range imgs {
		v := imageView{ID: i.ID, URL: base + "/i/" + i.ID, Size: i.Size, Width: i.Width, Height: i.Height,
			CreatedAt: i.CreatedAt.Format(time.RFC3339), Token: names[i.TokenID]}
		if !i.ExpiresAt.IsZero() {
			v.ExpiresAt = i.ExpiresAt.Format(time.RFC3339)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": out, "page": page, "has_more": more})
}

func (s *Server) handleAdminDeleteImage(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	id := r.PathValue("id")
	if !ids.ValidImageID(id) {
		apiFail(w, http.StatusNotFound, "not_found", "No such image.")
		return
	}
	img, err := s.repo.GetImage(r.Context(), id)
	if errors.Is(err, repo.ErrNotFound) {
		apiFail(w, http.StatusNotFound, "not_found", "No such image.")
		return
	} else if err != nil {
		s.internal(w, r, "loading image", err)
		return
	}
	if err := s.removeImage(r.Context(), img); err != nil {
		s.internal(w, r, "deleting image", err)
		return
	}
	s.log.Info("image deleted by admin", "id", requestID(r))
	w.WriteHeader(http.StatusNoContent)
}

// Tokens ------------------------------------------------------------------

type tokenView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	toks, err := s.repo.ListTokens(r.Context())
	if err != nil {
		s.internal(w, r, "listing tokens", err)
		return
	}
	out := make([]tokenView, 0, len(toks))
	for _, t := range toks {
		v := tokenView{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt.Format(time.RFC3339)}
		if !t.LastUsedAt.IsZero() {
			v.LastUsedAt = t.LastUsedAt.Format(time.RFC3339)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

type createTokenRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	var in createTokenRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	plain, rec, err := s.tokens.Issue(r.Context(), in.Name)
	if err != nil {
		s.internal(w, r, "creating token", err)
		return
	}
	s.log.Info("upload token created", "id", requestID(r), "token", rec.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"id": rec.ID, "name": rec.Name, "token": plain})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	id := r.PathValue("id")
	if !ids.ValidRandom(id, 10) {
		apiFail(w, http.StatusNotFound, "not_found", "No such token.")
		return
	}
	if err := s.repo.DeleteToken(r.Context(), id); errors.Is(err, repo.ErrNotFound) {
		apiFail(w, http.StatusNotFound, "not_found", "No such token.")
		return
	} else if err != nil {
		s.internal(w, r, "deleting token", err)
		return
	}
	s.log.Info("upload token revoked", "id", requestID(r), "token", id)
	w.WriteHeader(http.StatusNoContent)
}

// Settings ----------------------------------------------------------------

type settingsView struct {
	settingsInput
	S3SecretSet   bool  `json:"s3_secret_set"`
	CanSeal       bool  `json:"can_seal_secret"`
	StorageImages int64 `json:"storage_images"`
}

func (s *Server) viewOf(ctx context.Context, set settings.Settings) (settingsView, error) {
	v := settingsView{CanSeal: s.sets.CanSeal(), S3SecretSet: set.S3.SecretKey != ""}
	v.PublicURL, v.AuthRequired, v.RetentionDays = set.PublicURL, set.AuthRequired, set.RetentionDays
	v.MaxImageBytes, v.MaxTotalBytes = set.MaxImageBytes, set.MaxTotalBytes
	v.UploadsPerHour, v.ViewsPerMinute, v.StorageKind = set.UploadsPerHour, set.ViewsPerMinute, set.StorageKind
	v.S3 = s3Input{Endpoint: set.S3.Endpoint, Region: set.S3.Region, Bucket: set.S3.Bucket, AccessKey: set.S3.AccessKey,
		PathStyle: set.S3.PathStyle, Prefix: set.S3.Prefix} // never the secret
	n, err := s.repo.CountByStorage(ctx, set.StorageKind)
	v.StorageImages = n
	return v, err
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	v, err := s.viewOf(r.Context(), s.state.Load().set)
	if err != nil {
		s.internal(w, r, "reading settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	var in settingsInput
	if !decodeJSON(w, r, &in) {
		return
	}
	// Block uploads while a storage change is checked and applied (see Server.storeMu).
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	cur := s.state.Load().set
	next := in.toSettings(cur)
	if s.cfg.PublicURL != "" {
		next.PublicURL = s.cfg.PublicURL
	}
	if err := next.Validate(); err != nil {
		apiFail(w, http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	if next.StorageKind == storage.KindS3 && !s.sets.CanSeal() {
		apiFail(w, http.StatusBadRequest, "no_secret_key", settings.ErrNoSecretKey.Error())
		return
	}
	if !sameStorageLocation(cur, next) {
		// Images stay where they were written, so moving the storage would turn
		// every existing link into a 404.
		n, err := s.repo.CountByStorage(r.Context(), cur.StorageKind)
		if err != nil {
			s.internal(w, r, "counting images", err)
			return
		}
		if n > 0 {
			apiFail(w, http.StatusConflict, "storage_in_use", "The current storage still holds "+strconv.FormatInt(n, 10)+
				" images. Delete them (or wait for them to expire) before changing where images are stored.")
			return
		}
	}
	if !sameStorage(cur, next) {
		if res := s.testStorage(r.Context(), next); !res.OK {
			apiFail(w, http.StatusBadRequest, "storage_test_failed", "The storage test failed: "+res.Error)
			return
		}
	}
	saved, err := s.sets.Save(r.Context(), next)
	if err != nil {
		apiFail(w, http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	if err := s.apply(saved); err != nil {
		s.internal(w, r, "applying settings", err)
		return
	}
	s.log.Info("settings changed", "id", requestID(r))
	v, err := s.viewOf(r.Context(), saved)
	if err != nil {
		s.internal(w, r, "reading settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// sameStorageLocation is true when images written under cur remain readable
// under next: same backend and, for S3, same endpoint, bucket and prefix.
// (Changing only credentials or the region label is fine.)
func sameStorageLocation(cur, next settings.Settings) bool {
	if cur.StorageKind != next.StorageKind {
		return false
	}
	if cur.StorageKind == storage.KindS3 {
		return cur.S3.Endpoint == next.S3.Endpoint && cur.S3.Bucket == next.S3.Bucket && cur.S3.Prefix == next.S3.Prefix
	}
	return true
}

func (s *Server) handleAdminTestStorage(w http.ResponseWriter, r *http.Request, _ repo.Session) {
	var in settingsInput
	if !decodeJSON(w, r, &in) {
		return
	}
	cur := s.state.Load().set
	writeJSON(w, http.StatusOK, s.testStorage(r.Context(), in.toSettings(cur)))
}
