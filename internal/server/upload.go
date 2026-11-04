package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/degenview/snapshots/internal/auth"
	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/pngcheck"
	"github.com/degenview/snapshots/internal/repo"
)

type uploadResponse struct {
	URL       string `json:"url"`
	DeleteURL string `json:"delete_url"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// handleUpload implements POST /api/v1/images, the endpoint DegenView posts to.
// It never redirects: the client refuses to follow redirects.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	st := s.state.Load()
	if st == nil {
		apiFail(w, http.StatusServiceUnavailable, "not_configured", "This server has not been set up yet.")
		return
	}
	set := st.set

	// Throttle first, so credential guessing and junk uploads cost one bucket.
	if ok, wait := s.limUpload.Allow(clientKey(r)); !ok {
		tooMany(w, wait)
		return
	}

	var token repo.Token
	if set.AuthRequired {
		plain, ok := auth.BearerToken(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="snapshots"`)
			apiFail(w, http.StatusUnauthorized, "unauthorized", "An upload token is required (Authorization: Bearer <token>).")
			return
		}
		t, err := s.tokens.Authenticate(r.Context(), plain)
		if errors.Is(err, auth.ErrInvalid) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="snapshots", error="invalid_token"`)
			apiFail(w, http.StatusUnauthorized, "invalid_token", "The upload token is not valid.")
			return
		} else if err != nil {
			s.log.Error("token lookup failed", "id", requestID(r), "err", err)
			apiFail(w, http.StatusInternalServerError, "internal", "Internal error.")
			return
		}
		token = t
	}

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "image/png" {
		apiFail(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Send the image as Content-Type: image/png.")
		return
	}
	if r.ContentLength > set.MaxImageBytes {
		tooLarge(w, set.MaxImageBytes)
		return
	}

	select {
	case s.uploadSem <- struct{}{}:
		defer func() { <-s.uploadSem }()
	default:
		w.Header().Set("Retry-After", "2")
		apiFail(w, http.StatusServiceUnavailable, "busy", "The server is busy. Try again shortly.")
		return
	}

	extendDeadlines(w, 2*time.Minute)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, set.MaxImageBytes))
	if err != nil {
		var tb *http.MaxBytesError
		if errors.As(err, &tb) {
			tooLarge(w, set.MaxImageBytes)
		} else {
			apiFail(w, http.StatusBadRequest, "bad_request", "The upload was interrupted.")
		}
		return
	}

	clean, info, err := pngcheck.Sanitize(body, pngcheck.DefaultLimits)
	switch {
	case errors.Is(err, pngcheck.ErrDimensions):
		apiFail(w, http.StatusRequestEntityTooLarge, "image_too_large", "The image is larger than 8192 pixels a side or 32 megapixels.")
		return
	case err != nil:
		apiFail(w, http.StatusUnprocessableEntity, "invalid_image", "The body is not a valid PNG image.")
		return
	}

	if set.MaxTotalBytes > 0 {
		stats, err := s.repo.ImageStats(r.Context())
		if err != nil {
			s.log.Error("stats failed", "id", requestID(r), "err", err)
			apiFail(w, http.StatusInternalServerError, "internal", "Internal error.")
			return
		}
		if stats.Bytes+int64(len(clean)) > set.MaxTotalBytes {
			apiFail(w, http.StatusInsufficientStorage, "quota_exceeded", "The server's storage quota is full.")
			return
		}
	}

	now := s.now().UTC()
	img := repo.Image{Storage: st.store.Kind(), Size: int64(len(clean)), Width: int(info.Width), Height: int(info.Height),
		TokenID: token.ID, CreatedAt: now}
	if set.RetentionDays > 0 {
		img.ExpiresAt = now.AddDate(0, 0, set.RetentionDays)
	}
	secret, err := s.insertImage(r.Context(), &img)
	if err != nil {
		s.log.Error("storing image metadata failed", "id", requestID(r), "err", err)
		apiFail(w, http.StatusInternalServerError, "internal", "Internal error.")
		return
	}
	// Row first: if the object write fails or the process dies, the row simply
	// points at nothing (a 404) and the janitor removes it at expiry.
	if err := st.store.Put(r.Context(), img.ID, bytes.NewReader(clean), int64(len(clean))); err != nil {
		_ = s.repo.DeleteImage(context.WithoutCancel(r.Context()), img.ID)
		s.log.Error("storing image failed", "id", requestID(r), "storage", st.store.Kind(), "err", err)
		apiFail(w, http.StatusBadGateway, "storage_error", "The image could not be stored.")
		return
	}

	resp := uploadResponse{URL: set.PublicURL + "/i/" + img.ID, DeleteURL: set.PublicURL + "/d/" + secret}
	if !img.ExpiresAt.IsZero() {
		resp.ExpiresAt = img.ExpiresAt.Format(time.RFC3339)
	}
	s.log.Info("image uploaded", "id", requestID(r), "bytes", img.Size, "w", img.Width, "h", img.Height, "token", token.ID)
	writeJSON(w, http.StatusCreated, resp)
}

func tooLarge(w http.ResponseWriter, limit int64) {
	apiFail(w, http.StatusRequestEntityTooLarge, "payload_too_large", "The image is larger than "+humanBytes(limit)+".")
}

// insertImage picks a fresh id and delete secret and stores the row, retrying
// on the (astronomically unlikely) collision.
func (s *Server) insertImage(ctx context.Context, img *repo.Image) (secret string, err error) {
	for attempt := 0; attempt < 5; attempt++ {
		if img.ID, err = ids.ImageID(); err != nil {
			return "", err
		}
		if secret, err = ids.DeleteSecret(); err != nil {
			return "", err
		}
		img.DeleteHash = ids.Hash(secret)
		err = s.repo.CreateImage(ctx, *img)
		if !errors.Is(err, repo.ErrConflict) {
			return secret, err
		}
	}
	return "", err
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return itoa(n>>20) + " MiB"
	case n >= 1<<20:
		return itoa(n>>20) + "+ MiB"
	case n >= 1<<10:
		return itoa(n>>10) + " KiB"
	}
	return itoa(n) + " bytes"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
