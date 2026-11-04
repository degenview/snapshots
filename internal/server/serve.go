package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/storage"
)

func notFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "not found", http.StatusNotFound)
}

// handleImage serves GET|HEAD /i/{id}[.png]. Unknown, malformed and expired
// ids are indistinguishable.
func (s *Server) handleImage(w http.ResponseWriter, r *http.Request) {
	st := s.state.Load()
	if st == nil {
		notFound(w)
		return
	}
	if ok, wait := s.limView.Allow(clientKey(r)); !ok {
		tooMany(w, wait)
		return
	}
	id := strings.TrimSuffix(r.PathValue("id"), ".png")
	if !ids.ValidImageID(id) {
		notFound(w)
		return
	}
	img, err := s.repo.GetImage(r.Context(), id)
	if errors.Is(err, repo.ErrNotFound) || (err == nil && img.Expired(s.now())) {
		notFound(w)
		return
	}
	if err != nil {
		s.log.Error("image lookup failed", "id", requestID(r), "err", err)
		apiFail(w, http.StatusInternalServerError, "internal", "Internal error.")
		return
	}
	if img.Storage != st.store.Kind() {
		s.log.Error("image belongs to an inactive storage backend", "id", requestID(r), "storage", img.Storage)
		notFound(w)
		return
	}
	f, err := st.store.Open(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		notFound(w)
		return
	}
	if err != nil {
		s.log.Error("opening image failed", "id", requestID(r), "err", err)
		apiFail(w, http.StatusBadGateway, "storage_error", "The image could not be read.")
		return
	}
	defer f.Close()

	extendDeadlines(w, 2*time.Minute)
	h := w.Header()
	h.Set("Content-Type", "image/png")
	h.Set("Content-Disposition", `inline; filename="snapshot-`+id+`.png"`)
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("X-Robots-Tag", "noindex, noimageindex")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Cache-Control", cacheControl(img, s.now()))
	h.Set("ETag", `"`+id+`"`)
	http.ServeContent(w, r, "", img.CreatedAt, f)
}

// cacheControl lets shared caches keep an image for at most a day and never
// beyond its expiry, so deleting or expiring a snapshot takes effect promptly.
func cacheControl(img repo.Image, now time.Time) string {
	age := 24 * time.Hour
	if !img.ExpiresAt.IsZero() {
		if left := img.ExpiresAt.Sub(now); left < age {
			age = left
		}
	}
	if age < 0 {
		age = 0
	}
	return "public, max-age=" + strconv.Itoa(int(age/time.Second))
}

// Delete flow -------------------------------------------------------------

// lookupDelete resolves a delete secret to its image, or writes the response.
func (s *Server) lookupDelete(w http.ResponseWriter, r *http.Request) (repo.Image, bool) {
	if s.state.Load() == nil {
		s.page(w, r, http.StatusNotFound, "message", pageData{Title: "Not found", Heading: "Not found", Text: "This link does not exist."})
		return repo.Image{}, false
	}
	if ok, wait := s.limDelete.Allow(clientKey(r)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		s.page(w, r, http.StatusTooManyRequests, "message", pageData{Title: "Slow down", Heading: "Too many requests", Text: "Please try again in a minute."})
		return repo.Image{}, false
	}
	secret := r.PathValue("secret")
	missing := func() (repo.Image, bool) {
		s.page(w, r, http.StatusNotFound, "message", pageData{Title: "Not found", Heading: "Not found",
			Text: "This delete link is not valid. The snapshot may already be deleted or have expired."})
		return repo.Image{}, false
	}
	if !ids.ValidDeleteSecret(secret) {
		return missing()
	}
	img, err := s.repo.GetImageByDeleteHash(r.Context(), ids.Hash(secret))
	if errors.Is(err, repo.ErrNotFound) {
		return missing()
	}
	if err != nil {
		s.log.Error("delete lookup failed", "id", requestID(r), "err", err)
		s.page(w, r, http.StatusInternalServerError, "message", pageData{Title: "Error", Heading: "Something went wrong", Text: "Please try again."})
		return repo.Image{}, false
	}
	return img, true
}

// handleDeletePage shows a confirmation. Deleting needs a POST, so link
// previews and crawlers that fetch the URL cannot delete anything.
func (s *Server) handleDeletePage(w http.ResponseWriter, r *http.Request) {
	img, ok := s.lookupDelete(w, r)
	if !ok {
		return
	}
	data := pageData{Title: "Delete snapshot", Heading: "Delete this snapshot?"}
	if !img.Expired(s.now()) {
		data.ImageURL = "/i/" + img.ID
	}
	s.page(w, r, http.StatusOK, "delete", data)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	img, ok := s.lookupDelete(w, r)
	if !ok {
		return
	}
	if err := s.removeImage(r.Context(), img); err != nil {
		s.log.Error("delete failed", "id", requestID(r), "err", err)
		s.page(w, r, http.StatusBadGateway, "message", pageData{Title: "Error", Heading: "Could not delete", Text: "The snapshot could not be removed right now. Please try again."})
		return
	}
	s.log.Info("image deleted by owner", "id", requestID(r))
	s.page(w, r, http.StatusOK, "message", pageData{Title: "Deleted", Heading: "Snapshot deleted", Text: "The image is gone and its link no longer works."})
}

// removeImage deletes the object, then the row. If the object cannot be
// deleted the row stays so the image can be retried.
func (s *Server) removeImage(ctx context.Context, img repo.Image) error {
	st := s.state.Load()
	if st == nil {
		return errors.New("not configured")
	}
	if img.Storage == st.store.Kind() {
		if err := st.store.Delete(ctx, img.ID); err != nil {
			return err
		}
	}
	return s.repo.DeleteImage(ctx, img.ID)
}

// Health ------------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}

// handleReadyz checks the dependencies. Before setup only the database counts,
// so a platform health check passes on the first deploy.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.repo.Ping(ctx); err != nil {
		s.log.Warn("readiness: database check failed", "err", err)
		apiFail(w, http.StatusServiceUnavailable, "database_unavailable", "The database is not reachable.")
		return
	}
	if st := s.state.Load(); st != nil {
		if err := st.store.Ping(ctx); err != nil {
			s.log.Warn("readiness: storage check failed", "err", err)
			apiFail(w, http.StatusServiceUnavailable, "storage_unavailable", "The image storage is not reachable.")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "configured": s.Configured()})
}
