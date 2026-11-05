package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/ratelimit"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyClient
)

// statusWriter records what was written. Unwrap keeps http.ResponseController
// (deadlines, flushing) working through it.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// routes wires the handlers and wraps them in the middleware chain.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/images", s.handleUpload)
	mux.HandleFunc("GET /i/{id}", s.handleImage)
	mux.HandleFunc("GET /d/{secret}", s.handleDeletePage)
	mux.HandleFunc("POST /d/{secret}", s.handleDelete)

	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /static/{file}", s.handleStatic)

	mux.HandleFunc("GET /setup", s.handleSetupPage)
	mux.HandleFunc("POST /setup/verify", s.handleSetupVerify)
	mux.HandleFunc("POST /setup/test-storage", s.handleSetupTestStorage)
	mux.HandleFunc("POST /setup/complete", s.handleSetupComplete)

	mux.HandleFunc("GET /admin", s.handleAdminPage)
	mux.HandleFunc("POST /admin/api/login", s.handleLogin)
	mux.HandleFunc("GET /admin/api/session", s.admin(s.handleSession))
	mux.HandleFunc("POST /admin/api/logout", s.admin(s.handleLogout))
	mux.HandleFunc("GET /admin/api/overview", s.admin(s.handleOverview))
	mux.HandleFunc("GET /admin/api/images", s.admin(s.handleAdminImages))
	mux.HandleFunc("DELETE /admin/api/images/{id}", s.admin(s.handleAdminDeleteImage))
	mux.HandleFunc("GET /admin/api/tokens", s.admin(s.handleListTokens))
	mux.HandleFunc("POST /admin/api/tokens", s.admin(s.handleCreateToken))
	mux.HandleFunc("DELETE /admin/api/tokens/{id}", s.admin(s.handleDeleteToken))
	mux.HandleFunc("GET /admin/api/settings", s.admin(s.handleGetSettings))
	mux.HandleFunc("PUT /admin/api/settings", s.admin(s.handlePutSettings))
	mux.HandleFunc("POST /admin/api/settings/test-storage", s.admin(s.handleAdminTestStorage))
	mux.HandleFunc("POST /admin/api/password", s.admin(s.handleChangePassword))

	var h http.Handler = mux
	h = s.withDeadlines(h)
	h = s.withLogging(h)
	h = s.withSecurityHeaders(h)
	h = s.withClient(h)
	h = s.withRequestID(h)
	h = s.withRecover(h)
	return h
}

func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				s.log.Error("panic in handler", "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				apiFail(w, http.StatusInternalServerError, "internal", "Internal error.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.Random(12)
		if err != nil {
			id = "unknown"
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyRequestID, id)))
	})
}

// withClient resolves the client address once and stores its rate-limit key.
func (s *Server) withClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := "unknown"
		if a, ok := s.resolver.Client(r); ok {
			key = ratelimit.Key(a)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyClient, key)))
	})
}

func clientKey(r *http.Request) string {
	k, _ := r.Context().Value(keyClient).(string)
	return k
}

func requestID(r *http.Request) string {
	k, _ := r.Context().Value(keyRequestID).(string)
	return k
}

// withSecurityHeaders sets the defaults for every response. Image delivery
// overrides the ones that differ.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin") // image delivery overrides this
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if s.secure() {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// secure reports whether the service is published over https.
func (s *Server) secure() bool {
	if st := s.state.Load(); st != nil {
		return strings.HasPrefix(st.set.PublicURL, "https://")
	}
	return strings.HasPrefix(s.cfg.PublicURL, "https://")
}

// withDeadlines gives ordinary requests 30 s. Upload and image delivery extend
// their own, since they move megabytes.
func (s *Server) withDeadlines(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		d := time.Now().Add(30 * time.Second)
		_ = rc.SetReadDeadline(d)
		_ = rc.SetWriteDeadline(d)
		next.ServeHTTP(w, r)
	})
}

func extendDeadlines(w http.ResponseWriter, d time.Duration) {
	rc := http.NewResponseController(w)
	t := time.Now().Add(d)
	_ = rc.SetReadDeadline(t)
	_ = rc.SetWriteDeadline(t)
}

// withLogging writes one line per request. It never logs query strings,
// headers or bodies, and replaces secret path segments.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		level := slogLevelFor(r.URL.Path)
		s.log.Log(r.Context(), level, "request",
			"id", requestID(r), "ip", clientKey(r), "method", r.Method, "path", redactPath(r.URL.Path),
			"status", sw.status, "bytes", sw.bytes, "ms", time.Since(start).Milliseconds())
	})
}

// redactPath hides what must not reach logs: delete secrets entirely, and image
// ids (which tie a viewer to a picture) too.
func redactPath(p string) string {
	switch {
	case strings.HasPrefix(p, "/d/"):
		return "/d/:secret"
	case strings.HasPrefix(p, "/i/"):
		return "/i/:id"
	case strings.HasPrefix(p, "/admin/api/images/"):
		return "/admin/api/images/:id"
	case strings.HasPrefix(p, "/admin/api/tokens/"):
		return "/admin/api/tokens/:id"
	}
	if len(p) > 120 {
		return p[:120]
	}
	return p
}

func slogLevelFor(path string) slog.Level {
	if path == "/healthz" || path == "/readyz" {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}
