// Package server is the HTTP interface: the upload API, image delivery, the
// first-run wizard and the admin console.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/degenview/snapshots/internal/auth"
	"github.com/degenview/snapshots/internal/config"
	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/ratelimit"
	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/settings"
	"github.com/degenview/snapshots/internal/storage"
	"github.com/degenview/snapshots/internal/storage/local"
	"github.com/degenview/snapshots/internal/storage/s3"
)

// Deps are the collaborators a Server needs.
type Deps struct {
	Config     *config.Config
	Repo       *repo.Repo
	Settings   *settings.Store
	Log        *slog.Logger
	Version    string
	Now        func() time.Time // nil: time.Now
	SetupToken string           // unlocks the first-run wizard
}

// Fixed limits that are not worth a setting.
const (
	maxConcurrentUploads = 8
	maxJSONBody          = 64 << 10
)

// Server implements http.Handler.
type Server struct {
	cfg        *config.Config
	repo       *repo.Repo
	sets       *settings.Store
	log        *slog.Logger
	version    string
	now        func() time.Time
	setupToken string

	sessions *auth.Sessions
	tokens   *auth.Tokens
	resolver *ratelimit.Resolver

	limUpload *ratelimit.Limiter
	limView   *ratelimit.Limiter
	limDelete *ratelimit.Limiter
	limLogin  *ratelimit.Limiter
	limSetup  *ratelimit.Limiter
	uploadSem chan struct{}
	hashSem   chan struct{} // bounds concurrent Argon2 work, see hashing.go
	verify    func(pw, encoded string) bool

	state atomic.Pointer[state] // nil until setup is complete

	// storeMu orders storage changes against uploads: an upload holds the read
	// side from choosing the store until its row and object are written, and a
	// settings save holds the write side, so "no images here" cannot become false
	// between a save's check and its switch. It covers one process only.
	storeMu sync.RWMutex
	// testBeforePut, when set by a test, runs after the image row exists and
	// before the object is written.
	testBeforePut func()

	pages   map[string]*template.Template
	static  map[string]staticFile
	handler http.Handler
}

// state is what changes when an administrator saves settings.
type state struct {
	set   settings.Settings
	store storage.Store
}

// New builds a Server. Call Init before serving.
func New(d Deps) (*Server, error) {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	log := d.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	sessions := auth.NewSessions(d.Repo)
	sessions.Now = now
	s := &Server{
		cfg: d.Config, repo: d.Repo, sets: d.Settings, log: log, version: d.Version, now: now,
		setupToken: d.SetupToken,
		sessions:   sessions,
		tokens:     &auth.Tokens{Repo: d.Repo, Now: now},
		resolver:   ratelimit.NewResolver(d.Config.TrustedProxies, d.Config.TrustAnyProxy, d.Config.ClientIPHeader),
		uploadSem:  make(chan struct{}, maxConcurrentUploads),
		hashSem:    make(chan struct{}, maxConcurrentHashes),
		verify:     auth.VerifyPassword,
	}
	const maxKeys = 100_000
	def := settings.Defaults()
	s.limUpload = ratelimit.New(def.UploadsPerHour, time.Hour, uploadBurst(def.UploadsPerHour), maxKeys, now)
	s.limView = ratelimit.New(def.ViewsPerMinute, time.Minute, viewBurst(def.ViewsPerMinute), maxKeys, now)
	s.limDelete = ratelimit.New(30, time.Hour, 10, maxKeys, now)
	s.limLogin = ratelimit.New(10, 15*time.Minute, 5, maxKeys, now)
	s.limSetup = ratelimit.New(20, 15*time.Minute, 10, maxKeys, now)

	var err error
	if s.pages, err = loadTemplates(); err != nil {
		return nil, err
	}
	if s.static, err = loadStatic(); err != nil {
		return nil, err
	}
	s.handler = s.routes()
	return s, nil
}

func uploadBurst(perHour int) int { return max(1, min(perHour, 10)) }
func viewBurst(perMinute int) int { return max(1, min(perMinute, 120)) }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Init loads saved settings. Before first-run setup there are none and the
// server only offers the wizard.
func (s *Server) Init(ctx context.Context) error {
	set, found, err := s.sets.Load(ctx)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if set.StorageKind == storage.KindS3 && set.S3.Config().Plaintext() && !s.cfg.AllowInsecureBackends {
		s.log.Warn("S3 endpoint uses plaintext http:// on a remote host; set ALLOW_INSECURE_BACKENDS=true to acknowledge or switch to https://")
	}
	return s.apply(set)
}

// SetSetupToken sets the token that unlocks the wizard (used when none was configured).
func (s *Server) SetSetupToken(t string) { s.setupToken = t }

// Configured reports whether first-run setup has been completed.
func (s *Server) Configured() bool { return s.state.Load() != nil }

// Store returns the active image store, or nil before setup. The janitor uses it.
func (s *Server) Store() storage.Store {
	if st := s.state.Load(); st != nil {
		return st.store
	}
	return nil
}

// PruneSessions drops expired admin sessions.
func (s *Server) PruneSessions(ctx context.Context) error { return s.sessions.Prune(ctx) }

// apply makes set live: a new storage backend if its configuration changed and
// new rate limits.
func (s *Server) apply(set settings.Settings) error {
	var store storage.Store
	old := s.state.Load()
	if old != nil && sameStorage(old.set, set) {
		store = old.store
	} else {
		var err error
		if store, err = s.buildStore(set); err != nil {
			return err
		}
	}
	s.limUpload.Reconfigure(set.UploadsPerHour, time.Hour, uploadBurst(set.UploadsPerHour))
	s.limView.Reconfigure(set.ViewsPerMinute, time.Minute, viewBurst(set.ViewsPerMinute))
	s.state.Store(&state{set: set, store: store})
	if old != nil && old.store != store {
		if c, ok := old.store.(io.Closer); ok {
			time.AfterFunc(30*time.Second, func() { c.Close() }) // let in-flight reads finish
		}
	}
	return nil
}

func sameStorage(a, b settings.Settings) bool {
	return a.StorageKind == b.StorageKind && reflect.DeepEqual(a.S3, b.S3)
}

func (s *Server) buildStore(set settings.Settings) (storage.Store, error) {
	switch set.StorageKind {
	case storage.KindLocal:
		return local.New(filepath.Join(s.cfg.DataDir, "images"))
	case storage.KindS3:
		return s3.New(set.S3.Config())
	}
	return nil, fmt.Errorf("unknown storage %q", set.StorageKind)
}

// JSON helpers ------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type apiErrorBody struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func apiFail(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiErrorBody{apiError{Code: code, Message: msg}})
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait/time.Second) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	apiFail(w, http.StatusTooManyRequests, "rate_limited", "Too many requests. Try again in "+strconv.Itoa(secs)+" seconds.")
}

// decodeJSON reads a small JSON body strictly.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			apiFail(w, http.StatusRequestEntityTooLarge, "too_large", "Request body too large.")
		} else {
			apiFail(w, http.StatusBadRequest, "bad_request", "Malformed JSON request.")
		}
		return false
	}
	if dec.More() {
		apiFail(w, http.StatusBadRequest, "bad_request", "Unexpected data after JSON body.")
		return false
	}
	return true
}

func newTokenPlain() (string, error) { return ids.Token() }
