package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/degenview/snapshots/internal/auth"
	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/settings"
	"github.com/degenview/snapshots/internal/storage"
)

// settingsInput is the settings form shared by the wizard and the admin console.
type settingsInput struct {
	PublicURL      string  `json:"public_url"`
	AuthRequired   bool    `json:"auth_required"`
	RetentionDays  int     `json:"retention_days"`
	MaxImageBytes  int64   `json:"max_image_bytes"`
	MaxTotalBytes  int64   `json:"max_total_bytes"`
	UploadsPerHour int     `json:"uploads_per_hour"`
	ViewsPerMinute int     `json:"views_per_minute"`
	StorageKind    string  `json:"storage_kind"`
	S3             s3Input `json:"s3"`
}

type s3Input struct {
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	PathStyle bool   `json:"path_style"`
	Prefix    string `json:"prefix"`
}

// toSettings builds Settings from the form. An empty S3 secret keeps base's.
func (in settingsInput) toSettings(base settings.Settings) settings.Settings {
	s := settings.Settings{
		PublicURL: strings.TrimSpace(in.PublicURL), AuthRequired: in.AuthRequired, RetentionDays: in.RetentionDays,
		MaxImageBytes: in.MaxImageBytes, MaxTotalBytes: in.MaxTotalBytes,
		UploadsPerHour: in.UploadsPerHour, ViewsPerMinute: in.ViewsPerMinute,
		StorageKind: in.StorageKind,
	}
	if in.StorageKind == storage.KindS3 {
		s.S3 = settings.S3{Endpoint: strings.TrimSpace(in.S3.Endpoint), Region: strings.TrimSpace(in.S3.Region),
			Bucket: strings.TrimSpace(in.S3.Bucket), AccessKey: strings.TrimSpace(in.S3.AccessKey),
			SecretKey: in.S3.SecretKey, PathStyle: in.S3.PathStyle, Prefix: strings.TrimSpace(in.S3.Prefix)}
		if s.S3.SecretKey == "" && base.StorageKind == storage.KindS3 {
			s.S3.SecretKey = base.S3.SecretKey
		}
	}
	return s
}

// handleSetupPage serves the wizard until setup is done, then disappears.
func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if s.Configured() {
		notFound(w)
		return
	}
	suggested := s.cfg.PublicURL
	if suggested == "" {
		suggested = suggestURL(r.Host)
	}
	s.page(w, r, http.StatusOK, "setup", pageData{
		Title: "Set up", Heading: "Set up DegenView Snapshots", Scripts: []string{"setup.js"},
		Setup: &setupPageData{CanSeal: s.sets.CanSeal(), Postgres: s.cfg.IsPostgres(), SuggestedURL: suggested,
			URLFromEnv: s.cfg.PublicURL != "", DataDir: s.cfg.DataDir},
	})
}

// setupGuard enforces everything the wizard endpoints share: setup not done,
// same-origin, rate limit, and the setup token. It writes the failure itself.
func (s *Server) setupGuard(w http.ResponseWriter, r *http.Request, token string) bool {
	if s.Configured() {
		apiFail(w, http.StatusNotFound, "not_found", "Not found.")
		return false
	}
	if err := auth.CheckSameOrigin(r); err != nil {
		apiFail(w, http.StatusForbidden, "forbidden", "Cross-site request rejected.")
		return false
	}
	if ok, wait := s.limSetup.Allow(clientKey(r)); !ok {
		tooMany(w, wait)
		return false
	}
	if s.setupToken == "" || !auth.Equal(strings.TrimSpace(token), s.setupToken) {
		apiFail(w, http.StatusUnauthorized, "bad_setup_token", "That setup token is not correct. It is printed in the server log at startup.")
		return false
	}
	return true
}

type setupVerifyRequest struct {
	SetupToken string `json:"setup_token"`
}

func (s *Server) handleSetupVerify(w http.ResponseWriter, r *http.Request) {
	if s.Configured() {
		apiFail(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	var in setupVerifyRequest
	if !decodeJSON(w, r, &in) || !s.setupGuard(w, r, in.SetupToken) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type setupTestRequest struct {
	SetupToken string `json:"setup_token"`
	settingsInput
}

type testResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (s *Server) handleSetupTestStorage(w http.ResponseWriter, r *http.Request) {
	if s.Configured() {
		apiFail(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	var in setupTestRequest
	if !decodeJSON(w, r, &in) || !s.setupGuard(w, r, in.SetupToken) {
		return
	}
	writeJSON(w, http.StatusOK, s.testStorage(r.Context(), in.toSettings(settings.Defaults())))
}

var errPlaintextS3 = errors.New("the endpoint uses http:// on a remote host, so the access key, secret and images would travel unencrypted. " +
	"Use an https:// endpoint, or set ALLOW_INSECURE_BACKENDS=true if the network is private and trusted")

// testStorage writes, reads and deletes a probe object in the configured backend.
func (s *Server) testStorage(ctx context.Context, set settings.Settings) testResult {
	if set.StorageKind == storage.KindS3 {
		if err := set.S3.Config().Validate(); err != nil {
			return testResult{Error: err.Error()}
		}
	}
	if set.StorageKind == storage.KindS3 && set.S3.Config().Plaintext() && !s.cfg.AllowInsecureBackends {
		return testResult{Error: errPlaintextS3.Error()}
	}
	store, err := s.buildStore(set)
	if err != nil {
		return testResult{Error: err.Error()}
	}
	if c, ok := store.(interface{ Close() error }); ok {
		defer func() { _ = c.Close() }()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := storage.Probe(ctx, store); err != nil {
		return testResult{Error: err.Error()}
	}
	return testResult{OK: true}
}

type setupCompleteRequest struct {
	SetupToken string `json:"setup_token"`
	Password   string `json:"password"`
	TokenName  string `json:"token_name"`
	settingsInput
}

type setupCompleteResponse struct {
	UploadURL string `json:"upload_url"`
	PublicURL string `json:"public_url"`
	Token     string `json:"token,omitempty"`
	CSRF      string `json:"csrf"`
}

func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if s.Configured() {
		apiFail(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	var in setupCompleteRequest
	if !decodeJSON(w, r, &in) || !s.setupGuard(w, r, in.SetupToken) {
		return
	}
	if err := auth.ValidatePassword(in.Password); err != nil {
		apiFail(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	set := in.toSettings(settings.Defaults())
	if s.cfg.PublicURL != "" {
		set.PublicURL = s.cfg.PublicURL // fixed by the operator's environment
	}
	if err := set.Validate(); err != nil {
		apiFail(w, http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	if set.StorageKind == storage.KindS3 && !s.sets.CanSeal() {
		apiFail(w, http.StatusBadRequest, "no_secret_key", settings.ErrNoSecretKey.Error())
		return
	}
	if res := s.testStorage(r.Context(), set); !res.OK {
		apiFail(w, http.StatusBadRequest, "storage_test_failed", "The storage test failed: "+res.Error)
		return
	}
	raw, err := s.sets.Encode(set)
	if err != nil {
		apiFail(w, http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	release, ok := s.acquireHash(w, r)
	if !ok {
		return
	}
	hash, err := auth.HashPassword(in.Password)
	release()
	if err != nil {
		s.internal(w, r, "hashing password", err)
		return
	}
	data := repo.SetupData{AdminHash: hash, Settings: map[string]string{settings.SettingsKey(): raw}, Now: s.now().UTC()}
	var plainToken string
	if set.AuthRequired {
		plainToken, err = s.issueFirstToken(&data, in.TokenName)
		if err != nil {
			s.internal(w, r, "creating token", err)
			return
		}
	}
	if err := s.repo.CompleteSetup(r.Context(), data); err != nil {
		if errors.Is(err, repo.ErrConflict) {
			apiFail(w, http.StatusNotFound, "not_found", "Not found.")
			return
		}
		s.internal(w, r, "completing setup", err)
		return
	}
	s.sets.Publish(set)
	if err := s.apply(set); err != nil {
		s.internal(w, r, "applying settings", err)
		return
	}
	s.log.Info("setup completed", "id", requestID(r), "storage", set.StorageKind, "auth_required", set.AuthRequired)

	cookie, sess, err := s.sessions.Create(r.Context())
	if err != nil {
		s.internal(w, r, "creating session", err)
		return
	}
	s.setSessionCookie(w, cookie)
	writeJSON(w, http.StatusOK, setupCompleteResponse{
		UploadURL: set.PublicURL + "/api/v1/images", PublicURL: set.PublicURL, Token: plainToken, CSRF: sess.CSRF,
	})
}

func (s *Server) issueFirstToken(data *repo.SetupData, name string) (string, error) {
	plain, err := newTokenPlain()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(name) == "" {
		name = "DegenView"
	}
	rec, err := s.tokens.Build(name, plain)
	if err != nil {
		return "", err
	}
	data.Token = &rec
	return plain, nil
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error(what+" failed", "id", requestID(r), "err", err)
	apiFail(w, http.StatusInternalServerError, "internal", "Internal error.")
}

// suggestURL guesses the public URL from the Host header, only to pre-fill the
// wizard field: the administrator confirms it, and it is never used unchecked.
func suggestURL(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	scheme := "https"
	if a, err := netip.ParseAddr(host); host == "localhost" || strings.HasSuffix(host, ".localhost") || (err == nil && a.IsLoopback()) {
		scheme = "http"
	}
	return scheme + "://" + hostport
}
