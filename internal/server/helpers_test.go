package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/degenview/snapshots/internal/config"
	"github.com/degenview/snapshots/internal/db"
	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/settings"
)

const (
	testPassword = "correct horse battery staple"
	testSetupTok = "setup-token-1234567890"
	publicURL    = "https://snaps.example.com"
)

type env struct {
	t       *testing.T
	srv     *Server
	repo    *repo.Repo
	cfg     *config.Config
	key     []byte
	dataDir string
	logs    *syncBuf

	mu  sync.Mutex
	now time.Time
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type envOpt func(*config.Config, *env)

func withProxies(header string, cidrs ...string) envOpt {
	return func(c *config.Config, _ *env) {
		c.ClientIPHeader = header
		for _, s := range cidrs {
			c.TrustedProxies = append(c.TrustedProxies, netip.MustParsePrefix(s))
		}
	}
}

func withKey(k []byte) envOpt { return func(c *config.Config, e *env) { e.key = k } }

func withPublicURL(u string) envOpt { return func(c *config.Config, _ *env) { c.PublicURL = u } }

// newEnv builds an unconfigured server on a fresh SQLite database and temp dir.
func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	dir := t.TempDir()
	d, err := db.OpenSQLite(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, cfg: &config.Config{DataDir: dir}, dataDir: dir, now: time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC), logs: &syncBuf{}}
	for _, o := range opts {
		o(e.cfg, e)
	}
	e.repo = repo.New(d)
	e.build()
	return e
}

// build (re)creates the Server on the existing database, as a restart would.
func (e *env) build() {
	e.t.Helper()
	log := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := New(Deps{Config: e.cfg, Repo: e.repo, Settings: settings.NewStore(e.repo, e.key), Log: log,
		Version: "test", Now: e.clock, SetupToken: testSetupTok})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := srv.Init(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	e.srv = srv
}

func (e *env) clock() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

type req struct {
	method, path string
	body         []byte
	json         any
	headers      map[string]string
	remote       string
	cookies      []*http.Cookie
	noLength     bool
}

func (e *env) do(r req) *httptest.ResponseRecorder {
	e.t.Helper()
	body := r.body
	if r.json != nil {
		var err error
		if body, err = json.Marshal(r.json); err != nil {
			e.t.Fatal(err)
		}
	}
	hr := httptest.NewRequest(r.method, r.path, bytes.NewReader(body))
	if r.noLength {
		hr.ContentLength = -1
	}
	hr.RemoteAddr = "203.0.113.9:4000"
	if r.remote != "" {
		hr.RemoteAddr = r.remote
	}
	hr.Host = "snaps.example.com"
	if r.json != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	for k, v := range r.headers {
		hr.Header.Set(k, v)
	}
	for _, c := range r.cookies {
		hr.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, hr)
	return w
}

func (e *env) get(path string) *httptest.ResponseRecorder {
	return e.do(req{method: "GET", path: path})
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("status %d, body %q: %v", w.Code, w.Body.String(), err)
	}
	return v
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[apiErrorBody](t, w).Error.Code
}

// setupOpts tweaks the wizard submission.
type setupOpts func(*setupCompleteRequest)

func defaultSetup() setupCompleteRequest {
	return setupCompleteRequest{
		SetupToken: testSetupTok, Password: testPassword, TokenName: "test",
		settingsInput: settingsInput{
			PublicURL: publicURL, AuthRequired: true, RetentionDays: 90, MaxImageBytes: 24 << 20,
			UploadsPerHour: 60, ViewsPerMinute: 600, StorageKind: "local",
		},
	}
}

// setup completes the wizard through HTTP and returns the response and session cookie.
type setupResult struct {
	resp   setupCompleteResponse
	cookie *http.Cookie
}

func (e *env) setup(mods ...setupOpts) setupResult {
	e.t.Helper()
	body := defaultSetup()
	for _, m := range mods {
		m(&body)
	}
	w := e.do(req{method: "POST", path: "/setup/complete", json: body})
	if w.Code != 200 {
		e.t.Fatalf("setup failed: %d %s", w.Code, w.Body.String())
	}
	res := setupResult{resp: decode[setupCompleteResponse](e.t, w)}
	for _, c := range w.Result().Cookies() {
		res.cookie = c
	}
	return res
}

// pngBytes returns a real PNG of w×h pixels.
func pngBytes(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.NRGBA{uint8(x), uint8(y), 128, 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// noisyPNG returns an incompressible PNG, so its size is predictable (~4 bytes a pixel).
func noisyPNG(t testing.TB, w, h int) []byte {
	t.Helper()
	rng := rand.New(rand.NewPCG(1, uint64(w*1000+h)))
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = byte(rng.UintN(256))
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// withTextChunk inserts a tEXt chunk after IHDR.
func withTextChunk(t testing.TB, data []byte, text string) []byte {
	t.Helper()
	body := []byte("Comment\x00" + text)
	var c bytes.Buffer
	binary.Write(&c, binary.BigEndian, uint32(len(body)))
	c.WriteString("tEXt")
	c.Write(body)
	binary.Write(&c, binary.BigEndian, crc32.ChecksumIEEE(append([]byte("tEXt"), body...)))
	const afterIHDR = 8 + 25
	out := append([]byte{}, data[:afterIHDR]...)
	out = append(out, c.Bytes()...)
	return append(out, data[afterIHDR:]...)
}

func (e *env) upload(data []byte, token string, remote ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	r := req{method: "POST", path: "/api/v1/images", body: data, headers: map[string]string{"Content-Type": "image/png"}}
	if token != "" {
		r.headers["Authorization"] = "Bearer " + token
	}
	if len(remote) > 0 {
		r.remote = remote[0]
	}
	return e.do(r)
}

func (e *env) mustUpload(token string) (uploadResponse, []byte) {
	e.t.Helper()
	data := pngBytes(e.t, 30, 20)
	w := e.upload(data, token)
	if w.Code != http.StatusCreated {
		e.t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	return decode[uploadResponse](e.t, w), data
}

// pathOf strips the public base URL, leaving what a request would use.
func pathOf(t testing.TB, u string) string {
	t.Helper()
	if !strings.HasPrefix(u, publicURL) {
		t.Fatalf("url %q does not start with %q", u, publicURL)
	}
	return strings.TrimPrefix(u, publicURL)
}

func crc32IEEE(b []byte) uint32 { return crc32.ChecksumIEEE(b) }

// adminClient drives the admin API with a session cookie and CSRF token.
type adminClient struct {
	e      *env
	cookie *http.Cookie
	csrf   string
}

func (e *env) adminClient(res setupResult) *adminClient {
	return &adminClient{e: e, cookie: res.cookie, csrf: res.resp.CSRF}
}

func (a *adminClient) do(method, path string, body any) *httptest.ResponseRecorder {
	r := req{method: method, path: path, cookies: []*http.Cookie{a.cookie}, headers: map[string]string{"X-CSRF-Token": a.csrf}}
	if body != nil {
		r.json = body
	}
	return a.e.do(r)
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
func newRequest(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

var ctxBG = context.Background()
