package server

import (
	"bytes"
	"context"
	"errors"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/storage"
)

// --- before setup -------------------------------------------------------------------

func TestBeforeSetup(t *testing.T) {
	e := newEnv(t)
	if w := e.upload(pngBytes(t, 4, 4), ""); w.Code != 503 || errCode(t, w) != "not_configured" {
		t.Fatalf("upload: %d %s", w.Code, w.Body)
	}
	if w := e.get("/i/abcdefghij"); w.Code != 404 {
		t.Fatalf("image: %d", w.Code)
	}
	if w := e.get("/healthz"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := e.get("/readyz"); w.Code != 200 {
		t.Fatalf("readyz must pass before setup so a platform health check succeeds: %d", w.Code)
	}
	for _, p := range []string{"/", "/admin"} {
		w := e.get(p)
		if w.Code != 303 || w.Header().Get("Location") != "/setup" {
			t.Fatalf("%s: %d %s", p, w.Code, w.Header().Get("Location"))
		}
	}
	for _, c := range []req{
		{method: "POST", path: "/admin/api/login", json: loginRequest{Password: testPassword}},
		{method: "GET", path: "/admin/api/overview"},
	} {
		if w := e.do(c); w.Code != 404 {
			t.Fatalf("%s: %d", c.path, w.Code)
		}
	}
	if w := e.get("/setup"); w.Code != 200 || !strings.Contains(w.Body.String(), "Set up DegenView Snapshots") {
		t.Fatalf("setup page: %d", w.Code)
	}
}

// --- setup wizard ---------------------------------------------------------------------

func TestSetupRequiresTheToken(t *testing.T) {
	e := newEnv(t)
	for _, tok := range []string{"", "wrong", testSetupTok + "x", strings.ToUpper(testSetupTok)} {
		for _, path := range []string{"/setup/verify", "/setup/complete", "/setup/test-storage"} {
			body := defaultSetup()
			body.SetupToken = tok
			w := e.do(req{method: "POST", path: path, json: body})
			if w.Code != 400 && w.Code != 401 {
				t.Fatalf("%s with token %q: %d", path, tok, w.Code)
			}
			if w.Code == 401 && errCode(t, w) != "bad_setup_token" {
				t.Fatal(errCode(t, w))
			}
		}
	}
	if e.srv.Configured() {
		t.Fatal("setup completed without the token")
	}
	if w := e.do(req{method: "POST", path: "/setup/verify", json: setupVerifyRequest{SetupToken: testSetupTok}}); w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestSetupWithoutAnyConfiguredTokenIsLocked(t *testing.T) {
	e := newEnv(t)
	e.srv.setupToken = ""
	w := e.do(req{method: "POST", path: "/setup/verify", json: setupVerifyRequest{SetupToken: ""}})
	if w.Code != 401 {
		t.Fatalf("empty token matched empty configured token: %d", w.Code)
	}
}

func TestSetupRateLimited(t *testing.T) {
	e := newEnv(t)
	var last int
	for i := 0; i < 15; i++ {
		last = e.do(req{method: "POST", path: "/setup/verify", json: setupVerifyRequest{SetupToken: "guess"}}).Code
	}
	if last != 429 {
		t.Fatalf("token guessing not throttled: %d", last)
	}
	// Even the right token is refused while throttled.
	w := e.do(req{method: "POST", path: "/setup/verify", json: setupVerifyRequest{SetupToken: testSetupTok}})
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestSetupRejectsBadInput(t *testing.T) {
	cases := map[string]setupOpts{
		"short password": func(r *setupCompleteRequest) { r.Password = "short" },
		"bad url":        func(r *setupCompleteRequest) { r.PublicURL = "http://example.com" },
		"retention":      func(r *setupCompleteRequest) { r.RetentionDays = -3 },
		"image size":     func(r *setupCompleteRequest) { r.MaxImageBytes = 1 << 40 },
		"storage kind":   func(r *setupCompleteRequest) { r.StorageKind = "floppy" },
		"s3 incomplete":  func(r *setupCompleteRequest) { r.StorageKind = "s3" },
	}
	for name, mod := range cases {
		e := newEnv(t, withKey(bytes.Repeat([]byte{1}, 32)))
		body := defaultSetup()
		mod(&body)
		w := e.do(req{method: "POST", path: "/setup/complete", json: body})
		if w.Code != 400 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		if e.srv.Configured() {
			t.Errorf("%s: setup went through", name)
		}
	}
}

func TestSetupStrictJSON(t *testing.T) {
	e := newEnv(t)
	for _, body := range []string{`{`, `[]`, `{"setup_token":"x","bogus":1}`, `{"setup_token":"x"} {"a":1}`, strings.Repeat(" ", 70000) + `{}`} {
		w := e.do(req{method: "POST", path: "/setup/verify", body: []byte(body), headers: map[string]string{"Content-Type": "application/json"}})
		if w.Code != 400 && w.Code != 413 {
			t.Errorf("%.20q: %d", body, w.Code)
		}
	}
}

func TestSetupRejectsCrossSite(t *testing.T) {
	e := newEnv(t)
	w := e.do(req{method: "POST", path: "/setup/complete", json: defaultSetup(), headers: map[string]string{"Origin": "https://evil.example"}})
	if w.Code != 403 || e.srv.Configured() {
		t.Fatalf("%d", w.Code)
	}
}

func TestSetupCompletesOnceAndLocks(t *testing.T) {
	e := newEnv(t)
	res := e.setup()
	if !e.srv.Configured() || res.resp.Token == "" || !strings.HasPrefix(res.resp.Token, "dvs_") {
		t.Fatalf("%+v", res.resp)
	}
	if res.resp.UploadURL != publicURL+"/api/v1/images" {
		t.Fatal(res.resp.UploadURL)
	}
	if res.cookie == nil || !res.cookie.HttpOnly || !res.cookie.Secure || res.cookie.SameSite != http.SameSiteStrictMode ||
		res.cookie.Name != "__Host-dvs_session" || res.cookie.Path != "/" || res.cookie.Domain != "" {
		t.Fatalf("session cookie not hardened: %+v", res.cookie)
	}
	// The wizard is gone for good.
	for _, c := range []req{
		{method: "GET", path: "/setup"},
		{method: "POST", path: "/setup/verify", json: setupVerifyRequest{SetupToken: testSetupTok}},
		{method: "POST", path: "/setup/test-storage", json: setupTestRequest{SetupToken: testSetupTok}},
		{method: "POST", path: "/setup/complete", json: defaultSetup()},
	} {
		if w := e.do(c); w.Code != 404 {
			t.Fatalf("%s %s still answers after setup: %d", c.method, c.path, w.Code)
		}
	}
	// And survives a restart.
	e.build()
	if !e.srv.Configured() {
		t.Fatal("configuration lost on restart")
	}
	if w := e.do(req{method: "GET", path: "/setup"}); w.Code != 404 {
		t.Fatal("wizard reachable after restart")
	}
}

func TestSetupWithOpenUploadsIssuesNoToken(t *testing.T) {
	e := newEnv(t)
	res := e.setup(func(r *setupCompleteRequest) { r.AuthRequired = false })
	if res.resp.Token != "" {
		t.Fatal("token issued although auth is off")
	}
	if w := e.upload(pngBytes(t, 5, 5), ""); w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestPublicURLFromEnvironmentWins(t *testing.T) {
	e := newEnv(t, withPublicURL("https://fixed.example.org"))
	res := e.setup(func(r *setupCompleteRequest) { r.PublicURL = "https://other.example" })
	if res.resp.PublicURL != "https://fixed.example.org" {
		t.Fatal(res.resp.PublicURL)
	}
}

func TestSuggestURL(t *testing.T) {
	for in, want := range map[string]string{
		"localhost:8080": "http://localhost:8080", "127.0.0.1:8080": "http://127.0.0.1:8080", "[::1]:8080": "http://[::1]:8080",
		"snaps.example.com": "https://snaps.example.com", "app.localhost": "http://app.localhost", "10.0.0.5:80": "https://10.0.0.5:80",
	} {
		if got := suggestURL(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

// --- upload ---------------------------------------------------------------------------

func TestUploadAndFetch(t *testing.T) {
	e := newEnv(t)
	tok := e.setup().resp.Token
	data := pngBytes(t, 120, 80)
	w := e.upload(data, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatal(ct)
	}
	if w.Header().Get("Location") != "" {
		t.Fatal("upload response must not redirect")
	}
	resp := decode[uploadResponse](t, w)

	// Protocol rules the DegenView client enforces on the reply.
	if w.Body.Len() > 16<<10 {
		t.Fatal("reply too large")
	}
	u, err := url.Parse(resp.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || len(resp.URL) > 2048 || strings.ContainsAny(resp.URL, " \t\n") {
		t.Fatalf("url %q breaks the client's rules", resp.URL)
	}
	if !regexp.MustCompile(`^https://snaps\.example\.com/i/[0-9A-Za-z]{10}$`).MatchString(resp.URL) {
		t.Fatalf("url shape: %s", resp.URL)
	}
	if !regexp.MustCompile(`^https://snaps\.example\.com/d/[0-9A-Za-z]{24}$`).MatchString(resp.DeleteURL) {
		t.Fatalf("delete url shape: %s", resp.DeleteURL)
	}
	if want := e.clock().AddDate(0, 0, 90).Format(time.RFC3339); resp.ExpiresAt != want {
		t.Fatalf("expires_at %q, want %q", resp.ExpiresAt, want)
	}

	got := e.get(pathOf(t, resp.URL))
	if got.Code != 200 {
		t.Fatalf("%d", got.Code)
	}
	img, err := png.Decode(got.Body)
	if err != nil || img.Bounds().Dx() != 120 || img.Bounds().Dy() != 80 {
		t.Fatalf("served image differs: %v", err)
	}
	h := got.Header()
	for k, want := range map[string]string{
		"Content-Type": "image/png", "X-Content-Type-Options": "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox", "Referrer-Policy": "no-referrer",
	} {
		if h.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, h.Get(k), want)
		}
	}
	if !strings.HasPrefix(h.Get("Content-Disposition"), "inline") {
		t.Errorf("Content-Disposition = %q", h.Get("Content-Disposition"))
	}
	if cc := h.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=") || strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestUploadNeverExpiringOmitsExpiry(t *testing.T) {
	e := newEnv(t)
	tok := e.setup(func(r *setupCompleteRequest) { r.RetentionDays = 0 }).resp.Token
	resp, _ := e.mustUpload(tok)
	if resp.ExpiresAt != "" {
		t.Fatal(resp.ExpiresAt)
	}
	e.advance(10 * 365 * 24 * time.Hour)
	if w := e.get(pathOf(t, resp.URL)); w.Code != 200 {
		t.Fatalf("never-expiring image gone: %d", w.Code)
	}
}

func TestUploadAuthentication(t *testing.T) {
	e := newEnv(t)
	tok := e.setup().resp.Token
	data := pngBytes(t, 4, 4)
	other, _ := ids.Token()

	for name, header := range map[string]string{
		"none": "", "wrong token": "Bearer " + other, "wrong scheme": "Basic " + tok, "empty bearer": "Bearer ",
		"token as bare header": tok, "truncated": "Bearer " + tok[:20], "sql": "Bearer ' OR 1=1 --",
	} {
		r := req{method: "POST", path: "/api/v1/images", body: data, headers: map[string]string{"Content-Type": "image/png"}}
		if header != "" {
			r.headers["Authorization"] = header
		}
		w := e.do(r)
		if w.Code != 401 {
			t.Errorf("%s: %d", name, w.Code)
		}
		if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: no WWW-Authenticate", name)
		}
	}
	if w := e.upload(data, tok); w.Code != 201 {
		t.Fatal(w.Code)
	}
}

func TestRevokedTokenStopsWorkingImmediately(t *testing.T) {
	e := newEnv(t)
	res := e.setup()
	tok := res.resp.Token
	if w := e.upload(pngBytes(t, 4, 4), tok); w.Code != 201 {
		t.Fatal(w.Code)
	}
	a := e.adminClient(res)
	list := decode[map[string][]tokenView](t, a.do("GET", "/admin/api/tokens", nil))["tokens"]
	if w := a.do("DELETE", "/admin/api/tokens/"+list[0].ID, nil); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := e.upload(pngBytes(t, 4, 4), tok); w.Code != 401 {
		t.Fatalf("revoked token still works: %d", w.Code)
	}
}

func TestUploadValidation(t *testing.T) {
	e := newEnv(t)
	tok := e.setup(func(r *setupCompleteRequest) { r.MaxImageBytes = 4096 }).resp.Token
	good := pngBytes(t, 8, 8)

	post := func(ct string, body []byte, chunked bool) *httptest.ResponseRecorder {
		return e.do(req{method: "POST", path: "/api/v1/images", body: body, noLength: chunked,
			headers: map[string]string{"Content-Type": ct, "Authorization": "Bearer " + tok}})
	}
	if w := post("image/jpeg", good, false); w.Code != 415 {
		t.Errorf("jpeg content type: %d", w.Code)
	}
	if w := post("", good, false); w.Code != 415 {
		t.Errorf("no content type: %d", w.Code)
	}
	if w := post("image/png; charset=binary", good, false); w.Code != 201 {
		t.Errorf("content type parameters should be accepted: %d", w.Code)
	}
	if w := post("image/png", []byte("GIF89a not a png"), false); w.Code != 422 || errCode(t, w) != "invalid_image" {
		t.Errorf("fake png: %d", w.Code)
	}
	if w := post("image/png", nil, false); w.Code != 422 {
		t.Errorf("empty body: %d", w.Code)
	}
	if w := post("image/png", good[:len(good)-5], false); w.Code != 422 {
		t.Errorf("truncated png: %d", w.Code)
	}
	big := noisyPNG(t, 40, 40) // ~6 KiB
	if len(big) <= 4096 {
		t.Fatalf("fixture too small: %d", len(big))
	}
	if w := post("image/png", big, false); w.Code != 413 {
		t.Errorf("declared oversize: %d", w.Code)
	}
	if w := post("image/png", big, true); w.Code != 413 {
		t.Errorf("undeclared oversize (chunked) must still be stopped: %d", w.Code)
	}
}

func TestUploadRejectsHugeDimensions(t *testing.T) {
	e := newEnv(t)
	tok := e.setup().resp.Token
	// A tiny file that claims to be 20000×20000.
	hdr := pngBytes(t, 4, 4)
	hugeIHDR := append([]byte{}, hdr...)
	copy(hugeIHDR[16:20], []byte{0, 0, 0x4e, 0x20}) // width 20000
	copy(hugeIHDR[20:24], []byte{0, 0, 0x4e, 0x20})
	// fix IHDR CRC so only the dimensions are wrong
	crc := crc32IEEE(hugeIHDR[12:29])
	copy(hugeIHDR[29:33], []byte{byte(crc >> 24), byte(crc >> 16), byte(crc >> 8), byte(crc)})
	w := e.upload(hugeIHDR, tok)
	if w.Code != 413 || errCode(t, w) != "image_too_large" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestUploadStripsMetadata(t *testing.T) {
	e := newEnv(t)
	tok := e.setup().resp.Token
	data := withTextChunk(t, pngBytes(t, 10, 10), "gps=40.7,-74.0 author=jane")
	if !bytes.Contains(data, []byte("author=jane")) {
		t.Fatal("fixture broken")
	}
	w := e.upload(data, tok)
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	got := e.get(pathOf(t, decode[uploadResponse](t, w).URL))
	if bytes.Contains(got.Body.Bytes(), []byte("author=jane")) || bytes.Contains(got.Body.Bytes(), []byte("tEXt")) {
		t.Fatal("metadata reached storage")
	}
	if _, err := png.Decode(got.Body); err != nil {
		t.Fatal(err)
	}
}

func TestUploadQuota(t *testing.T) {
	e := newEnv(t)
	tok := e.setup(func(r *setupCompleteRequest) { r.MaxTotalBytes = 3000 }).resp.Token
	n := 0
	for ; n < 10; n++ {
		w := e.upload(noisyPNG(t, 16, 16+n), tok)
		if w.Code == 507 {
			if errCode(t, w) != "quota_exceeded" {
				t.Fatal(errCode(t, w))
			}
			break
		}
		if w.Code != 201 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
	if n == 0 || n == 10 {
		t.Fatalf("quota hit after %d uploads", n)
	}
}

func TestUploadBusy(t *testing.T) {
	e := newEnv(t)
	tok := e.setup().resp.Token
	for i := 0; i < cap(e.srv.uploadSem); i++ {
		e.srv.uploadSem <- struct{}{}
	}
	w := e.upload(pngBytes(t, 4, 4), tok)
	if w.Code != 503 || w.Header().Get("Retry-After") == "" || errCode(t, w) != "busy" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// failingStore makes Put fail.
type failingStore struct {
	storage.Store
	failPut, failPing bool
}

func (f *failingStore) Put(ctx context.Context, id string, r io.Reader, n int64) error {
	if f.failPut {
		return errors.New("disk on fire")
	}
	return f.Store.Put(ctx, id, r, n)
}
func (f *failingStore) Ping(ctx context.Context) error {
	if f.failPing {
		return errors.New("unreachable")
	}
	return f.Store.Ping(ctx)
}

func TestStorageFailureLeavesNoRow(t *testing.T) {
	e := newEnv(t)
	tok := e.setup().resp.Token
	st := e.srv.state.Load()
	e.srv.state.Store(&state{set: st.set, store: &failingStore{Store: st.store, failPut: true}})
	w := e.upload(pngBytes(t, 4, 4), tok)
	if w.Code != 502 || errCode(t, w) != "storage_error" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if s, _ := e.repo.ImageStats(context.Background()); s.Images != 0 {
		t.Fatal("metadata row left behind after failed write")
	}
	if strings.Contains(w.Body.String(), "fire") {
		t.Fatal("internal error text leaked to the client")
	}
}

func TestReadyzReportsStorageFailure(t *testing.T) {
	e := newEnv(t)
	e.setup()
	if w := e.get("/readyz"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	st := e.srv.state.Load()
	e.srv.state.Store(&state{set: st.set, store: &failingStore{Store: st.store, failPing: true}})
	if w := e.get("/readyz"); w.Code != 503 || errCode(t, w) != "storage_unavailable" {
		t.Fatalf("%d", w.Code)
	}
	if w := e.get("/healthz"); w.Code != 200 {
		t.Fatal("liveness must not depend on storage")
	}
}

// --- rate limiting ----------------------------------------------------------------------

func TestUploadRateLimitPerIP(t *testing.T) {
	e := newEnv(t)
	tok := e.setup(func(r *setupCompleteRequest) { r.UploadsPerHour = 3 }).resp.Token
	data := pngBytes(t, 4, 4)
	for i := 0; i < 3; i++ {
		if w := e.upload(data, tok); w.Code != 201 {
			t.Fatalf("upload %d: %d", i, w.Code)
		}
	}
	w := e.upload(data, tok)
	if w.Code != 429 || errCode(t, w) != "rate_limited" {
		t.Fatalf("%d", w.Code)
	}
	ra := w.Header().Get("Retry-After")
	if ra == "" || ra == "0" {
		t.Fatalf("Retry-After = %q", ra)
	}
	// A different client is unaffected.
	if w := e.upload(data, tok, "198.51.100.77:1"); w.Code != 201 {
		t.Fatalf("other IP: %d", w.Code)
	}
	// Refusals do not reveal whether the token was right.
	if w := e.upload(data, "dvs_"+strings.Repeat("a", 32)); w.Code != 429 {
		t.Fatalf("limited client got %d", w.Code)
	}
	e.advance(21 * time.Minute) // 3/hour → one token per 20 minutes
	if w := e.upload(data, tok); w.Code != 201 {
		t.Fatalf("not refilled: %d", w.Code)
	}
}

func TestIPv6ClientsShareTheirSlash64(t *testing.T) {
	e := newEnv(t)
	tok := e.setup(func(r *setupCompleteRequest) { r.UploadsPerHour = 1 }).resp.Token
	data := pngBytes(t, 4, 4)
	if w := e.upload(data, tok, "[2001:db8:1:2::1]:1"); w.Code != 201 {
		t.Fatal(w.Code)
	}
	if w := e.upload(data, tok, "[2001:db8:1:2:ffff::9]:1"); w.Code != 429 {
		t.Fatalf("rotating within a /64 evades the limit: %d", w.Code)
	}
}

func TestForwardedForIsIgnoredByDefault(t *testing.T) {
	e := newEnv(t)
	tok := e.setup(func(r *setupCompleteRequest) { r.UploadsPerHour = 1 }).resp.Token
	data := pngBytes(t, 4, 4)
	post := func(spoof string) int {
		return e.do(req{method: "POST", path: "/api/v1/images", body: data, headers: map[string]string{
			"Content-Type": "image/png", "Authorization": "Bearer " + tok, "X-Forwarded-For": spoof}}).Code
	}
	if c := post("1.1.1.1"); c != 201 {
		t.Fatal(c)
	}
	if c := post("2.2.2.2"); c != 429 {
		t.Fatalf("spoofed X-Forwarded-For gave a fresh rate limit: %d", c)
	}
}

func TestTrustedProxyHeaderIsHonoured(t *testing.T) {
	e := newEnv(t, withProxies("X-Forwarded-For", "10.0.0.0/8"))
	tok := e.setup(func(r *setupCompleteRequest) { r.UploadsPerHour = 1 }).resp.Token
	data := pngBytes(t, 4, 4)
	post := func(remote, xff string) int {
		return e.do(req{method: "POST", path: "/api/v1/images", body: data, remote: remote, headers: map[string]string{
			"Content-Type": "image/png", "Authorization": "Bearer " + tok, "X-Forwarded-For": xff}}).Code
	}
	if c := post("10.0.0.2:1", "198.51.100.1"); c != 201 {
		t.Fatal(c)
	}
	if c := post("10.0.0.2:1", "198.51.100.2"); c != 201 {
		t.Fatalf("distinct clients behind the proxy share one bucket: %d", c)
	}
	if c := post("10.0.0.2:1", "6.6.6.6, 198.51.100.1"); c != 429 {
		t.Fatalf("a forged leading entry must not pick the identity: %d", c)
	}
	// A peer outside the trusted range cannot use the header at all.
	if c := post("203.0.113.5:1", "198.51.100.99"); c != 201 {
		t.Fatal(c)
	}
	if c := post("203.0.113.5:1", "198.51.100.98"); c != 429 {
		t.Fatalf("untrusted peer chose its own identity: %d", c)
	}
}

func TestViewRateLimit(t *testing.T) {
	e := newEnv(t)
	tok := e.setup(func(r *setupCompleteRequest) { r.ViewsPerMinute = 2 }).resp.Token
	resp, _ := e.mustUpload(tok)
	p := pathOf(t, resp.URL)
	e.get(p)
	e.get(p)
	if w := e.get(p); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("%d", w.Code)
	}
	if w := e.do(req{method: "GET", path: p, remote: "198.51.100.5:1"}); w.Code != 200 {
		t.Fatal("limit is not per IP")
	}
}
