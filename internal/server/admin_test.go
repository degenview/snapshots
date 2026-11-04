package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/degenview/snapshots/internal/ids"
)

// every admin endpoint, as method + path.
var adminEndpoints = []struct{ method, path string }{
	{"GET", "/admin/api/session"}, {"POST", "/admin/api/logout"}, {"GET", "/admin/api/overview"},
	{"GET", "/admin/api/images"}, {"DELETE", "/admin/api/images/abcdefghij"},
	{"GET", "/admin/api/tokens"}, {"POST", "/admin/api/tokens"}, {"DELETE", "/admin/api/tokens/abcdefghij"},
	{"GET", "/admin/api/settings"}, {"PUT", "/admin/api/settings"}, {"POST", "/admin/api/settings/test-storage"},
	{"POST", "/admin/api/password"},
}

func TestAdminEndpointsRequireASession(t *testing.T) {
	e := newEnv(t)
	res := e.setup()
	forged := &http.Cookie{Name: "__Host-dvs_session", Value: strings.Repeat("A", 43)}
	for _, ep := range adminEndpoints {
		for name, r := range map[string]req{
			"no credentials": {method: ep.method, path: ep.path},
			"upload token":   {method: ep.method, path: ep.path, headers: map[string]string{"Authorization": "Bearer " + res.resp.Token}},
			"forged cookie":  {method: ep.method, path: ep.path, cookies: []*http.Cookie{forged}, headers: map[string]string{"X-CSRF-Token": "x"}},
			"csrf only":      {method: ep.method, path: ep.path, headers: map[string]string{"X-CSRF-Token": res.resp.CSRF}},
			"cookie name sans prefix": {method: ep.method, path: ep.path,
				cookies: []*http.Cookie{{Name: "dvs_session", Value: res.cookie.Value}}, headers: map[string]string{"X-CSRF-Token": res.resp.CSRF}},
		} {
			if w := e.do(r); w.Code != 401 {
				t.Errorf("%s %s with %s: %d", ep.method, ep.path, name, w.Code)
			}
		}
	}
}

func TestAdminMutationsRequireCSRF(t *testing.T) {
	e := newEnv(t)
	res := e.setup()
	for _, ep := range adminEndpoints {
		if ep.method == "GET" {
			continue
		}
		for name, h := range map[string]map[string]string{
			"missing token":  {},
			"wrong token":    {"X-CSRF-Token": "nope"},
			"cross-site":     {"X-CSRF-Token": res.resp.CSRF, "Sec-Fetch-Site": "cross-site"},
			"foreign origin": {"X-CSRF-Token": res.resp.CSRF, "Origin": "https://evil.example"},
			"login csrf (token from another session)": {"X-CSRF-Token": strings.Repeat("a", 32)},
		} {
			w := e.do(req{method: ep.method, path: ep.path, cookies: []*http.Cookie{res.cookie}, headers: h})
			if w.Code != 403 {
				t.Errorf("%s %s with %s: %d", ep.method, ep.path, name, w.Code)
			}
		}
	}
	if s, _ := e.repo.ImageStats(context.Background()); s.Images != 0 {
		t.Fatal()
	}
}

func TestAdminLogin(t *testing.T) {
	e := newEnv(t)
	e.setup()
	if w := e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: "wrong"}}); w.Code != 401 || errCode(t, w) != "invalid_credentials" {
		t.Fatalf("%d", w.Code)
	}
	w := e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: testPassword}})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("%+v", cookies)
	}
	csrf := decode[map[string]string](t, w)["csrf"]
	a := &adminClient{e: e, cookie: cookies[0], csrf: csrf}
	if w := a.do("GET", "/admin/api/session", nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: testPassword},
		headers: map[string]string{"Origin": "https://evil.example"}}); w.Code != 403 {
		t.Fatalf("cross-site login: %d", w.Code)
	}
}

func TestAdminLoginThrottled(t *testing.T) {
	e := newEnv(t)
	e.setup()
	var codes []int
	for i := 0; i < 8; i++ {
		codes = append(codes, e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: "wrong-attempt"}}).Code)
	}
	if codes[4] != 401 || codes[5] != 429 {
		t.Fatalf("codes %v: expected 5 attempts then 429", codes)
	}
	// While throttled even the right password is refused.
	if w := e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: testPassword}}); w.Code != 429 {
		t.Fatalf("%d", w.Code)
	}
	// Other clients are unaffected; time heals.
	if w := e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: testPassword}, remote: "198.51.100.1:1"}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	e.advance(10 * time.Minute)
	if w := e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: testPassword}}); w.Code != 200 {
		t.Fatalf("still throttled: %d", w.Code)
	}
}

func TestSessionExpiryAndLogout(t *testing.T) {
	e := newEnv(t)
	res := e.setup()
	a := e.adminClient(res)
	if w := a.do("GET", "/admin/api/overview", nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := a.do("POST", "/admin/api/logout", nil); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := a.do("GET", "/admin/api/overview", nil); w.Code != 401 {
		t.Fatalf("session usable after logout: %d", w.Code)
	}
	// Idle timeout.
	res2 := e.login()
	e.advance(13 * time.Hour)
	if w := res2.do("GET", "/admin/api/overview", nil); w.Code != 401 {
		t.Fatalf("idle session accepted: %d", w.Code)
	}
}

func (e *env) login() *adminClient {
	e.t.Helper()
	w := e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: testPassword}, remote: "192.0.2.200:1"})
	if w.Code != 200 {
		e.t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	return &adminClient{e: e, cookie: w.Result().Cookies()[0], csrf: decode[map[string]string](e.t, w)["csrf"]}
}

func TestAdminOverviewImagesAndDelete(t *testing.T) {
	e := newEnv(t)
	res := e.setup()
	a := e.adminClient(res)
	var urls []uploadResponse
	for i := 0; i < 3; i++ {
		u, _ := e.mustUpload(res.resp.Token)
		urls = append(urls, u)
	}
	ov := decode[map[string]any](t, a.do("GET", "/admin/api/overview", nil))
	if ov["images"].(float64) != 3 || ov["tokens"].(float64) != 1 || ov["upload_url"] != publicURL+"/api/v1/images" {
		t.Fatalf("%v", ov)
	}
	list := decode[struct {
		Images  []imageView `json:"images"`
		HasMore bool        `json:"has_more"`
	}](t, a.do("GET", "/admin/api/images", nil))
	if len(list.Images) != 3 || list.HasMore || list.Images[0].Token != "test" {
		t.Fatalf("%+v", list)
	}
	id := list.Images[0].ID
	if w := a.do("DELETE", "/admin/api/images/"+id, nil); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := a.do("DELETE", "/admin/api/images/"+id, nil); w.Code != 404 {
		t.Fatalf("double delete: %d", w.Code)
	}
	if w := a.do("DELETE", "/admin/api/images/not-an-id", nil); w.Code != 404 {
		t.Fatal(w.Code)
	}
	gone := 0
	for _, u := range urls {
		if e.get(pathOf(t, u.URL)).Code == 404 {
			gone++
		}
	}
	if gone != 1 {
		t.Fatalf("%d images gone, want 1", gone)
	}
	// Paging past the end is harmless.
	if w := a.do("GET", "/admin/api/images?page=999999999999", nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestAdminTokens(t *testing.T) {
	e := newEnv(t)
	a := e.adminClient(e.setup())
	w := a.do("POST", "/admin/api/tokens", createTokenRequest{Name: "ci"})
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	created := decode[map[string]string](t, w)
	if !strings.HasPrefix(created["token"], "dvs_") {
		t.Fatal(created)
	}
	if up := e.upload(pngBytes(t, 4, 4), created["token"]); up.Code != 201 {
		t.Fatal(up.Code)
	}
	list := decode[map[string][]tokenView](t, a.do("GET", "/admin/api/tokens", nil))["tokens"]
	if len(list) != 2 {
		t.Fatalf("%v", list)
	}
	for _, tv := range list {
		if tv.Name == "ci" && tv.LastUsedAt == "" {
			t.Fatal("last_used_at not tracked")
		}
	}
	// The listing never includes secrets or hashes.
	raw := a.do("GET", "/admin/api/tokens", nil).Body.String()
	if strings.Contains(raw, created["token"]) || strings.Contains(raw, ids.Hash(created["token"])) {
		t.Fatal("token secret or hash in listing")
	}
	if w := a.do("DELETE", "/admin/api/tokens/"+created["id"], nil); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := a.do("DELETE", "/admin/api/tokens/"+created["id"], nil); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := a.do("DELETE", "/admin/api/tokens/..%2f..", nil); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestAdminSettingsRoundTrip(t *testing.T) {
	e := newEnv(t)
	a := e.adminClient(e.setup())
	v := decode[settingsView](t, a.do("GET", "/admin/api/settings", nil))
	if v.PublicURL != publicURL || v.RetentionDays != 90 || v.StorageKind != "local" || !v.AuthRequired {
		t.Fatalf("%+v", v)
	}
	in := v.settingsInput
	in.RetentionDays = 7
	in.UploadsPerHour = 5
	in.MaxTotalBytes = 1 << 30
	w := a.do("PUT", "/admin/api/settings", in)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// Takes effect immediately, including after a restart.
	st, _ := e.srv.sets.Current()
	if st.RetentionDays != 7 || st.UploadsPerHour != 5 || st.MaxTotalBytes != 1<<30 {
		t.Fatalf("%+v", st)
	}
	e.build()
	st, _ = e.srv.sets.Current()
	if st.RetentionDays != 7 {
		t.Fatal("settings not persisted")
	}
}

func TestAdminSettingsAreAppliedToUploads(t *testing.T) {
	e := newEnv(t)
	a := e.adminClient(e.setup())
	in := decode[settingsView](t, a.do("GET", "/admin/api/settings", nil)).settingsInput
	in.RetentionDays = 7
	in.AuthRequired = false
	if w := a.do("PUT", "/admin/api/settings", in); w.Code != 200 {
		t.Fatal(w.Code)
	}
	resp, _ := e.mustUpload("")
	if want := e.clock().AddDate(0, 0, 7).Format(time.RFC3339); resp.ExpiresAt != want {
		t.Fatalf("expires %q, want %q", resp.ExpiresAt, want)
	}
}

func TestAdminSettingsValidation(t *testing.T) {
	e := newEnv(t)
	a := e.adminClient(e.setup())
	base := decode[settingsView](t, a.do("GET", "/admin/api/settings", nil)).settingsInput
	for name, mod := range map[string]func(*settingsInput){
		"url":       func(s *settingsInput) { s.PublicURL = "javascript:alert(1)" },
		"retention": func(s *settingsInput) { s.RetentionDays = 100000 },
		"limits":    func(s *settingsInput) { s.UploadsPerHour = 0 },
		"kind":      func(s *settingsInput) { s.StorageKind = "nfs" },
	} {
		in := base
		mod(&in)
		if w := a.do("PUT", "/admin/api/settings", in); w.Code != 400 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if st, _ := e.srv.sets.Current(); st.PublicURL != publicURL || st.RetentionDays != 90 {
		t.Fatal("invalid settings were applied")
	}
}

func TestStorageCannotMoveWhileImagesExist(t *testing.T) {
	e := newEnv(t, withKey(make32()))
	res := e.setup()
	a := e.adminClient(res)
	e.mustUpload(res.resp.Token)
	in := decode[settingsView](t, a.do("GET", "/admin/api/settings", nil)).settingsInput
	in.StorageKind = "s3"
	in.S3 = s3Input{Endpoint: "http://127.0.0.1:1", Bucket: "b", AccessKey: "k", SecretKey: "s", PathStyle: true}
	w := a.do("PUT", "/admin/api/settings", in)
	if w.Code != 409 || errCode(t, w) != "storage_in_use" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if e.srv.Store().Kind() != "local" {
		t.Fatal("storage switched anyway")
	}
}

func TestSettingsViewNeverExposesTheSecret(t *testing.T) {
	e := newEnv(t, withKey(make32()))
	be := newFakeS3(t)
	a := e.adminClient(e.setup(be.useS3("my-super-secret")))
	raw := a.do("GET", "/admin/api/settings", nil).Body.String()
	if strings.Contains(raw, "my-super-secret") {
		t.Fatal("settings API leaks the storage secret")
	}
	v := decode[settingsView](t, a.do("GET", "/admin/api/settings", nil))
	if !v.S3SecretSet || v.S3.SecretKey != "" {
		t.Fatalf("%+v", v)
	}
	// Saving with an empty secret field keeps the stored one.
	in := v.settingsInput
	in.RetentionDays = 30
	if w := a.do("PUT", "/admin/api/settings", in); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if cur, _ := e.srv.sets.Current(); cur.S3.SecretKey != "my-super-secret" {
		t.Fatal("blank secret field overwrote the stored secret")
	}
}

func TestChangePassword(t *testing.T) {
	e := newEnv(t)
	res := e.setup()
	a := e.adminClient(res)
	other := e.login()

	if w := a.do("POST", "/admin/api/password", passwordRequest{Current: "wrong", New: "a-new-long-password"}); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := a.do("POST", "/admin/api/password", passwordRequest{Current: testPassword, New: "short"}); w.Code != 400 {
		t.Fatal(w.Code)
	}
	w := a.do("POST", "/admin/api/password", passwordRequest{Current: testPassword, New: "a-new-long-password"})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if o := other.do("GET", "/admin/api/overview", nil); o.Code != 401 {
		t.Fatalf("another session survived a password change: %d", o.Code)
	}
	if o := a.do("GET", "/admin/api/overview", nil); o.Code != 401 {
		t.Fatal("old session survived")
	}
	fresh := &adminClient{e: e, cookie: w.Result().Cookies()[0], csrf: decode[map[string]string](t, w)["csrf"]}
	if o := fresh.do("GET", "/admin/api/overview", nil); o.Code != 200 {
		t.Fatalf("session issued by the change is unusable: %d", o.Code)
	}
	if lw := e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: testPassword}, remote: "192.0.2.50:1"}); lw.Code != 401 {
		t.Fatal("old password still works")
	}
	if lw := e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: "a-new-long-password"}, remote: "192.0.2.51:1"}); lw.Code != 200 {
		t.Fatal("new password rejected")
	}
}

func TestAdminPageServed(t *testing.T) {
	e := newEnv(t)
	e.setup()
	w := e.get("/admin")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `/static/admin.js`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d", w.Code)
	}
}
