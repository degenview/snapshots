package server

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/degenview/snapshots/internal/ids"
)

func TestServeVariants(t *testing.T) {
	e := newEnv(t)
	tok := e.setup().resp.Token
	resp, data := e.mustUpload(tok)
	p := pathOf(t, resp.URL)

	// With the .png suffix.
	if w := e.get(p + ".png"); w.Code != 200 {
		t.Fatalf(".png: %d", w.Code)
	}
	// HEAD: headers, no body.
	w := e.do(req{method: "HEAD", path: p})
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Type") != "image/png" || w.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD: %d len=%d", w.Code, w.Body.Len())
	}
	// Conditional request.
	etag := e.get(p).Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	if w := e.do(req{method: "GET", path: p, headers: map[string]string{"If-None-Match": etag}}); w.Code != 304 {
		t.Fatalf("If-None-Match: %d", w.Code)
	}
	// Range.
	w = e.do(req{method: "GET", path: p, headers: map[string]string{"Range": "bytes=0-7"}})
	if w.Code != 206 || !bytes.Equal(w.Body.Bytes(), data[:8]) {
		t.Fatalf("range: %d %q", w.Code, w.Body.Bytes())
	}
}

func TestServeCrossOriginEmbedding(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.mustUpload(e.setup().resp.Token)
	h := e.get(pathOf(t, resp.URL)).Header()
	// Shared links are embedded on other sites (chat, social cards), so images allow it.
	if h.Get("Cross-Origin-Resource-Policy") != "cross-origin" {
		t.Fatal("CORP blocks embedding")
	}
}

func TestExpiredAndUnknownAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	tok := e.setup(func(r *setupCompleteRequest) { r.RetentionDays = 1 }).resp.Token
	resp, _ := e.mustUpload(tok)
	p := pathOf(t, resp.URL)
	if w := e.get(p); w.Code != 200 {
		t.Fatal(w.Code)
	}
	e.advance(24*time.Hour - time.Second)
	if w := e.get(p); w.Code != 200 {
		t.Fatalf("expired a second early: %d", w.Code)
	}
	e.advance(time.Second)
	expired := e.get(p)
	unknown, _ := ids.ImageID()
	missing := e.get("/i/" + unknown)
	if expired.Code != 404 || missing.Code != 404 {
		t.Fatalf("expired %d, unknown %d", expired.Code, missing.Code)
	}
	if expired.Body.String() != missing.Body.String() || expired.Header().Get("Content-Type") != missing.Header().Get("Content-Type") {
		t.Fatal("responses differ: expiry is observable")
	}
	// Expired images are never served even though the janitor has not run.
	if _, err := e.repo.GetImage(context.Background(), strings.TrimPrefix(p, "/i/")); err != nil {
		t.Fatal("test premise: row still present")
	}
}

func TestCacheControlNeverOutlivesExpiry(t *testing.T) {
	e := newEnv(t)
	tok := e.setup(func(r *setupCompleteRequest) { r.RetentionDays = 1 }).resp.Token
	resp, _ := e.mustUpload(tok)
	e.advance(24*time.Hour - 90*time.Second)
	cc := e.get(pathOf(t, resp.URL)).Header().Get("Cache-Control")
	if cc != "public, max-age=90" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestMalformedImageIDsAre404(t *testing.T) {
	e := newEnv(t)
	e.setup()
	for _, id := range []string{"x", "..", "%2e%2e", "..%2fetc%2fpasswd", "abcdefghij1", "abcdefghi", "abcdefghi%00", "' OR 1=1 --", "abc defghi", "abcdefghij.png.png", "abcdefghij.jpg"} {
		// 307 is the mux cleaning a ".." path: it never reaches a handler.
		if w := e.get("/i/" + url.PathEscape(id)); w.Code != 404 && w.Code != 400 && w.Code != 307 {
			t.Errorf("/i/%s → %d", id, w.Code)
		}
	}
	if w := e.do(req{method: "POST", path: "/i/abcdefghij"}); w.Code != 405 {
		t.Errorf("POST /i: %d", w.Code)
	}
}

// --- delete flow & IDOR ---------------------------------------------------------------

func TestDeleteWithSecret(t *testing.T) {
	e := newEnv(t)
	tok := e.setup().resp.Token
	a, _ := e.mustUpload(tok)
	b, _ := e.mustUpload(tok)

	// GET only confirms: link scanners must not delete anything.
	w := e.get(pathOf(t, a.DeleteURL))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<form method=\"post\">") {
		t.Fatalf("%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `src="`+pathOf(t, a.URL)+`"`) {
		t.Fatal("confirmation page should preview the image")
	}
	if w := e.get(pathOf(t, a.URL)); w.Code != 200 {
		t.Fatal("GET on the delete link deleted the image")
	}

	if w := e.do(req{method: "POST", path: pathOf(t, a.DeleteURL)}); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	if w := e.get(pathOf(t, a.URL)); w.Code != 404 {
		t.Fatalf("image still served after delete: %d", w.Code)
	}
	// The object is gone from storage, not just hidden.
	id := strings.TrimPrefix(pathOf(t, a.URL), "/i/")
	if f, err := e.srv.Store().Open(context.Background(), id); err == nil {
		f.Close()
		t.Fatal("object still in storage")
	}
	// The other image is untouched (no cross-talk between delete links).
	if w := e.get(pathOf(t, b.URL)); w.Code != 200 {
		t.Fatalf("deleting A removed B: %d", w.Code)
	}
	// The link is single-use.
	if w := e.do(req{method: "POST", path: pathOf(t, a.DeleteURL)}); w.Code != 404 {
		t.Fatalf("second delete: %d", w.Code)
	}
}

func TestDeleteCannotBeDoneWithTheImageID(t *testing.T) {
	e := newEnv(t)
	tok := e.setup().resp.Token
	a, _ := e.mustUpload(tok)
	imageID := strings.TrimPrefix(pathOf(t, a.URL), "/i/")
	// The public id is 10 chars, a secret is 24: neither shape works as the other.
	for _, guess := range []string{imageID, imageID + strings.Repeat("a", 14), strings.Repeat("a", 24), ids.Hash(imageID)[:24]} {
		if w := e.do(req{method: "POST", path: "/d/" + guess}); w.Code != 404 {
			t.Errorf("POST /d/%s: %d", guess, w.Code)
		}
	}
	if w := e.get(pathOf(t, a.URL)); w.Code != 200 {
		t.Fatal("image was deleted by a guess")
	}
}

func TestDeleteSecretIsNotStoredInClear(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.mustUpload(e.setup().resp.Token)
	secret := strings.TrimPrefix(pathOf(t, resp.DeleteURL), "/d/")
	imgs, _ := e.repo.ListImages(context.Background(), 10, 0)
	if len(imgs) != 1 || imgs[0].DeleteHash == secret || imgs[0].DeleteHash != ids.Hash(secret) {
		t.Fatalf("%+v", imgs)
	}
}

func TestDeleteRateLimited(t *testing.T) {
	e := newEnv(t)
	e.setup()
	var last int
	for i := 0; i < 15; i++ {
		last = e.do(req{method: "POST", path: "/d/" + strings.Repeat("a", 24)}).Code
	}
	if last != 429 {
		t.Fatalf("delete-secret guessing not throttled: %d", last)
	}
}

func TestDeletePagesAreNotIndexableOrCacheable(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.mustUpload(e.setup().resp.Token)
	h := e.get(pathOf(t, resp.DeleteURL)).Header()
	if h.Get("Cache-Control") != "no-store" || !strings.Contains(h.Get("X-Robots-Tag"), "noindex") || h.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("%v", h)
	}
}

// --- headers & logs -------------------------------------------------------------------

func TestSecurityHeadersOnPages(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/setup", "/healthz", "/static/app.css", "/nope"} {
		h := e.get(p).Header()
		for _, k := range []string{"X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Content-Security-Policy", "X-Request-Id",
			"Cross-Origin-Resource-Policy", "X-Permitted-Cross-Domain-Policies"} {
			if h.Get(k) == "" {
				t.Errorf("%s: missing %s", p, k)
			}
		}
	}
	if got := e.get("/setup").Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
		t.Fatalf("pages must default to CORP same-origin, got %q", got)
	}
	csp := e.get("/setup").Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Fatal("CSP allows inline code")
	}
	if e.get("/setup").Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS on a non-https configuration")
	}
}

func TestHSTSWhenHTTPS(t *testing.T) {
	e := newEnv(t)
	e.setup()
	if e.get("/").Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("no HSTS on https deployment")
	}
}

func TestPagesHaveNoInlineScriptOrStyle(t *testing.T) {
	e := newEnv(t)
	body := e.get("/setup").Body.String()
	for _, bad := range []string{"<script>", " style=", "onclick=", "javascript:"} {
		if strings.Contains(body, bad) {
			t.Errorf("setup page contains %q, which the CSP would block or which is unsafe", bad)
		}
	}
}

func TestStaticAssets(t *testing.T) {
	e := newEnv(t)
	w := e.get("/static/app.css")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w2 := e.do(req{method: "GET", path: "/static/app.css", headers: map[string]string{"If-None-Match": w.Header().Get("ETag")}}); w2.Code != 304 {
		t.Fatal(w2.Code)
	}
	for _, p := range []string{"/static/missing.css", "/static/..%2f..%2fgo.mod", "/static/templates"} {
		if w := e.get(p); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

func TestLogsNeverContainSecrets(t *testing.T) {
	e := newEnv(t)
	res := e.setup()
	resp, data := e.mustUpload(res.resp.Token)
	secret := strings.TrimPrefix(pathOf(t, resp.DeleteURL), "/d/")
	imageID := strings.TrimPrefix(pathOf(t, resp.URL), "/i/")
	e.get("/i/" + imageID)
	e.get("/d/" + secret)
	e.do(req{method: "POST", path: "/d/" + secret})
	a := e.adminClient(res)
	a.do("POST", "/admin/api/tokens", createTokenRequest{Name: "x"})
	e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: "wrong-password-here"}})
	e.do(req{method: "POST", path: "/admin/api/login", json: loginRequest{Password: testPassword}})
	e.upload(data, "dvs_"+strings.Repeat("z", 32))

	logs := e.logs.String()
	for name, secretValue := range map[string]string{
		"delete secret": secret, "image id": imageID, "upload token": res.resp.Token, "admin password": testPassword,
		"wrong password": "wrong-password-here", "session cookie": res.cookie.Value, "csrf": res.resp.CSRF, "image bytes": string(data[:16]),
	} {
		if strings.Contains(logs, secretValue) {
			t.Errorf("logs contain the %s", name)
		}
	}
	if !strings.Contains(logs, `"/d/:secret"`) || !strings.Contains(logs, `"/i/:id"`) {
		t.Fatal("expected redacted paths in the log")
	}
}

func TestRedactPath(t *testing.T) {
	for in, want := range map[string]string{
		"/d/abc": "/d/:secret", "/i/abc.png": "/i/:id", "/admin/api/images/x": "/admin/api/images/:id",
		"/admin/api/tokens/x": "/admin/api/tokens/:id", "/healthz": "/healthz", "/" + strings.Repeat("a", 300): "/" + strings.Repeat("a", 119),
	} {
		if got := redactPath(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestPanicIsContained(t *testing.T) {
	e := newEnv(t)
	h := e.srv.withRecover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w := newRecorder()
	h.ServeHTTP(w, newRequest("GET", "/"))
	if w.Code != 500 || strings.Contains(w.Body.String(), "boom") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
