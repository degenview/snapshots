package server

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"

	"github.com/degenview/snapshots/internal/config"
)

func make32() []byte { return bytes.Repeat([]byte{9}, 32) }

type fakeS3 struct {
	url string
	be  *s3mem.Backend
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	be := s3mem.New()
	if err := be.CreateBucket("snaps"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gofakes3.New(be).Server())
	t.Cleanup(srv.Close)
	return &fakeS3{url: srv.URL, be: be}
}

func (f *fakeS3) useS3(secret string) setupOpts {
	return func(r *setupCompleteRequest) {
		r.StorageKind = "s3"
		r.S3 = s3Input{Endpoint: f.url, Region: "us-east-1", Bucket: "snaps", AccessKey: "AK", SecretKey: secret, PathStyle: true, Prefix: "dv/"}
	}
}

func TestS3EndToEnd(t *testing.T) {
	e := newEnv(t, withKey(make32()))
	be := newFakeS3(t)
	res := e.setup(be.useS3("s3-secret-value"))
	if e.srv.Store().Kind() != "s3" {
		t.Fatal(e.srv.Store().Kind())
	}
	// The sealed secret is what reached the database.
	raw, _ := e.repo.GetSetting(ctxBG, "config")
	if strings.Contains(raw, "s3-secret-value") {
		t.Fatal("S3 secret stored in clear")
	}

	resp, _ := e.mustUpload(res.resp.Token)
	id := strings.TrimPrefix(pathOf(t, resp.URL), "/i/")
	if _, err := be.be.HeadObject("snaps", "dv/"+id+".png"); err != nil {
		t.Fatalf("object not in bucket: %v", err)
	}
	got := e.get(pathOf(t, resp.URL))
	if got.Code != 200 || got.Body.Len() == 0 {
		t.Fatalf("%d", got.Code)
	}
	if r := e.do(req{method: "GET", path: pathOf(t, resp.URL), headers: map[string]string{"Range": "bytes=0-3"}}); r.Code != 206 {
		t.Fatalf("range from S3: %d", r.Code)
	}

	// Owner deletion removes the object from the bucket.
	if w := e.do(req{method: "POST", path: pathOf(t, resp.DeleteURL)}); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	if _, err := be.be.HeadObject("snaps", "dv/"+id+".png"); err == nil {
		t.Fatal("object left in bucket after delete")
	}

	// A restart re-reads and decrypts the stored configuration.
	e.build()
	if e.srv.Store().Kind() != "s3" {
		t.Fatal("S3 configuration lost on restart")
	}
	if w := e.upload(pngBytes(t, 6, 6), res.resp.Token); w.Code != 201 {
		t.Fatalf("after restart: %d", w.Code)
	}
}

func TestSetupRefusesS3WithoutSecretKey(t *testing.T) {
	e := newEnv(t) // no key
	be := newFakeS3(t)
	body := defaultSetup()
	be.useS3("x")(&body)
	w := e.do(req{method: "POST", path: "/setup/complete", json: body})
	if w.Code != 400 || errCode(t, w) != "no_secret_key" || e.srv.Configured() {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestSetupFailsWhenTheBucketIsUnreachable(t *testing.T) {
	e := newEnv(t, withKey(make32()))
	body := defaultSetup()
	body.StorageKind = "s3"
	body.S3 = s3Input{Endpoint: "http://127.0.0.1:1", Region: "x", Bucket: "nope", AccessKey: "k", SecretKey: "s", PathStyle: true}
	w := e.do(req{method: "POST", path: "/setup/complete", json: body})
	if w.Code != 400 || errCode(t, w) != "storage_test_failed" || e.srv.Configured() {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestSetupTestStorageEndpoint(t *testing.T) {
	e := newEnv(t, withKey(make32()))
	be := newFakeS3(t)
	body := setupTestRequest{SetupToken: testSetupTok}
	dc := defaultSetup()
	be.useS3("secret")(&dc)
	body.settingsInput = dc.settingsInput
	w := e.do(req{method: "POST", path: "/setup/test-storage", json: body})
	if r := decode[testResult](t, w); !r.OK {
		t.Fatalf("%+v", r)
	}
	body.S3.Bucket = "missing"
	w = e.do(req{method: "POST", path: "/setup/test-storage", json: body})
	if r := decode[testResult](t, w); r.OK || r.Error == "" {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(w.Body.String(), "secret") {
		t.Fatal("error text echoes the secret")
	}
	// Local test works too.
	body.StorageKind = "local"
	if r := decode[testResult](t, e.do(req{method: "POST", path: "/setup/test-storage", json: body})); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestAdminCanSwitchStorageWhenEmpty(t *testing.T) {
	e := newEnv(t, withKey(make32()))
	a := e.adminClient(e.setup())
	be := newFakeS3(t)
	in := decode[settingsView](t, a.do("GET", "/admin/api/settings", nil)).settingsInput
	dc := defaultSetup()
	be.useS3("secret")(&dc)
	in.StorageKind, in.S3 = dc.StorageKind, dc.S3
	if w := a.do("PUT", "/admin/api/settings", in); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if e.srv.Store().Kind() != "s3" {
		t.Fatal("not switched")
	}
	// A bad bucket is rejected before it replaces a working store.
	in.S3.Bucket = "missing"
	if w := a.do("PUT", "/admin/api/settings", in); w.Code != 400 {
		t.Fatalf("%d", w.Code)
	}
	if st, _ := e.srv.sets.Current(); st.S3.Bucket != "snaps" {
		t.Fatal("broken storage settings were saved")
	}
	// Test endpoint reports without saving.
	in.S3.Bucket = "snaps"
	if r := decode[testResult](t, a.do("POST", "/admin/api/settings/test-storage", in)); !r.OK {
		t.Fatalf("%+v", r)
	}
}

// Plain http:// to a host that is not this computer is refused unless the
// operator acknowledges it; loopback (the fake S3 above) always works.
func TestRemotePlaintextS3IsRefused(t *testing.T) {
	remote := s3Input{Endpoint: "http://s3.invalid:9000", Region: "us-east-1", Bucket: "snaps", AccessKey: "AK", SecretKey: "x", PathStyle: true}

	e := newEnv(t, withKey(make32()))
	w := e.do(req{method: "POST", path: "/setup/complete", json: func() setupCompleteRequest {
		b := defaultSetup()
		b.StorageKind, b.S3 = "s3", remote
		return b
	}()})
	if w.Code != 400 || errCode(t, w) != "storage_test_failed" || !strings.Contains(w.Body.String(), "ALLOW_INSECURE_BACKENDS") {
		t.Fatalf("setup with remote http S3: %d %s", w.Code, w.Body)
	}

	// With the acknowledgement the policy check passes; the test then fails for
	// the real reason (the host does not exist), not because of http://.
	e = newEnv(t, withKey(make32()), func(c *config.Config, _ *env) { c.AllowInsecureBackends = true })
	b := defaultSetup()
	b.StorageKind, b.S3 = "s3", remote
	w = e.do(req{method: "POST", path: "/setup/complete", json: b})
	if w.Code != 400 || strings.Contains(w.Body.String(), "ALLOW_INSECURE_BACKENDS") {
		t.Fatalf("setup with the override: %d %s", w.Code, w.Body)
	}
}

// A storage change must wait for uploads in flight. Otherwise "no images here"
// can turn false right after the check and strand the new image in the old store.
func TestStorageSwitchWaitsForUploadsInFlight(t *testing.T) {
	e := newEnv(t, withKey(make32()))
	res := e.setup()
	a := e.adminClient(res)
	be := newFakeS3(t)

	inserted := make(chan struct{})
	release := make(chan struct{})
	e.srv.testBeforePut = func() {
		close(inserted)
		<-release
	}

	uploaded := make(chan int, 1)
	go func() { uploaded <- e.upload(pngBytes(t, 8, 8), res.resp.Token).Code }()
	<-inserted // the row exists, the object is not written yet

	in := decode[settingsView](t, a.do("GET", "/admin/api/settings", nil)).settingsInput
	in.StorageKind = "s3"
	in.S3 = s3Input{Endpoint: be.url, Region: "us-east-1", Bucket: "snaps", AccessKey: "AK", SecretKey: "s3-secret-value", PathStyle: true}
	switched := make(chan *httptest.ResponseRecorder, 1)
	go func() { switched <- a.do("PUT", "/admin/api/settings", in) }()

	select {
	case w := <-switched:
		t.Fatalf("storage changed while an upload was in flight: %d %s", w.Code, w.Body)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)

	if code := <-uploaded; code != 201 {
		t.Fatalf("upload: %d", code)
	}
	w := <-switched
	if w.Code != 409 || errCode(t, w) != "storage_in_use" {
		t.Fatalf("switch after the upload: %d %s", w.Code, w.Body)
	}
	if e.srv.Store().Kind() != "local" {
		t.Fatal("storage switched anyway")
	}
}
