package auth

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/degenview/snapshots/internal/db"
	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/repo"
)

var ctx = context.Background()

func newRepo(t *testing.T) *repo.Repo {
	t.Helper()
	d, err := db.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return repo.New(d)
}

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatal(h)
	}
	if !VerifyPassword("correct horse battery", h) {
		t.Fatal("right password refused")
	}
	if VerifyPassword("correct horse batterY", h) || VerifyPassword("", h) {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	good, _ := HashPassword("correct horse battery")
	parts := strings.Split(good, "$")
	bad := []string{
		"", "plain", "$argon2id$", "$bcrypt$v=19$m=1,t=1,p=1$YQ$YQ",
		"$argon2id$v=18$m=65536,t=2,p=2$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=999999999,t=2,p=2$" + parts[4] + "$" + parts[5], // memory bomb
		"$argon2id$v=19$m=65536,t=999,p=2$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=65536,t=2,p=0$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=0,t=2,p=2$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=65536,t=2,p=2$!!!$" + parts[5],
		"$argon2id$v=19$m=65536,t=2,p=2$" + parts[4] + "$",
	}
	for _, b := range bad {
		if VerifyPassword("correct horse battery", b) {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if ValidatePassword("short") == nil {
		t.Fatal()
	}
	if ValidatePassword("exactly12chr") != nil {
		t.Fatal()
	}
	if ValidatePassword("ééééééééééé") == nil { // 11 runes, 22 bytes
		t.Fatal("rune count should apply")
	}
	if ValidatePassword(strings.Repeat("x", 257)) == nil {
		t.Fatal("too long accepted")
	}
}

func TestTokens(t *testing.T) {
	r := newRepo(t)
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	tk := &Tokens{Repo: r, Now: func() time.Time { return now }}
	plain, rec, err := tk.Issue(ctx, "  laptop  ")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "laptop" || rec.Hash == plain || rec.Hash != ids.Hash(plain) {
		t.Fatalf("%+v", rec)
	}
	got, err := tk.Authenticate(ctx, plain)
	if err != nil || got.ID != rec.ID {
		t.Fatal(err)
	}
	stored, _ := r.FindToken(ctx, rec.Hash)
	if !stored.LastUsedAt.Equal(now) {
		t.Fatal("use not recorded")
	}
	other, _ := ids.Token()
	for _, bad := range []string{"", plain + "x", plain[:len(plain)-1], other, strings.ToUpper(plain), "Bearer " + plain, rec.ID, rec.Hash, "' OR 1=1 --"} {
		if _, err := tk.Authenticate(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("Authenticate(%q) = %v", bad, err)
		}
	}
	// Revoking works at once.
	if err := r.DeleteToken(ctx, rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tk.Authenticate(ctx, plain); !errors.Is(err, ErrInvalid) {
		t.Fatal("revoked token accepted")
	}
}

func TestTokenNames(t *testing.T) {
	tk := &Tokens{}
	rec, _ := tk.Build("", "x")
	if rec.Name != "Untitled" {
		t.Fatal(rec.Name)
	}
	rec, _ = tk.Build(strings.Repeat("é", 100), "x")
	if len([]rune(rec.Name)) != 60 {
		t.Fatal(len([]rune(rec.Name)))
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]struct {
		tok string
		ok  bool
	}{
		"Bearer abc":   {"abc", true},
		"bearer abc":   {"abc", true},
		"BEARER  abc ": {"abc", true},
		"Basic abc":    {"", false},
		"Bearer":       {"", false},
		"Bearer ":      {"", false},
		"":             {"", false},
		"abc":          {"", false},
	}
	for h, want := range cases {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		tok, ok := BearerToken(r)
		if tok != want.tok || ok != want.ok {
			t.Errorf("%q → %q %v", h, tok, ok)
		}
	}
}

func TestSessionLifecycle(t *testing.T) {
	r := newRepo(t)
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewSessions(r)
	s.Now = func() time.Time { return now }
	cookie, sess, err := s.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cookie) != 43 || sess.IDHash == cookie || sess.CSRF == "" {
		t.Fatalf("%q %+v", cookie, sess)
	}
	got, err := s.Validate(ctx, cookie)
	if err != nil || got.CSRF != sess.CSRF {
		t.Fatal(err)
	}
	// Activity within the idle window keeps it alive, past the absolute limit it dies.
	for i := 0; i < 20; i++ {
		now = now.Add(11 * time.Hour)
		if _, err := s.Validate(ctx, cookie); err != nil {
			if now.Sub(sess.CreatedAt) < s.Absolute {
				t.Fatalf("session died early at %v: %v", now.Sub(sess.CreatedAt), err)
			}
			return
		}
	}
	t.Fatal("session outlived the absolute limit")
}

func TestSessionIdleTimeout(t *testing.T) {
	r := newRepo(t)
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewSessions(r)
	s.Now = func() time.Time { return now }
	cookie, _, _ := s.Create(ctx)
	now = now.Add(13 * time.Hour)
	if _, err := s.Validate(ctx, cookie); !errors.Is(err, ErrInvalid) {
		t.Fatalf("idle session accepted: %v", err)
	}
	now = now.Add(-time.Hour)
	if _, err := s.Validate(ctx, cookie); !errors.Is(err, ErrInvalid) {
		t.Fatal("expired session must be deleted, not just refused once")
	}
}

func TestSessionRejectsForgeries(t *testing.T) {
	r := newRepo(t)
	s := NewSessions(r)
	cookie, sess, _ := s.Create(ctx)
	for _, bad := range []string{"", "x", cookie + "x", cookie[:42], sess.IDHash, sess.CSRF, strings.Repeat("a", 43), "' OR 1=1 --" + strings.Repeat("a", 32)} {
		if _, err := s.Validate(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("Validate(%q) = %v", bad, err)
		}
	}
	s.Destroy(ctx, cookie)
	if _, err := s.Validate(ctx, cookie); !errors.Is(err, ErrInvalid) {
		t.Fatal("destroyed session accepted")
	}
}

func TestSessionPrune(t *testing.T) {
	r := newRepo(t)
	now := time.Now().UTC()
	s := NewSessions(r)
	s.Now = func() time.Time { return now }
	cookie, _, _ := s.Create(ctx)
	now = now.Add(8 * 24 * time.Hour)
	if err := s.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSession(ctx, ids.Hash(cookie)); !errors.Is(err, repo.ErrNotFound) {
		t.Fatal("not pruned")
	}
}

func req(method string, hdr map[string]string) *http.Request {
	r, _ := http.NewRequest(method, "https://snaps.example.com/admin/api/x", nil)
	r.Host = "snaps.example.com"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestCheckCSRF(t *testing.T) {
	sess := repo.Session{CSRF: "tok123"}
	ok := map[string]string{"X-CSRF-Token": "tok123"}
	cases := []struct {
		name string
		hdr  map[string]string
		ok   bool
	}{
		{"token only", ok, true},
		{"same-origin fetch", map[string]string{"X-CSRF-Token": "tok123", "Sec-Fetch-Site": "same-origin", "Origin": "https://snaps.example.com"}, true},
		{"no token", map[string]string{}, false},
		{"wrong token", map[string]string{"X-CSRF-Token": "nope"}, false},
		{"cross-site", map[string]string{"X-CSRF-Token": "tok123", "Sec-Fetch-Site": "cross-site"}, false},
		{"same-site subdomain", map[string]string{"X-CSRF-Token": "tok123", "Sec-Fetch-Site": "same-site"}, false},
		{"foreign origin", map[string]string{"X-CSRF-Token": "tok123", "Origin": "https://evil.example"}, false},
		{"origin lookalike", map[string]string{"X-CSRF-Token": "tok123", "Origin": "https://snaps.example.com.evil.example"}, false},
		{"null origin", map[string]string{"X-CSRF-Token": "tok123", "Origin": "null"}, false},
	}
	for _, c := range cases {
		if got := CheckCSRF(req("POST", c.hdr), sess) == nil; got != c.ok {
			t.Errorf("%s: ok=%v", c.name, got)
		}
	}
}

func TestCheckSameOrigin(t *testing.T) {
	if CheckSameOrigin(req("POST", nil)) != nil {
		t.Fatal("plain request refused")
	}
	if CheckSameOrigin(req("POST", map[string]string{"Origin": "https://snaps.example.com"})) != nil {
		t.Fatal()
	}
	if CheckSameOrigin(req("POST", map[string]string{"Origin": "https://evil.example"})) == nil {
		t.Fatal()
	}
	if CheckSameOrigin(req("POST", map[string]string{"Sec-Fetch-Site": "cross-site"})) == nil {
		t.Fatal()
	}
}

func TestEqualAndSetupToken(t *testing.T) {
	a, _ := NewSetupToken()
	b, _ := NewSetupToken()
	if len(a) != 24 || a == b || !Equal(a, a) || Equal(a, b) || Equal(a, "") {
		t.Fatal()
	}
}
