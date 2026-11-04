package settings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/degenview/snapshots/internal/config"
	"github.com/degenview/snapshots/internal/db"
	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/storage"
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

func valid() Settings {
	s := Defaults()
	s.PublicURL = "https://snaps.example.com"
	return s
}

func s3Settings() Settings {
	s := valid()
	s.StorageKind = storage.KindS3
	s.S3 = S3{Endpoint: "https://nyc3.digitaloceanspaces.com", Region: "nyc3", Bucket: "b", AccessKey: "AK", SecretKey: "very-secret-value", Prefix: "x/"}
	return s
}

var key = bytes.Repeat([]byte{7}, 32)

func TestDefaultsAreSafe(t *testing.T) {
	d := Defaults()
	if !d.AuthRequired || d.RetentionDays != 90 || d.MaxImageBytes != 24<<20 || d.StorageKind != storage.KindLocal {
		t.Fatalf("%+v", d)
	}
	d.PublicURL = "https://x.example"
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]func(*Settings){
		"no url":          func(s *Settings) { s.PublicURL = "" },
		"http url":        func(s *Settings) { s.PublicURL = "http://example.com" },
		"neg retention":   func(s *Settings) { s.RetentionDays = -1 },
		"huge retention":  func(s *Settings) { s.RetentionDays = 99999 },
		"tiny image":      func(s *Settings) { s.MaxImageBytes = 10 },
		"huge image":      func(s *Settings) { s.MaxImageBytes = 1 << 40 },
		"neg quota":       func(s *Settings) { s.MaxTotalBytes = -1 },
		"zero uploads":    func(s *Settings) { s.UploadsPerHour = 0 },
		"zero views":      func(s *Settings) { s.ViewsPerMinute = 0 },
		"unknown storage": func(s *Settings) { s.StorageKind = "ftp" },
		"s3 no bucket":    func(s *Settings) { *s = s3Settings(); s.S3.Bucket = "" },
	}
	for name, mod := range cases {
		s := valid()
		mod(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	s := valid()
	s.PublicURL = "https://x.example///"
	s.RetentionDays = 0
	if err := s.Validate(); err != nil || s.PublicURL != "https://x.example" {
		t.Fatalf("%v %q", err, s.PublicURL)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	r := newRepo(t)
	st := NewStore(r, key)
	if _, found, err := st.Load(ctx); err != nil || found {
		t.Fatalf("fresh load: %v %v", found, err)
	}
	want := s3Settings()
	want.MaxTotalBytes = 1 << 30
	if _, err := st.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := NewStore(r, key).Load(ctx)
	if err != nil || !found {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	if cur, ok := st.Current(); !ok || cur != want {
		t.Fatal("Current not updated")
	}
}

func TestSecretIsEncryptedAtRest(t *testing.T) {
	r := newRepo(t)
	st := NewStore(r, key)
	if _, err := st.Save(ctx, s3Settings()); err != nil {
		t.Fatal(err)
	}
	raw, _ := r.GetSetting(ctx, SettingsKey())
	if strings.Contains(raw, "very-secret-value") {
		t.Fatal("secret stored in clear")
	}
	var generic map[string]any
	json.Unmarshal([]byte(raw), &generic)
	if _, ok := generic["s3_secret_sealed"]; !ok {
		t.Fatalf("no sealed field: %s", raw)
	}
	// Wrong key cannot read it; tampering is detected.
	if _, _, err := NewStore(r, bytes.Repeat([]byte{8}, 32)).Load(ctx); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
	if _, _, err := NewStore(r, nil).Load(ctx); !errors.Is(err, ErrNoSecretKey) {
		t.Fatalf("err = %v", err)
	}
	tampered := strings.Replace(raw, `"s3_secret_sealed":"v1:`, `"s3_secret_sealed":"v1:AAAA`, 1)
	r.SetSetting(ctx, SettingsKey(), tampered)
	if _, _, err := NewStore(r, key).Load(ctx); err == nil {
		t.Fatal("tampered secret accepted")
	}
}

func TestSealingIsRandomised(t *testing.T) {
	a, _ := seal(key, []byte("x"))
	b, _ := seal(key, []byte("x"))
	if a == b {
		t.Fatal("nonce reused")
	}
	if _, err := open(key, "garbage"); err == nil {
		t.Fatal()
	}
	if _, err := open(key, "v1:"); err == nil {
		t.Fatal()
	}
}

func TestLocalStorageNeedsNoKey(t *testing.T) {
	st := NewStore(newRepo(t), nil)
	if st.CanSeal() {
		t.Fatal()
	}
	if _, err := st.Save(ctx, valid()); err != nil {
		t.Fatalf("local settings need no secret key: %v", err)
	}
	if _, err := st.Save(ctx, s3Settings()); !errors.Is(err, ErrNoSecretKey) {
		t.Fatalf("S3 secret saved without a key: %v", err)
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	st := NewStore(newRepo(t), key)
	bad := valid()
	bad.RetentionDays = -5
	if _, err := st.Save(ctx, bad); err == nil {
		t.Fatal()
	}
	if _, found, _ := st.Load(ctx); found {
		t.Fatal("invalid settings were stored")
	}
}

func TestSecretNeverInJSONOfSettings(t *testing.T) {
	b, _ := json.Marshal(s3Settings())
	if strings.Contains(string(b), "very-secret-value") {
		t.Fatal("Settings marshals the secret; the admin API would leak it")
	}
}

func TestCorruptDocument(t *testing.T) {
	r := newRepo(t)
	r.SetSetting(ctx, SettingsKey(), "{not json")
	if _, _, err := NewStore(r, key).Load(ctx); err == nil {
		t.Fatal()
	}
}

func TestResolveKey(t *testing.T) {
	// 1. SECRET_KEY wins.
	cfg := &config.Config{SecretKey: key, DataDir: t.TempDir()}
	if k, err := ResolveKey(cfg); err != nil || !bytes.Equal(k, key) {
		t.Fatal(err)
	}
	// 2. Postgres without SECRET_KEY: no key (never invent one that a redeploy would lose).
	cfg = &config.Config{DatabaseURL: "postgres://x", DataDir: t.TempDir()}
	if k, err := ResolveKey(cfg); err != nil || k != nil {
		t.Fatalf("%v %v", k, err)
	}
	// 3. SQLite: generated once, then stable.
	dir := filepath.Join(t.TempDir(), "d")
	cfg = &config.Config{DataDir: dir}
	k1, err := ResolveKey(cfg)
	if err != nil || len(k1) != 32 {
		t.Fatal(err)
	}
	k2, _ := ResolveKey(cfg)
	if !bytes.Equal(k1, k2) {
		t.Fatal("key changed between calls")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(dir, "secret.key"))
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", info.Mode().Perm())
		}
	}
	// 4. A damaged key file is an error, not a silent new key.
	os.WriteFile(filepath.Join(dir, "secret.key"), []byte("zz"), 0o600)
	if _, err := ResolveKey(cfg); err == nil {
		t.Fatal("corrupt key file ignored")
	}
}
