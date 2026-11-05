package config

import (
	"log/slog"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8080" || c.DataDir != "./data" || c.LogFormat != "json" || c.LogLevel != slog.LevelInfo {
		t.Fatalf("%+v", c)
	}
	if c.IsPostgres() || c.SQLitePath() != "data/snapshots.db" || c.SecretKey != nil {
		t.Fatalf("%+v", c)
	}
}

func TestPortFallback(t *testing.T) {
	c, _ := Load(env(map[string]string{"PORT": "9000"}))
	if c.ListenAddr != ":9000" {
		t.Fatal(c.ListenAddr)
	}
	c, _ = Load(env(map[string]string{"PORT": "9000", "LISTEN_ADDR": "127.0.0.1:1"}))
	if c.ListenAddr != "127.0.0.1:1" {
		t.Fatal(c.ListenAddr)
	}
}

func TestDatabaseURL(t *testing.T) {
	c, _ := Load(env(map[string]string{"DATABASE_URL": "postgres://u:p@h/db"}))
	if !c.IsPostgres() || c.Validate() != nil {
		t.Fatal()
	}
	c, _ = Load(env(map[string]string{"DATABASE_URL": "sqlite:///var/x.db"}))
	if c.IsPostgres() || c.SQLitePath() != "/var/x.db" || c.Validate() != nil {
		t.Fatal(c.SQLitePath())
	}
	c, _ = Load(env(map[string]string{"DATABASE_URL": "mysql://x"}))
	if c.Validate() == nil {
		t.Fatal("mysql accepted")
	}
}

func TestSecretKey(t *testing.T) {
	if _, err := Load(env(map[string]string{"SECRET_KEY": "short"})); err == nil {
		t.Fatal("short key accepted")
	}
	c, err := Load(env(map[string]string{"SECRET_KEY": strings.Repeat("k", 40)}))
	if err != nil || len(c.SecretKey) != 32 {
		t.Fatal(err)
	}
}

func TestSetupTokenLength(t *testing.T) {
	if _, err := Load(env(map[string]string{"SETUP_TOKEN": "tiny"})); err == nil {
		t.Fatal()
	}
}

func TestProxies(t *testing.T) {
	c, err := Load(env(map[string]string{"TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.1 ,::1", "CLIENT_IP_HEADER": "X-Forwarded-For"}))
	if err != nil || len(c.TrustedProxies) != 3 {
		t.Fatal(err, c)
	}
	if c.TrustedProxies[1].Bits() != 32 {
		t.Fatal("bare address should be a /32")
	}
	if _, err := Load(env(map[string]string{"TRUSTED_PROXIES": "nope", "CLIENT_IP_HEADER": "X"})); err == nil {
		t.Fatal()
	}
	if _, err := Load(env(map[string]string{"TRUSTED_PROXIES": "10.0.0.0/8"})); err == nil {
		t.Fatal("proxies without header accepted")
	}
	if _, err := Load(env(map[string]string{"CLIENT_IP_HEADER": "X-Forwarded-For"})); err == nil {
		t.Fatal("header without proxies accepted")
	}
}

func TestTrustAnyProxy(t *testing.T) {
	c, err := Load(env(map[string]string{"TRUSTED_PROXIES": "*", "CLIENT_IP_HEADER": "Do-Connecting-IP"}))
	if err != nil || !c.TrustAnyProxy || len(c.TrustedProxies) != 0 {
		t.Fatal(err, c)
	}
	if _, err := Load(env(map[string]string{"TRUSTED_PROXIES": "*"})); err == nil {
		t.Fatal("* without a header accepted")
	}
}

func TestLogSettings(t *testing.T) {
	c, _ := Load(env(map[string]string{"LOG_LEVEL": "DEBUG", "LOG_FORMAT": "TEXT"}))
	if c.LogLevel != slog.LevelDebug || c.LogFormat != "text" {
		t.Fatal()
	}
	if _, err := Load(env(map[string]string{"LOG_LEVEL": "loud"})); err == nil {
		t.Fatal()
	}
	if _, err := Load(env(map[string]string{"LOG_FORMAT": "xml"})); err == nil {
		t.Fatal()
	}
}

func TestNormalizePublicURL(t *testing.T) {
	ok := map[string]string{
		"https://img.example.com":     "https://img.example.com",
		"https://img.example.com/":    "https://img.example.com",
		"https://example.com/snap/":   "https://example.com/snap",
		"http://localhost:8080":       "http://localhost:8080",
		"http://127.0.0.1:8080/":      "http://127.0.0.1:8080",
		"http://[::1]:8080":           "http://[::1]:8080",
		"http://dev.localhost:3000":   "http://dev.localhost:3000",
		"  https://img.example.com  ": "https://img.example.com",
	}
	for in, want := range ok {
		got, err := NormalizePublicURL(in)
		if err != nil || got != want {
			t.Errorf("%q → %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "img.example.com", "ftp://x.com", "http://example.com", "https://u:p@x.com", "https://x.com?a=b", "https://x.com#f", "https://", "javascript:alert(1)"} {
		if _, err := NormalizePublicURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := Load(env(map[string]string{"PUBLIC_URL": "http://evil.com"})); err == nil {
		t.Fatal("PUBLIC_URL not validated")
	}
}

func TestPostgresPlaintext(t *testing.T) {
	for url, want := range map[string]bool{
		"postgres://u:p@db.example.com/x":                          false, // driver default: prefer TLS
		"postgres://u:p@db.example.com/x?sslmode=require":          false,
		"postgres://u:p@db.example.com/x?sslmode=verify-full":      false,
		"postgres://u:p@db.example.com:5432/x?sslmode=disable":     true,
		"postgres://u:p@db.example.com/x?sslmode=DISABLE":          true,
		"postgres://u:p@postgres:5432/x?sslmode=disable":           true,
		"postgres://u:p@a.example.com,127.0.0.1/x?sslmode=disable": true,
		"postgres://u:p@localhost:5432/x?sslmode=disable":          false,
		"postgres://u:p@127.0.0.1/x?sslmode=disable":               false,
		"postgres://u:p@[::1]:5432/x?sslmode=disable":              false,
		"postgres:///x?host=/var/run/postgresql&sslmode=disable":   false,
		"sqlite:///var/x.db":                                       false,
	} {
		c, err := Load(env(map[string]string{"DATABASE_URL": url}))
		if err != nil {
			t.Fatal(err)
		}
		if got := c.PostgresPlaintext(); got != want {
			t.Errorf("%s: PostgresPlaintext() = %v, want %v", url, got, want)
		}
	}
}

func TestAllowInsecureBackends(t *testing.T) {
	for v, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "TRUE": true, "1": true} {
		c, err := Load(env(map[string]string{"ALLOW_INSECURE_BACKENDS": v}))
		if err != nil || c.AllowInsecureBackends != want {
			t.Errorf("%q: %v %v", v, c.AllowInsecureBackends, err)
		}
	}
	if _, err := Load(env(map[string]string{"ALLOW_INSECURE_BACKENDS": "maybe"})); err == nil {
		t.Fatal("garbage accepted")
	}
}
