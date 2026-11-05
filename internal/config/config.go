// Package config reads the infrastructure settings, which come from the
// environment. Everything an operator would change at runtime (storage,
// retention, limits, tokens) lives in the database and is managed in the
// browser instead.
package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config is the process configuration.
type Config struct {
	ListenAddr  string
	DataDir     string
	DatabaseURL string // postgres://… or sqlite:///path; empty means SQLite in DataDir
	PublicURL   string // optional override of the public base URL; normally set in the wizard

	SecretKey  []byte // 32 bytes derived from SECRET_KEY; nil if unset
	SetupToken string // empty: generated at startup

	TrustedProxies []netip.Prefix
	TrustAnyProxy  bool // TRUSTED_PROXIES=*: any peer may set CLIENT_IP_HEADER
	ClientIPHeader string

	LogLevel  slog.Level
	LogFormat string // "json" or "text"

	// AllowInsecureBackends silences the plaintext-transport checks for Postgres
	// and S3 on hosts that are not this computer (ALLOW_INSECURE_BACKENDS=true).
	AllowInsecureBackends bool
}

// Load builds a Config from getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	c := &Config{
		ListenAddr:     first(getenv("LISTEN_ADDR"), portAddr(getenv("PORT")), ":8080"),
		DataDir:        first(getenv("DATA_DIR"), "./data"),
		DatabaseURL:    strings.TrimSpace(getenv("DATABASE_URL")),
		SetupToken:     strings.TrimSpace(getenv("SETUP_TOKEN")),
		ClientIPHeader: strings.TrimSpace(getenv("CLIENT_IP_HEADER")),
		LogFormat:      strings.ToLower(first(getenv("LOG_FORMAT"), "json")),
	}
	switch strings.ToLower(strings.TrimSpace(getenv("ALLOW_INSECURE_BACKENDS"))) {
	case "", "0", "false", "no":
	case "1", "true", "yes":
		c.AllowInsecureBackends = true
	default:
		return nil, fmt.Errorf("ALLOW_INSECURE_BACKENDS must be true or false, got %q", getenv("ALLOW_INSECURE_BACKENDS"))
	}

	if v := strings.TrimSpace(getenv("PUBLIC_URL")); v != "" {
		u, err := NormalizePublicURL(v)
		if err != nil {
			return nil, fmt.Errorf("PUBLIC_URL: %w", err)
		}
		c.PublicURL = u
	}

	if v := getenv("SECRET_KEY"); v != "" {
		if len(v) < 32 {
			return nil, errors.New("SECRET_KEY must be at least 32 characters (try: openssl rand -hex 32)")
		}
		sum := sha256.Sum256([]byte(v))
		c.SecretKey = sum[:]
	}
	if c.SetupToken != "" && len(c.SetupToken) < 16 {
		return nil, errors.New("SETUP_TOKEN must be at least 16 characters")
	}

	for _, p := range strings.Split(getenv("TRUSTED_PROXIES"), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "*" {
			c.TrustAnyProxy = true
			continue
		}
		pre, err := parsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q: %w", p, err)
		}
		c.TrustedProxies = append(c.TrustedProxies, pre)
	}
	if (len(c.TrustedProxies) > 0 || c.TrustAnyProxy) != (c.ClientIPHeader != "") {
		return nil, errors.New("TRUSTED_PROXIES and CLIENT_IP_HEADER must be set together (or neither)")
	}

	switch strings.ToLower(first(getenv("LOG_LEVEL"), "info")) {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "info":
		c.LogLevel = slog.LevelInfo
	case "warn", "warning":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("LOG_LEVEL: unknown level %q", getenv("LOG_LEVEL"))
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		return nil, fmt.Errorf("LOG_FORMAT must be json or text, got %q", c.LogFormat)
	}
	return c, nil
}

// LoadEnv is Load on the real environment.
func LoadEnv() (*Config, error) { return Load(os.Getenv) }

// IsPostgres reports whether the metadata database is Postgres.
func (c *Config) IsPostgres() bool {
	return strings.HasPrefix(c.DatabaseURL, "postgres://") || strings.HasPrefix(c.DatabaseURL, "postgresql://")
}

// SQLitePath returns the SQLite file to use when the database is not Postgres.
func (c *Config) SQLitePath() string {
	if p, ok := strings.CutPrefix(c.DatabaseURL, "sqlite://"); ok && p != "" {
		return p
	}
	return filepath.Join(c.DataDir, "snapshots.db")
}

// Validate checks DATABASE_URL has a supported scheme.
func (c *Config) Validate() error {
	if c.DatabaseURL == "" || c.IsPostgres() || strings.HasPrefix(c.DatabaseURL, "sqlite://") {
		return nil
	}
	return errors.New("DATABASE_URL must start with postgres://, postgresql:// or sqlite://")
}

// NormalizePublicURL validates a public base URL and returns it without a
// trailing slash. It must be https, except for a host on this computer.
func NormalizePublicURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", errors.New("not a valid URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("must not contain credentials, a query or a fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "", errors.New("must be https (http is only allowed for localhost)")
		}
	default:
		return "", errors.New("must start with https://")
	}
	if len(raw) > 200 {
		return "", errors.New("too long")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

// PostgresPlaintext reports whether DATABASE_URL names Postgres on a host other
// than this computer with TLS switched off (sslmode=disable). The driver's
// default, sslmode=prefer, negotiates TLS when the server offers it.
func (c *Config) PostgresPlaintext() bool {
	if !c.IsPostgres() {
		return false
	}
	u, err := url.Parse(c.DatabaseURL)
	if err != nil {
		return false
	}
	q := u.Query()
	if !strings.EqualFold(q.Get("sslmode"), "disable") {
		return false
	}
	if h := q.Get("host"); strings.HasPrefix(h, "/") { // unix socket
		return false
	}
	hosts := strings.Split(u.Host, "@")
	hosts = strings.Split(hosts[len(hosts)-1], ",")
	if len(hosts) == 1 && hosts[0] == "" {
		return false // no host: the local socket
	}
	for _, h := range hosts {
		name := h
		if hn, _, err := net.SplitHostPort(h); err == nil {
			name = hn
		}
		if !IsLoopbackHost(strings.Trim(name, "[]")) {
			return true
		}
	}
	return false
}

// IsLoopbackHost reports whether host is localhost or a loopback address.
func IsLoopbackHost(host string) bool { return isLoopback(host) }

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

func first(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func portAddr(p string) string {
	if strings.TrimSpace(p) == "" {
		return ""
	}
	return ":" + strings.TrimSpace(p)
}
