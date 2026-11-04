// Package auth implements upload tokens, the administrator password, login
// sessions and the CSRF checks for the admin interface.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/repo"
)

// ErrInvalid is returned for any credential that does not check out. It never
// says which part was wrong.
var ErrInvalid = errors.New("invalid credentials")

// Passwords ---------------------------------------------------------------

const (
	minPasswordRunes = 12
	maxPasswordBytes = 256

	argonTime    = 2
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ValidatePassword enforces the length rules for the administrator password.
func ValidatePassword(pw string) error {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Errorf("password must be at least %d characters", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
	}
	return nil
}

// HashPassword returns an encoded argon2id hash of pw.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether pw matches an encoded hash from HashPassword.
func VerifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	// Parameters come from our own database, but never let a corrupt row
	// request gigabytes of memory.
	if m == 0 || m > 256*1024 || t == 0 || t > 10 || p == 0 || p > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Upload tokens -----------------------------------------------------------

// Tokens issues and checks upload tokens.
type Tokens struct {
	Repo *repo.Repo
	Now  func() time.Time
}

func (t *Tokens) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Issue creates a token and returns its plaintext, which is never stored and
// cannot be shown again.
func (t *Tokens) Issue(ctx context.Context, name string) (string, repo.Token, error) {
	plain, err := ids.Token()
	if err != nil {
		return "", repo.Token{}, err
	}
	tok, err := t.Build(name, plain)
	if err != nil {
		return "", repo.Token{}, err
	}
	if err := t.Repo.CreateToken(ctx, tok); err != nil {
		return "", repo.Token{}, err
	}
	return plain, tok, nil
}

// Build prepares (without storing) the record for a plaintext token.
func (t *Tokens) Build(name, plain string) (repo.Token, error) {
	id, err := ids.Random(10)
	if err != nil {
		return repo.Token{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Untitled"
	}
	if utf8.RuneCountInString(name) > 60 {
		name = string([]rune(name)[:60])
	}
	return repo.Token{ID: id, Name: name, Hash: ids.Hash(plain), CreatedAt: t.now().UTC()}, nil
}

// Authenticate checks a plaintext token and notes its use.
func (t *Tokens) Authenticate(ctx context.Context, plain string) (repo.Token, error) {
	if !strings.HasPrefix(plain, ids.TokenPrefix) || len(plain) != len(ids.TokenPrefix)+ids.TokenLen {
		return repo.Token{}, ErrInvalid
	}
	tok, err := t.Repo.FindToken(ctx, ids.Hash(plain))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return repo.Token{}, ErrInvalid
		}
		return repo.Token{}, err
	}
	_ = t.Repo.TouchToken(ctx, tok.ID, t.now())
	return tok, nil
}

// BearerToken extracts the token from an Authorization header.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(p):])
	return tok, tok != ""
}

// Sessions ----------------------------------------------------------------

// Sessions manages administrator login sessions. The cookie holds a random id;
// only its hash is stored.
type Sessions struct {
	Repo     *repo.Repo
	Now      func() time.Time
	Idle     time.Duration
	Absolute time.Duration
}

// NewSessions returns Sessions with the standard lifetimes.
func NewSessions(r *repo.Repo) *Sessions {
	return &Sessions{Repo: r, Idle: 12 * time.Hour, Absolute: 7 * 24 * time.Hour}
}

func (s *Sessions) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Create starts a session and returns the cookie value and the session.
func (s *Sessions) Create(ctx context.Context) (string, repo.Session, error) {
	id, err := ids.Random(43) // ≈ 256 bits
	if err != nil {
		return "", repo.Session{}, err
	}
	csrf, err := ids.Random(32)
	if err != nil {
		return "", repo.Session{}, err
	}
	now := s.now()
	sess := repo.Session{IDHash: ids.Hash(id), CSRF: csrf, CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(s.Absolute)}
	if err := s.Repo.CreateSession(ctx, sess); err != nil {
		return "", repo.Session{}, err
	}
	return id, sess, nil
}

// Validate returns the live session for a cookie value, or ErrInvalid.
func (s *Sessions) Validate(ctx context.Context, cookie string) (repo.Session, error) {
	if len(cookie) != 43 {
		return repo.Session{}, ErrInvalid
	}
	sess, err := s.Repo.GetSession(ctx, ids.Hash(cookie))
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return repo.Session{}, ErrInvalid
		}
		return repo.Session{}, err
	}
	now := s.now()
	if !now.Before(sess.ExpiresAt) || !now.Before(sess.LastSeen.Add(s.Idle)) {
		_ = s.Repo.DeleteSession(ctx, sess.IDHash)
		return repo.Session{}, ErrInvalid
	}
	if now.Sub(sess.LastSeen) > time.Minute {
		_ = s.Repo.TouchSession(ctx, sess.IDHash, now)
	}
	return sess, nil
}

// Destroy ends the session for a cookie value.
func (s *Sessions) Destroy(ctx context.Context, cookie string) {
	_ = s.Repo.DeleteSession(ctx, ids.Hash(cookie))
}

// Prune deletes expired sessions.
func (s *Sessions) Prune(ctx context.Context) error {
	now := s.now()
	return s.Repo.PruneSessions(ctx, now, now.Add(-s.Idle))
}

// CSRF --------------------------------------------------------------------

// ErrCSRF is returned when a state-changing request fails the cross-site checks.
var ErrCSRF = errors.New("cross-site request rejected")

// CheckCSRF validates a state-changing request from the admin UI. It needs the
// session's token in X-CSRF-Token and, when the browser says so, a same-origin
// request. A cross-site page can do neither.
func CheckCSRF(r *http.Request, sess repo.Session) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return ErrCSRF
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return ErrCSRF
		}
	}
	got := r.Header.Get("X-CSRF-Token")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRF)) != 1 {
		return ErrCSRF
	}
	return nil
}

// CheckSameOrigin is the cookie-less variant, for forms before a session exists
// (login, setup): Origin and Sec-Fetch-Site must not point elsewhere.
func CheckSameOrigin(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return ErrCSRF
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return ErrCSRF
		}
	}
	return nil
}

// Equal compares two secrets in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NewSetupToken returns a random token for unlocking the first-run wizard.
func NewSetupToken() (string, error) { return ids.Random(24) }
