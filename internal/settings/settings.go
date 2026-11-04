// Package settings holds the configuration an administrator manages in the
// browser. It is stored as one JSON document in the database; the S3 secret key
// inside it is sealed with AES-256-GCM.
package settings

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/degenview/snapshots/internal/config"
	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/storage"
	"github.com/degenview/snapshots/internal/storage/s3"
)

const settingsKey = "config"

// Limits and defaults.
const (
	DefaultMaxImageBytes  = 24 << 20 // what DegenView sends at most
	MaxImageBytesCeiling  = 64 << 20
	MinImageBytes         = 1 << 10
	DefaultRetentionDays  = 90
	MaxRetentionDays      = 3650
	DefaultUploadsPerHour = 60
	DefaultViewsPerMinute = 600
)

// ErrNoSecretKey is returned when a secret has to be stored but no key exists
// to seal it with.
var ErrNoSecretKey = errors.New("no SECRET_KEY configured: set the SECRET_KEY environment variable (at least 32 characters) so the storage secret can be encrypted at rest")

// S3 is the bucket configuration.
type S3 struct {
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"-"` // plaintext in memory only
	PathStyle bool   `json:"path_style"`
	Prefix    string `json:"prefix"`
}

// Config converts to the storage backend's config.
func (s S3) Config() s3.Config {
	return s3.Config{Endpoint: s.Endpoint, Region: s.Region, Bucket: s.Bucket, AccessKey: s.AccessKey,
		SecretKey: s.SecretKey, PathStyle: s.PathStyle, Prefix: s.Prefix}
}

// Settings is everything configurable at runtime.
type Settings struct {
	PublicURL      string `json:"public_url"`
	AuthRequired   bool   `json:"auth_required"`
	RetentionDays  int    `json:"retention_days"` // 0 keeps images forever
	MaxImageBytes  int64  `json:"max_image_bytes"`
	MaxTotalBytes  int64  `json:"max_total_bytes"` // 0 means unlimited
	UploadsPerHour int    `json:"uploads_per_hour"`
	ViewsPerMinute int    `json:"views_per_minute"`

	StorageKind string `json:"storage_kind"` // storage.KindLocal or storage.KindS3
	S3          S3     `json:"s3"`
}

// Defaults returns the settings a fresh installation starts with.
func Defaults() Settings {
	return Settings{
		AuthRequired:   true,
		RetentionDays:  DefaultRetentionDays,
		MaxImageBytes:  DefaultMaxImageBytes,
		UploadsPerHour: DefaultUploadsPerHour,
		ViewsPerMinute: DefaultViewsPerMinute,
		StorageKind:    storage.KindLocal,
	}
}

// Validate checks every field.
func (s *Settings) Validate() error {
	if s.PublicURL == "" {
		return errors.New("public URL is required")
	}
	norm, err := config.NormalizePublicURL(s.PublicURL)
	if err != nil {
		return fmt.Errorf("public URL: %w", err)
	}
	s.PublicURL = norm
	if s.RetentionDays < 0 || s.RetentionDays > MaxRetentionDays {
		return fmt.Errorf("retention must be between 0 (never) and %d days", MaxRetentionDays)
	}
	if s.MaxImageBytes < MinImageBytes || s.MaxImageBytes > MaxImageBytesCeiling {
		return fmt.Errorf("maximum image size must be between %d bytes and %d MiB", MinImageBytes, MaxImageBytesCeiling>>20)
	}
	if s.MaxTotalBytes < 0 {
		return errors.New("storage quota must not be negative")
	}
	if s.UploadsPerHour < 1 || s.UploadsPerHour > 100000 {
		return errors.New("uploads per hour must be between 1 and 100000")
	}
	if s.ViewsPerMinute < 1 || s.ViewsPerMinute > 1000000 {
		return errors.New("views per minute must be between 1 and 1000000")
	}
	switch s.StorageKind {
	case storage.KindLocal:
	case storage.KindS3:
		if err := s.S3.Config().Validate(); err != nil {
			return fmt.Errorf("S3: %w", err)
		}
	default:
		return fmt.Errorf("unknown storage %q", s.StorageKind)
	}
	return nil
}

// Store is the settings persistence layer.
type Store struct {
	repo *repo.Repo
	key  []byte
	cur  atomic.Pointer[Settings]
}

// NewStore returns a Store that seals secrets with key (which may be nil if no
// secret will ever be saved).
func NewStore(r *repo.Repo, key []byte) *Store { return &Store{repo: r, key: key} }

// Load reads the settings from the database. found is false before setup.
func (st *Store) Load(ctx context.Context) (s Settings, found bool, err error) {
	raw, err := st.repo.GetSetting(ctx, settingsKey)
	if errors.Is(err, repo.ErrNotFound) {
		return Defaults(), false, nil
	}
	if err != nil {
		return s, false, err
	}
	s, err = decode(raw, st.key)
	if err != nil {
		return s, false, err
	}
	st.cur.Store(&s)
	return s, true, nil
}

// Encode serialises s for storage.
func (st *Store) Encode(s Settings) (string, error) { return encode(s, st.key) }

// Save validates, stores and publishes s.
func (st *Store) Save(ctx context.Context, s Settings) (Settings, error) {
	if err := s.Validate(); err != nil {
		return s, err
	}
	raw, err := encode(s, st.key)
	if err != nil {
		return s, err
	}
	if err := st.repo.SetSetting(ctx, settingsKey, raw); err != nil {
		return s, err
	}
	st.cur.Store(&s)
	return s, nil
}

// SettingsKey is the key under which Encode's output must be stored by setup.
func SettingsKey() string { return settingsKey }

// Current returns the last loaded or saved settings.
func (st *Store) Current() (Settings, bool) {
	p := st.cur.Load()
	if p == nil {
		return Defaults(), false
	}
	return *p, true
}

// Publish makes s current without storing it (used after a setup transaction).
func (st *Store) Publish(s Settings) { st.cur.Store(&s) }

// CanSeal reports whether a secret can be stored.
func (st *Store) CanSeal() bool { return len(st.key) == 32 }

type stored struct {
	Settings
	S3SecretSealed string `json:"s3_secret_sealed,omitempty"`
}

func encode(s Settings, key []byte) (string, error) {
	st := stored{Settings: s}
	if s.StorageKind == storage.KindS3 && s.S3.SecretKey != "" {
		sealed, err := seal(key, []byte(s.S3.SecretKey))
		if err != nil {
			return "", err
		}
		st.S3SecretSealed = sealed
	}
	b, err := json.Marshal(st)
	return string(b), err
}

func decode(raw string, key []byte) (Settings, error) {
	var st stored
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return Settings{}, fmt.Errorf("settings: corrupt document: %w", err)
	}
	s := st.Settings
	if st.S3SecretSealed != "" {
		plain, err := open(key, st.S3SecretSealed)
		if err != nil {
			return Settings{}, fmt.Errorf("settings: cannot decrypt the storage secret (is SECRET_KEY the one it was saved with?): %w", err)
		}
		s.S3.SecretKey = string(plain)
	}
	return s, nil
}

// Sealing -----------------------------------------------------------------

var aad = []byte("degenview-snapshots/s3-secret/v1")

const sealPrefix = "v1:"

func seal(key, plain []byte) (string, error) {
	if len(key) != 32 {
		return "", ErrNoSecretKey
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return sealPrefix + base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plain, aad)), nil
}

func open(key []byte, sealed string) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrNoSecretKey
	}
	b64, ok := strings.CutPrefix(sealed, sealPrefix)
	if !ok {
		return nil, errors.New("unknown format")
	}
	raw, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("truncated")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// ResolveKey returns the key used to seal secrets: SECRET_KEY if given;
// otherwise, for SQLite installations, a random key kept in DataDir/secret.key
// (mode 0600) next to the database it protects; otherwise nil.
func ResolveKey(cfg *config.Config) ([]byte, error) {
	if cfg.SecretKey != nil {
		return cfg.SecretKey, nil
	}
	if cfg.IsPostgres() {
		return nil, nil
	}
	path := filepath.Join(cfg.DataDir, "secret.key")
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // path is DATA_DIR/secret.key from operator config
		k, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("%s is not a 32-byte hex key", path)
		}
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // as above
	if err != nil {
		if errors.Is(err, os.ErrExist) { // another process won the race
			return ResolveKey(cfg)
		}
		return nil, err
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(k) + "\n"); err != nil {
		return nil, err
	}
	return k, nil
}
