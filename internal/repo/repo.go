// Package repo is the only code that talks SQL. Every value reaches the
// database as a bound parameter; the few identifiers that vary are constants.
package repo

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/degenview/snapshots/internal/db"
)

// Errors returned by Repo.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

// Repo is the data access layer.
type Repo struct {
	db *db.DB
}

// New returns a Repo on d.
func New(d *db.DB) *Repo { return &Repo{db: d} }

func (r *Repo) q(query string) string { return r.db.Rebind(query) }

func unix(t time.Time) int64 { return t.Unix() }

func nullTime(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

func fromNull(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(n.Int64, 0).UTC()
}

// isUnique reports whether err is a unique/primary-key violation.
func isUnique(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23505"
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		switch coded.Code() {
		case 1555, 2067: // SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE
			return true
		}
	}
	return false
}

// Ping checks the database is reachable.
func (r *Repo) Ping(ctx context.Context) error { return r.db.PingContext(ctx) }

// Settings ---------------------------------------------------------------

// GetSetting returns the value for key, or ErrNotFound.
func (r *Repo) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := r.db.QueryRowContext(ctx, r.q(`SELECT value FROM settings WHERE key = ?`), key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting stores value under key.
func (r *Repo) SetSetting(ctx context.Context, key, value string) error {
	return setSetting(ctx, r, r.db, key, value)
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func setSetting(ctx context.Context, r *Repo, e execer, key, value string) error {
	_, err := e.ExecContext(ctx, r.q(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`), key, value)
	return err
}

// AllSettings returns every setting.
func (r *Repo) AllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// Admin -------------------------------------------------------------------

// HasAdmin reports whether the administrator exists (setup is complete).
func (r *Repo) HasAdmin(ctx context.Context) (bool, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin`).Scan(&n)
	return n > 0, err
}

// AdminHash returns the administrator's password hash.
func (r *Repo) AdminHash(ctx context.Context) (string, error) {
	var h string
	err := r.db.QueryRowContext(ctx, `SELECT password_hash FROM admin WHERE id = 1`).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return h, err
}

// SetAdminHash replaces the administrator's password hash.
func (r *Repo) SetAdminHash(ctx context.Context, hash string) error {
	res, err := r.db.ExecContext(ctx, r.q(`UPDATE admin SET password_hash = ? WHERE id = 1`), hash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetupData is everything the first-run wizard commits in one transaction.
type SetupData struct {
	AdminHash string
	Settings  map[string]string
	Token     *Token // optional first upload token
	Now       time.Time
}

// CompleteSetup creates the administrator and stores the settings atomically.
// It returns ErrConflict if setup already happened, so two concurrent wizards
// cannot both win.
func (r *Repo) CompleteSetup(ctx context.Context, d SetupData) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, r.q(`INSERT INTO admin (id, password_hash, created_at) VALUES (1, ?, ?)`), d.AdminHash, unix(d.Now)); err != nil {
		if isUnique(err) {
			return ErrConflict
		}
		return err
	}
	for k, v := range d.Settings {
		if err := setSetting(ctx, r, tx, k, v); err != nil {
			return err
		}
	}
	if d.Token != nil {
		if err := insertToken(ctx, r, tx, *d.Token); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Sessions ----------------------------------------------------------------

// Session is an administrator login.
type Session struct {
	IDHash    string
	CSRF      string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

// CreateSession stores a session.
func (r *Repo) CreateSession(ctx context.Context, s Session) error {
	_, err := r.db.ExecContext(ctx, r.q(`INSERT INTO sessions (id_hash, csrf, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?)`),
		s.IDHash, s.CSRF, unix(s.CreatedAt), unix(s.LastSeen), unix(s.ExpiresAt))
	return err
}

// GetSession returns the session with this id hash, or ErrNotFound.
func (r *Repo) GetSession(ctx context.Context, idHash string) (Session, error) {
	var s Session
	var c, l, e int64
	err := r.db.QueryRowContext(ctx, r.q(`SELECT id_hash, csrf, created_at, last_seen, expires_at FROM sessions WHERE id_hash = ?`), idHash).
		Scan(&s.IDHash, &s.CSRF, &c, &l, &e)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	s.CreatedAt, s.LastSeen, s.ExpiresAt = time.Unix(c, 0).UTC(), time.Unix(l, 0).UTC(), time.Unix(e, 0).UTC()
	return s, err
}

// TouchSession records activity.
func (r *Repo) TouchSession(ctx context.Context, idHash string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, r.q(`UPDATE sessions SET last_seen = ? WHERE id_hash = ?`), unix(now), idHash)
	return err
}

// DeleteSession removes one session.
func (r *Repo) DeleteSession(ctx context.Context, idHash string) error {
	_, err := r.db.ExecContext(ctx, r.q(`DELETE FROM sessions WHERE id_hash = ?`), idHash)
	return err
}

// DeleteAllSessions removes every session (used after a password change).
func (r *Repo) DeleteAllSessions(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions`)
	return err
}

// PruneSessions removes sessions that expired or idled since idleBefore.
func (r *Repo) PruneSessions(ctx context.Context, now, idleBefore time.Time) error {
	_, err := r.db.ExecContext(ctx, r.q(`DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?`), unix(now), unix(idleBefore))
	return err
}

// Tokens ------------------------------------------------------------------

// Token is an upload token. Only its hash is stored.
type Token struct {
	ID         string
	Name       string
	Hash       string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero if never
}

// CreateToken stores a token.
func (r *Repo) CreateToken(ctx context.Context, t Token) error {
	return insertToken(ctx, r, r.db, t)
}

func insertToken(ctx context.Context, r *Repo, e execer, t Token) error {
	_, err := e.ExecContext(ctx, r.q(`INSERT INTO tokens (id, name, hash, created_at) VALUES (?, ?, ?, ?)`), t.ID, t.Name, t.Hash, unix(t.CreatedAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// FindToken returns the token whose hash is hash, or ErrNotFound.
func (r *Repo) FindToken(ctx context.Context, hash string) (Token, error) {
	var t Token
	var c int64
	var used sql.NullInt64
	err := r.db.QueryRowContext(ctx, r.q(`SELECT id, name, hash, created_at, last_used_at FROM tokens WHERE hash = ?`), hash).
		Scan(&t.ID, &t.Name, &t.Hash, &c, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	t.CreatedAt, t.LastUsedAt = time.Unix(c, 0).UTC(), fromNull(used)
	return t, err
}

// TouchToken sets last_used_at, at most once per minute per token.
func (r *Repo) TouchToken(ctx context.Context, id string, now time.Time) error {
	_, err := r.db.ExecContext(ctx, r.q(`UPDATE tokens SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`),
		unix(now), id, unix(now.Add(-time.Minute)))
	return err
}

// ListTokens returns all tokens, newest first.
func (r *Repo) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, hash, created_at, last_used_at FROM tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		var c int64
		var used sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Name, &t.Hash, &c, &used); err != nil {
			return nil, err
		}
		t.CreatedAt, t.LastUsedAt = time.Unix(c, 0).UTC(), fromNull(used)
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteToken revokes a token. Images it uploaded are kept.
func (r *Repo) DeleteToken(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.q(`DELETE FROM tokens WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Images ------------------------------------------------------------------

// Image is the metadata of one stored picture.
type Image struct {
	ID         string
	DeleteHash string
	Storage    string
	Size       int64
	Width      int
	Height     int
	TokenID    string
	CreatedAt  time.Time
	ExpiresAt  time.Time // zero: never
}

// Expired reports whether the image is past its expiry at now.
func (i Image) Expired(now time.Time) bool {
	return !i.ExpiresAt.IsZero() && !now.Before(i.ExpiresAt)
}

const imageCols = `id, delete_hash, storage, size_bytes, width, height, token_id, created_at, expires_at`

func scanImage(s interface{ Scan(...any) error }) (Image, error) {
	var i Image
	var tok sql.NullString
	var created int64
	var exp sql.NullInt64
	if err := s.Scan(&i.ID, &i.DeleteHash, &i.Storage, &i.Size, &i.Width, &i.Height, &tok, &created, &exp); err != nil {
		return i, err
	}
	i.TokenID = tok.String
	i.CreatedAt = time.Unix(created, 0).UTC()
	i.ExpiresAt = fromNull(exp)
	return i, nil
}

// CreateImage stores image metadata. ErrConflict means the id (or delete hash)
// is taken and the caller should pick another.
func (r *Repo) CreateImage(ctx context.Context, i Image) error {
	var tok sql.NullString
	if i.TokenID != "" {
		tok = sql.NullString{String: i.TokenID, Valid: true}
	}
	_, err := r.db.ExecContext(ctx, r.q(`INSERT INTO images (`+imageCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		i.ID, i.DeleteHash, i.Storage, i.Size, i.Width, i.Height, tok, unix(i.CreatedAt), nullTime(i.ExpiresAt))
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// GetImage returns an image by public id.
func (r *Repo) GetImage(ctx context.Context, id string) (Image, error) {
	i, err := scanImage(r.db.QueryRowContext(ctx, r.q(`SELECT `+imageCols+` FROM images WHERE id = ?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return i, ErrNotFound
	}
	return i, err
}

// GetImageByDeleteHash finds the image a delete secret belongs to.
func (r *Repo) GetImageByDeleteHash(ctx context.Context, hash string) (Image, error) {
	i, err := scanImage(r.db.QueryRowContext(ctx, r.q(`SELECT `+imageCols+` FROM images WHERE delete_hash = ?`), hash))
	if errors.Is(err, sql.ErrNoRows) {
		return i, ErrNotFound
	}
	return i, err
}

// DeleteImage removes an image's row. Deleting a missing row is not an error.
func (r *Repo) DeleteImage(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, r.q(`DELETE FROM images WHERE id = ?`), id)
	return err
}

// ExpiredImages returns up to limit images whose expiry is at or before now.
func (r *Repo) ExpiredImages(ctx context.Context, now time.Time, limit int) ([]Image, error) {
	rows, err := r.db.QueryContext(ctx, r.q(`SELECT `+imageCols+` FROM images WHERE expires_at IS NOT NULL AND expires_at <= ? ORDER BY expires_at LIMIT ?`), unix(now), limit)
	if err != nil {
		return nil, err
	}
	return collectImages(rows)
}

// ListImages returns a page of images, newest first.
func (r *Repo) ListImages(ctx context.Context, limit, offset int) ([]Image, error) {
	rows, err := r.db.QueryContext(ctx, r.q(`SELECT `+imageCols+` FROM images ORDER BY created_at DESC, id LIMIT ? OFFSET ?`), limit, offset)
	if err != nil {
		return nil, err
	}
	return collectImages(rows)
}

func collectImages(rows *sql.Rows) ([]Image, error) {
	defer rows.Close()
	var out []Image
	for rows.Next() {
		i, err := scanImage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// Stats summarises stored images.
type Stats struct {
	Images int64
	Bytes  int64
}

// ImageStats counts all images and their total size.
func (r *Repo) ImageStats(ctx context.Context) (Stats, error) {
	var s Stats
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM images`).Scan(&s.Images, &s.Bytes)
	return s, err
}

// CountByStorage counts images held by one storage backend.
func (r *Repo) CountByStorage(ctx context.Context, storage string) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, r.q(`SELECT COUNT(*) FROM images WHERE storage = ?`), storage).Scan(&n)
	return n, err
}
