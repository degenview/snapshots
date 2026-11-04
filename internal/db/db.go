// Package db opens the metadata database (SQLite or Postgres) and applies the
// embedded migrations.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	_ "modernc.org/sqlite"             // registers "sqlite"
)

//go:embed migrations
var migrationFS embed.FS

// DB wraps *sql.DB with the dialect in use.
type DB struct {
	*sql.DB
	Postgres bool
}

// OpenSQLite opens (creating if needed) the SQLite database at path.
func OpenSQLite(path string) (*DB, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("db: creating data directory: %w", err)
		}
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		sdb.SetMaxOpenConns(1) // each connection would otherwise get its own database
	} else {
		sdb.SetMaxOpenConns(8)
	}
	d := &DB{DB: sdb}
	if err := d.ping(); err != nil {
		sdb.Close()
		return nil, err
	}
	if path != ":memory:" {
		_ = os.Chmod(path, 0o600)
	}
	return d, nil
}

// OpenPostgres opens the Postgres database at rawURL.
func OpenPostgres(rawURL string) (*DB, error) {
	sdb, err := sql.Open("pgx", rawURL)
	if err != nil {
		return nil, err
	}
	sdb.SetMaxOpenConns(10)
	sdb.SetMaxIdleConns(5)
	sdb.SetConnMaxLifetime(30 * time.Minute)
	d := &DB{DB: sdb, Postgres: true}
	if err := d.ping(); err != nil {
		sdb.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.PingContext(ctx); err != nil {
		return fmt.Errorf("db: cannot connect: %w", err)
	}
	return nil
}

// Rebind rewrites ? placeholders to $1, $2, … for Postgres.
func (d *DB) Rebind(q string) string {
	if !d.Postgres {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

const pgLockID = 0x44565331 // "DVS1": serialises migrations across instances

// Migrate applies every embedded migration that has not run yet.
func (d *DB) Migrate(ctx context.Context) error {
	dir := "migrations/sqlite"
	if d.Postgres {
		dir = "migrations/postgres"
	}
	entries, err := fs.ReadDir(migrationFS, dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	conn, err := d.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if d.Postgres {
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", pgLockID); err != nil {
			return fmt.Errorf("db: taking migration lock: %w", err)
		}
		defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", pgLockID) }()
	}
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		ver, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("db: bad migration name %q", name)
		}
		var have int
		err = conn.QueryRowContext(ctx, d.Rebind("SELECT version FROM schema_migrations WHERE version = ?"), ver).Scan(&have)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		body, err := fs.ReadFile(migrationFS, dir+"/"+name)
		if err != nil {
			return err
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("db: migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, d.Rebind("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)"), ver, time.Now().UTC().Format(time.RFC3339)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
