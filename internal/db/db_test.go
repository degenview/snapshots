package db

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSQLiteMigrateCreatesSchema(t *testing.T) {
	d, err := OpenSQLite(filepath.Join(t.TempDir(), "nested", "dir", "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	for i := 0; i < 2; i++ { // idempotent
		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	for _, table := range []string{"settings", "admin", "sessions", "tokens", "images"} {
		if _, err := d.Exec("SELECT 1 FROM " + table); err != nil {
			t.Errorf("table %s: %v", table, err)
		}
	}
	// The admin table can only ever hold one row.
	if _, err := d.Exec(`INSERT INTO admin (id, password_hash, created_at) VALUES (2, 'x', 0)`); err == nil {
		t.Fatal("a second administrator row was accepted")
	}
}

func TestSQLiteFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	path := filepath.Join(t.TempDir(), "t.db")
	d, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
}

func TestSQLiteMemory(t *testing.T) {
	d, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFailures(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLite(filepath.Join(file, "sub", "t.db")); err == nil {
		t.Fatal("opened a database below a regular file")
	}
	if _, err := OpenPostgres("postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"); err == nil {
		t.Fatal("connected to nothing")
	}
}

func TestRebind(t *testing.T) {
	pg := &DB{Postgres: true}
	if got := pg.Rebind("a = ? AND b = ?"); got != "a = $1 AND b = $2" {
		t.Fatal(got)
	}
	if got := (&DB{}).Rebind("a = ?"); got != "a = ?" {
		t.Fatal(got)
	}
}
