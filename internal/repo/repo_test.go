package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/degenview/snapshots/internal/db"
)

var ctx = context.Background()

// backends returns a fresh Repo for each database under test: SQLite always,
// Postgres when TEST_POSTGRES_URL points at a database we may create schemas in.
func backends(t *testing.T) map[string]func(*testing.T) *Repo {
	m := map[string]func(*testing.T) *Repo{
		"sqlite": func(t *testing.T) *Repo {
			d, err := db.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { d.Close() })
			if err := d.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			return New(d)
		},
	}
	if base := os.Getenv("TEST_POSTGRES_URL"); base != "" {
		m["postgres"] = func(t *testing.T) *Repo {
			admin, err := sql.Open("pgx", base)
			if err != nil {
				t.Fatal(err)
			}
			schema := fmt.Sprintf("t_%d", time.Now().UnixNano())
			if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				admin.Exec("DROP SCHEMA " + schema + " CASCADE")
				admin.Close()
			})
			u, _ := url.Parse(base)
			q := u.Query()
			q.Set("search_path", schema)
			u.RawQuery = q.Encode()
			d, err := db.OpenPostgres(u.String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { d.Close() })
			if err := d.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			return New(d)
		}
	}
	return m
}

func eachBackend(t *testing.T, fn func(t *testing.T, r *Repo)) {
	for name, mk := range backends(t) {
		t.Run(name, func(t *testing.T) { fn(t, mk(t)) })
	}
}

var now = time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)

func img(id string) Image {
	return Image{ID: id, DeleteHash: "del-" + id, Storage: "local", Size: 1234, Width: 800, Height: 600,
		TokenID: "tok", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func TestMigrateIsIdempotent(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		if err := r.db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSettings(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		if _, err := r.GetSetting(ctx, "a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
		must(t, r.SetSetting(ctx, "a", "1"))
		must(t, r.SetSetting(ctx, "a", "2"))
		must(t, r.SetSetting(ctx, "b", "x"))
		if v, _ := r.GetSetting(ctx, "a"); v != "2" {
			t.Fatalf("a = %q", v)
		}
		all, err := r.AllSettings(ctx)
		if err != nil || len(all) != 2 || all["b"] != "x" {
			t.Fatalf("%v %v", all, err)
		}
	})
}

func TestImagesCRUD(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		must(t, r.CreateImage(ctx, img("aaaaaaaaaa")))
		got, err := r.GetImage(ctx, "aaaaaaaaaa")
		if err != nil {
			t.Fatal(err)
		}
		want := img("aaaaaaaaaa")
		if got != want {
			t.Fatalf("got %+v\nwant %+v", got, want)
		}
		if got.Expired(now) || !got.Expired(now.Add(time.Hour)) {
			t.Fatal("Expired wrong at the boundary")
		}
		if err := r.CreateImage(ctx, img("aaaaaaaaaa")); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate id: %v", err)
		}
		dup := img("bbbbbbbbbb")
		dup.DeleteHash = "del-aaaaaaaaaa"
		if err := r.CreateImage(ctx, dup); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate delete hash: %v", err)
		}
		byHash, err := r.GetImageByDeleteHash(ctx, "del-aaaaaaaaaa")
		if err != nil || byHash.ID != "aaaaaaaaaa" {
			t.Fatal(err)
		}
		if _, err := r.GetImageByDeleteHash(ctx, "aaaaaaaaaa"); !errors.Is(err, ErrNotFound) {
			t.Fatal("the public id must not work as a delete secret")
		}
		must(t, r.DeleteImage(ctx, "aaaaaaaaaa"))
		must(t, r.DeleteImage(ctx, "aaaaaaaaaa"))
		if _, err := r.GetImage(ctx, "aaaaaaaaaa"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	})
}

func TestImageWithoutExpiryOrToken(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		i := img("cccccccccc")
		i.ExpiresAt, i.TokenID = time.Time{}, ""
		must(t, r.CreateImage(ctx, i))
		got, _ := r.GetImage(ctx, i.ID)
		if !got.ExpiresAt.IsZero() || got.TokenID != "" || got.Expired(now.Add(1000*time.Hour)) {
			t.Fatalf("%+v", got)
		}
		exp, err := r.ExpiredImages(ctx, now.Add(1000*time.Hour), 10)
		if err != nil || len(exp) != 0 {
			t.Fatalf("never-expiring image listed as expired: %v %v", exp, err)
		}
	})
}

func TestExpiredAndListAndStats(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		for k := 0; k < 5; k++ {
			i := img(fmt.Sprintf("img000000%d", k))
			i.CreatedAt = now.Add(time.Duration(k) * time.Minute)
			i.ExpiresAt = now.Add(time.Duration(k) * time.Hour)
			must(t, r.CreateImage(ctx, i))
		}
		exp, err := r.ExpiredImages(ctx, now.Add(90*time.Minute), 10)
		if err != nil || len(exp) != 2 || exp[0].ID != "img0000000" {
			t.Fatalf("%v %v", exp, err)
		}
		exp, _ = r.ExpiredImages(ctx, now.Add(90*time.Minute), 1)
		if len(exp) != 1 {
			t.Fatal("limit ignored")
		}
		page, err := r.ListImages(ctx, 2, 1)
		if err != nil || len(page) != 2 || page[0].ID != "img0000003" || page[1].ID != "img0000002" {
			t.Fatalf("%v %v", page, err)
		}
		st, err := r.ImageStats(ctx)
		if err != nil || st.Images != 5 || st.Bytes != 5*1234 {
			t.Fatalf("%+v %v", st, err)
		}
		if n, _ := r.CountByStorage(ctx, "local"); n != 5 {
			t.Fatal(n)
		}
		if n, _ := r.CountByStorage(ctx, "s3"); n != 0 {
			t.Fatal(n)
		}
	})
}

func TestEmptyStats(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		st, err := r.ImageStats(ctx)
		if err != nil || st != (Stats{}) {
			t.Fatalf("%+v %v", st, err)
		}
	})
}

func TestTokens(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		must(t, r.CreateToken(ctx, Token{ID: "t1", Name: "laptop", Hash: "h1", CreatedAt: now}))
		must(t, r.CreateToken(ctx, Token{ID: "t2", Name: "desktop", Hash: "h2", CreatedAt: now.Add(time.Second)}))
		if err := r.CreateToken(ctx, Token{ID: "t3", Name: "x", Hash: "h1", CreatedAt: now}); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate hash: %v", err)
		}
		tok, err := r.FindToken(ctx, "h1")
		if err != nil || tok.ID != "t1" || !tok.LastUsedAt.IsZero() {
			t.Fatalf("%+v %v", tok, err)
		}
		if _, err := r.FindToken(ctx, "nope"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		must(t, r.TouchToken(ctx, "t1", now.Add(time.Hour)))
		tok, _ = r.FindToken(ctx, "h1")
		if !tok.LastUsedAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("last used %v", tok.LastUsedAt)
		}
		must(t, r.TouchToken(ctx, "t1", now.Add(time.Hour+10*time.Second)))
		tok, _ = r.FindToken(ctx, "h1")
		if !tok.LastUsedAt.Equal(now.Add(time.Hour)) {
			t.Fatal("touch is throttled to once a minute")
		}
		list, err := r.ListTokens(ctx)
		if err != nil || len(list) != 2 || list[0].ID != "t2" {
			t.Fatalf("%v %v", list, err)
		}
		must(t, r.DeleteToken(ctx, "t1"))
		if err := r.DeleteToken(ctx, "t1"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := r.FindToken(ctx, "h1"); !errors.Is(err, ErrNotFound) {
			t.Fatal("revoked token still found")
		}
	})
}

func TestSessions(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		s := Session{IDHash: "s1", CSRF: "c", CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(time.Hour)}
		must(t, r.CreateSession(ctx, s))
		must(t, r.CreateSession(ctx, Session{IDHash: "s2", CSRF: "c", CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(48 * time.Hour)}))
		got, err := r.GetSession(ctx, "s1")
		if err != nil || got != s {
			t.Fatalf("%+v %v", got, err)
		}
		must(t, r.TouchSession(ctx, "s1", now.Add(time.Minute)))
		got, _ = r.GetSession(ctx, "s1")
		if !got.LastSeen.Equal(now.Add(time.Minute)) {
			t.Fatal("not touched")
		}
		must(t, r.PruneSessions(ctx, now.Add(2*time.Hour), now.Add(-time.Hour)))
		if _, err := r.GetSession(ctx, "s1"); !errors.Is(err, ErrNotFound) {
			t.Fatal("expired session survived")
		}
		if _, err := r.GetSession(ctx, "s2"); err != nil {
			t.Fatal("live session pruned")
		}
		must(t, r.PruneSessions(ctx, now, now.Add(time.Hour))) // idle
		if _, err := r.GetSession(ctx, "s2"); !errors.Is(err, ErrNotFound) {
			t.Fatal("idle session survived")
		}
		must(t, r.CreateSession(ctx, s))
		must(t, r.DeleteSession(ctx, "s1"))
		must(t, r.CreateSession(ctx, s))
		must(t, r.DeleteAllSessions(ctx))
		if _, err := r.GetSession(ctx, "s1"); !errors.Is(err, ErrNotFound) {
			t.Fatal()
		}
	})
}

func TestCompleteSetup(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		if has, _ := r.HasAdmin(ctx); has {
			t.Fatal("fresh db has admin")
		}
		data := SetupData{AdminHash: "ph", Settings: map[string]string{"x": "1", "y": "2"}, Now: now,
			Token: &Token{ID: "t1", Name: "first", Hash: "h", CreatedAt: now}}
		must(t, r.CompleteSetup(ctx, data))
		if has, _ := r.HasAdmin(ctx); !has {
			t.Fatal()
		}
		if h, _ := r.AdminHash(ctx); h != "ph" {
			t.Fatal(h)
		}
		if v, _ := r.GetSetting(ctx, "y"); v != "2" {
			t.Fatal(v)
		}
		if _, err := r.FindToken(ctx, "h"); err != nil {
			t.Fatal(err)
		}
		// A second wizard loses and changes nothing.
		data.AdminHash, data.Settings = "other", map[string]string{"x": "evil"}
		if err := r.CompleteSetup(ctx, data); !errors.Is(err, ErrConflict) {
			t.Fatalf("err = %v", err)
		}
		if v, _ := r.GetSetting(ctx, "x"); v != "1" {
			t.Fatal("losing setup wrote settings")
		}
		must(t, r.SetAdminHash(ctx, "new"))
		if h, _ := r.AdminHash(ctx); h != "new" {
			t.Fatal(h)
		}
	})
}

func TestSetupRacesHaveOneWinner(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				err := r.CompleteSetup(ctx, SetupData{AdminHash: fmt.Sprint(i), Settings: map[string]string{"k": fmt.Sprint(i)}, Now: now})
				if err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				} else if !errors.Is(err, ErrConflict) {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d winners", wins)
		}
	})
}

func TestAdminHashMissing(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		if _, err := r.AdminHash(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if err := r.SetAdminHash(ctx, "x"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	})
}

// Hostile strings are data, never SQL.
func TestInjectionStringsAreInert(t *testing.T) {
	evil := []string{
		"' OR '1'='1", "'; DROP TABLE images; --", "\" OR 1=1 --", "x' UNION SELECT delete_hash FROM images --",
		"%", "_", "\\", "a\x00b", strings.Repeat("é", 50), "'); DELETE FROM tokens; --",
	}
	eachBackend(t, func(t *testing.T, r *Repo) {
		must(t, r.CreateImage(ctx, img("safeimg001")))
		must(t, r.CreateToken(ctx, Token{ID: "t1", Name: "n", Hash: "real", CreatedAt: now}))
		for _, e := range evil {
			// Postgres refuses NUL bytes in text outright; that is an error, never a match.
			nul := strings.ContainsRune(e, 0)
			notFound := func(err error) bool {
				return errors.Is(err, ErrNotFound) || (nul && err != nil)
			}
			if _, err := r.GetImage(ctx, e); !notFound(err) {
				t.Errorf("GetImage(%q): %v", e, err)
			}
			if _, err := r.GetImageByDeleteHash(ctx, e); !notFound(err) {
				t.Errorf("GetImageByDeleteHash(%q): %v", e, err)
			}
			if _, err := r.FindToken(ctx, e); !notFound(err) {
				t.Errorf("FindToken(%q): %v", e, err)
			}
			if _, err := r.GetSession(ctx, e); !notFound(err) {
				t.Errorf("GetSession(%q): %v", e, err)
			}
			if nul {
				continue
			}
			must(t, r.DeleteImage(ctx, e))
			must(t, r.SetSetting(ctx, e, e))
			if v, err := r.GetSetting(ctx, e); err != nil || v != e {
				t.Errorf("setting round trip %q: %q %v", e, v, err)
			}
		}
		// And a hostile value stored verbatim comes back verbatim.
		i := img("evilimg001")
		i.TokenID = evil[1]
		must(t, r.CreateImage(ctx, i))
		got, _ := r.GetImage(ctx, "evilimg001")
		if got.TokenID != evil[1] {
			t.Fatal("stored value changed")
		}
		if st, _ := r.ImageStats(ctx); st.Images != 2 {
			t.Fatalf("images = %d: something was deleted", st.Images)
		}
		if _, err := r.FindToken(ctx, "real"); err != nil {
			t.Fatal("token table damaged")
		}
	})
}

func TestRebind(t *testing.T) {
	d := &db.DB{Postgres: true}
	if got := d.Rebind("a = ? AND b = ? LIMIT ?"); got != "a = $1 AND b = $2 LIMIT $3" {
		t.Fatal(got)
	}
	d.Postgres = false
	if d.Rebind("a = ?") != "a = ?" {
		t.Fatal()
	}
}

func TestPing(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) { must(t, r.Ping(ctx)) })
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Concurrent quota-checked inserts must never take the total above the limit,
// however they interleave.
func TestCreateImageWithinQuotaIsAtomic(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		const size, limit, workers = 1000, 2500, 8 // room for two
		var wg sync.WaitGroup
		var mu sync.Mutex
		accepted := 0
		start := make(chan struct{})
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				i2 := img(fmt.Sprintf("quota%05d", i))
				i2.Size = size
				i2.DeleteHash = fmt.Sprintf("hash%d", i)
				<-start
				err := r.CreateImageWithinQuota(ctx, i2, limit)
				switch {
				case err == nil:
					mu.Lock()
					accepted++
					mu.Unlock()
				case !errors.Is(err, ErrQuota):
					t.Error(err)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		st, err := r.ImageStats(ctx)
		must(t, err)
		if accepted != 2 || st.Bytes != 2*size || st.Bytes > limit {
			t.Fatalf("accepted %d, stored %d bytes (limit %d)", accepted, st.Bytes, limit)
		}
	})
}

func TestCreateImageWithinQuotaUnlimitedAndRelease(t *testing.T) {
	eachBackend(t, func(t *testing.T, r *Repo) {
		a := img("quotaaaaa1")
		a.Size = 900
		must(t, r.CreateImageWithinQuota(ctx, a, 0)) // 0 = unlimited
		b := img("quotabbbb2")
		b.Size = 200
		b.DeleteHash = "hb"
		if err := r.CreateImageWithinQuota(ctx, b, 1000); !errors.Is(err, ErrQuota) {
			t.Fatalf("want ErrQuota, got %v", err)
		}
		must(t, r.DeleteImage(ctx, a.ID)) // deleting releases the bytes
		must(t, r.CreateImageWithinQuota(ctx, b, 1000))
		if err := r.CreateImageWithinQuota(ctx, b, 1000); !errors.Is(err, ErrConflict) {
			t.Fatalf("want ErrConflict for a reused id, got %v", err)
		}
	})
}
