package janitor

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/degenview/snapshots/internal/db"
	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/storage"
	"github.com/degenview/snapshots/internal/storage/local"
)

var ctx = context.Background()

type fixture struct {
	r     *repo.Repo
	store *local.Store
	now   time.Time
	j     *Janitor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d, err := db.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := local.New(filepath.Join(t.TempDir(), "img"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fixture{r: repo.New(d), store: st, now: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	f.j = &Janitor{Repo: f.r, Store: func() storage.Store { return f.store }, Now: func() time.Time { return f.now }, Batch: 3}
	return f
}

func (f *fixture) add(t *testing.T, expires time.Duration) string {
	t.Helper()
	id, _ := ids.ImageID()
	sec, _ := ids.DeleteSecret()
	img := repo.Image{ID: id, DeleteHash: ids.Hash(sec), Storage: storage.KindLocal, Size: 1, Width: 1, Height: 1, CreatedAt: f.now}
	if expires != 0 {
		img.ExpiresAt = f.now.Add(expires)
	}
	if err := f.r.CreateImage(ctx, img); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Put(ctx, id, bytes.NewReader([]byte("x")), 1); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fixture) has(id string) (row, object bool) {
	_, err := f.r.GetImage(ctx, id)
	row = err == nil
	o, err := f.store.Open(ctx, id)
	if err == nil {
		o.Close()
	}
	return row, err == nil
}

func TestSweepRemovesOnlyExpired(t *testing.T) {
	f := newFixture(t)
	var gone, kept []string
	for i := 0; i < 7; i++ { // more than one batch
		gone = append(gone, f.add(t, time.Duration(i+1)*time.Minute))
	}
	kept = append(kept, f.add(t, 24*time.Hour), f.add(t, 0)) // later, and never
	f.now = f.now.Add(time.Hour)

	n, err := f.j.Sweep(ctx)
	if err != nil || n != 7 {
		t.Fatalf("removed %d, %v", n, err)
	}
	for _, id := range gone {
		if row, obj := f.has(id); row || obj {
			t.Errorf("%s survived (row=%v object=%v)", id, row, obj)
		}
	}
	for _, id := range kept {
		if row, obj := f.has(id); !row || !obj {
			t.Errorf("%s was removed (row=%v object=%v)", id, row, obj)
		}
	}
	if n, _ := f.j.Sweep(ctx); n != 0 {
		t.Fatal("second sweep found work")
	}
}

func TestSweepBoundaryIsInclusive(t *testing.T) {
	f := newFixture(t)
	id := f.add(t, time.Minute)
	f.now = f.now.Add(time.Minute - time.Second)
	if n, _ := f.j.Sweep(ctx); n != 0 {
		t.Fatal("removed early")
	}
	f.now = f.now.Add(time.Second)
	if n, _ := f.j.Sweep(ctx); n != 1 {
		t.Fatal("not removed at expiry")
	}
	if row, _ := f.has(id); row {
		t.Fatal()
	}
}

func TestSweepSurvivesMissingObject(t *testing.T) {
	f := newFixture(t)
	id := f.add(t, time.Minute)
	f.store.Delete(ctx, id) // e.g. a crash between row and object
	f.now = f.now.Add(time.Hour)
	if n, err := f.j.Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
}

// flaky fails deletes until told otherwise.
type flaky struct {
	storage.Store
	fail bool
}

func (s *flaky) Delete(ctx context.Context, id string) error {
	if s.fail {
		return errors.New("backend down")
	}
	return s.Store.Delete(ctx, id)
}

func TestFailedObjectDeleteKeepsRowForRetry(t *testing.T) {
	f := newFixture(t)
	fl := &flaky{Store: f.store, fail: true}
	f.j.Store = func() storage.Store { return fl }
	id := f.add(t, time.Minute)
	f.now = f.now.Add(time.Hour)

	if n, err := f.j.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	if row, _ := f.has(id); !row {
		t.Fatal("row deleted although the object is still there; it would leak forever")
	}
	fl.fail = false
	if n, err := f.j.Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("retry: %d %v", n, err)
	}
	if row, obj := f.has(id); row || obj {
		t.Fatal("not cleaned on retry")
	}
}

func TestNoStoreBeforeSetup(t *testing.T) {
	f := newFixture(t)
	f.add(t, time.Minute)
	f.now = f.now.Add(time.Hour)
	f.j.Store = func() storage.Store { return nil }
	if n, err := f.j.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestSkipsImagesOfOtherBackends(t *testing.T) {
	f := newFixture(t)
	id, _ := ids.ImageID()
	f.r.CreateImage(ctx, repo.Image{ID: id, DeleteHash: "h", Storage: storage.KindS3, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Minute)})
	f.now = f.now.Add(time.Hour)
	if n, err := f.j.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := f.r.GetImage(ctx, id); err != nil {
		t.Fatal("row for another backend was dropped without its object")
	}
}

func TestPruneIsCalled(t *testing.T) {
	f := newFixture(t)
	called := 0
	f.j.Prune = func(context.Context) error { called++; return errors.New("ignored") }
	f.j.Sweep(ctx)
	if called != 1 {
		t.Fatal(called)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	f := newFixture(t)
	f.j.Interval = 10 * time.Millisecond
	id := f.add(t, time.Nanosecond)
	f.now = f.now.Add(time.Hour)
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { f.j.Run(c); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if row, _ := f.has(id); !row {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if row, _ := f.has(id); row {
		t.Fatal("Run never swept")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
