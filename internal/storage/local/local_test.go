package local

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/storage"
)

var ctx = context.Background()

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "images")
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func put(t *testing.T, s *Store, id string, data []byte) {
	t.Helper()
	if err := s.Put(ctx, id, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	s, dir := newStore(t)
	id, _ := ids.ImageID()
	data := []byte("\x89PNG pretend")
	put(t, s, id, data)

	f, err := s.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("bytes differ")
	}
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		t.Fatal("seek on closed file should fail")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, id[:2], id+".png"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("file mode %v", info.Mode().Perm())
		}
		dinfo, _ := os.Stat(filepath.Join(dir, id[:2]))
		if dinfo.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v", dinfo.Mode().Perm())
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, tmpDir)); len(ents) != 0 {
		t.Fatalf("temp files left: %v", ents)
	}
}

func TestOpenSeekable(t *testing.T) {
	s, _ := newStore(t)
	id, _ := ids.ImageID()
	put(t, s, id, []byte("0123456789"))
	f, _ := s.Open(ctx, id)
	defer f.Close()
	if n, err := f.Seek(0, io.SeekEnd); err != nil || n != 10 {
		t.Fatal(n, err)
	}
}

func TestOverwrite(t *testing.T) {
	s, _ := newStore(t)
	id, _ := ids.ImageID()
	put(t, s, id, []byte("one"))
	put(t, s, id, []byte("two"))
	f, _ := s.Open(ctx, id)
	defer f.Close()
	if b, _ := io.ReadAll(f); string(b) != "two" {
		t.Fatal(string(b))
	}
}

func TestNotFoundAndIdempotentDelete(t *testing.T) {
	s, _ := newStore(t)
	id, _ := ids.ImageID()
	if _, err := s.Open(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	put(t, s, id, []byte("x"))
	if err := s.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("still there after delete")
	}
}

func TestRejectsHostileIDs(t *testing.T) {
	s, dir := newStore(t)
	secret := filepath.Join(filepath.Dir(dir), "secret.png")
	os.WriteFile(secret, []byte("top secret"), 0o600)
	for _, id := range []string{"", "../secret", "../../etc/passwd", "ab/../../secret", "/etc/passwd", "..", ".", "aa..%2f..%2fx", "a\x00bcdefghij", strings.Repeat("a", 11), "abcdefghi.", "abcdefghi/", `abcdefgh\\`} {
		if _, err := s.Open(ctx, id); !errors.Is(err, storage.ErrInvalidID) {
			t.Errorf("Open(%q) = %v", id, err)
		}
		if err := s.Put(ctx, id, strings.NewReader("x"), 1); !errors.Is(err, storage.ErrInvalidID) {
			t.Errorf("Put(%q) = %v", id, err)
		}
		if err := s.Delete(ctx, id); !errors.Is(err, storage.ErrInvalidID) {
			t.Errorf("Delete(%q) = %v", id, err)
		}
	}
	if b, _ := os.ReadFile(secret); string(b) != "top secret" {
		t.Fatal("file outside the root was touched")
	}
}

// A symlink planted inside the data directory must not lead out of it.
func TestSymlinkCannotEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	s, dir := newStore(t)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "abcdefghij.png"), []byte("outside"), 0o600)
	if err := os.Symlink(outside, filepath.Join(dir, "ab")); err != nil {
		t.Fatal(err)
	}
	if f, err := s.Open(ctx, "abcdefghij"); err == nil {
		f.Close()
		t.Fatal("followed a symlink out of the root")
	}
	if err := s.Put(ctx, "abcdefghij", strings.NewReader("x"), 1); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "abcdefghij.png")); string(b) != "outside" {
		t.Fatal("outside file changed")
	}
}

func TestPutSizeMismatchLeavesNothing(t *testing.T) {
	s, dir := newStore(t)
	id, _ := ids.ImageID()
	if err := s.Put(ctx, id, strings.NewReader("abc"), 5); err == nil {
		t.Fatal("short body accepted")
	}
	if err := s.Put(ctx, id, strings.NewReader("abcdef"), 3); err == nil {
		t.Fatal("long body accepted")
	}
	if _, err := s.Open(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("partial object visible")
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, tmpDir)); len(ents) != 0 {
		t.Fatalf("temp files left: %v", ents)
	}
}

func TestPutHonoursCancelledContext(t *testing.T) {
	s, _ := newStore(t)
	id, _ := ids.ImageID()
	c, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Put(c, id, strings.NewReader("x"), 1); err == nil {
		t.Fatal("cancelled put succeeded")
	}
	if _, err := s.Open(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("object exists after cancelled put")
	}
}

func TestConcurrentPuts(t *testing.T) {
	s, _ := newStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, _ := ids.ImageID()
			data := bytes.Repeat([]byte{byte(i)}, 4096)
			if err := s.Put(ctx, id, bytes.NewReader(data), int64(len(data))); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestSweepTmp(t *testing.T) {
	s, dir := newStore(t)
	old := filepath.Join(dir, tmpDir, "old")
	fresh := filepath.Join(dir, tmpDir, "fresh")
	os.WriteFile(old, nil, 0o600)
	os.WriteFile(fresh, nil, 0o600)
	os.Chtimes(old, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour))
	s.sweepTmp(time.Hour)
	if _, err := os.Stat(old); err == nil {
		t.Fatal("old temp file kept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh temp file removed")
	}
}

func TestPingAndProbe(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := storage.Probe(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s.Kind() != storage.KindLocal {
		t.Fatal(s.Kind())
	}
}
