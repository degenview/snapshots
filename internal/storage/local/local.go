// Package local stores images as files below one directory. All access goes
// through os.Root, so no name, link or race can reach outside it.
package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"time"

	"github.com/degenview/snapshots/internal/ids"
	"github.com/degenview/snapshots/internal/storage"
)

const tmpDir = ".tmp"

// Store is a directory-backed store.
type Store struct {
	root *os.Root
	dir  string
}

// New opens (creating it if needed) the directory dir.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("local storage: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("local storage: %w", err)
	}
	if err := root.MkdirAll(tmpDir, 0o700); err != nil {
		root.Close()
		return nil, fmt.Errorf("local storage: %w", err)
	}
	s := &Store{root: root, dir: dir}
	s.sweepTmp(time.Hour)
	return s, nil
}

// Close releases the directory handle.
func (s *Store) Close() error { return s.root.Close() }

// Kind implements storage.Store.
func (s *Store) Kind() string { return storage.KindLocal }

// objectPath shards by the first two characters to keep directories small.
func objectPath(id string) string { return path.Join(id[:2], id+".png") }

// Put implements storage.Store. The file appears atomically or not at all.
func (s *Store) Put(ctx context.Context, id string, r io.Reader, size int64) (err error) {
	if err := storage.CheckID(id); err != nil {
		return err
	}
	suffix, err := ids.Random(16)
	if err != nil {
		return err
	}
	tmp := path.Join(tmpDir, suffix)
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			s.root.Remove(tmp)
		}
	}()
	n, err := io.Copy(f, io.LimitReader(r, size+1))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("local storage: wrote %d bytes, expected %d", n, size)
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = s.root.MkdirAll(id[:2], 0o700); err != nil {
		return err
	}
	return s.root.Rename(tmp, objectPath(id))
}

// Open implements storage.Store.
func (s *Store) Open(_ context.Context, id string) (io.ReadSeekCloser, error) {
	if err := storage.CheckID(id); err != nil {
		return nil, err
	}
	f, err := s.root.Open(objectPath(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Delete implements storage.Store.
func (s *Store) Delete(_ context.Context, id string) error {
	if err := storage.CheckID(id); err != nil {
		return err
	}
	err := s.root.Remove(objectPath(id))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Ping implements storage.Store: the directory must still be writable.
func (s *Store) Ping(_ context.Context) error {
	suffix, err := ids.Random(16)
	if err != nil {
		return err
	}
	p := path.Join(tmpDir, "ping-"+suffix)
	f, err := s.root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	return s.root.Remove(p)
}

// sweepTmp removes leftovers of uploads that were interrupted by a crash.
func (s *Store) sweepTmp(olderThan time.Duration) {
	d, err := s.root.Open(tmpDir)
	if err != nil {
		return
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && time.Since(info.ModTime()) > olderThan {
			s.root.Remove(path.Join(tmpDir, e.Name()))
		}
	}
}
