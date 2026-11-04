// Package storage holds the image bytes, either on local disk or in an
// S3-compatible bucket. Objects are addressed only by a validated image id.
package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/degenview/snapshots/internal/ids"
)

// Kinds of backend, as stored in the database.
const (
	KindLocal = "local"
	KindS3    = "s3"
)

// Errors returned by every backend.
var (
	ErrNotFound  = errors.New("storage: object not found")
	ErrInvalidID = errors.New("storage: invalid image id")
)

// Store is an image store.
type Store interface {
	// Kind is KindLocal or KindS3.
	Kind() string
	// Put stores size bytes from r under id, replacing any object there.
	Put(ctx context.Context, id string, r io.Reader, size int64) error
	// Open returns the object, or ErrNotFound.
	Open(ctx context.Context, id string) (io.ReadSeekCloser, error)
	// Delete removes the object. A missing object is not an error.
	Delete(ctx context.Context, id string) error
	// Ping checks the backend is usable.
	Ping(ctx context.Context) error
}

// CheckID returns ErrInvalidID unless id is exactly an image id. Backends call
// it first so no other string can reach a path or an object key.
func CheckID(id string) error {
	if !ids.ValidImageID(id) {
		return ErrInvalidID
	}
	return nil
}

// Probe writes, reads back and deletes a throwaway object, proving the backend
// is writable. It is what the setup wizard's "Test" button runs.
func Probe(ctx context.Context, s Store) error {
	id, err := ids.ImageID()
	if err != nil {
		return err
	}
	payload := []byte("degenview-snapshots probe " + id)
	if err := s.Put(ctx, id, bytes.NewReader(payload), int64(len(payload))); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	defer s.Delete(context.WithoutCancel(ctx), id)
	f, err := s.Open(ctx, id)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	defer f.Close()
	got, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return errors.New("read back different bytes than were written")
	}
	if err := s.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}
