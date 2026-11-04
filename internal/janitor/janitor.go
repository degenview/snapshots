// Package janitor removes expired images and sessions on a schedule.
package janitor

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/storage"
)

// Janitor sweeps expired data.
type Janitor struct {
	Repo *repo.Repo
	// Store returns the active image store, or nil before setup.
	Store func() storage.Store
	// Prune is called each sweep to drop expired login sessions; may be nil.
	Prune    func(context.Context) error
	Now      func() time.Time
	Log      *slog.Logger
	Interval time.Duration
	Batch    int
}

func (j *Janitor) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

// Sweep deletes up to Batch expired images, repeating until none remain or ctx
// ends. For each image the object goes first and the row second: if the object
// cannot be deleted the row stays, the image stays unreachable (reads check the
// expiry), and the next sweep tries again. It returns how many images were removed.
func (j *Janitor) Sweep(ctx context.Context) (int, error) {
	if j.Prune != nil {
		if err := j.Prune(ctx); err != nil && j.Log != nil {
			j.Log.Warn("pruning sessions failed", "err", err)
		}
	}
	store := j.Store()
	if store == nil {
		return 0, nil
	}
	batch := j.Batch
	if batch <= 0 {
		batch = 100
	}
	total := 0
	for ctx.Err() == nil {
		expired, err := j.Repo.ExpiredImages(ctx, j.now(), batch)
		if err != nil {
			return total, err
		}
		progress := 0
		for _, img := range expired {
			if img.Storage != store.Kind() {
				j.warn("expired image belongs to an inactive storage backend; leaving it", "storage", img.Storage)
				continue
			}
			if err := store.Delete(ctx, img.ID); err != nil {
				j.warn("deleting expired object failed; will retry", "err", err)
				continue
			}
			if err := j.Repo.DeleteImage(ctx, img.ID); err != nil {
				return total, err
			}
			progress++
		}
		total += progress
		if progress == 0 || len(expired) < batch {
			break
		}
	}
	return total, nil
}

func (j *Janitor) warn(msg string, args ...any) {
	if j.Log != nil {
		j.Log.Warn(msg, args...)
	}
}

// Run sweeps every Interval (with up to 10% jitter, so replicas do not all
// fire together) until ctx is cancelled.
func (j *Janitor) Run(ctx context.Context) {
	interval := j.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	for {
		if n, err := j.Sweep(ctx); err != nil && ctx.Err() == nil {
			j.warn("sweep failed", "err", err)
		} else if n > 0 && j.Log != nil {
			j.Log.Info("expired images removed", "count", n)
		}
		wait := interval + time.Duration(rand.Int64N(int64(interval)/10+1)) //nolint:gosec // jitter, not security
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
