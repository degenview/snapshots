package server

import (
	"context"
	"net/http"
	"time"
)

// Argon2id costs 64 MiB per operation (see internal/auth), and per-client rate
// limits do not bound how many run at once: attempts from many addresses can
// overlap. A small process-wide slot count keeps worst-case memory and CPU
// predictable on a small instance. Excess attempts wait briefly and then get a
// 503 instead of queueing without limit.
const maxConcurrentHashes = 2

// hashSlotWait is a variable so tests can shorten it.
var hashSlotWait = 2 * time.Second

// acquireHash reserves one password-hashing slot. On success it returns the
// function that frees it. When none frees up within hashSlotWait (or the client
// goes away) it answers 503 itself and reports false.
func (s *Server) acquireHash(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	ctx, cancel := context.WithTimeout(r.Context(), hashSlotWait)
	defer cancel()
	select {
	case s.hashSem <- struct{}{}:
		return func() { <-s.hashSem }, true
	case <-ctx.Done():
		w.Header().Set("Retry-After", "2")
		apiFail(w, http.StatusServiceUnavailable, "busy", "The server is busy. Try again shortly.")
		return nil, false
	}
}
