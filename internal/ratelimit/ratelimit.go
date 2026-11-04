// Package ratelimit implements per-client token buckets and the logic for
// deciding which address a request really came from.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limiter is a set of token buckets keyed by client. It is safe for
// concurrent use. State lives in memory: with several instances each enforces
// its own limit.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a Limiter allowing `burst` requests at once and then `per`
// ÷ `n` sustained: n requests every `per`. maxKeys bounds memory: past it, an
// arbitrary bucket is evicted for each new key. now may be nil.
func New(n int, per time.Duration, burst int, maxKeys int, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if maxKeys < 1 {
		maxKeys = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    float64(n) / per.Seconds(),
		burst:   float64(burst),
		maxKeys: maxKeys,
		now:     now,
		buckets: make(map[string]*bucket),
	}
}

// Allow takes one token for key. When it refuses it says how long until a
// token will be available.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	return l.take(key, 1)
}

func (l *Limiter) take(key string, cost float64) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.evictLocked(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
	}
	if b.tokens >= cost {
		b.tokens -= cost
		return true, 0
	}
	if l.rate <= 0 {
		return false, time.Hour
	}
	wait := time.Duration((cost - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// evictLocked frees room for one key. It first drops buckets that have fully
// refilled (they carry no information), and otherwise one arbitrary bucket, so
// memory stays bounded however many addresses an attacker uses.
func (l *Limiter) evictLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) < l.maxKeys {
		return
	}
	for k := range l.buckets {
		delete(l.buckets, k)
		return
	}
}

// Len reports how many keys are tracked.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Reconfigure changes the rate and burst for future requests. Existing buckets
// keep their tokens (clamped to the new burst on next use).
func (l *Limiter) Reconfigure(n int, per time.Duration, burst int) {
	if burst < 1 {
		burst = 1
	}
	l.mu.Lock()
	l.rate = float64(n) / per.Seconds()
	l.burst = float64(burst)
	l.mu.Unlock()
}
