// Package ratelimit limits how often each client may do something, with one
// token bucket per key, e.g. per client IP address or per user.
package ratelimit

import (
	"sync"
	"time"
)

// pruneInterval is how often Allow deletes the buckets that are full again.
const pruneInterval = time.Minute

// Limiter allows each key burst events at once and one more every interval.
// It is safe for concurrent use.
type Limiter struct {
	mu        sync.Mutex
	interval  time.Duration
	burst     int
	now       func() time.Time
	buckets   map[string]bucket
	lastPrune time.Time
}

// bucket is the state of one key: tokens it had at updated.
type bucket struct {
	tokens  float64
	updated time.Time
}

// New returns a Limiter allowing burst events per key at once and one more
// every interval, reading the time from now (normally time.Now).
func New(burst int, interval time.Duration, now func() time.Time) *Limiter {
	return &Limiter{interval: interval, burst: burst, now: now, buckets: map[string]bucket{}, lastPrune: now()}
}

// Allow takes a token of key. When none is left it returns false and how long
// until the next one.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastPrune) >= pruneInterval {
		l.pruneLocked(now)
	}
	b := l.refill(key, now)
	if b.tokens < 1 {
		l.buckets[key] = b
		return false, time.Duration((1 - b.tokens) * float64(l.interval))
	}
	b.tokens--
	l.buckets[key] = b
	return true, 0
}

// refill returns the bucket of key with the tokens earned since its last use.
func (l *Limiter) refill(key string, now time.Time) bucket {
	b, ok := l.buckets[key]
	if !ok {
		return bucket{tokens: float64(l.burst), updated: now}
	}
	if elapsed := now.Sub(b.updated); elapsed > 0 {
		b.tokens = min(float64(l.burst), b.tokens+float64(elapsed)/float64(l.interval))
	}
	b.updated = now
	return b
}

// pruneLocked deletes the buckets that are full again, which behave like
// missing ones, so the map does not grow with every key ever seen.
func (l *Limiter) pruneLocked(now time.Time) {
	for key := range l.buckets {
		if l.refill(key, now).tokens >= float64(l.burst) {
			delete(l.buckets, key)
		}
	}
	l.lastPrune = now
}

// Len returns the number of keys with a bucket that is not full.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
