package ratelimit_test

import (
	"testing"
	"time"

	"authentikManager/internal/ratelimit"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestLimiter_Allow(t *testing.T) {
	t.Parallel()
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := ratelimit.New(3, 10*time.Second, c.now)

	for i := range 3 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("event %d of the burst refused", i+1)
		}
	}
	ok, wait := l.Allow("a")
	if ok || wait != 10*time.Second {
		t.Fatalf("event after the burst: ok = %v, wait = %v, want refused for 10s", ok, wait)
	}
	// Other keys have their own bucket.
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("other key refused")
	}

	c.t = c.t.Add(4 * time.Second)
	if ok, wait := l.Allow("a"); ok || wait != 6*time.Second {
		t.Fatalf("after 4s: ok = %v, wait = %v, want refused for 6s", ok, wait)
	}
	c.t = c.t.Add(6 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("refused after a token was earned")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("allowed beyond the earned token")
	}
}

func TestLimiter_prunesFullBuckets(t *testing.T) {
	t.Parallel()
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := ratelimit.New(2, time.Second, c.now)
	l.Allow("a")
	l.Allow("b")
	if n := l.Len(); n != 2 {
		t.Fatalf("Len = %d, want 2", n)
	}
	c.t = c.t.Add(time.Minute)
	l.Allow("c")
	if n := l.Len(); n != 1 {
		t.Errorf("Len after pruning = %d, want 1 (only c)", n)
	}
}
