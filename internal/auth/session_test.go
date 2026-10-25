package auth

import (
	"testing"
	"time"
)

// fakeClock is a settable time source for the session store.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestStore(ttl, idle time.Duration) (*sessionStore, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)}
	s := newSessionStore(ttl, idle)
	s.now = clock.now
	return s, clock
}

func TestSessionStore_idleTimeout(t *testing.T) {
	t.Parallel()
	s, clock := newTestStore(8*time.Hour, 30*time.Minute)
	id := s.create(User{Username: "ann"}, "token", "sid")

	// Use within the idle timeout keeps the session alive past the first timeout.
	clock.t = clock.t.Add(20 * time.Minute)
	if _, ok := s.get(id, true); !ok {
		t.Fatal("session ended after 20 minutes of use")
	}
	clock.t = clock.t.Add(20 * time.Minute)
	if _, ok := s.get(id, true); !ok {
		t.Fatal("session ended 20 minutes after its last use")
	}

	// Background requests do not count as use.
	clock.t = clock.t.Add(20 * time.Minute)
	if _, ok := s.get(id, false); !ok {
		t.Fatal("session ended 20 minutes after its last use")
	}
	clock.t = clock.t.Add(11 * time.Minute)
	if _, ok := s.get(id, false); ok {
		t.Fatal("session alive 31 minutes after its last use")
	}
	if _, ok := s.sessions[id]; ok {
		t.Error("ended session still stored")
	}
}

func TestSessionStore_lifetime(t *testing.T) {
	t.Parallel()
	s, clock := newTestStore(time.Hour, 30*time.Minute)
	id := s.create(User{Username: "ann"}, "token", "sid")
	// Used every 20 minutes, the session lasts until the end of its lifetime.
	for range 3 {
		clock.t = clock.t.Add(20 * time.Minute)
		if _, ok := s.get(id, true); !ok {
			t.Fatalf("session ended at %v, within its lifetime", clock.t)
		}
	}
	clock.t = clock.t.Add(time.Second)
	if _, ok := s.get(id, true); ok {
		t.Error("session alive past its lifetime despite use")
	}
}

func TestSessionStore_prune(t *testing.T) {
	t.Parallel()
	s, clock := newTestStore(8*time.Hour, 30*time.Minute)
	idle := s.create(User{Username: "idle"}, "token", "sid1")
	clock.t = clock.t.Add(20 * time.Minute)
	active := s.create(User{Username: "active"}, "token", "sid2")
	clock.t = clock.t.Add(15 * time.Minute)
	s.prune()
	if _, ok := s.sessions[idle]; ok {
		t.Error("idle session not pruned")
	}
	if _, ok := s.sessions[active]; !ok {
		t.Error("active session pruned")
	}
}
