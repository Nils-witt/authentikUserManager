package pki_test

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"authentikManager/internal/pki"
)

// fakeClock is a settable time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newPending() (*pki.Pending, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	return pki.NewPending(clock.Now), clock
}

func annDownload() pki.Download {
	return pki.Download{UserPK: 1, Username: "ann", Filename: "ann.p12", Data: []byte("secret")}
}

func TestPending_Put(t *testing.T) {
	t.Parallel()
	p, clock := newPending()
	expires, err := p.Put("ab", annDownload())
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if want := clock.Now().Add(pki.DownloadTTL); !expires.Equal(want) {
		t.Errorf("expires = %v, want %v", expires, want)
	}
}

func TestPending_Take(t *testing.T) {
	t.Parallel()
	p, _ := newPending()
	if _, err := p.Put("ab", annDownload()); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Take("ab", "bob"); ok {
		t.Error("Take by another user succeeded")
	}
	d, ok := p.Take("ab", "ann")
	if !ok || string(d.Data) != "secret" || d.UserPK != 1 {
		t.Errorf("Take = %+v, %v, want the download", d, ok)
	}
	if _, ok := p.Take("ab", "ann"); ok {
		t.Error("second Take succeeded")
	}
}

func TestPending_Take_expired(t *testing.T) {
	t.Parallel()
	p, clock := newPending()
	data := []byte("secret")
	if _, err := p.Put("ab", pki.Download{Username: "ann", Data: data}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(pki.DownloadTTL)
	if p.Has("ab", "ann") {
		t.Error("Has after expiry = true")
	}
	if _, ok := p.Take("ab", "ann"); ok {
		t.Error("Take after expiry succeeded")
	}
	if string(data) == "secret" {
		t.Error("expired data was not cleared")
	}
}

func TestPending_Has(t *testing.T) {
	t.Parallel()
	p, _ := newPending()
	if _, err := p.Put("ab", annDownload()); err != nil {
		t.Fatal(err)
	}
	if !p.Has("ab", "ann") || p.Has("ab", "bob") || p.Has("cd", "ann") {
		t.Error("Has does not match the pending download of ann only")
	}
}

func TestPending_Delete(t *testing.T) {
	t.Parallel()
	p, _ := newPending()
	if _, err := p.Put("ab", annDownload()); err != nil {
		t.Fatal(err)
	}
	p.Delete("ab")
	if p.Has("ab", "ann") {
		t.Error("Has after Delete = true")
	}
}

func TestPending_Prune(t *testing.T) {
	t.Parallel()
	p, clock := newPending()
	data := []byte("secret")
	if _, err := p.Put("ab", pki.Download{Username: "ann", Data: data}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(pki.DownloadTTL - time.Second)
	if _, err := p.Put("cd", annDownload()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	p.Prune()
	if string(data) == "secret" {
		t.Error("Prune did not clear the expired download")
	}
	if !p.Has("cd", "ann") {
		t.Error("Prune removed a download that has not expired")
	}
}

func TestPending_Put_limit(t *testing.T) {
	t.Parallel()
	p, _ := newPending()
	var err error
	for i := 0; err == nil && i <= 1000; i++ {
		_, err = p.Put(strconv.Itoa(i), annDownload())
	}
	if err == nil {
		t.Error("Put never hit the limit")
	}
}

func TestPending_Run(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		p := pki.NewPending(time.Now)
		data := []byte("secret")
		if _, err := p.Put("ab", pki.Download{Username: "ann", Data: data}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			p.Run(ctx, pki.PruneInterval)
			close(done)
		}()
		time.Sleep(pki.DownloadTTL + pki.PruneInterval)
		synctest.Wait()
		if string(data) == "secret" {
			t.Error("Run did not prune the expired download")
		}
		cancel()
		<-done
	})
}
