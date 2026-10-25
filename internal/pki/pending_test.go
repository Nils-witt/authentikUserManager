package pki_test

import (
	"context"
	"errors"
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
	return pki.Download{UserPK: 1, Username: "ann", Downloader: "ann", Filename: "ann.p12", Data: []byte("secret")}
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

func TestPending_Take_downloader(t *testing.T) {
	t.Parallel()
	p, _ := newPending()
	// An operator issued the key for the service account svc.
	d := pki.Download{UserPK: 2, Username: "svc", Downloader: "ann", Data: []byte("secret")}
	if _, err := p.Put("ab", d); err != nil {
		t.Fatal(err)
	}
	if p.Has("ab", "svc") {
		t.Error("Has for the certificate's user, want only for its downloader")
	}
	if _, ok := p.Take("ab", "svc"); ok {
		t.Error("Take by the certificate's user succeeded")
	}
	if got, ok := p.Take("ab", "ann"); !ok || got.Username != "svc" {
		t.Errorf("Take by the downloader = %+v, %v, want the download", got, ok)
	}
}

func TestPending_Take_expired(t *testing.T) {
	t.Parallel()
	p, clock := newPending()
	data := []byte("secret")
	if _, err := p.Put("ab", pki.Download{Username: "ann", Downloader: "ann", Data: data}); err != nil {
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
	if _, err := p.Put("ab", pki.Download{Username: "ann", Downloader: "ann", Data: data}); err != nil {
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
		d := annDownload()
		d.Downloader = "user" + strconv.Itoa(i)
		_, err = p.Put(strconv.Itoa(i), d)
	}
	if !errors.Is(err, pki.ErrTooManyDownloads) {
		t.Errorf("Put error = %v, want ErrTooManyDownloads", err)
	}
}

func TestPending_Put_downloaderLimit(t *testing.T) {
	t.Parallel()
	p, clock := newPending()
	for i := range pki.MaxPendingPerDownloader {
		if _, err := p.Put(strconv.Itoa(i), annDownload()); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	if err := p.Check("ann"); !errors.Is(err, pki.ErrTooManyDownloaderDownloads) {
		t.Errorf("Check = %v, want ErrTooManyDownloaderDownloads", err)
	}
	if _, err := p.Put("next", annDownload()); !errors.Is(err, pki.ErrTooManyDownloaderDownloads) {
		t.Errorf("Put = %v, want ErrTooManyDownloaderDownloads", err)
	}
	// Other downloaders are not affected.
	if err := p.Check("bob"); err != nil {
		t.Errorf("Check of another downloader = %v", err)
	}
	// A download taken or expired frees its place.
	if _, ok := p.Take("0", "ann"); !ok {
		t.Fatal("Take failed")
	}
	if err := p.Check("ann"); err != nil {
		t.Errorf("Check after a download = %v", err)
	}
	clock.Advance(pki.DownloadTTL)
	if _, err := p.Put("later", annDownload()); err != nil {
		t.Errorf("Put after the downloads expired = %v", err)
	}
}

func TestPending_Run(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		p := pki.NewPending(time.Now)
		data := []byte("secret")
		if _, err := p.Put("ab", pki.Download{Username: "ann", Downloader: "ann", Data: data}); err != nil {
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
