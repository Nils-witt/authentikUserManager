package pki

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Limits of the pending downloads.
const (
	// DownloadTTL is how long a generated key can be downloaded.
	DownloadTTL = 15 * time.Minute
	// PruneInterval is how often Run removes expired downloads.
	PruneInterval = time.Minute
	// maxPending bounds the number of downloads held in memory.
	maxPending = 1000
)

// ErrTooManyDownloads is returned by Put when too many downloads are pending.
var ErrTooManyDownloads = errors.New("pki: too many pending downloads")

// Download is a file holding a generated private key, which its user may
// download once.
type Download struct {
	// UserPK and Username identify the user the key was issued to.
	UserPK   int
	Username string
	// Filename and ContentType describe the file for the browser.
	Filename    string
	ContentType string
	Data        []byte
}

type pendingEntry struct {
	download Download
	expires  time.Time
}

// Pending holds generated keys in memory until their user downloads them, at
// most once and within DownloadTTL. Keys are never written to disk, so they
// are lost on restart. It is safe for concurrent use.
type Pending struct {
	mu      sync.Mutex
	entries map[string]pendingEntry
	now     func() time.Time
}

// NewPending returns an empty Pending reading the time from now (normally time.Now).
func NewPending(now func() time.Time) *Pending {
	return &Pending{entries: map[string]pendingEntry{}, now: now}
}

// Put stores d for the certificate with serial and returns when it expires.
// It returns ErrTooManyDownloads when the limit of pending downloads is reached.
func (p *Pending) Put(serial string, d Download) (time.Time, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	if len(p.entries) >= maxPending {
		return time.Time{}, ErrTooManyDownloads
	}
	expires := p.now().Add(DownloadTTL)
	p.entries[serial] = pendingEntry{download: d, expires: expires}
	return expires, nil
}

// Take removes and returns the download for serial when it belongs to
// username and has not expired. The caller owns the returned data and should
// clear it once written. A download of another user is left in place.
func (p *Pending) Take(serial, username string) (Download, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[serial]
	if !ok || e.download.Username != username {
		return Download{}, false
	}
	delete(p.entries, serial)
	if !p.now().Before(e.expires) {
		clear(e.download.Data)
		return Download{}, false
	}
	return e.download, true
}

// Has reports whether a download for serial is pending for username.
func (p *Pending) Has(serial, username string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[serial]
	return ok && e.download.Username == username && p.now().Before(e.expires)
}

// Delete discards the download for serial, if any, e.g. after revoking its certificate.
func (p *Pending) Delete(serial string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[serial]; ok {
		clear(e.download.Data)
		delete(p.entries, serial)
	}
}

// Prune discards the expired downloads.
func (p *Pending) Prune() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
}

func (p *Pending) pruneLocked() {
	now := p.now()
	for serial, e := range p.entries {
		if !now.Before(e.expires) {
			clear(e.download.Data)
			delete(p.entries, serial)
		}
	}
}

// Run calls Prune every interval until ctx is done.
func (p *Pending) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Prune()
		}
	}
}
