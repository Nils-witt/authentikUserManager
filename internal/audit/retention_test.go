package audit_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"authentikManager/internal/audit"
)

// fakePruner records the cutoffs passed to PruneAudit.
type fakePruner struct {
	mu      sync.Mutex
	cutoffs []time.Time
	err     error
}

func (f *fakePruner) PruneAudit(_ context.Context, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cutoffs = append(f.cutoffs, cutoff)
	return 1, f.err
}

func (f *fakePruner) calls() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.cutoffs...)
}

func TestRetain(t *testing.T) {
	t.Parallel()
	for name, pruneErr := range map[string]error{"success": nil, "failure": errors.New("connection refused")} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				const retention = 30 * 24 * time.Hour
				p := &fakePruner{err: pruneErr}
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				start := time.Now()
				go func() {
					audit.Retain(ctx, p, retention, time.Hour, slog.New(slog.DiscardHandler))
					close(done)
				}()

				// Pruned at once, then every hour, also after failures.
				time.Sleep(2*time.Hour + time.Minute)
				synctest.Wait()
				calls := p.calls()
				if len(calls) != 3 {
					t.Fatalf("pruned %d times, want 3", len(calls))
				}
				for i, cutoff := range calls {
					expected := start.Add(time.Duration(i)*time.Hour - retention)
					if !cutoff.Equal(expected) {
						t.Errorf("cutoff %d = %v, want %v", i, cutoff, expected)
					}
				}

				cancel()
				<-done
			})
		})
	}
}
