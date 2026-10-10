package audit

import (
	"context"
	"log/slog"
	"time"
)

// PruneInterval is how often Retain deletes expired entries.
const PruneInterval = time.Hour

// Pruner deletes audit log entries.
type Pruner interface {
	// PruneAudit deletes the entries recorded before cutoff and returns how many it deleted.
	PruneAudit(ctx context.Context, cutoff time.Time) (int64, error)
}

// Retain deletes the entries older than retention from p right away and then
// every interval, until ctx is done. Failures are logged and retried at the
// next interval.
func Retain(ctx context.Context, p Pruner, retention, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		prune(ctx, p, retention, logger)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func prune(ctx context.Context, p Pruner, retention time.Duration, logger *slog.Logger) {
	cutoff := time.Now().Add(-retention)
	n, err := p.PruneAudit(ctx, cutoff)
	if err != nil {
		if ctx.Err() == nil {
			logger.ErrorContext(ctx, "pruning audit log failed", slog.Any("error", err))
		}
		return
	}
	if n > 0 {
		logger.InfoContext(ctx, "pruned audit log",
			slog.Int64("deleted", n),
			slog.Time("cutoff", cutoff),
		)
	}
}
