package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"authentikManager/internal/audit"
)

// likeEscaper escapes the LIKE wildcards so search text matches literally.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// RecordAudit appends e to the audit log. The store sets its ID and time.
func (s *Store) RecordAudit(ctx context.Context, e audit.Entry) error {
	details := e.Details
	if details == nil {
		details = map[string]string{}
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO audit_log (actor, action, target, details) VALUES ($1, $2, $3, $4)`,
		e.Actor, e.Action, e.Target, details,
	); err != nil {
		return fmt.Errorf("store: recording audit entry %q: %w", e.Action, err)
	}
	return nil
}

// ListAudit returns the audit log entries matching q, newest first. q must be
// normalized (see audit.Query.Normalize).
func (s *Store) ListAudit(ctx context.Context, q audit.Query) ([]audit.Entry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, created_at, actor, action, target, details
		FROM audit_log
		WHERE ($1 = '' OR actor ILIKE $2 OR target ILIKE $2)
		  AND ($3 = '' OR action = $3)
		  AND ($4::bigint = 0 OR id < $4)
		ORDER BY id DESC
		LIMIT $5`,
		q.Search, "%"+likeEscaper.Replace(q.Search)+"%", q.Action, q.Before, q.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: querying audit log: %w", err)
	}
	entries, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (audit.Entry, error) {
		var e audit.Entry
		err := row.Scan(&e.ID, &e.Time, &e.Actor, &e.Action, &e.Target, &e.Details)
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: reading audit log: %w", err)
	}
	return entries, nil
}

// PruneAudit deletes the audit log entries recorded before cutoff and returns
// how many it deleted.
func (s *Store) PruneAudit(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM audit_log WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: pruning audit log: %w", err)
	}
	return tag.RowsAffected(), nil
}
