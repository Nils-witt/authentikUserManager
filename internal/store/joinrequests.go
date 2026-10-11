package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"authentikManager/internal/joinrequest"
)

// uniqueViolation is the PostgreSQL error code (SQLSTATE) of a unique constraint violation.
const uniqueViolation = "23505"

// joinRequestColumns are the columns scanned by scanJoinRequest, in order.
const joinRequestColumns = `id, group_pk, group_name, user_pk, username, message, status,
	created_at, decided_at, COALESCE(decided_by, '')`

func scanJoinRequest(row pgx.CollectableRow) (joinrequest.Request, error) {
	var jr joinrequest.Request
	err := row.Scan(&jr.ID, &jr.GroupPK, &jr.GroupName, &jr.UserPK, &jr.Username, &jr.Message, &jr.Status,
		&jr.CreatedAt, &jr.DecidedAt, &jr.DecidedBy)
	return jr, err
}

// CreateJoinRequest stores a new pending request and returns it with its ID
// and time set. It returns joinrequest.ErrPending when the user already has a
// pending request for the group.
func (s *Store) CreateJoinRequest(ctx context.Context, jr joinrequest.Request) (joinrequest.Request, error) {
	rows, err := s.pool.Query(ctx, `
		INSERT INTO group_join_requests (group_pk, group_name, user_pk, username, message)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+joinRequestColumns,
		jr.GroupPK, jr.GroupName, jr.UserPK, jr.Username, jr.Message,
	)
	if err != nil {
		return joinrequest.Request{}, fmt.Errorf("store: creating join request: %w", err)
	}
	created, err := pgx.CollectExactlyOneRow(rows, scanJoinRequest)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == uniqueViolation {
		return joinrequest.Request{}, joinrequest.ErrPending
	}
	if err != nil {
		return joinrequest.Request{}, fmt.Errorf("store: creating join request: %w", err)
	}
	return created, nil
}

// GetJoinRequest returns the request with id, or joinrequest.ErrNotFound.
func (s *Store) GetJoinRequest(ctx context.Context, id int64) (joinrequest.Request, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+joinRequestColumns+` FROM group_join_requests WHERE id = $1`, id)
	if err != nil {
		return joinrequest.Request{}, fmt.Errorf("store: querying join request %d: %w", id, err)
	}
	jr, err := pgx.CollectExactlyOneRow(rows, scanJoinRequest)
	if errors.Is(err, pgx.ErrNoRows) {
		return joinrequest.Request{}, joinrequest.ErrNotFound
	}
	if err != nil {
		return joinrequest.Request{}, fmt.Errorf("store: reading join request %d: %w", id, err)
	}
	return jr, nil
}

// ListJoinRequests returns the requests matching q, newest first, up to
// joinrequest.MaxList of them.
func (s *Store) ListJoinRequests(ctx context.Context, q joinrequest.Query) ([]joinrequest.Request, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+joinRequestColumns+`
		FROM group_join_requests
		WHERE ($1 = '' OR status = $1)
		  AND ($2::text[] IS NULL OR group_pk = ANY($2))
		  AND ($3 = '' OR username = $3)
		ORDER BY id DESC
		LIMIT $4`,
		q.Status, q.GroupPKs, q.Username, joinrequest.MaxList,
	)
	if err != nil {
		return nil, fmt.Errorf("store: querying join requests: %w", err)
	}
	list, err := pgx.CollectRows(rows, scanJoinRequest)
	if err != nil {
		return nil, fmt.Errorf("store: reading join requests: %w", err)
	}
	return list, nil
}

// DecideJoinRequest approves or rejects the pending request with id and
// returns it. actor is recorded as the decider. It returns
// joinrequest.ErrNotFound when there is no such request and
// joinrequest.ErrDecided when it is no longer pending.
func (s *Store) DecideJoinRequest(ctx context.Context, id int64, status joinrequest.Status, actor string) (joinrequest.Request, error) {
	if status != joinrequest.StatusApproved && status != joinrequest.StatusRejected {
		return joinrequest.Request{}, fmt.Errorf("store: invalid decision %q", status)
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE group_join_requests
		SET status = $2, decided_at = now(), decided_by = $3
		WHERE id = $1 AND status = 'pending'
		RETURNING `+joinRequestColumns,
		id, status, actor,
	)
	if err != nil {
		return joinrequest.Request{}, fmt.Errorf("store: deciding join request %d: %w", id, err)
	}
	jr, err := pgx.CollectExactlyOneRow(rows, scanJoinRequest)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := s.GetJoinRequest(ctx, id); err != nil {
			return joinrequest.Request{}, err
		}
		return joinrequest.Request{}, joinrequest.ErrDecided
	}
	if err != nil {
		return joinrequest.Request{}, fmt.Errorf("store: deciding join request %d: %w", id, err)
	}
	return jr, nil
}

// ReopenJoinRequest makes the approved request with id pending again, after
// the user could not be added to the group.
func (s *Store) ReopenJoinRequest(ctx context.Context, id int64) error {
	if _, err := s.pool.Exec(ctx, `
		UPDATE group_join_requests
		SET status = 'pending', decided_at = NULL, decided_by = NULL
		WHERE id = $1 AND status = 'approved'`,
		id,
	); err != nil {
		return fmt.Errorf("store: reopening join request %d: %w", id, err)
	}
	return nil
}

// WithdrawJoinRequest deletes the pending request with id made by username.
// It returns joinrequest.ErrNotFound when there is no such pending request.
func (s *Store) WithdrawJoinRequest(ctx context.Context, id int64, username string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM group_join_requests WHERE id = $1 AND username = $2 AND status = 'pending'`,
		id, username,
	)
	if err != nil {
		return fmt.Errorf("store: withdrawing join request %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return joinrequest.ErrNotFound
	}
	return nil
}
