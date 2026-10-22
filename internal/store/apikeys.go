package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"authentikManager/internal/apikey"
)

// apiKeyColumns are the columns scanned by scanAPIKey, in order.
//
//nolint:gosec // G101: column names, not credentials; the key hash is never read back.
const apiKeyColumns = `id, user_pk, username, description, start, created_at, created_by, expires_at, last_used_at`

func scanAPIKey(row pgx.CollectableRow) (apikey.Key, error) {
	var k apikey.Key
	err := row.Scan(&k.ID, &k.UserPK, &k.Username, &k.Description, &k.Start, &k.CreatedAt, &k.CreatedBy,
		&k.ExpiresAt, &k.LastUsedAt)
	return k, err
}

// CreateAPIKey stores the record of a new API key under hash, the hash of the
// key, and returns it with its ID and creation time set.
func (s *Store) CreateAPIKey(ctx context.Context, k apikey.Key, hash []byte) (apikey.Key, error) {
	rows, err := s.pool.Query(ctx, `
		INSERT INTO api_keys (user_pk, username, description, start, key_hash, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+apiKeyColumns,
		k.UserPK, k.Username, k.Description, k.Start, hash, k.CreatedBy, k.ExpiresAt,
	)
	if err != nil {
		return apikey.Key{}, fmt.Errorf("store: creating api key: %w", err)
	}
	created, err := pgx.CollectExactlyOneRow(rows, scanAPIKey)
	if err != nil {
		return apikey.Key{}, fmt.Errorf("store: creating api key: %w", err)
	}
	return created, nil
}

// ListAPIKeys returns the API keys of the user with userPK, newest first.
func (s *Store) ListAPIKeys(ctx context.Context, userPK int) ([]apikey.Key, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+apiKeyColumns+` FROM api_keys WHERE user_pk = $1 ORDER BY id DESC`,
		userPK,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing api keys: %w", err)
	}
	list, err := pgx.CollectRows(rows, scanAPIKey)
	if err != nil {
		return nil, fmt.Errorf("store: reading api keys: %w", err)
	}
	return list, nil
}

// DeleteAPIKey deletes the API key with id of the user with userPK and returns
// it, or returns apikey.ErrNotFound when the user has no such key.
func (s *Store) DeleteAPIKey(ctx context.Context, userPK int, id int64) (apikey.Key, error) {
	rows, err := s.pool.Query(ctx,
		`DELETE FROM api_keys WHERE id = $1 AND user_pk = $2 RETURNING `+apiKeyColumns,
		id, userPK,
	)
	if err != nil {
		return apikey.Key{}, fmt.Errorf("store: deleting api key: %w", err)
	}
	k, err := pgx.CollectExactlyOneRow(rows, scanAPIKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return apikey.Key{}, apikey.ErrNotFound
	}
	if err != nil {
		return apikey.Key{}, fmt.Errorf("store: deleting api key: %w", err)
	}
	return k, nil
}

// DeleteUserAPIKeys deletes every API key of the user with userPK and returns how many it deleted.
func (s *Store) DeleteUserAPIKeys(ctx context.Context, userPK int) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM api_keys WHERE user_pk = $1`, userPK)
	if err != nil {
		return 0, fmt.Errorf("store: deleting user api keys: %w", err)
	}
	return tag.RowsAffected(), nil
}

// AuthenticateAPIKey returns the API key stored under hash that has not
// expired at now, recording now as its last use. It returns
// apikey.ErrNotFound when there is no such key.
func (s *Store) AuthenticateAPIKey(ctx context.Context, hash []byte, now time.Time) (apikey.Key, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE api_keys SET last_used_at = $2
		WHERE key_hash = $1 AND (expires_at IS NULL OR expires_at > $2)
		RETURNING `+apiKeyColumns,
		hash, now,
	)
	if err != nil {
		return apikey.Key{}, fmt.Errorf("store: authenticating api key: %w", err)
	}
	k, err := pgx.CollectExactlyOneRow(rows, scanAPIKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return apikey.Key{}, apikey.ErrNotFound
	}
	if err != nil {
		return apikey.Key{}, fmt.Errorf("store: authenticating api key: %w", err)
	}
	return k, nil
}
