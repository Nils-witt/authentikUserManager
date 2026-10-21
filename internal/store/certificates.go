package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"authentikManager/internal/certificate"
)

// certificateColumns are the columns scanned by scanCertificate, in order.
// Unassigned certificates have neither user_pk nor username; see certificate.Certificate.Assigned.
const certificateColumns = `serial, COALESCE(user_pk, 0), COALESCE(username, ''), subject, not_before, not_after,
	issued_at, issued_by, key_source, revoked_at, COALESCE(revoked_by, ''), der IS NOT NULL`

func scanCertificate(row pgx.CollectableRow) (certificate.Certificate, error) {
	var c certificate.Certificate
	err := row.Scan(&c.Serial, &c.UserPK, &c.Username, &c.Subject, &c.NotBefore, &c.NotAfter,
		&c.IssuedAt, &c.IssuedBy, &c.KeySource, &c.RevokedAt, &c.RevokedBy, &c.Stored)
	return c, err
}

// CreateCertificate stores the record of a newly issued or imported
// certificate, with its DER encoding when set, and returns it with its issue
// time set. It returns certificate.ErrExists when the serial is already recorded.
func (s *Store) CreateCertificate(ctx context.Context, c certificate.Certificate) (certificate.Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		INSERT INTO certificates (serial, user_pk, username, subject, not_before, not_after, issued_by, key_source, der)
		VALUES ($1, NULLIF($2, 0), NULLIF($3, ''), $4, $5, $6, $7, $8, $9)
		RETURNING `+certificateColumns,
		c.Serial, c.UserPK, c.Username, c.Subject, c.NotBefore, c.NotAfter, c.IssuedBy, c.KeySource, c.DER,
	)
	if err != nil {
		return certificate.Certificate{}, fmt.Errorf("store: creating certificate: %w", err)
	}
	created, err := pgx.CollectExactlyOneRow(rows, scanCertificate)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == uniqueViolation {
		return certificate.Certificate{}, certificate.ErrExists
	}
	if err != nil {
		return certificate.Certificate{}, fmt.Errorf("store: creating certificate: %w", err)
	}
	return created, nil
}

// GetCertificate returns the certificate with serial, or certificate.ErrNotFound.
func (s *Store) GetCertificate(ctx context.Context, serial string) (certificate.Certificate, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+certificateColumns+` FROM certificates WHERE serial = $1`, serial)
	if err != nil {
		return certificate.Certificate{}, fmt.Errorf("store: querying certificate: %w", err)
	}
	c, err := pgx.CollectExactlyOneRow(rows, scanCertificate)
	if errors.Is(err, pgx.ErrNoRows) {
		return certificate.Certificate{}, certificate.ErrNotFound
	}
	if err != nil {
		return certificate.Certificate{}, fmt.Errorf("store: reading certificate: %w", err)
	}
	return c, nil
}

// GetCertificateDER returns the DER encoding of the certificate with serial.
// It returns certificate.ErrNotFound when there is no such certificate, and
// certificate.ErrNotStored when it was issued before encodings were stored.
func (s *Store) GetCertificateDER(ctx context.Context, serial string) ([]byte, error) {
	var der []byte
	err := s.pool.QueryRow(ctx, `SELECT der FROM certificates WHERE serial = $1`, serial).Scan(&der)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, certificate.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading certificate encoding: %w", err)
	}
	if der == nil {
		return nil, certificate.ErrNotStored
	}
	return der, nil
}

// ListCertificates returns the certificates of the user with userPK, newest
// first, up to certificate.MaxList of them.
func (s *Store) ListCertificates(ctx context.Context, userPK int) ([]certificate.Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+certificateColumns+` FROM certificates
		WHERE user_pk = $1
		ORDER BY issued_at DESC, serial
		LIMIT $2`,
		userPK, certificate.MaxList,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing certificates: %w", err)
	}
	list, err := pgx.CollectRows(rows, scanCertificate)
	if err != nil {
		return nil, fmt.Errorf("store: reading certificates: %w", err)
	}
	if list == nil {
		list = []certificate.Certificate{}
	}
	return list, nil
}

// certificateFilter is the WHERE clause of ListAllCertificates: $1 is the
// search text, $2 the escaped username pattern, $3 the escaped serial prefix
// pattern, $4 the status and $5 the time deciding which certificates expired.
const certificateFilter = `
	WHERE ($1 = '' OR username ILIKE $2 OR serial LIKE $3)
	  AND CASE $4::text
	        WHEN 'active'  THEN revoked_at IS NULL AND not_after > $5
	        WHEN 'revoked' THEN revoked_at IS NOT NULL
	        WHEN 'expired' THEN revoked_at IS NULL AND not_after <= $5
	        ELSE true
	      END`

// ListAllCertificates returns the page of the certificates of all users
// matching q, newest first, and how many match in total. now decides which
// certificates have expired. q must be normalized (see certificate.Query.Normalize).
func (s *Store) ListAllCertificates(ctx context.Context, q certificate.Query, now time.Time) ([]certificate.Certificate, int, error) {
	search := likeEscaper.Replace(q.Search)
	args := []any{q.Search, "%" + search + "%", strings.ToLower(search) + "%", string(q.Status), now}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM certificates`+certificateFilter, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: counting certificates: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+certificateColumns+` FROM certificates`+certificateFilter+`
		ORDER BY issued_at DESC, serial
		LIMIT $6 OFFSET $7`,
		append(args, q.PageSize, (q.Page-1)*q.PageSize)...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("store: listing certificates: %w", err)
	}
	list, err := pgx.CollectRows(rows, scanCertificate)
	if err != nil {
		return nil, 0, fmt.Errorf("store: reading certificates: %w", err)
	}
	if list == nil {
		list = []certificate.Certificate{}
	}
	return list, total, nil
}

// RevokeCertificate revokes the certificate with serial and returns it. actor
// is recorded as the revoker. It returns certificate.ErrNotFound when there is
// no such certificate and certificate.ErrRevoked when it is already revoked.
func (s *Store) RevokeCertificate(ctx context.Context, serial, actor string) (certificate.Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE certificates
		SET revoked_at = now(), revoked_by = $2
		WHERE serial = $1 AND revoked_at IS NULL
		RETURNING `+certificateColumns,
		serial, actor,
	)
	if err != nil {
		return certificate.Certificate{}, fmt.Errorf("store: revoking certificate: %w", err)
	}
	c, err := pgx.CollectExactlyOneRow(rows, scanCertificate)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := s.GetCertificate(ctx, serial); err != nil {
			return certificate.Certificate{}, err
		}
		return certificate.Certificate{}, certificate.ErrRevoked
	}
	if err != nil {
		return certificate.Certificate{}, fmt.Errorf("store: revoking certificate: %w", err)
	}
	return c, nil
}

// RevokeUserCertificates revokes every certificate of the user with userPK
// that is not revoked yet, recording actor as the revoker, and returns the
// serials it revoked.
func (s *Store) RevokeUserCertificates(ctx context.Context, userPK int, actor string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE certificates
		SET revoked_at = now(), revoked_by = $2
		WHERE user_pk = $1 AND revoked_at IS NULL
		RETURNING serial`,
		userPK, actor,
	)
	if err != nil {
		return nil, fmt.Errorf("store: revoking user certificates: %w", err)
	}
	serials, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("store: revoking user certificates: %w", err)
	}
	return serials, nil
}

// ListRevokedCertificates returns the revoked certificates that are still
// valid at now, for the CRL.
func (s *Store) ListRevokedCertificates(ctx context.Context, now time.Time) ([]certificate.Revoked, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT serial, revoked_at FROM certificates
		WHERE revoked_at IS NOT NULL AND not_after > $1
		ORDER BY serial`,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing revoked certificates: %w", err)
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (certificate.Revoked, error) {
		var r certificate.Revoked
		err := row.Scan(&r.Serial, &r.RevokedAt)
		return r, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: reading revoked certificates: %w", err)
	}
	return list, nil
}
