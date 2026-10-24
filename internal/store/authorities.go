package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"authentikManager/internal/authority"
)

// checkViolation is the PostgreSQL error code of a violated CHECK constraint.
const checkViolation = "23514"

// authorityColumns are the columns scanned by scanAuthority, in order.
const authorityColumns = `id, name, description, cert_pem, key_ciphertext, fingerprint, crl_url,
	validity_days, crl_validity_days, user_cn_suffix, service_account_cn_suffix, allowed_groups,
	is_default, legacy, disabled, created_at, created_by`

func scanAuthority(row pgx.CollectableRow) (authority.Authority, error) {
	var a authority.Authority
	err := row.Scan(&a.ID, &a.Name, &a.Description, &a.CertPEM, &a.KeyCiphertext, &a.Fingerprint, &a.CRLURL,
		&a.ValidityDays, &a.CRLValidityDays, &a.UserCNSuffix, &a.ServiceAccountCNSuffix, &a.AllowedGroups,
		&a.Default, &a.Legacy, &a.Disabled, &a.CreatedAt, &a.CreatedBy)
	return a, err
}

// ListAuthorities returns every CA, ordered by name.
func (s *Store) ListAuthorities(ctx context.Context) ([]authority.Authority, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+authorityColumns+` FROM certificate_authorities ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: listing certificate authorities: %w", err)
	}
	list, err := pgx.CollectRows(rows, scanAuthority)
	if err != nil {
		return nil, fmt.Errorf("store: reading certificate authorities: %w", err)
	}
	if list == nil {
		list = []authority.Authority{}
	}
	return list, nil
}

// CreateAuthority stores a new CA and returns it. It becomes the default CA
// when there is none. It returns authority.ErrExists when its name or
// certificate is already stored.
func (s *Store) CreateAuthority(ctx context.Context, a authority.Authority) (authority.Authority, error) {
	var created authority.Authority
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		created, err = insertAuthority(ctx, tx, a, false)
		return err
	})
	if err != nil {
		return authority.Authority{}, err
	}
	return created, nil
}

// insertAuthority stores a in tx, as the default CA when there is none and as
// the legacy CA when legacy is set.
func insertAuthority(ctx context.Context, tx pgx.Tx, a authority.Authority, legacy bool) (authority.Authority, error) {
	// Serializes the check for a default CA with concurrent inserts; reads go on.
	if _, err := tx.Exec(ctx, `LOCK TABLE certificate_authorities IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return authority.Authority{}, fmt.Errorf("store: locking certificate authorities: %w", err)
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO certificate_authorities (name, description, cert_pem, key_ciphertext, fingerprint, crl_url,
			validity_days, crl_validity_days, user_cn_suffix, service_account_cn_suffix, allowed_groups,
			is_default, legacy, disabled, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
			NOT $12 AND NOT EXISTS (SELECT 1 FROM certificate_authorities WHERE is_default), $13, $12, $14)
		RETURNING `+authorityColumns,
		a.Name, a.Description, a.CertPEM, a.KeyCiphertext, a.Fingerprint, a.CRLURL,
		a.ValidityDays, a.CRLValidityDays, a.UserCNSuffix, a.ServiceAccountCNSuffix, a.AllowedGroups,
		a.Disabled, legacy, a.CreatedBy,
	)
	if err != nil {
		return authority.Authority{}, fmt.Errorf("store: creating certificate authority: %w", err)
	}
	created, err := pgx.CollectExactlyOneRow(rows, scanAuthority)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == uniqueViolation {
		return authority.Authority{}, authority.ErrExists
	}
	if err != nil {
		return authority.Authority{}, fmt.Errorf("store: creating certificate authority: %w", err)
	}
	return created, nil
}

// UpdateAuthority replaces the settings of the CA with id and enables or
// disables it, and returns it. It returns authority.ErrNotFound when there is
// no such CA and authority.ErrDefaultDisabled when disabling the default CA.
func (s *Store) UpdateAuthority(ctx context.Context, id int64, settings authority.Settings, disabled bool) (authority.Authority, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE certificate_authorities
		SET description = $2, crl_url = $3, validity_days = $4, crl_validity_days = $5,
			user_cn_suffix = $6, service_account_cn_suffix = $7, allowed_groups = $8, disabled = $9
		WHERE id = $1
		RETURNING `+authorityColumns,
		id, settings.Description, settings.CRLURL, settings.ValidityDays, settings.CRLValidityDays,
		settings.UserCNSuffix, settings.ServiceAccountCNSuffix, settings.AllowedGroups, disabled,
	)
	if err != nil {
		return authority.Authority{}, fmt.Errorf("store: updating certificate authority: %w", err)
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanAuthority)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == checkViolation {
		return authority.Authority{}, authority.ErrDefaultDisabled
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.Authority{}, authority.ErrNotFound
	}
	if err != nil {
		return authority.Authority{}, fmt.Errorf("store: updating certificate authority: %w", err)
	}
	return a, nil
}

// SetDefaultAuthority makes the CA with id the default CA. It returns
// authority.ErrNotFound when there is no such CA and
// authority.ErrDefaultDisabled when it is disabled.
func (s *Store) SetDefaultAuthority(ctx context.Context, id int64) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var disabled bool
		err := tx.QueryRow(ctx, `SELECT disabled FROM certificate_authorities WHERE id = $1 FOR UPDATE`, id).Scan(&disabled)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return authority.ErrNotFound
		case err != nil:
			return fmt.Errorf("store: reading certificate authority: %w", err)
		case disabled:
			return authority.ErrDefaultDisabled
		}
		// Cleared first, since at most one CA may be the default at any time.
		if _, err := tx.Exec(ctx, `UPDATE certificate_authorities SET is_default = false WHERE is_default AND id <> $1`, id); err != nil {
			return fmt.Errorf("store: clearing default certificate authority: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE certificate_authorities SET is_default = true WHERE id = $1`, id); err != nil {
			return fmt.Errorf("store: setting default certificate authority: %w", err)
		}
		return nil
	})
}

// ImportLegacyAuthority stores a, the CA of CA_CERT_FILE, unless a CA with
// its certificate is stored already, and returns the stored CA. A new CA
// becomes the legacy CA when there is none, and the default CA when there is
// none; the certificates recorded before CAs were stored are then assigned
// to it. A stored CA is left unchanged. It returns authority.ErrExists when
// another CA has a's name.
func (s *Store) ImportLegacyAuthority(ctx context.Context, a authority.Authority) (authority.Authority, error) {
	var stored authority.Authority
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+authorityColumns+` FROM certificate_authorities WHERE fingerprint = $1`, a.Fingerprint)
		if err != nil {
			return fmt.Errorf("store: querying certificate authority: %w", err)
		}
		stored, err = pgx.CollectExactlyOneRow(rows, scanAuthority)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: reading certificate authority: %w", err)
		}
		var hasLegacy bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM certificate_authorities WHERE legacy)`).Scan(&hasLegacy); err != nil {
			return fmt.Errorf("store: querying legacy certificate authority: %w", err)
		}
		if stored, err = insertAuthority(ctx, tx, a, !hasLegacy); err != nil {
			return err
		}
		if !stored.Legacy {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE certificates SET ca_id = $1 WHERE ca_id IS NULL`, stored.ID); err != nil {
			return fmt.Errorf("store: assigning certificates to the legacy certificate authority: %w", err)
		}
		return nil
	})
	if err != nil {
		return authority.Authority{}, err
	}
	return stored, nil
}
