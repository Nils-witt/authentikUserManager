// Package store persists the access rules and the audit log in PostgreSQL.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Pool limits. The app is a small admin tool running as a single instance.
const (
	maxConns        = 10
	maxConnLifetime = 30 * time.Minute
	maxConnIdleTime = 5 * time.Minute
)

// Store is the PostgreSQL-backed rule store and audit log. It is safe for concurrent use.
type Store struct {
	pool *pgxpool.Pool
}

var (
	_ access.Store = (*Store)(nil)
	_ audit.Pruner = (*Store)(nil)
)

// Open connects to the database at url (a postgres:// URL or key=value DSN)
// and applies pending migrations.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		// The parse error may contain the password; do not wrap it.
		return nil, errors.New("store: invalid database url")
	}
	cfg.MaxConns = maxConns
	cfg.MaxConnLifetime = maxConnLifetime
	cfg.MaxConnIdleTime = maxConnIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: creating pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: connecting to database: %w", err)
	}
	if err := migrateUp(pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// migrateUp applies the embedded migrations. golang-migrate holds an advisory
// lock meanwhile, so concurrent starts are safe.
func migrateUp(pool *pgxpool.Pool) error {
	src, err := iofs.New(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("store: loading migrations: %w", err)
	}
	// Closing db does not close the pool.
	db := stdlib.OpenDBFromPool(pool)
	driver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("store: preparing migrations: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", driver)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("store: preparing migrations: %w", err)
	}
	defer m.Close() //nolint:errcheck // closes the source and db; the migration result is already known
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("store: applying migrations: %w", err)
	}
	return nil
}

// Close closes the connection pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks the database connection.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}
	return nil
}

// TargetGroups returns the target groups of all rules for operatorGroups.
func (s *Store) TargetGroups(ctx context.Context, operatorGroups []string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT target_group FROM access_rules WHERE operator_group = ANY($1)`,
		operatorGroups,
	)
	if err != nil {
		return nil, fmt.Errorf("store: querying target groups: %w", err)
	}
	groups, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("store: reading target groups: %w", err)
	}
	return groups, nil
}

// ListRules returns all rules, ordered by operator group, with sorted target groups.
func (s *Store) ListRules(ctx context.Context) ([]access.Rule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT operator_group, array_agg(target_group ORDER BY target_group)
		FROM access_rules
		GROUP BY operator_group
		ORDER BY operator_group`)
	if err != nil {
		return nil, fmt.Errorf("store: querying rules: %w", err)
	}
	rules, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (access.Rule, error) {
		var r access.Rule
		err := row.Scan(&r.OperatorGroup, &r.TargetGroups)
		return r, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: reading rules: %w", err)
	}
	return rules, nil
}

// PutRule creates or replaces the rule for rule.OperatorGroup. The rule must
// be normalized (see access.Rule.Normalize). actor is recorded as the editor.
func (s *Store) PutRule(ctx context.Context, rule access.Rule, actor string) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM access_rules WHERE operator_group = $1`,
			rule.OperatorGroup,
		); err != nil {
			return fmt.Errorf("deleting old targets: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO access_rules (operator_group, target_group, updated_by)
			SELECT $1, target, $3 FROM unnest($2::text[]) AS target`,
			rule.OperatorGroup, rule.TargetGroups, actor,
		); err != nil {
			return fmt.Errorf("inserting targets: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: saving rule for %q: %w", rule.OperatorGroup, err)
	}
	return nil
}

// DeleteRule removes the rule for operatorGroup, returning
// access.ErrRuleNotFound if there is none.
func (s *Store) DeleteRule(ctx context.Context, operatorGroup string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM access_rules WHERE operator_group = $1`, operatorGroup)
	if err != nil {
		return fmt.Errorf("store: deleting rule for %q: %w", operatorGroup, err)
	}
	if tag.RowsAffected() == 0 {
		return access.ErrRuleNotFound
	}
	return nil
}

// RenameGroup replaces the group name oldName with newName in every rule, as
// operator group and as target group, and returns how many rule entries it
// changed. Entries that already exist under the new name are merged.
// actor is recorded as the editor.
func (s *Store) RenameGroup(ctx context.Context, oldName, newName, actor string) (int64, error) {
	var changed int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Copy then delete, since updating in place could collide with an existing entry.
		if _, err := tx.Exec(ctx, `
			INSERT INTO access_rules (operator_group, target_group, updated_by)
			SELECT
				CASE WHEN operator_group = $1 THEN $2 ELSE operator_group END,
				CASE WHEN target_group = $1 THEN $2 ELSE target_group END,
				$3
			FROM access_rules
			WHERE operator_group = $1 OR target_group = $1
			ON CONFLICT (operator_group, target_group) DO NOTHING`,
			oldName, newName, actor,
		); err != nil {
			return fmt.Errorf("copying entries: %w", err)
		}
		tag, err := tx.Exec(ctx,
			`DELETE FROM access_rules WHERE operator_group = $1 OR target_group = $1`,
			oldName,
		)
		if err != nil {
			return fmt.Errorf("deleting old entries: %w", err)
		}
		changed = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: renaming group %q in rules: %w", oldName, err)
	}
	return changed, nil
}
