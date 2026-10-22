package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"authentikManager/internal/notification"
)

var _ notification.Store = (*Store)(nil)

// notificationColumns are the columns scanned by scanNotification, in order.
const notificationColumns = `id, user_pk, category, header, message, created_at, read_at`

func scanNotification(row pgx.CollectableRow) (notification.Notification, error) {
	var n notification.Notification
	err := row.Scan(&n.ID, &n.UserPK, &n.Category, &n.Header, &n.Message, &n.CreatedAt, &n.ReadAt)
	return n, err
}

// CreateNotification stores n as unread and returns it with its ID and time set.
func (s *Store) CreateNotification(ctx context.Context, n notification.Notification) (notification.Notification, error) {
	rows, err := s.pool.Query(ctx, `
		INSERT INTO notifications (user_pk, category, header, message)
		VALUES ($1, $2, $3, $4)
		RETURNING `+notificationColumns,
		n.UserPK, n.Category, n.Header, n.Message,
	)
	if err != nil {
		return notification.Notification{}, fmt.Errorf("store: creating notification: %w", err)
	}
	created, err := pgx.CollectExactlyOneRow(rows, scanNotification)
	if err != nil {
		return notification.Notification{}, fmt.Errorf("store: creating notification: %w", err)
	}
	return created, nil
}

// ListNotifications returns the notifications of a user matching q, newest
// first. q must be normalized (see notification.Query.Normalize).
func (s *Store) ListNotifications(ctx context.Context, userPK int, q notification.Query) ([]notification.Notification, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+notificationColumns+`
		FROM notifications
		WHERE user_pk = $1 AND ($2::bigint = 0 OR id < $2)
		ORDER BY id DESC
		LIMIT $3`,
		userPK, q.Before, q.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: querying notifications: %w", err)
	}
	list, err := pgx.CollectRows(rows, scanNotification)
	if err != nil {
		return nil, fmt.Errorf("store: reading notifications: %w", err)
	}
	return list, nil
}

// CountUnreadNotifications returns how many notifications of a user are unread.
func (s *Store) CountUnreadNotifications(ctx context.Context, userPK int) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM notifications WHERE user_pk = $1 AND read_at IS NULL`, userPK,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: counting unread notifications: %w", err)
	}
	return n, nil
}

// MarkNotificationRead marks the notification with id of a user read. It
// returns notification.ErrNotFound when the user has no such notification.
func (s *Store) MarkNotificationRead(ctx context.Context, userPK int, id int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE notifications SET read_at = COALESCE(read_at, now()) WHERE id = $1 AND user_pk = $2`,
		id, userPK,
	)
	if err != nil {
		return fmt.Errorf("store: marking notification %d read: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return notification.ErrNotFound
	}
	return nil
}

// MarkAllNotificationsRead marks every unread notification of a user read.
func (s *Store) MarkAllNotificationsRead(ctx context.Context, userPK int) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE notifications SET read_at = now() WHERE user_pk = $1 AND read_at IS NULL`, userPK,
	); err != nil {
		return fmt.Errorf("store: marking notifications read: %w", err)
	}
	return nil
}

// DeleteNotification deletes the notification with id of a user. It returns
// notification.ErrNotFound when the user has no such notification.
func (s *Store) DeleteNotification(ctx context.Context, userPK int, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM notifications WHERE id = $1 AND user_pk = $2`, id, userPK)
	if err != nil {
		return fmt.Errorf("store: deleting notification %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return notification.ErrNotFound
	}
	return nil
}

// DeleteAllNotifications deletes every notification of a user.
func (s *Store) DeleteAllNotifications(ctx context.Context, userPK int) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM notifications WHERE user_pk = $1`, userPK); err != nil {
		return fmt.Errorf("store: deleting notifications: %w", err)
	}
	return nil
}

// NotificationPreferences returns the stored preferences of a user; entries
// that were never stored are missing.
func (s *Store) NotificationPreferences(ctx context.Context, userPK int) (notification.Preferences, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT category, channel, enabled FROM notification_preferences WHERE user_pk = $1`, userPK,
	)
	if err != nil {
		return nil, fmt.Errorf("store: querying notification preferences: %w", err)
	}
	prefs := notification.Preferences{}
	var (
		cat     notification.Category
		ch      notification.Channel
		enabled bool
	)
	_, err = pgx.ForEachRow(rows, []any{&cat, &ch, &enabled}, func() error {
		if prefs[cat] == nil {
			prefs[cat] = map[notification.Channel]bool{}
		}
		prefs[cat][ch] = enabled
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: reading notification preferences: %w", err)
	}
	return prefs, nil
}

// PutNotificationPreferences replaces the stored preferences of a user with p.
func (s *Store) PutNotificationPreferences(ctx context.Context, userPK int, p notification.Preferences) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM notification_preferences WHERE user_pk = $1`, userPK); err != nil {
			return err
		}
		var batch pgx.Batch
		for cat, channels := range p {
			for ch, enabled := range channels {
				batch.Queue(`INSERT INTO notification_preferences (user_pk, category, channel, enabled)
					VALUES ($1, $2, $3, $4)`, userPK, cat, ch, enabled)
			}
		}
		if batch.Len() == 0 {
			return nil
		}
		return tx.SendBatch(ctx, &batch).Close()
	})
	if err != nil {
		return fmt.Errorf("store: storing notification preferences: %w", err)
	}
	return nil
}
