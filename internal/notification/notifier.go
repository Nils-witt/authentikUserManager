package notification

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Store persists the notifications and preferences of users.
type Store interface {
	// CreateNotification stores n and returns it with its ID and time set.
	CreateNotification(ctx context.Context, n Notification) (Notification, error)
	// ListNotifications returns the notifications of a user matching a normalized query, newest first.
	ListNotifications(ctx context.Context, userPK int, q Query) ([]Notification, error)
	CountUnreadNotifications(ctx context.Context, userPK int) (int, error)
	// MarkNotificationRead returns ErrNotFound when the user has no such notification.
	MarkNotificationRead(ctx context.Context, userPK int, id int64) error
	MarkAllNotificationsRead(ctx context.Context, userPK int) error
	// DeleteNotification returns ErrNotFound when the user has no such notification.
	DeleteNotification(ctx context.Context, userPK int, id int64) error
	DeleteAllNotifications(ctx context.Context, userPK int) error
	// NotificationPreferences returns the stored preferences of a user, which may be incomplete.
	NotificationPreferences(ctx context.Context, userPK int) (Preferences, error)
	// PutNotificationPreferences replaces the stored preferences of a user.
	PutNotificationPreferences(ctx context.Context, userPK int, p Preferences) error
}

// Delivery limits.
const (
	// queueSize bounds the deliveries waiting for a receiver.
	queueSize = 256
	// deliveryTimeout bounds one delivery by one receiver.
	deliveryTimeout = 30 * time.Second
)

// delivery is one notification waiting for one receiver.
type delivery struct {
	receiver NotificationReceiver
	rcpt     Recipient
	n        Notification
}

// Notifier stores notifications in the in-app inbox and hands them to the
// receivers the recipient chose. Deliveries to receivers run in the background
// once Run is started, so a slow receiver never delays the change that caused
// the notification. It is safe for concurrent use.
type Notifier struct {
	store     Store
	receivers []NotificationReceiver
	logger    *slog.Logger
	queue     chan delivery
}

// NewNotifier returns a Notifier storing notifications in store and delivering
// them to receivers, whose names must be unique and differ from ChannelInApp.
func NewNotifier(store Store, logger *slog.Logger, receivers ...NotificationReceiver) (*Notifier, error) {
	seen := map[Channel]bool{ChannelInApp: true}
	for _, r := range receivers {
		if r.Name() == "" || seen[r.Name()] {
			return nil, fmt.Errorf("notification: duplicate or empty receiver name %q", r.Name())
		}
		seen[r.Name()] = true
	}
	return &Notifier{
		store:     store,
		receivers: receivers,
		logger:    logger,
		queue:     make(chan delivery, queueSize),
	}, nil
}

// Channels returns the in-app channel followed by the receivers' channels.
func (n *Notifier) Channels() []ChannelInfo {
	out := make([]ChannelInfo, 0, len(n.receivers)+1)
	out = append(out, ChannelInfo{Name: ChannelInApp, Label: "In-app"})
	for _, r := range n.receivers {
		out = append(out, ChannelInfo{Name: r.Name(), Label: r.Label()})
	}
	return out
}

// channelNames returns the names of Channels.
func (n *Notifier) channelNames() []Channel {
	out := make([]Channel, 0, len(n.receivers)+1)
	out = append(out, ChannelInApp)
	for _, r := range n.receivers {
		out = append(out, r.Name())
	}
	return out
}

// Notify sends a notification of cat to rcpt on every channel their
// preferences enable; mandatory categories go to every channel. It returns an
// error when the notification is invalid or cannot be stored; failed
// deliveries to receivers are logged.
func (n *Notifier) Notify(ctx context.Context, rcpt Recipient, cat Category, header, message string) error {
	msg, err := New(cat, header, message)
	if err != nil {
		return err
	}
	msg.UserPK = rcpt.UserPK
	prefs, err := n.store.NotificationPreferences(ctx, rcpt.UserPK)
	if err != nil {
		return fmt.Errorf("notification: loading preferences: %w", err)
	}
	if prefs.Enabled(cat, ChannelInApp) {
		if msg, err = n.store.CreateNotification(ctx, msg); err != nil {
			return fmt.Errorf("notification: storing: %w", err)
		}
	}
	for _, r := range n.receivers {
		if prefs.Enabled(cat, r.Name()) {
			n.enqueue(ctx, delivery{receiver: r, rcpt: rcpt, n: msg})
		}
	}
	return nil
}

// Forward hands a notification of cat to the receivers of rcpt without
// storing it in the inbox, e.g. to tell a previous email address that it was
// replaced. The receivers the user's preferences disable are skipped.
func (n *Notifier) Forward(ctx context.Context, rcpt Recipient, cat Category, header, message string) error {
	msg, err := New(cat, header, message)
	if err != nil {
		return err
	}
	msg.UserPK = rcpt.UserPK
	prefs, err := n.store.NotificationPreferences(ctx, rcpt.UserPK)
	if err != nil {
		return fmt.Errorf("notification: loading preferences: %w", err)
	}
	for _, r := range n.receivers {
		if prefs.Enabled(cat, r.Name()) {
			n.enqueue(ctx, delivery{receiver: r, rcpt: rcpt, n: msg})
		}
	}
	return nil
}

// enqueue queues d for Run, dropping it when the queue is full.
func (n *Notifier) enqueue(ctx context.Context, d delivery) {
	select {
	case n.queue <- d:
	default:
		n.logger.WarnContext(ctx, "notification queue full; delivery dropped",
			slog.String("channel", string(d.receiver.Name())),
			slog.Int("user_id", d.rcpt.UserPK),
		)
	}
}

// Run delivers queued notifications until ctx is done, then delivers the ones
// still queued before returning.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case d := <-n.queue:
			n.deliver(ctx, d)
		case <-ctx.Done():
			n.drain(context.WithoutCancel(ctx))
			return
		}
	}
}

// drain delivers the notifications queued at the time of the call.
func (n *Notifier) drain(ctx context.Context) {
	for range len(n.queue) {
		n.deliver(ctx, <-n.queue)
	}
}

func (n *Notifier) deliver(ctx context.Context, d delivery) {
	ctx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	err := d.receiver.Receive(ctx, d.rcpt, d.n)
	switch {
	case err == nil:
	case errors.Is(err, ErrNoAddress):
		n.logger.DebugContext(ctx, "notification not delivered: no address",
			slog.String("channel", string(d.receiver.Name())),
			slog.Int("user_id", d.rcpt.UserPK),
		)
	default:
		n.logger.ErrorContext(ctx, "delivering notification failed",
			slog.String("channel", string(d.receiver.Name())),
			slog.Int("user_id", d.rcpt.UserPK),
			slog.Any("error", err),
		)
	}
}

// List returns a page of the notifications of a user, newest first.
func (n *Notifier) List(ctx context.Context, userPK int, q Query) ([]Notification, error) {
	return n.store.ListNotifications(ctx, userPK, q)
}

// CountUnread returns how many notifications of a user are unread.
func (n *Notifier) CountUnread(ctx context.Context, userPK int) (int, error) {
	return n.store.CountUnreadNotifications(ctx, userPK)
}

// MarkRead marks a notification of a user read, or returns ErrNotFound.
func (n *Notifier) MarkRead(ctx context.Context, userPK int, id int64) error {
	return n.store.MarkNotificationRead(ctx, userPK, id)
}

// MarkAllRead marks every notification of a user read.
func (n *Notifier) MarkAllRead(ctx context.Context, userPK int) error {
	return n.store.MarkAllNotificationsRead(ctx, userPK)
}

// Delete deletes a notification of a user, or returns ErrNotFound.
func (n *Notifier) Delete(ctx context.Context, userPK int, id int64) error {
	return n.store.DeleteNotification(ctx, userPK, id)
}

// DeleteAll deletes every notification of a user.
func (n *Notifier) DeleteAll(ctx context.Context, userPK int) error {
	return n.store.DeleteAllNotifications(ctx, userPK)
}

// Preferences returns the complete preferences of a user for the current channels.
func (n *Notifier) Preferences(ctx context.Context, userPK int) (Preferences, error) {
	stored, err := n.store.NotificationPreferences(ctx, userPK)
	if err != nil {
		return nil, fmt.Errorf("notification: loading preferences: %w", err)
	}
	return stored.Complete(n.channelNames()), nil
}

// ErrInvalidPreferences wraps the reason preferences are rejected, which is safe to show users.
var ErrInvalidPreferences = errors.New("invalid notification preferences")

// SetPreferences replaces the preferences of rcpt and returns them completed.
// It always notifies rcpt of the change, even when nothing changed, so a user
// learns when someone else changes their settings. It returns an error
// wrapping ErrInvalidPreferences when p is not valid.
func (n *Notifier) SetPreferences(ctx context.Context, rcpt Recipient, p Preferences) (Preferences, error) {
	channels := n.channelNames()
	next, err := p.Normalize(channels)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPreferences, err)
	}
	previous, err := n.Preferences(ctx, rcpt.UserPK)
	if err != nil {
		return nil, err
	}
	if err := n.store.PutNotificationPreferences(ctx, rcpt.UserPK, next); err != nil {
		return nil, fmt.Errorf("notification: storing preferences: %w", err)
	}
	if err := n.Notify(ctx, rcpt, CategorySettings, "Notification settings changed",
		n.describeChanges(previous, next)); err != nil {
		return nil, err
	}
	return next, nil
}

// describeChanges returns a message listing the differences between the
// complete preferences previous and next.
func (n *Notifier) describeChanges(previous, next Preferences) string {
	var b strings.Builder
	for _, cat := range Categories {
		for _, ch := range n.Channels() {
			if on := next[cat][ch.Name]; on != previous[cat][ch.Name] {
				fmt.Fprintf(&b, "\n- %s – %s: %s", cat.Label(), ch.Label, onOff(on))
			}
		}
	}
	if b.Len() == 0 {
		return "Your notification settings were saved without changes."
	}
	return "Your notification settings were changed:" + b.String()
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
