package notification_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"authentikManager/internal/notification"
)

// fakeStore is an in-memory notification.Store.
type fakeStore struct {
	mu            sync.Mutex
	notifications []notification.Notification
	prefs         map[int]notification.Preferences
	err           error
}

func (f *fakeStore) CreateNotification(_ context.Context, n notification.Notification) (notification.Notification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return notification.Notification{}, f.err
	}
	n.ID = int64(len(f.notifications) + 1)
	f.notifications = append(f.notifications, n)
	return n, nil
}

func (f *fakeStore) ListNotifications(context.Context, int, notification.Query) ([]notification.Notification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.notifications), nil
}

func (f *fakeStore) CountUnreadNotifications(context.Context, int) (int, error) { return 0, nil }

func (f *fakeStore) MarkNotificationRead(context.Context, int, int64) error { return nil }

func (f *fakeStore) MarkAllNotificationsRead(context.Context, int) error { return nil }

func (f *fakeStore) DeleteNotification(context.Context, int, int64) error { return nil }

func (f *fakeStore) DeleteAllNotifications(context.Context, int) error { return nil }

func (f *fakeStore) NotificationPreferences(_ context.Context, userPK int) (notification.Preferences, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.prefs[userPK], nil
}

func (f *fakeStore) PutNotificationPreferences(_ context.Context, userPK int, p notification.Preferences) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prefs == nil {
		f.prefs = map[int]notification.Preferences{}
	}
	f.prefs[userPK] = p
	return nil
}

// fakeReceiver records the notifications it receives, or fails with err.
type fakeReceiver struct {
	name     notification.Channel
	err      error
	mu       sync.Mutex
	received []notification.Notification
}

func (f *fakeReceiver) Name() notification.Channel { return f.name }

func (f *fakeReceiver) Label() string { return strings.ToUpper(string(f.name)) }

func (f *fakeReceiver) Receive(_ context.Context, _ notification.Recipient, n notification.Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.received = append(f.received, n)
	return f.err
}

func (f *fakeReceiver) headers() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, n := range f.received {
		out = append(out, n.Header)
	}
	return out
}

// runNotifier starts n and returns a function that stops it and waits until
// it has delivered everything queued.
func runNotifier(t *testing.T, n *notification.Notifier) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() { n.Run(ctx) })
	stop := func() {
		cancel()
		wg.Wait()
	}
	t.Cleanup(stop)
	return stop
}

func newTestNotifier(t *testing.T, store *fakeStore, receivers ...notification.NotificationReceiver) *notification.Notifier {
	t.Helper()
	n, err := notification.NewNotifier(store, slog.New(slog.DiscardHandler), receivers...)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

var ann = notification.Recipient{UserPK: 7, Username: "ann", Email: "ann@example.com"}

func TestNewNotifier_duplicateReceiver(t *testing.T) {
	t.Parallel()
	for _, names := range [][]notification.Channel{{"email", "email"}, {notification.ChannelInApp}, {""}} {
		receivers := []notification.NotificationReceiver{}
		for _, name := range names {
			receivers = append(receivers, &fakeReceiver{name: name})
		}
		if _, err := notification.NewNotifier(&fakeStore{}, slog.New(slog.DiscardHandler), receivers...); err == nil {
			t.Errorf("NewNotifier(%v) succeeded, want an error", names)
		}
	}
}

func TestNotifier_Channels(t *testing.T) {
	t.Parallel()
	n := newTestNotifier(t, &fakeStore{}, &fakeReceiver{name: "email"})
	got := n.Channels()
	expected := []notification.ChannelInfo{{Name: notification.ChannelInApp, Label: "In-app"}, {Name: "email", Label: "EMAIL"}}
	if !slices.Equal(got, expected) {
		t.Errorf("Channels = %v, want %v", got, expected)
	}
}

func TestNotifier_Notify(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		prefs         notification.Preferences
		category      notification.Category
		expectedInApp int
		expectedEmail int
		expectedChat  int
	}{
		{name: "defaults deliver everywhere", category: notification.CategoryProfile, expectedInApp: 1, expectedEmail: 1, expectedChat: 1},
		{
			name:     "disabled channels skipped",
			prefs:    notification.Preferences{notification.CategoryProfile: {notification.ChannelInApp: false, "email": false}},
			category: notification.CategoryProfile, expectedChat: 1,
		},
		{
			name:     "other category unaffected",
			prefs:    notification.Preferences{notification.CategoryProfile: {"email": false}},
			category: notification.CategoryCertificate, expectedInApp: 1, expectedEmail: 1, expectedChat: 1,
		},
		{
			name: "settings always delivered",
			prefs: notification.Preferences{notification.CategorySettings: {
				notification.ChannelInApp: false, "email": false, "chat": false,
			}},
			category: notification.CategorySettings, expectedInApp: 1, expectedEmail: 1, expectedChat: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := &fakeStore{prefs: map[int]notification.Preferences{ann.UserPK: tt.prefs}}
			email := &fakeReceiver{name: "email"}
			chat := &fakeReceiver{name: "chat"}
			n := newTestNotifier(t, store, email, chat)
			stop := runNotifier(t, n)

			if err := n.Notify(t.Context(), ann, tt.category, "Header", "Message"); err != nil {
				t.Fatalf("Notify: %v", err)
			}
			stop()
			if len(store.notifications) != tt.expectedInApp {
				t.Errorf("in-app = %d, want %d", len(store.notifications), tt.expectedInApp)
			}
			if got := len(email.headers()); got != tt.expectedEmail {
				t.Errorf("email = %d, want %d", got, tt.expectedEmail)
			}
			if got := len(chat.headers()); got != tt.expectedChat {
				t.Errorf("chat = %d, want %d", got, tt.expectedChat)
			}
		})
	}
}

func TestNotifier_Notify_storedFields(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	n := newTestNotifier(t, store)
	if err := n.Notify(t.Context(), ann, notification.CategoryJoinRequest, " Header ", "Message"); err != nil {
		t.Fatal(err)
	}
	got := store.notifications[0]
	if got.UserPK != ann.UserPK || got.Category != notification.CategoryJoinRequest || got.Header != "Header" || got.Message != "Message" {
		t.Errorf("stored %+v", got)
	}
}

func TestNotifier_Notify_errors(t *testing.T) {
	t.Parallel()
	n := newTestNotifier(t, &fakeStore{})
	if err := n.Notify(t.Context(), ann, notification.CategoryProfile, "", "Message"); err == nil {
		t.Error("Notify without header succeeded, want an error")
	}
	failing := newTestNotifier(t, &fakeStore{err: errors.New("db down")})
	if err := failing.Notify(t.Context(), ann, notification.CategoryProfile, "Header", "Message"); err == nil {
		t.Error("Notify with a failing store succeeded, want an error")
	}
}

func TestNotifier_Notify_failingReceiver(t *testing.T) {
	t.Parallel()
	broken := &fakeReceiver{name: "broken", err: errors.New("unreachable")}
	email := &fakeReceiver{name: "email"}
	n := newTestNotifier(t, &fakeStore{}, broken, email)
	stop := runNotifier(t, n)
	for range 2 {
		if err := n.Notify(t.Context(), ann, notification.CategoryProfile, "Header", "Message"); err != nil {
			t.Fatal(err)
		}
	}
	stop()
	if got := len(email.headers()); got != 2 {
		t.Errorf("email received %d, want 2 despite the failing receiver", got)
	}
}

func TestNotifier_Forward(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	email := &fakeReceiver{name: "email"}
	n := newTestNotifier(t, store, email)
	stop := runNotifier(t, n)
	if err := n.Forward(t.Context(), ann, notification.CategoryProfile, "Header", "Message"); err != nil {
		t.Fatal(err)
	}
	stop()
	if len(store.notifications) != 0 {
		t.Errorf("Forward stored %d notifications, want none", len(store.notifications))
	}
	if got := email.headers(); !slices.Equal(got, []string{"Header"}) {
		t.Errorf("email = %v, want the forwarded notification", got)
	}
}

func TestNotifier_SetPreferences(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	email := &fakeReceiver{name: "email"}
	n := newTestNotifier(t, store, email)
	stop := runNotifier(t, n)

	off := notification.Preferences{notification.CategoryProfile: {"email": false}}
	got, err := n.SetPreferences(t.Context(), ann, off)
	if err != nil {
		t.Fatalf("SetPreferences: %v", err)
	}
	if got[notification.CategoryProfile]["email"] || !got[notification.CategoryProfile][notification.ChannelInApp] {
		t.Errorf("SetPreferences = %v, want profile email off and in-app on", got)
	}
	// Saving the same preferences again still notifies.
	if _, err := n.SetPreferences(t.Context(), ann, off); err != nil {
		t.Fatalf("SetPreferences again: %v", err)
	}
	stop()

	if len(store.notifications) != 2 {
		t.Fatalf("notifications = %d, want 2", len(store.notifications))
	}
	first, second := store.notifications[0], store.notifications[1]
	if first.Category != notification.CategorySettings || !strings.Contains(first.Message, "Profile changes – EMAIL: off") {
		t.Errorf("first = %+v, want the change listed", first)
	}
	if !strings.Contains(second.Message, "without changes") {
		t.Errorf("second = %+v, want no changes", second)
	}
	if got := len(email.headers()); got != 2 {
		t.Errorf("email received %d, want 2", got)
	}
}

func TestNotifier_SetPreferences_invalid(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	n := newTestNotifier(t, store)
	_, err := n.SetPreferences(t.Context(), ann, notification.Preferences{notification.CategoryProfile: {"email": false}})
	if !errors.Is(err, notification.ErrInvalidPreferences) {
		t.Errorf("SetPreferences = %v, want ErrInvalidPreferences", err)
	}
	if len(store.notifications) != 0 || store.prefs != nil {
		t.Error("invalid preferences changed something")
	}
}
