package store_test

import (
	"crypto/rand"
	"errors"
	"math/big"
	"slices"
	"testing"

	"authentikManager/internal/notification"
	"authentikManager/internal/store"
)

// testUserPK returns a user key no other test uses, since the tables are not wiped.
func testUserPK(t *testing.T) int {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<30))
	if err != nil {
		t.Fatal(err)
	}
	return int(n.Int64()) + 1_000_000
}

func createTestNotification(t *testing.T, s *store.Store, userPK int, header string) notification.Notification {
	t.Helper()
	n, err := s.CreateNotification(t.Context(), notification.Notification{
		UserPK:   userPK,
		Category: notification.CategoryProfile,
		Header:   header,
		Message:  "message",
	})
	if err != nil {
		t.Fatalf("CreateNotification: %v", err)
	}
	return n
}

func notificationIDs(list []notification.Notification) []int64 {
	ids := []int64{}
	for _, n := range list {
		ids = append(ids, n.ID)
	}
	return ids
}

func TestStore_createAndListNotifications(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	ann, bob := testUserPK(t), testUserPK(t)

	first := createTestNotification(t, s, ann, "first")
	second := createTestNotification(t, s, ann, "second")
	createTestNotification(t, s, bob, "other user")
	if first.ID == 0 || first.CreatedAt.IsZero() || first.ReadAt != nil || first.Header != "first" {
		t.Errorf("created = %+v, want an unread notification with ID and time", first)
	}

	tests := []struct {
		name     string
		query    notification.Query
		expected []int64
	}{
		{name: "newest first", query: notification.Query{Limit: 10}, expected: []int64{second.ID, first.ID}},
		{name: "limit", query: notification.Query{Limit: 1}, expected: []int64{second.ID}},
		{name: "before", query: notification.Query{Before: second.ID, Limit: 10}, expected: []int64{first.ID}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := s.ListNotifications(ctx, ann, tt.query)
			if err != nil {
				t.Fatalf("ListNotifications: %v", err)
			}
			if ids := notificationIDs(list); !slices.Equal(ids, tt.expected) {
				t.Errorf("ids = %v, want %v", ids, tt.expected)
			}
		})
	}
}

func TestStore_readNotifications(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	ann, bob := testUserPK(t), testUserPK(t)
	first := createTestNotification(t, s, ann, "first")
	createTestNotification(t, s, ann, "second")

	unread := func(userPK int) int {
		t.Helper()
		n, err := s.CountUnreadNotifications(ctx, userPK)
		if err != nil {
			t.Fatalf("CountUnreadNotifications: %v", err)
		}
		return n
	}
	if got := unread(ann); got != 2 {
		t.Fatalf("unread = %d, want 2", got)
	}
	if err := s.MarkNotificationRead(ctx, bob, first.ID); !errors.Is(err, notification.ErrNotFound) {
		t.Errorf("MarkNotificationRead of another user = %v, want ErrNotFound", err)
	}
	if err := s.MarkNotificationRead(ctx, ann, first.ID); err != nil {
		t.Fatalf("MarkNotificationRead: %v", err)
	}
	if got := unread(ann); got != 1 {
		t.Errorf("unread = %d, want 1", got)
	}
	if err := s.MarkAllNotificationsRead(ctx, ann); err != nil {
		t.Fatalf("MarkAllNotificationsRead: %v", err)
	}
	if got := unread(ann); got != 0 {
		t.Errorf("unread = %d, want 0", got)
	}
}

func TestStore_deleteNotifications(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	ann, bob := testUserPK(t), testUserPK(t)
	first := createTestNotification(t, s, ann, "first")
	createTestNotification(t, s, ann, "second")
	kept := createTestNotification(t, s, bob, "kept")

	if err := s.DeleteNotification(ctx, bob, first.ID); !errors.Is(err, notification.ErrNotFound) {
		t.Errorf("DeleteNotification of another user = %v, want ErrNotFound", err)
	}
	if err := s.DeleteNotification(ctx, ann, first.ID); err != nil {
		t.Fatalf("DeleteNotification: %v", err)
	}
	if err := s.DeleteNotification(ctx, ann, first.ID); !errors.Is(err, notification.ErrNotFound) {
		t.Errorf("second DeleteNotification = %v, want ErrNotFound", err)
	}
	if err := s.DeleteAllNotifications(ctx, ann); err != nil {
		t.Fatalf("DeleteAllNotifications: %v", err)
	}
	list, err := s.ListNotifications(ctx, ann, notification.Query{Limit: 10})
	if err != nil || len(list) != 0 {
		t.Errorf("ListNotifications after delete = %v, %v, want none", list, err)
	}
	list, err = s.ListNotifications(ctx, bob, notification.Query{Limit: 10})
	if err != nil || !slices.Equal(notificationIDs(list), []int64{kept.ID}) {
		t.Errorf("other user's notifications = %v, %v, want them kept", list, err)
	}
}

func TestStore_notificationPreferences(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	ann := testUserPK(t)

	got, err := s.NotificationPreferences(ctx, ann)
	if err != nil || len(got) != 0 {
		t.Fatalf("NotificationPreferences of a new user = %v, %v, want none", got, err)
	}
	first := notification.Preferences{
		notification.CategoryProfile:     {notification.ChannelInApp: true, "email": false},
		notification.CategoryCertificate: {"email": true},
	}
	if err := s.PutNotificationPreferences(ctx, ann, first); err != nil {
		t.Fatalf("PutNotificationPreferences: %v", err)
	}
	if got, err = s.NotificationPreferences(ctx, ann); err != nil || !got.Equal(first) {
		t.Errorf("NotificationPreferences = %v, %v, want %v", got, err, first)
	}
	// Putting again replaces every entry.
	second := notification.Preferences{notification.CategoryJoinRequest: {"email": false}}
	if err := s.PutNotificationPreferences(ctx, ann, second); err != nil {
		t.Fatalf("PutNotificationPreferences: %v", err)
	}
	if got, err = s.NotificationPreferences(ctx, ann); err != nil || !got.Equal(second) {
		t.Errorf("NotificationPreferences = %v, %v, want %v", got, err, second)
	}
}
