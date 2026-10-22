package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"authentikManager/internal/authentik"
	"authentikManager/internal/notification"
)

// notificationTimeout bounds sending a notification, which outlives the request.
const notificationTimeout = 5 * time.Second

// recipientOf returns the notification recipient of user.
func recipientOf(user *authentik.User) notification.Recipient {
	return notification.Recipient{UserPK: user.PK, Username: user.Username, Email: user.Email}
}

// receivesNotifications reports whether user can receive notifications: only
// internal users sign in here and read them.
func (s *Server) receivesNotifications(user *authentik.User) bool {
	return s.notifications != nil && user != nil && user.Type == authentik.UserTypeInternal
}

// notify sends a notification of cat to user. The change it describes has
// already been made, so a failure is logged rather than reported to the client.
func (s *Server) notify(r *http.Request, user *authentik.User, cat notification.Category, header, message string) {
	if !s.receivesNotifications(user) {
		return
	}
	// Send it even when the client has gone away meanwhile.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), notificationTimeout)
	defer cancel()
	if err := s.notifications.Notify(ctx, recipientOf(user), cat, header, message); err != nil {
		s.logger.ErrorContext(r.Context(), "sending notification failed",
			slog.String("category", string(cat)),
			slog.Int("user_id", user.PK),
			slog.Any("error", err),
		)
	}
}

// notificationRecipient loads the user with the primary key userPK to notify
// them, or returns nil when notifications are disabled or the user cannot be
// loaded, e.g. because they were deleted.
func (s *Server) notificationRecipient(r *http.Request, userPK int) *authentik.User {
	if s.notifications == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), notificationTimeout)
	defer cancel()
	user, err := s.users.GetUser(ctx, userPK)
	if errors.Is(err, authentik.ErrNotFound) {
		return nil
	}
	if err != nil {
		s.logger.ErrorContext(r.Context(), "loading notification recipient failed",
			slog.Int("user_id", userPK),
			slog.Any("error", err),
		)
		return nil
	}
	return user
}

// forwardToPreviousEmail tells the previous email address of user, replaced
// by an update, about the change, through the receivers only.
func (s *Server) forwardToPreviousEmail(r *http.Request, user *authentik.User, previous, header, message string) {
	if !s.receivesNotifications(user) || previous == "" || previous == user.Email {
		return
	}
	rcpt := recipientOf(user)
	rcpt.Email = previous
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), notificationTimeout)
	defer cancel()
	if err := s.notifications.Forward(ctx, rcpt, notification.CategoryProfile, header, message); err != nil {
		s.logger.ErrorContext(r.Context(), "forwarding notification failed",
			slog.Int("user_id", user.PK),
			slog.Any("error", err),
		)
	}
}

// changedBy names who made a change to user, for notification messages.
func changedBy(r *http.Request, user *authentik.User) string {
	if isActor(r, user) {
		return "you"
	}
	return actorName(r)
}

// orNone returns s, or "(none)" when it is empty.
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// profileChanges lists the changes from before to after that the user sees,
// one per line. The hidden flag is for access administrators only and left out.
func profileChanges(before, after *authentik.User) []string {
	changes := []string{}
	field := func(label, old, current string) {
		if old != current {
			changes = append(changes, fmt.Sprintf("%s: %s → %s", label, orNone(old), orNone(current)))
		}
	}
	field("Username", before.Username, after.Username)
	field("Name", before.Name, after.Name)
	field("Email address", before.Email, after.Email)
	field("Folder", before.Path, after.Path)
	if before.IsActive != after.IsActive {
		state := "deactivated"
		if after.IsActive {
			state = "activated"
		}
		changes = append(changes, "Account: "+state)
	}
	return changes
}

// changeList formats a notification message introducing the changes with intro.
func changeList(intro string, changes []string) string {
	return intro + "\n- " + strings.Join(changes, "\n- ")
}

// notifyProfileUpdate tells user about the changes an update made to their
// profile, and their previous email address about a new one.
func (s *Server) notifyProfileUpdate(r *http.Request, before, after *authentik.User) {
	changes := profileChanges(before, after)
	if len(changes) == 0 {
		return
	}
	const header = "Your profile was updated"
	message := changeList(fmt.Sprintf("Your profile was changed by %s:", changedBy(r, after)), changes)
	s.notify(r, after, notification.CategoryProfile, header, message)
	s.forwardToPreviousEmail(r, after, before.Email, header, message)
}

// notifyGroupChanges tells user that their groups changed.
func (s *Server) notifyGroupChanges(r *http.Request, user *authentik.User, changes []string) {
	if len(changes) == 0 {
		return
	}
	s.notify(r, user, notification.CategoryProfile, "Your groups were changed",
		changeList(fmt.Sprintf("Your groups were changed by %s:", changedBy(r, user)), changes))
}

// notifyCertificatesRevoked tells user that their certificates with serials
// were revoked, for reason when it is not empty.
func (s *Server) notifyCertificatesRevoked(r *http.Request, user *authentik.User, serials []string, reason string) {
	if len(serials) == 0 {
		return
	}
	header := "Certificate revoked"
	intro := "Your certificate was revoked by " + changedBy(r, user)
	if len(serials) > 1 {
		header = "Certificates revoked"
		intro = fmt.Sprintf("%d of your certificates were revoked by %s", len(serials), changedBy(r, user))
	}
	if reason != "" {
		intro += " (" + reason + ")"
	}
	lines := make([]string, 0, len(serials))
	for _, serial := range serials {
		lines = append(lines, "Serial number: "+serial)
	}
	s.notify(r, user, notification.CategoryCertificate, header, changeList(intro+".", lines))
}

// requireNotifications responds 501 when notifications are disabled.
func (s *Server) requireNotifications(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.notifications == nil {
			writeError(w, http.StatusNotImplemented, "notifications are disabled", nil)
			return
		}
		h(w, r)
	})
}

// notificationUser returns the signed-in user's internal account, whose
// notifications they may read, writing the error response when it returns false.
func (s *Server) notificationUser(w http.ResponseWriter, r *http.Request) (*authentik.User, bool) {
	user, err := s.findActor(r, authentik.ListUsersParams{})
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return nil, false
	}
	if user == nil {
		writeError(w, http.StatusForbidden, "only internal users receive notifications", nil)
		return nil, false
	}
	return user, true
}

// notificationPage is the response of GET /api/notifications.
type notificationPage struct {
	Notifications []notification.Notification `json:"notifications"`
	// Next is the value of the "before" parameter for the next page; it is
	// omitted on the last page.
	Next int64 `json:"next,omitempty"`
	// Unread is how many of all the user's notifications are unread.
	Unread int `json:"unread"`
}

// listNotifications returns a page of the signed-in user's notifications,
// newest first. The query parameters before and limit page it.
func (s *Server) listNotifications(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	var q notification.Query
	var err error
	if v := params.Get("before"); v != "" {
		if q.Before, err = strconv.ParseInt(v, 10, 64); err != nil || q.Before < 1 {
			writeError(w, http.StatusBadRequest, "before must be a positive integer", nil)
			return
		}
	}
	if v := params.Get("limit"); v != "" {
		if q.Limit, err = strconv.Atoi(v); err != nil || q.Limit < 1 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("limit must be between 1 and %d", notification.MaxLimit), nil)
			return
		}
	}
	if q, err = q.Normalize(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}

	// One more notification than requested tells whether there is another page.
	limit := q.Limit
	q.Limit++
	list, err := s.notifications.List(r.Context(), user.PK, q)
	if err != nil {
		s.writeNotificationError(w, r, err)
		return
	}
	unread, err := s.notifications.CountUnread(r.Context(), user.PK)
	if err != nil {
		s.writeNotificationError(w, r, err)
		return
	}
	page := notificationPage{Notifications: list, Unread: unread}
	if len(list) > limit {
		page.Notifications = list[:limit]
		page.Next = page.Notifications[limit-1].ID
	}
	if page.Notifications == nil {
		page.Notifications = []notification.Notification{}
	}
	writeJSON(w, http.StatusOK, page)
}

// countUnreadNotifications returns how many of the signed-in user's notifications are unread.
func (s *Server) countUnreadNotifications(w http.ResponseWriter, r *http.Request) {
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}
	unread, err := s.notifications.CountUnread(r.Context(), user.PK)
	if err != nil {
		s.writeNotificationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Unread int `json:"unread"`
	}{Unread: unread})
}

// markNotificationRead marks the signed-in user's notification with the {id} path value read.
func (s *Server) markNotificationRead(w http.ResponseWriter, r *http.Request) {
	s.changeNotification(w, r, s.notifications.MarkRead)
}

// deleteNotification deletes the signed-in user's notification with the {id} path value.
func (s *Server) deleteNotification(w http.ResponseWriter, r *http.Request) {
	s.changeNotification(w, r, s.notifications.Delete)
}

// changeNotification applies change to the signed-in user's notification with
// the {id} path value. Notifications of other users are reported as not found.
func (s *Server) changeNotification(w http.ResponseWriter, r *http.Request, change func(context.Context, int, int64) error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "invalid notification id", nil)
		return
	}
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}
	if err := change(r.Context(), user.PK, id); err != nil {
		s.writeNotificationError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// markAllNotificationsRead marks every notification of the signed-in user read.
func (s *Server) markAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	s.changeAllNotifications(w, r, s.notifications.MarkAllRead)
}

// deleteAllNotifications deletes every notification of the signed-in user.
func (s *Server) deleteAllNotifications(w http.ResponseWriter, r *http.Request) {
	s.changeAllNotifications(w, r, s.notifications.DeleteAll)
}

func (s *Server) changeAllNotifications(w http.ResponseWriter, r *http.Request, change func(context.Context, int) error) {
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}
	if err := change(r.Context(), user.PK); err != nil {
		s.writeNotificationError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// notificationCategory describes a category for the settings UI.
type notificationCategory struct {
	Name  notification.Category `json:"name"`
	Label string                `json:"label"`
	// Mandatory categories are delivered on every channel whatever the preferences say.
	Mandatory bool `json:"mandatory"`
}

// notificationSettings is the response of the preferences endpoints.
type notificationSettings struct {
	Channels    []notification.ChannelInfo `json:"channels"`
	Categories  []notificationCategory     `json:"categories"`
	Preferences notification.Preferences   `json:"preferences"`
}

func (s *Server) newNotificationSettings(prefs notification.Preferences) notificationSettings {
	categories := make([]notificationCategory, 0, len(notification.Categories))
	for _, c := range notification.Categories {
		categories = append(categories, notificationCategory{Name: c, Label: c.Label(), Mandatory: c.Mandatory()})
	}
	return notificationSettings{Channels: s.notifications.Channels(), Categories: categories, Preferences: prefs}
}

// getNotificationPreferences returns the signed-in user's preferences with
// the channels and categories they choose between.
func (s *Server) getNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}
	prefs, err := s.notifications.Preferences(r.Context(), user.PK)
	if err != nil {
		s.writeNotificationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.newNotificationSettings(prefs))
}

// putNotificationPreferences replaces the signed-in user's preferences. The
// user is always notified of the change.
func (s *Server) putNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Preferences notification.Preferences `json:"preferences"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}
	prefs, err := s.notifications.SetPreferences(r.Context(), recipientOf(user), in.Preferences)
	if err != nil {
		s.writeNotificationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.newNotificationSettings(prefs))
}

// writeNotificationError translates a notification error into a response.
func (s *Server) writeNotificationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, notification.ErrNotFound):
		writeError(w, http.StatusNotFound, "notification not found", nil)
	case errors.Is(err, notification.ErrInvalidPreferences):
		writeError(w, http.StatusBadRequest, err.Error(), nil)
	case errors.Is(err, context.Canceled):
	default:
		s.logger.ErrorContext(r.Context(), "notification store failed",
			slog.String("path", r.URL.Path),
			slog.Any("error", err),
		)
		writeError(w, http.StatusInternalServerError, "saving or loading notifications failed", nil)
	}
}
