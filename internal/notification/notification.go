// Package notification defines the notifications users receive about changes
// to their account, the preferences that choose which ones they receive on
// which channel, and the Notifier that stores and delivers them.
package notification

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Category groups notifications about one kind of change.
type Category string

// The categories.
const (
	// CategoryProfile is about changes to the user's profile, such as their
	// name, email address or groups.
	CategoryProfile Category = "profile"
	// CategoryCertificate is about certificates issued to or revoked from the user.
	CategoryCertificate Category = "certificate"
	// CategoryJoinRequest is about decisions on the user's requests to join groups.
	CategoryJoinRequest Category = "join_request"
	// CategorySettings is about changes to the user's notification preferences.
	// It is always delivered on every channel.
	CategorySettings Category = "settings"
)

// Categories lists the categories in display order.
var Categories = []Category{CategoryProfile, CategoryCertificate, CategoryJoinRequest, CategorySettings}

// Valid reports whether c is one of the categories.
func (c Category) Valid() bool {
	switch c {
	case CategoryProfile, CategoryCertificate, CategoryJoinRequest, CategorySettings:
		return true
	}
	return false
}

// Label returns the name of c shown to users.
func (c Category) Label() string {
	switch c {
	case CategoryProfile:
		return "Profile changes"
	case CategoryCertificate:
		return "Certificates"
	case CategoryJoinRequest:
		return "Join requests"
	case CategorySettings:
		return "Notification settings"
	}
	return string(c)
}

// Mandatory reports whether notifications of c are delivered whatever the preferences say.
func (c Category) Mandatory() bool {
	return c == CategorySettings
}

// Channel names a way notifications reach users: the in-app inbox, or the
// Name of a NotificationReceiver.
type Channel string

// ChannelInApp is the inbox in the application, which is always available.
const ChannelInApp Channel = "in_app"

// ChannelInfo describes a channel for the settings UI.
type ChannelInfo struct {
	Name  Channel `json:"name"`
	Label string  `json:"label"`
}

// Length limits of notifications, in characters.
const (
	MaxHeaderLen  = 200
	MaxMessageLen = 2000
)

var (
	// ErrNotFound is returned when the user has no notification with the given ID.
	ErrNotFound = errors.New("notification not found")
	// ErrNoAddress is returned by a NotificationReceiver that cannot reach the recipient.
	ErrNoAddress = errors.New("recipient has no address for this channel")
)

// Notification is one message to one user.
type Notification struct {
	// ID is set by the store.
	ID int64 `json:"id"`
	// UserPK is the authentik primary key of the recipient.
	UserPK   int      `json:"-"`
	Category Category `json:"category"`
	// Header is a short summary, e.g. the subject of an email.
	Header  string `json:"header"`
	Message string `json:"message"`
	// CreatedAt is set by the store.
	CreatedAt time.Time `json:"created_at"`
	// ReadAt is nil while the notification is unread.
	ReadAt *time.Time `json:"read_at"`
}

// New returns a notification of cat with the trimmed header and message. Both
// are required and bounded by MaxHeaderLen and MaxMessageLen.
func New(cat Category, header, message string) (Notification, error) {
	header = strings.TrimSpace(header)
	message = strings.TrimSpace(message)
	switch {
	case !cat.Valid():
		return Notification{}, fmt.Errorf("notification: unknown category %q", cat)
	case header == "":
		return Notification{}, errors.New("notification: header is required")
	case message == "":
		return Notification{}, errors.New("notification: message is required")
	case utf8.RuneCountInString(header) > MaxHeaderLen:
		return Notification{}, fmt.Errorf("notification: header must be at most %d characters", MaxHeaderLen)
	case utf8.RuneCountInString(message) > MaxMessageLen:
		return Notification{}, fmt.Errorf("notification: message must be at most %d characters", MaxMessageLen)
	}
	return Notification{Category: cat, Header: header, Message: message}, nil
}

// Recipient is the user a notification is for.
type Recipient struct {
	// UserPK is the authentik primary key of the user.
	UserPK   int
	Username string
	// Email is the user's email address; empty when they have none.
	Email string
}

// NotificationReceiver delivers notifications through another system than the
// in-app inbox, such as email. Implementations must be safe for concurrent use.
//
//nolint:revive // The stuttering name was chosen deliberately, so it reads the same wherever it is implemented.
type NotificationReceiver interface {
	// Name is the channel key stored in the preferences, e.g. "email".
	Name() Channel
	// Label is the channel's name shown to users, e.g. "Email".
	Label() string
	// Receive delivers n to rcpt. It returns ErrNoAddress when rcpt cannot be
	// reached on this channel.
	Receive(ctx context.Context, rcpt Recipient, n Notification) error
}

// Preferences tell per category and channel whether a user receives
// notifications. A missing entry means they do.
type Preferences map[Category]map[Channel]bool

// Enabled reports whether notifications of cat are delivered on ch.
func (p Preferences) Enabled(cat Category, ch Channel) bool {
	if cat.Mandatory() {
		return true
	}
	on, ok := p[cat][ch]
	return !ok || on
}

// Complete returns the preferences of every category on every channel in
// channels, filling in the defaults and leaving out unknown entries.
func (p Preferences) Complete(channels []Channel) Preferences {
	out := make(Preferences, len(Categories))
	for _, cat := range Categories {
		out[cat] = make(map[Channel]bool, len(channels))
		for _, ch := range channels {
			out[cat][ch] = p.Enabled(cat, ch)
		}
	}
	return out
}

// Normalize checks that p names only known categories and the given channels
// and returns it completed (see Complete). Mandatory categories are turned on.
// The returned error is safe to show users.
func (p Preferences) Normalize(channels []Channel) (Preferences, error) {
	for cat, chs := range p {
		if !cat.Valid() {
			return nil, fmt.Errorf("unknown category %q", cat)
		}
		for ch := range chs {
			if !slices.Contains(channels, ch) {
				return nil, fmt.Errorf("unknown channel %q", ch)
			}
		}
	}
	return p.Complete(channels), nil
}

// Equal reports whether p and q hold the same entries.
func (p Preferences) Equal(q Preferences) bool {
	return maps.EqualFunc(p, q, maps.Equal)
}

// Page size limits for listing notifications.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Query selects a user's notifications, newest first.
type Query struct {
	// Before, when positive, matches only notifications with a lower ID; it pages through the list.
	Before int64
	// Limit is the maximum number of notifications, between 1 and MaxLimit.
	Limit int
}

// Normalize fills in the default limit and validates the query. The returned
// error is safe to show users.
func (q Query) Normalize() (Query, error) {
	if q.Limit == 0 {
		q.Limit = DefaultLimit
	}
	switch {
	case q.Before < 0:
		return Query{}, errors.New("before must be a positive integer")
	case q.Limit < 1 || q.Limit > MaxLimit:
		return Query{}, fmt.Errorf("limit must be between 1 and %d", MaxLimit)
	}
	return q, nil
}
