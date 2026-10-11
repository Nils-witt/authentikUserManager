// Package joinrequest defines requests by signed-in users to join a visible
// group, which the operators managing that group approve or reject.
package joinrequest

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Status is the state of a request.
type Status string

// The states of a request. A request starts pending and is decided once.
const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// Valid reports whether s is one of the states.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusApproved, StatusRejected:
		return true
	}
	return false
}

// MaxMessageLen bounds the message a user adds to a request, in characters.
const MaxMessageLen = 500

// MaxList bounds the number of requests one list returns.
const MaxList = 200

var (
	// ErrNotFound is returned when there is no request with the given ID.
	ErrNotFound = errors.New("join request not found")
	// ErrPending is returned when the user already has a pending request for the group.
	ErrPending = errors.New("join request already pending")
	// ErrDecided is returned when deciding a request that is no longer pending.
	ErrDecided = errors.New("join request already decided")
)

// Request is one user's request to join one group.
type Request struct {
	// ID is set by the store.
	ID int64 `json:"id"`
	// GroupPK is the authentik primary key of the requested group.
	GroupPK string `json:"group_pk"`
	// GroupName is the name of the group when the request was made.
	GroupName string `json:"group_name"`
	// UserPK is the authentik primary key of the requesting user.
	UserPK   int    `json:"user_pk"`
	Username string `json:"username"`
	// Message is the user's optional reason for joining.
	Message string `json:"message"`
	Status  Status `json:"status"`
	// CreatedAt is set by the store.
	CreatedAt time.Time `json:"created_at"`
	// DecidedAt and DecidedBy are set once the request is approved or rejected.
	DecidedAt *time.Time `json:"decided_at"`
	DecidedBy string     `json:"decided_by"`
}

// NormalizeMessage trims a request message and checks its length. The
// returned error is safe to show users.
func NormalizeMessage(msg string) (string, error) {
	msg = strings.TrimSpace(msg)
	if utf8.RuneCountInString(msg) > MaxMessageLen {
		return "", fmt.Errorf("message must be at most %d characters", MaxMessageLen)
	}
	return msg, nil
}

// Query selects requests, newest first, up to MaxList of them. Zero fields match everything.
type Query struct {
	Status Status
	// GroupPKs, when non-nil, matches only requests for these groups.
	GroupPKs []string
	// Username, when set, matches only the requests of this user.
	Username string
}
