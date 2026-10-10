// Package audit defines the audit log: a record of the changes operators make
// and of their denied access attempts, which access administrators can review.
package audit

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Action names what an operator did.
type Action string

// The recorded actions.
const (
	ActionUserCreated       Action = "user.created"
	ActionUserUpdated       Action = "user.updated"
	ActionUserDeleted       Action = "user.deleted"
	ActionUserGroupAdded    Action = "user.group_added"
	ActionUserGroupRemoved  Action = "user.group_removed"
	ActionRecoveryEmailSent Action = "user.recovery_email_sent"
	// ActionAccessDenied is recorded when an operator requests a user outside their scope.
	ActionAccessDenied Action = "user.access_denied"
	ActionRuleSaved    Action = "access_rule.saved"
	ActionRuleDeleted  Action = "access_rule.deleted"
)

// Valid reports whether a is one of the recorded actions.
func (a Action) Valid() bool {
	switch a {
	case ActionUserCreated, ActionUserUpdated, ActionUserDeleted,
		ActionUserGroupAdded, ActionUserGroupRemoved, ActionRecoveryEmailSent,
		ActionAccessDenied, ActionRuleSaved, ActionRuleDeleted:
		return true
	}
	return false
}

// Entry is one record in the audit log.
type Entry struct {
	// ID increases with every entry; it is set by the store.
	ID int64 `json:"id"`
	// Time is set by the store.
	Time time.Time `json:"time"`
	// Actor is the username of the operator.
	Actor  string `json:"actor"`
	Action Action `json:"action"`
	// Target is the username of the affected user or the operator group of the affected rule.
	Target string `json:"target"`
	// Details holds action-specific values, such as the user ID or the changed fields.
	Details map[string]string `json:"details"`
}

// Page size limits for listing entries.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// maxSearchLen bounds the search text.
const maxSearchLen = 255

// Query selects audit log entries, newest first.
type Query struct {
	// Search, when set, matches the actor or the target case-insensitively by substring.
	Search string
	// Action, when set, matches only entries of this action.
	Action Action
	// Before, when positive, matches only entries with a lower ID; it pages through the log.
	Before int64
	// Limit is the maximum number of entries, between 1 and MaxLimit.
	Limit int
}

// Normalize trims the search text and fills in the default limit, then
// validates the query. The returned error is safe to show users.
func (q Query) Normalize() (Query, error) {
	q.Search = strings.TrimSpace(q.Search)
	if q.Limit == 0 {
		q.Limit = DefaultLimit
	}
	switch {
	case len(q.Search) > maxSearchLen:
		return Query{}, fmt.Errorf("search must be at most %d characters", maxSearchLen)
	case q.Action != "" && !q.Action.Valid():
		return Query{}, errors.New("unknown action")
	case q.Before < 0:
		return Query{}, errors.New("before must be a positive integer")
	case q.Limit < 1 || q.Limit > MaxLimit:
		return Query{}, fmt.Errorf("limit must be between 1 and %d", MaxLimit)
	}
	return q, nil
}
