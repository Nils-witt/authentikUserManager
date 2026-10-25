// Package audit defines the audit log: a record of the changes operators make,
// of their denied access attempts and of logins, which access administrators
// can review.
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
	ActionUserCreated      Action = "user.created"
	ActionUserUpdated      Action = "user.updated"
	ActionUserDeleted      Action = "user.deleted"
	ActionUserGroupAdded   Action = "user.group_added"
	ActionUserGroupRemoved Action = "user.group_removed"
	// ActionUserPrimaryGroupChanged is recorded when a user's primary group is set, changed or removed.
	ActionUserPrimaryGroupChanged Action = "user.primary_group_changed"
	ActionRecoveryEmailSent       Action = "user.recovery_email_sent"
	// ActionAccessDenied is recorded when an operator requests a user outside their scope.
	ActionAccessDenied Action = "user.access_denied"
	ActionRuleSaved    Action = "access_rule.saved"
	ActionRuleDeleted  Action = "access_rule.deleted"
	// ActionGroupCreated is recorded when an access administrator creates a group.
	ActionGroupCreated Action = "group.created"
	// ActionGroupRenamed is recorded when a group is renamed, together with the access rules naming it.
	ActionGroupRenamed Action = "group.renamed"
	// ActionGroupVisibilityChanged is recorded when a group is made visible to every signed-in user or hidden again.
	ActionGroupVisibilityChanged Action = "group.visibility_changed"
	// ActionGroupPathChanged is recorded when a group is moved to another folder.
	ActionGroupPathChanged Action = "group.path_changed"
	// ActionJoinRequested is recorded when a user requests to join a visible group.
	ActionJoinRequested Action = "group.join_requested"
	// ActionJoinWithdrawn is recorded when a user withdraws their pending request.
	ActionJoinWithdrawn Action = "group.join_withdrawn"
	// ActionJoinApproved is recorded when an operator approves a request and the user joins the group.
	ActionJoinApproved Action = "group.join_approved"
	// ActionJoinRejected is recorded when an operator rejects a request.
	ActionJoinRejected Action = "group.join_rejected"
	// ActionCertificateIssued is recorded when a user issues a client certificate for their own account.
	ActionCertificateIssued Action = "user.certificate_issued"
	// ActionCertificateKeyDownloaded is recorded when a user downloads the generated key of their certificate.
	ActionCertificateKeyDownloaded Action = "user.certificate_key_downloaded"
	// ActionCertificateRevoked is recorded when a user or an operator revokes a certificate.
	ActionCertificateRevoked Action = "user.certificate_revoked"
	// ActionCertificateImported is recorded when an access administrator imports a certificate the CA signed elsewhere.
	ActionCertificateImported Action = "user.certificate_imported"
	// ActionCertificateAssigned is recorded when an access administrator assigns an imported certificate
	// that was assigned to no user to the account its subject names.
	ActionCertificateAssigned Action = "user.certificate_assigned"
	// ActionServiceAccountCreated is recorded when an operator creates a service account.
	ActionServiceAccountCreated Action = "service_account.created"
	// ActionServiceAccountUpdated is recorded when an operator changes a service account.
	ActionServiceAccountUpdated Action = "service_account.updated"
	// ActionServiceAccountDeleted is recorded when an access administrator deletes a service account.
	ActionServiceAccountDeleted Action = "service_account.deleted"
	// ActionTokenCreated is recorded when an operator creates a token of a service account.
	ActionTokenCreated Action = "service_account.token_created"
	// ActionTokenDeleted is recorded when an operator deletes a token of a service account.
	ActionTokenDeleted Action = "service_account.token_deleted"
	// ActionAPIKeyCreated is recorded when an operator creates an API key of a service account.
	ActionAPIKeyCreated Action = "service_account.api_key_created"
	// ActionAPIKeyDeleted is recorded when an operator deletes an API key of a service account,
	// or its keys are deleted with the service account.
	ActionAPIKeyDeleted Action = "service_account.api_key_deleted"
	// ActionAuthorityCreated is recorded when an access administrator adds a certificate authority.
	ActionAuthorityCreated Action = "certificate_authority.created"
	// ActionAuthorityUpdated is recorded when an access administrator changes the settings of a
	// certificate authority, or enables or disables it.
	ActionAuthorityUpdated Action = "certificate_authority.updated"
	// ActionAuthorityDefaultChanged is recorded when an access administrator makes a certificate
	// authority the default one.
	ActionAuthorityDefaultChanged Action = "certificate_authority.default_changed"
	// ActionLogin is recorded when a user signs in.
	ActionLogin Action = "auth.login"
	// ActionLoginFailed is recorded when a login cannot be completed, e.g. for
	// an invalid state or a code the provider refuses. Its actor is empty.
	ActionLoginFailed Action = "auth.login_failed"
	// ActionLogout is recorded when a user signs out, or the provider ends their session.
	ActionLogout Action = "auth.logout"
	// ActionSessionEnded is recorded when a session ends because the user's
	// account was deleted, deactivated or renamed.
	ActionSessionEnded Action = "auth.session_ended"
	// ActionAPIKeyRejected is recorded when the service API refuses an API key.
	// Its actor is empty.
	ActionAPIKeyRejected Action = "service_api.api_key_rejected"
)

// Valid reports whether a is one of the recorded actions.
func (a Action) Valid() bool {
	switch a {
	case ActionUserCreated, ActionUserUpdated, ActionUserDeleted,
		ActionUserGroupAdded, ActionUserGroupRemoved, ActionUserPrimaryGroupChanged, ActionRecoveryEmailSent,
		ActionAccessDenied, ActionRuleSaved, ActionRuleDeleted,
		ActionGroupCreated, ActionGroupRenamed, ActionGroupVisibilityChanged, ActionGroupPathChanged,
		ActionJoinRequested, ActionJoinWithdrawn, ActionJoinApproved, ActionJoinRejected,
		ActionCertificateIssued, ActionCertificateKeyDownloaded, ActionCertificateRevoked, ActionCertificateImported,
		ActionCertificateAssigned,
		ActionServiceAccountCreated, ActionServiceAccountUpdated, ActionServiceAccountDeleted,
		ActionTokenCreated, ActionTokenDeleted, ActionAPIKeyCreated, ActionAPIKeyDeleted,
		ActionAuthorityCreated, ActionAuthorityUpdated, ActionAuthorityDefaultChanged,
		ActionLogin, ActionLoginFailed, ActionLogout, ActionSessionEnded, ActionAPIKeyRejected:
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
	// Target is the username of the affected user or service account, the operator group of the
	// affected rule, the (new) name of the affected group, or the name of the
	// affected certificate authority. For join requests it is the username of
	// the requesting user.
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
