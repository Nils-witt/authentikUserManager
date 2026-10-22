// Package server exposes the user management REST API consumed by the frontend
// and optionally serves the built frontend itself.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
	"authentikManager/internal/auth"
	"authentikManager/internal/authentik"
	"authentikManager/internal/buildinfo"
	"authentikManager/internal/certificate"
	"authentikManager/internal/joinrequest"
	"authentikManager/internal/notification"
	"authentikManager/internal/pki"
)

// maxRequestBytes bounds JSON request bodies.
const maxRequestBytes = 1 << 20

// cspNoncePlaceholder is written into index.html by Vite (html.cspNonce in
// frontend/vite.config.ts) and replaced with a fresh nonce on every request.
const cspNoncePlaceholder = "__CSP_NONCE__"

// contentSecurityPolicy returns the CSP header value. A non-empty nonce allows
// the <style> elements the frontend's CSS-in-JS library (Emotion) injects.
func contentSecurityPolicy(nonce string) string {
	styleSrc := "style-src 'self'"
	if nonce != "" {
		styleSrc += " 'nonce-" + nonce + "'"
	}
	return "default-src 'self'; " + styleSrc + "; img-src 'self' https: data:; frame-ancestors 'none'"
}

// UserService is the subset of the authentik client the handlers depend on.
type UserService interface {
	ListUsers(ctx context.Context, p authentik.ListUsersParams) (*authentik.UserList, error)
	GetUser(ctx context.Context, id int) (*authentik.User, error)
	CreateUser(ctx context.Context, req authentik.CreateUserRequest) (*authentik.User, error)
	UpdateUser(ctx context.Context, id int, req authentik.UpdateUserRequest) (*authentik.User, error)
	DeleteUser(ctx context.Context, id int) error
	FindGroup(ctx context.Context, name string) (*authentik.Group, error)
	AddUserToGroup(ctx context.Context, groupPK string, userID int) error
	RemoveUserFromGroup(ctx context.Context, groupPK string, userID int) error
	SendRecoveryEmail(ctx context.Context, id int, emailStage string) error
	ListGroups(ctx context.Context, p authentik.ListGroupsParams) (*authentik.GroupList, error)
	GetGroup(ctx context.Context, pk string) (*authentik.Group, error)
	CreateGroup(ctx context.Context, req authentik.CreateGroupRequest) (*authentik.Group, error)
	UpdateGroup(ctx context.Context, pk string, req authentik.UpdateGroupRequest) (*authentik.Group, error)
	ListTokens(ctx context.Context, userPK int, username string) ([]authentik.Token, error)
	GetToken(ctx context.Context, identifier string) (*authentik.Token, error)
	CreateToken(ctx context.Context, req authentik.CreateTokenRequest) (*authentik.Token, error)
	TokenKey(ctx context.Context, identifier string) (string, error)
	DeleteToken(ctx context.Context, identifier string) error
	ListUserApplications(ctx context.Context, userPK int) ([]authentik.Application, error)
}

var _ UserService = (*authentik.Client)(nil)

// Authenticator provides the login endpoints and guards the API.
type Authenticator interface {
	// Handler serves the /auth/ endpoints.
	Handler() http.Handler
	// Require rejects unauthenticated requests and stores the auth.User in the context.
	Require(next http.Handler) http.Handler
}

var _ Authenticator = (*auth.Authenticator)(nil)

// Policy resolves which users an operator may manage.
type Policy interface {
	ScopeFor(ctx context.Context, operatorGroups []string) (access.Scope, error)
	// IsAdmin reports whether the operator may edit the access rules.
	IsAdmin(operatorGroups []string) bool
}

var _ Policy = (*access.Policy)(nil)

// RuleStore lists and edits the access rules.
type RuleStore interface {
	ListRules(ctx context.Context) ([]access.Rule, error)
	// PutRule creates or replaces a normalized rule.
	PutRule(ctx context.Context, rule access.Rule, actor string) error
	// DeleteRule returns access.ErrRuleNotFound when there is no rule.
	DeleteRule(ctx context.Context, operatorGroup string) error
	// RenameGroup replaces a group name in every rule and returns how many entries changed.
	RenameGroup(ctx context.Context, oldName, newName, actor string) (int64, error)
}

// AuditLog records the changes operators make and lists them.
type AuditLog interface {
	RecordAudit(ctx context.Context, e audit.Entry) error
	// ListAudit returns the entries matching a normalized query, newest first.
	ListAudit(ctx context.Context, q audit.Query) ([]audit.Entry, error)
}

// JoinRequestStore keeps the requests to join groups.
type JoinRequestStore interface {
	// CreateJoinRequest returns joinrequest.ErrPending when the user already has a pending request for the group.
	CreateJoinRequest(ctx context.Context, jr joinrequest.Request) (joinrequest.Request, error)
	// GetJoinRequest returns joinrequest.ErrNotFound when there is no request.
	GetJoinRequest(ctx context.Context, id int64) (joinrequest.Request, error)
	ListJoinRequests(ctx context.Context, q joinrequest.Query) ([]joinrequest.Request, error)
	// DecideJoinRequest returns joinrequest.ErrDecided when the request is no longer pending.
	DecideJoinRequest(ctx context.Context, id int64, status joinrequest.Status, actor string) (joinrequest.Request, error)
	// ReopenJoinRequest makes an approved request pending again.
	ReopenJoinRequest(ctx context.Context, id int64) error
	// WithdrawJoinRequest deletes a pending request of username, or returns joinrequest.ErrNotFound.
	WithdrawJoinRequest(ctx context.Context, id int64, username string) error
}

// CertificateStore keeps the records of the certificates issued to users.
type CertificateStore interface {
	// CreateCertificate returns certificate.ErrExists when the serial is already recorded.
	CreateCertificate(ctx context.Context, c certificate.Certificate) (certificate.Certificate, error)
	// GetCertificate returns certificate.ErrNotFound when there is no certificate.
	GetCertificate(ctx context.Context, serial string) (certificate.Certificate, error)
	// GetCertificateDER returns the encoded certificate, certificate.ErrNotFound
	// when there is none, or certificate.ErrNotStored when it was not stored.
	GetCertificateDER(ctx context.Context, serial string) ([]byte, error)
	// ListCertificates returns the certificates of a user, newest first.
	ListCertificates(ctx context.Context, userPK int) ([]certificate.Certificate, error)
	// ListAllCertificates returns a page of the certificates of all users
	// matching a normalized query, newest first, and how many match in total.
	ListAllCertificates(ctx context.Context, q certificate.Query, now time.Time) ([]certificate.Certificate, int, error)
	// RevokeCertificate returns certificate.ErrRevoked when the certificate is already revoked.
	RevokeCertificate(ctx context.Context, serial, actor string) (certificate.Certificate, error)
	// AssignCertificate assigns an unassigned certificate to a user. It returns
	// certificate.ErrAssigned when the certificate already belongs to one.
	AssignCertificate(ctx context.Context, serial string, userPK int, username string) (certificate.Certificate, error)
	// RevokeUserCertificates revokes every unrevoked certificate of a user and returns their serials.
	RevokeUserCertificates(ctx context.Context, userPK int, actor string) ([]string, error)
	// ListRevokedCertificates returns the revoked certificates still valid at now.
	ListRevokedCertificates(ctx context.Context, now time.Time) ([]certificate.Revoked, error)
}

// NotificationService stores the notifications of users, delivers them on the
// channels they choose and keeps their preferences.
type NotificationService interface {
	// Notify sends a notification of cat to rcpt on the channels their preferences enable.
	Notify(ctx context.Context, rcpt notification.Recipient, cat notification.Category, header, message string) error
	// Forward hands a notification to the receivers of rcpt without storing it in their inbox.
	Forward(ctx context.Context, rcpt notification.Recipient, cat notification.Category, header, message string) error
	// Channels lists the channels users choose between, the in-app inbox first.
	Channels() []notification.ChannelInfo
	// List returns the notifications of a user matching a normalized query, newest first.
	List(ctx context.Context, userPK int, q notification.Query) ([]notification.Notification, error)
	CountUnread(ctx context.Context, userPK int) (int, error)
	// MarkRead returns notification.ErrNotFound when the user has no such notification.
	MarkRead(ctx context.Context, userPK int, id int64) error
	MarkAllRead(ctx context.Context, userPK int) error
	// Delete returns notification.ErrNotFound when the user has no such notification.
	Delete(ctx context.Context, userPK int, id int64) error
	DeleteAll(ctx context.Context, userPK int) error
	// Preferences returns the complete preferences of a user.
	Preferences(ctx context.Context, userPK int) (notification.Preferences, error)
	// SetPreferences replaces the preferences of rcpt and always notifies them of
	// the change. It returns an error wrapping notification.ErrInvalidPreferences
	// for invalid preferences.
	SetPreferences(ctx context.Context, rcpt notification.Recipient, p notification.Preferences) (notification.Preferences, error)
}

var _ NotificationService = (*notification.Notifier)(nil)

// Deps are the collaborators of the Server.
type Deps struct {
	Users  UserService
	Auth   Authenticator
	Policy Policy
	Rules  RuleStore
	Audit  AuditLog
	// JoinRequests keeps the requests to join groups.
	JoinRequests JoinRequestStore
	Logger       *slog.Logger
	// Static, when non-nil, is the built frontend.
	Static fs.FS
	// RecoveryEmailStage is the UUID of the email stage that sends password
	// recovery emails. When empty, sending them is disabled.
	RecoveryEmailStage string
	// CA issues user certificates. When nil, certificates are disabled and
	// KeyDownloads is not used.
	CA *pki.CA
	// Certificates keeps the records of the issued certificates. When set, a
	// user's certificates are revoked when the user is deleted, deactivated or
	// renamed, even while CA is nil.
	Certificates CertificateStore
	// KeyDownloads holds generated keys until their single download.
	KeyDownloads *pki.Pending
	// Notifications tells users about changes to their account. When nil,
	// notifications are disabled.
	Notifications NotificationService
}

// Server is the HTTP handler for the application.
type Server struct {
	users  UserService
	policy Policy
	rules  RuleStore
	// auditLog records changes; see Server.record.
	auditLog AuditLog
	// joinRequests keeps the requests to join groups.
	joinRequests JoinRequestStore
	logger       *slog.Logger
	// recoveryEmailStage is the email stage for recovery emails; empty disables them.
	recoveryEmailStage string
	// ca issues user certificates; nil disables them.
	ca           *pki.CA
	certificates CertificateStore
	keyDownloads *pki.Pending
	// notifications tells users about changes to their account; nil disables them.
	notifications NotificationService
	// crl caches the signed revocation list.
	crl crlCache
	// handler is the router wrapped in CSRF protection.
	handler http.Handler
}

// New builds the handler. Every /api/ route requires an authenticated session,
// and the policy limits which users each operator may see and manage.
// When d.Static is non-nil it is served for all other paths, falling back to
// index.html so client-side routing works; the SPA holds no data itself.
func New(d Deps) *Server {
	s := &Server{
		users:              d.Users,
		policy:             d.Policy,
		rules:              d.Rules,
		auditLog:           d.Audit,
		joinRequests:       d.JoinRequests,
		logger:             d.Logger,
		recoveryEmailStage: d.RecoveryEmailStage,
		ca:                 d.CA,
		certificates:       d.Certificates,
		keyDownloads:       d.KeyDownloads,
		notifications:      d.Notifications,
	}

	api := http.NewServeMux()
	api.HandleFunc("GET /api/access", s.getAccess)
	api.Handle("GET /api/access/rules", s.requireAdmin(s.listRules))
	api.Handle("PUT /api/access/rules/{group}", s.requireAdmin(s.putRule))
	api.Handle("DELETE /api/access/rules/{group}", s.requireAdmin(s.deleteRule))
	api.Handle("GET /api/groups", s.requireAdmin(s.listGroups))
	api.Handle("POST /api/groups", s.requireAdmin(s.createGroup))
	// Every signed-in user may list the visible groups, their own groups and
	// those of the accounts they may see, without their members.
	api.HandleFunc("GET /api/groups/visible", s.listVisibleGroups)
	// Every signed-in user may list the group folders: all of them for access
	// administrators, those of the groups they may list for everyone else.
	api.HandleFunc("GET /api/groups/paths", s.listGroupPaths)
	// Every signed-in user may request to join a visible group.
	api.HandleFunc("POST /api/groups/{pk}/join-requests", s.requestJoin)
	api.Handle("GET /api/groups/{pk}", s.requireAdmin(s.getGroup))
	api.Handle("PATCH /api/groups/{pk}", s.requireAdmin(s.updateGroup))
	api.Handle("GET /api/groups/{pk}/members", s.requireAdmin(s.listGroupMembers))
	api.Handle("PUT /api/groups/{pk}/members/{id}", s.requireAdmin(s.addGroupMember))
	api.Handle("DELETE /api/groups/{pk}/members/{id}", s.requireAdmin(s.removeGroupMember))
	// The operators managing a group decide the requests to join it; see joinrequests.go.
	api.HandleFunc("GET /api/join-requests", s.listJoinRequests)
	api.HandleFunc("GET /api/join-requests/mine", s.listMyJoinRequests)
	api.HandleFunc("POST /api/join-requests/{id}/approve", s.approveJoinRequest)
	api.HandleFunc("POST /api/join-requests/{id}/reject", s.rejectJoinRequest)
	api.HandleFunc("DELETE /api/join-requests/{id}", s.withdrawJoinRequest)
	api.Handle("GET /api/audit", s.requireAdmin(s.listAudit))
	api.HandleFunc("GET /api/users", s.listAccounts(userAccounts))
	api.HandleFunc("POST /api/users", s.createAccount(userAccounts))
	api.HandleFunc("GET /api/users/paths", s.listAccountPaths(userAccounts))
	api.HandleFunc("GET /api/users/{id}", s.getAccount(userAccounts))
	api.HandleFunc("PATCH /api/users/{id}", s.updateAccount(userAccounts))
	api.Handle("DELETE /api/users/{id}", s.requireAdmin(s.deleteAccount(userAccounts)))
	api.HandleFunc("PUT /api/users/{id}/groups", s.setAccountGroups(userAccounts))
	api.HandleFunc("POST /api/users/{id}/recovery-email", s.sendRecoveryEmail)
	// Operators who may see a user may list the applications the user may access.
	api.HandleFunc("GET /api/users/{id}/applications", s.listUserApplications)
	// Service accounts follow the access rules of users; see serviceaccounts.go.
	api.HandleFunc("GET /api/service-accounts", s.listAccounts(serviceAccounts))
	api.HandleFunc("POST /api/service-accounts", s.createAccount(serviceAccounts))
	api.HandleFunc("GET /api/service-accounts/paths", s.listAccountPaths(serviceAccounts))
	api.HandleFunc("GET /api/service-accounts/{id}", s.getAccount(serviceAccounts))
	api.HandleFunc("PATCH /api/service-accounts/{id}", s.updateAccount(serviceAccounts))
	api.Handle("DELETE /api/service-accounts/{id}", s.requireAdmin(s.deleteAccount(serviceAccounts)))
	api.HandleFunc("PUT /api/service-accounts/{id}/groups", s.setAccountGroups(serviceAccounts))
	api.HandleFunc("GET /api/service-accounts/{id}/tokens", s.listServiceAccountTokens)
	api.HandleFunc("POST /api/service-accounts/{id}/tokens", s.createServiceAccountToken)
	api.HandleFunc("DELETE /api/service-accounts/{id}/tokens/{identifier}", s.deleteServiceAccountToken)
	// Users issue certificates for their own account only and download the
	// generated key once; see certificates.go. Operators who may change a
	// user may list and revoke the user's certificates.
	api.Handle("GET /api/certificates/mine", s.requireCertificates(s.listMyCertificates))
	api.Handle("POST /api/certificates/mine", s.requireCertificates(s.issueCertificate))
	api.Handle("GET /api/certificates/mine/{serial}/download", s.requireCertificates(s.downloadCertificateKey))
	api.Handle("GET /api/users/{id}/certificates", s.requireCertificates(s.listUserCertificates))
	api.Handle("POST /api/users/{id}/certificates/{serial}/revoke",
		s.requireCertificates(s.revokeAccountCertificate(userAccounts)))
	// Operators who may change a service account also issue its certificates.
	api.Handle("GET /api/service-accounts/{id}/certificates", s.requireCertificates(s.listServiceAccountCertificates))
	api.Handle("POST /api/service-accounts/{id}/certificates", s.requireCertificates(s.issueServiceAccountCertificate))
	api.Handle("POST /api/service-accounts/{id}/certificates/{serial}/revoke",
		s.requireCertificates(s.revokeAccountCertificate(serviceAccounts)))
	// Access administrators may list, download and revoke the certificates of
	// all users, including deleted ones; see certificates.go.
	api.Handle("GET /api/certificates", s.requireCertificates(s.requireAdmin(s.listCertificates).ServeHTTP))
	api.Handle("GET /api/certificates/{serial}/pem", s.requireCertificates(s.requireAdmin(s.downloadCertificate).ServeHTTP))
	api.Handle("POST /api/certificates/{serial}/revoke", s.requireCertificates(s.requireAdmin(s.revokeAnyCertificate).ServeHTTP))
	// Access administrators may import certificates the CA signed elsewhere, so they can be revoked.
	api.Handle("POST /api/certificates/import", s.requireCertificates(s.requireAdmin(s.importCertificates).ServeHTTP))
	// They may assign an imported certificate to its account once the account exists.
	api.Handle("POST /api/certificates/{serial}/assign", s.requireCertificates(s.requireAdmin(s.assignCertificate).ServeHTTP))
	// Every signed-in internal user reads their own notifications and chooses
	// which ones they receive; see notifications.go.
	api.Handle("GET /api/notifications", s.requireNotifications(s.listNotifications))
	api.Handle("DELETE /api/notifications", s.requireNotifications(s.deleteAllNotifications))
	api.Handle("GET /api/notifications/unread-count", s.requireNotifications(s.countUnreadNotifications))
	api.Handle("POST /api/notifications/read-all", s.requireNotifications(s.markAllNotificationsRead))
	api.Handle("POST /api/notifications/{id}/read", s.requireNotifications(s.markNotificationRead))
	api.Handle("DELETE /api/notifications/{id}", s.requireNotifications(s.deleteNotification))
	api.Handle("GET /api/notifications/preferences", s.requireNotifications(s.getNotificationPreferences))
	api.Handle("PUT /api/notifications/preferences", s.requireNotifications(s.putNotificationPreferences))
	api.HandleFunc("GET /api/version", getVersion)
	api.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found", nil)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/auth/", d.Auth.Handler())
	// The CRL and the CA certificate are public, for relying parties.
	mux.Handle("GET /pki/crl", s.requireCertificates(s.getCRL))
	mux.Handle("GET /pki/crl.pem", s.requireCertificates(s.getCRLPEM))
	mux.Handle("GET /pki/ca.pem", s.requireCertificates(s.getCAChain))
	mux.Handle("/api/", d.Auth.Require(api))
	if d.Static != nil {
		mux.Handle("/", s.spaHandler(d.Static))
	}

	// Rejects cross-origin state-changing browser requests (CSRF), on top of SameSite cookies.
	s.handler = http.NewCrossOriginProtection().Handler(mux)
	return s
}

// ServeHTTP adds security headers and request logging around the router.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", contentSecurityPolicy(""))

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	s.handler.ServeHTTP(rec, r)

	s.logger.LogAttrs(r.Context(), slog.LevelInfo, "http request",
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", rec.status),
		slog.Duration("duration", time.Since(start)),
	)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// actorName returns the username of the logged-in operator.
func actorName(r *http.Request) string {
	u, _ := auth.UserFromContext(r.Context())
	return u.Username
}

// operatorGroups returns the groups of the logged-in operator.
func operatorGroups(r *http.Request) []string {
	u, _ := auth.UserFromContext(r.Context())
	return u.Groups
}

// scope returns the users the logged-in operator may manage. Without an
// operator in the context it grants nothing. It writes a 500 response and
// returns false when the rules cannot be loaded.
func (s *Server) scope(w http.ResponseWriter, r *http.Request) (access.Scope, bool) {
	scope, err := s.policy.ScopeFor(r.Context(), operatorGroups(r))
	if err != nil {
		s.logger.ErrorContext(r.Context(), "resolving access scope", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "access check failed", nil)
		return access.Scope{}, false
	}
	return scope, true
}

func (s *Server) getAccess(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, struct {
		access.Scope
		// Admin is set when the operator may edit the access rules and delete users.
		Admin bool `json:"admin"`
		// RecoveryEmail is set when password recovery emails can be sent.
		RecoveryEmail bool `json:"recovery_email"`
		// Certificates is set when users can issue certificates.
		Certificates bool `json:"certificates"`
		// CertificateCNSuffixes are the suffixes appended to usernames in the
		// common names of issued certificates, longest first.
		CertificateCNSuffixes []string `json:"certificate_cn_suffixes"`
		// CertificateUserCNSuffix is the suffix of user certificates alone,
		// for previewing their common name.
		CertificateUserCNSuffix string `json:"certificate_user_cn_suffix"`
	}{
		Scope:                   scope,
		Admin:                   s.policy.IsAdmin(operatorGroups(r)),
		RecoveryEmail:           s.recoveryEmailStage != "",
		Certificates:            s.ca != nil,
		CertificateCNSuffixes:   s.certificateCNSuffixes(),
		CertificateUserCNSuffix: s.certificateUserCNSuffix(),
	})
}

// certificateCNSuffixes returns the CA's common name suffixes, none when
// certificates are disabled.
func (s *Server) certificateCNSuffixes() []string {
	if s.ca == nil {
		return []string{}
	}
	return s.ca.CNSuffixes()
}

// certificateUserCNSuffix returns the CA's user common name suffix, empty
// when certificates are disabled.
func (s *Server) certificateUserCNSuffix() string {
	if s.ca == nil {
		return ""
	}
	return s.ca.UserCNSuffix()
}

// getVersion reports the repository, commit and tag the server was built from.
func getVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, buildinfo.Get())
}

// requireAdmin restricts h to access administrators, who may edit the access
// rules and the groups, delete users and read the audit log.
func (s *Server) requireAdmin(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.policy.IsAdmin(operatorGroups(r)) {
			writeError(w, http.StatusForbidden, "only access administrators may do this", nil)
			return
		}
		h(w, r)
	})
}

// spaHandler serves files from static and falls back to index.html for unknown paths.
func (s *Server) spaHandler(static fs.FS) http.Handler {
	files := http.FileServerFS(static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[1:]
		if name != "" && name != "index.html" && fs.ValidPath(name) {
			if _, err := fs.Stat(static, name); err == nil {
				files.ServeHTTP(w, r)
				return
			}
		}
		s.serveIndex(w, r, static)
	})
}

// serveIndex serves index.html with a per-request CSP nonce in place of
// cspNoncePlaceholder, and allows that nonce in the style-src directive.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request, static fs.FS) {
	page, err := fs.ReadFile(static, "index.html")
	if err != nil {
		s.logger.ErrorContext(r.Context(), "reading index.html", slog.Any("error", err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	nonce := rand.Text()
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy(nonce))
	h.Set("Content-Type", "text/html; charset=utf-8")
	// The nonce must not be reused, so the page must not be cached.
	h.Set("Cache-Control", "no-store")
	// The status line is already sent; a write error here means the client went away.
	_, _ = w.Write(bytes.ReplaceAll(page, []byte(cspNoncePlaceholder), []byte(nonce)))
}

// OpenStatic opens dir as a traversal-safe filesystem for New.
func OpenStatic(dir string) (fs.FS, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("opening static dir: %w", err)
	}
	return root.FS(), nil
}

type errorBody struct {
	Error  string              `json:"error"`
	Fields map[string][]string `json:"fields,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status line is already sent; an encode error here means the client went away.
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string, fields map[string][]string) {
	writeJSON(w, status, errorBody{Error: msg, Fields: fields})
}

// writeUpstreamError translates an authentik client error into a response.
// Validation errors are passed through so the UI can show them per field;
// everything else is logged and reported generically.
func (s *Server) writeUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, authentik.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found", nil)
		return
	}
	if apiErr, ok := errors.AsType[*authentik.APIError](err); ok && apiErr.StatusCode == http.StatusBadRequest {
		msg := apiErr.Detail
		if msg == "" {
			msg = "validation failed"
		}
		writeError(w, http.StatusBadRequest, msg, apiErr.Fields)
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	s.logger.ErrorContext(r.Context(), "authentik request failed",
		slog.String("path", r.URL.Path),
		slog.Any("error", err),
	)
	writeError(w, http.StatusBadGateway, "authentik request failed", nil)
}
