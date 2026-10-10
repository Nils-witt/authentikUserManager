// Package server exposes the user management REST API consumed by the frontend
// and optionally serves the built frontend itself.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"authentikManager/internal/access"
	"authentikManager/internal/auth"
	"authentikManager/internal/authentik"
)

// maxRequestBytes bounds JSON request bodies.
const maxRequestBytes = 1 << 20

// UserService is the subset of the authentik client the handlers depend on.
type UserService interface {
	ListUsers(ctx context.Context, p authentik.ListUsersParams) (*authentik.UserList, error)
	ListUserPaths(ctx context.Context) ([]string, error)
	GetUser(ctx context.Context, id int) (*authentik.User, error)
	CreateUser(ctx context.Context, req authentik.CreateUserRequest) (*authentik.User, error)
	UpdateUser(ctx context.Context, id int, req authentik.UpdateUserRequest) (*authentik.User, error)
	DeleteUser(ctx context.Context, id int) error
	FindGroup(ctx context.Context, name string) (*authentik.Group, error)
	AddUserToGroup(ctx context.Context, groupPK string, userID int) error
	RemoveUserFromGroup(ctx context.Context, groupPK string, userID int) error
	SendRecoveryEmail(ctx context.Context, id int, emailStage string) error
	ListGroups(ctx context.Context, search string) ([]authentik.Group, error)
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
}

// Deps are the collaborators of the Server.
type Deps struct {
	Users  UserService
	Auth   Authenticator
	Policy Policy
	Rules  RuleStore
	Logger *slog.Logger
	// Static, when non-nil, is the built frontend.
	Static fs.FS
	// RecoveryEmailStage is the UUID of the email stage that sends password
	// recovery emails. When empty, sending them is disabled.
	RecoveryEmailStage string
}

// Server is the HTTP handler for the application.
type Server struct {
	users  UserService
	policy Policy
	rules  RuleStore
	logger *slog.Logger
	// recoveryEmailStage is the email stage for recovery emails; empty disables them.
	recoveryEmailStage string
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
		logger:             d.Logger,
		recoveryEmailStage: d.RecoveryEmailStage,
	}

	api := http.NewServeMux()
	api.HandleFunc("GET /api/access", s.getAccess)
	api.Handle("GET /api/access/rules", s.requireAdmin(s.listRules))
	api.Handle("PUT /api/access/rules/{group}", s.requireAdmin(s.putRule))
	api.Handle("DELETE /api/access/rules/{group}", s.requireAdmin(s.deleteRule))
	api.Handle("GET /api/groups", s.requireAdmin(s.listGroups))
	api.HandleFunc("GET /api/users", s.listUsers)
	api.HandleFunc("POST /api/users", s.createUser)
	api.HandleFunc("GET /api/users/paths", s.listUserPaths)
	api.HandleFunc("GET /api/users/{id}", s.getUser)
	api.HandleFunc("PATCH /api/users/{id}", s.updateUser)
	api.Handle("DELETE /api/users/{id}", s.requireAdmin(s.deleteUser))
	api.HandleFunc("PUT /api/users/{id}/groups", s.setUserGroups)
	api.HandleFunc("POST /api/users/{id}/recovery-email", s.sendRecoveryEmail)
	api.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found", nil)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/auth/", d.Auth.Handler())
	mux.Handle("/api/", d.Auth.Require(api))
	if d.Static != nil {
		mux.Handle("/", spaHandler(d.Static))
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
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' https: data:; frame-ancestors 'none'")

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

// audit logs a successful change together with the logged-in user.
func (s *Server) audit(r *http.Request, msg string, attrs ...slog.Attr) {
	attrs = append(attrs, slog.String("actor", actorName(r)))
	s.logger.LogAttrs(r.Context(), slog.LevelInfo, msg, attrs...)
}

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
	}{
		Scope:         scope,
		Admin:         s.policy.IsAdmin(operatorGroups(r)),
		RecoveryEmail: s.recoveryEmailStage != "",
	})
}

// requireAdmin restricts h to access administrators, who may edit the access rules and delete users.
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
func spaHandler(static fs.FS) http.Handler {
	files := http.FileServerFS(static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[1:]
		if name != "" && fs.ValidPath(name) {
			if _, err := fs.Stat(static, name); err == nil {
				files.ServeHTTP(w, r)
				return
			}
		}
		http.ServeFileFS(w, r, static, "index.html")
	})
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
