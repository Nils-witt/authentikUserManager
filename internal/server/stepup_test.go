package server_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"authentikManager/internal/access"
	"authentikManager/internal/server"
)

// newStepUpServer returns a server for an access administrator authenticated
// as authn describes, requiring a login within 15 minutes for critical changes.
func newStepUpServer(t *testing.T, users *fakeUsers, authn fakeAuth) (*server.Server, *fakeRules) {
	t.Helper()
	rules := newFakeRules()
	policy, err := access.NewPolicy([]string{"admins"}, rules)
	if err != nil {
		t.Fatal(err)
	}
	authn.groups = []string{"admins"}
	return server.New(server.Deps{
		Users:  users,
		Auth:   authn,
		Policy: policy,
		Rules:  rules,
		Audit:  &fakeAudit{},
		Logger: slog.New(slog.DiscardHandler),

		RecoveryEmailStage: testRecoveryStage,
		ReauthMaxAge:       15 * time.Minute,
	}), rules
}

func TestServer_requireRecentAuth(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		authn   fakeAuth
		wantOK  bool
		wantMsg string
	}{
		{name: "recent login", authn: fakeAuth{authTime: time.Now().Add(-time.Minute)}, wantOK: true},
		{name: "old login", authn: fakeAuth{authTime: time.Now().Add(-time.Hour)}, wantMsg: "Confirm this change by signing in again."},
		{name: "unknown login time", authn: fakeAuth{}, wantMsg: "Confirm this change by signing in again."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv, rules := newStepUpServer(t, &fakeUsers{}, tt.authn)
			rec := do(t, srv, http.MethodDelete, "/api/access/rules/helpdesk", "")
			_, kept := rules.rules["helpdesk"]
			if tt.wantOK {
				if rec.Code != http.StatusNoContent || kept {
					t.Errorf("delete = %d %s, rule kept %v, want it deleted", rec.Code, rec.Body, kept)
				}
				return
			}
			var body struct {
				Error          string `json:"error"`
				Reauthenticate bool   `json:"reauthenticate"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusForbidden || !body.Reauthenticate || body.Error != tt.wantMsg || !kept {
				t.Errorf("delete = %d %s, rule kept %v, want 403 asking to sign in again", rec.Code, rec.Body, kept)
			}
		})
	}
}

func TestServer_requireRecentAuth_routes(t *testing.T) {
	t.Parallel()
	srv, _ := newStepUpServer(t, &fakeUsers{}, fakeAuth{authTime: time.Now().Add(-time.Hour)})
	critical := []struct{ method, target string }{
		{http.MethodPut, "/api/access/rules/helpdesk"},
		{http.MethodDelete, "/api/access/rules/helpdesk"},
		{http.MethodDelete, "/api/users/4"},
		{http.MethodPost, "/api/users/4/recovery-email"},
		{http.MethodDelete, "/api/service-accounts/4"},
		{http.MethodPost, "/api/service-accounts/4/tokens"},
	}
	for _, c := range critical {
		if rec := do(t, srv, c.method, c.target, "{}"); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", c.method, c.target, rec.Code)
		}
	}
	// Everyday changes need no recent login.
	if rec := do(t, srv, http.MethodGet, "/api/users", ""); rec.Code != http.StatusOK {
		t.Errorf("GET /api/users = %d, want 200", rec.Code)
	}
}
