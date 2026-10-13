package server_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// serviceAccount returns a service account named svc in the named groups.
func serviceAccount(groups ...string) *authentik.User {
	u := member(groups...)
	u.Username, u.Email, u.Type, u.IsActive = "svc", "", authentik.UserTypeServiceAccount, true
	return u
}

func listedUsernames(t *testing.T, body []byte) []string {
	t.Helper()
	var out struct {
		Results []authentik.User `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, u := range out.Results {
		names = append(names, u.Username)
	}
	return names
}

func TestServiceAccounts_list(t *testing.T) {
	t.Parallel()
	listed := []authentik.User{
		{PK: 1, Username: "svc-staff", Type: authentik.UserTypeServiceAccount, Groups: []authentik.UserGroup{{PK: "pk-staff", Name: "staff"}}},
		{PK: 2, Username: "svc-other", Type: authentik.UserTypeServiceAccount, Groups: []authentik.UserGroup{{PK: "pk-other", Name: "other"}}},
		{PK: 3, Username: "ann", Type: authentik.UserTypeInternal, Groups: []authentik.UserGroup{{PK: "pk-staff", Name: "staff"}}},
		{PK: 4, Username: "outpost", Type: authentik.UserTypeInternalServiceAccount},
	}
	tests := []struct {
		name     string
		groups   []string
		expected []string
		calls    int
	}{
		{name: "access administrator", groups: []string{"admins"}, expected: []string{"svc-staff", "svc-other"}, calls: 1},
		{name: "restricted operator", groups: []string{"helpdesk"}, expected: []string{"svc-staff"}, calls: 1},
		{name: "operator without rules", groups: []string{"nobody"}, expected: []string{}, calls: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{listed: listed}
			rec := do(t, newScopedServer(t, fake, tt.groups...), http.MethodGet, "/api/service-accounts?search=svc", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
			}
			if got := listedUsernames(t, rec.Body.Bytes()); !slices.Equal(got, tt.expected) {
				t.Errorf("listed = %v, want %v", got, tt.expected)
			}
			// Service accounts never sign in, so the operator's own account is not looked up.
			if len(fake.listCalls) != tt.calls {
				t.Fatalf("ListUsers calls = %+v, want %d", fake.listCalls, tt.calls)
			}
			if tt.calls > 0 && !slices.Equal(fake.listParams.Type, []authentik.UserType{authentik.UserTypeServiceAccount}) {
				t.Errorf("type filter = %v, want service accounts", fake.listParams.Type)
			}
		})
	}
}

func TestServiceAccounts_get(t *testing.T) {
	t.Parallel()
	outpost := member("staff")
	outpost.Type = authentik.UserTypeInternalServiceAccount
	tests := []struct {
		name     string
		user     *authentik.User
		target   string
		expected int
	}{
		{name: "service account in scope", user: serviceAccount("staff"), target: "/api/service-accounts/5", expected: http.StatusOK},
		{name: "service account outside scope", user: serviceAccount("other"), target: "/api/service-accounts/5", expected: http.StatusNotFound},
		{name: "internal user", user: member("staff"), target: "/api/service-accounts/5", expected: http.StatusNotFound},
		{name: "internal service account", user: outpost, target: "/api/service-accounts/5", expected: http.StatusNotFound},
		{name: "service account through users", user: serviceAccount("staff"), target: "/api/users/5", expected: http.StatusNotFound},
		{
			name:     "service account certificates through users",
			user:     serviceAccount("staff"),
			target:   "/api/users/5/certificates",
			expected: http.StatusNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, &fakeUsers{user: tt.user}, "helpdesk")
			if rec := do(t, env.srv, http.MethodGet, tt.target, ""); rec.Code != tt.expected {
				t.Errorf("GET %s = %d, want %d; body %s", tt.target, rec.Code, tt.expected, rec.Body)
			}
		})
	}
}

func TestServiceAccounts_create(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		body     string
		expected int
		field    string
	}{
		{name: "group required", body: `{"username":"svc","name":"Backup"}`, expected: http.StatusBadRequest, field: "group"},
		{name: "group outside scope", body: `{"username":"svc","name":"Backup","group":"other"}`, expected: http.StatusBadRequest, field: "group"},
		{
			name:     "another type",
			body:     `{"username":"svc","name":"Backup","group":"staff","type":"internal"}`,
			expected: http.StatusBadRequest,
			field:    "type",
		},
		{name: "valid", body: `{"username":"svc","name":"Backup","group":"staff","path":"services"}`, expected: http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{groups: testGroups()}
			log := &fakeAudit{}
			srv := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: []string{"helpdesk"}})
			rec := do(t, srv, http.MethodPost, "/api/service-accounts", tt.body)
			if rec.Code != tt.expected {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.expected, rec.Body)
			}
			if tt.field != "" {
				if !strings.Contains(rec.Body.String(), `"`+tt.field+`"`) {
					t.Errorf("body = %s, want an error for %q", rec.Body, tt.field)
				}
				return
			}
			c := fake.created
			if c.Type != authentik.UserTypeServiceAccount || !slices.Equal(c.Groups, []string{"g1"}) ||
				c.Attributes[primaryGroupAttribute] != "g1" || c.Path != "services" {
				t.Errorf("created = %+v, want a service account in staff with staff as primary group", c)
			}
			if len(log.recorded) != 1 || log.recorded[0].Action != audit.ActionServiceAccountCreated ||
				log.recorded[0].Details["type"] != "service_account" {
				t.Errorf("audit = %+v, want a service account creation", log.recorded)
			}
		})
	}
}

func TestServiceAccounts_update(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		user     *authentik.User
		body     string
		expected int
	}{
		{name: "deactivate", user: serviceAccount("staff"), body: `{"is_active":false}`, expected: http.StatusOK},
		{name: "change type", user: serviceAccount("staff"), body: `{"type":"internal"}`, expected: http.StatusBadRequest},
		{
			name:     "primary group outside scope",
			user:     withPrimary(serviceAccount("staff", "other"), "other"),
			body:     `{"name":"Renamed"}`,
			expected: http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: tt.user}
			log := &fakeAudit{}
			srv := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: []string{"helpdesk"}})
			rec := do(t, srv, http.MethodPatch, "/api/service-accounts/5", tt.body)
			if rec.Code != tt.expected {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.expected, rec.Body)
			}
			if tt.expected != http.StatusOK {
				if fake.mutated {
					t.Error("the service account was changed")
				}
				return
			}
			if !slices.Contains(actions(log), audit.ActionServiceAccountUpdated) {
				t.Errorf("audit = %v, want a service account update", actions(log))
			}
		})
	}
}

func TestServiceAccounts_delete(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		groups   []string
		expected int
	}{
		{name: "restricted operator", groups: []string{"helpdesk"}, expected: http.StatusForbidden},
		{name: "access administrator", groups: []string{"admins"}, expected: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: serviceAccount("staff")}
			log := &fakeAudit{}
			srv := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: tt.groups})
			rec := do(t, srv, http.MethodDelete, "/api/service-accounts/5", "")
			if rec.Code != tt.expected {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.expected, rec.Body)
			}
			deleted := slices.Contains(actions(log), audit.ActionServiceAccountDeleted)
			if deleted != (tt.expected == http.StatusNoContent) || fake.mutated != deleted {
				t.Errorf("audit = %v, mutated = %v", actions(log), fake.mutated)
			}
		})
	}
}

func TestServiceAccounts_listTokens(t *testing.T) {
	t.Parallel()
	fake := &fakeUsers{
		user: serviceAccount("staff"),
		tokens: []authentik.Token{
			{Identifier: "mine", Intent: authentik.TokenIntentAPI, UserPK: 5},
			{Identifier: "theirs", Intent: authentik.TokenIntentAPI, UserPK: 6},
		},
	}
	rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodGet, "/api/service-accounts/5/tokens", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"mine"`) || strings.Contains(rec.Body.String(), `"theirs"`) {
		t.Errorf("tokens = %d %s, want the service account's token only", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "key") {
		t.Errorf("tokens = %s, want no keys", rec.Body)
	}
}

func TestServiceAccounts_createToken(t *testing.T) {
	t.Parallel()
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	inactive := serviceAccount("staff")
	inactive.IsActive = false
	tests := []struct {
		name        string
		user        *authentik.User
		body        string
		tokenOwner  int
		tokenKeyErr error
		expected    int
		discarded   bool
	}{
		{name: "invalid intent", user: serviceAccount("staff"), body: `{"intent":"recovery"}`, expected: http.StatusBadRequest},
		{name: "expired", user: serviceAccount("staff"), body: `{"intent":"api","expires":"` + past + `"}`, expected: http.StatusBadRequest},
		{name: "inactive account", user: inactive, body: `{"intent":"api"}`, expected: http.StatusConflict},
		{name: "outside scope", user: serviceAccount("other"), body: `{"intent":"api"}`, expected: http.StatusNotFound},
		{
			name:       "assigned to another user",
			user:       serviceAccount("staff"),
			body:       `{"intent":"api"}`,
			tokenOwner: 1,
			expected:   http.StatusBadGateway,
			discarded:  true,
		},
		{
			name:        "key unavailable",
			user:        serviceAccount("staff"),
			body:        `{"intent":"api"}`,
			tokenKeyErr: errors.New("forbidden"),
			expected:    http.StatusBadGateway,
			discarded:   true,
		},
		{
			name:     "valid",
			user:     serviceAccount("staff"),
			body:     `{"intent":"app_password","description":" backups ","expires":"` + future + `"}`,
			expected: http.StatusCreated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: tt.user, tokenOwner: tt.tokenOwner, tokenKeyErr: tt.tokenKeyErr}
			log := &fakeAudit{}
			srv := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: []string{"helpdesk"}})
			rec := do(t, srv, http.MethodPost, "/api/service-accounts/5/tokens", tt.body)
			if rec.Code != tt.expected {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.expected, rec.Body)
			}
			if tt.discarded {
				if !slices.Equal(fake.deletedTokens, []string{fake.createdToken.Identifier}) || strings.Contains(rec.Body.String(), "s3cret") {
					t.Errorf("deleted = %v, body %s, want the created token deleted and no key", fake.deletedTokens, rec.Body)
				}
				return
			}
			if tt.expected != http.StatusCreated {
				if fake.mutated {
					t.Error("a token was created")
				}
				return
			}
			checkCreatedToken(t, fake, log, rec.Body.Bytes())
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

// checkCreatedToken checks the response and audit entry of a valid token creation for user 5.
func checkCreatedToken(t *testing.T, fake *fakeUsers, log *fakeAudit, body []byte) {
	t.Helper()
	req := fake.createdToken
	if req.UserPK != 5 || !strings.HasPrefix(req.Identifier, "am-5-") || req.Description != "backups" || !req.Expiring {
		t.Errorf("request = %+v", req)
	}
	var out struct {
		Token authentik.Token `json:"token"`
		Key   string          `json:"key"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Key != "s3cret-key" || out.Token.Identifier != req.Identifier {
		t.Errorf("response = %+v, want the token and its key", out)
	}
	if len(log.recorded) != 1 || log.recorded[0].Action != audit.ActionTokenCreated {
		t.Fatalf("audit = %+v, want a token creation", log.recorded)
	}
	for k, v := range log.recorded[0].Details {
		if strings.Contains(v, "s3cret") {
			t.Errorf("audit detail %s holds the key", k)
		}
	}
}

func TestServiceAccounts_deleteToken(t *testing.T) {
	t.Parallel()
	managed := "goauthentik.io/outpost"
	tokens := []authentik.Token{
		{Identifier: "mine", Intent: authentik.TokenIntentAPI, UserPK: 5},
		{Identifier: "theirs", Intent: authentik.TokenIntentAPI, UserPK: 6},
		{Identifier: "managed", Intent: authentik.TokenIntentAPI, UserPK: 5, Managed: &managed},
	}
	tests := []struct {
		name       string
		identifier string
		expected   int
	}{
		{name: "own token", identifier: "mine", expected: http.StatusNoContent},
		{name: "token of another user", identifier: "theirs", expected: http.StatusNotFound},
		{name: "unknown token", identifier: "unknown", expected: http.StatusNotFound},
		{name: "managed token", identifier: "managed", expected: http.StatusConflict},
		{name: "invalid identifier", identifier: "a.b", expected: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: serviceAccount("staff"), tokens: slices.Clone(tokens)}
			log := &fakeAudit{}
			srv := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: []string{"helpdesk"}})
			rec := do(t, srv, http.MethodDelete, "/api/service-accounts/5/tokens/"+tt.identifier, "")
			if rec.Code != tt.expected {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.expected, rec.Body)
			}
			deleted := tt.expected == http.StatusNoContent
			if deleted != (len(fake.deletedTokens) == 1) || deleted != slices.Contains(actions(log), audit.ActionTokenDeleted) {
				t.Errorf("deleted = %v, audit = %v", fake.deletedTokens, actions(log))
			}
		})
	}
}

func TestServiceAccounts_certificates(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")}, "helpdesk")

	rec := do(t, env.srv, http.MethodPost, "/api/service-accounts/5/certificates", `{"format":"pem"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue = %d %s", rec.Code, rec.Body)
	}
	var out issueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	c := out.Certificate
	if c.UserPK != 5 || c.Username != "svc" || c.IssuedBy != "admin" {
		t.Errorf("certificate = %+v, want one of svc issued by admin", c)
	}
	if !slices.Contains(actions(env.log), audit.ActionCertificateIssued) {
		t.Errorf("audit = %v, want an issued certificate", actions(env.log))
	}

	// The issuing operator, not the service account, downloads the key.
	rec = do(t, env.srv, http.MethodGet, "/api/service-accounts/5/certificates", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"downloadable":true`) {
		t.Errorf("list = %d %s, want the certificate downloadable", rec.Code, rec.Body)
	}
	if rec := do(t, env.srv, http.MethodGet, out.DownloadURL, ""); rec.Code != http.StatusOK {
		t.Errorf("download = %d %s", rec.Code, rec.Body)
	}

	rec = do(t, env.srv, http.MethodPost, "/api/service-accounts/5/certificates/"+c.Serial+"/revoke", "")
	if rec.Code != http.StatusOK || env.certs.certs[0].RevokedAt == nil {
		t.Errorf("revoke = %d %s", rec.Code, rec.Body)
	}
}

func TestServiceAccounts_certificatesRefused(t *testing.T) {
	t.Parallel()
	inactive := serviceAccount("staff")
	inactive.IsActive = false
	tests := []struct {
		name     string
		user     *authentik.User
		expected int
	}{
		{name: "inactive", user: inactive, expected: http.StatusConflict},
		{name: "outside scope", user: serviceAccount("other"), expected: http.StatusNotFound},
		{name: "primary group outside scope", user: withPrimary(serviceAccount("staff", "other"), "other"), expected: http.StatusForbidden},
		{name: "internal user", user: member("staff"), expected: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, &fakeUsers{user: tt.user}, "helpdesk")
			rec := do(t, env.srv, http.MethodPost, "/api/service-accounts/5/certificates", `{"format":"pem"}`)
			if rec.Code != tt.expected || len(env.certs.certs) != 0 {
				t.Errorf("issue = %d %s, want %d and no certificate", rec.Code, rec.Body, tt.expected)
			}
		})
	}
}
