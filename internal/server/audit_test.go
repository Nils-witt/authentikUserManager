package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"
	"testing"

	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// fakeAudit is an in-memory audit log. Each test uses its own instance.
type fakeAudit struct {
	// recorded are the entries passed to RecordAudit.
	recorded []audit.Entry
	// listed are returned by ListAudit, limited to the query's limit.
	listed []audit.Entry
	// query records the query passed to ListAudit.
	query audit.Query
	err   error
}

func (f *fakeAudit) RecordAudit(_ context.Context, e audit.Entry) error {
	if f.err != nil {
		return f.err
	}
	f.recorded = append(f.recorded, e)
	return nil
}

func (f *fakeAudit) ListAudit(_ context.Context, q audit.Query) ([]audit.Entry, error) {
	f.query = q
	if f.err != nil {
		return nil, f.err
	}
	return f.listed[:min(q.Limit, len(f.listed))], nil
}

// adminAuth is an access administrator named "admin".
var adminAuth = fakeAuth{groups: []string{"admins"}}

func TestServer_listAudit_requireAdmin(t *testing.T) {
	t.Parallel()
	log := &fakeAudit{}
	h := newAuditedServer(t, &fakeUsers{}, newFakeRules(), log, fakeAuth{groups: []string{"superhelp"}})
	rec := do(t, h, http.MethodGet, "/api/audit", "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestServer_listAudit(t *testing.T) {
	t.Parallel()
	log := &fakeAudit{listed: []audit.Entry{
		{ID: 7, Actor: "admin", Action: audit.ActionUserDeleted, Target: "bob", Details: map[string]string{}},
		{ID: 5, Actor: "admin", Action: audit.ActionUserCreated, Target: "ann", Details: map[string]string{}},
		{ID: 2, Actor: "eve", Action: audit.ActionUserUpdated, Target: "ann", Details: map[string]string{}},
	}}
	h := newAuditedServer(t, &fakeUsers{}, newFakeRules(), log, adminAuth)

	rec := do(t, h, http.MethodGet, "/api/audit?search=+ann+&action=user.created&before=9&limit=2", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	expected := audit.Query{Search: "ann", Action: audit.ActionUserCreated, Before: 9, Limit: 3}
	if log.query != expected {
		t.Errorf("query = %+v, want %+v (one more than the limit)", log.query, expected)
	}
	var page struct {
		Entries []audit.Entry `json:"entries"`
		Next    int64         `json:"next"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 || page.Entries[1].ID != 5 || page.Next != 5 {
		t.Errorf("page = %+v, want the first two entries and next 5", page)
	}

	// The last page has no next cursor.
	rec = do(t, h, http.MethodGet, "/api/audit", "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"next"`) {
		t.Errorf("last page = %d %s, want 200 without next", rec.Code, rec.Body)
	}
	if log.query.Limit != audit.DefaultLimit+1 {
		t.Errorf("default limit = %d, want %d", log.query.Limit, audit.DefaultLimit+1)
	}
}

func TestServer_listAudit_empty(t *testing.T) {
	t.Parallel()
	h := newAuditedServer(t, &fakeUsers{}, newFakeRules(), &fakeAudit{}, adminAuth)
	rec := do(t, h, http.MethodGet, "/api/audit", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"entries":[]`) {
		t.Errorf("GET /api/audit = %d %s, want an empty list", rec.Code, rec.Body)
	}
}

func TestServer_listAudit_validation(t *testing.T) {
	t.Parallel()
	for _, query := range []string{
		"before=0",
		"before=x",
		"limit=0",
		"limit=201",
		"limit=x",
		"action=user.hacked",
		"search=" + strings.Repeat("a", 256),
	} {
		t.Run(query, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(t, &fakeUsers{}), http.MethodGet, "/api/audit?"+query, "")
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body %s)", rec.Code, rec.Body)
			}
		})
	}
}

func TestServer_listAudit_storeError(t *testing.T) {
	t.Parallel()
	log := &fakeAudit{err: errors.New("connection refused")}
	rec := do(t, newAuditedServer(t, &fakeUsers{}, newFakeRules(), log, adminAuth), http.MethodGet, "/api/audit", "")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("status = %d body %s, want generic 500", rec.Code, rec.Body)
	}
}

func TestServer_records(t *testing.T) {
	t.Parallel()
	groups := map[string]authentik.Group{"students": {PK: "pk-students", Name: "students"}}
	tests := []struct {
		name     string
		operator string
		method   string
		target   string
		body     string
		expected []audit.Entry
	}{
		{
			name:     "create user",
			operator: "helpdesk",
			method:   http.MethodPost,
			target:   "/api/users",
			body:     `{"username":"new","name":"New","group":"students"}`,
			expected: []audit.Entry{{
				Action: audit.ActionUserCreated, Target: "new",
				Details: map[string]string{"user_id": "9", "group": "students"},
			}},
		},
		{
			name:     "update user",
			operator: "helpdesk",
			method:   http.MethodPatch,
			target:   "/api/users/4",
			body:     `{"name":"X","is_active":false}`,
			expected: []audit.Entry{{
				Action:  audit.ActionUserUpdated,
				Details: map[string]string{"user_id": "4", "fields": "name,is_active", "is_active": "false"},
			}},
		},
		{
			name:     "change groups",
			operator: "helpdesk",
			method:   http.MethodPut,
			target:   "/api/users/4/groups",
			body:     `{"groups":["students"]}`,
			expected: []audit.Entry{
				{Action: audit.ActionUserGroupAdded, Target: "target", Details: map[string]string{"user_id": "4", "group": "students"}},
				{Action: audit.ActionUserGroupRemoved, Target: "target", Details: map[string]string{"user_id": "4", "group": "staff"}},
			},
		},
		{
			name:     "delete user",
			operator: "admins",
			method:   http.MethodDelete,
			target:   "/api/users/4",
			expected: []audit.Entry{{Action: audit.ActionUserDeleted, Target: "target", Details: map[string]string{"user_id": "4"}}},
		},
		{
			name:     "send recovery email",
			operator: "helpdesk",
			method:   http.MethodPost,
			target:   "/api/users/4/recovery-email",
			expected: []audit.Entry{{Action: audit.ActionRecoveryEmailSent, Target: "target", Details: map[string]string{"user_id": "4"}}},
		},
		{
			name:     "access denied",
			operator: "teachers",
			method:   http.MethodGet,
			target:   "/api/users/4",
			expected: []audit.Entry{{Action: audit.ActionAccessDenied, Target: "target", Details: map[string]string{"user_id": "4"}}},
		},
		{
			name:     "save rule",
			operator: "admins",
			method:   http.MethodPut,
			target:   "/api/access/rules/teachers",
			body:     `{"target_groups":["students","staff"]}`,
			expected: []audit.Entry{{
				Action: audit.ActionRuleSaved, Target: "teachers",
				Details: map[string]string{"target_groups": "staff,students"},
			}},
		},
		{
			name:     "delete rule",
			operator: "admins",
			method:   http.MethodDelete,
			target:   "/api/access/rules/helpdesk",
			expected: []audit.Entry{{Action: audit.ActionRuleDeleted, Target: "helpdesk"}},
		},
		{name: "read user", operator: "helpdesk", method: http.MethodGet, target: "/api/users/4"},
		{name: "rejected change", operator: "helpdesk", method: http.MethodPatch, target: "/api/users/4", body: `{"type":"external"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			log := &fakeAudit{}
			fake := &fakeUsers{user: member("staff"), groups: groups}
			h := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: []string{tt.operator}})
			do(t, h, tt.method, tt.target, tt.body)
			if len(log.recorded) != len(tt.expected) {
				t.Fatalf("recorded %+v, want %+v", log.recorded, tt.expected)
			}
			for i, got := range log.recorded {
				want := tt.expected[i]
				sameDetails := maps.Equal(got.Details, want.Details) || len(got.Details)+len(want.Details) == 0
				if got.Actor != "admin" || got.Action != want.Action || got.Target != want.Target || !sameDetails {
					t.Errorf("entry %d = %+v, want %+v by admin", i, got, want)
				}
			}
		})
	}
}

func TestServer_records_failureDoesNotFailRequest(t *testing.T) {
	t.Parallel()
	log := &fakeAudit{err: errors.New("connection refused")}
	fake := &fakeUsers{user: member("staff")}
	rec := do(t, newAuditedServer(t, fake, newFakeRules(), log, adminAuth), http.MethodDelete, "/api/users/4", "")
	if rec.Code != http.StatusNoContent || !fake.mutated {
		t.Errorf("status = %d, mutated = %v, want 204 after deleting", rec.Code, fake.mutated)
	}
}
