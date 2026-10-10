package server_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestServer_rules_requireAdmin(t *testing.T) {
	t.Parallel()
	requests := []struct{ method, target, body string }{
		{http.MethodGet, "/api/access/rules", ""},
		{http.MethodPut, "/api/access/rules/helpdesk", `{"target_groups":["*"]}`},
		{http.MethodDelete, "/api/access/rules/helpdesk", ""},
		{http.MethodGet, "/api/groups", ""},
	}
	for _, req := range requests {
		t.Run(req.method+" "+req.target, func(t *testing.T) {
			t.Parallel()
			rules := newFakeRules()
			// Even a wildcard rule does not make an operator an access administrator.
			h := newTestServer(t, &fakeUsers{}, rules, fakeAuth{groups: []string{"superhelp"}})
			rec := do(t, h, req.method, req.target, req.body)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
			if !slices.Equal(rules.rules["helpdesk"], []string{"staff", "students"}) {
				t.Errorf("rules changed: %v", rules.rules)
			}
		})
	}
}

func TestServer_rules_crud(t *testing.T) {
	t.Parallel()
	rules := newFakeRules()
	h := newTestServer(t, &fakeUsers{}, rules, fakeAuth{groups: []string{"admins"}})

	rec := do(t, h, http.MethodGet, "/api/access/rules", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"operator_group":"helpdesk"`) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}

	// Group names may contain slashes and spaces when URL-encoded.
	rec = do(t, h, http.MethodPut, "/api/access/rules/team%2Fa%20b", `{"target_groups":["students"," staff","staff"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put = %d %s", rec.Code, rec.Body)
	}
	if got := rules.rules["team/a b"]; !slices.Equal(got, []string{"staff", "students"}) {
		t.Errorf("saved targets = %v, want normalized [staff students]", got)
	}

	rec = do(t, h, http.MethodDelete, "/api/access/rules/team%2Fa%20b", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if _, ok := rules.rules["team/a b"]; ok {
		t.Error("rule still present after delete")
	}

	rec = do(t, h, http.MethodDelete, "/api/access/rules/nope", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("delete missing = %d, want 404", rec.Code)
	}
}

func TestServer_putRule_validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "no targets", body: `{"target_groups":[]}`},
		{name: "empty target", body: `{"target_groups":[""]}`},
		{name: "unknown field", body: `{"target_groups":["staff"],"operator_group":"admins"}`},
		{name: "malformed", body: `{`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(t, &fakeUsers{}), http.MethodPut, "/api/access/rules/helpdesk", tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body %s)", rec.Code, rec.Body)
			}
		})
	}
}

func TestServer_storeErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		groups []string
		method string
		target string
		body   string
	}{
		{name: "list rules", groups: []string{"admins"}, method: http.MethodGet, target: "/api/access/rules"},
		{
			name:   "put rule",
			groups: []string{"admins"},
			method: http.MethodPut,
			target: "/api/access/rules/x",
			body:   `{"target_groups":["y"]}`,
		},
		{name: "scope for list", groups: []string{"helpdesk"}, method: http.MethodGet, target: "/api/users"},
		{name: "scope for user", groups: []string{"helpdesk"}, method: http.MethodDelete, target: "/api/users/4"},
		{name: "scope for access", groups: []string{"helpdesk"}, method: http.MethodGet, target: "/api/access"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rules := newFakeRules()
			rules.err = errors.New("connection refused")
			fake := &fakeUsers{user: member("staff")}
			rec := do(t, newTestServer(t, fake, rules, fakeAuth{groups: tt.groups}), tt.method, tt.target, tt.body)
			if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "connection refused") {
				t.Errorf("status = %d body %s, want generic 500", rec.Code, rec.Body)
			}
			if fake.mutated {
				t.Error("user changed although the access check failed")
			}
		})
	}
}

func TestServer_getAccess_admin(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		group string
		want  bool
	}{{"admins", true}, {"superhelp", false}} {
		rec := do(t, newScopedServer(t, &fakeUsers{}, tt.group), http.MethodGet, "/api/access", "")
		var body struct {
			All   bool `json:"all"`
			Admin bool `json:"admin"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding body: %v", err)
		}
		if !body.All || body.Admin != tt.want {
			t.Errorf("%s: access = %+v, want all and admin=%v", tt.group, body, tt.want)
		}
	}
}

func TestServer_listGroups(t *testing.T) {
	t.Parallel()
	rec := do(t, newServer(t, &fakeUsers{}), http.MethodGet, "/api/groups?search=st", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"groups":["staff","students"]`) {
		t.Errorf("GET /api/groups = %d %s", rec.Code, rec.Body)
	}
}
