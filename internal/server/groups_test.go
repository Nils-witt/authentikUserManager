package server_test

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// testGroups are the groups known to fakeUsers in the group tests, keyed by name.
func testGroups() map[string]authentik.Group {
	return map[string]authentik.Group{
		"admins":   {PK: "g0", Name: "admins"},
		"staff":    {PK: "g1", Name: "staff"},
		"students": {PK: "g2", Name: "students"},
		"teachers": {PK: "g3", Name: "teachers", Attributes: map[string]any{visibleAttribute: true, "other": "kept"}},
	}
}

// visibleAttribute is the group attribute marking groups visible to every signed-in user.
const visibleAttribute = "authentik_manager_visible"

// pathAttribute is the group attribute holding the group's path.
const pathAttribute = "authentik_manager_path"

func TestServer_groups_requireAdmin(t *testing.T) {
	t.Parallel()
	requests := []struct{ method, target, body string }{
		{http.MethodGet, "/api/groups", ""},
		{http.MethodGet, "/api/groups/g1", ""},
		{http.MethodPatch, "/api/groups/g1", `{"name":"employees"}`},
		{http.MethodPatch, "/api/groups/g1", `{"visible":true}`},
		{http.MethodGet, "/api/groups/g1/members", ""},
		{http.MethodPut, "/api/groups/g1/members/4", ""},
		{http.MethodDelete, "/api/groups/g1/members/4", ""},
	}
	for _, req := range requests {
		t.Run(req.method+" "+req.target, func(t *testing.T) {
			t.Parallel()
			users := &fakeUsers{groups: testGroups()}
			// Even a wildcard rule does not make an operator an access administrator.
			h := newTestServer(t, users, newFakeRules(), fakeAuth{groups: []string{"superhelp"}})
			rec := do(t, h, req.method, req.target, req.body)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
			if users.mutated {
				t.Error("authentik was changed")
			}
		})
	}
}

func TestServer_listGroups(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{}
	rec := do(t, newServer(t, users), http.MethodGet, "/api/groups?search=st&page=2&page_size=50", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	p := users.groupParams
	if p.Search != "st" || p.Page != 2 || p.PageSize != 50 || p.Attributes != nil {
		t.Errorf("params = %+v, want the search and paging without a filter", p)
	}
	var list authentik.GroupList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if len(list.Results) != 2 || list.Results[0].Name != "staff" {
		t.Errorf("groups = %+v", list.Results)
	}
}

func TestServer_listGroups_views(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{groupList: []authentik.Group{
		{PK: "g1", Name: "staff", Attributes: map[string]any{visibleAttribute: true, pathAttribute: "school", "secret": "x"}},
		{PK: "g2", Name: "students", Attributes: map[string]any{visibleAttribute: "true"}},
	}}
	rec := do(t, newServer(t, users), http.MethodGet, "/api/groups", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	// Only a JSON true counts; other attributes are not passed on.
	if !strings.Contains(body, `"name":"staff","is_superuser":false,"parent_name":"","path":"school","visible":true`) ||
		!strings.Contains(body, `"name":"students","is_superuser":false,"parent_name":"","path":"","visible":false`) ||
		strings.Contains(body, "secret") {
		t.Errorf("body = %s, want the visibility and no attributes", body)
	}
}

func TestServer_listVisibleGroups(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{groupList: []authentik.Group{
		{PK: "g1", Name: "staff", IsSuperuser: true, Attributes: map[string]any{visibleAttribute: true, "secret": "x"}},
		// Returned as if authentik ignored the filter; it must be dropped.
		{PK: "g2", Name: "hidden"},
	}}
	// The signed-in user joined staff after their login.
	users.listed = requester(authentik.UserGroup{PK: "g1", Name: "staff"})
	// Any signed-in user may list them, even without access to any user.
	h := newTestServer(t, users, newFakeRules(), fakeAuth{groups: []string{"guests"}})
	rec := do(t, h, http.MethodGet, "/api/groups/visible?search=st&page=2", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	p := users.groupParams
	if p.Search != "st" || p.Page != 2 || !maps.Equal(p.Attributes, map[string]any{visibleAttribute: true}) {
		t.Errorf("params = %+v, want the search, paging and visibility filter", p)
	}
	expected := `{"pagination":{"count":0,"current":0,"total_pages":0,"next":0,"previous":0,"start_index":0,"end_index":0},` +
		`"results":[{"pk":"g1","name":"staff","parent_name":"","path":"","member":true}]}`
	if got := strings.TrimSpace(rec.Body.String()); got != expected {
		t.Errorf("body = %s, want %s", got, expected)
	}
}

func TestServer_listGroups_pathFilter(t *testing.T) {
	t.Parallel()
	groups := []authentik.Group{
		{PK: "g1", Name: "staff", Attributes: map[string]any{visibleAttribute: true, pathAttribute: "school"}},
		// Returned as if authentik ignored the filter; they must be dropped.
		{PK: "g2", Name: "classes", Attributes: map[string]any{visibleAttribute: true, pathAttribute: "school/classes"}},
		{PK: "g3", Name: "top", Attributes: map[string]any{visibleAttribute: true}},
	}
	tests := []struct {
		name        string
		authn       fakeAuth
		target      string
		expectAttrs map[string]any
	}{
		{
			name:        "all groups",
			authn:       adminAuth,
			target:      "/api/groups?path=school",
			expectAttrs: map[string]any{pathAttribute: "school"},
		},
		{
			name:        "visible groups",
			authn:       fakeAuth{groups: []string{"guests"}},
			target:      "/api/groups/visible?path=school",
			expectAttrs: map[string]any{pathAttribute: "school", visibleAttribute: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := &fakeUsers{groupList: groups, listed: requester()}
			rec := do(t, newTestServer(t, users, newFakeRules(), tt.authn), http.MethodGet, tt.target, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d %s", rec.Code, rec.Body)
			}
			if !maps.Equal(users.groupParams.Attributes, tt.expectAttrs) {
				t.Errorf("attributes filter = %v, want %v", users.groupParams.Attributes, tt.expectAttrs)
			}
			var body struct {
				Results []struct {
					Name string `json:"name"`
				} `json:"results"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			if len(body.Results) != 1 || body.Results[0].Name != "staff" {
				t.Errorf("results = %+v, want staff only", body.Results)
			}
		})
	}
}

func TestServer_listGroupPaths(t *testing.T) {
	t.Parallel()
	groups := []authentik.Group{
		{PK: "g1", Name: "staff", Attributes: map[string]any{visibleAttribute: true, pathAttribute: "school"}},
		{PK: "g2", Name: "teachers", Attributes: map[string]any{visibleAttribute: true, pathAttribute: "school"}},
		{PK: "g3", Name: "classes", Attributes: map[string]any{pathAttribute: "school/classes"}},
		{PK: "g4", Name: "top", Attributes: map[string]any{visibleAttribute: true}},
	}
	tests := []struct {
		name        string
		authn       fakeAuth
		expected    string
		expectAttrs map[string]any
	}{
		{name: "access administrator sees all", authn: adminAuth, expected: `{"paths":["school","school/classes"]}`},
		{
			name:        "others see the visible groups",
			authn:       fakeAuth{groups: []string{"guests"}},
			expected:    `{"paths":["school"]}`,
			expectAttrs: map[string]any{visibleAttribute: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := &fakeUsers{groupList: groups}
			rec := do(t, newTestServer(t, users, newFakeRules(), tt.authn), http.MethodGet, "/api/groups/paths", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d %s", rec.Code, rec.Body)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != tt.expected {
				t.Errorf("body = %s, want %s", got, tt.expected)
			}
			if !maps.Equal(users.groupParams.Attributes, tt.expectAttrs) {
				t.Errorf("attributes filter = %v, want %v", users.groupParams.Attributes, tt.expectAttrs)
			}
		})
	}
}

func TestServer_listGroups_paging(t *testing.T) {
	t.Parallel()
	for _, query := range []string{"page=0", "page=x", "page_size=0", "page_size=101"} {
		t.Run(query, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(t, &fakeUsers{}), http.MethodGet, "/api/groups?"+query, "")
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body %s)", rec.Code, rec.Body)
			}
		})
	}
}

func TestServer_getGroup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		target     string
		expected   int
		expectBody string
	}{
		{name: "found", target: "/api/groups/g1", expected: http.StatusOK, expectBody: `"name":"staff"`},
		{name: "unknown", target: "/api/groups/nope", expected: http.StatusNotFound, expectBody: "group not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(t, &fakeUsers{groups: testGroups()}), http.MethodGet, tt.target, "")
			if rec.Code != tt.expected || !strings.Contains(rec.Body.String(), tt.expectBody) {
				t.Errorf("GET %s = %d %s, want %d containing %q", tt.target, rec.Code, rec.Body, tt.expected, tt.expectBody)
			}
		})
	}
}

func TestServer_renameGroup(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{groups: testGroups()}
	rules := newFakeRules()
	log := &fakeAudit{}
	h := newAuditedServer(t, users, rules, log, adminAuth)

	rec := do(t, h, http.MethodPatch, "/api/groups/g1", `{"name":" employees "}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"employees"`) {
		t.Fatalf("rename = %d %s", rec.Code, rec.Body)
	}
	if !slices.Equal(users.groupRenames, []string{"employees"}) {
		t.Errorf("authentik renames = %v, want [employees]", users.groupRenames)
	}
	// The rules name groups, so they follow the rename.
	if got := rules.rules["helpdesk"]; !slices.Equal(got, []string{"employees", "students"}) {
		t.Errorf("helpdesk targets = %v, want staff renamed to employees", got)
	}
	expected := audit.Entry{
		Actor:  "admin",
		Action: audit.ActionGroupRenamed,
		Target: "employees",
		Details: map[string]string{
			"group_id":      "g1",
			"previous_name": "staff",
			"rules_changed": "1",
		},
	}
	if len(log.recorded) != 1 || !equalEntry(log.recorded[0], expected) {
		t.Errorf("audit = %+v, want %+v", log.recorded, expected)
	}
}

// equalEntry compares the fields of audit entries that the server sets.
func equalEntry(got, expected audit.Entry) bool {
	if got.Actor != expected.Actor || got.Action != expected.Action || got.Target != expected.Target ||
		len(got.Details) != len(expected.Details) {
		return false
	}
	for k, v := range expected.Details {
		if got.Details[k] != v {
			return false
		}
	}
	return true
}

func TestServer_renameGroup_unchangedName(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{groups: testGroups()}
	rec := do(t, newServer(t, users), http.MethodPatch, "/api/groups/g1", `{"name":"staff"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if users.mutated {
		t.Error("authentik was changed although the name is the same")
	}
}

func TestServer_renameGroup_refused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		target   string
		body     string
		expected int
		// expectMsg is part of the expected response body.
		expectMsg string
	}{
		{name: "empty name", target: "/api/groups/g1", body: `{"name":"  "}`, expected: http.StatusBadRequest, expectMsg: "Name is required."},
		{name: "unknown field", target: "/api/groups/g1", body: `{"name":"x","is_superuser":true}`, expected: http.StatusBadRequest, expectMsg: "invalid JSON body"},
		{name: "unknown group", target: "/api/groups/nope", body: `{"name":"x"}`, expected: http.StatusNotFound, expectMsg: "group not found"},
		{name: "admin group", target: "/api/groups/g0", body: `{"name":"x"}`, expected: http.StatusBadRequest, expectMsg: "cannot be renamed"},
		{name: "to admin group", target: "/api/groups/g1", body: `{"name":"admins"}`, expected: http.StatusBadRequest, expectMsg: "reserved for an access administrator group"},
		{name: "to wildcard", target: "/api/groups/g1", body: `{"name":"*"}`, expected: http.StatusBadRequest, expectMsg: "reserved for access rules"},
		{name: "name taken", target: "/api/groups/g1", body: `{"name":"students"}`, expected: http.StatusBadRequest, expectMsg: "already named"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := &fakeUsers{groups: testGroups()}
			rules := newFakeRules()
			rec := do(t, newTestServer(t, users, rules, adminAuth), http.MethodPatch, tt.target, tt.body)
			if rec.Code != tt.expected || !strings.Contains(rec.Body.String(), tt.expectMsg) {
				t.Errorf("status = %d %s, want %d containing %q", rec.Code, rec.Body, tt.expected, tt.expectMsg)
			}
			if users.mutated {
				t.Error("authentik was changed")
			}
			if !slices.Equal(rules.rules["helpdesk"], []string{"staff", "students"}) {
				t.Errorf("rules changed: %v", rules.rules)
			}
		})
	}
}

func TestServer_renameGroup_storeFailureRestoresName(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{groups: testGroups()}
	rules := newFakeRules()
	log := &fakeAudit{}
	h := newAuditedServer(t, users, rules, log, adminAuth)
	rules.renameErr = errors.New("database down")

	rec := do(t, h, http.MethodPatch, "/api/groups/g1", `{"name":"employees"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d %s, want 500", rec.Code, rec.Body)
	}
	if !slices.Equal(users.groupRenames, []string{"employees", "staff"}) {
		t.Errorf("authentik renames = %v, want the rename undone", users.groupRenames)
	}
	if len(log.recorded) != 0 {
		t.Errorf("audit = %+v, want nothing recorded", log.recorded)
	}
}

func TestServer_updateGroup_visibility(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		target      string
		body        string
		expectAttrs map[string]any
		expectAudit string
	}{
		{
			name:        "show",
			target:      "/api/groups/g1",
			body:        `{"visible":true}`,
			expectAttrs: map[string]any{visibleAttribute: true},
			expectAudit: "true",
		},
		{
			name:        "hide keeps other attributes",
			target:      "/api/groups/g3",
			body:        `{"visible":false}`,
			expectAttrs: map[string]any{"other": "kept"},
			expectAudit: "false",
		},
		{name: "already visible", target: "/api/groups/g3", body: `{"visible":true}`},
		{name: "already hidden", target: "/api/groups/g1", body: `{"visible":false}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := &fakeUsers{groups: testGroups()}
			log := &fakeAudit{}
			rec := do(t, newAuditedServer(t, users, newFakeRules(), log, adminAuth), http.MethodPatch, tt.target, tt.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d %s", rec.Code, rec.Body)
			}
			if len(users.groupRenames) != 0 {
				t.Errorf("renames = %v, want none", users.groupRenames)
			}
			if tt.expectAttrs == nil {
				if users.mutated || len(log.recorded) != 0 {
					t.Errorf("updated %v, audit %+v; want nothing changed", users.groupAttrs, log.recorded)
				}
				return
			}
			if len(users.groupAttrs) != 1 || !maps.Equal(users.groupAttrs[0], tt.expectAttrs) {
				t.Errorf("attributes = %v, want %v", users.groupAttrs, tt.expectAttrs)
			}
			if !strings.Contains(rec.Body.String(), `"visible":`+tt.expectAudit) {
				t.Errorf("body = %s, want visible %s", rec.Body, tt.expectAudit)
			}
			if len(log.recorded) != 1 || log.recorded[0].Action != audit.ActionGroupVisibilityChanged ||
				log.recorded[0].Details["visible"] != tt.expectAudit {
				t.Errorf("audit = %+v, want the visibility change", log.recorded)
			}
		})
	}
}

func TestServer_updateGroup_path(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		target      string
		body        string
		expectAttrs map[string]any
		wantStatus  int
	}{
		{
			name:        "set keeps other attributes",
			target:      "/api/groups/g3",
			body:        `{"path":" /school/teachers/ "}`,
			expectAttrs: map[string]any{visibleAttribute: true, "other": "kept", pathAttribute: "school/teachers"},
			wantStatus:  http.StatusOK,
		},
		{
			name:        "set with visibility",
			target:      "/api/groups/g1",
			body:        `{"path":"school","visible":true}`,
			expectAttrs: map[string]any{visibleAttribute: true, pathAttribute: "school"},
			wantStatus:  http.StatusOK,
		},
		{
			name:        "clear",
			target:      "/api/groups/g4",
			body:        `{"path":""}`,
			expectAttrs: map[string]any{},
			wantStatus:  http.StatusOK,
		},
		{name: "unchanged", target: "/api/groups/g4", body: `{"path":"school/"}`, wantStatus: http.StatusOK},
		{name: "empty folder", target: "/api/groups/g1", body: `{"path":"school//classes"}`, wantStatus: http.StatusBadRequest},
		{name: "too long", target: "/api/groups/g1", body: `{"path":"` + strings.Repeat("a", 256) + `"}`, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			groups := testGroups()
			groups["school"] = authentik.Group{PK: "g4", Name: "school", Attributes: map[string]any{pathAttribute: "school"}}
			users := &fakeUsers{groups: groups}
			log := &fakeAudit{}
			rec := do(t, newAuditedServer(t, users, newFakeRules(), log, adminAuth), http.MethodPatch, tt.target, tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.expectAttrs == nil {
				if users.mutated || len(log.recorded) != 0 {
					t.Errorf("updated %v, audit %+v; want nothing changed", users.groupAttrs, log.recorded)
				}
				return
			}
			if len(users.groupAttrs) != 1 || !maps.Equal(users.groupAttrs[0], tt.expectAttrs) {
				t.Errorf("attributes = %v, want %v", users.groupAttrs, tt.expectAttrs)
			}
			want, _ := tt.expectAttrs[pathAttribute].(string)
			if !strings.Contains(rec.Body.String(), `"path":"`+want+`"`) {
				t.Errorf("body = %s, want path %q", rec.Body, want)
			}
			i := slices.IndexFunc(log.recorded, func(e audit.Entry) bool { return e.Action == audit.ActionGroupPathChanged })
			if i < 0 || log.recorded[i].Details["path"] != want {
				t.Errorf("audit = %+v, want the path change to %q", log.recorded, want)
			}
		})
	}
}

func TestServer_updateGroup_renameAndVisibility(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{groups: testGroups()}
	log := &fakeAudit{}
	rec := do(t, newAuditedServer(t, users, newFakeRules(), log, adminAuth),
		http.MethodPatch, "/api/groups/g1", `{"name":"employees","visible":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if !slices.Equal(users.groupRenames, []string{"employees"}) || len(users.groupAttrs) != 1 {
		t.Errorf("renames %v, attributes %v; want both in one update", users.groupRenames, users.groupAttrs)
	}
	var actions []audit.Action
	for _, e := range log.recorded {
		actions = append(actions, e.Action)
	}
	if !slices.Equal(actions, []audit.Action{audit.ActionGroupVisibilityChanged, audit.ActionGroupRenamed}) {
		t.Errorf("audit actions = %v", actions)
	}
}

func TestServer_listGroupMembers(t *testing.T) {
	t.Parallel()
	inStaff := []authentik.UserGroup{{PK: "g1", Name: "staff"}}
	users := &fakeUsers{
		groups: testGroups(),
		listed: []authentik.User{
			{PK: 1, Username: "ann", Groups: inStaff},
			// Returned as if authentik ignored the filter; it must be dropped.
			{PK: 2, Username: "bob", Groups: []authentik.UserGroup{{PK: "g2", Name: "students"}}},
			{PK: 3, Username: "svc", Type: authentik.UserTypeServiceAccount, Groups: inStaff},
		},
	}
	rec := do(t, newServer(t, users), http.MethodGet, "/api/groups/g1/members?search=a&page=2", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	p := users.listParams
	if !slices.Equal(p.GroupsByPK, []string{"g1"}) || p.Search != "a" || p.Page != 2 || p.PageSize != 20 {
		t.Errorf("params = %+v, want the group filter, search and paging", p)
	}
	var list authentik.UserList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	var names []string
	for _, u := range list.Results {
		names = append(names, u.Username)
	}
	if !slices.Equal(names, []string{"ann", "svc"}) {
		t.Errorf("members = %v, want [ann svc]", names)
	}
}

func TestServer_changeGroupMember(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		method       string
		target       string
		expected     int
		expectAdded  []string
		expectRemove []string
		expectAudit  audit.Action
	}{
		{
			name:        "add",
			method:      http.MethodPut,
			target:      "/api/groups/g1/members/4",
			expected:    http.StatusNoContent,
			expectAdded: []string{"g1"},
			expectAudit: audit.ActionUserGroupAdded,
		},
		{
			name:         "remove",
			method:       http.MethodDelete,
			target:       "/api/groups/g1/members/4",
			expected:     http.StatusNoContent,
			expectRemove: []string{"g1"},
			expectAudit:  audit.ActionUserGroupRemoved,
		},
		{name: "unknown group", method: http.MethodPut, target: "/api/groups/nope/members/4", expected: http.StatusNotFound},
		{name: "invalid user id", method: http.MethodPut, target: "/api/groups/g1/members/x", expected: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := &fakeUsers{groups: testGroups(), user: &authentik.User{Username: "dan"}}
			log := &fakeAudit{}
			rec := do(t, newAuditedServer(t, users, newFakeRules(), log, adminAuth), tt.method, tt.target, "")
			if rec.Code != tt.expected {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body, tt.expected)
			}
			if !slices.Equal(users.added, tt.expectAdded) || !slices.Equal(users.removed, tt.expectRemove) {
				t.Errorf("added %v removed %v, want %v and %v", users.added, users.removed, tt.expectAdded, tt.expectRemove)
			}
			if tt.expectAudit == "" {
				if len(log.recorded) != 0 {
					t.Errorf("audit = %+v, want nothing recorded", log.recorded)
				}
				return
			}
			expected := audit.Entry{
				Actor:   "admin",
				Action:  tt.expectAudit,
				Target:  "dan",
				Details: map[string]string{"group": "staff", "user_id": "4"},
			}
			if len(log.recorded) != 1 || !equalEntry(log.recorded[0], expected) {
				t.Errorf("audit = %+v, want %+v", log.recorded, expected)
			}
		})
	}
}

func TestServer_removeGroupMember_primaryGroup(t *testing.T) {
	t.Parallel()
	user := &authentik.User{
		Username:   "dan",
		Groups:     []authentik.UserGroup{{PK: "g1", Name: "staff"}, {PK: "g2", Name: "students"}},
		Attributes: map[string]any{primaryGroupAttribute: "g1"},
	}
	tests := []struct {
		name           string
		target         string
		expectedStatus int
		expectedRemove []string
	}{
		{name: "primary group refused", target: "/api/groups/g1/members/4", expectedStatus: http.StatusConflict},
		{name: "other group", target: "/api/groups/g2/members/4", expectedStatus: http.StatusNoContent, expectedRemove: []string{"g2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := &fakeUsers{groups: testGroups(), user: user}
			rec := do(t, newTestServer(t, users, newFakeRules(), adminAuth), http.MethodDelete, tt.target, "")
			if rec.Code != tt.expectedStatus {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body, tt.expectedStatus)
			}
			if !slices.Equal(users.removed, tt.expectedRemove) {
				t.Errorf("removed %v, want %v", users.removed, tt.expectedRemove)
			}
		})
	}
}
