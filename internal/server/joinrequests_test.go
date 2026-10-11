package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
	"authentikManager/internal/joinrequest"
	"authentikManager/internal/server"
)

// fakeJoinRequests is an in-memory join request store. Each test uses its own instance.
type fakeJoinRequests struct {
	requests []joinrequest.Request
	// query records the query passed to ListJoinRequests.
	query joinrequest.Query
	// reopened records the IDs passed to ReopenJoinRequest.
	reopened []int64
	err      error
}

func (f *fakeJoinRequests) find(id int64) (int, error) {
	i := slices.IndexFunc(f.requests, func(jr joinrequest.Request) bool { return jr.ID == id })
	if i < 0 {
		return 0, joinrequest.ErrNotFound
	}
	return i, nil
}

func (f *fakeJoinRequests) CreateJoinRequest(_ context.Context, jr joinrequest.Request) (joinrequest.Request, error) {
	if f.err != nil {
		return joinrequest.Request{}, f.err
	}
	if slices.ContainsFunc(f.requests, func(o joinrequest.Request) bool {
		return o.Status == joinrequest.StatusPending && o.GroupPK == jr.GroupPK && o.UserPK == jr.UserPK
	}) {
		return joinrequest.Request{}, joinrequest.ErrPending
	}
	jr.ID = int64(len(f.requests) + 1)
	jr.Status = joinrequest.StatusPending
	jr.CreatedAt = time.Now()
	f.requests = append(f.requests, jr)
	return jr, nil
}

func (f *fakeJoinRequests) GetJoinRequest(_ context.Context, id int64) (joinrequest.Request, error) {
	if f.err != nil {
		return joinrequest.Request{}, f.err
	}
	i, err := f.find(id)
	if err != nil {
		return joinrequest.Request{}, err
	}
	return f.requests[i], nil
}

func (f *fakeJoinRequests) ListJoinRequests(_ context.Context, q joinrequest.Query) ([]joinrequest.Request, error) {
	f.query = q
	if f.err != nil {
		return nil, f.err
	}
	var out []joinrequest.Request
	for _, jr := range slices.Backward(f.requests) {
		if (q.Status == "" || jr.Status == q.Status) &&
			(q.GroupPKs == nil || slices.Contains(q.GroupPKs, jr.GroupPK)) &&
			(q.Username == "" || jr.Username == q.Username) {
			out = append(out, jr)
		}
	}
	return out, nil
}

func (f *fakeJoinRequests) DecideJoinRequest(_ context.Context, id int64, status joinrequest.Status, actor string) (joinrequest.Request, error) {
	if f.err != nil {
		return joinrequest.Request{}, f.err
	}
	i, err := f.find(id)
	if err != nil {
		return joinrequest.Request{}, err
	}
	if f.requests[i].Status != joinrequest.StatusPending {
		return joinrequest.Request{}, joinrequest.ErrDecided
	}
	now := time.Now()
	f.requests[i].Status, f.requests[i].DecidedAt, f.requests[i].DecidedBy = status, &now, actor
	return f.requests[i], nil
}

func (f *fakeJoinRequests) ReopenJoinRequest(_ context.Context, id int64) error {
	f.reopened = append(f.reopened, id)
	i, err := f.find(id)
	if err != nil {
		return err
	}
	f.requests[i].Status, f.requests[i].DecidedAt, f.requests[i].DecidedBy = joinrequest.StatusPending, nil, ""
	return nil
}

func (f *fakeJoinRequests) WithdrawJoinRequest(_ context.Context, id int64, username string) error {
	if f.err != nil {
		return f.err
	}
	i, err := f.find(id)
	if err != nil || f.requests[i].Username != username || f.requests[i].Status != joinrequest.StatusPending {
		return joinrequest.ErrNotFound
	}
	f.requests = slices.Delete(f.requests, i, i+1)
	return nil
}

// failingAdd is a fakeUsers whose AddUserToGroup fails.
type failingAdd struct {
	*fakeUsers
}

func (failingAdd) AddUserToGroup(context.Context, string, int) error {
	return errors.New("authentik is down")
}

// joinTestGroups are testGroups plus a visible superuser group.
func joinTestGroups() map[string]authentik.Group {
	groups := testGroups()
	groups["root"] = authentik.Group{PK: "g4", Name: "root", IsSuperuser: true, Attributes: map[string]any{visibleAttribute: true}}
	return groups
}

// newJoinServer returns a server for the operator "admin" in groups, with the
// test rules: "helpdesk" manages staff and students, "admins" are access administrators.
func newJoinServer(t *testing.T, users server.UserService, jrs *fakeJoinRequests, log *fakeAudit, groups ...string) *server.Server {
	t.Helper()
	rules := newFakeRules()
	policy, err := access.NewPolicy([]string{"admins"}, rules)
	if err != nil {
		t.Fatal(err)
	}
	return server.New(server.Deps{
		Users:        users,
		Auth:         fakeAuth{groups: groups},
		Policy:       policy,
		Rules:        rules,
		Audit:        log,
		JoinRequests: jrs,
		Logger:       slog.New(slog.DiscardHandler),
	})
}

// requester returns the authentik account of the signed-in test operator "admin".
func requester(groups ...authentik.UserGroup) []authentik.User {
	return []authentik.User{{PK: 7, Username: "admin", Type: authentik.UserTypeInternal, Groups: groups}}
}

// pending returns a pending request by username for the group with pk and name.
func pending(id int64, pk, name, username string) joinrequest.Request {
	return joinrequest.Request{ID: id, GroupPK: pk, GroupName: name, UserPK: 5, Username: username, Status: joinrequest.StatusPending}
}

func TestServer_requestJoin(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{groups: joinTestGroups(), listed: requester()}
	jrs := &fakeJoinRequests{}
	log := &fakeAudit{}
	// Any signed-in user may request, even one who may not manage any users.
	h := newJoinServer(t, users, jrs, log, "guests")

	rec := do(t, h, http.MethodPost, "/api/groups/g3/join-requests", `{"message":"  I teach maths. "}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if p := users.listParams; p.Username != "admin" || !slices.Equal(p.Type, []authentik.UserType{authentik.UserTypeInternal}) {
		t.Errorf("requester lookup = %+v, want the internal user admin", p)
	}
	expected := joinrequest.Request{ID: 1, GroupPK: "g3", GroupName: "teachers", UserPK: 7, Username: "admin", Message: "I teach maths.", Status: joinrequest.StatusPending}
	if len(jrs.requests) != 1 || !equalRequest(jrs.requests[0], expected) {
		t.Errorf("stored = %+v, want %+v", jrs.requests, expected)
	}
	var got joinrequest.Request
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || !equalRequest(got, expected) {
		t.Errorf("body = %s (%v), want %+v", rec.Body, err, expected)
	}
	expectedEntry := audit.Entry{
		Actor:   "admin",
		Action:  audit.ActionJoinRequested,
		Target:  "admin",
		Details: map[string]string{"request_id": "1", "group": "teachers", "group_id": "g3", "user_id": "7"},
	}
	if len(log.recorded) != 1 || !equalEntry(log.recorded[0], expectedEntry) {
		t.Errorf("audit = %+v, want %+v", log.recorded, expectedEntry)
	}
	if users.mutated {
		t.Error("authentik was changed")
	}
}

// equalRequest compares the fields of requests that the server sets.
func equalRequest(got, expected joinrequest.Request) bool {
	return got.ID == expected.ID && got.GroupPK == expected.GroupPK && got.GroupName == expected.GroupName &&
		got.UserPK == expected.UserPK && got.Username == expected.Username && got.Message == expected.Message &&
		got.Status == expected.Status && got.DecidedBy == expected.DecidedBy
}

func TestServer_requestJoin_refused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		target     string
		body       string
		listed     []authentik.User
		existing   []joinrequest.Request
		expected   int
		expectBody string
	}{
		{name: "hidden group", target: "/api/groups/g1/join-requests", body: `{}`, expected: http.StatusNotFound, expectBody: "group not found"},
		{name: "unknown group", target: "/api/groups/nope/join-requests", body: `{}`, expected: http.StatusNotFound, expectBody: "group not found"},
		{name: "superuser group", target: "/api/groups/g4/join-requests", body: `{}`, expected: http.StatusForbidden, expectBody: "cannot be requested"},
		{
			name: "already a member", target: "/api/groups/g3/join-requests", body: `{}`,
			listed:   requester(authentik.UserGroup{PK: "g3", Name: "teachers"}),
			expected: http.StatusConflict, expectBody: "already a member",
		},
		{
			name: "already pending", target: "/api/groups/g3/join-requests", body: `{}`,
			existing: []joinrequest.Request{{ID: 1, GroupPK: "g3", UserPK: 7, Username: "admin", Status: joinrequest.StatusPending}},
			expected: http.StatusConflict, expectBody: "already requested",
		},
		{
			name: "not an internal user", target: "/api/groups/g3/join-requests", body: `{}`,
			// authentik ignored the filters and returned someone else.
			listed:   []authentik.User{{PK: 8, Username: "administrator", Type: authentik.UserTypeInternal}},
			expected: http.StatusForbidden, expectBody: "only internal users",
		},
		{
			name: "message too long", target: "/api/groups/g3/join-requests",
			body:     `{"message":"` + strings.Repeat("x", joinrequest.MaxMessageLen+1) + `"}`,
			expected: http.StatusBadRequest, expectBody: "message must be at most",
		},
		{name: "unknown field", target: "/api/groups/g3/join-requests", body: `{"user_pk":1}`, expected: http.StatusBadRequest, expectBody: "invalid JSON body"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := &fakeUsers{groups: joinTestGroups(), listed: orDefault(tt.listed, requester())}
			jrs := &fakeJoinRequests{requests: tt.existing}
			rec := do(t, newJoinServer(t, users, jrs, &fakeAudit{}, "guests"), http.MethodPost, tt.target, tt.body)
			if rec.Code != tt.expected || !strings.Contains(rec.Body.String(), tt.expectBody) {
				t.Errorf("POST %s = %d %s, want %d containing %q", tt.target, rec.Code, rec.Body, tt.expected, tt.expectBody)
			}
			if len(jrs.requests) != len(tt.existing) {
				t.Errorf("requests = %+v, want none added", jrs.requests)
			}
		})
	}
}

// orDefault returns s, or fallback when s is nil.
func orDefault[T any](s, fallback []T) []T {
	if s == nil {
		return fallback
	}
	return s
}

func TestServer_listMyJoinRequests(t *testing.T) {
	t.Parallel()
	jrs := &fakeJoinRequests{requests: []joinrequest.Request{
		pending(1, "g3", "teachers", "admin"),
		pending(2, "g3", "teachers", "bob"),
		{ID: 3, GroupPK: "g1", GroupName: "staff", Username: "admin", Status: joinrequest.StatusRejected},
	}}
	rec := do(t, newJoinServer(t, &fakeUsers{}, jrs, &fakeAudit{}, "guests"), http.MethodGet, "/api/join-requests/mine", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if jrs.query.Username != "admin" || jrs.query.Status != "" {
		t.Errorf("query = %+v, want all requests of admin", jrs.query)
	}
	if ids := responseIDs(t, rec.Body.Bytes()); !slices.Equal(ids, []int64{3, 1}) {
		t.Errorf("ids = %v, want [3 1]", ids)
	}
}

// responseIDs returns the IDs of the requests in a join request list response.
func responseIDs(t *testing.T, body []byte) []int64 {
	t.Helper()
	var list struct {
		Requests []joinrequest.Request `json:"requests"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	if list.Requests == nil {
		t.Fatalf("requests = null in %s, want a list", body)
	}
	ids := []int64{}
	for _, jr := range list.Requests {
		ids = append(ids, jr.ID)
	}
	return ids
}

func TestServer_listJoinRequests(t *testing.T) {
	t.Parallel()
	requests := []joinrequest.Request{
		pending(1, "g1", "staff", "bob"),
		pending(2, "g3", "teachers", "carl"),
		pending(3, "g2", "students", "admin"),
		{ID: 4, GroupPK: "g1", GroupName: "staff", Username: "dora", Status: joinrequest.StatusApproved},
		pending(5, "g2", "students", "erin"),
	}
	tests := []struct {
		name         string
		groups       []string
		expected     []int64
		expectGroups []string
	}{
		// Their own request (3) is left out.
		{name: "access administrator", groups: []string{"admins"}, expected: []int64{5, 2, 1}},
		{name: "wildcard rule", groups: []string{"superhelp"}, expected: []int64{5, 2, 1}},
		{name: "restricted operator", groups: []string{"helpdesk"}, expected: []int64{5, 1}, expectGroups: []string{"g1", "g2"}},
		{name: "no access", groups: []string{"guests"}, expected: []int64{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			jrs := &fakeJoinRequests{requests: slices.Clone(requests)}
			h := newJoinServer(t, &fakeUsers{groups: joinTestGroups()}, jrs, &fakeAudit{}, tt.groups...)
			rec := do(t, h, http.MethodGet, "/api/join-requests", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d %s", rec.Code, rec.Body)
			}
			if ids := responseIDs(t, rec.Body.Bytes()); !slices.Equal(ids, tt.expected) {
				t.Errorf("ids = %v, want %v", ids, tt.expected)
			}
			if len(tt.expected) > 0 && jrs.query.Status != joinrequest.StatusPending {
				t.Errorf("status filter = %q, want pending", jrs.query.Status)
			}
			if got := slices.Sorted(slices.Values(jrs.query.GroupPKs)); !slices.Equal(got, tt.expectGroups) {
				t.Errorf("group filter = %v, want %v", got, tt.expectGroups)
			}
		})
	}
}

func TestServer_approveJoinRequest(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{groups: joinTestGroups()}
	jrs := &fakeJoinRequests{requests: []joinrequest.Request{pending(1, "g1", "staff", "bob")}}
	log := &fakeAudit{}
	h := newJoinServer(t, users, jrs, log, "helpdesk")

	rec := do(t, h, http.MethodPost, "/api/join-requests/1/approve", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"approved"`) {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body)
	}
	if !slices.Equal(users.added, []string{"g1"}) {
		t.Errorf("added to %v, want [g1]", users.added)
	}
	if jr := jrs.requests[0]; jr.Status != joinrequest.StatusApproved || jr.DecidedBy != "admin" {
		t.Errorf("request = %+v, want approved by admin", jr)
	}
	expected := audit.Entry{
		Actor:   "admin",
		Action:  audit.ActionJoinApproved,
		Target:  "bob",
		Details: map[string]string{"request_id": "1", "group": "staff", "group_id": "g1", "user_id": "5"},
	}
	if len(log.recorded) != 1 || !equalEntry(log.recorded[0], expected) {
		t.Errorf("audit = %+v, want %+v", log.recorded, expected)
	}

	// A decided request cannot be decided again.
	rec = do(t, h, http.MethodPost, "/api/join-requests/1/reject", "")
	if rec.Code != http.StatusConflict {
		t.Errorf("second decision = %d %s, want 409", rec.Code, rec.Body)
	}
}

func TestServer_rejectJoinRequest(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{groups: joinTestGroups()}
	jrs := &fakeJoinRequests{requests: []joinrequest.Request{pending(1, "g1", "staff", "bob")}}
	log := &fakeAudit{}

	rec := do(t, newJoinServer(t, users, jrs, log, "helpdesk"), http.MethodPost, "/api/join-requests/1/reject", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"rejected"`) {
		t.Fatalf("reject = %d %s", rec.Code, rec.Body)
	}
	if users.mutated {
		t.Error("authentik was changed")
	}
	if len(log.recorded) != 1 || log.recorded[0].Action != audit.ActionJoinRejected {
		t.Errorf("audit = %+v, want one rejection", log.recorded)
	}
}

func TestServer_decideJoinRequest_refused(t *testing.T) {
	t.Parallel()
	requests := []joinrequest.Request{
		pending(1, "g3", "teachers", "bob"),
		pending(2, "g1", "staff", "admin"),
		{ID: 3, GroupPK: "g1", GroupName: "staff", Username: "bob", Status: joinrequest.StatusRejected},
		pending(4, "gone", "staff", "bob"),
	}
	tests := []struct {
		name       string
		target     string
		groups     []string
		expected   int
		expectBody string
	}{
		{name: "group outside the scope", target: "/api/join-requests/1/approve", groups: []string{"helpdesk"}, expected: http.StatusNotFound, expectBody: "join request not found"},
		{name: "own request", target: "/api/join-requests/2/approve", groups: []string{"admins"}, expected: http.StatusForbidden, expectBody: "your own"},
		{name: "already decided", target: "/api/join-requests/3/approve", groups: []string{"helpdesk"}, expected: http.StatusConflict, expectBody: "already decided"},
		{name: "unknown request", target: "/api/join-requests/99/reject", groups: []string{"admins"}, expected: http.StatusNotFound, expectBody: "join request not found"},
		{name: "invalid id", target: "/api/join-requests/x/reject", groups: []string{"admins"}, expected: http.StatusBadRequest, expectBody: "invalid join request id"},
		{name: "approve for a deleted group", target: "/api/join-requests/4/approve", groups: []string{"helpdesk"}, expected: http.StatusNotFound, expectBody: "group not found"},
		{name: "no access", target: "/api/join-requests/1/reject", groups: []string{"guests"}, expected: http.StatusNotFound, expectBody: "join request not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := &fakeUsers{groups: joinTestGroups()}
			jrs := &fakeJoinRequests{requests: slices.Clone(requests)}
			rec := do(t, newJoinServer(t, users, jrs, &fakeAudit{}, tt.groups...), http.MethodPost, tt.target, "")
			if rec.Code != tt.expected || !strings.Contains(rec.Body.String(), tt.expectBody) {
				t.Errorf("POST %s = %d %s, want %d containing %q", tt.target, rec.Code, rec.Body, tt.expected, tt.expectBody)
			}
			if users.mutated || !slices.Equal(jrs.requests, requests) {
				t.Error("a request or authentik was changed")
			}
		})
	}
}

func TestServer_decideJoinRequest_superuserGroup(t *testing.T) {
	t.Parallel()
	groups := joinTestGroups()
	staff := groups["staff"]
	staff.IsSuperuser = true
	groups["staff"] = staff
	users := &fakeUsers{groups: groups}
	jrs := &fakeJoinRequests{requests: []joinrequest.Request{pending(1, "g1", "staff", "bob")}}

	// Restricted operators may not add users to superuser groups.
	rec := do(t, newJoinServer(t, users, jrs, &fakeAudit{}, "helpdesk"), http.MethodPost, "/api/join-requests/1/approve", "")
	if rec.Code != http.StatusForbidden || users.mutated || jrs.requests[0].Status != joinrequest.StatusPending {
		t.Errorf("restricted approve = %d %s, want 403 and nothing changed", rec.Code, rec.Body)
	}
	// Access administrators may.
	rec = do(t, newJoinServer(t, users, jrs, &fakeAudit{}, "admins"), http.MethodPost, "/api/join-requests/1/approve", "")
	if rec.Code != http.StatusOK || !slices.Equal(users.added, []string{"g1"}) {
		t.Errorf("admin approve = %d %s, added %v", rec.Code, rec.Body, users.added)
	}
}

func TestServer_rejectJoinRequest_deletedGroup(t *testing.T) {
	t.Parallel()
	jrs := &fakeJoinRequests{requests: []joinrequest.Request{pending(1, "gone", "staff", "bob")}}
	h := newJoinServer(t, &fakeUsers{groups: joinTestGroups()}, jrs, &fakeAudit{}, "helpdesk")

	// The operators who managed the group under its requested name may still reject it.
	rec := do(t, h, http.MethodPost, "/api/join-requests/1/reject", "")
	if rec.Code != http.StatusOK || jrs.requests[0].Status != joinrequest.StatusRejected {
		t.Errorf("reject = %d %s, want 200 and rejected", rec.Code, rec.Body)
	}
}

func TestServer_approveJoinRequest_addFails(t *testing.T) {
	t.Parallel()
	jrs := &fakeJoinRequests{requests: []joinrequest.Request{pending(1, "g1", "staff", "bob")}}
	log := &fakeAudit{}
	users := failingAdd{&fakeUsers{groups: joinTestGroups()}}

	rec := do(t, newJoinServer(t, users, jrs, log, "helpdesk"), http.MethodPost, "/api/join-requests/1/approve", "")
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d %s, want 502", rec.Code, rec.Body)
	}
	// The request is pending again, so it can be decided once authentik is back.
	if !slices.Equal(jrs.reopened, []int64{1}) || jrs.requests[0].Status != joinrequest.StatusPending {
		t.Errorf("reopened = %v, request = %+v, want it pending again", jrs.reopened, jrs.requests[0])
	}
	if len(log.recorded) != 0 {
		t.Errorf("audit = %+v, want nothing recorded", log.recorded)
	}
}

func TestServer_withdrawJoinRequest(t *testing.T) {
	t.Parallel()
	requests := []joinrequest.Request{
		pending(1, "g3", "teachers", "admin"),
		pending(2, "g3", "teachers", "bob"),
		{ID: 3, GroupPK: "g1", GroupName: "staff", Username: "admin", Status: joinrequest.StatusApproved},
	}
	tests := []struct {
		name      string
		target    string
		expected  int
		remaining []int64
	}{
		{name: "own pending request", target: "/api/join-requests/1", expected: http.StatusNoContent, remaining: []int64{2, 3}},
		{name: "request of another user", target: "/api/join-requests/2", expected: http.StatusNotFound, remaining: []int64{1, 2, 3}},
		{name: "decided request", target: "/api/join-requests/3", expected: http.StatusConflict, remaining: []int64{1, 2, 3}},
		{name: "unknown request", target: "/api/join-requests/9", expected: http.StatusNotFound, remaining: []int64{1, 2, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			jrs := &fakeJoinRequests{requests: slices.Clone(requests)}
			log := &fakeAudit{}
			rec := do(t, newJoinServer(t, &fakeUsers{}, jrs, log, "guests"), http.MethodDelete, tt.target, "")
			if rec.Code != tt.expected {
				t.Errorf("DELETE %s = %d %s, want %d", tt.target, rec.Code, rec.Body, tt.expected)
			}
			var ids []int64
			for _, jr := range jrs.requests {
				ids = append(ids, jr.ID)
			}
			if !slices.Equal(ids, tt.remaining) {
				t.Errorf("remaining = %v, want %v", ids, tt.remaining)
			}
			if withdrawn := tt.expected == http.StatusNoContent; withdrawn != (len(log.recorded) == 1) {
				t.Errorf("audit = %+v", log.recorded)
			}
		})
	}
}

func TestServer_joinRequests_storeError(t *testing.T) {
	t.Parallel()
	jrs := &fakeJoinRequests{err: errors.New("database is down")}
	rec := do(t, newJoinServer(t, &fakeUsers{}, jrs, &fakeAudit{}, "admins"), http.MethodGet, "/api/join-requests", "")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "database is down") {
		t.Errorf("status = %d %s, want 500 without the cause", rec.Code, rec.Body)
	}
}
