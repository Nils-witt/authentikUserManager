package server_test

import (
	"cmp"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"authentikManager/internal/access"
	"authentikManager/internal/auth"
	"authentikManager/internal/authentik"
	"authentikManager/internal/server"
)

// fakeAuth lets every request through as a fixed user in groups, or rejects all when deny is set.
type fakeAuth struct {
	deny   bool
	groups []string
}

func (fakeAuth) Handler() http.Handler { return http.NotFoundHandler() }

func (f fakeAuth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.deny {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), auth.User{Username: "admin", Groups: f.groups})))
	})
}

// fakeUsers is a UserService whose behavior is set per test.
type fakeUsers struct {
	listParams authentik.ListUsersParams
	created    authentik.CreateUserRequest
	// listed are returned by ListUsers; nil means a single user "ann".
	listed []authentik.User
	// user is returned by GetUser; nil means a user without groups.
	user *authentik.User
	// groups are found by FindGroup and GetGroup, keyed by name.
	groups map[string]authentik.Group
	// groupParams records the parameters passed to ListGroups.
	groupParams authentik.ListGroupsParams
	// groupRenames records the names passed to UpdateGroup, in order.
	groupRenames []string
	// groupAttrs records the attributes passed to UpdateGroup, in order.
	groupAttrs []map[string]any
	// groupList, when set, is returned by ListGroups.
	groupList []authentik.Group
	// added and removed record the group keys passed to AddUserToGroup and RemoveUserFromGroup.
	added   []string
	removed []string
	mutated bool
	// recoveryStage records the email stage passed to SendRecoveryEmail.
	recoveryStage string
	err           error
}

func (f *fakeUsers) ListUsers(_ context.Context, p authentik.ListUsersParams) (*authentik.UserList, error) {
	f.listParams = p
	if f.err != nil {
		return nil, f.err
	}
	if f.listed != nil {
		return &authentik.UserList{Results: slices.Clone(f.listed)}, nil
	}
	return &authentik.UserList{Results: []authentik.User{{PK: 1, Username: "ann", Type: authentik.UserTypeInternal}}}, nil
}

func (f *fakeUsers) ListUserPaths(context.Context) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []string{"users", "users/staff"}, nil
}

func (f *fakeUsers) GetUser(_ context.Context, id int) (*authentik.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.user != nil {
		u := *f.user
		u.PK = id
		return &u, nil
	}
	return &authentik.User{PK: id, Type: authentik.UserTypeInternal}, nil
}

func (f *fakeUsers) FindGroup(_ context.Context, name string) (*authentik.Group, error) {
	if f.err != nil {
		return nil, f.err
	}
	g, ok := f.groups[name]
	if !ok {
		return nil, authentik.ErrNotFound
	}
	return &g, nil
}

func (f *fakeUsers) ListGroups(_ context.Context, p authentik.ListGroupsParams) (*authentik.GroupList, error) {
	f.groupParams = p
	if f.err != nil {
		return nil, f.err
	}
	if f.groupList != nil {
		return &authentik.GroupList{Results: slices.Clone(f.groupList)}, nil
	}
	return &authentik.GroupList{Results: []authentik.Group{{PK: "g1", Name: "staff"}, {PK: "g2", Name: "students"}}}, nil
}

func (f *fakeUsers) GetGroup(_ context.Context, pk string) (*authentik.Group, error) {
	if f.err != nil {
		return nil, f.err
	}
	for _, g := range f.groups {
		if g.PK == pk {
			return &g, nil
		}
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeUsers) UpdateGroup(_ context.Context, pk string, req authentik.UpdateGroupRequest) (*authentik.Group, error) {
	f.mutated = true
	if f.err != nil {
		return nil, f.err
	}
	g, err := f.GetGroup(context.Background(), pk)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		f.groupRenames = append(f.groupRenames, *req.Name)
		g.Name = *req.Name
	}
	if req.Attributes != nil {
		f.groupAttrs = append(f.groupAttrs, req.Attributes)
		g.Attributes = req.Attributes
	}
	return g, nil
}

func (f *fakeUsers) CreateUser(_ context.Context, req authentik.CreateUserRequest) (*authentik.User, error) {
	f.created = req
	if f.err != nil {
		return nil, f.err
	}
	return &authentik.User{PK: 9, Username: req.Username, Name: req.Name}, nil
}

func (f *fakeUsers) UpdateUser(_ context.Context, id int, _ authentik.UpdateUserRequest) (*authentik.User, error) {
	f.mutated = true
	if f.err != nil {
		return nil, f.err
	}
	return &authentik.User{PK: id}, nil
}

func (f *fakeUsers) DeleteUser(context.Context, int) error {
	f.mutated = true
	return f.err
}

func (f *fakeUsers) AddUserToGroup(_ context.Context, groupPK string, _ int) error {
	f.mutated = true
	f.added = append(f.added, groupPK)
	return f.err
}

func (f *fakeUsers) RemoveUserFromGroup(_ context.Context, groupPK string, _ int) error {
	f.mutated = true
	f.removed = append(f.removed, groupPK)
	return f.err
}

func (f *fakeUsers) SendRecoveryEmail(_ context.Context, _ int, emailStage string) error {
	f.mutated = true
	f.recoveryStage = emailStage
	return f.err
}

func do(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// fakeRules is an in-memory rule store. Each test uses its own instance.
type fakeRules struct {
	rules map[string][]string
	err   error
	// renameErr, when set, fails RenameGroup only.
	renameErr error
}

// newFakeRules returns the test rules: "helpdesk" manages staff and students,
// "superhelp" manages everyone. Members of "admins" are access administrators.
func newFakeRules() *fakeRules {
	return &fakeRules{rules: map[string][]string{
		"helpdesk":  {"staff", "students"},
		"superhelp": {access.Wildcard},
	}}
}

func (f *fakeRules) TargetGroups(_ context.Context, operatorGroups []string) ([]string, error) {
	var out []string
	for _, g := range operatorGroups {
		out = append(out, f.rules[g]...)
	}
	return out, f.err
}

func (f *fakeRules) ListRules(context.Context) ([]access.Rule, error) {
	var out []access.Rule
	for _, g := range slices.Sorted(maps.Keys(f.rules)) {
		out = append(out, access.Rule{OperatorGroup: g, TargetGroups: f.rules[g]})
	}
	return out, f.err
}

func (f *fakeRules) PutRule(_ context.Context, r access.Rule, _ string) error {
	if f.err != nil {
		return f.err
	}
	f.rules[r.OperatorGroup] = r.TargetGroups
	return nil
}

func (f *fakeRules) DeleteRule(_ context.Context, group string) error {
	if f.err != nil {
		return f.err
	}
	if _, ok := f.rules[group]; !ok {
		return access.ErrRuleNotFound
	}
	delete(f.rules, group)
	return nil
}

func (f *fakeRules) RenameGroup(_ context.Context, oldName, newName, _ string) (int64, error) {
	if err := cmp.Or(f.renameErr, f.err); err != nil {
		return 0, err
	}
	var changed int64
	for _, targets := range f.rules {
		for i, t := range targets {
			if t == oldName {
				targets[i] = newName
				changed++
			}
		}
	}
	if targets, ok := f.rules[oldName]; ok {
		delete(f.rules, oldName)
		f.rules[newName] = targets
		changed += int64(len(targets))
	}
	return changed, nil
}

// newTestServer returns a server for an operator in groups, with the test rules.
func newTestServer(t *testing.T, users server.UserService, rules *fakeRules, authn fakeAuth) *server.Server {
	t.Helper()
	return newAuditedServer(t, users, rules, &fakeAudit{}, authn)
}

// newAuditedServer is newTestServer recording to log.
func newAuditedServer(t *testing.T, users server.UserService, rules *fakeRules, log *fakeAudit, authn fakeAuth) *server.Server {
	t.Helper()
	policy, err := access.NewPolicy([]string{"admins"}, rules)
	if err != nil {
		t.Fatal(err)
	}
	return server.New(server.Deps{
		Users:  users,
		Auth:   authn,
		Policy: policy,
		Rules:  rules,
		Audit:  log,
		Logger: slog.New(slog.DiscardHandler),

		RecoveryEmailStage: testRecoveryStage,
	})
}

// testRecoveryStage is the email stage configured by newTestServer.
const testRecoveryStage = "5f2e8a3c-1b4d-4e6f-9a7b-0c1d2e3f4a5b"

// newServer returns a server for an access administrator (full access).
func newServer(t *testing.T, users server.UserService) *server.Server {
	t.Helper()
	return newTestServer(t, users, newFakeRules(), fakeAuth{groups: []string{"admins"}})
}

// newScopedServer returns a server for an operator in groups.
func newScopedServer(t *testing.T, users server.UserService, groups ...string) *server.Server {
	t.Helper()
	return newTestServer(t, users, newFakeRules(), fakeAuth{groups: groups})
}

// member returns a user who belongs to the named groups.
func member(groups ...string) *authentik.User {
	u := &authentik.User{Username: "target", Email: "target@example.com", Type: authentik.UserTypeInternal}
	for _, g := range groups {
		u.Groups = append(u.Groups, authentik.UserGroup{PK: "pk-" + g, Name: g})
	}
	return u
}

func TestServer_protection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		authn      fakeAuth
		header     http.Header
		wantStatus int
	}{
		{name: "unauthenticated", authn: fakeAuth{deny: true}, wantStatus: http.StatusUnauthorized},
		{
			name:       "cross-site request rejected",
			header:     http.Header{"Sec-Fetch-Site": {"cross-site"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "same-origin request allowed",
			header:     http.Header{"Sec-Fetch-Site": {"same-origin"}},
			wantStatus: http.StatusNoContent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.authn.groups = []string{"admins"}
			h := newTestServer(t, &fakeUsers{}, newFakeRules(), tt.authn)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/users/1", nil)
			maps.Copy(req.Header, tt.header)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestServer_listUsers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		target     string
		wantStatus int
	}{
		{name: "defaults", target: "/api/users", wantStatus: http.StatusOK},
		{name: "search and paging", target: "/api/users?search=ann&page=2&page_size=50", wantStatus: http.StatusOK},
		{name: "bad page", target: "/api/users?page=0", wantStatus: http.StatusBadRequest},
		{name: "page size too large", target: "/api/users?page_size=1000", wantStatus: http.StatusBadRequest},
		{name: "bad is_active", target: "/api/users?is_active=maybe", wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(t, &fakeUsers{}), http.MethodGet, tt.target, "")
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
		})
	}
}

func TestServer_listUsers_pathFilter(t *testing.T) {
	t.Parallel()
	fake := &fakeUsers{}
	rec := do(t, newServer(t, fake), http.MethodGet, "/api/users?path=users&path_startswith=users%2Fstaff", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body)
	}
	if fake.listParams.Path != "users" || fake.listParams.PathStartsWith != "users/staff" {
		t.Errorf("params = %+v, want Path=users PathStartsWith=users/staff", fake.listParams)
	}
}

func TestServer_listUsers_activeFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target string
		want   *bool
	}{
		{name: "all", target: "/api/users", want: nil},
		{name: "active", target: "/api/users?is_active=true", want: new(true)},
		{name: "inactive", target: "/api/users?is_active=false", want: new(false)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{}
			rec := do(t, newServer(t, fake), http.MethodGet, tt.target, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body)
			}
			if got := fake.listParams.IsActive; (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Errorf("IsActive = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServer_listUsers_internalOnly(t *testing.T) {
	t.Parallel()
	fake := &fakeUsers{listed: []authentik.User{
		{PK: 1, Username: "ann", Type: authentik.UserTypeInternal},
		{PK: 2, Username: "bot", Type: authentik.UserTypeServiceAccount},
		{PK: 3, Username: "guest", Type: authentik.UserTypeExternal},
	}}
	rec := do(t, newServer(t, fake), http.MethodGet, "/api/users?type=external", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body)
	}
	if !slices.Equal(fake.listParams.Type, []authentik.UserType{authentik.UserTypeInternal}) {
		t.Errorf("Type = %v, want [internal]", fake.listParams.Type)
	}
	var body authentik.UserList
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	// Non-internal users are dropped even when authentik ignored the filter.
	if len(body.Results) != 1 || body.Results[0].Username != "ann" {
		t.Errorf("results = %+v, want ann only", body.Results)
	}
}

func TestServer_listUserPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "ok", wantStatus: http.StatusOK},
		{name: "upstream failure", err: &authentik.APIError{StatusCode: 500}, wantStatus: http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(t, &fakeUsers{err: tt.err}), http.MethodGet, "/api/users/paths", "")
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if rec.Code != http.StatusOK {
				return
			}
			var body struct {
				Paths []string `json:"paths"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			if len(body.Paths) != 2 || body.Paths[1] != "users/staff" {
				t.Errorf("paths = %v", body.Paths)
			}
		})
	}
}

func TestServer_listUserPaths_noAccess(t *testing.T) {
	t.Parallel()
	rec := do(t, newScopedServer(t, &fakeUsers{}, "guests"), http.MethodGet, "/api/users/paths", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"paths":[]`) {
		t.Errorf("GET /api/users/paths = %d %s, want empty paths", rec.Code, rec.Body)
	}
}

func TestServer_createUser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       string
		err        error
		wantStatus int
		wantField  string
	}{
		{name: "ok", body: `{"username":" ann ","name":"Ann"}`, wantStatus: http.StatusCreated},
		{name: "internal type", body: `{"username":"ann","name":"Ann","type":"internal"}`, wantStatus: http.StatusCreated},
		{
			name:       "non-internal type",
			body:       `{"username":"ann","name":"Ann","type":"service_account"}`,
			wantStatus: http.StatusBadRequest,
			wantField:  "type",
		},
		{name: "missing username", body: `{"name":"Ann"}`, wantStatus: http.StatusBadRequest, wantField: "username"},
		{name: "unknown field", body: `{"username":"ann","name":"Ann","is_superuser":true}`, wantStatus: http.StatusBadRequest},
		{name: "malformed json", body: `{`, wantStatus: http.StatusBadRequest},
		{
			name:       "upstream validation passed through",
			body:       `{"username":"ann","name":"Ann"}`,
			err:        &authentik.APIError{StatusCode: 400, Fields: map[string][]string{"username": {"taken"}}},
			wantStatus: http.StatusBadRequest,
			wantField:  "username",
		},
		{
			name:       "upstream failure hidden",
			body:       `{"username":"ann","name":"Ann"}`,
			err:        &authentik.APIError{StatusCode: 403, Detail: "token invalid"},
			wantStatus: http.StatusBadGateway,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{err: tt.err}
			rec := do(t, newServer(t, fake), http.MethodPost, "/api/users", tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			var body struct {
				Error  string              `json:"error"`
				Fields map[string][]string `json:"fields"`
			}
			if rec.Code >= 400 {
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("decoding error body: %v", err)
				}
				if strings.Contains(body.Error, "token") {
					t.Errorf("error %q leaks upstream detail", body.Error)
				}
			}
			if tt.wantField != "" && len(body.Fields[tt.wantField]) == 0 {
				t.Errorf("fields = %v, want entry for %q", body.Fields, tt.wantField)
			}
			if tt.wantStatus == http.StatusCreated && fake.created.Username != "ann" {
				t.Errorf("username = %q, want trimmed %q", fake.created.Username, "ann")
			}
			if tt.wantStatus == http.StatusCreated && fake.created.Type != authentik.UserTypeInternal {
				t.Errorf("type = %q, want %q", fake.created.Type, authentik.UserTypeInternal)
			}
		})
	}
}

func TestServer_userByID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		err        error
		wantStatus int
	}{
		{name: "get", method: http.MethodGet, target: "/api/users/4", wantStatus: http.StatusOK},
		{name: "get invalid id", method: http.MethodGet, target: "/api/users/abc", wantStatus: http.StatusBadRequest},
		{name: "get negative id", method: http.MethodGet, target: "/api/users/-1", wantStatus: http.StatusBadRequest},
		{
			name:       "get not found",
			method:     http.MethodGet,
			target:     "/api/users/4",
			err:        &authentik.APIError{StatusCode: 404},
			wantStatus: http.StatusNotFound,
		},
		{name: "patch", method: http.MethodPatch, target: "/api/users/4", body: `{"is_active":false}`, wantStatus: http.StatusOK},
		{name: "patch internal type", method: http.MethodPatch, target: "/api/users/4", body: `{"type":"internal"}`, wantStatus: http.StatusOK},
		{name: "patch non-internal type", method: http.MethodPatch, target: "/api/users/4", body: `{"type":"external"}`, wantStatus: http.StatusBadRequest},
		{name: "patch bad type", method: http.MethodPatch, target: "/api/users/4", body: `{"type":"root"}`, wantStatus: http.StatusBadRequest},
		{name: "delete", method: http.MethodDelete, target: "/api/users/4", wantStatus: http.StatusNoContent},
		{name: "unknown api route", method: http.MethodGet, target: "/api/nope", wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(t, &fakeUsers{err: tt.err}), tt.method, tt.target, tt.body)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
		})
	}
}

func TestServer_static(t *testing.T) {
	t.Parallel()
	static := fstest.MapFS{
		"index.html":    {Data: []byte("<html>app</html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
	policy, err := access.NewPolicy([]string{"admins"}, newFakeRules())
	if err != nil {
		t.Fatal(err)
	}
	h := server.New(server.Deps{
		Users:  &fakeUsers{},
		Auth:   fakeAuth{},
		Policy: policy,
		Rules:  newFakeRules(),
		Audit:  &fakeAudit{},
		Logger: slog.New(slog.DiscardHandler),
		Static: static,
	})

	tests := []struct {
		name     string
		target   string
		wantBody string
	}{
		{name: "asset", target: "/assets/app.js", wantBody: "console.log(1)"},
		{name: "spa fallback", target: "/users/42", wantBody: "<html>app</html>"},
		{name: "root", target: "/", wantBody: "<html>app</html>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, h, http.MethodGet, tt.target, "")
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("GET %s = %d %q, want 200 containing %q", tt.target, rec.Code, rec.Body, tt.wantBody)
			}
		})
	}
}

func TestServer_static_cspNonce(t *testing.T) {
	t.Parallel()
	static := fstest.MapFS{
		"index.html": {Data: []byte(`<meta property="csp-nonce" nonce="__CSP_NONCE__">`)},
	}
	policy, err := access.NewPolicy([]string{"admins"}, newFakeRules())
	if err != nil {
		t.Fatal(err)
	}
	h := server.New(server.Deps{
		Users:  &fakeUsers{},
		Auth:   fakeAuth{},
		Policy: policy,
		Rules:  newFakeRules(),
		Audit:  &fakeAudit{},
		Logger: slog.New(slog.DiscardHandler),
		Static: static,
	})

	nonceOf := func(t *testing.T) string {
		t.Helper()
		rec := do(t, h, http.MethodGet, "/", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (body %s)", rec.Code, rec.Body)
		}
		body := rec.Body.String()
		nonce, ok := strings.CutPrefix(body, `<meta property="csp-nonce" nonce="`)
		nonce, _, found := strings.Cut(nonce, `"`)
		if !ok || !found || nonce == "" || nonce == "__CSP_NONCE__" {
			t.Fatalf("body = %q, want the placeholder replaced by a nonce", body)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "style-src 'self' 'nonce-"+nonce+"'") {
			t.Errorf("Content-Security-Policy = %q, want style-src allowing nonce %q", csp, nonce)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", cc)
		}
		return nonce
	}
	if first, second := nonceOf(t), nonceOf(t); first == second {
		t.Errorf("nonce %q reused across requests", first)
	}
}

func TestServer_getAccess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		groups     []string
		wantAll    bool
		wantGroups []string
	}{
		{name: "full access", groups: []string{"admins"}, wantAll: true, wantGroups: []string{}},
		{name: "restricted", groups: []string{"helpdesk"}, wantGroups: []string{"staff", "students"}},
		{name: "no rule", groups: []string{"guests"}, wantGroups: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newScopedServer(t, &fakeUsers{}, tt.groups...), http.MethodGet, "/api/access", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d (body %s)", rec.Code, rec.Body)
			}
			var got access.Scope
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			if got.All != tt.wantAll || !slices.Equal(got.Groups, tt.wantGroups) {
				t.Errorf("access = %+v, want All=%v Groups=%v", got, tt.wantAll, tt.wantGroups)
			}
		})
	}
}

func TestServer_listUsers_scoped(t *testing.T) {
	t.Parallel()
	admin := member("staff")
	admin.IsSuperuser = true
	listed := []authentik.User{*member("staff"), *member("other"), *admin, *member("students", "other")}

	t.Run("restricted operator", func(t *testing.T) {
		t.Parallel()
		fake := &fakeUsers{listed: listed}
		rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodGet, "/api/users", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (body %s)", rec.Code, rec.Body)
		}
		if !slices.Equal(fake.listParams.GroupsByName, []string{"staff", "students"}) {
			t.Errorf("GroupsByName = %v", fake.listParams.GroupsByName)
		}
		if fake.listParams.IsSuperuser == nil || *fake.listParams.IsSuperuser {
			t.Errorf("IsSuperuser = %v, want false", fake.listParams.IsSuperuser)
		}
		var body authentik.UserList
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding body: %v", err)
		}
		// Out-of-scope users are dropped even when authentik ignored the filters.
		if len(body.Results) != 2 {
			t.Errorf("results = %+v, want the staff and students members only", body.Results)
		}
	})

	t.Run("full access", func(t *testing.T) {
		t.Parallel()
		fake := &fakeUsers{listed: listed}
		rec := do(t, newScopedServer(t, fake, "admins"), http.MethodGet, "/api/users", "")
		var body authentik.UserList
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding body: %v", err)
		}
		if fake.listParams.GroupsByName != nil || fake.listParams.IsSuperuser != nil || len(body.Results) != 4 {
			t.Errorf("params = %+v, %d results, want unfiltered", fake.listParams, len(body.Results))
		}
	})

	t.Run("no access", func(t *testing.T) {
		t.Parallel()
		fake := &fakeUsers{listed: listed}
		rec := do(t, newScopedServer(t, fake, "guests"), http.MethodGet, "/api/users", "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"results":[]`) {
			t.Errorf("GET /api/users = %d %s, want empty results", rec.Code, rec.Body)
		}
	})
}

func TestServer_userByID_scoped(t *testing.T) {
	t.Parallel()
	admin := member("staff")
	admin.IsSuperuser = true
	serviceAccount := member("staff")
	serviceAccount.Type = authentik.UserTypeServiceAccount
	external := member("staff")
	external.Type = authentik.UserTypeExternal
	requests := []struct{ method, target, body string }{
		{http.MethodGet, "/api/users/4", ""},
		{http.MethodPatch, "/api/users/4", `{"name":"x"}`},
		{http.MethodPost, "/api/users/4/recovery-email", ""},
	}
	tests := []struct {
		name    string
		groups  []string
		target  *authentik.User
		allowed bool
	}{
		{name: "member of target group", groups: []string{"helpdesk"}, target: member("students"), allowed: true},
		{name: "outside target groups", groups: []string{"helpdesk"}, target: member("other"), allowed: false},
		{name: "superuser for restricted operator", groups: []string{"helpdesk"}, target: admin, allowed: false},
		{name: "superuser for full access", groups: []string{"admins"}, target: admin, allowed: true},
		{name: "operator without rule", groups: []string{"guests"}, target: member("staff"), allowed: false},
		{name: "service account for full access", groups: []string{"admins"}, target: serviceAccount, allowed: false},
		{name: "external user for full access", groups: []string{"admins"}, target: external, allowed: false},
	}
	for _, tt := range tests {
		for _, req := range requests {
			t.Run(tt.name+"/"+req.method, func(t *testing.T) {
				t.Parallel()
				fake := &fakeUsers{user: tt.target}
				rec := do(t, newScopedServer(t, fake, tt.groups...), req.method, req.target, req.body)
				if tt.allowed && rec.Code >= 400 {
					t.Errorf("status = %d, want success (body %s)", rec.Code, rec.Body)
				}
				if !tt.allowed && (rec.Code != http.StatusNotFound || fake.mutated) {
					t.Errorf("status = %d, mutated = %v, want 404 without change", rec.Code, fake.mutated)
				}
			})
		}
	}
}

func TestServer_deleteUser_admin(t *testing.T) {
	t.Parallel()
	serviceAccount := member("staff")
	serviceAccount.Type = authentik.UserTypeServiceAccount
	tests := []struct {
		name       string
		groups     []string
		target     *authentik.User
		wantStatus int
	}{
		{name: "admin", groups: []string{"admins"}, target: member("staff"), wantStatus: http.StatusNoContent},
		{name: "admin, service account", groups: []string{"admins"}, target: serviceAccount, wantStatus: http.StatusNotFound},
		{name: "restricted operator in scope", groups: []string{"helpdesk"}, target: member("staff"), wantStatus: http.StatusForbidden},
		{name: "full access without admin", groups: []string{"superhelp"}, target: member("staff"), wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: tt.target}
			rec := do(t, newScopedServer(t, fake, tt.groups...), http.MethodDelete, "/api/users/4", "")
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if wantMutated := tt.wantStatus == http.StatusNoContent; fake.mutated != wantMutated {
				t.Errorf("mutated = %v, want %v", fake.mutated, wantMutated)
			}
		})
	}
}

func TestServer_createUser_scoped(t *testing.T) {
	t.Parallel()
	groups := map[string]authentik.Group{
		"staff":    {PK: "pk-staff", Name: "staff"},
		"other":    {PK: "pk-other", Name: "other"},
		"students": {PK: "pk-students", Name: "students", IsSuperuser: true},
	}
	tests := []struct {
		name       string
		operator   string
		body       string
		wantStatus int
		wantGroups []string
	}{
		{
			name:       "restricted with own group",
			operator:   "helpdesk",
			body:       `{"username":"ann","name":"Ann","group":"staff"}`,
			wantStatus: http.StatusCreated,
			wantGroups: []string{"pk-staff"},
		},
		{
			name:       "restricted without group",
			operator:   "helpdesk",
			body:       `{"username":"ann","name":"Ann"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "restricted with foreign group",
			operator:   "helpdesk",
			body:       `{"username":"ann","name":"Ann","group":"other"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "restricted with superuser group",
			operator:   "helpdesk",
			body:       `{"username":"ann","name":"Ann","group":"students"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "raw group keys rejected",
			operator:   "helpdesk",
			body:       `{"username":"ann","name":"Ann","group":"staff","groups":["pk-admins"]}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "full access without group",
			operator:   "admins",
			body:       `{"username":"ann","name":"Ann"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "full access with any group",
			operator:   "admins",
			body:       `{"username":"ann","name":"Ann","group":"other"}`,
			wantStatus: http.StatusCreated,
			wantGroups: []string{"pk-other"},
		},
		{
			name:       "unknown group",
			operator:   "admins",
			body:       `{"username":"ann","name":"Ann","group":"nope"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "operator without rule",
			operator:   "guests",
			body:       `{"username":"ann","name":"Ann"}`,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{groups: groups}
			rec := do(t, newScopedServer(t, fake, tt.operator), http.MethodPost, "/api/users", tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if !slices.Equal(fake.created.Groups, tt.wantGroups) {
				t.Errorf("created groups = %v, want %v", fake.created.Groups, tt.wantGroups)
			}
		})
	}
}

func TestServer_setUserGroups(t *testing.T) {
	t.Parallel()
	known := map[string]authentik.Group{
		"staff":    {PK: "pk-staff", Name: "staff"},
		"students": {PK: "pk-students", Name: "students"},
		"new":      {PK: "pk-new", Name: "new"},
		"admins":   {PK: "pk-admins", Name: "admins", IsSuperuser: true},
	}
	tests := []struct {
		name        string
		operator    string
		body        string
		wantStatus  int
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name:        "full access adds and removes any group",
			operator:    "admins",
			body:        `{"groups":["staff"," new ","new"]}`,
			wantStatus:  http.StatusOK,
			wantAdded:   []string{"pk-new"},
			wantRemoved: []string{"pk-other"},
		},
		{
			name:       "full access may add an administrator group",
			operator:   "admins",
			body:       `{"groups":["staff","other","admins"]}`,
			wantStatus: http.StatusOK,
			wantAdded:  []string{"pk-admins"},
		},
		{name: "unchanged", operator: "helpdesk", body: `{"groups":["other","staff"]}`, wantStatus: http.StatusOK},
		{
			name:       "restricted adds a target group",
			operator:   "helpdesk",
			body:       `{"groups":["staff","other","students"]}`,
			wantStatus: http.StatusOK,
			wantAdded:  []string{"pk-students"},
		},
		{
			name:        "restricted swaps target groups",
			operator:    "helpdesk",
			body:        `{"groups":["students","other"]}`,
			wantStatus:  http.StatusOK,
			wantAdded:   []string{"pk-students"},
			wantRemoved: []string{"pk-staff"},
		},
		{name: "restricted adds other group", operator: "helpdesk", body: `{"groups":["staff","other","new"]}`, wantStatus: http.StatusBadRequest},
		{name: "restricted removes other group", operator: "helpdesk", body: `{"groups":["staff"]}`, wantStatus: http.StatusBadRequest},
		{name: "restricted removes last target group", operator: "helpdesk", body: `{"groups":["other"]}`, wantStatus: http.StatusBadRequest},
		{name: "unknown group", operator: "admins", body: `{"groups":["staff","other","nope"]}`, wantStatus: http.StatusBadRequest},
		{name: "malformed body", operator: "admins", body: `{"groups":"staff"}`, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: member("staff", "other"), groups: known}
			rec := do(t, newScopedServer(t, fake, tt.operator), http.MethodPut, "/api/users/4/groups", tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantStatus != http.StatusOK && fake.mutated {
				t.Errorf("groups changed on a rejected request: added %v, removed %v", fake.added, fake.removed)
			}
			if !slices.Equal(fake.added, tt.wantAdded) || !slices.Equal(fake.removed, tt.wantRemoved) {
				t.Errorf("added %v, removed %v, want %v and %v", fake.added, fake.removed, tt.wantAdded, tt.wantRemoved)
			}
			if tt.wantStatus == http.StatusBadRequest && strings.Contains(tt.name, "group") &&
				!strings.Contains(rec.Body.String(), `"groups":[`) {
				t.Errorf("body %s, want a message for the groups field", rec.Body)
			}
		})
	}
}

func TestServer_setUserGroups_restrictedSuperuserGroup(t *testing.T) {
	t.Parallel()
	fake := &fakeUsers{
		user:   member("staff"),
		groups: map[string]authentik.Group{"students": {PK: "pk-students", Name: "students", IsSuperuser: true}},
	}
	rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodPut, "/api/users/4/groups", `{"groups":["staff","students"]}`)
	if rec.Code != http.StatusBadRequest || fake.mutated {
		t.Errorf("status = %d, mutated = %v, want 400 without change", rec.Code, fake.mutated)
	}
}

func TestServer_setUserGroups_outOfScope(t *testing.T) {
	t.Parallel()
	fake := &fakeUsers{user: member("other")}
	rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodPut, "/api/users/4/groups", `{"groups":["other","staff"]}`)
	if rec.Code != http.StatusNotFound || fake.mutated {
		t.Errorf("status = %d, mutated = %v, want 404 without change", rec.Code, fake.mutated)
	}
}

func TestServer_sendRecoveryEmail(t *testing.T) {
	t.Parallel()
	noEmail := member("staff")
	noEmail.Email = ""
	tests := []struct {
		name       string
		target     *authentik.User
		err        error
		wantStatus int
	}{
		{name: "sent", target: member("staff"), wantStatus: http.StatusNoContent},
		{name: "no email address", target: noEmail, wantStatus: http.StatusBadRequest},
		{
			name:       "no recovery flow",
			target:     member("staff"),
			err:        &authentik.APIError{StatusCode: http.StatusBadRequest, Detail: "No recovery flow set."},
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: tt.target, err: tt.err}
			rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodPost, "/api/users/4/recovery-email", "")
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantStatus == http.StatusNoContent && fake.recoveryStage != testRecoveryStage {
				t.Errorf("email stage = %q, want %q", fake.recoveryStage, testRecoveryStage)
			}
		})
	}
}

func TestServer_sendRecoveryEmail_disabled(t *testing.T) {
	t.Parallel()
	rules := newFakeRules()
	policy, err := access.NewPolicy([]string{"admins"}, rules)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeUsers{user: member("staff")}
	h := server.New(server.Deps{
		Users:  fake,
		Auth:   fakeAuth{groups: []string{"admins"}},
		Policy: policy,
		Rules:  rules,
		Audit:  &fakeAudit{},
		Logger: slog.New(slog.DiscardHandler),
	})

	rec := do(t, h, http.MethodPost, "/api/users/4/recovery-email", "")
	if rec.Code != http.StatusNotImplemented || fake.mutated {
		t.Errorf("status = %d, mutated = %v, want 501 without sending", rec.Code, fake.mutated)
	}
	rec = do(t, h, http.MethodGet, "/api/access", "")
	if !strings.Contains(rec.Body.String(), `"recovery_email":false`) {
		t.Errorf("GET /api/access = %s, want recovery_email false", rec.Body)
	}
}
