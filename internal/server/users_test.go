package server_test

import (
	"cmp"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
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
	// listCalls records the parameters of every ListUsers call, in order.
	listCalls []authentik.ListUsersParams
	created   authentik.CreateUserRequest
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
	// createdGroup records the request passed to CreateGroup.
	createdGroup *authentik.CreateGroupRequest
	// createGroupErr, when set, fails CreateGroup only.
	createGroupErr error
	// groupList, when set, is returned by ListGroups.
	groupList []authentik.Group
	// userAttrs records the attributes passed to UpdateUser, in order, when set.
	userAttrs []map[string]any
	// added and removed record the group keys passed to AddUserToGroup and RemoveUserFromGroup.
	added   []string
	removed []string
	mutated bool
	// recoveryStage records the email stage passed to SendRecoveryEmail.
	recoveryStage string
	// tokens are the tokens of all users, as authentik holds them.
	tokens []authentik.Token
	// createdToken records the request passed to CreateToken.
	createdToken authentik.CreateTokenRequest
	// tokenOwner, when non-zero, is the user CreateToken assigns every token
	// to, as authentik does for API users who are no superusers.
	tokenOwner int
	// deletedTokens records the identifiers passed to DeleteToken, in order.
	deletedTokens []string
	// tokenKeyErr, when set, fails TokenKey only.
	tokenKeyErr error
	// apps are returned by ListUserApplications.
	apps []authentik.Application
	// appsUserPK records the user passed to ListUserApplications.
	appsUserPK int
	// appsErr, when set, fails ListUserApplications only.
	appsErr error
	err     error
}

func (f *fakeUsers) ListUsers(_ context.Context, p authentik.ListUsersParams) (*authentik.UserList, error) {
	f.listParams = p
	f.listCalls = append(f.listCalls, p)
	if f.err != nil {
		return nil, f.err
	}
	if f.listed != nil {
		return &authentik.UserList{Results: slices.Clone(f.listed)}, nil
	}
	return &authentik.UserList{Results: []authentik.User{{PK: 1, Username: "ann", Type: authentik.UserTypeInternal}}}, nil
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

func (f *fakeUsers) CreateGroup(_ context.Context, req authentik.CreateGroupRequest) (*authentik.Group, error) {
	f.mutated = true
	f.createdGroup = &req
	if err := cmp.Or(f.err, f.createGroupErr); err != nil {
		return nil, err
	}
	return &authentik.Group{PK: "g-new", Name: req.Name, Attributes: req.Attributes}, nil
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
	return &authentik.User{PK: 9, Username: req.Username, Name: req.Name, Type: req.Type}, nil
}

func (f *fakeUsers) UpdateUser(_ context.Context, id int, req authentik.UpdateUserRequest) (*authentik.User, error) {
	f.mutated = true
	if req.Attributes != nil {
		f.userAttrs = append(f.userAttrs, req.Attributes)
	}
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

func (f *fakeUsers) ListTokens(_ context.Context, userPK int, _ string) ([]authentik.Token, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := []authentik.Token{}
	for _, tok := range f.tokens {
		if tok.UserPK == userPK {
			out = append(out, tok)
		}
	}
	return out, nil
}

func (f *fakeUsers) ListUserApplications(_ context.Context, userPK int) ([]authentik.Application, error) {
	if f.appsErr != nil {
		return nil, f.appsErr
	}
	if f.err != nil {
		return nil, f.err
	}
	f.appsUserPK = userPK
	return f.apps, nil
}

func (f *fakeUsers) GetToken(_ context.Context, identifier string) (*authentik.Token, error) {
	if f.err != nil {
		return nil, f.err
	}
	i := slices.IndexFunc(f.tokens, func(tok authentik.Token) bool { return tok.Identifier == identifier })
	if i < 0 {
		return nil, authentik.ErrNotFound
	}
	tok := f.tokens[i]
	return &tok, nil
}

func (f *fakeUsers) CreateToken(_ context.Context, req authentik.CreateTokenRequest) (*authentik.Token, error) {
	f.mutated = true
	f.createdToken = req
	if f.err != nil {
		return nil, f.err
	}
	tok := authentik.Token{
		Identifier:  req.Identifier,
		Intent:      req.Intent,
		Description: req.Description,
		UserPK:      cmp.Or(f.tokenOwner, req.UserPK),
		Expiring:    req.Expiring,
		Expires:     req.Expires,
	}
	f.tokens = append(f.tokens, tok)
	return &tok, nil
}

func (f *fakeUsers) TokenKey(context.Context, string) (string, error) {
	if err := cmp.Or(f.tokenKeyErr, f.err); err != nil {
		return "", err
	}
	return "s3cret-key", nil
}

func (f *fakeUsers) DeleteToken(_ context.Context, identifier string) error {
	f.mutated = true
	f.deletedTokens = append(f.deletedTokens, identifier)
	if f.err != nil {
		return f.err
	}
	f.tokens = slices.DeleteFunc(f.tokens, func(tok authentik.Token) bool { return tok.Identifier == identifier })
	return nil
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

// primaryGroupAttribute is the user attribute holding the primary key of the user's primary group.
const primaryGroupAttribute = "authentik_manager_primary_group"

// withPrimary sets the primary group of u, created by member, to the group
// named name, next to an attribute of another application.
func withPrimary(u *authentik.User, name string) *authentik.User {
	u.Attributes = map[string]any{"other_app": "kept", primaryGroupAttribute: "pk-" + name}
	return u
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

func TestServer_listAccountPaths(t *testing.T) {
	t.Parallel()
	inGroup := func(username, path, group string) authentik.User {
		return authentik.User{
			Username: username,
			Path:     path,
			Type:     authentik.UserTypeInternal,
			Groups:   []authentik.UserGroup{{Name: group}},
		}
	}
	hidden := inGroup("hal", "hidden/only", "staff")
	hidden.Attributes = map[string]any{access.HiddenAttribute: true}
	service := inGroup("svc", "services", "staff")
	service.Type = authentik.UserTypeServiceAccount
	listed := []authentik.User{
		inGroup("ann", "users/staff", "staff"),
		inGroup("bob", "users/staff", "students"),
		inGroup("cat", "users", "staff"),
		inGroup("dan", "", "staff"),
		inGroup("eve", "other", "guests"),
		// The operator's own account, outside the helpdesk scope.
		inGroup("admin", "own", "guests"),
		hidden,
		service,
	}
	tests := []struct {
		name       string
		groups     []string
		err        error
		wantStatus int
		wantPaths  []string
	}{
		{
			name:       "access administrator sees the folders of every internal user",
			groups:     []string{"admins"},
			wantStatus: http.StatusOK,
			wantPaths:  []string{"hidden/only", "other", "own", "users", "users/staff"},
		},
		{
			name:       "operator sees only the folders of visible users and their own",
			groups:     []string{"helpdesk"},
			wantStatus: http.StatusOK,
			wantPaths:  []string{"own", "users", "users/staff"},
		},
		{
			name:       "upstream failure",
			groups:     []string{"admins"},
			err:        &authentik.APIError{StatusCode: 500},
			wantStatus: http.StatusBadGateway,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{listed: listed, err: tt.err}
			rec := do(t, newScopedServer(t, fake, tt.groups...), http.MethodGet, "/api/users/paths", "")
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
			if !slices.Equal(body.Paths, tt.wantPaths) {
				t.Errorf("paths = %v, want %v", body.Paths, tt.wantPaths)
			}
			if p := fake.listCalls[0]; !slices.Equal(p.Type, []authentik.UserType{authentik.UserTypeInternal}) {
				t.Errorf("Type = %v, want [internal]", p.Type)
			}
		})
	}
}

func TestServer_listAccountPaths_serviceAccounts(t *testing.T) {
	t.Parallel()
	account := func(username, path, group string, typ authentik.UserType) authentik.User {
		return authentik.User{
			Username: username,
			Path:     path,
			Type:     typ,
			Groups:   []authentik.UserGroup{{Name: group}},
		}
	}
	fake := &fakeUsers{listed: []authentik.User{
		account("ci", "service-accounts/ci", "staff", authentik.UserTypeServiceAccount),
		account("backup", "service-accounts", "staff", authentik.UserTypeServiceAccount),
		account("other", "service-accounts/other", "guests", authentik.UserTypeServiceAccount),
		account("ann", "users", "staff", authentik.UserTypeInternal),
		// The operator's own account is no service account, so its folder is left out.
		account("admin", "own", "guests", authentik.UserTypeInternal),
	}}
	rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodGet, "/api/service-accounts/paths", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body)
	}
	var body struct {
		Paths []string `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if want := []string{"service-accounts", "service-accounts/ci"}; !slices.Equal(body.Paths, want) {
		t.Errorf("paths = %v, want %v", body.Paths, want)
	}
	if p := fake.listCalls[0]; !slices.Equal(p.Type, []authentik.UserType{authentik.UserTypeServiceAccount}) {
		t.Errorf("Type = %v, want [service_account]", p.Type)
	}
}

func TestServer_listAccountPaths_scopeFilters(t *testing.T) {
	t.Parallel()
	fake := &fakeUsers{}
	rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodGet, "/api/users/paths", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body)
	}
	// Filter upstream too, so that pages stay full of users the operator may see.
	p := fake.listCalls[0]
	if !slices.Equal(p.GroupsByName, []string{"staff", "students"}) {
		t.Errorf("GroupsByName = %v, want [staff students]", p.GroupsByName)
	}
	if p.IsSuperuser == nil || *p.IsSuperuser {
		t.Errorf("IsSuperuser = %v, want false", p.IsSuperuser)
	}
	if !slices.Equal(p.WithoutAttributes, []string{access.HiddenAttribute}) {
		t.Errorf("WithoutAttributes = %v, want [%s]", p.WithoutAttributes, access.HiddenAttribute)
	}
}

func TestServer_listAccountPaths_noAccess(t *testing.T) {
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
		{
			name:       "patch attributes refused",
			method:     http.MethodPatch,
			target:     "/api/users/4",
			body:       `{"attributes":{"authentik_manager_primary_group":"pk-admins"}}`,
			wantStatus: http.StatusBadRequest,
		},
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

// self returns the account of the operator signed in by fakeAuth, a member of the named groups.
func self(groups ...string) *authentik.User {
	u := member(groups...)
	u.Username = "admin"
	return u
}

func TestServer_listUsers_self(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		groups   []string
		target   string
		listed   []authentik.User
		expected []string
		// selfChangeable is whether the own account, when listed, may be changed.
		selfChangeable bool
		// wantCount, when set, is the expected total count.
		wantCount int
	}{
		{
			name:      "no access sees only themselves",
			groups:    []string{"guests"},
			target:    "/api/users",
			listed:    []authentik.User{*member("staff"), *self("guests")},
			expected:  []string{"admin"},
			wantCount: 1,
		},
		{
			name:     "outside the scope goes first",
			groups:   []string{"helpdesk"},
			target:   "/api/users",
			listed:   []authentik.User{*member("staff"), *self("other")},
			expected: []string{"admin", "target"},
		},
		{
			name:           "inside the scope is listed once",
			groups:         []string{"helpdesk"},
			target:         "/api/users",
			listed:         []authentik.User{*member("staff"), *self("staff")},
			expected:       []string{"target", "admin"},
			selfChangeable: true,
		},
		{
			name:     "only on the first page",
			groups:   []string{"helpdesk"},
			target:   "/api/users?page=2",
			listed:   []authentik.User{*member("staff"), *self("other")},
			expected: []string{"target"},
		},
		{
			name:     "not matching the filters",
			groups:   []string{"guests"},
			target:   "/api/users?search=ann",
			listed:   []authentik.User{*member("staff")},
			expected: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{listed: tt.listed}
			rec := do(t, newScopedServer(t, fake, tt.groups...), http.MethodGet, tt.target, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d (body %s)", rec.Code, rec.Body)
			}
			var body struct {
				Pagination authentik.Pagination `json:"pagination"`
				Results    []struct {
					Username   string `json:"username"`
					Changeable bool   `json:"changeable"`
				} `json:"results"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			usernames := []string{}
			for _, u := range body.Results {
				usernames = append(usernames, u.Username)
				if u.Username == "admin" && u.Changeable != tt.selfChangeable {
					t.Errorf("own account changeable = %v, want %v", u.Changeable, tt.selfChangeable)
				}
			}
			if !slices.Equal(usernames, tt.expected) {
				t.Errorf("usernames = %v, want %v", usernames, tt.expected)
			}
			if tt.wantCount != 0 && body.Pagination.Count != tt.wantCount {
				t.Errorf("count = %d, want %d", body.Pagination.Count, tt.wantCount)
			}
			// The own account is looked up with the list's filters, but without the scope.
			own := fake.listCalls[0]
			if own.Username != "admin" || own.GroupsByName != nil || own.IsSuperuser != nil {
				t.Errorf("own account looked up with %+v", own)
			}
			target, err := url.Parse(tt.target)
			if err != nil {
				t.Fatal(err)
			}
			if want := target.Query().Get("search"); own.Search != want {
				t.Errorf("own account search = %q, want the list's %q", own.Search, want)
			}
		})
	}
}

// hidden marks u, created by member, as hidden from operators who are not
// access administrators, next to an attribute of another application.
func hidden(u *authentik.User) *authentik.User {
	u.Attributes = map[string]any{"other_app": "kept", access.HiddenAttribute: true}
	return u
}

func TestServer_listUsers_hidden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		groups []string
		listed []authentik.User
		// expected are the listed usernames; authentik ignoring the filter is simulated.
		expected   []string
		wantFilter bool
	}{
		{
			name:     "access administrator sees hidden users",
			groups:   []string{"admins"},
			listed:   []authentik.User{*member("staff"), *hidden(member("staff"))},
			expected: []string{"target", "target"},
		},
		{
			name:       "wildcard rule hides them",
			groups:     []string{"superhelp"},
			listed:     []authentik.User{*member("staff"), *hidden(member("other"))},
			expected:   []string{"target"},
			wantFilter: true,
		},
		{
			name:       "restricted operator does not see hidden members",
			groups:     []string{"helpdesk"},
			listed:     []authentik.User{*member("staff"), *hidden(member("staff"))},
			expected:   []string{"target"},
			wantFilter: true,
		},
		{
			name:       "hidden operator sees their own account",
			groups:     []string{"superhelp"},
			listed:     []authentik.User{*member("staff"), *hidden(self("staff"))},
			expected:   []string{"admin", "target"},
			wantFilter: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{listed: tt.listed}
			rec := do(t, newScopedServer(t, fake, tt.groups...), http.MethodGet, "/api/users", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d (body %s)", rec.Code, rec.Body)
			}
			var body authentik.UserList
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			usernames := []string{}
			for _, u := range body.Results {
				usernames = append(usernames, u.Username)
			}
			if !slices.Equal(usernames, tt.expected) {
				t.Errorf("usernames = %v, want %v", usernames, tt.expected)
			}
			for _, p := range fake.listCalls {
				// The own account is looked up whether hidden or not.
				wantFilter := tt.wantFilter && p.Username == ""
				if got := slices.Equal(p.WithoutAttributes, []string{access.HiddenAttribute}); got != wantFilter {
					t.Errorf("ListUsers(%+v) filters hidden users = %v, want %v", p, got, wantFilter)
				}
			}
		})
	}
}

func TestServer_updateUser_hidden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		groups     []string
		target     *authentik.User
		body       string
		wantStatus int
		// expected are the attributes sent to authentik, or nil when none are.
		expected map[string]any
	}{
		{
			name:       "access administrator hides",
			groups:     []string{"admins"},
			target:     withPrimary(member("staff"), "staff"),
			body:       `{"hidden":true}`,
			wantStatus: http.StatusOK,
			expected:   map[string]any{"other_app": "kept", primaryGroupAttribute: "pk-staff", access.HiddenAttribute: true},
		},
		{
			name:       "access administrator shows",
			groups:     []string{"admins"},
			target:     hidden(member("staff")),
			body:       `{"hidden":false}`,
			wantStatus: http.StatusOK,
			expected:   map[string]any{"other_app": "kept"},
		},
		{
			name:       "unchanged is not sent",
			groups:     []string{"admins"},
			target:     hidden(member("staff")),
			body:       `{"hidden":true,"name":"x"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "wildcard rule may not hide",
			groups:     []string{"superhelp"},
			target:     member("staff"),
			body:       `{"hidden":true}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "restricted operator may send the unchanged value",
			groups:     []string{"helpdesk"},
			target:     member("staff"),
			body:       `{"hidden":false,"name":"x"}`,
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: tt.target}
			log := &fakeAudit{}
			srv := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: tt.groups})
			rec := do(t, srv, http.MethodPatch, "/api/users/4", tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantStatus == http.StatusForbidden && fake.mutated {
				t.Error("user changed although forbidden")
			}
			var sent map[string]any
			if len(fake.userAttrs) > 0 {
				sent = fake.userAttrs[0]
			}
			if !maps.Equal(sent, tt.expected) {
				t.Errorf("attributes = %v, want %v", sent, tt.expected)
			}
		})
	}
}

func TestServer_createUser_hidden(t *testing.T) {
	t.Parallel()
	groups := map[string]authentik.Group{"staff": {PK: "pk-staff", Name: "staff"}}
	body := `{"username":"bob","name":"Bob","group":"staff","hidden":true}`

	t.Run("access administrator", func(t *testing.T) {
		t.Parallel()
		fake := &fakeUsers{groups: groups}
		rec := do(t, newServer(t, fake), http.MethodPost, "/api/users", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d (body %s)", rec.Code, rec.Body)
		}
		expected := map[string]any{primaryGroupAttribute: "pk-staff", access.HiddenAttribute: true}
		if !maps.Equal(fake.created.Attributes, expected) {
			t.Errorf("attributes = %v, want %v", fake.created.Attributes, expected)
		}
	})

	t.Run("restricted operator", func(t *testing.T) {
		t.Parallel()
		fake := &fakeUsers{groups: groups}
		rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodPost, "/api/users", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"hidden"`) {
			t.Errorf("status = %d (body %s), want 400 for hidden", rec.Code, rec.Body)
		}
		if fake.created.Username != "" {
			t.Error("user created although hiding is forbidden")
		}
	})
}

func TestServer_getUser_primaryGroup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		user     *authentik.User
		expected string
	}{
		{name: "set", user: withPrimary(member("staff", "other"), "other"), expected: "other"},
		{name: "unset", user: member("staff"), expected: ""},
		{name: "no longer a member", user: withPrimary(member("staff"), "other"), expected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(t, &fakeUsers{user: tt.user}), http.MethodGet, "/api/users/4", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body)
			}
			var body struct {
				Username     string `json:"username"`
				PrimaryGroup string `json:"primary_group"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			if body.PrimaryGroup != tt.expected || body.Username != "target" {
				t.Errorf("username %q, primary_group %q, want %q and %q", body.Username, body.PrimaryGroup, "target", tt.expected)
			}
		})
	}
}

func TestServer_createUser_primaryGroup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		body     string
		expected map[string]any
	}{
		{
			name:     "group becomes the primary group",
			body:     `{"username":"ann","name":"Ann","group":"staff"}`,
			expected: map[string]any{primaryGroupAttribute: "pk-staff"},
		},
		{name: "no group", body: `{"username":"ann","name":"Ann"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{groups: map[string]authentik.Group{"staff": {PK: "pk-staff", Name: "staff"}}}
			rec := do(t, newServer(t, fake), http.MethodPost, "/api/users", tt.body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201 (body %s)", rec.Code, rec.Body)
			}
			if !maps.Equal(fake.created.Attributes, tt.expected) {
				t.Errorf("attributes = %v, want %v", fake.created.Attributes, tt.expected)
			}
		})
	}
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
		{name: "hidden member for restricted operator", groups: []string{"helpdesk"}, target: hidden(member("students")), allowed: false},
		{name: "hidden user for wildcard rule", groups: []string{"superhelp"}, target: hidden(member("staff")), allowed: false},
		{name: "hidden user for access administrator", groups: []string{"admins"}, target: hidden(member("staff")), allowed: true},
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

func TestServer_userByID_self(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		method     string
		groups     []string
		target     *authentik.User
		wantStatus int
	}{
		{name: "get outside the scope", method: http.MethodGet, groups: []string{"guests"}, target: self("other"), wantStatus: http.StatusOK},
		{name: "change outside the scope", method: http.MethodPatch, groups: []string{"guests"}, target: self("other"), wantStatus: http.StatusForbidden},
		{name: "change inside the scope", method: http.MethodPatch, groups: []string{"helpdesk"}, target: self("staff"), wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: tt.target}
			body := ""
			if tt.method == http.MethodPatch {
				body = `{"name":"x"}`
			}
			rec := do(t, newScopedServer(t, fake, tt.groups...), tt.method, "/api/users/4", body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantStatus == http.StatusForbidden && fake.mutated {
				t.Error("own account changed outside the scope")
			}
		})
	}

	t.Run("get reports read-only", func(t *testing.T) {
		t.Parallel()
		rec := do(t, newScopedServer(t, &fakeUsers{user: self("other")}, "guests"), http.MethodGet, "/api/users/4", "")
		if !strings.Contains(rec.Body.String(), `"changeable":false`) {
			t.Errorf("body = %s, want changeable false", rec.Body)
		}
	})
}

func TestServer_changeUser_primaryGroup(t *testing.T) {
	t.Parallel()
	requests := []struct{ method, target, body string }{
		{http.MethodPatch, "/api/users/4", `{"name":"x"}`},
		{http.MethodPut, "/api/users/4/groups", `{"groups":["staff","other"]}`},
		{http.MethodPost, "/api/users/4/recovery-email", ""},
	}
	tests := []struct {
		name     string
		operator string
		// primary is the name of the user's primary group; empty for none.
		primary  string
		expected bool
	}{
		{name: "primary group in scope", operator: "helpdesk", primary: "staff", expected: true},
		{name: "primary group outside scope", operator: "helpdesk", primary: "other", expected: false},
		{name: "no primary group", operator: "helpdesk", expected: true},
		{name: "all users", operator: "superhelp", primary: "other", expected: true},
		{name: "access administrator", operator: "admins", primary: "other", expected: true},
	}
	for _, tt := range tests {
		newTarget := func() *authentik.User {
			user := member("staff", "other")
			if tt.primary != "" {
				withPrimary(user, tt.primary)
			}
			return user
		}
		t.Run(tt.name+"/GET", func(t *testing.T) {
			t.Parallel()
			rec := do(t, newScopedServer(t, &fakeUsers{user: newTarget()}, tt.operator), http.MethodGet, "/api/users/4", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body)
			}
			var body struct {
				Changeable bool `json:"changeable"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			if body.Changeable != tt.expected {
				t.Errorf("changeable = %v, want %v", body.Changeable, tt.expected)
			}
		})
		for _, req := range requests {
			t.Run(tt.name+"/"+req.method+" "+req.target, func(t *testing.T) {
				t.Parallel()
				fake := &fakeUsers{user: newTarget()}
				log := &fakeAudit{}
				h := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: []string{tt.operator}})
				rec := do(t, h, req.method, req.target, req.body)
				if tt.expected {
					if rec.Code >= 400 {
						t.Errorf("status = %d, want success (body %s)", rec.Code, rec.Body)
					}
					return
				}
				if rec.Code != http.StatusForbidden || fake.mutated {
					t.Errorf("status = %d, mutated = %v, want 403 without change", rec.Code, fake.mutated)
				}
				denied := slices.ContainsFunc(log.recorded, func(e audit.Entry) bool { return e.Action == audit.ActionAccessDenied })
				if !denied {
					t.Errorf("recorded %v, want an access denied entry", log.recorded)
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

func TestServer_setUserGroups_accessAdminGroup(t *testing.T) {
	t.Parallel()
	known := map[string]authentik.Group{"admins": {PK: "pk-admins", Name: "admins"}}
	tests := []struct {
		name       string
		operator   string
		wantStatus int
	}{
		// Full access to the users does not make an operator an access administrator.
		{name: "full access", operator: "superhelp", wantStatus: http.StatusBadRequest},
		{name: "access administrator", operator: "admins", wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: member("staff"), groups: known}
			rec := do(t, newScopedServer(t, fake, tt.operator), http.MethodPut, "/api/users/4/groups", `{"groups":["staff","admins"]}`)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantStatus != http.StatusOK && fake.mutated {
				t.Errorf("groups changed on a rejected request: added %v", fake.added)
			}
		})
	}
}

func TestServer_setUserGroups_own(t *testing.T) {
	t.Parallel()
	known := map[string]authentik.Group{"students": {PK: "pk-students", Name: "students"}}
	tests := []struct {
		name       string
		operator   string
		wantStatus int
	}{
		{name: "restricted", operator: "helpdesk", wantStatus: http.StatusForbidden},
		{name: "full access", operator: "superhelp", wantStatus: http.StatusForbidden},
		{name: "access administrator", operator: "admins", wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// The test operator is named "admin".
			self := member("staff")
			self.Username = "admin"
			fake := &fakeUsers{user: self, groups: known}
			log := &fakeAudit{}
			h := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: []string{tt.operator}})
			rec := do(t, h, http.MethodPut, "/api/users/4/groups", `{"groups":["staff","students"]}`)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantStatus != http.StatusOK {
				if fake.mutated {
					t.Errorf("groups changed on a rejected request: added %v", fake.added)
				}
				if !strings.Contains(rec.Body.String(), `"groups":[`) {
					t.Errorf("body %s, want a message for the groups field", rec.Body)
				}
				if !slices.ContainsFunc(log.recorded, func(e audit.Entry) bool { return e.Action == audit.ActionAccessDenied }) {
					t.Errorf("audit = %v, want an access denied entry", log.recorded)
				}
			}
		})
	}
}

func TestServer_createUser_accessAdminGroup(t *testing.T) {
	t.Parallel()
	fake := &fakeUsers{groups: map[string]authentik.Group{"admins": {PK: "pk-admins", Name: "admins"}}}
	rec := do(t, newScopedServer(t, fake, "superhelp"), http.MethodPost, "/api/users", `{"username":"ann","name":"Ann","group":"admins"}`)
	if rec.Code != http.StatusBadRequest || fake.created.Username != "" {
		t.Errorf("status = %d (body %s), created %q, want 400 and nothing created", rec.Code, rec.Body, fake.created.Username)
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

func TestServer_setUserGroups_primaryGroup(t *testing.T) {
	t.Parallel()
	known := map[string]authentik.Group{
		"staff":    {PK: "pk-staff", Name: "staff"},
		"students": {PK: "pk-students", Name: "students"},
		"other":    {PK: "pk-other", Name: "other"},
	}
	tests := []struct {
		name     string
		operator string
		// primary is the name of the user's current primary group; empty for none.
		primary        string
		body           string
		expectedStatus int
		// expectedField is the field of the validation message, if any.
		expectedField string
		// expectedPrimary is the primary key stored, "" when removed, or nil when unchanged.
		expectedPrimary *string
		expectedRemoved []string
	}{
		{
			name:            "set to a current group",
			operator:        "admins",
			body:            `{"groups":["staff","other"],"primary_group":"other"}`,
			expectedStatus:  http.StatusOK,
			expectedPrimary: new("pk-other"),
		},
		{
			name:            "set to a joined group",
			operator:        "admins",
			body:            `{"groups":["staff","other","students"],"primary_group":" students "}`,
			expectedStatus:  http.StatusOK,
			expectedPrimary: new("pk-students"),
		},
		{
			name:            "changed while leaving the previous one",
			operator:        "admins",
			primary:         "staff",
			body:            `{"groups":["other"],"primary_group":"other"}`,
			expectedStatus:  http.StatusOK,
			expectedPrimary: new("pk-other"),
			expectedRemoved: []string{"pk-staff"},
		},
		{
			name:            "removed",
			operator:        "admins",
			primary:         "staff",
			body:            `{"groups":["staff","other"],"primary_group":""}`,
			expectedStatus:  http.StatusOK,
			expectedPrimary: new(""),
		},
		{
			name:           "kept when omitted",
			operator:       "admins",
			primary:        "staff",
			body:           `{"groups":["staff","other","students"]}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "unchanged",
			operator:       "admins",
			primary:        "staff",
			body:           `{"groups":["staff","other"],"primary_group":"staff"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "leaving the primary group refused",
			operator:       "admins",
			primary:        "staff",
			body:           `{"groups":["other"]}`,
			expectedStatus: http.StatusBadRequest,
			expectedField:  "groups",
		},
		{
			name:           "leaving the primary group refused when named again",
			operator:       "admins",
			primary:        "staff",
			body:           `{"groups":["other"],"primary_group":"staff"}`,
			expectedStatus: http.StatusBadRequest,
			expectedField:  "groups",
		},
		{
			name:           "not one of the groups",
			operator:       "admins",
			body:           `{"groups":["staff","other"],"primary_group":"students"}`,
			expectedStatus: http.StatusBadRequest,
			expectedField:  "primary_group",
		},
		{
			name:            "restricted sets a target group",
			operator:        "helpdesk",
			body:            `{"groups":["staff","other"],"primary_group":"staff"}`,
			expectedStatus:  http.StatusOK,
			expectedPrimary: new("pk-staff"),
		},
		{
			name:           "restricted sets another group",
			operator:       "helpdesk",
			body:           `{"groups":["staff","other"],"primary_group":"other"}`,
			expectedStatus: http.StatusBadRequest,
			expectedField:  "primary_group",
		},
		{
			name:           "restricted changes another group",
			operator:       "helpdesk",
			primary:        "other",
			body:           `{"groups":["staff","other"],"primary_group":"staff"}`,
			expectedStatus: http.StatusForbidden,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user := member("staff", "other")
			if tt.primary != "" {
				withPrimary(user, tt.primary)
			}
			fake := &fakeUsers{user: user, groups: known}
			log := &fakeAudit{}
			h := newAuditedServer(t, fake, newFakeRules(), log, fakeAuth{groups: []string{tt.operator}})
			rec := do(t, h, http.MethodPut, "/api/users/4/groups", tt.body)
			if rec.Code != tt.expectedStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.expectedStatus, rec.Body)
			}
			if tt.expectedField != "" {
				if !strings.Contains(rec.Body.String(), `"`+tt.expectedField+`":[`) {
					t.Errorf("body %s, want a message for the %s field", rec.Body, tt.expectedField)
				}
				if fake.mutated {
					t.Errorf("user changed on a rejected request")
				}
			}
			if !slices.Equal(fake.removed, tt.expectedRemoved) {
				t.Errorf("removed %v, want %v", fake.removed, tt.expectedRemoved)
			}
			checkPrimaryUpdate(t, fake, log, tt.expectedPrimary)
		})
	}
}

// checkPrimaryUpdate checks that the primary group attribute was set to the
// primary key expected, removed when it is empty, or left alone when it is
// nil, and that the user's other attributes were kept.
func checkPrimaryUpdate(t *testing.T, fake *fakeUsers, log *fakeAudit, expected *string) {
	t.Helper()
	recordedChange := slices.ContainsFunc(log.recorded, func(e audit.Entry) bool {
		return e.Action == audit.ActionUserPrimaryGroupChanged
	})
	if expected == nil {
		if len(fake.userAttrs) != 0 || recordedChange {
			t.Errorf("attributes updated to %v (audit %v), want no update", fake.userAttrs, recordedChange)
		}
		return
	}
	if len(fake.userAttrs) != 1 || !recordedChange {
		t.Fatalf("attributes updated %v (audit %v), want one update", fake.userAttrs, recordedChange)
	}
	attrs := fake.userAttrs[0]
	got, ok := attrs[primaryGroupAttribute]
	if *expected == "" && ok || *expected != "" && got != *expected {
		t.Errorf("primary group attribute = %v, want %q", got, *expected)
	}
	if other, ok := fake.user.Attributes["other_app"]; ok && attrs["other_app"] != other {
		t.Errorf("attributes = %v, want the other attributes kept", attrs)
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
