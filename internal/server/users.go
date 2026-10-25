package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// Page sizes of the paginated lists.
const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// accountKind is a type of authentik account the application manages, with
// the audit actions recorded for it. Internal users and service accounts share
// the access rules and most handlers; other account types are never managed.
type accountKind struct {
	typ authentik.UserType
	// noun names the accounts in messages, e.g. "user".
	noun string
	// typeError is the validation message for a request naming another type.
	typeError                 string
	created, updated, deleted audit.Action
}

// The managed account kinds.
var (
	userAccounts = accountKind{
		typ:       authentik.UserTypeInternal,
		noun:      "user",
		typeError: "Only internal users can be managed.",
		created:   audit.ActionUserCreated,
		updated:   audit.ActionUserUpdated,
		deleted:   audit.ActionUserDeleted,
	}
	serviceAccounts = accountKind{
		typ:       authentik.UserTypeServiceAccount,
		noun:      "service account",
		typeError: "The type of a service account cannot be changed.",
		created:   audit.ActionServiceAccountCreated,
		updated:   audit.ActionServiceAccountUpdated,
		deleted:   audit.ActionServiceAccountDeleted,
	}
)

// seesOwnAccount reports whether operators see their own account of this kind
// even outside their scope; only internal users sign in.
func (k accountKind) seesOwnAccount() bool {
	return k.typ == authentik.UserTypeInternal
}

// primaryGroupAttribute is the authentik user attribute holding the primary key
// of the user's primary group. It holds the key rather than the name, so
// renaming the group keeps it.
const primaryGroupAttribute = "authentik_manager_primary_group"

// primaryGroup returns the primary group of u, or nil when none is set or u is
// no longer a direct member of it.
func primaryGroup(u *authentik.User) *authentik.UserGroup {
	pk, ok := u.Attributes[primaryGroupAttribute].(string)
	if !ok || pk == "" {
		return nil
	}
	i := slices.IndexFunc(u.Groups, func(g authentik.UserGroup) bool { return g.PK == pk })
	if i < 0 {
		return nil
	}
	return &u.Groups[i]
}

// primaryGroupName returns the name of the primary group of u, or "" when it has none.
func primaryGroupName(u *authentik.User) string {
	if g := primaryGroup(u); g != nil {
		return g.Name
	}
	return ""
}

// withPrimaryGroup returns a copy of attrs with the primary group set to the
// group with primary key pk, or removed when pk is empty, leaving the other
// attributes as they are. It never returns nil, so an update clearing the last
// attribute is still sent.
func withPrimaryGroup(attrs map[string]any, pk string) map[string]any {
	out := maps.Clone(attrs)
	if out == nil {
		out = map[string]any{}
	}
	if pk != "" {
		out[primaryGroupAttribute] = pk
	} else {
		delete(out, primaryGroupAttribute)
	}
	return out
}

// withHidden returns a copy of attrs with the user hidden from operators who
// are not access administrators, or shown again, leaving the other attributes
// as they are. It never returns nil, so an update clearing the last attribute
// is still sent.
func withHidden(attrs map[string]any, hidden bool) map[string]any {
	out := maps.Clone(attrs)
	if out == nil {
		out = map[string]any{}
	}
	if hidden {
		out[access.HiddenAttribute] = true
	} else {
		delete(out, access.HiddenAttribute)
	}
	return out
}

// mayChange reports whether an operator with scope may change u. Only the
// operators managing the user's primary group may change a user who has one,
// so the operators of the user's other groups cannot take the user over. Users
// see their own account even outside their scope, but may not change it then.
func mayChange(u *authentik.User, scope access.Scope) bool {
	if !scope.Allows(u) {
		return false
	}
	g := primaryGroupName(u)
	return g == "" || scope.HasGroup(g)
}

// userView is a user as operators see it.
type userView struct {
	authentik.User
	// PrimaryGroup is the name of the user's primary group; empty when none is set.
	PrimaryGroup string `json:"primary_group"`
	// Changeable is set when the operator may change the user (see mayChange).
	Changeable bool `json:"changeable"`
	// Hidden is set when only access administrators may see the user (see access.IsHidden).
	Hidden bool `json:"hidden"`
}

func newUserView(u *authentik.User, scope access.Scope) userView {
	return userView{
		User:         *u,
		PrimaryGroup: primaryGroupName(u),
		Changeable:   mayChange(u, scope),
		Hidden:       access.IsHidden(u),
	}
}

func newUserPage(list *authentik.UserList, scope access.Scope) page[userView] {
	out := page[userView]{Pagination: list.Pagination, Results: make([]userView, len(list.Results))}
	for i := range list.Results {
		out.Results[i] = newUserView(&list.Results[i], scope)
	}
	return out
}

// parsePaging parses the page and page_size query parameters, which default to
// the first page of defaultPageSize entries. It writes a 400 response when they are invalid.
func parsePaging(w http.ResponseWriter, q url.Values) (page, size int, ok bool) {
	page, size = 1, defaultPageSize
	var err error
	if v := q.Get("page"); v != "" {
		if page, err = strconv.Atoi(v); err != nil || page < 1 {
			writeError(w, http.StatusBadRequest, "page must be a positive integer", nil)
			return 0, 0, false
		}
	}
	if v := q.Get("page_size"); v != "" {
		if size, err = strconv.Atoi(v); err != nil || size < 1 || size > maxPageSize {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("page_size must be between 1 and %d", maxPageSize), nil)
			return 0, 0, false
		}
	}
	return page, size, true
}

// listAccounts returns a handler listing the accounts of kind k the operator
// may see, filtered and paged by the query parameters.
func (s *Server) listAccounts(k accountKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.listAccountsOf(w, r, k)
	}
}

func (s *Server) listAccountsOf(w http.ResponseWriter, r *http.Request, k accountKind) {
	q := r.URL.Query()
	params := authentik.ListUsersParams{
		Search:         q.Get("search"),
		Ordering:       q.Get("ordering"),
		Path:           q.Get("path"),
		PathStartsWith: q.Get("path_startswith"),
		// Only accounts of kind k are listed; other types are hidden.
		Type: []authentik.UserType{k.typ},
	}
	var ok bool
	if params.Page, params.PageSize, ok = parsePaging(w, q); !ok {
		return
	}
	if v := q.Get("is_active"); v != "" {
		active, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "is_active must be true or false", nil)
			return
		}
		params.IsActive = &active
	}

	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	if !scope.IncludesHidden {
		// Leave the hidden users out upstream, so that every page stays full.
		params.WithoutAttributes = []string{access.HiddenAttribute}
	}

	self, err := s.ownAccountOutsideScope(r, k, params, scope)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	list := &authentik.UserList{Results: []authentik.User{}}
	if !scope.Empty() {
		scoped := params
		if !scope.All {
			scoped.GroupsByName = scope.Groups
			scoped.IsSuperuser = new(false)
		}
		if list, err = s.users.ListUsers(r.Context(), scoped); err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		// Defense in depth: authentik silently ignores filters it does not know,
		// so drop anything outside the scope or of another type even if the filters were not applied.
		list.Results = slices.DeleteFunc(list.Results, func(u authentik.User) bool {
			return u.Type != k.typ || !scope.Allows(&u)
		})
	}
	if self != nil {
		addSelf(list, self, params.Page)
	}
	writeJSON(w, http.StatusOK, newUserPage(list, scope))
}

// ownAccountOutsideScope returns the operator's own account of kind k when it
// matches the filters of params but is outside scope, or nil otherwise. Every
// user sees their own account, even outside their scope.
func (s *Server) ownAccountOutsideScope(r *http.Request, k accountKind, params authentik.ListUsersParams, scope access.Scope) (*authentik.User, error) {
	// Access administrators see every account anyway.
	if !k.seesOwnAccount() || scope.All && scope.IncludesHidden {
		return nil, nil
	}
	self, err := s.findActor(r, params)
	if err != nil || self == nil || scope.Allows(self) {
		return nil, err // listed with the others, if at all
	}
	return self, nil
}

// addSelf adds the operator's own account, which is outside their scope, to a
// page of the users in scope. It goes first on the first page and is counted
// on every page, so that page holds one user more than the others.
func addSelf(list *authentik.UserList, self *authentik.User, page int) {
	p := &list.Pagination
	p.Count++
	if p.TotalPages == 0 {
		// No user in scope matched, so there is just this page.
		*p = authentik.Pagination{Count: 1, Current: 1, TotalPages: 1, StartIndex: 1, EndIndex: 1}
	}
	if page == 1 {
		list.Results = slices.Insert(list.Results, 0, *self)
	}
}

// findActor returns the internal authentik account of the signed-in user when
// it matches the filters of params, or nil otherwise. The groups and paging of
// params are ignored.
func (s *Server) findActor(r *http.Request, params authentik.ListUsersParams) (*authentik.User, error) {
	username := actorName(r)
	if username == "" {
		return nil, nil
	}
	params.Username = username
	params.Type = []authentik.UserType{authentik.UserTypeInternal}
	params.GroupsByName, params.GroupsByPK, params.IsSuperuser = nil, nil, nil
	params.WithoutAttributes = nil
	params.Page, params.PageSize = 0, 0
	list, err := s.users.ListUsers(r.Context(), params)
	if err != nil {
		return nil, err
	}
	// authentik silently ignores filters it does not know, so match exactly.
	i := slices.IndexFunc(list.Results, func(u authentik.User) bool {
		return u.Username == username && u.Type == authentik.UserTypeInternal
	})
	if i < 0 {
		return nil, nil
	}
	return &list.Results[i], nil
}

// visibleAccount loads the account of kind k with the {id} path value and
// checks that the operator may see it: accounts in their scope, and their own
// account. Accounts of other types and outside the scope are reported as not
// found so their existence is not revealed. It returns the operator's scope
// too, and writes the error response when it returns false.
func (s *Server) visibleAccount(w http.ResponseWriter, r *http.Request, k accountKind) (*authentik.User, access.Scope, bool) {
	id, ok := pathID(w, r)
	if !ok {
		return nil, access.Scope{}, false
	}
	user, err := s.users.GetUser(r.Context(), id)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return nil, access.Scope{}, false
	}
	scope, ok := s.scope(w, r)
	if !ok {
		return nil, access.Scope{}, false
	}
	isOwn := k.seesOwnAccount() && isActor(r, user)
	if user.Type != k.typ || !scope.Allows(user) && !isOwn {
		s.recordUser(r, audit.ActionAccessDenied, user, nil)
		writeError(w, http.StatusNotFound, k.noun+" not found", nil)
		return nil, access.Scope{}, false
	}
	return user, scope, true
}

// isActor reports whether u is the signed-in user's own account.
func isActor(r *http.Request, u *authentik.User) bool {
	username := actorName(r)
	return username != "" && u.Username == username
}

// changeableUser is changeableAccount for internal users.
func (s *Server) changeableUser(w http.ResponseWriter, r *http.Request) (*authentik.User, access.Scope, bool) {
	return s.changeableAccount(w, r, userAccounts)
}

// changeableAccount is visibleAccount for the routes that change the account:
// it also checks that the operator may change it (see mayChange), and answers
// 403 otherwise, since the operator may see the account.
func (s *Server) changeableAccount(w http.ResponseWriter, r *http.Request, k accountKind) (*authentik.User, access.Scope, bool) {
	user, scope, ok := s.visibleAccount(w, r, k)
	if !ok {
		return nil, access.Scope{}, false
	}
	if !scope.Allows(user) {
		s.recordUser(r, audit.ActionAccessDenied, user, nil)
		writeError(w, http.StatusForbidden, "your groups do not allow changing your own account", nil)
		return nil, access.Scope{}, false
	}
	if !mayChange(user, scope) {
		primary := primaryGroupName(user)
		s.recordUser(r, audit.ActionAccessDenied, user, map[string]string{"primary_group": primary})
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("only the operators managing the primary group %q may change this %s", primary, k.noun), nil)
		return nil, access.Scope{}, false
	}
	return user, scope, true
}

// maxVisibleAccountPages bounds the pages of accounts read by visibleAccounts.
const maxVisibleAccountPages = 50

// visibleAccounts returns the accounts of the given types in scope. It leaves
// out the operator's own account when it is outside the scope, and reads at
// most maxVisibleAccountPages pages.
func (s *Server) visibleAccounts(r *http.Request, scope access.Scope, types ...authentik.UserType) ([]authentik.User, error) {
	if scope.Empty() {
		return nil, nil
	}
	params := authentik.ListUsersParams{PageSize: maxPageSize, Type: types}
	if !scope.IncludesHidden {
		params.WithoutAttributes = []string{access.HiddenAttribute}
	}
	if !scope.All {
		params.GroupsByName = scope.Groups
		params.IsSuperuser = new(false)
	}
	var out []authentik.User
	for params.Page = 1; ; params.Page++ {
		list, err := s.users.ListUsers(r.Context(), params)
		if err != nil {
			return nil, err
		}
		// authentik silently ignores filters it does not know, so check the type and scope too.
		for i := range list.Results {
			if u := &list.Results[i]; slices.Contains(types, u.Type) && scope.Allows(u) {
				out = append(out, *u)
			}
		}
		if list.Pagination.Next == 0 {
			return out, nil
		}
		if params.Page == maxVisibleAccountPages {
			s.logger.WarnContext(r.Context(), "too many accounts; using only the first ones",
				slog.Int("accounts", params.Page*params.PageSize))
			return out, nil
		}
	}
}

// listAccountPaths returns a handler listing every distinct path of the
// accounts of kind k the operator may see, so folders holding only hidden
// accounts, accounts outside the scope or other account types are left out.
func (s *Server) listAccountPaths(k accountKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.listAccountPathsOf(w, r, k)
	}
}

func (s *Server) listAccountPathsOf(w http.ResponseWriter, r *http.Request, k accountKind) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	// Any authentik user may log in, so do not reveal the folders to operators without access.
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string][]string{"paths": {}})
		return
	}
	accounts, err := s.visibleAccounts(r, scope, k.typ)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	// Operators see their own account outside their scope too, so its folder must not be empty.
	self, err := s.ownAccountOutsideScope(r, k, authentik.ListUsersParams{}, scope)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	if self != nil {
		accounts = append(accounts, *self)
	}
	paths := []string{}
	for _, a := range accounts {
		if a.Path != "" {
			paths = append(paths, a.Path)
		}
	}
	slices.Sort(paths)
	writeJSON(w, http.StatusOK, map[string][]string{"paths": slices.Compact(paths)})
}

// getAccount returns a handler serving the account of kind k with the {id} path value.
func (s *Server) getAccount(k accountKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, scope, ok := s.visibleAccount(w, r, k)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, newUserView(user, scope))
	}
}

// createUserInput is the body of POST /api/users and POST
// /api/service-accounts. It is decoded separately from
// authentik.CreateUserRequest so clients cannot pass arbitrary group keys.
type createUserInput struct {
	Username string             `json:"username"`
	Name     string             `json:"name"`
	Email    string             `json:"email"`
	IsActive *bool              `json:"is_active"`
	Path     string             `json:"path"`
	Type     authentik.UserType `json:"type"`
	// Group is the name of a group the new user joins, which becomes their
	// primary group. Operators with restricted access must name one of their
	// target groups.
	Group string `json:"group"`
	// Hidden hides the new user from operators who are not access
	// administrators; only access administrators may set it.
	Hidden bool `json:"hidden"`
}

// validate checks the input for an account of kind k against the operator's
// scope and returns the authentik request, or the validation messages per
// field. in.Group must be trimmed.
func (in createUserInput) validate(k accountKind, scope access.Scope) (authentik.CreateUserRequest, map[string][]string) {
	req := authentik.CreateUserRequest{
		Username: strings.TrimSpace(in.Username),
		Name:     strings.TrimSpace(in.Name),
		Email:    in.Email,
		IsActive: in.IsActive,
		Path:     in.Path,
		Type:     k.typ,
	}
	fields := map[string][]string{}
	if req.Username == "" {
		fields["username"] = []string{"Username is required."}
	}
	if req.Name == "" {
		fields["name"] = []string{"Name is required."}
	}
	if in.Type != "" && in.Type != k.typ {
		fields["type"] = []string{k.typeError}
	}
	switch {
	case in.Group == "" && !scope.All:
		fields["group"] = []string{"Group is required."}
	case in.Group != "" && !scope.HasGroup(in.Group):
		fields["group"] = []string{"You may not add users to this group."}
	}
	if in.Hidden && !scope.IncludesHidden {
		fields["hidden"] = []string{"Only access administrators may hide users."}
	}
	return req, fields
}

// createAccount returns a handler creating an account of kind k.
func (s *Server) createAccount(k accountKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.createAccountOf(w, r, k)
	}
}

func (s *Server) createAccountOf(w http.ResponseWriter, r *http.Request, k accountKind) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	if scope.Empty() {
		writeError(w, http.StatusForbidden, "you may not manage any users", nil)
		return
	}
	var in createUserInput
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Group = strings.TrimSpace(in.Group)
	req, fields := in.validate(k, scope)
	if len(fields) > 0 {
		writeError(w, http.StatusBadRequest, "validation failed", fields)
		return
	}

	if in.Group != "" {
		group, ok := s.findGroup(w, r, "group", in.Group, scope)
		if !ok {
			return
		}
		req.Groups = []string{group.PK}
		req.Attributes = withPrimaryGroup(nil, group.PK)
	}
	if in.Hidden {
		req.Attributes = withHidden(req.Attributes, true)
	}

	user, err := s.users.CreateUser(r.Context(), req)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	details := map[string]string{}
	if in.Group != "" {
		details["group"] = in.Group
	}
	if in.Hidden {
		details["hidden"] = "true"
	}
	s.recordUser(r, k.created, user, details)
	writeJSON(w, http.StatusCreated, newUserView(user, scope))
}

// findGroup resolves a group a user joins, writing the error response for the
// input field when it returns false.
func (s *Server) findGroup(w http.ResponseWriter, r *http.Request, field, name string, scope access.Scope) (*authentik.Group, bool) {
	group, err := s.users.FindGroup(r.Context(), name)
	if errors.Is(err, authentik.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{field: {fmt.Sprintf("Unknown group %q.", name)}})
		return nil, false
	}
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return nil, false
	}
	// A superuser group would create an administrator the operator could not manage.
	if group.IsSuperuser && !scope.All {
		writeError(w, http.StatusBadRequest, "validation failed",
			map[string][]string{field: {"You may not add users to an administrator group."}})
		return nil, false
	}
	if !s.mayGrantGroup(r, group) {
		writeError(w, http.StatusBadRequest, "validation failed",
			map[string][]string{field: {"Only access administrators may add users to an access administrator group."}})
		return nil, false
	}
	return group, true
}

// mayGrantGroup reports whether the signed-in operator may add users to
// group. Members of an access administrator group (ACCESS_ADMIN_GROUPS) become
// access administrators, so only access administrators may add them, even
// operators with full access to the users.
func (s *Server) mayGrantGroup(r *http.Request, group *authentik.Group) bool {
	return !s.policy.IsAdmin([]string{group.Name}) || s.policy.IsAdmin(operatorGroups(r))
}

// updateUserInput is the body of PATCH /api/users/{id} and PATCH
// /api/service-accounts/{id}; nil fields are left
// unchanged. It is decoded separately from authentik.UpdateUserRequest so
// clients cannot replace the user's attributes.
type updateUserInput struct {
	Username *string             `json:"username"`
	Name     *string             `json:"name"`
	Email    *string             `json:"email"`
	IsActive *bool               `json:"is_active"`
	Path     *string             `json:"path"`
	Type     *authentik.UserType `json:"type"`
	// Hidden hides the user from operators who are not access administrators,
	// or shows them again; only access administrators may change it.
	Hidden *bool `json:"hidden"`
}

func (in updateUserInput) request() authentik.UpdateUserRequest {
	return authentik.UpdateUserRequest{
		Username: in.Username,
		Name:     in.Name,
		Email:    in.Email,
		IsActive: in.IsActive,
		Path:     in.Path,
		Type:     in.Type,
	}
}

// updateAccount returns a handler applying a partial update to the account of
// kind k with the {id} path value.
func (s *Server) updateAccount(k accountKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.updateAccountOf(w, r, k)
	}
}

func (s *Server) updateAccountOf(w http.ResponseWriter, r *http.Request, k accountKind) {
	target, scope, ok := s.changeableAccount(w, r, k)
	if !ok {
		return
	}
	id := target.PK
	var in updateUserInput
	if !decodeJSON(w, r, &in) {
		return
	}
	// Changing the type would turn the account into one these routes no longer manage.
	if in.Type != nil && *in.Type != k.typ {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"type": {k.typeError}})
		return
	}

	req := in.request()
	if in.Hidden != nil && *in.Hidden != access.IsHidden(target) {
		if !scope.IncludesHidden {
			s.recordUser(r, audit.ActionAccessDenied, target, map[string]string{"hidden": strconv.FormatBool(*in.Hidden)})
			writeError(w, http.StatusForbidden, "only access administrators may hide or show users", nil)
			return
		}
		// authentik replaces all attributes, so keep the others. A concurrent
		// change to them elsewhere between loading and saving is lost.
		req.Attributes = withHidden(target.Attributes, *in.Hidden)
	}
	user, err := s.users.UpdateUser(r.Context(), id, req)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	details := map[string]string{"fields": updatedFields(req)}
	if req.Username != nil && user.Username != target.Username {
		details["previous_username"] = target.Username
	}
	if req.IsActive != nil {
		details["is_active"] = strconv.FormatBool(*req.IsActive)
	}
	if req.Attributes != nil {
		details["hidden"] = strconv.FormatBool(*in.Hidden)
	}
	s.recordUser(r, k.updated, user, details)
	s.notifyProfileUpdate(r, target, user)

	if reason := certificateRevocationReason(target, req); reason != "" {
		// The user is changed already, so finish revoking even when the client goes away.
		if err := s.revokeUserCertificates(context.WithoutCancel(r.Context()), r, target, reason); err != nil {
			s.logger.ErrorContext(r.Context(), "revoking user certificates",
				slog.Int("user_id", target.PK),
				slog.String("reason", reason),
				slog.Any("error", err),
			)
			writeError(w, http.StatusInternalServerError,
				fmt.Sprintf("the %s was updated, but revoking their certificates failed; revoke them manually", k.noun), nil)
			return
		}
	}
	writeJSON(w, http.StatusOK, newUserView(user, scope))
}

// certificateRevocationReason returns why req ends the certificates of
// target, or "" when it does not: deactivating the user, or renaming them,
// since their certificates name the old username, which another user may get.
func certificateRevocationReason(target *authentik.User, req authentik.UpdateUserRequest) string {
	switch {
	case req.IsActive != nil && !*req.IsActive:
		return "user deactivated"
	case req.Username != nil && *req.Username != target.Username:
		return "user renamed"
	default:
		return ""
	}
}

// userGroupsInput is the body of PUT /api/users/{id}/groups.
type userGroupsInput struct {
	// Groups are the names of the groups the user should be in.
	Groups []string `json:"groups"`
	// PrimaryGroup, when non-nil, is the name of the user's new primary group,
	// which must be one of Groups; empty removes it. When nil it stays.
	PrimaryGroup *string `json:"primary_group"`
}

// setAccountGroups returns a handler replacing the groups of the account of
// kind k with the {id} path value; see setAccountGroupsOf.
func (s *Server) setAccountGroups(k accountKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.setAccountGroupsOf(w, r, k)
	}
}

// setAccountGroupsOf replaces the groups of an account with the names in the
// body and sets its primary group. Only access administrators may change their
// own groups. Restricted operators may only add or remove their
// target groups, and the user must stay in one of them so the operator does
// not lose access to it. The user's primary group cannot be removed unless the
// same request chooses another one.
func (s *Server) setAccountGroupsOf(w http.ResponseWriter, r *http.Request, k accountKind) {
	user, scope, ok := s.changeableAccount(w, r, k)
	if !ok {
		return
	}
	if !s.mayChangeGroupsOf(w, r, user) {
		return
	}
	var in userGroupsInput
	if !decodeJSON(w, r, &in) {
		return
	}
	change, msg := diffGroups(user, in.Groups, scope)
	if msg != "" {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"groups": {msg}})
		return
	}
	primary, fields := nextPrimaryGroup(user, change.groups, in.PrimaryGroup, scope)
	if fields != nil {
		writeError(w, http.StatusBadRequest, "validation failed", fields)
		return
	}

	// Resolve every new group before changing anything, so invalid input changes nothing.
	toAdd := make([]*authentik.Group, 0, len(change.added))
	for _, name := range change.added {
		group, ok := s.findGroup(w, r, "groups", name, scope)
		if !ok {
			return
		}
		toAdd = append(toAdd, group)
	}
	// One notification lists every change made, also when a later one fails.
	changes := []string{}
	defer func() { s.notifyGroupChanges(r, user, changes) }()
	for _, g := range toAdd {
		if err := s.users.AddUserToGroup(r.Context(), g.PK, user.PK); err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		s.recordUser(r, audit.ActionUserGroupAdded, user, map[string]string{"group": g.Name})
		changes = append(changes, fmt.Sprintf("Added to the group %q", g.Name))
	}
	// Set the primary group between adding and removing, so it is always one of the user's groups.
	previous := primaryGroupName(user)
	next := authentik.UserGroup{Name: primary, PK: groupPK(primary, user.Groups, toAdd)}
	if !s.setPrimaryGroup(w, r, user, next) {
		return
	}
	if primary != previous {
		changes = append(changes, fmt.Sprintf("Primary group: %s → %s", orNone(previous), orNone(primary)))
	}
	for _, g := range change.removed {
		if err := s.users.RemoveUserFromGroup(r.Context(), g.PK, user.PK); err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		s.recordUser(r, audit.ActionUserGroupRemoved, user, map[string]string{"group": g.Name})
		changes = append(changes, fmt.Sprintf("Removed from the group %q", g.Name))
	}

	updated, err := s.users.GetUser(r.Context(), user.PK)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newUserView(updated, scope))
}

// mayChangeGroupsOf reports whether the signed-in operator may change the
// groups of user, and answers 403 otherwise. For separation of duties, only
// access administrators may change their own groups: other operators could
// grant themselves groups.
func (s *Server) mayChangeGroupsOf(w http.ResponseWriter, r *http.Request, user *authentik.User) bool {
	if !isActor(r, user) || s.policy.IsAdmin(operatorGroups(r)) {
		return true
	}
	s.recordUser(r, audit.ActionAccessDenied, user, map[string]string{"reason": "own groups"})
	writeError(w, http.StatusForbidden, "validation failed", map[string][]string{
		"groups": {"You may not change your own groups; ask another operator."},
	})
	return false
}

// groupChange is the difference between a user's groups and the requested ones.
type groupChange struct {
	// groups are the names of the groups the user is in after the change.
	groups []string
	// added are the names of the groups the user joins.
	added []string
	// removed are the groups the user leaves.
	removed []authentik.UserGroup
}

// diffGroups compares the groups of user with the requested names and checks
// the change against scope. When the change is not allowed it returns a
// message that is safe to show users.
func diffGroups(user *authentik.User, names []string, scope access.Scope) (groupChange, string) {
	want := []string{}
	for _, g := range names {
		if g = strings.TrimSpace(g); g != "" {
			want = append(want, g)
		}
	}
	slices.Sort(want)
	want = slices.Compact(want)

	have := user.GroupNames()
	change := groupChange{
		groups:  want,
		added:   slices.DeleteFunc(slices.Clone(want), func(g string) bool { return slices.Contains(have, g) }),
		removed: slices.DeleteFunc(slices.Clone(user.Groups), func(g authentik.UserGroup) bool { return slices.Contains(want, g.Name) }),
	}
	for _, g := range change.added {
		if !scope.HasGroup(g) {
			return groupChange{}, fmt.Sprintf("You may not add users to %q.", g)
		}
	}
	for _, g := range change.removed {
		if !scope.HasGroup(g.Name) {
			return groupChange{}, fmt.Sprintf("You may not remove users from %q.", g.Name)
		}
	}
	if !scope.All && !slices.ContainsFunc(want, scope.HasGroup) {
		return groupChange{}, "The user must stay in at least one of your groups."
	}
	return change, ""
}

// nextPrimaryGroup returns the name of the primary group user has once they
// are in exactly groups, or "" for none. requested is the name of the new
// primary group, "" to remove it, or nil to keep the current one. The operator
// must manage the current primary group (see changeableUser). When the change
// is not allowed it returns the messages per field, which are safe to show users.
func nextPrimaryGroup(user *authentik.User, groups []string, requested *string, scope access.Scope) (string, map[string][]string) {
	current := primaryGroupName(user)
	next := current
	if requested != nil {
		next = strings.TrimSpace(*requested)
	}
	isMember := next == "" || slices.Contains(groups, next)
	switch {
	case !isMember && next == current:
		return "", map[string][]string{"groups": {
			fmt.Sprintf("%q is the user's primary group. Choose another primary group before removing it.", current),
		}}
	case !isMember:
		return "", map[string][]string{"primary_group": {"The primary group must be one of the user's groups."}}
	case next == current:
		return next, nil
	case next != "" && !scope.HasGroup(next):
		return "", map[string][]string{"primary_group": {fmt.Sprintf("You may not make %q the primary group.", next)}}
	}
	return next, nil
}

// groupPK returns the primary key of the group named name among the groups a
// user has and the ones they joined, or "" when it is in neither.
func groupPK(name string, have []authentik.UserGroup, joined []*authentik.Group) string {
	if i := slices.IndexFunc(have, func(g authentik.UserGroup) bool { return g.Name == name }); i >= 0 {
		return have[i].PK
	}
	if i := slices.IndexFunc(joined, func(g *authentik.Group) bool { return g.Name == name }); i >= 0 {
		return joined[i].PK
	}
	return ""
}

// setPrimaryGroup makes next the primary group of user, or removes it when
// next.PK is empty. It does nothing when the primary group stays the same, and
// writes the error response when it returns false.
func (s *Server) setPrimaryGroup(w http.ResponseWriter, r *http.Request, user *authentik.User, next authentik.UserGroup) bool {
	previous := primaryGroupName(user)
	if next.Name == previous {
		return true
	}
	// authentik replaces all attributes, so keep the others. A concurrent
	// change to them elsewhere between loading and saving is lost.
	req := authentik.UpdateUserRequest{Attributes: withPrimaryGroup(user.Attributes, next.PK)}
	if _, err := s.users.UpdateUser(r.Context(), user.PK, req); err != nil {
		s.writeUpstreamError(w, r, err)
		return false
	}
	details := map[string]string{"primary_group": next.Name}
	if previous != "" {
		details["previous_primary_group"] = previous
	}
	s.recordUser(r, audit.ActionUserPrimaryGroupChanged, user, details)
	return true
}

// reasonUserDeleted is the reason recorded for the certificates revoked when
// their user is deleted. The deleted user is not notified.
const reasonUserDeleted = "user deleted"

// deleteAccount returns a handler deleting the account of kind k with the {id}
// path value, after revoking its certificates.
func (s *Server) deleteAccount(k accountKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.deleteAccountOf(w, r, k)
	}
}

func (s *Server) deleteAccountOf(w http.ResponseWriter, r *http.Request, k accountKind) {
	target, _, ok := s.changeableAccount(w, r, k)
	if !ok {
		return
	}
	// Revoke first: once the user is deleted, nobody can list or revoke their certificates.
	if err := s.revokeUserCertificates(r.Context(), r, target, reasonUserDeleted); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.ErrorContext(r.Context(), "revoking user certificates",
				slog.Int("user_id", target.PK),
				slog.Any("error", err),
			)
		}
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("revoking the %[1]s's certificates failed; the %[1]s was not deleted", k.noun), nil)
		return
	}
	if err := s.deleteUserAPIKeys(r.Context(), r, target); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.ErrorContext(r.Context(), "deleting user API keys",
				slog.Int("user_id", target.PK),
				slog.Any("error", err),
			)
		}
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("deleting the %[1]s's API keys failed; the %[1]s was not deleted", k.noun), nil)
		return
	}
	if err := s.users.DeleteUser(r.Context(), target.PK); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.recordUser(r, k.deleted, target, nil)
	w.WriteHeader(http.StatusNoContent)
}

// sendRecoveryEmail emails the user a link to recover their account and set a new password.
func (s *Server) sendRecoveryEmail(w http.ResponseWriter, r *http.Request) {
	if s.recoveryEmailStage == "" {
		writeError(w, http.StatusNotImplemented, "recovery emails are not configured", nil)
		return
	}
	user, _, ok := s.changeableUser(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(user.Email) == "" {
		writeError(w, http.StatusBadRequest, "the user has no email address", nil)
		return
	}
	if err := s.users.SendRecoveryEmail(r.Context(), user.PK, s.recoveryEmailStage); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.recordUser(r, audit.ActionRecoveryEmailSent, user, nil)
	w.WriteHeader(http.StatusNoContent)
}

// pathID parses the {id} path segment, writing a 400 response when invalid.
func pathID(w http.ResponseWriter, r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "invalid user id", nil)
		return 0, false
	}
	return id, true
}

// decodeJSON strictly decodes a bounded JSON body into dst, writing a 400 response on failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large", nil)
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body", nil)
		return false
	}
	return true
}
