package server

import (
	"encoding/json"
	"errors"
	"fmt"
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
}

func newUserView(u *authentik.User, scope access.Scope) userView {
	return userView{User: *u, PrimaryGroup: primaryGroupName(u), Changeable: mayChange(u, scope)}
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

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := authentik.ListUsersParams{
		Search:         q.Get("search"),
		Ordering:       q.Get("ordering"),
		Path:           q.Get("path"),
		PathStartsWith: q.Get("path_startswith"),
		// Only internal users are managed here; service accounts and external users are hidden.
		Type: []authentik.UserType{authentik.UserTypeInternal},
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
	if scope.All {
		list, err := s.users.ListUsers(r.Context(), params)
		if err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		// Defense in depth: authentik silently ignores filters it does not know,
		// so drop anything not internal even if the filter was not applied.
		list.Results = slices.DeleteFunc(list.Results, func(u authentik.User) bool { return u.Type != authentik.UserTypeInternal })
		writeJSON(w, http.StatusOK, newUserPage(list, scope))
		return
	}

	// Every user sees their own account, even outside their scope.
	self, err := s.findActor(r, params)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	if self != nil && scope.Allows(self) {
		self = nil // listed with the others
	}
	list := &authentik.UserList{Results: []authentik.User{}}
	if !scope.Empty() {
		scoped := params
		scoped.GroupsByName = scope.Groups
		scoped.IsSuperuser = new(false)
		if list, err = s.users.ListUsers(r.Context(), scoped); err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		// Defense in depth: authentik silently ignores filters it does not know,
		// so drop anything outside the scope or not internal even if the filters were not applied.
		list.Results = slices.DeleteFunc(list.Results, func(u authentik.User) bool {
			return u.Type != authentik.UserTypeInternal || !scope.Allows(&u)
		})
	}
	if self != nil {
		addSelf(list, self, params.Page)
	}
	writeJSON(w, http.StatusOK, newUserPage(list, scope))
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

// visibleUser loads the user with the {id} path value and checks that the
// operator may see it: users in their scope, and their own account. Only
// internal users are managed. Other users are reported as not found so their
// existence is not revealed. It returns the operator's scope too, and writes
// the error response when it returns false.
func (s *Server) visibleUser(w http.ResponseWriter, r *http.Request) (*authentik.User, access.Scope, bool) {
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
	if user.Type != authentik.UserTypeInternal || !scope.Allows(user) && !isActor(r, user) {
		s.recordUser(r, audit.ActionAccessDenied, user, nil)
		writeError(w, http.StatusNotFound, "user not found", nil)
		return nil, access.Scope{}, false
	}
	return user, scope, true
}

// isActor reports whether u is the signed-in user's own account.
func isActor(r *http.Request, u *authentik.User) bool {
	username := actorName(r)
	return username != "" && u.Username == username
}

// changeableUser is visibleUser for the routes that change the user: it also
// checks that the operator may change them (see mayChange), and answers 403
// otherwise, since the operator may see the user.
func (s *Server) changeableUser(w http.ResponseWriter, r *http.Request) (*authentik.User, access.Scope, bool) {
	user, scope, ok := s.visibleUser(w, r)
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
			fmt.Sprintf("only the operators managing the primary group %q may change this user", primary), nil)
		return nil, access.Scope{}, false
	}
	return user, scope, true
}

func (s *Server) listUserPaths(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	// Any authentik user may log in, so do not reveal the folders to operators without access.
	if scope.Empty() {
		writeJSON(w, http.StatusOK, map[string][]string{"paths": {}})
		return
	}
	paths, err := s.users.ListUserPaths(r.Context())
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"paths": paths})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	user, scope, ok := s.visibleUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, newUserView(user, scope))
}

// createUserInput is the body of POST /api/users. It is decoded separately from
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
}

// validate checks the input against the operator's scope and returns the
// authentik request, or the validation messages per field. in.Group must be trimmed.
func (in createUserInput) validate(scope access.Scope) (authentik.CreateUserRequest, map[string][]string) {
	req := authentik.CreateUserRequest{
		Username: strings.TrimSpace(in.Username),
		Name:     strings.TrimSpace(in.Name),
		Email:    in.Email,
		IsActive: in.IsActive,
		Path:     in.Path,
		Type:     authentik.UserTypeInternal,
	}
	fields := map[string][]string{}
	if req.Username == "" {
		fields["username"] = []string{"Username is required."}
	}
	if req.Name == "" {
		fields["name"] = []string{"Name is required."}
	}
	if in.Type != "" && in.Type != authentik.UserTypeInternal {
		fields["type"] = []string{"Only internal users can be managed."}
	}
	switch {
	case in.Group == "" && !scope.All:
		fields["group"] = []string{"Group is required."}
	case in.Group != "" && !scope.HasGroup(in.Group):
		fields["group"] = []string{"You may not add users to this group."}
	}
	return req, fields
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
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
	req, fields := in.validate(scope)
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

	user, err := s.users.CreateUser(r.Context(), req)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	details := map[string]string{}
	if in.Group != "" {
		details["group"] = in.Group
	}
	s.recordUser(r, audit.ActionUserCreated, user, details)
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
	return group, true
}

// updateUserInput is the body of PATCH /api/users/{id}; nil fields are left
// unchanged. It is decoded separately from authentik.UpdateUserRequest so
// clients cannot replace the user's attributes.
type updateUserInput struct {
	Username *string             `json:"username"`
	Name     *string             `json:"name"`
	Email    *string             `json:"email"`
	IsActive *bool               `json:"is_active"`
	Path     *string             `json:"path"`
	Type     *authentik.UserType `json:"type"`
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

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	target, scope, ok := s.changeableUser(w, r)
	if !ok {
		return
	}
	id := target.PK
	var in updateUserInput
	if !decodeJSON(w, r, &in) {
		return
	}
	// Changing the type would turn the user into one this application no longer manages.
	if in.Type != nil && *in.Type != authentik.UserTypeInternal {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"type": {"Only internal users can be managed."}})
		return
	}

	req := in.request()
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
	s.recordUser(r, audit.ActionUserUpdated, user, details)
	writeJSON(w, http.StatusOK, newUserView(user, scope))
}

// userGroupsInput is the body of PUT /api/users/{id}/groups.
type userGroupsInput struct {
	// Groups are the names of the groups the user should be in.
	Groups []string `json:"groups"`
	// PrimaryGroup, when non-nil, is the name of the user's new primary group,
	// which must be one of Groups; empty removes it. When nil it stays.
	PrimaryGroup *string `json:"primary_group"`
}

// setUserGroups replaces the groups of a user with the names in the body and
// sets their primary group. Restricted operators may only add or remove their
// target groups, and the user must stay in one of them so the operator does
// not lose access to it. The user's primary group cannot be removed unless the
// same request chooses another one.
func (s *Server) setUserGroups(w http.ResponseWriter, r *http.Request) {
	user, scope, ok := s.changeableUser(w, r)
	if !ok {
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
	for _, g := range toAdd {
		if err := s.users.AddUserToGroup(r.Context(), g.PK, user.PK); err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		s.recordUser(r, audit.ActionUserGroupAdded, user, map[string]string{"group": g.Name})
	}
	// Set the primary group between adding and removing, so it is always one of the user's groups.
	next := authentik.UserGroup{Name: primary, PK: groupPK(primary, user.Groups, toAdd)}
	if !s.setPrimaryGroup(w, r, user, next) {
		return
	}
	for _, g := range change.removed {
		if err := s.users.RemoveUserFromGroup(r.Context(), g.PK, user.PK); err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		s.recordUser(r, audit.ActionUserGroupRemoved, user, map[string]string{"group": g.Name})
	}

	updated, err := s.users.GetUser(r.Context(), user.PK)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newUserView(updated, scope))
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

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	target, _, ok := s.changeableUser(w, r)
	if !ok {
		return
	}
	if err := s.users.DeleteUser(r.Context(), target.PK); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.recordUser(r, audit.ActionUserDeleted, target, nil)
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
