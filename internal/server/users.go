package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"authentikManager/internal/access"
	"authentikManager/internal/authentik"
)

const maxPageSize = 100

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := authentik.ListUsersParams{
		Search:         q.Get("search"),
		Ordering:       q.Get("ordering"),
		Page:           1,
		PageSize:       20,
		Path:           q.Get("path"),
		PathStartsWith: q.Get("path_startswith"),
		// Only internal users are managed here; service accounts and external users are hidden.
		Type: []authentik.UserType{authentik.UserTypeInternal},
	}
	var err error
	if v := q.Get("page"); v != "" {
		if params.Page, err = strconv.Atoi(v); err != nil || params.Page < 1 {
			writeError(w, http.StatusBadRequest, "page must be a positive integer", nil)
			return
		}
	}
	if v := q.Get("page_size"); v != "" {
		if params.PageSize, err = strconv.Atoi(v); err != nil || params.PageSize < 1 || params.PageSize > maxPageSize {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("page_size must be between 1 and %d", maxPageSize), nil)
			return
		}
	}

	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	if scope.Empty() {
		writeJSON(w, http.StatusOK, authentik.UserList{Results: []authentik.User{}})
		return
	}
	if !scope.All {
		params.GroupsByName = scope.Groups
		params.IsSuperuser = new(false)
	}

	list, err := s.users.ListUsers(r.Context(), params)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	// Defense in depth: authentik silently ignores filters it does not know,
	// so drop anything outside the scope or not internal even if the filters were not applied.
	list.Results = slices.DeleteFunc(list.Results, func(u authentik.User) bool {
		return u.Type != authentik.UserTypeInternal || !scope.Allows(&u)
	})
	writeJSON(w, http.StatusOK, list)
}

// allowedUser loads the user with the {id} path value and checks that the
// operator may manage it. Only internal users are managed. Users outside the
// scope or of another type are reported as not found so their existence is not revealed.
// It returns the operator's scope too, and writes the error response when it returns false.
func (s *Server) allowedUser(w http.ResponseWriter, r *http.Request) (*authentik.User, access.Scope, bool) {
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
	if user.Type != authentik.UserTypeInternal || !scope.Allows(user) {
		s.audit(r, "access denied", slog.Int("user_id", id))
		writeError(w, http.StatusNotFound, "user not found", nil)
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
	user, _, ok := s.allowedUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, user)
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
	// Group is the name of a group the new user joins. Operators with
	// restricted access must name one of their target groups.
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
	}

	user, err := s.users.CreateUser(r.Context(), req)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.audit(r, "user created", slog.Int("user_id", user.PK), slog.String("username", user.Username))
	writeJSON(w, http.StatusCreated, user)
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

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	target, _, ok := s.allowedUser(w, r)
	if !ok {
		return
	}
	id := target.PK
	var req authentik.UpdateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// Changing the type would turn the user into one this application no longer manages.
	if req.Type != nil && *req.Type != authentik.UserTypeInternal {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"type": {"Only internal users can be managed."}})
		return
	}

	user, err := s.users.UpdateUser(r.Context(), id, req)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.audit(r, "user updated", slog.Int("user_id", id))
	writeJSON(w, http.StatusOK, user)
}

// setUserGroups replaces the groups of a user with the names in the body.
// Restricted operators may only add or remove their target groups, and the user
// must stay in one of them so the operator does not lose access to it.
func (s *Server) setUserGroups(w http.ResponseWriter, r *http.Request) {
	user, scope, ok := s.allowedUser(w, r)
	if !ok {
		return
	}
	var in struct {
		Groups []string `json:"groups"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	change, msg := diffGroups(user, in.Groups, scope)
	if msg != "" {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"groups": {msg}})
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
		s.audit(r, "user added to group", slog.Int("user_id", user.PK), slog.String("group", g.Name))
	}
	for _, g := range change.removed {
		if err := s.users.RemoveUserFromGroup(r.Context(), g.PK, user.PK); err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		s.audit(r, "user removed from group", slog.Int("user_id", user.PK), slog.String("group", g.Name))
	}

	updated, err := s.users.GetUser(r.Context(), user.PK)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// groupChange is the difference between a user's groups and the requested ones.
type groupChange struct {
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

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	target, _, ok := s.allowedUser(w, r)
	if !ok {
		return
	}
	id := target.PK
	if err := s.users.DeleteUser(r.Context(), id); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.audit(r, "user deleted", slog.Int("user_id", id))
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
