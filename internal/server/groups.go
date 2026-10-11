package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// The group handlers are restricted to access administrators (see requireAdmin),
// who have full access, so they do not check the operator's scope. The only
// exceptions are listVisibleGroups and requestJoin.

// visibleAttribute is the authentik group attribute that, when true, lets every
// signed-in user see the group's name. Its members stay hidden.
const visibleAttribute = "authentik_manager_visible"

// isVisible reports whether g is visible to every signed-in user.
func isVisible(g *authentik.Group) bool {
	visible, ok := g.Attributes[visibleAttribute].(bool)
	return ok && visible
}

// withVisibility returns a copy of attrs with the visibility set, leaving the
// other attributes as they are. It never returns nil, so an update clearing
// the last attribute is still sent.
func withVisibility(attrs map[string]any, visible bool) map[string]any {
	out := maps.Clone(attrs)
	if out == nil {
		out = map[string]any{}
	}
	if visible {
		out[visibleAttribute] = true
	} else {
		delete(out, visibleAttribute)
	}
	return out
}

// groupView is a group as access administrators see it. It leaves out the
// other attributes, which authentik and other applications use.
type groupView struct {
	PK          string `json:"pk"`
	Name        string `json:"name"`
	IsSuperuser bool   `json:"is_superuser"`
	ParentName  string `json:"parent_name"`
	// Visible is set when every signed-in user may see the group's name.
	Visible bool `json:"visible"`
}

func newGroupView(g *authentik.Group) groupView {
	return groupView{PK: g.PK, Name: g.Name, IsSuperuser: g.IsSuperuser, ParentName: g.ParentName, Visible: isVisible(g)}
}

// publicGroup is a visible group as every signed-in user sees it.
type publicGroup struct {
	PK         string `json:"pk"`
	Name       string `json:"name"`
	ParentName string `json:"parent_name"`
	// Member is set when the signed-in user is a direct member of the group.
	Member bool `json:"member"`
}

// page is one page of a list response.
type page[T any] struct {
	Pagination authentik.Pagination `json:"pagination"`
	Results    []T                  `json:"results"`
}

// groupListParams parses the query parameters search, page and page_size of a
// group list, writing a 400 response when they are invalid.
func groupListParams(w http.ResponseWriter, r *http.Request) (authentik.ListGroupsParams, bool) {
	q := r.URL.Query()
	params := authentik.ListGroupsParams{Search: q.Get("search")}
	var ok bool
	params.Page, params.PageSize, ok = parsePaging(w, q)
	return params, ok
}

// listGroups returns a page of authentik groups, ordered by name. The query
// parameters search, page and page_size filter and page it.
func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	params, ok := groupListParams(w, r)
	if !ok {
		return
	}
	list, err := s.users.ListGroups(r.Context(), params)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	out := page[groupView]{Pagination: list.Pagination, Results: make([]groupView, len(list.Results))}
	for i := range list.Results {
		out.Results[i] = newGroupView(&list.Results[i])
	}
	writeJSON(w, http.StatusOK, out)
}

// listVisibleGroups returns a page of the groups visible to every signed-in
// user, ordered by name, with their names only. It is open to every operator,
// including those who may not manage any users. The query parameters search,
// page and page_size filter and page it. Users may request to join them; see
// requestJoin.
func (s *Server) listVisibleGroups(w http.ResponseWriter, r *http.Request) {
	params, ok := groupListParams(w, r)
	if !ok {
		return
	}
	params.Attributes = map[string]any{visibleAttribute: true}
	list, err := s.users.ListGroups(r.Context(), params)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	// The groups read at login miss the ones joined since, by an approved request for example.
	user, err := s.findRequester(r)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	isMember := func(*authentik.Group) bool { return false }
	if user != nil {
		isMember = func(g *authentik.Group) bool {
			return slices.ContainsFunc(user.Groups, func(ug authentik.UserGroup) bool { return ug.PK == g.PK })
		}
	}
	out := page[publicGroup]{Pagination: list.Pagination, Results: []publicGroup{}}
	for i := range list.Results {
		g := &list.Results[i]
		// authentik silently ignores filters it does not know, so drop hidden
		// groups in case the filter was not applied.
		if isVisible(g) {
			out.Results = append(out.Results, publicGroup{
				PK:         g.PK,
				Name:       g.Name,
				ParentName: g.ParentName,
				Member:     isMember(g),
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// loadGroup loads the group with the {pk} path value, writing the error
// response when it returns false.
func (s *Server) loadGroup(w http.ResponseWriter, r *http.Request) (*authentik.Group, bool) {
	pk := r.PathValue("pk")
	if pk == "" {
		writeError(w, http.StatusBadRequest, "invalid group id", nil)
		return nil, false
	}
	group, err := s.users.GetGroup(r.Context(), pk)
	if err != nil {
		s.writeGroupError(w, r, err)
		return nil, false
	}
	return group, true
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, newGroupView(group))
}

// groupInput is the body of PATCH /api/groups/{pk}; nil fields are left unchanged.
type groupInput struct {
	Name    *string `json:"name"`
	Visible *bool   `json:"visible"`
}

// updateGroup renames a group and sets whether it is visible to every
// signed-in user. A rename applies to every access rule naming the group too,
// since the rules match groups by name.
func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	var in groupInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"name": {"Name is required."}})
			return
		}
		in.Name = &name
	}
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	req, ok := s.groupUpdate(w, r, group, in)
	if !ok {
		return
	}
	if req.Name == nil && req.Attributes == nil {
		writeJSON(w, http.StatusOK, newGroupView(group))
		return
	}

	updated, err := s.users.UpdateGroup(r.Context(), group.PK, req)
	if err != nil {
		s.writeGroupError(w, r, err)
		return
	}
	if req.Attributes != nil {
		s.record(r, audit.ActionGroupVisibilityChanged, updated.Name, map[string]string{
			"group_id": updated.PK,
			"visible":  strconv.FormatBool(isVisible(updated)),
		})
	}
	if req.Name != nil && !s.renameInRules(w, r, group, updated) {
		return
	}
	writeJSON(w, http.StatusOK, newGroupView(updated))
}

// groupUpdate returns the authentik update for in, leaving out the fields that
// do not change. It writes the error response and returns false when in is invalid.
func (s *Server) groupUpdate(w http.ResponseWriter, r *http.Request, group *authentik.Group, in groupInput) (authentik.UpdateGroupRequest, bool) {
	var req authentik.UpdateGroupRequest
	if in.Name != nil && *in.Name != group.Name {
		msg, ok := s.checkGroupName(w, r, group, *in.Name)
		if !ok {
			return req, false
		}
		if msg != "" {
			writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"name": {msg}})
			return req, false
		}
		req.Name = in.Name
	}
	if in.Visible != nil && *in.Visible != isVisible(group) {
		// authentik replaces all attributes, so keep the others. A concurrent
		// change to them elsewhere between loading and saving is lost.
		req.Attributes = withVisibility(group.Attributes, *in.Visible)
	}
	return req, true
}

// renameInRules renames group in the access rules after authentik renamed it
// to updated.Name. When the rules cannot be renamed it restores the previous
// name, writes the error response and returns false.
func (s *Server) renameInRules(w http.ResponseWriter, r *http.Request, group, updated *authentik.Group) bool {
	changed, err := s.rules.RenameGroup(r.Context(), group.Name, updated.Name, actorName(r))
	if err != nil {
		s.undoRename(r, group)
		s.writeStoreError(w, r, err)
		return false
	}
	s.record(r, audit.ActionGroupRenamed, updated.Name, map[string]string{
		"group_id":      updated.PK,
		"previous_name": group.Name,
		"rules_changed": strconv.FormatInt(changed, 10),
	})
	return true
}

// checkGroupName checks whether group may be renamed to name. It returns a
// message that is safe to show users when not, and writes the error response
// and returns false when the check itself fails.
func (s *Server) checkGroupName(w http.ResponseWriter, r *http.Request, group *authentik.Group, name string) (string, bool) {
	// The admin groups are configured by name, so renaming one would lock its
	// members out, and renaming a group to one would make its members access administrators.
	if s.policy.IsAdmin([]string{group.Name}) {
		return "Access administrator groups (ACCESS_ADMIN_GROUPS) cannot be renamed here.", true
	}
	if s.policy.IsAdmin([]string{name}) {
		return "This name is reserved for an access administrator group (ACCESS_ADMIN_GROUPS).", true
	}
	if name == access.Wildcard {
		return fmt.Sprintf("%q is reserved for access rules granting all users.", access.Wildcard), true
	}
	// Rules match groups by name, so two groups of one name would share their rules.
	other, err := s.users.FindGroup(r.Context(), name)
	switch {
	case errors.Is(err, authentik.ErrNotFound):
		return "", true
	case err != nil:
		s.writeUpstreamError(w, r, err)
		return "", false
	case other.PK != group.PK:
		return fmt.Sprintf("Another group is already named %q.", name), true
	}
	return "", true
}

// undoRename restores the previous name of group after its access rules could
// not be renamed, so the rules keep matching it. A visibility change made in
// the same update stays.
func (s *Server) undoRename(r *http.Request, group *authentik.Group) {
	// Restore the name even when the client has gone away meanwhile.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditTimeout)
	defer cancel()
	if _, err := s.users.UpdateGroup(ctx, group.PK, authentik.UpdateGroupRequest{Name: &group.Name}); err != nil {
		s.logger.ErrorContext(r.Context(), "restoring group name failed; access rules still name the previous one",
			slog.String("group_id", group.PK),
			slog.String("previous_name", group.Name),
			slog.Any("error", err),
		)
	}
}

// listGroupMembers returns a page of the direct members of a group, ordered by
// username. The query parameters search, page and page_size filter and page it.
func (s *Server) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := authentik.ListUsersParams{Search: q.Get("search"), Ordering: "username"}
	var ok bool
	if params.Page, params.PageSize, ok = parsePaging(w, q); !ok {
		return
	}
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	params.GroupsByPK = []string{group.PK}

	list, err := s.users.ListUsers(r.Context(), params)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	// authentik silently ignores filters it does not know, so drop non-members
	// in case the filter was not applied.
	list.Results = slices.DeleteFunc(list.Results, func(u authentik.User) bool {
		return !slices.ContainsFunc(u.Groups, func(g authentik.UserGroup) bool { return g.PK == group.PK })
	})
	// Only access administrators list the members, and they may change every user.
	writeJSON(w, http.StatusOK, newUserPage(list, access.Scope{All: true}))
}

func (s *Server) addGroupMember(w http.ResponseWriter, r *http.Request) {
	group, user, ok := s.loadGroupMember(w, r)
	if !ok {
		return
	}
	if err := s.users.AddUserToGroup(r.Context(), group.PK, user.PK); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.recordUser(r, audit.ActionUserGroupAdded, user, map[string]string{"group": group.Name})
	w.WriteHeader(http.StatusNoContent)
}

// removeGroupMember removes a user from a group. It refuses to remove a user
// from their primary group; another one has to be chosen first.
func (s *Server) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	group, user, ok := s.loadGroupMember(w, r)
	if !ok {
		return
	}
	if pg := primaryGroup(user); pg != nil && pg.PK == group.PK {
		writeError(w, http.StatusConflict,
			fmt.Sprintf("%q is the primary group of %s. Choose another primary group for the user first.", group.Name, user.Username), nil)
		return
	}
	if err := s.users.RemoveUserFromGroup(r.Context(), group.PK, user.PK); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.recordUser(r, audit.ActionUserGroupRemoved, user, map[string]string{"group": group.Name})
	w.WriteHeader(http.StatusNoContent)
}

// loadGroupMember loads the group with the {pk} path value and the user with
// the {id} path value, writing the error response when it returns false.
func (s *Server) loadGroupMember(w http.ResponseWriter, r *http.Request) (*authentik.Group, *authentik.User, bool) {
	id, ok := pathID(w, r)
	if !ok {
		return nil, nil, false
	}
	group, ok := s.loadGroup(w, r)
	if !ok {
		return nil, nil, false
	}
	user, err := s.users.GetUser(r.Context(), id)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return nil, nil, false
	}
	return group, user, true
}

// writeGroupError is writeUpstreamError for requests about a group.
func (s *Server) writeGroupError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, authentik.ErrNotFound) {
		writeError(w, http.StatusNotFound, "group not found", nil)
		return
	}
	s.writeUpstreamError(w, r, err)
}
