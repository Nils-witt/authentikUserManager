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
// who have full access, so they do not check the operator's scope. Only they
// may create groups. The only exceptions are listVisibleGroups and requestJoin.

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

// pathAttribute is the authentik group attribute holding the group's path, such
// as "school/classes", which sorts the groups into folders like the user paths
// do. Groups without it are at the top level.
const pathAttribute = "authentik_manager_path"

// maxGroupPathLen bounds group paths.
const maxGroupPathLen = 255

// maxGroupPages bounds the pages of groups read by collectGroups.
const maxGroupPages = 50

// groupFolder returns the path of g, or "" when it is at the top level.
func groupFolder(g *authentik.Group) string {
	path, _ := g.Attributes[pathAttribute].(string)
	return path
}

// withGroupPath returns a copy of attrs with the path set, or removed when path
// is empty, leaving the other attributes as they are. It never returns nil, so
// an update clearing the last attribute is still sent.
func withGroupPath(attrs map[string]any, path string) map[string]any {
	out := maps.Clone(attrs)
	if out == nil {
		out = map[string]any{}
	}
	if path != "" {
		out[pathAttribute] = path
	} else {
		delete(out, pathAttribute)
	}
	return out
}

// normalizeGroupPath trims the spaces around path and the slashes at its ends.
// When path is invalid it returns a message that is safe to show users.
func normalizeGroupPath(path string) (string, string) {
	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return "", ""
	}
	if len(path) > maxGroupPathLen {
		return "", fmt.Sprintf("Path must be at most %d characters.", maxGroupPathLen)
	}
	for folder := range strings.SplitSeq(path, "/") {
		if strings.TrimSpace(folder) == "" {
			return "", "Folder names in the path must not be empty."
		}
	}
	return path, ""
}

// inFolder reports whether g has the path params filters for, if any.
func inFolder(g *authentik.Group, params authentik.ListGroupsParams) bool {
	want, ok := params.Attributes[pathAttribute]
	return !ok || groupFolder(g) == want
}

// groupView is a group as access administrators see it. It leaves out the
// other attributes, which authentik and other applications use.
type groupView struct {
	PK          string `json:"pk"`
	Name        string `json:"name"`
	IsSuperuser bool   `json:"is_superuser"`
	ParentName  string `json:"parent_name"`
	// Path sorts the group into folders; empty at the top level.
	Path string `json:"path"`
	// Visible is set when every signed-in user may see the group's name.
	Visible bool `json:"visible"`
}

func newGroupView(g *authentik.Group) groupView {
	return groupView{
		PK:          g.PK,
		Name:        g.Name,
		IsSuperuser: g.IsSuperuser,
		ParentName:  g.ParentName,
		Path:        groupFolder(g),
		Visible:     isVisible(g),
	}
}

// publicGroup is a group as operators who are no access administrators see it.
type publicGroup struct {
	PK         string `json:"pk"`
	Name       string `json:"name"`
	ParentName string `json:"parent_name"`
	// Path sorts the group into folders; empty at the top level.
	Path string `json:"path"`
	// Member is set when the signed-in user is a direct member of the group.
	Member bool `json:"member"`
	// Joinable is set when the signed-in user may request to join the group
	// (see requestJoin), unless already a member.
	Joinable bool `json:"joinable"`
}

// page is one page of a list response.
type page[T any] struct {
	Pagination authentik.Pagination `json:"pagination"`
	Results    []T                  `json:"results"`
}

// groupListParams parses the query parameters search, path, page and
// page_size of a group list, writing a 400 response when they are invalid.
// path matches the groups with exactly this path.
func groupListParams(w http.ResponseWriter, r *http.Request) (authentik.ListGroupsParams, bool) {
	q := r.URL.Query()
	params := authentik.ListGroupsParams{Search: q.Get("search")}
	if path := q.Get("path"); path != "" {
		params.Attributes = map[string]any{pathAttribute: path}
	}
	var ok bool
	params.Page, params.PageSize, ok = parsePaging(w, q)
	return params, ok
}

// listGroups returns a page of authentik groups, ordered by name. The query
// parameters search, path, page and page_size filter and page it.
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
	out := page[groupView]{Pagination: list.Pagination, Results: make([]groupView, 0, len(list.Results))}
	for i := range list.Results {
		// authentik silently ignores filters it does not know, so drop groups
		// in other folders in case the filter was not applied.
		if g := &list.Results[i]; inFolder(g, params) {
			out.Results = append(out.Results, newGroupView(g))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// collectGroups returns the groups matching params and keep, ignoring the
// paging of params. It reads at most maxGroupPages pages.
func (s *Server) collectGroups(r *http.Request, params authentik.ListGroupsParams, keep func(*authentik.Group) bool) ([]authentik.Group, error) {
	params.PageSize = maxPageSize
	out := []authentik.Group{}
	for params.Page = 1; ; params.Page++ {
		list, err := s.users.ListGroups(r.Context(), params)
		if err != nil {
			return nil, err
		}
		for i := range list.Results {
			if g := &list.Results[i]; keep(g) {
				out = append(out, *g)
			}
		}
		if list.Pagination.Next == 0 {
			return out, nil
		}
		if params.Page == maxGroupPages {
			s.logger.WarnContext(r.Context(), "too many groups; using only the first ones",
				slog.Int("groups", params.Page*params.PageSize))
			return out, nil
		}
	}
}

// listableGroups returns a predicate reporting whether an operator with scope
// who is no access administrator sees a group in the group list: the visible
// groups, the operator's own groups and the groups of the accounts the
// operator may see. It also returns the operator's own account, or nil when
// it is not found.
func (s *Server) listableGroups(r *http.Request, scope access.Scope) (func(*authentik.Group) bool, *authentik.User, error) {
	// The groups read at login miss the ones joined since, by an approved request for example.
	self, err := s.findRequester(r)
	if err != nil {
		return nil, nil, err
	}
	accounts, err := s.visibleAccounts(r, scope, userAccounts.typ, serviceAccounts.typ)
	if err != nil {
		return nil, nil, err
	}
	if self != nil {
		accounts = append(accounts, *self)
	}
	related := map[string]bool{}
	for _, u := range accounts {
		for _, g := range u.Groups {
			related[g.PK] = true
		}
	}
	return func(g *authentik.Group) bool { return isVisible(g) || related[g.PK] }, self, nil
}

// pageOf returns the page with the given number and size of items, numbered
// from 1 like authentik's pages.
func pageOf[T any](items []T, number, size int) ([]T, authentik.Pagination) {
	start := min((number-1)*size, len(items))
	end := min(start+size, len(items))
	p := authentik.Pagination{Count: len(items), Current: number, TotalPages: (len(items) + size - 1) / size}
	if number < p.TotalPages {
		p.Next = number + 1
	}
	if number > 1 {
		p.Previous = number - 1
	}
	if end > start {
		p.StartIndex, p.EndIndex = start+1, end
	}
	return items[start:end], p
}

// listVisibleGroups returns a page of the groups an operator who is no access
// administrator sees (see listableGroups), ordered by name, with their names
// only. It is open to every operator, including those who may not manage any
// users. The query parameters search, path, page and page_size filter and page
// it. Users may request to join the visible ones; see requestJoin.
func (s *Server) listVisibleGroups(w http.ResponseWriter, r *http.Request) {
	params, ok := groupListParams(w, r)
	if !ok {
		return
	}
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	listable, self, err := s.listableGroups(r, scope)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	// The groups are combined from several sources, so page them here.
	groups, err := s.collectGroups(r, params, func(g *authentik.Group) bool {
		// authentik silently ignores filters it does not know, so drop groups
		// in other folders in case the filter was not applied.
		return listable(g) && inFolder(g, params)
	})
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	isMember := func(*authentik.Group) bool { return false }
	if self != nil {
		isMember = func(g *authentik.Group) bool {
			return slices.ContainsFunc(self.Groups, func(ug authentik.UserGroup) bool { return ug.PK == g.PK })
		}
	}
	results, pagination := pageOf(groups, params.Page, params.PageSize)
	out := page[publicGroup]{Pagination: pagination, Results: make([]publicGroup, len(results))}
	for i := range results {
		g := &results[i]
		out.Results[i] = publicGroup{
			PK:         g.PK,
			Name:       g.Name,
			ParentName: g.ParentName,
			Path:       groupFolder(g),
			Member:     isMember(g),
			Joinable:   isVisible(g) && !g.IsSuperuser && !s.policy.IsAdmin([]string{g.Name}),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// listGroupPaths returns every distinct group path. Access administrators get
// the paths of all groups, everyone else those of the groups they see in the
// group list (see listableGroups).
func (s *Server) listGroupPaths(w http.ResponseWriter, r *http.Request) {
	keep := func(*authentik.Group) bool { return true }
	if !s.policy.IsAdmin(operatorGroups(r)) {
		scope, ok := s.scope(w, r)
		if !ok {
			return
		}
		listable, _, err := s.listableGroups(r, scope)
		if err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		keep = listable
	}
	groups, err := s.collectGroups(r, authentik.ListGroupsParams{}, keep)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	paths := []string{}
	for i := range groups {
		if path := groupFolder(&groups[i]); path != "" {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	writeJSON(w, http.StatusOK, map[string][]string{"paths": slices.Compact(paths)})
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

// newGroupInput is the body of POST /api/groups.
type newGroupInput struct {
	Name    string `json:"name"`
	Visible bool   `json:"visible"`
	// Path sorts the group into folders; empty puts it at the top level.
	Path string `json:"path"`
}

// createGroup creates a group without members, optionally visible to every
// signed-in user and in a folder. Its name must not be taken, since the access
// rules match groups by name.
func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in newGroupInput
	if !decodeJSON(w, r, &in) {
		return
	}
	fields := map[string][]string{}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		fields["name"] = append(fields["name"], "Name is required.")
	}
	path, msg := normalizeGroupPath(in.Path)
	if msg != "" {
		fields["path"] = append(fields["path"], msg)
	}
	if name != "" {
		msg, ok := s.checkGroupName(w, r, nil, name)
		if !ok {
			return
		}
		if msg != "" {
			fields["name"] = append(fields["name"], msg)
		}
	}
	if len(fields) > 0 {
		writeError(w, http.StatusBadRequest, "validation failed", fields)
		return
	}

	attrs := withGroupPath(withVisibility(nil, in.Visible), path)
	group, err := s.users.CreateGroup(r.Context(), authentik.CreateGroupRequest{Name: name, Attributes: attrs})
	if err != nil {
		s.writeGroupError(w, r, err)
		return
	}
	s.record(r, audit.ActionGroupCreated, group.Name, map[string]string{
		"group_id": group.PK,
		"visible":  strconv.FormatBool(isVisible(group)),
		"path":     groupFolder(group),
	})
	writeJSON(w, http.StatusCreated, newGroupView(group))
}

// groupInput is the body of PATCH /api/groups/{pk}; nil fields are left unchanged.
type groupInput struct {
	Name    *string `json:"name"`
	Visible *bool   `json:"visible"`
	// Path sorts the group into folders; empty moves it to the top level.
	Path *string `json:"path"`
}

// updateGroup renames a group, sets whether it is visible to every signed-in
// user and sets its path. A rename applies to every access rule naming the
// group too, since the rules match groups by name.
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
	if in.Path != nil {
		path, msg := normalizeGroupPath(*in.Path)
		if msg != "" {
			writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"path": {msg}})
			return
		}
		in.Path = &path
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
	if isVisible(updated) != isVisible(group) {
		s.record(r, audit.ActionGroupVisibilityChanged, updated.Name, map[string]string{
			"group_id": updated.PK,
			"visible":  strconv.FormatBool(isVisible(updated)),
		})
	}
	if previous := groupFolder(group); groupFolder(updated) != previous {
		s.record(r, audit.ActionGroupPathChanged, updated.Name, map[string]string{
			"group_id":      updated.PK,
			"path":          groupFolder(updated),
			"previous_path": previous,
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
	if in.Path != nil && *in.Path != groupFolder(group) {
		attrs := group.Attributes
		if req.Attributes != nil {
			attrs = req.Attributes
		}
		req.Attributes = withGroupPath(attrs, *in.Path)
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

// checkGroupName checks whether group may be renamed to name, or, when group
// is nil, whether a new group may be named name. It returns a message that is
// safe to show users when not, and writes the error response and returns false
// when the check itself fails.
func (s *Server) checkGroupName(w http.ResponseWriter, r *http.Request, group *authentik.Group, name string) (string, bool) {
	// The admin groups are configured by name, so renaming one would lock its
	// members out, and renaming a group to one would make its members access
	// administrators. A new group has no members, so it may take such a name.
	if group != nil && s.policy.IsAdmin([]string{group.Name}) {
		return "Access administrator groups (ACCESS_ADMIN_GROUPS) cannot be renamed here.", true
	}
	if group != nil && s.policy.IsAdmin([]string{name}) {
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
	case group == nil || other.PK != group.PK:
		return fmt.Sprintf("Another group is already named %q.", name), true
	}
	return "", true
}

// undoRename restores the previous name of group after its access rules could
// not be renamed, so the rules keep matching it. A visibility or path change
// made in the same update stays.
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
	writeJSON(w, http.StatusOK, newUserPage(list, access.Scope{All: true, IncludesHidden: true}))
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
	s.notifyGroupChanges(r, user, []string{fmt.Sprintf("Added to the group %q", group.Name)})
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
	s.notifyGroupChanges(r, user, []string{fmt.Sprintf("Removed from the group %q", group.Name)})
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
