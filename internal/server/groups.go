package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// The group handlers are restricted to access administrators (see requireAdmin),
// who have full access, so they do not check the operator's scope.

// listGroups returns a page of authentik groups, ordered by name. The query
// parameters search, page and page_size filter and page it.
func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := authentik.ListGroupsParams{Search: q.Get("search")}
	var ok bool
	if params.Page, params.PageSize, ok = parsePaging(w, q); !ok {
		return
	}
	list, err := s.users.ListGroups(r.Context(), params)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
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
	writeJSON(w, http.StatusOK, group)
}

// renameGroup renames a group in authentik and in every access rule naming
// it, since the rules match groups by name.
func (s *Server) renameGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"name": {"Name is required."}})
		return
	}
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if name == group.Name {
		writeJSON(w, http.StatusOK, group)
		return
	}
	msg, ok := s.checkGroupName(w, r, group, name)
	if !ok {
		return
	}
	if msg != "" {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"name": {msg}})
		return
	}

	updated, err := s.users.UpdateGroup(r.Context(), group.PK, authentik.UpdateGroupRequest{Name: &name})
	if err != nil {
		s.writeGroupError(w, r, err)
		return
	}
	changed, err := s.rules.RenameGroup(r.Context(), group.Name, updated.Name, actorName(r))
	if err != nil {
		s.undoRename(r, group)
		s.writeStoreError(w, r, err)
		return
	}
	s.record(r, audit.ActionGroupRenamed, updated.Name, map[string]string{
		"group_id":      updated.PK,
		"previous_name": group.Name,
		"rules_changed": strconv.FormatInt(changed, 10),
	})
	writeJSON(w, http.StatusOK, updated)
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
// not be renamed, so the rules keep matching it.
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
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) addGroupMember(w http.ResponseWriter, r *http.Request) {
	s.changeGroupMember(w, r, s.users.AddUserToGroup, audit.ActionUserGroupAdded)
}

func (s *Server) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	s.changeGroupMember(w, r, s.users.RemoveUserFromGroup, audit.ActionUserGroupRemoved)
}

// changeGroupMember adds the user with the {id} path value to the group with
// the {pk} path value, or removes them, using change.
func (s *Server) changeGroupMember(w http.ResponseWriter, r *http.Request,
	change func(ctx context.Context, groupPK string, userID int) error, action audit.Action,
) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	user, err := s.users.GetUser(r.Context(), id)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	if err := change(r.Context(), group.PK, user.PK); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.recordUser(r, action, user, map[string]string{"group": group.Name})
	w.WriteHeader(http.StatusNoContent)
}

// writeGroupError is writeUpstreamError for requests about a group.
func (s *Server) writeGroupError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, authentik.ErrNotFound) {
		writeError(w, http.StatusNotFound, "group not found", nil)
		return
	}
	s.writeUpstreamError(w, r, err)
}
