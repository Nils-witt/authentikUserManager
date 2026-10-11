package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
	"authentikManager/internal/joinrequest"
)

// Every signed-in user may request to join a visible group. The operators who
// may manage the group's members (see access.Scope.HasGroup) decide the
// request; nobody decides their own.

// joinRequestList is the response of the join request lists.
type joinRequestList struct {
	Requests []joinrequest.Request `json:"requests"`
}

func writeJoinRequests(w http.ResponseWriter, list []joinrequest.Request) {
	if list == nil {
		list = []joinrequest.Request{}
	}
	writeJSON(w, http.StatusOK, joinRequestList{Requests: list})
}

// requestJoin lets the signed-in user request to join the visible group with
// the {pk} path value. The body may hold a message for the deciders.
func (s *Server) requestJoin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Message string `json:"message"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	msg, err := joinrequest.NormalizeMessage(in.Message)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"message": {err.Error()}})
		return
	}
	group, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	// Hidden groups are reported as not found so their existence is not revealed.
	if !isVisible(group) {
		writeError(w, http.StatusNotFound, "group not found", nil)
		return
	}
	// Restricted operators may not add users to superuser groups, so only
	// access administrators could decide; they add members directly instead.
	if group.IsSuperuser {
		writeError(w, http.StatusForbidden, "this group cannot be requested", nil)
		return
	}
	user, ok := s.requester(w, r)
	if !ok {
		return
	}
	if slices.ContainsFunc(user.Groups, func(g authentik.UserGroup) bool { return g.PK == group.PK }) {
		writeError(w, http.StatusConflict, "you are already a member of this group", nil)
		return
	}

	created, err := s.joinRequests.CreateJoinRequest(r.Context(), joinrequest.Request{
		GroupPK:   group.PK,
		GroupName: group.Name,
		UserPK:    user.PK,
		Username:  user.Username,
		Message:   msg,
	})
	if errors.Is(err, joinrequest.ErrPending) {
		writeError(w, http.StatusConflict, "you already requested to join this group", nil)
		return
	}
	if err != nil {
		s.writeJoinRequestError(w, r, err)
		return
	}
	s.record(r, audit.ActionJoinRequested, user.Username, joinRequestDetails(created, group.Name))
	writeJSON(w, http.StatusCreated, created)
}

// requester loads the authentik account of the signed-in user, writing the
// error response when it returns false. Only internal users may join groups
// here, like only internal users are managed here.
func (s *Server) requester(w http.ResponseWriter, r *http.Request) (*authentik.User, bool) {
	user, err := s.findRequester(r)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return nil, false
	}
	if user == nil {
		writeError(w, http.StatusForbidden, "only internal users can request to join groups", nil)
		return nil, false
	}
	return user, true
}

// findRequester returns the internal authentik account of the signed-in user,
// or nil when there is none. Unlike the groups read at login, its groups are current.
func (s *Server) findRequester(r *http.Request) (*authentik.User, error) {
	return s.findActor(r, authentik.ListUsersParams{})
}

// listMyJoinRequests returns the requests of the signed-in user, newest first.
func (s *Server) listMyJoinRequests(w http.ResponseWriter, r *http.Request) {
	list, err := s.joinRequests.ListJoinRequests(r.Context(), joinrequest.Query{Username: actorName(r)})
	if err != nil {
		s.writeJoinRequestError(w, r, err)
		return
	}
	writeJoinRequests(w, list)
}

// withdrawJoinRequest deletes a pending request of the signed-in user.
func (s *Server) withdrawJoinRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := joinRequestID(w, r)
	if !ok {
		return
	}
	jr, err := s.joinRequests.GetJoinRequest(r.Context(), id)
	// Requests of other users are reported as not found.
	if err == nil && jr.Username != actorName(r) {
		err = joinrequest.ErrNotFound
	}
	if err == nil && jr.Status != joinrequest.StatusPending {
		err = joinrequest.ErrDecided
	}
	if err == nil {
		err = s.joinRequests.WithdrawJoinRequest(r.Context(), id, jr.Username)
	}
	if err != nil {
		s.writeJoinRequestError(w, r, err)
		return
	}
	s.record(r, audit.ActionJoinWithdrawn, jr.Username, joinRequestDetails(jr, jr.GroupName))
	w.WriteHeader(http.StatusNoContent)
}

// listJoinRequests returns the pending requests the signed-in operator may
// decide, newest first: those for the groups whose members they may manage,
// except their own.
func (s *Server) listJoinRequests(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	if scope.Empty() {
		writeJoinRequests(w, nil)
		return
	}
	q := joinrequest.Query{Status: joinrequest.StatusPending}
	if !scope.All {
		pks, ok := s.groupPKs(w, r, scope.Groups)
		if !ok {
			return
		}
		if len(pks) == 0 {
			writeJoinRequests(w, nil)
			return
		}
		q.GroupPKs = pks
	}
	list, err := s.joinRequests.ListJoinRequests(r.Context(), q)
	if err != nil {
		s.writeJoinRequestError(w, r, err)
		return
	}
	actor := actorName(r)
	list = slices.DeleteFunc(list, func(jr joinrequest.Request) bool { return jr.Username == actor })
	writeJoinRequests(w, list)
}

// groupPKs returns the primary keys of the named groups, skipping unknown
// names. It writes the error response when it returns false.
func (s *Server) groupPKs(w http.ResponseWriter, r *http.Request, names []string) ([]string, bool) {
	pks := make([]string, 0, len(names))
	for _, name := range names {
		group, err := s.users.FindGroup(r.Context(), name)
		if errors.Is(err, authentik.ErrNotFound) {
			continue
		}
		if err != nil {
			s.writeUpstreamError(w, r, err)
			return nil, false
		}
		pks = append(pks, group.PK)
	}
	return pks, true
}

func (s *Server) approveJoinRequest(w http.ResponseWriter, r *http.Request) {
	s.decideJoinRequest(w, r, joinrequest.StatusApproved)
}

func (s *Server) rejectJoinRequest(w http.ResponseWriter, r *http.Request) {
	s.decideJoinRequest(w, r, joinrequest.StatusRejected)
}

// decideJoinRequest approves or rejects the pending request with the {id}
// path value. Approving adds the user to the group.
func (s *Server) decideJoinRequest(w http.ResponseWriter, r *http.Request, status joinrequest.Status) {
	id, ok := joinRequestID(w, r)
	if !ok {
		return
	}
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	jr, err := s.joinRequests.GetJoinRequest(r.Context(), id)
	if err == nil && jr.Status != joinrequest.StatusPending {
		err = joinrequest.ErrDecided
	}
	if err != nil {
		s.writeJoinRequestError(w, r, err)
		return
	}
	group, ok := s.joinRequestGroup(w, r, jr, status, scope)
	if !ok {
		return
	}
	// Such a group would make the user an administrator the operator could not manage.
	if status == joinrequest.StatusApproved && group.IsSuperuser && !scope.All {
		writeError(w, http.StatusForbidden, "you may not add users to an administrator group", nil)
		return
	}

	// Decide first, so that a concurrent decision cannot disagree with the membership.
	decided, err := s.joinRequests.DecideJoinRequest(r.Context(), id, status, actorName(r))
	if err != nil {
		s.writeJoinRequestError(w, r, err)
		return
	}
	action := audit.ActionJoinRejected
	if status == joinrequest.StatusApproved {
		action = audit.ActionJoinApproved
		if err := s.users.AddUserToGroup(r.Context(), group.PK, jr.UserPK); err != nil {
			s.reopenJoinRequest(r, id)
			s.writeUpstreamError(w, r, err)
			return
		}
	}
	s.record(r, action, jr.Username, joinRequestDetails(decided, group.Name))
	writeJSON(w, http.StatusOK, decided)
}

// joinRequestGroup loads the group of jr and checks that the operator may
// decide jr with status. It writes the error response when it returns false.
func (s *Server) joinRequestGroup(w http.ResponseWriter, r *http.Request,
	jr joinrequest.Request, status joinrequest.Status, scope access.Scope,
) (*authentik.Group, bool) {
	if jr.Username == actorName(r) {
		writeError(w, http.StatusForbidden, "you cannot decide your own join request", nil)
		return nil, false
	}
	group, err := s.users.GetGroup(r.Context(), jr.GroupPK)
	switch {
	case errors.Is(err, authentik.ErrNotFound) && status == joinrequest.StatusRejected:
		// A request for a deleted group can still be rejected, by the
		// operators who managed the group under its requested name.
		group = &authentik.Group{PK: jr.GroupPK, Name: jr.GroupName}
	case err != nil:
		s.writeGroupError(w, r, err)
		return nil, false
	}
	// Requests the operator may not decide are reported as not found, like users outside their scope.
	if !scope.HasGroup(group.Name) {
		writeError(w, http.StatusNotFound, "join request not found", nil)
		return nil, false
	}
	return group, true
}

// reopenJoinRequest makes an approved request pending again after the user
// could not be added to the group, so it can be decided again.
func (s *Server) reopenJoinRequest(r *http.Request, id int64) {
	// Reopen it even when the client has gone away meanwhile.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditTimeout)
	defer cancel()
	if err := s.joinRequests.ReopenJoinRequest(ctx, id); err != nil {
		s.logger.ErrorContext(r.Context(), "reopening join request failed; it stays approved although the user was not added",
			slog.Int64("request_id", id),
			slog.Any("error", err),
		)
	}
}

// joinRequestDetails returns the audit details of jr, naming its group groupName.
func joinRequestDetails(jr joinrequest.Request, groupName string) map[string]string {
	return map[string]string{
		"request_id": strconv.FormatInt(jr.ID, 10),
		"group":      groupName,
		"group_id":   jr.GroupPK,
		"user_id":    strconv.Itoa(jr.UserPK),
	}
}

// joinRequestID parses the {id} path value, writing a 400 response when it is invalid.
func joinRequestID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "invalid join request id", nil)
		return 0, false
	}
	return id, true
}

// writeJoinRequestError translates a join request store error into a response.
func (s *Server) writeJoinRequestError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, joinrequest.ErrNotFound):
		writeError(w, http.StatusNotFound, "join request not found", nil)
	case errors.Is(err, joinrequest.ErrDecided):
		writeError(w, http.StatusConflict, "join request already decided", nil)
	case errors.Is(err, context.Canceled):
	default:
		s.logger.ErrorContext(r.Context(), "join request store failed",
			slog.String("path", r.URL.Path),
			slog.Any("error", err),
		)
		writeError(w, http.StatusInternalServerError, "saving or loading join requests failed", nil)
	}
}
