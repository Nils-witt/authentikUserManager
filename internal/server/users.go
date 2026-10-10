package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

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
	for _, t := range q["type"] {
		ut := authentik.UserType(t)
		if !ut.Valid() {
			writeError(w, http.StatusBadRequest, "unknown user type", nil)
			return
		}
		params.Type = append(params.Type, ut)
	}

	list, err := s.users.ListUsers(r.Context(), params)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) listUserPaths(w http.ResponseWriter, r *http.Request) {
	paths, err := s.users.ListUserPaths(r.Context())
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"paths": paths})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	user, err := s.users.GetUser(r.Context(), id)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req authentik.CreateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Name = strings.TrimSpace(req.Name)
	fields := map[string][]string{}
	if req.Username == "" {
		fields["username"] = []string{"Username is required."}
	}
	if req.Name == "" {
		fields["name"] = []string{"Name is required."}
	}
	if req.Type != "" && !req.Type.Valid() {
		fields["type"] = []string{"Unknown user type."}
	}
	if len(fields) > 0 {
		writeError(w, http.StatusBadRequest, "validation failed", fields)
		return
	}

	user, err := s.users.CreateUser(r.Context(), req)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.audit(r, "user created", slog.Int("user_id", user.PK), slog.String("username", user.Username))
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req authentik.UpdateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Type != nil && !req.Type.Valid() {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"type": {"Unknown user type."}})
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

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.users.DeleteUser(r.Context(), id); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.audit(r, "user deleted", slog.Int("user_id", id))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"password": {"Password is required."}})
		return
	}
	if err := s.users.SetPassword(r.Context(), id, req.Password); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.audit(r, "user password set", slog.Int("user_id", id))
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
