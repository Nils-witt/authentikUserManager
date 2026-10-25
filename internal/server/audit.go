package server

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// auditTimeout bounds writing an audit entry, which outlives the request.
const auditTimeout = 5 * time.Second

// record adds an entry by the logged-in operator to the audit log and the
// application log. The change it describes has already been made, so a
// failure to store it is logged rather than reported to the client.
func (s *Server) record(r *http.Request, action audit.Action, target string, details map[string]string) {
	details = maps.Clone(details)
	if details == nil {
		details = map[string]string{}
	}
	details["client_ip"] = s.clientIP(r)
	if caller, ok := apiCallerFrom(r.Context()); ok {
		// Changes made through the service API name the API key used.
		details["api_key_id"] = strconv.FormatInt(caller.keyID, 10)
	}
	e := audit.Entry{Actor: actorName(r), Action: action, Target: target, Details: details}
	s.logger.LogAttrs(r.Context(), slog.LevelInfo, "audit",
		slog.String("actor", e.Actor),
		slog.String("action", string(e.Action)),
		slog.String("target", e.Target),
		slog.Any("details", e.Details),
	)

	// Store the entry even when the client has gone away meanwhile.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditTimeout)
	defer cancel()
	if err := s.auditLog.RecordAudit(ctx, e); err != nil {
		s.logger.ErrorContext(r.Context(), "recording audit entry failed",
			slog.String("action", string(e.Action)),
			slog.Any("error", err),
		)
	}
}

// recordUser adds an entry about user to the audit log; details may be nil.
// Entries about service accounts carry their type.
func (s *Server) recordUser(r *http.Request, action audit.Action, user *authentik.User, details map[string]string) {
	if details == nil {
		details = map[string]string{}
	}
	details["user_id"] = strconv.Itoa(user.PK)
	if user.Type == authentik.UserTypeServiceAccount {
		details["type"] = string(user.Type)
	}
	s.record(r, action, user.Username, details)
}

// updatedFields lists the names of the fields req changes, for the audit log.
func updatedFields(req authentik.UpdateUserRequest) string {
	var fields []string
	if req.Username != nil {
		fields = append(fields, "username")
	}
	if req.Name != nil {
		fields = append(fields, "name")
	}
	if req.Email != nil {
		fields = append(fields, "email")
	}
	if req.IsActive != nil {
		fields = append(fields, "is_active")
	}
	if req.Path != nil {
		fields = append(fields, "path")
	}
	if req.Type != nil {
		fields = append(fields, "type")
	}
	if req.Attributes != nil {
		fields = append(fields, "attributes")
	}
	return strings.Join(fields, ",")
}

// auditPage is the response of GET /api/audit.
type auditPage struct {
	Entries []audit.Entry `json:"entries"`
	// Next is the value of the "before" parameter for the next page; it is
	// omitted on the last page.
	Next int64 `json:"next,omitempty"`
}

// listAudit returns a page of the audit log, newest first. The query parameters
// search, action, before and limit filter and page it (see audit.Query).
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	q := audit.Query{Search: params.Get("search"), Action: audit.Action(params.Get("action"))}
	var err error
	if v := params.Get("before"); v != "" {
		if q.Before, err = strconv.ParseInt(v, 10, 64); err != nil || q.Before < 1 {
			writeError(w, http.StatusBadRequest, "before must be a positive integer", nil)
			return
		}
	}
	if v := params.Get("limit"); v != "" {
		if q.Limit, err = strconv.Atoi(v); err != nil || q.Limit < 1 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("limit must be between 1 and %d", audit.MaxLimit), nil)
			return
		}
	}
	if q, err = q.Normalize(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// One more entry than requested tells whether there is another page.
	limit := q.Limit
	q.Limit++
	entries, err := s.auditLog.ListAudit(r.Context(), q)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "loading audit log failed", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "loading the audit log failed", nil)
		return
	}
	page := auditPage{Entries: entries}
	if len(entries) > limit {
		page.Entries = entries[:limit]
		page.Next = page.Entries[limit-1].ID
	}
	if page.Entries == nil {
		page.Entries = []audit.Entry{}
	}
	writeJSON(w, http.StatusOK, page)
}
