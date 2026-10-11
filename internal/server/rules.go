package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
)

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.rules.ListRules(r.Context())
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if rules == nil {
		rules = []access.Rule{}
	}
	writeJSON(w, http.StatusOK, map[string][]access.Rule{"rules": rules})
}

func (s *Server) putRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TargetGroups []string `json:"target_groups"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	rule, err := access.Rule{OperatorGroup: r.PathValue("group"), TargetGroups: body.TargetGroups}.Normalize()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	actor := actorName(r)
	if err := s.rules.PutRule(r.Context(), rule, actor); err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	s.record(r, audit.ActionRuleSaved, rule.OperatorGroup,
		map[string]string{"target_groups": strings.Join(rule.TargetGroups, ",")})
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	group := strings.TrimSpace(r.PathValue("group"))
	err := s.rules.DeleteRule(r.Context(), group)
	if errors.Is(err, access.ErrRuleNotFound) {
		writeError(w, http.StatusNotFound, "rule not found", nil)
		return
	}
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	s.record(r, audit.ActionRuleDeleted, group, nil)
	w.WriteHeader(http.StatusNoContent)
}

// writeStoreError logs a database error and reports it generically.
func (s *Server) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.ErrorContext(r.Context(), "access rule store failed",
		slog.String("path", r.URL.Path),
		slog.Any("error", err),
	)
	writeError(w, http.StatusInternalServerError, "saving or loading access rules failed", nil)
}
