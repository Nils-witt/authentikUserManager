package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"authentikManager/internal/apikey"
	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// maxAPIKeyDescriptionLen bounds the descriptions of API keys.
const maxAPIKeyDescriptionLen = 255

// The operators who may change a service account manage its API keys, with
// which it issues and revokes its own certificates through the service API
// (see serviceapi.go).

// requireAPIKeys answers 501 for h while no API key store is configured.
func (s *Server) requireAPIKeys(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKeys == nil {
			writeError(w, http.StatusNotImplemented, "API keys are not configured", nil)
			return
		}
		h(w, r)
	})
}

// apiKeyList is the body of GET /api/service-accounts/{id}/api-keys.
type apiKeyList struct {
	APIKeys []apikey.Key `json:"api_keys"`
}

// listAPIKeys returns the API keys of the service account with the {id} path
// value, without the keys themselves.
func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	account, _, ok := s.changeableAccount(w, r, serviceAccounts)
	if !ok {
		return
	}
	list, err := s.apiKeys.ListAPIKeys(r.Context(), account.PK)
	if err != nil {
		s.writeAPIKeyError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, apiKeyList{APIKeys: list})
}

// createAPIKeyInput is the body of POST /api/service-accounts/{id}/api-keys.
type createAPIKeyInput struct {
	Description string `json:"description"`
	// Expires is when the key expires; nil for a key that never expires.
	Expires *time.Time `json:"expires"`
}

// validate checks the input at now and returns the key record without its
// account, start and creator, or the validation messages per field.
func (in createAPIKeyInput) validate(now time.Time) (apikey.Key, map[string][]string) {
	k := apikey.Key{Description: strings.TrimSpace(in.Description), ExpiresAt: in.Expires}
	fields := map[string][]string{}
	if len(k.Description) > maxAPIKeyDescriptionLen {
		fields["description"] = []string{fmt.Sprintf("The description must be at most %d characters.", maxAPIKeyDescriptionLen)}
	}
	if in.Expires != nil && !in.Expires.After(now) {
		fields["expires"] = []string{"The expiry must be in the future."}
	}
	return k, fields
}

// createdAPIKey answers an API key creation; Key is shown this once.
type createdAPIKey struct {
	APIKey apikey.Key `json:"api_key"`
	Key    string     `json:"key"`
}

// createAPIKey creates an API key for the active service account with the
// {id} path value and returns it with the key, which is not shown again.
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var in createAPIKeyInput
	if !decodeJSON(w, r, &in) {
		return
	}
	k, fields := in.validate(time.Now())
	if len(fields) > 0 {
		writeError(w, http.StatusBadRequest, "validation failed", fields)
		return
	}
	account, _, ok := s.changeableAccount(w, r, serviceAccounts)
	if !ok {
		return
	}
	if !account.IsActive {
		writeError(w, http.StatusConflict, "the service account is inactive", nil)
		return
	}
	key, start, hash := apikey.New()
	k.UserPK, k.Username, k.Start, k.CreatedBy = account.PK, account.Username, start, actorName(r)
	created, err := s.apiKeys.CreateAPIKey(r.Context(), k, hash)
	if err != nil {
		s.writeAPIKeyError(w, r, err)
		return
	}
	details := map[string]string{"api_key_id": strconv.FormatInt(created.ID, 10), "start": created.Start}
	if created.ExpiresAt != nil {
		details["expires"] = created.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.recordUser(r, audit.ActionAPIKeyCreated, account, details)

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, createdAPIKey{APIKey: created, Key: key})
}

// deleteAPIKey deletes the API key with the {keyID} path value of the service
// account with the {id} path value. Requests with it are rejected at once.
func (s *Server) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("keyID"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "invalid API key id", nil)
		return
	}
	account, _, ok := s.changeableAccount(w, r, serviceAccounts)
	if !ok {
		return
	}
	deleted, err := s.apiKeys.DeleteAPIKey(r.Context(), account.PK, id)
	if err != nil {
		s.writeAPIKeyError(w, r, err)
		return
	}
	s.recordUser(r, audit.ActionAPIKeyDeleted, account, map[string]string{
		"api_key_id": strconv.FormatInt(deleted.ID, 10),
		"start":      deleted.Start,
	})
	w.WriteHeader(http.StatusNoContent)
}

// deleteUserAPIKeys deletes every API key of user, recording how many it
// deleted. It is called before a service account is deleted, so that a new
// account given the same primary key could not use them.
func (s *Server) deleteUserAPIKeys(ctx context.Context, r *http.Request, user *authentik.User) error {
	if s.apiKeys == nil || !user.Type.IsServiceAccount() {
		return nil
	}
	n, err := s.apiKeys.DeleteUserAPIKeys(ctx, user.PK)
	if err != nil {
		return err
	}
	if n > 0 {
		s.recordUser(r, audit.ActionAPIKeyDeleted, user, map[string]string{
			"count":  strconv.FormatInt(n, 10),
			"reason": reasonUserDeleted,
		})
	}
	return nil
}

// writeAPIKeyError translates an API key store error into a response.
func (s *Server) writeAPIKeyError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, apikey.ErrNotFound):
		writeError(w, http.StatusNotFound, "API key not found", nil)
	case errors.Is(err, context.Canceled):
	default:
		s.logger.ErrorContext(r.Context(), "API key store failed",
			slog.String("path", r.URL.Path),
			slog.Any("error", err),
		)
		writeError(w, http.StatusInternalServerError, "API key store failed", nil)
	}
}
