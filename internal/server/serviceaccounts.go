package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// Limits of service account tokens.
const (
	maxTokenDescriptionLen = 255
	// maxTokenIdentifierLen is authentik's limit for token identifiers.
	maxTokenIdentifierLen = 255
)

// Service accounts share the handlers of users (see accountKind) for listing,
// creating, changing, deleting and grouping them. The handlers here manage
// their tokens and certificates, which only the operators who may change the
// service account may see.

// tokenList is the body of GET /api/service-accounts/{id}/tokens.
type tokenList struct {
	Tokens []authentik.Token `json:"tokens"`
}

// listServiceAccountTokens returns the tokens of the service account with the
// {id} path value, without their keys.
func (s *Server) listServiceAccountTokens(w http.ResponseWriter, r *http.Request) {
	account, _, ok := s.changeableAccount(w, r, serviceAccounts)
	if !ok {
		return
	}
	tokens, err := s.users.ListTokens(r.Context(), account.PK, account.Username)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenList{Tokens: tokens})
}

// createTokenInput is the body of POST /api/service-accounts/{id}/tokens.
type createTokenInput struct {
	Intent      authentik.TokenIntent `json:"intent"`
	Description string                `json:"description"`
	// Expires is when the token expires; nil for a token that never expires.
	Expires *time.Time `json:"expires"`
}

// validate checks the input at now and returns the authentik request without
// its identifier and user, or the validation messages per field.
func (in createTokenInput) validate(now time.Time) (authentik.CreateTokenRequest, map[string][]string) {
	req := authentik.CreateTokenRequest{
		Intent:      in.Intent,
		Description: strings.TrimSpace(in.Description),
		Expiring:    in.Expires != nil,
		Expires:     in.Expires,
	}
	fields := map[string][]string{}
	if !in.Intent.Valid() {
		fields["intent"] = []string{`The intent must be "api" or "app_password".`}
	}
	if len(req.Description) > maxTokenDescriptionLen {
		fields["description"] = []string{fmt.Sprintf("The description must be at most %d characters.", maxTokenDescriptionLen)}
	}
	if in.Expires != nil && !in.Expires.After(now) {
		fields["expires"] = []string{"The expiry must be in the future."}
	}
	return req, fields
}

// createdToken answers a token creation; Key is shown this once.
type createdToken struct {
	Token authentik.Token `json:"token"`
	Key   string          `json:"key"`
}

// newTokenIdentifier returns a random identifier for a token of account. It
// is a slug, as authentik requires, and names the account's primary key.
func newTokenIdentifier(account *authentik.User) string {
	return "am-" + strconv.Itoa(account.PK) + "-" + strings.ToLower(rand.Text())
}

// createServiceAccountToken creates a token for the service account with the
// {id} path value and returns it with its key, which is not shown again.
func (s *Server) createServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	var in createTokenInput
	if !decodeJSON(w, r, &in) {
		return
	}
	req, fields := in.validate(time.Now())
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
	req.Identifier = newTokenIdentifier(account)
	req.UserPK = account.PK

	token, err := s.users.CreateToken(r.Context(), req)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	// authentik assigns tokens created by an API user who is no superuser to
	// that user, so the token would authenticate as this application. Never
	// hand it out.
	if token.UserPK != account.PK {
		s.discardToken(r, token.Identifier)
		s.logger.ErrorContext(r.Context(), "authentik created a token for another user; the API token's user must be a superuser",
			slog.Int("user_id", account.PK),
			slog.Int("token_user_id", token.UserPK),
		)
		writeError(w, http.StatusBadGateway, "authentik created the token for another user, so it was deleted again", nil)
		return
	}
	key, err := s.users.TokenKey(r.Context(), token.Identifier)
	if err != nil {
		// Nobody would know the key, so do not leave the token behind.
		s.discardToken(r, token.Identifier)
		s.writeUpstreamError(w, r, err)
		return
	}
	details := map[string]string{"identifier": token.Identifier, "intent": string(token.Intent)}
	if token.Expires != nil {
		details["expires"] = token.Expires.UTC().Format(time.RFC3339)
	}
	s.recordUser(r, audit.ActionTokenCreated, account, details)

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, createdToken{Token: *token, Key: key})
}

// discardToken deletes a token that was just created but cannot be handed out,
// logging a failure, since the request fails anyway.
func (s *Server) discardToken(r *http.Request, identifier string) {
	if err := s.users.DeleteToken(context.WithoutCancel(r.Context()), identifier); err != nil {
		s.logger.ErrorContext(r.Context(), "deleting a token that cannot be handed out; delete it in authentik",
			slog.String("identifier", identifier),
			slog.Any("error", err),
		)
	}
}

// validTokenIdentifier reports whether id can be an authentik token
// identifier, which is a slug.
func validTokenIdentifier(id string) bool {
	if id == "" || len(id) > maxTokenIdentifierLen {
		return false
	}
	for _, c := range id {
		isAlnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !isAlnum && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// deleteServiceAccountToken deletes the token with the {identifier} path value
// of the service account with the {id} path value. Tokens authentik manages
// itself cannot be deleted.
func (s *Server) deleteServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	identifier := r.PathValue("identifier")
	if !validTokenIdentifier(identifier) {
		writeError(w, http.StatusBadRequest, "invalid token identifier", nil)
		return
	}
	account, _, ok := s.changeableAccount(w, r, serviceAccounts)
	if !ok {
		return
	}
	token, err := s.users.GetToken(r.Context(), identifier)
	// Tokens of other users are reported as not found.
	if errors.Is(err, authentik.ErrNotFound) || err == nil && token.UserPK != account.PK {
		writeError(w, http.StatusNotFound, "token not found", nil)
		return
	}
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	if token.IsManaged() {
		writeError(w, http.StatusConflict, "authentik manages this token itself", nil)
		return
	}
	if err := s.users.DeleteToken(r.Context(), identifier); err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	s.recordUser(r, audit.ActionTokenDeleted, account, map[string]string{
		"identifier": identifier,
		"intent":     string(token.Intent),
	})
	w.WriteHeader(http.StatusNoContent)
}

// listServiceAccountCertificates returns the certificates of the service
// account with the {id} path value, without their keys. Each is marked
// downloadable while the signed-in operator can download its generated key.
func (s *Server) listServiceAccountCertificates(w http.ResponseWriter, r *http.Request) {
	account, ok := s.certificateAccount(w, r, serviceAccounts)
	if !ok {
		return
	}
	list, err := s.certificates.ListCertificates(r.Context(), account.PK)
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, certificateList[ownCertificate]{Certificates: s.withDownloads(r, list)})
}

// issueServiceAccountCertificate issues a client certificate for the active
// service account with the {id} path value, for the operators who may change
// it. A generated key is held for a single download by the issuing operator.
func (s *Server) issueServiceAccountCertificate(w http.ResponseWriter, r *http.Request) {
	var in issueCertificateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	pub, fields := in.validate()
	if fields != nil {
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
	s.issueFor(w, r, account, pub, in)
}
