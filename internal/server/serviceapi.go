package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"authentikManager/internal/apikey"
	"authentikManager/internal/auth"
	"authentikManager/internal/authentik"
	"authentikManager/internal/certificate"
	"authentikManager/internal/pki"
)

// The service API lets service accounts issue certificates for CSRs and
// revoke their own certificates. They authenticate with an API key in the
// Authorization header ("Bearer amk_…") instead of a session, so the
// endpoints read no cookies. Its requests carry no Origin or Sec-Fetch-Site
// header, which the cross-origin protection lets through.

// apiCaller is the service account a service API request authenticated as.
type apiCaller struct {
	account *authentik.User
	// keyID is the ID of the API key used.
	keyID int64
}

type apiCallerKey struct{}

// apiCallerFrom returns the caller of a service API request.
func apiCallerFrom(ctx context.Context) (apiCaller, bool) {
	c, ok := ctx.Value(apiCallerKey{}).(apiCaller)
	return c, ok
}

// serviceAPI returns the handler of the /service-api/ paths.
func (s *Server) serviceAPI() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /service-api/v1/certificates", s.requireCertificates(s.listCallerCertificates))
	mux.Handle("POST /service-api/v1/certificates", s.requireCertificates(s.issueCallerCertificate))
	mux.Handle("POST /service-api/v1/certificates/{serial}/revoke", s.requireCertificates(s.revokeCallerCertificate))
	mux.HandleFunc("/service-api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found", nil)
	})
	return s.requireAPIKey(mux)
}

// requireAPIKey rejects requests without the API key of an active service
// account with 401, and otherwise stores the account as the caller and as the
// signed-in user, so that changes name it as their actor.
func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiKeys == nil {
			writeError(w, http.StatusNotImplemented, "API keys are not configured", nil)
			return
		}
		key, ok := bearerToken(r)
		if !ok || !apikey.WellFormed(key) {
			writeUnauthorized(w)
			return
		}
		// The lookup is by hash, so its timing reveals nothing about stored keys.
		k, err := s.apiKeys.AuthenticateAPIKey(r.Context(), apikey.Hash(key), time.Now())
		if errors.Is(err, apikey.ErrNotFound) {
			writeUnauthorized(w)
			return
		}
		if err != nil {
			s.writeAPIKeyError(w, r, err)
			return
		}
		account, err := s.users.GetUser(r.Context(), k.UserPK)
		if errors.Is(err, authentik.ErrNotFound) {
			writeUnauthorized(w)
			return
		}
		if err != nil {
			s.writeUpstreamError(w, r, err)
			return
		}
		if account.Type != authentik.UserTypeServiceAccount || !account.IsActive {
			s.logger.WarnContext(r.Context(), "API key of an inactive account or one that is no service account used",
				slog.Int64("api_key_id", k.ID),
				slog.Int("user_id", account.PK),
			)
			writeUnauthorized(w)
			return
		}
		ctx := auth.WithUser(r.Context(), auth.User{Username: account.Username})
		ctx = context.WithValue(ctx, apiCallerKey{}, apiCaller{account: account, keyID: k.ID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearerToken returns the token of the request's Bearer authorization.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimSpace(token), true
}

// writeUnauthorized answers a request without a valid API key, telling no
// more about why.
func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="service-api"`)
	writeError(w, http.StatusUnauthorized, "invalid API key", nil)
}

// callerAccount returns the service account of a request that passed requireAPIKey.
func callerAccount(r *http.Request) *authentik.User {
	c, _ := apiCallerFrom(r.Context())
	return c.account
}

// listCallerCertificates returns the certificates of the calling service account, newest first.
func (s *Server) listCallerCertificates(w http.ResponseWriter, r *http.Request) {
	list, err := s.certificates.ListCertificates(r.Context(), callerAccount(r).PK)
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, certificateList[certificate.Certificate]{Certificates: list})
}

// issueCallerCertificateInput is the body of POST /service-api/v1/certificates.
// The service account keeps its key; the server never generates one here.
type issueCallerCertificateInput struct {
	CSR string `json:"csr"`
}

// issueCallerCertificate issues a client certificate for the public key of a
// CSR to the calling service account and returns it with the CA chain.
func (s *Server) issueCallerCertificate(w http.ResponseWriter, r *http.Request) {
	var body issueCallerCertificateInput
	if !decodeJSON(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.CSR) == "" {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"csr": {"a CSR is required"}})
		return
	}
	in := issueCertificateInput{CSR: body.CSR}
	pub, fields := in.validate()
	if fields != nil {
		writeError(w, http.StatusBadRequest, "validation failed", fields)
		return
	}
	s.issueFor(w, r, callerAccount(r), pub, in)
}

// revokeCallerCertificate revokes the certificate with the {serial} path value
// of the calling service account.
func (s *Server) revokeCallerCertificate(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if _, ok := pki.ParseSerial(serial); !ok {
		writeError(w, http.StatusBadRequest, "invalid serial number", nil)
		return
	}
	s.revokeCertificateOf(w, r, callerAccount(r), serial)
}
