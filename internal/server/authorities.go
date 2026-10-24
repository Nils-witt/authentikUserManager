package server

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"uuid"

	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
	"authentikManager/internal/authority"
	"authentikManager/internal/pki"
)

// Access administrators add certificate authorities by uploading their
// certificate and private key, which is stored encrypted. They change their
// settings, choose which groups' accounts each CA issues certificates for,
// disable CAs and choose the default one; CAs are never deleted, so the CRLs
// of the certificates they issued stay published.

// authorityView is a CA as access administrators see it, without its key.
type authorityView struct {
	authority.Authority
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// Fingerprint is the uppercase hex SHA-256 hash of the CA certificate.
	Fingerprint string `json:"fingerprint_sha256"`
}

func newAuthorityView(e *authority.Entry) authorityView {
	cert := e.CA.Certificate()
	return authorityView{
		Authority:   e.Authority,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Fingerprint: strings.ToUpper(hex.EncodeToString(pki.Fingerprint(cert))),
	}
}

// listAuthorities returns every CA, disabled ones included, ordered by name.
func (s *Server) listAuthorities(w http.ResponseWriter, _ *http.Request) {
	entries := s.cas.All()
	views := make([]authorityView, 0, len(entries))
	for _, e := range entries {
		views = append(views, newAuthorityView(e))
	}
	writeJSON(w, http.StatusOK, struct {
		Authorities []authorityView `json:"authorities"`
	}{Authorities: views})
}

// createAuthorityInput is the body of POST /api/certificate-authorities.
type createAuthorityInput struct {
	Name string `json:"name"`
	// CertificatePEM is the CA certificate, optionally followed by the certificates above it.
	CertificatePEM string `json:"certificate_pem"`
	// KeyPEM is the CA's unencrypted private key.
	KeyPEM string `json:"key_pem"`
	authority.Settings
}

// createAuthority adds a CA. It becomes the default CA when there is none.
func (s *Server) createAuthority(w http.ResponseWriter, r *http.Request) {
	var in createAuthorityInput
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if err := authority.ValidateName(in.Name); err != nil {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"name": {err.Error()}})
		return
	}
	settings, err := in.Normalize()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	keyPEM := []byte(in.KeyPEM)
	defer clear(keyPEM)
	a := authority.Authority{ID: uuid.New(), Name: in.Name, Settings: settings, CreatedBy: actorName(r)}
	ca, err := pki.LoadCA([]byte(in.CertificatePEM), keyPEM, a.Options())
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"certificate_pem": {userPKIError(err)}})
		return
	}
	if !time.Now().Before(ca.Certificate().NotAfter) {
		writeError(w, http.StatusBadRequest, "validation failed",
			map[string][]string{"certificate_pem": {"the CA certificate has expired"}})
		return
	}
	a.CertPEM = string(ca.ChainPEM())
	a.Fingerprint = pki.Fingerprint(ca.Certificate())
	if a.KeyCiphertext, err = s.cas.SealKey(a.ID, keyPEM); err != nil {
		s.logger.ErrorContext(r.Context(), "encrypting ca key", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "saving the certificate authority failed", nil)
		return
	}
	created, err := s.authorities.CreateAuthority(r.Context(), a)
	if err != nil {
		s.writeAuthorityError(w, r, err)
		return
	}
	s.record(r, audit.ActionAuthorityCreated, created.ID.String(), map[string]string{
		"name":               created.Name,
		"subject":            ca.Certificate().Subject.String(),
		"fingerprint_sha256": hex.EncodeToString(created.Fingerprint),
	})
	s.writeReloadedAuthority(w, r, http.StatusCreated, created.ID)
}

// updateAuthorityInput is the body of PUT /api/certificate-authorities/{id}.
type updateAuthorityInput struct {
	authority.Settings
	Disabled bool `json:"disabled"`
}

// updateAuthority replaces the settings of the CA with the {id} path value
// and enables or disables it. Its name, certificate and key never change.
// The default CA cannot be disabled.
func (s *Server) updateAuthority(w http.ResponseWriter, r *http.Request) {
	e, ok := s.pathAuthority(w, r)
	if !ok {
		return
	}
	var in updateAuthorityInput
	if !decodeJSON(w, r, &in) {
		return
	}
	settings, err := in.Normalize()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	updated, err := s.authorities.UpdateAuthority(r.Context(), e.ID, settings, in.Disabled)
	if err != nil {
		s.writeAuthorityError(w, r, err)
		return
	}
	s.record(r, audit.ActionAuthorityUpdated, updated.ID.String(), authorityChanges(e.Authority, updated))
	s.writeReloadedAuthority(w, r, http.StatusOK, updated.ID)
}

// setDefaultAuthority makes the enabled CA with the {id} path value the one
// that signs when a request names none.
func (s *Server) setDefaultAuthority(w http.ResponseWriter, r *http.Request) {
	e, ok := s.pathAuthority(w, r)
	if !ok {
		return
	}
	if err := s.authorities.SetDefaultAuthority(r.Context(), e.ID); err != nil {
		s.writeAuthorityError(w, r, err)
		return
	}
	s.record(r, audit.ActionAuthorityDefaultChanged, e.ID.String(), map[string]string{"name": e.Name})
	s.writeReloadedAuthority(w, r, http.StatusOK, e.ID)
}

// pathAuthority returns the CA with the {id} path value. It writes the error
// response when it returns false.
func (s *Server) pathAuthority(w http.ResponseWriter, r *http.Request) (*authority.Entry, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid certificate authority id", nil)
		return nil, false
	}
	e, ok := s.cas.ByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "certificate authority not found", nil)
		return nil, false
	}
	return e, true
}

// writeReloadedAuthority reloads the CAs after a change and answers with the
// CA with id and status.
func (s *Server) writeReloadedAuthority(w http.ResponseWriter, r *http.Request, status int, id uuid.UUID) {
	if err := s.reloadAuthorities(r.Context()); err != nil {
		s.logger.ErrorContext(r.Context(), "reloading certificate authorities", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "the change was saved, but loading the certificate authorities failed", nil)
		return
	}
	e, ok := s.cas.ByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "certificate authority not found", nil)
		return
	}
	writeJSON(w, status, newAuthorityView(e))
}

// reloadAuthorities loads the stored CAs into the registry, so that changes
// take effect, and discards the cached CRLs signed with the old settings.
func (s *Server) reloadAuthorities(ctx context.Context) error {
	// Serialized, so a slow reload cannot replace the CAs of a later one.
	s.reloading.Lock()
	defer s.reloading.Unlock()
	list, err := s.authorities.ListAuthorities(ctx)
	if err != nil {
		return err
	}
	if err := s.cas.Load(list); err != nil {
		return err
	}
	s.invalidateCRL()
	return nil
}

// authorityChanges returns the audit details of the settings that differ
// between old and changed.
func authorityChanges(old, changed authority.Authority) map[string]string {
	details := map[string]string{"name": changed.Name}
	set := func(field string, before, after any) {
		if b, a := fmt.Sprint(before), fmt.Sprint(after); b != a {
			details[field] = b + " → " + a
		}
	}
	set("description", old.Description, changed.Description)
	set("crl_url", old.CRLURL, changed.CRLURL)
	set("validity_days", old.ValidityDays, changed.ValidityDays)
	set("crl_validity_days", old.CRLValidityDays, changed.CRLValidityDays)
	set("user_cn_suffix", old.UserCNSuffix, changed.UserCNSuffix)
	set("service_account_cn_suffix", old.ServiceAccountCNSuffix, changed.ServiceAccountCNSuffix)
	set("allowed_groups", strings.Join(old.AllowedGroups, ", "), strings.Join(changed.AllowedGroups, ", "))
	set("disabled", old.Disabled, changed.Disabled)
	return details
}

// userPKIError returns err of pki.LoadCA without its package prefix, to show users.
func userPKIError(err error) string {
	return strings.TrimPrefix(err.Error(), "pki: ")
}

// writeAuthorityError translates a CA store error into a response.
func (s *Server) writeAuthorityError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authority.ErrNotFound):
		writeError(w, http.StatusNotFound, "certificate authority not found", nil)
	case errors.Is(err, authority.ErrExists):
		writeError(w, http.StatusConflict, "a certificate authority with this name or certificate already exists", nil)
	case errors.Is(err, authority.ErrDefaultDisabled):
		writeError(w, http.StatusConflict,
			"the default certificate authority cannot be disabled; make another one the default first", nil)
	case errors.Is(err, context.Canceled):
	default:
		s.logger.ErrorContext(r.Context(), "certificate authority store failed",
			slog.String("path", r.URL.Path),
			slog.Any("error", err),
		)
		writeError(w, http.StatusInternalServerError, "saving or loading certificate authorities failed", nil)
	}
}

// usableAuthority is a CA that issues certificates for an account.
type usableAuthority struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	// Default is set for the CA that signs when a request names none.
	Default bool `json:"default"`
	// CNSuffix is appended to the username in the common name of the account's certificates.
	CNSuffix string    `json:"cn_suffix"`
	NotAfter time.Time `json:"not_after"`
}

// writeUsableAuthorities answers with the CAs that issue certificates for
// user, the one signing when a request names none first.
func (s *Server) writeUsableAuthorities(w http.ResponseWriter, user *authentik.User) {
	usable := s.cas.Usable(user.GroupNames())
	out := make([]usableAuthority, 0, len(usable))
	for i, e := range usable {
		suffix := e.UserCNSuffix
		if user.Type.IsServiceAccount() {
			suffix = e.ServiceAccountCNSuffix
		}
		out = append(out, usableAuthority{
			ID:          e.ID,
			Name:        e.Name,
			Description: e.Description,
			Default:     i == 0,
			CNSuffix:    suffix,
			NotAfter:    e.CA.Certificate().NotAfter,
		})
	}
	writeJSON(w, http.StatusOK, struct {
		Authorities []usableAuthority `json:"authorities"`
	}{Authorities: out})
}

// listMyAuthorities returns the CAs that issue certificates for the signed-in user.
func (s *Server) listMyAuthorities(w http.ResponseWriter, r *http.Request) {
	user, ok := s.ownAccount(w, r)
	if !ok {
		return
	}
	s.writeUsableAuthorities(w, user)
}

// listServiceAccountAuthorities returns the CAs that issue certificates for
// the service account with the {id} path value, for the operators who may
// issue its certificates.
func (s *Server) listServiceAccountAuthorities(w http.ResponseWriter, r *http.Request) {
	account, _, ok := s.changeableAccount(w, r, serviceAccounts)
	if !ok {
		return
	}
	s.writeUsableAuthorities(w, account)
}

// issuingAuthority returns the enabled CA with id if it issues certificates
// for user. When id is the nil UUID, it returns the default CA if it does,
// otherwise the first CA by name that does. It writes the error response when
// it returns false.
func (s *Server) issuingAuthority(w http.ResponseWriter, user *authentik.User, id uuid.UUID) (*authority.Entry, bool) {
	groups := user.GroupNames()
	if id == (uuid.UUID{}) {
		usable := s.cas.Usable(groups)
		if len(usable) == 0 {
			writeError(w, http.StatusForbidden, "no certificate authority issues certificates for this account", nil)
			return nil, false
		}
		return usable[0], true
	}
	e, ok := s.cas.ByID(id)
	if !ok || e.Disabled {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{
			"ca_id": {fmt.Sprintf("there is no enabled certificate authority with id %s", id)},
		})
		return nil, false
	}
	if !e.Allows(groups) {
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("the certificate authority %s does not issue certificates for this account", id), nil)
		return nil, false
	}
	return e, true
}

// inAnyChain reports whether cert is the certificate of a CA or one above it.
func (s *Server) inAnyChain(cert *x509.Certificate) bool {
	for _, e := range s.cas.All() {
		if e.CA.InChain(cert) {
			return true
		}
	}
	return false
}

// signingAuthority returns the CA, disabled ones included, that signed cert,
// or nil when none did.
func (s *Server) signingAuthority(cert *x509.Certificate) *authority.Entry {
	for _, e := range s.cas.All() {
		if e.CA.Signed(cert) {
			return e
		}
	}
	return nil
}
