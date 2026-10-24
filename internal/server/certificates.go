package server

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
	"authentikManager/internal/authority"
	"authentikManager/internal/certificate"
	"authentikManager/internal/notification"
	"authentikManager/internal/pki"
)

// crlCacheTTL is how long a generated CRL is served before it is signed anew.
// Revoking a certificate discards the cached CRL at once.
const crlCacheTTL = 5 * time.Minute

// maxPasswordLen bounds PKCS#12 passwords.
const maxPasswordLen = 1024

// Download formats of a generated key.
const (
	formatPEM    = "pem"
	formatPKCS12 = "pkcs12"
)

// crlCache holds the last signed CRL of each CA.
type crlCache struct {
	mu sync.Mutex
	// signed maps CA IDs to their CRL; nil until the first CRL is signed.
	signed map[int64]signedCRL
}

// signedCRL is a DER CRL, served until expires.
type signedCRL struct {
	der     []byte
	expires time.Time
}

// requireCertificates answers 501 for h while certificates are not configured.
func (s *Server) requireCertificates(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cas == nil {
			writeError(w, http.StatusNotImplemented, "certificates are not configured", nil)
			return
		}
		h(w, r)
	})
}

// ownAccount returns the internal authentik account of the signed-in user. It
// writes the error response and returns false when there is none.
func (s *Server) ownAccount(w http.ResponseWriter, r *http.Request) (*authentik.User, bool) {
	user, err := s.findActor(r, authentik.ListUsersParams{})
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return nil, false
	}
	if user == nil || !user.IsActive {
		writeError(w, http.StatusForbidden, "only active internal users have certificates", nil)
		return nil, false
	}
	return user, true
}

// certificateAccount loads the account of kind k with the {id} path value
// whose certificates the signed-in user may list and revoke: their own
// account, and the accounts they may change (see changeableAccount). Operators
// can never issue or download certificates of other users, only of service
// accounts. It writes the error response when it returns false.
func (s *Server) certificateAccount(w http.ResponseWriter, r *http.Request, k accountKind) (*authentik.User, bool) {
	user, scope, ok := s.visibleAccount(w, r, k)
	if !ok {
		return nil, false
	}
	if k.seesOwnAccount() && isActor(r, user) {
		return user, true
	}
	if !mayChange(user, scope) {
		primary := primaryGroupName(user)
		s.recordUser(r, audit.ActionAccessDenied, user, map[string]string{"primary_group": primary})
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("only the operators managing the primary group %q may revoke certificates of this %s", primary, k.noun), nil)
		return nil, false
	}
	return user, true
}

// ownCertificate is a certificate the signed-in user requested: one of their
// own, or one they issued for a service account.
type ownCertificate struct {
	certificate.Certificate
	// Downloadable is set while the signed-in user can still download the generated key.
	Downloadable bool `json:"downloadable"`
}

// withDownloads marks the certificates whose generated key the signed-in user can still download.
func (s *Server) withDownloads(r *http.Request, list []certificate.Certificate) []ownCertificate {
	out := make([]ownCertificate, 0, len(list))
	for _, c := range list {
		out = append(out, ownCertificate{Certificate: c, Downloadable: s.keyDownloads.Has(c.Serial, actorName(r))})
	}
	return out
}

type certificateList[T any] struct {
	Certificates []T `json:"certificates"`
}

// listMyCertificates returns the certificates of the signed-in user, newest first.
func (s *Server) listMyCertificates(w http.ResponseWriter, r *http.Request) {
	user, ok := s.ownAccount(w, r)
	if !ok {
		return
	}
	list, err := s.certificates.ListCertificates(r.Context(), user.PK)
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, certificateList[ownCertificate]{Certificates: s.withDownloads(r, list)})
}

// listUserCertificates returns the certificates of the user with the {id}
// path value, without their keys.
func (s *Server) listUserCertificates(w http.ResponseWriter, r *http.Request) {
	user, ok := s.certificateAccount(w, r, userAccounts)
	if !ok {
		return
	}
	list, err := s.certificates.ListCertificates(r.Context(), user.PK)
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, certificateList[certificate.Certificate]{Certificates: list})
}

// listCertificates returns a page of the certificates of all users, newest
// first, for access administrators. The query parameters search, status, page
// and page_size filter and page it (see certificate.Query).
func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	current, size, ok := parsePaging(w, params)
	if !ok {
		return
	}
	q, err := certificate.Query{
		Search:   params.Get("search"),
		Status:   certificate.Status(params.Get("status")),
		Page:     current,
		PageSize: size,
	}.Normalize()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	list, total, err := s.certificates.ListAllCertificates(r.Context(), q, time.Now())
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page[certificate.Certificate]{
		Pagination: pagination(total, q.Page, q.PageSize, len(list)),
		Results:    list,
	})
}

// pagination describes page number current of size entries, holding n of total entries.
func pagination(total, current, size, n int) authentik.Pagination {
	p := authentik.Pagination{Count: total, Current: current, TotalPages: max(1, (total+size-1)/size)}
	if current < p.TotalPages {
		p.Next = current + 1
	}
	if current > 1 {
		p.Previous = current - 1
	}
	if n > 0 {
		p.StartIndex = (current-1)*size + 1
		p.EndIndex = p.StartIndex + n - 1
	}
	return p
}

// issueCertificateInput requests a certificate either for the public key of
// a CSR or for a generated key, downloaded as format.
type issueCertificateInput struct {
	CSR      string `json:"csr"`
	Format   string `json:"format"`
	Password string `json:"password"`
	// Prefix, when set, precedes the username in the common name of a user's
	// own certificate (see pki.Subject).
	Prefix string `json:"prefix"`
	// CA names the CA to sign the certificate. When empty, the default CA
	// signs if it issues certificates for the account, otherwise the first
	// CA that does (see issuingAuthority).
	CA string `json:"ca"`
}

// validate checks in, trimming its prefix, and returns the public key of its
// CSR, or nil when a key is to be generated. It returns the per-field errors
// otherwise.
func (in *issueCertificateInput) validate() (crypto.PublicKey, map[string][]string) {
	in.Prefix = strings.TrimSpace(in.Prefix)
	in.CA = strings.TrimSpace(in.CA)
	if in.Prefix != "" {
		if err := pki.ValidateCNPrefix(in.Prefix); err != nil {
			return nil, map[string][]string{"prefix": {err.Error()}}
		}
	}
	if in.CSR != "" {
		pub, err := pki.ParseCSR(in.CSR)
		if err != nil {
			return nil, map[string][]string{"csr": {err.Error()}}
		}
		return pub, nil
	}
	switch in.Format {
	case formatPEM:
	case formatPKCS12:
		if n := len([]rune(in.Password)); n < pki.MinPasswordLen || n > maxPasswordLen {
			return nil, map[string][]string{"password": {
				fmt.Sprintf("the password must have between %d and %d characters", pki.MinPasswordLen, maxPasswordLen),
			}}
		}
	default:
		return nil, map[string][]string{"format": {`the format must be "pem" or "pkcs12"`}}
	}
	return nil, nil
}

// issuedCertificate answers an issue request.
type issuedCertificate struct {
	Certificate certificate.Certificate `json:"certificate"`
	// CertificatePEM and ChainPEM are set for a CSR, whose key the user keeps.
	CertificatePEM string `json:"certificate_pem,omitempty"`
	ChainPEM       string `json:"chain_pem,omitempty"`
	// DownloadURL and DownloadExpiresAt are set for a generated key, which
	// can be downloaded once from DownloadURL until DownloadExpiresAt.
	DownloadURL       string     `json:"download_url,omitempty"`
	DownloadExpiresAt *time.Time `json:"download_expires_at,omitempty"`
}

// issueCertificate issues a client certificate for the signed-in user's own
// account. Nobody can issue certificates for other users, only for service
// accounts (see issueServiceAccountCertificate).
func (s *Server) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var in issueCertificateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	pub, fields := in.validate()
	if fields != nil {
		writeError(w, http.StatusBadRequest, "validation failed", fields)
		return
	}
	user, ok := s.ownAccount(w, r)
	if !ok {
		return
	}
	if in.Prefix != "" && !s.checkPrefixFree(w, r, in.Prefix+pki.CNPrefixSeparator+user.Username) {
		return
	}
	s.issueFor(w, r, user, pub, in)
}

// checkPrefixFree checks that no account of any type is named name, the
// prefixed username of a common name, which would then name that account.
// It writes the error response and returns false otherwise.
func (s *Server) checkPrefixFree(w http.ResponseWriter, r *http.Request, name string) bool {
	list, err := s.users.ListUsers(r.Context(), authentik.ListUsersParams{Username: name})
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return false
	}
	if slices.ContainsFunc(list.Results, func(u authentik.User) bool { return u.Username == name }) {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{
			"prefix": {fmt.Sprintf("the common name would name the account %q", name)},
		})
		return false
	}
	return true
}

// issueFor issues a client certificate for user, for the public key pub of a
// validated CSR, or for a generated key when pub is nil. With a CSR, the
// certificate is returned; otherwise the bundle of key and certificate is held
// for a single download by the signed-in user (see downloadCertificateKey).
func (s *Server) issueFor(w http.ResponseWriter, r *http.Request, user *authentik.User, pub crypto.PublicKey, in issueCertificateInput) {
	ca, ok := s.issuingAuthority(w, user, in.CA)
	if !ok {
		return
	}
	var key crypto.Signer
	if pub == nil {
		var err error
		if key, err = pki.GenerateKey(); err != nil {
			s.logger.ErrorContext(r.Context(), "generating certificate key", slog.Any("error", err))
			writeError(w, http.StatusInternalServerError, "issuing the certificate failed", nil)
			return
		}
		pub = key.Public()
	}

	cert, err := ca.CA.Issue(pub, pki.Subject{
		Username:       user.Username,
		UUID:           user.UUID,
		ServiceAccount: user.Type.IsServiceAccount(),
		Prefix:         in.Prefix,
	}, time.Now())
	if errors.Is(err, pki.ErrCommonNameTooLong) {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{
			"prefix": {"the prefix makes the common name longer than 64 characters"},
		})
		return
	}
	if err != nil {
		s.logger.ErrorContext(r.Context(), "issuing certificate", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "issuing the certificate failed", nil)
		return
	}
	source := certificate.KeySourceCSR
	if key != nil {
		source = certificate.KeySourceGenerated
	}
	// The record must exist before the certificate is handed out, so it can be revoked.
	record, err := s.certificates.CreateCertificate(r.Context(), certificate.Certificate{
		Serial:    pki.SerialText(cert.SerialNumber),
		UserPK:    user.PK,
		Username:  user.Username,
		Subject:   cert.Subject.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		IssuedBy:  actorName(r),
		KeySource: source,
		DER:       cert.Raw,
		CAID:      ca.ID,
	})
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	details := map[string]string{
		"serial":     record.Serial,
		"not_after":  record.NotAfter.UTC().Format(time.RFC3339),
		"key_source": string(source),
		"ca":         ca.Name,
	}
	if in.Prefix != "" {
		details["cn_prefix"] = in.Prefix
	}
	s.recordUser(r, audit.ActionCertificateIssued, user, details)
	s.notify(r, user, notification.CategoryCertificate, "Certificate issued", fmt.Sprintf(
		"A certificate was issued to your account by %s.\n- Serial number: %s\n- Subject: %s\n- Certificate authority: %s\n- Valid until: %s",
		changedBy(r, user), record.Serial, record.Subject, ca.Name, record.NotAfter.UTC().Format("2006-01-02 15:04 MST"),
	))

	out := issuedCertificate{Certificate: record}
	if key == nil {
		out.CertificatePEM = string(pki.EncodeCertificate(cert))
		out.ChainPEM = string(ca.CA.ChainPEM())
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, out)
		return
	}
	expires, err := s.holdKey(ca.CA, user, actorName(r), cert, key, in)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "holding generated key", slog.String("serial", record.Serial), slog.Any("error", err))
		status := http.StatusInternalServerError
		if errors.Is(err, pki.ErrTooManyDownloads) {
			status = http.StatusServiceUnavailable
		}
		writeError(w, status, "the certificate was issued but its key cannot be offered for download; revoke it and try again later", nil)
		return
	}
	out.DownloadURL = "/api/certificates/mine/" + record.Serial + "/download"
	out.DownloadExpiresAt = &expires
	writeJSON(w, http.StatusCreated, out)
}

// holdKey encodes the key, the certificate and the chain of ca, which signed
// it, of user as requested and holds the file for a single download by the
// user named downloader. It returns when the download expires.
func (s *Server) holdKey(
	ca *pki.CA,
	user *authentik.User,
	downloader string,
	cert *x509.Certificate,
	key crypto.Signer,
	in issueCertificateInput,
) (time.Time, error) {
	d := pki.Download{UserPK: user.PK, Username: user.Username, Downloader: downloader}
	var err error
	if in.Format == formatPKCS12 {
		d.Filename, d.ContentType = user.Username+".p12", "application/x-pkcs12"
		d.Data, err = ca.PKCS12(cert, key, in.Password)
	} else {
		d.Filename, d.ContentType = user.Username+".pem", "application/x-pem-file"
		d.Data, err = ca.PEMBundle(cert, key)
	}
	if err != nil {
		return time.Time{}, err
	}
	expires, err := s.keyDownloads.Put(pki.SerialText(cert.SerialNumber), d)
	if err != nil {
		clear(d.Data)
		return time.Time{}, err
	}
	return expires, nil
}

// downloadCertificateKey serves the generated key of the certificate with the
// {serial} path value that the signed-in user requested, for their own account
// or for a service account, once: the server forgets it then.
func (s *Server) downloadCertificateKey(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if _, ok := pki.ParseSerial(serial); !ok {
		writeError(w, http.StatusBadRequest, "invalid serial number", nil)
		return
	}
	d, ok := s.keyDownloads.Take(serial, actorName(r))
	if !ok {
		writeError(w, http.StatusGone, "the key was already downloaded or has expired", nil)
		return
	}
	defer clear(d.Data)

	h := w.Header()
	h.Set("Content-Type", d.ContentType)
	h.Set("Content-Length", strconv.Itoa(len(d.Data)))
	h.Set("Cache-Control", "no-store")
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": d.Filename})
	if disposition == "" {
		disposition = "attachment"
	}
	h.Set("Content-Disposition", disposition)
	w.WriteHeader(http.StatusOK)
	// The status line is already sent; a write error here means the client went away.
	_, _ = w.Write(d.Data)

	s.record(r, audit.ActionCertificateKeyDownloaded, d.Username, map[string]string{
		"user_id": strconv.Itoa(d.UserPK),
		"serial":  serial,
	})
}

// revokeAccountCertificate returns a handler revoking the certificate with
// the {serial} path value of the account of kind k with the {id} path value.
// Its key can no longer be downloaded.
func (s *Server) revokeAccountCertificate(k accountKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.revokeAccountCertificateOf(w, r, k)
	}
}

func (s *Server) revokeAccountCertificateOf(w http.ResponseWriter, r *http.Request, k accountKind) {
	serial := r.PathValue("serial")
	if _, ok := pki.ParseSerial(serial); !ok {
		writeError(w, http.StatusBadRequest, "invalid serial number", nil)
		return
	}
	user, ok := s.certificateAccount(w, r, k)
	if !ok {
		return
	}
	s.revokeCertificateOf(w, r, user, serial)
}

// revokeCertificateOf revokes the certificate with the valid serial of user.
// Its key can no longer be downloaded. Certificates of other users are
// reported as not found.
func (s *Server) revokeCertificateOf(w http.ResponseWriter, r *http.Request, user *authentik.User, serial string) {
	c, err := s.certificates.GetCertificate(r.Context(), serial)
	if err == nil && c.UserPK != user.PK {
		err = certificate.ErrNotFound
	}
	if err == nil {
		c, err = s.certificates.RevokeCertificate(r.Context(), serial, actorName(r))
	}
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	s.keyDownloads.Delete(serial)
	s.invalidateCRL()
	s.recordUser(r, audit.ActionCertificateRevoked, user, map[string]string{"serial": serial})
	s.notifyCertificatesRevoked(r, user, []string{serial}, "")
	writeJSON(w, http.StatusOK, c)
}

// downloadCertificate serves the certificate with the {serial} path value as
// PEM, for access administrators. It holds no private key.
func (s *Server) downloadCertificate(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if _, ok := pki.ParseSerial(serial); !ok {
		writeError(w, http.StatusBadRequest, "invalid serial number", nil)
		return
	}
	der, err := s.certificates.GetCertificateDER(r.Context(), serial)
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/x-pem-file")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": serial + ".crt"}))
	// The status line is already sent; a write error here means the client went away.
	_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// revokeAnyCertificate revokes the certificate with the {serial} path value,
// for access administrators. Unlike revokeCertificate it does not load the
// user from authentik, so it also revokes the certificates of deleted users
// and those assigned to no user.
func (s *Server) revokeAnyCertificate(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if _, ok := pki.ParseSerial(serial); !ok {
		writeError(w, http.StatusBadRequest, "invalid serial number", nil)
		return
	}
	c, err := s.certificates.RevokeCertificate(r.Context(), serial, actorName(r))
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	s.keyDownloads.Delete(serial)
	s.invalidateCRL()
	if c.Assigned() {
		s.recordUser(r, audit.ActionCertificateRevoked, &authentik.User{PK: c.UserPK, Username: c.Username},
			map[string]string{"serial": serial})
		if user := s.notificationRecipient(r, c.UserPK); user != nil {
			s.notifyCertificatesRevoked(r, user, []string{serial}, "")
		}
	} else {
		s.record(r, audit.ActionCertificateRevoked, "", map[string]string{"serial": serial, "unassigned": "true"})
	}
	writeJSON(w, http.StatusOK, c)
}

// maxImport bounds the number of certificates imported by one request.
const maxImport = 100

// importCertificatesInput holds PEM certificates the CAs signed outside this
// application, and how to import them.
type importCertificatesInput struct {
	PEM string `json:"pem"`
	importOptions
}

// importOptions tell how certificates are imported.
type importOptions struct {
	// AllowUnassigned imports certificates whose account cannot be resolved
	// without a user instead of rejecting them.
	AllowUnassigned bool `json:"allow_unassigned"`
	// Revoke records the certificates as revoked at the import, so the CRL
	// lists them, e.g. to withdraw certificates signed before this application.
	Revoke bool `json:"revoke"`
}

// importResult tells whether one certificate of an import request was imported.
type importResult struct {
	Serial  string `json:"serial"`
	Subject string `json:"subject"`
	// Certificate is the record of the imported certificate; nil when Error is set.
	Certificate *certificate.Certificate `json:"certificate,omitempty"`
	// Unassigned tells why the certificate was imported without a user; empty
	// when it was assigned to one.
	Unassigned string `json:"unassigned,omitempty"`
	// Error tells why the certificate was not imported.
	Error string `json:"error,omitempty"`
}

// importCertificates records certificates a CA signed elsewhere, e.g. with
// openssl before this application was used, so that access administrators can
// list, download and revoke them. Each certificate is assigned to the user or
// service account named by its common name, which must be active and, when
// the certificate holds a urn:uuid SAN, have that UUID. Certificates without
// such an account are rejected, or imported without a user when the request
// allows it. They are revoked right away when the request asks for it. The
// certificates of the CAs and their chains in a bundle are skipped. Every certificate is imported or
// rejected on its own; the response lists the outcome of each.
func (s *Server) importCertificates(w http.ResponseWriter, r *http.Request) {
	var in importCertificatesInput
	if !decodeJSON(w, r, &in) {
		return
	}
	certs, err := pki.ParseCertificatesPEM(in.PEM, maxImport)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"pem": {err.Error()}})
		return
	}
	now := time.Now()
	// Owners caches the accounts looked up by username; nil when there is none.
	owners := map[string]*authentik.User{}
	results := make([]importResult, 0, len(certs))
	for _, cert := range certs {
		if s.inAnyChain(cert) {
			continue
		}
		res := importResult{Serial: pki.SerialText(cert.SerialNumber), Subject: cert.Subject.String()}
		record, unassigned, err := s.importCertificate(r, cert, now, owners, in.importOptions)
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Certificate = &record
			if unassigned != nil {
				res.Unassigned = unassigned.Error()
			}
		}
		results = append(results, res)
	}
	if len(results) == 0 {
		writeError(w, http.StatusBadRequest, "validation failed",
			map[string][]string{"pem": {"only CA certificates were found"}})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Results []importResult `json:"results"`
	}{Results: results})
}

// importCertificate records cert, signed by one of the CAs, disabled ones
// included, for the account its subject names, looking accounts up through owners. When there is no such account and
// opts.AllowUnassigned is set, it records cert without a user and returns why
// as unassigned. With opts.Revoke, cert is recorded as revoked at now. Both
// errors are safe to show users.
func (s *Server) importCertificate(
	r *http.Request,
	cert *x509.Certificate,
	now time.Time,
	owners map[string]*authentik.User,
	opts importOptions,
) (record certificate.Certificate, unassigned, err error) {
	ca := s.signingAuthority(cert)
	if ca == nil {
		return certificate.Certificate{}, nil, errors.New("it is not signed by any configured CA")
	}
	if err := ca.CA.CheckIssued(cert, now); err != nil {
		return certificate.Certificate{}, nil, err
	}
	user, unassigned, err := s.certificateOwner(r, ca.CA.IssuedSubject(cert), owners)
	if err != nil {
		return certificate.Certificate{}, nil, err
	}
	if unassigned != nil && !opts.AllowUnassigned {
		return certificate.Certificate{}, nil, unassigned
	}

	c := certificate.Certificate{
		Serial:    pki.SerialText(cert.SerialNumber),
		Subject:   cert.Subject.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		IssuedBy:  actorName(r),
		KeySource: certificate.KeySourceImported,
		DER:       cert.Raw,
		CAID:      ca.ID,
	}
	if user != nil {
		c.UserPK, c.Username = user.PK, user.Username
	}
	if opts.Revoke {
		// Recorded together with the certificate, so it is never listed unrevoked.
		c.RevokedAt, c.RevokedBy = &now, actorName(r)
	}
	record, err = s.certificates.CreateCertificate(r.Context(), c)
	if errors.Is(err, certificate.ErrExists) {
		return certificate.Certificate{}, nil, errors.New("it is already recorded")
	}
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.ErrorContext(r.Context(), "importing certificate", slog.Any("error", err))
		}
		return certificate.Certificate{}, nil, errors.New("saving it failed")
	}
	details := map[string]string{
		"serial":    record.Serial,
		"not_after": record.NotAfter.UTC().Format(time.RFC3339),
		"ca":        ca.Name,
	}
	if opts.Revoke {
		details["revoked"] = "true"
	}
	actions := []audit.Action{audit.ActionCertificateImported}
	if opts.Revoke {
		actions = append(actions, audit.ActionCertificateRevoked)
	}
	for _, action := range actions {
		if user == nil {
			details["unassigned"] = unassigned.Error()
			s.record(r, action, "", details)
		} else {
			s.recordUser(r, action, user, details)
		}
	}
	return record, unassigned, nil
}

// certificateOwner returns the active account a certificate for subject
// belongs to, looking accounts up through owners. When there is none, it
// returns nil and the reason as unassigned. err is set when the lookup failed.
// Both errors are safe to show users.
func (s *Server) certificateOwner(
	r *http.Request,
	subject pki.Subject,
	owners map[string]*authentik.User,
) (user *authentik.User, unassigned, err error) {
	if subject.Username == "" {
		return nil, errors.New("it has no common name naming its user"), nil
	}
	name := subject.Username
	if subject.Prefix != "" {
		// The prefix may be part of a username holding the separator, so the
		// account named by the whole common name comes first.
		literal := subject.Prefix + pki.CNPrefixSeparator + subject.Username
		if user, err = s.cachedCertificateOwner(r, literal, owners); err != nil {
			return nil, nil, err
		}
		if user != nil {
			name = literal
		}
	}
	if name == subject.Username {
		if user, err = s.cachedCertificateOwner(r, name, owners); err != nil {
			return nil, nil, err
		}
	}
	switch {
	case user == nil:
		return nil, fmt.Errorf("there is no user or service account named %q", name), nil
	case !user.IsActive:
		return nil, fmt.Errorf("the account %q is inactive", name), nil
	case subject.UUID != "" && !strings.EqualFold(subject.UUID, user.UUID):
		// The username was given to another account since: the certificate was
		// revoked when the account was renamed or deleted, or must be.
		return nil, fmt.Errorf("it was issued to another account named %q", name), nil
	}
	return user, nil, nil
}

// cachedCertificateOwner returns the account findCertificateOwner finds for
// username, nil when there is none, looking it up once per owners. The error
// is safe to show users.
func (s *Server) cachedCertificateOwner(r *http.Request, username string, owners map[string]*authentik.User) (*authentik.User, error) {
	if user, ok := owners[username]; ok {
		return user, nil
	}
	user, err := s.findCertificateOwner(r, username)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.ErrorContext(r.Context(), "looking up certificate owner", slog.Any("error", err))
		}
		return nil, errors.New("looking up its user in authentik failed")
	}
	owners[username] = user
	return user, nil
}

// assignCertificateInput is the body of an assign request.
type assignCertificateInput struct {
	// Username names the user or service account to assign the certificate to.
	Username string `json:"username"`
}

// assignCertificate assigns the unassigned certificate with the {serial} path
// value to the active user or service account the request names, for access
// administrators, e.g. once the account named by its common name was created
// or reactivated after the import. Any active account may be chosen; relying
// parties that identify certificates by their common name still see the name
// the certificate holds.
func (s *Server) assignCertificate(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if _, ok := pki.ParseSerial(serial); !ok {
		writeError(w, http.StatusBadRequest, "invalid serial number", nil)
		return
	}
	var in assignCertificateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" {
		writeError(w, http.StatusBadRequest, "validation failed", map[string][]string{"username": {"is required"}})
		return
	}
	c, err := s.certificates.GetCertificate(r.Context(), serial)
	if err == nil && c.Assigned() {
		err = certificate.ErrAssigned
	}
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	user, err := s.findCertificateOwner(r, in.Username)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.ErrorContext(r.Context(), "looking up certificate owner", slog.Any("error", err))
		}
		writeError(w, http.StatusBadGateway, "the certificate cannot be assigned: looking up its user in authentik failed", nil)
		return
	}
	switch {
	case user == nil:
		writeError(w, http.StatusConflict,
			fmt.Sprintf("the certificate cannot be assigned: there is no user or service account named %q", in.Username), nil)
		return
	case !user.IsActive:
		writeError(w, http.StatusConflict,
			fmt.Sprintf("the certificate cannot be assigned: the account %q is inactive", in.Username), nil)
		return
	}
	c, err = s.certificates.AssignCertificate(r.Context(), serial, user.PK, user.Username)
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	s.recordUser(r, audit.ActionCertificateAssigned, user, map[string]string{"serial": serial})
	writeJSON(w, http.StatusOK, c)
}

// findCertificateOwner returns the internal user or service account with
// username, or nil when there is none.
func (s *Server) findCertificateOwner(r *http.Request, username string) (*authentik.User, error) {
	types := []authentik.UserType{authentik.UserTypeInternal, authentik.UserTypeServiceAccount}
	list, err := s.users.ListUsers(r.Context(), authentik.ListUsersParams{Username: username, Type: types})
	if err != nil {
		return nil, err
	}
	// authentik silently ignores filters it does not know, so match exactly.
	i := slices.IndexFunc(list.Results, func(u authentik.User) bool {
		return u.Username == username && slices.Contains(types, u.Type)
	})
	if i < 0 {
		return nil, nil
	}
	return &list.Results[i], nil
}

// revokeUserCertificates revokes every certificate of user and discards their
// keys waiting for download, recording reason in the audit log. It is called
// when the user is deleted, deactivated or renamed, since relying parties
// identify certificates by the username alone. It also runs while no CA is
// configured, so that certificates issued earlier stay revoked.
func (s *Server) revokeUserCertificates(ctx context.Context, r *http.Request, user *authentik.User, reason string) error {
	if s.certificates == nil {
		return nil
	}
	serials, err := s.certificates.RevokeUserCertificates(ctx, user.PK, actorName(r))
	if err != nil {
		return err
	}
	if len(serials) == 0 {
		return nil
	}
	for _, serial := range serials {
		if s.keyDownloads != nil {
			s.keyDownloads.Delete(serial)
		}
		s.recordUser(r, audit.ActionCertificateRevoked, user, map[string]string{"serial": serial, "reason": reason})
	}
	s.invalidateCRL()
	if reason != reasonUserDeleted {
		s.notifyCertificatesRevoked(r, user, serials, reason)
	}
	return nil
}

// getCRL serves the DER certificate revocation list of the CA named by the
// {ca} path value, or of the legacy CA (see authority.Registry.Legacy) when
// there is none. It is public, so that relying parties can check
// certificates without signing in.
func (s *Server) getCRL(w http.ResponseWriter, r *http.Request) {
	der, ok := s.currentCRLOrError(w, r)
	if !ok {
		return
	}
	writeCRL(w, "application/pkix-crl", der)
}

// getCRLPEM serves the same revocation list as getCRL, PEM-encoded as a download.
func (s *Server) getCRLPEM(w http.ResponseWriter, r *http.Request) {
	der, ok := s.currentCRLOrError(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="crl.pem"`)
	writeCRL(w, "application/x-pem-file", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

// publishedAuthority returns the CA whose CRL or chain r requests: the one
// named by the {ca} path value, or the legacy CA when there is none. Disabled
// CAs are included, since certificates they issued may still be valid. It
// answers r with 404 and reports false when there is no such CA.
func (s *Server) publishedAuthority(w http.ResponseWriter, r *http.Request) (*authority.Entry, bool) {
	var (
		e  *authority.Entry
		ok bool
	)
	if name := r.PathValue("ca"); name != "" {
		e, ok = s.cas.ByName(name)
	} else {
		e, ok = s.cas.Legacy()
	}
	if !ok {
		http.Error(w, "certificate authority not found", http.StatusNotFound)
		return nil, false
	}
	return e, true
}

// currentCRLOrError returns the current DER CRL of the CA r requests, or
// answers r with an error and reports false when there is no such CA or the
// CRL cannot be generated.
func (s *Server) currentCRLOrError(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	ca, ok := s.publishedAuthority(w, r)
	if !ok {
		return nil, false
	}
	der, err := s.currentCRL(r.Context(), ca)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.ErrorContext(r.Context(), "generating crl", slog.String("ca", ca.Name), slog.Any("error", err))
		}
		http.Error(w, "generating the CRL failed", http.StatusInternalServerError)
		return nil, false
	}
	return der, true
}

// writeCRL writes an encoded CRL, cacheable for as long as the server caches it.
func writeCRL(w http.ResponseWriter, contentType string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", "public, max-age="+strconv.Itoa(int(crlCacheTTL/time.Second)))
	// The status line is already sent; a write error here means the client went away.
	_, _ = w.Write(body)
}

// currentCRL returns the cached CRL of ca, signing a new one when it has expired.
func (s *Server) currentCRL(ctx context.Context, ca *authority.Entry) ([]byte, error) {
	s.crl.mu.Lock()
	defer s.crl.mu.Unlock()
	now := time.Now()
	if c, ok := s.crl.signed[ca.ID]; ok && now.Before(c.expires) {
		return c.der, nil
	}
	list, err := s.certificates.ListRevokedCertificates(ctx, ca.ID, now)
	if err != nil {
		return nil, err
	}
	revoked := make([]pki.Revoked, 0, len(list))
	for _, c := range list {
		serial, ok := new(big.Int).SetString(c.Serial, 16)
		if !ok {
			return nil, fmt.Errorf("invalid stored serial %q", c.Serial)
		}
		revoked = append(revoked, pki.Revoked{Serial: serial, RevokedAt: c.RevokedAt})
	}
	der, err := ca.CA.CRL(revoked, now)
	if err != nil {
		return nil, err
	}
	if s.crl.signed == nil {
		s.crl.signed = map[int64]signedCRL{}
	}
	s.crl.signed[ca.ID] = signedCRL{der: der, expires: now.Add(crlCacheTTL)}
	return der, nil
}

// invalidateCRL discards the cached CRLs, so the next request lists a new
// revocation or signs with changed settings.
func (s *Server) invalidateCRL() {
	s.crl.mu.Lock()
	defer s.crl.mu.Unlock()
	clear(s.crl.signed)
}

// getCAChain serves the certificate of the CA r requests and the certificates
// above it as PEM (see publishedAuthority).
func (s *Server) getCAChain(w http.ResponseWriter, r *http.Request) {
	ca, ok := s.publishedAuthority(w, r)
	if !ok {
		return
	}
	// The unnamed URL keeps the file name it always had.
	filename := "ca.pem"
	if r.PathValue("ca") != "" {
		filename = ca.Name + ".pem"
	}
	h := w.Header()
	h.Set("Content-Type", "application/x-pem-file")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	// The status line is already sent; a write error here means the client went away.
	_, _ = w.Write(ca.CA.ChainPEM())
}

// writeCertificateError translates a certificate store error into a response.
func (s *Server) writeCertificateError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, certificate.ErrNotFound):
		writeError(w, http.StatusNotFound, "certificate not found", nil)
	case errors.Is(err, certificate.ErrExists):
		writeError(w, http.StatusConflict, "certificate already exists", nil)
	case errors.Is(err, certificate.ErrRevoked):
		writeError(w, http.StatusConflict, "certificate already revoked", nil)
	case errors.Is(err, certificate.ErrAssigned):
		writeError(w, http.StatusConflict, "certificate already assigned", nil)
	case errors.Is(err, certificate.ErrNotStored):
		writeError(w, http.StatusNotFound, "the certificate was issued before certificates were stored and cannot be downloaded", nil)
	case errors.Is(err, context.Canceled):
	default:
		s.logger.ErrorContext(r.Context(), "certificate store failed",
			slog.String("path", r.URL.Path),
			slog.Any("error", err),
		)
		writeError(w, http.StatusInternalServerError, "saving or loading certificates failed", nil)
	}
}
