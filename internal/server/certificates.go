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
	"strconv"
	"sync"
	"time"

	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
	"authentikManager/internal/certificate"
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

// crlCache holds the last signed CRL.
type crlCache struct {
	mu      sync.Mutex
	der     []byte
	expires time.Time
}

// requireCertificates answers 501 for h while no CA is configured.
func (s *Server) requireCertificates(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ca == nil {
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
}

// validate checks in and returns the public key of its CSR, or nil when a
// key is to be generated. It returns the per-field errors otherwise.
func (in issueCertificateInput) validate() (crypto.PublicKey, map[string][]string) {
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
	s.issueFor(w, r, user, pub, in)
}

// issueFor issues a client certificate for user, for the public key pub of a
// validated CSR, or for a generated key when pub is nil. With a CSR, the
// certificate is returned; otherwise the bundle of key and certificate is held
// for a single download by the signed-in user (see downloadCertificateKey).
func (s *Server) issueFor(w http.ResponseWriter, r *http.Request, user *authentik.User, pub crypto.PublicKey, in issueCertificateInput) {
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

	cert, err := s.ca.Issue(pub, pki.Subject{Username: user.Username, UUID: user.UUID}, time.Now())
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
	})
	if err != nil {
		s.writeCertificateError(w, r, err)
		return
	}
	s.recordUser(r, audit.ActionCertificateIssued, user, map[string]string{
		"serial":     record.Serial,
		"not_after":  record.NotAfter.UTC().Format(time.RFC3339),
		"key_source": string(source),
	})

	out := issuedCertificate{Certificate: record}
	if key == nil {
		out.CertificatePEM = string(pki.EncodeCertificate(cert))
		out.ChainPEM = string(s.ca.ChainPEM())
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, out)
		return
	}
	expires, err := s.holdKey(user, actorName(r), cert, key, in)
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

// holdKey encodes the key, the certificate and the CA chain of user as
// requested and holds the file for a single download by the user named
// downloader. It returns when the download expires.
func (s *Server) holdKey(
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
		d.Data, err = s.ca.PKCS12(cert, key, in.Password)
	} else {
		d.Filename, d.ContentType = user.Username+".pem", "application/x-pem-file"
		d.Data, err = s.ca.PEMBundle(cert, key)
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
	c, err := s.certificates.GetCertificate(r.Context(), serial)
	// Certificates of other users are reported as not found.
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
// user from authentik, so it also revokes the certificates of deleted users.
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
	s.recordUser(r, audit.ActionCertificateRevoked, &authentik.User{PK: c.UserPK, Username: c.Username},
		map[string]string{"serial": serial})
	writeJSON(w, http.StatusOK, c)
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
	return nil
}

// getCRL serves the CA's DER certificate revocation list. It is public, so
// that relying parties can check certificates without signing in.
func (s *Server) getCRL(w http.ResponseWriter, r *http.Request) {
	der, err := s.currentCRL(r.Context())
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.ErrorContext(r.Context(), "generating crl", slog.Any("error", err))
		}
		http.Error(w, "generating the CRL failed", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/pkix-crl")
	h.Set("Cache-Control", "public, max-age="+strconv.Itoa(int(crlCacheTTL/time.Second)))
	// The status line is already sent; a write error here means the client went away.
	_, _ = w.Write(der)
}

// currentCRL returns the cached CRL, signing a new one when it has expired.
func (s *Server) currentCRL(ctx context.Context) ([]byte, error) {
	s.crl.mu.Lock()
	defer s.crl.mu.Unlock()
	now := time.Now()
	if s.crl.der != nil && now.Before(s.crl.expires) {
		return s.crl.der, nil
	}
	list, err := s.certificates.ListRevokedCertificates(ctx, now)
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
	der, err := s.ca.CRL(revoked, now)
	if err != nil {
		return nil, err
	}
	s.crl.der, s.crl.expires = der, now.Add(crlCacheTTL)
	return der, nil
}

// invalidateCRL discards the cached CRL, so the next request lists a new revocation.
func (s *Server) invalidateCRL() {
	s.crl.mu.Lock()
	defer s.crl.mu.Unlock()
	s.crl.der = nil
}

// getCAChain serves the CA certificate and the certificates above it as PEM.
func (s *Server) getCAChain(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/x-pem-file")
	h.Set("Content-Disposition", `attachment; filename="ca.pem"`)
	// The status line is already sent; a write error here means the client went away.
	_, _ = w.Write(s.ca.ChainPEM())
}

// writeCertificateError translates a certificate store error into a response.
func (s *Server) writeCertificateError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, certificate.ErrNotFound):
		writeError(w, http.StatusNotFound, "certificate not found", nil)
	case errors.Is(err, certificate.ErrRevoked):
		writeError(w, http.StatusConflict, "certificate already revoked", nil)
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
