package server

import (
	"context"
	"crypto"
	"crypto/x509"
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

// certificateUser loads the user with the {id} path value whose certificates
// the signed-in user may list and revoke: their own account, and the users
// they may change (see changeableUser). Operators can never issue or download
// certificates of other users. It writes the error response when it returns false.
func (s *Server) certificateUser(w http.ResponseWriter, r *http.Request) (*authentik.User, bool) {
	user, scope, ok := s.visibleUser(w, r)
	if !ok {
		return nil, false
	}
	if isActor(r, user) {
		return user, true
	}
	if !mayChange(user, scope) {
		primary := primaryGroupName(user)
		s.recordUser(r, audit.ActionAccessDenied, user, map[string]string{"primary_group": primary})
		writeError(w, http.StatusForbidden,
			fmt.Sprintf("only the operators managing the primary group %q may revoke certificates of this user", primary), nil)
		return nil, false
	}
	return user, true
}

// ownCertificate is a certificate of the signed-in user.
type ownCertificate struct {
	certificate.Certificate
	// Downloadable is set while the generated key can still be downloaded.
	Downloadable bool `json:"downloadable"`
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
	out := make([]ownCertificate, 0, len(list))
	for _, c := range list {
		out = append(out, ownCertificate{Certificate: c, Downloadable: s.keyDownloads.Has(c.Serial, user.Username)})
	}
	writeJSON(w, http.StatusOK, certificateList[ownCertificate]{Certificates: out})
}

// listUserCertificates returns the certificates of the user with the {id}
// path value, without their keys.
func (s *Server) listUserCertificates(w http.ResponseWriter, r *http.Request) {
	user, ok := s.certificateUser(w, r)
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
// account. Nobody can issue certificates for other users. With a CSR, the
// certificate is returned; otherwise a key is generated and the bundle of key
// and certificate is held for a single download (see downloadCertificateKey).
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

	cert, err := s.ca.Issue(pub, pki.Subject{Username: user.Username, Email: user.Email}, time.Now())
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
	expires, err := s.holdKey(user, cert, key, in)
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

// holdKey encodes the key, the certificate and the CA chain as requested and
// holds the file for a single download by user. It returns when the download expires.
func (s *Server) holdKey(user *authentik.User, cert *x509.Certificate, key crypto.Signer, in issueCertificateInput) (time.Time, error) {
	d := pki.Download{UserPK: user.PK, Username: user.Username}
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

// downloadCertificateKey serves the generated key of the signed-in user's
// certificate with the {serial} path value, once: the server forgets it then.
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

// revokeCertificate revokes the certificate with the {serial} path value of
// the user with the {id} path value. Its key can no longer be downloaded.
func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if _, ok := pki.ParseSerial(serial); !ok {
		writeError(w, http.StatusBadRequest, "invalid serial number", nil)
		return
	}
	user, ok := s.certificateUser(w, r)
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
	case errors.Is(err, context.Canceled):
	default:
		s.logger.ErrorContext(r.Context(), "certificate store failed",
			slog.String("path", r.URL.Path),
			slog.Any("error", err),
		)
		writeError(w, http.StatusInternalServerError, "saving or loading certificates failed", nil)
	}
}
