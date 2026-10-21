package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
	"authentikManager/internal/certificate"
	"authentikManager/internal/pki"
	"authentikManager/internal/server"
)

// fakeCertificates is an in-memory certificate store. Each test uses its own instance.
type fakeCertificates struct {
	certs []certificate.Certificate
	// query records the query passed to ListAllCertificates.
	query certificate.Query
	err   error
}

func (f *fakeCertificates) find(serial string) (int, error) {
	i := slices.IndexFunc(f.certs, func(c certificate.Certificate) bool { return c.Serial == serial })
	if i < 0 {
		return 0, certificate.ErrNotFound
	}
	return i, nil
}

func (f *fakeCertificates) CreateCertificate(_ context.Context, c certificate.Certificate) (certificate.Certificate, error) {
	if f.err != nil {
		return certificate.Certificate{}, f.err
	}
	if _, err := f.find(c.Serial); err == nil {
		return certificate.Certificate{}, certificate.ErrExists
	}
	c.IssuedAt = time.Now()
	c.Stored = c.DER != nil
	f.certs = append(f.certs, c)
	c.DER = nil
	return c, nil
}

func (f *fakeCertificates) GetCertificateDER(_ context.Context, serial string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	i, err := f.find(serial)
	if err != nil {
		return nil, err
	}
	if f.certs[i].DER == nil {
		return nil, certificate.ErrNotStored
	}
	return f.certs[i].DER, nil
}

func (f *fakeCertificates) GetCertificate(_ context.Context, serial string) (certificate.Certificate, error) {
	if f.err != nil {
		return certificate.Certificate{}, f.err
	}
	i, err := f.find(serial)
	if err != nil {
		return certificate.Certificate{}, err
	}
	return f.certs[i], nil
}

func (f *fakeCertificates) ListCertificates(_ context.Context, userPK int) ([]certificate.Certificate, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := []certificate.Certificate{}
	for _, c := range slices.Backward(f.certs) {
		if c.UserPK == userPK {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeCertificates) ListAllCertificates(_ context.Context, q certificate.Query, now time.Time) ([]certificate.Certificate, int, error) {
	f.query = q
	if f.err != nil {
		return nil, 0, f.err
	}
	matches := []certificate.Certificate{}
	for _, c := range slices.Backward(f.certs) {
		expired := !c.NotAfter.After(now)
		statusOK := q.Status == "" ||
			q.Status == certificate.StatusActive && c.RevokedAt == nil && !expired ||
			q.Status == certificate.StatusRevoked && c.RevokedAt != nil ||
			q.Status == certificate.StatusExpired && c.RevokedAt == nil && expired
		searchOK := strings.Contains(strings.ToLower(c.Username), strings.ToLower(q.Search)) ||
			strings.HasPrefix(c.Serial, strings.ToLower(q.Search))
		if statusOK && searchOK {
			matches = append(matches, c)
		}
	}
	start := min(len(matches), (q.Page-1)*q.PageSize)
	end := min(len(matches), start+q.PageSize)
	return matches[start:end], len(matches), nil
}

func (f *fakeCertificates) RevokeCertificate(_ context.Context, serial, actor string) (certificate.Certificate, error) {
	if f.err != nil {
		return certificate.Certificate{}, f.err
	}
	i, err := f.find(serial)
	if err != nil {
		return certificate.Certificate{}, err
	}
	if f.certs[i].RevokedAt != nil {
		return certificate.Certificate{}, certificate.ErrRevoked
	}
	now := time.Now()
	f.certs[i].RevokedAt, f.certs[i].RevokedBy = &now, actor
	return f.certs[i], nil
}

func (f *fakeCertificates) AssignCertificate(_ context.Context, serial string, userPK int, username string) (certificate.Certificate, error) {
	if f.err != nil {
		return certificate.Certificate{}, f.err
	}
	i, err := f.find(serial)
	if err != nil {
		return certificate.Certificate{}, err
	}
	if f.certs[i].Assigned() {
		return certificate.Certificate{}, certificate.ErrAssigned
	}
	f.certs[i].UserPK, f.certs[i].Username = userPK, username
	return f.certs[i], nil
}

func (f *fakeCertificates) RevokeUserCertificates(_ context.Context, userPK int, actor string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	serials := []string{}
	now := time.Now()
	for i, c := range f.certs {
		if c.UserPK == userPK && c.RevokedAt == nil {
			f.certs[i].RevokedAt, f.certs[i].RevokedBy = &now, actor
			serials = append(serials, c.Serial)
		}
	}
	return serials, nil
}

func (f *fakeCertificates) ListRevokedCertificates(_ context.Context, now time.Time) ([]certificate.Revoked, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []certificate.Revoked
	for _, c := range f.certs {
		if c.RevokedAt != nil && c.NotAfter.After(now) {
			out = append(out, certificate.Revoked{Serial: c.Serial, RevokedAt: *c.RevokedAt})
		}
	}
	return out, nil
}

// testClock is a settable time source for the pending downloads.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// certEnv is a server with certificates enabled and its collaborators.
type certEnv struct {
	srv       *server.Server
	ca        *pki.CA
	caCert    *x509.Certificate
	certs     *fakeCertificates
	downloads *pki.Pending
	clock     *testClock
	log       *fakeAudit
}

// newTestCA returns a self-signed CA and its certificate.
func newTestCA(t *testing.T) (*pki.CA, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadCA(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pki.Options{Validity: time.Hour},
	)
	if err != nil {
		t.Fatal(err)
	}
	return ca, cert
}

// newCertServer returns a server with certificates enabled for the signed-in
// operator "admin" in groups.
func newCertServer(t *testing.T, users server.UserService, groups ...string) *certEnv {
	t.Helper()
	ca, caCert := newTestCA(t)
	rules := newFakeRules()
	policy, err := access.NewPolicy([]string{"admins"}, rules)
	if err != nil {
		t.Fatal(err)
	}
	env := &certEnv{
		ca:     ca,
		caCert: caCert,
		certs:  &fakeCertificates{},
		clock:  &testClock{t: time.Now()},
		log:    &fakeAudit{},
	}
	env.downloads = pki.NewPending(env.clock.Now)
	env.srv = server.New(server.Deps{
		Users:        users,
		Auth:         fakeAuth{groups: groups},
		Policy:       policy,
		Rules:        rules,
		Audit:        env.log,
		Logger:       slog.New(slog.DiscardHandler),
		CA:           ca,
		Certificates: env.certs,
		KeyDownloads: env.downloads,
	})
	return env
}

// ownAccountUsers returns a UserService knowing the active internal account of
// the signed-in test operator "admin", with primary key 7.
func ownAccountUsers() *fakeUsers {
	return &fakeUsers{listed: []authentik.User{{
		PK:       7,
		UUID:     "6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
		Username: "admin",
		Email:    "admin@example.com",
		Type:     authentik.UserTypeInternal,
		IsActive: true,
	}}}
}

type issueResponse struct {
	Certificate       certificate.Certificate `json:"certificate"`
	CertificatePEM    string                  `json:"certificate_pem"`
	ChainPEM          string                  `json:"chain_pem"`
	DownloadURL       string                  `json:"download_url"`
	DownloadExpiresAt *time.Time              `json:"download_expires_at"`
}

func issue(t *testing.T, env *certEnv, body string) issueResponse {
	t.Helper()
	rec := do(t, env.srv, http.MethodPost, "/api/certificates/mine", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, body %s", rec.Code, rec.Body)
	}
	var out issueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func actions(log *fakeAudit) []audit.Action {
	out := []audit.Action{}
	for _, e := range log.recorded {
		out = append(out, e.Action)
	}
	return out
}

func TestCertificates_disabled(t *testing.T) {
	t.Parallel()
	srv := newServer(t, ownAccountUsers())
	for _, target := range []string{"/api/certificates/mine", "/api/users/5/certificates", "/pki/crl", "/pki/crl.pem", "/pki/ca.pem"} {
		if rec := do(t, srv, http.MethodGet, target, ""); rec.Code != http.StatusNotImplemented {
			t.Errorf("GET %s = %d, want 501", target, rec.Code)
		}
	}
	rec := do(t, srv, http.MethodGet, "/api/access", "")
	if !strings.Contains(rec.Body.String(), `"certificates":false`) {
		t.Errorf("access = %s, want certificates disabled", rec.Body)
	}
}

func TestCertificates_issuePKCS12(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers(), "admins")

	out := issue(t, env, `{"format":"pkcs12","password":"correct horse"}`)
	c := out.Certificate
	if c.UserPK != 7 || c.Username != "admin" || c.IssuedBy != "admin" || c.KeySource != certificate.KeySourceGenerated {
		t.Errorf("certificate = %+v, want a generated certificate of admin", c)
	}
	if out.CertificatePEM != "" || out.DownloadURL != "/api/certificates/mine/"+c.Serial+"/download" || out.DownloadExpiresAt == nil {
		t.Errorf("response = %+v, want a download URL and no certificate PEM", out)
	}
	if len(env.certs.certs) != 1 {
		t.Errorf("stored %d certificates, want 1", len(env.certs.certs))
	}

	checkPKCS12Download(t, env, out.DownloadURL, c.Serial)
	if rec := do(t, env.srv, http.MethodGet, out.DownloadURL, ""); rec.Code != http.StatusGone {
		t.Errorf("second download = %d, want 410", rec.Code)
	}
	want := []audit.Action{audit.ActionCertificateIssued, audit.ActionCertificateKeyDownloaded}
	if got := actions(env.log); !slices.Equal(got, want) {
		t.Errorf("audit = %v, want %v", got, want)
	}
}

// checkPKCS12Download downloads the PKCS#12 file of admin's certificate with serial from url.
func checkPKCS12Download(t *testing.T, env *certEnv, url, serial string) {
	t.Helper()
	rec := do(t, env.srv, http.MethodGet, url, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-pkcs12" ||
		rec.Header().Get("Cache-Control") != "no-store" ||
		rec.Header().Get("Content-Disposition") != `attachment; filename=admin.p12` {
		t.Fatalf("download = %d %v", rec.Code, rec.Header())
	}
	_, cert, chain, err := pkcs12.DecodeChain(rec.Body.Bytes(), "correct horse")
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if pki.SerialText(cert.SerialNumber) != serial || cert.Subject.CommonName != "admin" || len(chain) != 1 || !chain[0].Equal(env.caCert) {
		t.Errorf("downloaded certificate %v for %q, chain of %d", cert.SerialNumber, cert.Subject.CommonName, len(chain))
	}
	// The unverified email address is left out; the immutable user ID identifies the user.
	if len(cert.EmailAddresses) != 0 || len(cert.URIs) != 1 || cert.URIs[0].String() != "urn:uuid:6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5b" {
		t.Errorf("SANs: email %v, URIs %v, want only the user's urn:uuid", cert.EmailAddresses, cert.URIs)
	}
}

func TestCertificates_issuePEM(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers())

	out := issue(t, env, `{"format":"pem"}`)
	rec := do(t, env.srv, http.MethodGet, out.DownloadURL, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("download = %d %v", rec.Code, rec.Header())
	}
	body := rec.Body.String()
	if strings.Count(body, "BEGIN PRIVATE KEY") != 1 || strings.Count(body, "BEGIN CERTIFICATE") != 2 {
		t.Errorf("bundle = %s, want a key, the certificate and the CA", body)
	}
}

func TestCertificates_issueCSR(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "root"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}

	out := issue(t, env, `{"csr":`+string(csr)+`}`)
	if out.DownloadURL != "" || out.Certificate.KeySource != certificate.KeySourceCSR || out.ChainPEM == "" {
		t.Errorf("response = %+v, want the certificate without a download", out)
	}
	block, _ := pem.Decode([]byte(out.CertificatePEM))
	if block == nil {
		t.Fatalf("certificate_pem = %q", out.CertificatePEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "admin" || !key.PublicKey.Equal(cert.PublicKey) {
		t.Errorf("certificate for %q, want the CSR's key certified for admin, not the requested subject", cert.Subject.CommonName)
	}
}

func TestCertificates_issueInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		body      string
		wantField string
	}{
		{name: "short password", body: `{"format":"pkcs12","password":"short"}`, wantField: "password"},
		{name: "unknown format", body: `{"format":"der"}`, wantField: "format"},
		{name: "missing format", body: `{}`, wantField: "format"},
		{name: "invalid csr", body: `{"csr":"hello"}`, wantField: "csr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, ownAccountUsers())
			rec := do(t, env.srv, http.MethodPost, "/api/certificates/mine", tt.body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"`+tt.wantField+`"`) {
				t.Errorf("issue = %d %s, want 400 for field %s", rec.Code, rec.Body, tt.wantField)
			}
			if len(env.certs.certs) != 0 {
				t.Error("a certificate was stored")
			}
		})
	}
}

func TestCertificates_issueWithoutOwnAccount(t *testing.T) {
	t.Parallel()
	inactive := ownAccountUsers()
	inactive.listed[0].IsActive = false
	for name, users := range map[string]*fakeUsers{
		"no account":       {listed: []authentik.User{}},
		"inactive account": inactive,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, users, "admins")
			if rec := do(t, env.srv, http.MethodPost, "/api/certificates/mine", `{"format":"pem"}`); rec.Code != http.StatusForbidden {
				t.Errorf("issue = %d, want 403", rec.Code)
			}
		})
	}
}

func TestCertificates_noIssuingForOthers(t *testing.T) {
	t.Parallel()
	// Even access administrators can only issue certificates for themselves.
	env := newCertServer(t, ownAccountUsers(), "admins")
	for _, target := range []string{"/api/users/5/certificates", "/api/users/5/certificates/mine"} {
		rec := do(t, env.srv, http.MethodPost, target, `{"format":"pem"}`)
		if rec.Code < 400 {
			t.Errorf("POST %s = %d, want an error", target, rec.Code)
		}
	}
	if len(env.certs.certs) != 0 {
		t.Error("a certificate was issued for another user")
	}
}

func TestCertificates_downloadOtherUsersKey(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers(), "admins")
	if _, err := env.downloads.Put("ab", pki.Download{Username: "bob", Downloader: "bob", Data: []byte("secret")}); err != nil {
		t.Fatal(err)
	}
	if rec := do(t, env.srv, http.MethodGet, "/api/certificates/mine/ab/download", ""); rec.Code != http.StatusGone {
		t.Errorf("download of bob's key = %d, want 410", rec.Code)
	}
	if !env.downloads.Has("ab", "bob") {
		t.Error("bob's key was discarded")
	}
	if rec := do(t, env.srv, http.MethodGet, "/api/certificates/mine/AB/download", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("download with invalid serial = %d, want 400", rec.Code)
	}
}

func TestCertificates_downloadExpired(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers())
	out := issue(t, env, `{"format":"pem"}`)
	env.clock.Advance(pki.DownloadTTL)
	if rec := do(t, env.srv, http.MethodGet, out.DownloadURL, ""); rec.Code != http.StatusGone {
		t.Errorf("download after expiry = %d, want 410", rec.Code)
	}
}

func TestCertificates_listMine(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers())
	out := issue(t, env, `{"format":"pem"}`)
	env.certs.certs = append(env.certs.certs, certificate.Certificate{Serial: "cd", UserPK: 8, Username: "bob"})

	list := func() []map[string]any {
		t.Helper()
		rec := do(t, env.srv, http.MethodGet, "/api/certificates/mine", "")
		var body struct {
			Certificates []map[string]any `json:"certificates"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("list = %d %s", rec.Code, rec.Body)
		}
		return body.Certificates
	}
	got := list()
	if len(got) != 1 || got[0]["serial"] != out.Certificate.Serial || got[0]["downloadable"] != true {
		t.Errorf("list = %v, want the own certificate, downloadable", got)
	}
	do(t, env.srv, http.MethodGet, out.DownloadURL, "")
	if got := list(); got[0]["downloadable"] != false {
		t.Errorf("list after download = %v, want it no longer downloadable", got)
	}
}

// addCertificates stores certificate "ab" of bob (user 5) and "cd" of cat (user 6).
func TestCertificates_listAll(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		query       string
		wantSerials []string
		wantPage    authentik.Pagination
	}{
		{
			name:        "all, newest first",
			wantSerials: []string{"cd", "ab"},
			wantPage:    authentik.Pagination{Count: 2, Current: 1, TotalPages: 1, StartIndex: 1, EndIndex: 2},
		},
		{
			name:        "username",
			query:       "search=CA",
			wantSerials: []string{"cd"},
			wantPage:    authentik.Pagination{Count: 1, Current: 1, TotalPages: 1, StartIndex: 1, EndIndex: 1},
		},
		{
			name:        "serial prefix",
			query:       "search=AB",
			wantSerials: []string{"ab"},
			wantPage:    authentik.Pagination{Count: 1, Current: 1, TotalPages: 1, StartIndex: 1, EndIndex: 1},
		},
		{
			name:        "revoked",
			query:       "status=revoked",
			wantSerials: []string{"ab"},
			wantPage:    authentik.Pagination{Count: 1, Current: 1, TotalPages: 1, StartIndex: 1, EndIndex: 1},
		},
		{
			name:        "second page",
			query:       "page=2&page_size=1",
			wantSerials: []string{"ab"},
			wantPage:    authentik.Pagination{Count: 2, Current: 2, TotalPages: 2, Previous: 1, StartIndex: 2, EndIndex: 2},
		},
		{
			name:        "past the end",
			query:       "page=3&page_size=1",
			wantSerials: []string{},
			wantPage:    authentik.Pagination{Count: 2, Current: 3, TotalPages: 2, Previous: 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, &fakeUsers{}, "admins")
			addCertificates(env)
			now := time.Now()
			env.certs.certs[0].RevokedAt, env.certs.certs[0].RevokedBy = &now, "admin"

			rec := do(t, env.srv, http.MethodGet, "/api/certificates?"+tt.query, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d %s", rec.Code, rec.Body)
			}
			var out struct {
				Pagination authentik.Pagination      `json:"pagination"`
				Results    []certificate.Certificate `json:"results"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			serials := []string{}
			for _, c := range out.Results {
				serials = append(serials, c.Serial)
			}
			if !slices.Equal(serials, tt.wantSerials) {
				t.Errorf("serials = %v, want %v", serials, tt.wantSerials)
			}
			if out.Pagination != tt.wantPage {
				t.Errorf("pagination = %+v, want %+v", out.Pagination, tt.wantPage)
			}
		})
	}
}

func TestCertificates_listAllRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		groups     []string
		query      string
		wantStatus int
	}{
		{name: "not an administrator", groups: []string{"helpdesk"}, wantStatus: http.StatusForbidden},
		{name: "unknown status", groups: []string{"admins"}, query: "status=valid", wantStatus: http.StatusBadRequest},
		{name: "page size too large", groups: []string{"admins"}, query: "page_size=500", wantStatus: http.StatusBadRequest},
		{name: "search too long", groups: []string{"admins"}, query: "search=" + strings.Repeat("a", 256), wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, &fakeUsers{}, tt.groups...)
			if rec := do(t, env.srv, http.MethodGet, "/api/certificates?"+tt.query, ""); rec.Code != tt.wantStatus {
				t.Errorf("status = %d %s, want %d", rec.Code, rec.Body, tt.wantStatus)
			}
			if env.certs.query != (certificate.Query{}) {
				t.Errorf("the store was queried with %+v", env.certs.query)
			}
		})
	}
}

func TestCertificates_downloadCertificate(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers(), "admins")
	addCertificates(env)
	issued := issue(t, env, `{"format":"pem"}`).Certificate
	if !issued.Stored {
		t.Error("the issued certificate is not marked as stored")
	}

	rec := do(t, env.srv, http.MethodGet, "/api/certificates/"+issued.Serial+"/pem", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-pem-file" ||
		rec.Header().Get("Content-Disposition") != "attachment; filename="+issued.Serial+".crt" {
		t.Fatalf("download = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	block, rest := pem.Decode(rec.Body.Bytes())
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatalf("download = %q, want one CERTIFICATE block", rec.Body)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if pki.SerialText(cert.SerialNumber) != issued.Serial || cert.Subject.CommonName != "admin" {
		t.Errorf("downloaded certificate %s for %q, want %s for admin", pki.SerialText(cert.SerialNumber), cert.Subject.CommonName, issued.Serial)
	}

	tests := []struct {
		name       string
		serial     string
		wantStatus int
	}{
		{name: "issued before certificates were stored", serial: "ab", wantStatus: http.StatusNotFound},
		{name: "unknown", serial: "ef", wantStatus: http.StatusNotFound},
		{name: "invalid serial", serial: "AB", wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if rec := do(t, env.srv, http.MethodGet, "/api/certificates/"+tt.serial+"/pem", ""); rec.Code != tt.wantStatus {
				t.Errorf("download = %d %s, want %d", rec.Code, rec.Body, tt.wantStatus)
			}
		})
	}
}

func TestCertificates_revokeAny(t *testing.T) {
	t.Parallel()
	// bob was deleted: authentik no longer knows him, but his certificate can be revoked.
	env := newCertServer(t, &fakeUsers{err: authentik.ErrNotFound}, "admins")
	addCertificates(env)
	if err := put(env.downloads, "ab", "bob"); err != nil {
		t.Fatal(err)
	}

	rec := do(t, env.srv, http.MethodPost, "/api/certificates/ab/revoke", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"revoked_by":"admin"`) {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	if env.certs.certs[0].RevokedBy != "admin" || env.certs.certs[1].RevokedAt != nil {
		t.Errorf("certificates = %+v, want only ab revoked", env.certs.certs)
	}
	if env.downloads.Has("ab", "bob") {
		t.Error("the key of the revoked certificate can still be downloaded")
	}
	i := slices.IndexFunc(env.log.recorded, func(e audit.Entry) bool { return e.Action == audit.ActionCertificateRevoked })
	if i < 0 || env.log.recorded[i].Target != "bob" || env.log.recorded[i].Details["user_id"] != "5" ||
		env.log.recorded[i].Details["serial"] != "ab" {
		t.Errorf("audit = %+v, want the revocation of bob's ab", env.log.recorded)
	}
	crl := fetchCRL(t, env)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Int64() != 0xab {
		t.Errorf("CRL = %v, want serial ab", crl.RevokedCertificateEntries)
	}

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{name: "already revoked", path: "/api/certificates/ab/revoke", wantStatus: http.StatusConflict},
		{name: "unknown", path: "/api/certificates/ef/revoke", wantStatus: http.StatusNotFound},
		{name: "invalid serial", path: "/api/certificates/0ab/revoke", wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rec := do(t, env.srv, http.MethodPost, tt.path, ""); rec.Code != tt.wantStatus {
				t.Errorf("revoke = %d %s, want %d", rec.Code, rec.Body, tt.wantStatus)
			}
		})
	}
}

func TestCertificates_adminOnly(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers(), "helpdesk")
	addCertificates(env)
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "list", method: http.MethodGet, path: "/api/certificates"},
		{name: "download", method: http.MethodGet, path: "/api/certificates/ab/pem"},
		{name: "revoke", method: http.MethodPost, path: "/api/certificates/ab/revoke"},
		{name: "import", method: http.MethodPost, path: "/api/certificates/import"},
		{name: "assign", method: http.MethodPost, path: "/api/certificates/ab/assign"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rec := do(t, env.srv, tt.method, tt.path, ""); rec.Code != http.StatusForbidden {
				t.Errorf("status = %d %s, want 403", rec.Code, rec.Body)
			}
		})
	}
	if env.certs.certs[0].RevokedAt != nil {
		t.Error("the certificate was revoked")
	}
}

// importUsers returns a UserService knowing the active user ann, the inactive
// user ian and the service account svc.
func importUsers() *fakeUsers {
	return &fakeUsers{listed: []authentik.User{
		{PK: 1, UUID: "6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5b", Username: "ann", Type: authentik.UserTypeInternal, IsActive: true},
		{PK: 2, Username: "ian", Type: authentik.UserTypeInternal},
		{PK: 3, Username: "svc", Type: authentik.UserTypeServiceAccount, IsActive: true},
		{PK: 4, Username: "ext", Type: authentik.UserTypeExternal, IsActive: true},
	}}
}

// signPEM returns a certificate ca signed for s at now, as PEM.
func signPEM(t *testing.T, ca *pki.CA, s pki.Subject, now time.Time) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(key.Public(), s, now)
	if err != nil {
		t.Fatal(err)
	}
	return string(pki.EncodeCertificate(cert)), cert
}

type importResponse struct {
	Results []struct {
		Serial      string                   `json:"serial"`
		Subject     string                   `json:"subject"`
		Certificate *certificate.Certificate `json:"certificate"`
		Unassigned  string                   `json:"unassigned"`
		Error       string                   `json:"error"`
	} `json:"results"`
}

func importBody(t *testing.T, pemText string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"pem": pemText})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestCertificates_import(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, importUsers(), "admins")
	other, _ := newTestCA(t)
	now := time.Now()
	annPEM, annCert := signPEM(t, env.ca, pki.Subject{Username: "ann", UUID: "6F1C2A9E-3B4D-4E5F-8A9B-0C1D2E3F4A5B"}, now)
	svcPEM, _ := signPEM(t, env.ca, pki.Subject{Username: "svc"}, now)
	renamedPEM, _ := signPEM(t, env.ca, pki.Subject{Username: "ann", UUID: "00000000-0000-4000-8000-000000000000"}, now)
	inactivePEM, _ := signPEM(t, env.ca, pki.Subject{Username: "ian"}, now)
	unknownPEM, _ := signPEM(t, env.ca, pki.Subject{Username: "zoe"}, now)
	externalPEM, _ := signPEM(t, env.ca, pki.Subject{Username: "ext"}, now)
	expiredPEM, _ := signPEM(t, env.ca, pki.Subject{Username: "ann"}, now.Add(-2*time.Hour))
	foreignPEM, _ := signPEM(t, other, pki.Subject{Username: "ann"}, now)
	chainPEM := string(env.ca.ChainPEM())

	rec := do(t, env.srv, http.MethodPost, "/api/certificates/import", importBody(t, annPEM+chainPEM+svcPEM+
		renamedPEM+inactivePEM+unknownPEM+externalPEM+expiredPEM+foreignPEM+annPEM))
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d %s", rec.Code, rec.Body)
	}
	var out importResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	wantErrors := []string{
		"",
		"",
		`it was issued to another account named "ann"`,
		`the account "ian" is inactive`,
		`there is no user or service account named "zoe"`,
		`there is no user or service account named "ext"`,
		"it has expired",
		"it is not signed by the configured CA",
		"it is already recorded",
	}
	if len(out.Results) != len(wantErrors) {
		t.Fatalf("results = %+v, want %d of them, without the CA certificate", out.Results, len(wantErrors))
	}
	for i, want := range wantErrors {
		got := out.Results[i]
		if got.Error != want || (got.Certificate == nil) != (want != "") || got.Serial == "" || got.Subject == "" {
			t.Errorf("result %d = %+v, want error %q", i, got, want)
		}
	}

	ann := out.Results[0].Certificate
	want := certificate.Certificate{
		Serial:    pki.SerialText(annCert.SerialNumber),
		UserPK:    1,
		Username:  "ann",
		Subject:   annCert.Subject.String(),
		NotBefore: annCert.NotBefore,
		NotAfter:  annCert.NotAfter,
		IssuedAt:  ann.IssuedAt,
		IssuedBy:  "admin",
		KeySource: certificate.KeySourceImported,
		Stored:    true,
	}
	if !reflect.DeepEqual(*ann, want) {
		t.Errorf("imported = %+v, want %+v", *ann, want)
	}
	checkImportRecorded(t, env, out)

	// The imported certificate can be revoked like an issued one.
	if rec := do(t, env.srv, http.MethodPost, "/api/certificates/"+ann.Serial+"/revoke", ""); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	crl := fetchCRL(t, env)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(annCert.SerialNumber) != 0 {
		t.Errorf("CRL = %v, want the imported certificate", crl.RevokedCertificateEntries)
	}
}

// checkImportRecorded checks that the certificates of ann and svc, the first
// results of out, were stored and recorded in the audit log.
func checkImportRecorded(t *testing.T, env *certEnv, out importResponse) {
	t.Helper()
	if svc := out.Results[1].Certificate; svc.UserPK != 3 || svc.Username != "svc" {
		t.Errorf("imported = %+v, want the certificate of svc", svc)
	}
	if len(env.certs.certs) != 2 {
		t.Errorf("stored %d certificates, want 2", len(env.certs.certs))
	}
	if got := actions(env.log); !slices.Equal(got, []audit.Action{audit.ActionCertificateImported, audit.ActionCertificateImported}) {
		t.Errorf("audit = %v, want two imports", got)
	}
	if e := env.log.recorded[0]; e.Target != "ann" || e.Details["serial"] != out.Results[0].Serial || e.Details["user_id"] != "1" {
		t.Errorf("audit entry = %+v, want ann's import", e)
	}
	if e := env.log.recorded[1]; e.Target != "svc" || e.Details["type"] != string(authentik.UserTypeServiceAccount) {
		t.Errorf("audit entry = %+v, want svc's import", e)
	}
}

func TestCertificates_importUnassigned(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, importUsers(), "admins")
	now := time.Now()
	annPEM, _ := signPEM(t, env.ca, pki.Subject{Username: "ann"}, now)
	renamedPEM, _ := signPEM(t, env.ca, pki.Subject{Username: "ann", UUID: "00000000-0000-4000-8000-000000000000"}, now)
	inactivePEM, _ := signPEM(t, env.ca, pki.Subject{Username: "ian"}, now)
	unknownPEM, unknownCert := signPEM(t, env.ca, pki.Subject{Username: "zoe"}, now)
	expiredPEM, _ := signPEM(t, env.ca, pki.Subject{Username: "zoe"}, now.Add(-2*time.Hour))

	body, err := json.Marshal(map[string]any{
		"pem":              annPEM + renamedPEM + inactivePEM + unknownPEM + expiredPEM,
		"allow_unassigned": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, env.srv, http.MethodPost, "/api/certificates/import", string(body))
	var out importResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("import = %d %s", rec.Code, rec.Body)
	}
	tests := []struct {
		wantUser       string
		wantUnassigned string
		wantError      string
	}{
		{wantUser: "ann"},
		{wantUnassigned: `it was issued to another account named "ann"`},
		{wantUnassigned: `the account "ian" is inactive`},
		{wantUnassigned: `there is no user or service account named "zoe"`},
		// Unassigned imports still need a valid certificate of the CA.
		{wantError: "it has expired"},
	}
	if len(out.Results) != len(tests) {
		t.Fatalf("results = %+v, want %d of them", out.Results, len(tests))
	}
	for i, tt := range tests {
		got := out.Results[i]
		if got.Error != tt.wantError || got.Unassigned != tt.wantUnassigned {
			t.Errorf("result %d = %+v, want unassigned %q, error %q", i, got, tt.wantUnassigned, tt.wantError)
			continue
		}
		if tt.wantError == "" && (got.Certificate.Username != tt.wantUser || got.Certificate.Assigned() != (tt.wantUser != "")) {
			t.Errorf("result %d = %+v, want the certificate assigned to %q", i, got.Certificate, tt.wantUser)
		}
	}
	e := env.log.recorded[3]
	if e.Action != audit.ActionCertificateImported || e.Target != "" || e.Details["user_id"] != "" ||
		e.Details["unassigned"] != tests[3].wantUnassigned {
		t.Errorf("audit entry = %+v, want an unassigned import", e)
	}

	checkRevokeUnassigned(t, env, unknownCert)
}

// checkRevokeUnassigned checks that access administrators revoke cert, an
// unassigned certificate, like any other.
func checkRevokeUnassigned(t *testing.T, env *certEnv, cert *x509.Certificate) {
	t.Helper()
	serial := pki.SerialText(cert.SerialNumber)
	if rec := do(t, env.srv, http.MethodPost, "/api/certificates/"+serial+"/revoke", ""); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	last := env.log.recorded[len(env.log.recorded)-1]
	if last.Action != audit.ActionCertificateRevoked || last.Target != "" || last.Details["serial"] != serial ||
		last.Details["user_id"] != "" {
		t.Errorf("audit entry = %+v, want the revocation of the unassigned certificate", last)
	}
	crl := fetchCRL(t, env)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("CRL = %v, want the unassigned certificate", crl.RevokedCertificateEntries)
	}
}

func TestCertificates_importRejected(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, importUsers(), "admins")
	chainPEM := string(env.ca.ChainPEM())
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{name: "no certificate", body: importBody(t, "hello"), wantStatus: http.StatusBadRequest, wantError: "no PEM CERTIFICATE"},
		{name: "only the ca", body: importBody(t, chainPEM), wantStatus: http.StatusBadRequest, wantError: "only CA certificates"},
		{
			name:       "too many",
			body:       importBody(t, strings.Repeat(chainPEM, 101)),
			wantStatus: http.StatusBadRequest,
			wantError:  "at most 100",
		},
		{name: "unknown field", body: `{"pem":"","user":1}`, wantStatus: http.StatusBadRequest, wantError: "invalid JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, env.srv, http.MethodPost, "/api/certificates/import", tt.body)
			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantError) {
				t.Errorf("import = %d %s, want %d with %q", rec.Code, rec.Body, tt.wantStatus, tt.wantError)
			}
		})
	}
}

func TestCertificates_importFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		usersErr  error
		storeErr  error
		wantError string
	}{
		{name: "authentik", usersErr: errors.New("boom"), wantError: "looking up its user in authentik failed"},
		{name: "store", storeErr: errors.New("boom"), wantError: "saving it failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := importUsers()
			users.err = tt.usersErr
			env := newCertServer(t, users, "admins")
			env.certs.err = tt.storeErr
			annPEM, _ := signPEM(t, env.ca, pki.Subject{Username: "ann"}, time.Now())
			// A failed lookup is not taken for a missing account.
			body := `{"allow_unassigned":true,` + importBody(t, annPEM+annPEM)[1:]
			rec := do(t, env.srv, http.MethodPost, "/api/certificates/import", body)
			var out importResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("import = %d %s", rec.Code, rec.Body)
			}
			for _, r := range out.Results {
				if r.Error != tt.wantError || r.Certificate != nil {
					t.Errorf("result = %+v, want error %q", r, tt.wantError)
				}
			}
			if len(env.log.recorded) != 0 {
				t.Errorf("audit = %+v, want nothing recorded", env.log.recorded)
			}
		})
	}
}

// importUnassigned imports certificates the CA signed for each username,
// allowing unassigned ones, and returns their serials.
func importUnassigned(t *testing.T, env *certEnv, usernames ...string) []string {
	t.Helper()
	var pemText strings.Builder
	serials := make([]string, 0, len(usernames))
	for _, username := range usernames {
		p, cert := signPEM(t, env.ca, pki.Subject{Username: username}, time.Now())
		pemText.WriteString(p)
		serials = append(serials, pki.SerialText(cert.SerialNumber))
	}
	body, err := json.Marshal(map[string]any{"pem": pemText.String(), "allow_unassigned": true})
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(t, env.srv, http.MethodPost, "/api/certificates/import", string(body)); rec.Code != http.StatusOK {
		t.Fatalf("import = %d %s", rec.Code, rec.Body)
	}
	return serials
}

func assignCertificate(t *testing.T, env *certEnv, serial string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, env.srv, http.MethodPost, "/api/certificates/"+serial+"/assign", "")
}

func TestCertificates_assign(t *testing.T) {
	t.Parallel()
	users := importUsers()
	env := newCertServer(t, users, "admins")
	zoe := importUnassigned(t, env, "zoe")[0]

	// The certificate stays unassigned while its account does not exist.
	rec := assignCertificate(t, env, zoe)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `no user or service account named \"zoe\"`) {
		t.Errorf("assign before the account exists = %d %s, want 409", rec.Code, rec.Body)
	}

	users.listed = append(users.listed,
		authentik.User{PK: 8, Username: "zoe", Type: authentik.UserTypeInternal, IsActive: true})
	rec = assignCertificate(t, env, zoe)
	var got certificate.Certificate
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("assign = %d %s", rec.Code, rec.Body)
	}
	if got.Serial != zoe || got.UserPK != 8 || got.Username != "zoe" {
		t.Errorf("assigned = %+v, want the certificate of zoe", got)
	}
	last := env.log.recorded[len(env.log.recorded)-1]
	if last.Action != audit.ActionCertificateAssigned || last.Target != "zoe" || last.Details["serial"] != zoe ||
		last.Details["user_id"] != "8" {
		t.Errorf("audit entry = %+v, want the assignment to zoe", last)
	}
}

func TestCertificates_assignRejected(t *testing.T) {
	t.Parallel()
	users := importUsers()
	env := newCertServer(t, users, "admins")
	addCertificates(env)
	ian := importUnassigned(t, env, "ian")[0]
	tests := []struct {
		name       string
		serial     string
		usersErr   error
		wantStatus int
		wantError  string
	}{
		{name: "already assigned", serial: "ab", wantStatus: http.StatusConflict, wantError: "already assigned"},
		{name: "inactive account", serial: ian, wantStatus: http.StatusConflict, wantError: `the account \"ian\" is inactive`},
		{name: "unknown", serial: "ef", wantStatus: http.StatusNotFound, wantError: "not found"},
		{name: "invalid serial", serial: "0ab", wantStatus: http.StatusBadRequest, wantError: "invalid serial"},
		// A failed lookup is not taken for a missing account.
		{
			name:       "authentik down",
			serial:     ian,
			usersErr:   errors.New("boom"),
			wantStatus: http.StatusBadGateway,
			wantError:  "looking up its user in authentik failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users.err = tt.usersErr
			rec := assignCertificate(t, env, tt.serial)
			if rec.Code != tt.wantStatus || !strings.Contains(rec.Body.String(), tt.wantError) {
				t.Errorf("assign = %d %s, want %d with %q", rec.Code, rec.Body, tt.wantStatus, tt.wantError)
			}
		})
	}
	if got := actions(env.log); !slices.Equal(got, []audit.Action{audit.ActionCertificateImported}) {
		t.Errorf("audit = %v, want only the import", got)
	}
}

func addCertificates(env *certEnv) {
	env.certs.certs = append(env.certs.certs,
		certificate.Certificate{Serial: "ab", UserPK: 5, Username: "bob", NotAfter: time.Now().Add(time.Hour)},
		certificate.Certificate{Serial: "cd", UserPK: 6, Username: "cat", NotAfter: time.Now().Add(time.Hour)},
	)
}

// staffUser returns a UserService whose user bob is in staff and teachers,
// with primary as the primary group.
func staffUser(primary string) *fakeUsers {
	u := &authentik.User{
		Username: "bob",
		Type:     authentik.UserTypeInternal,
		Groups:   []authentik.UserGroup{{PK: "pk-staff", Name: "staff"}, {PK: "pk-teachers", Name: "teachers"}},
	}
	return &fakeUsers{user: withPrimary(u, primary)}
}

func TestCertificates_operatorListAndRevoke(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, staffUser("staff"), "helpdesk")
	addCertificates(env)

	rec := do(t, env.srv, http.MethodGet, "/api/users/5/certificates", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"serial":"ab"`) || strings.Contains(rec.Body.String(), `"cd"`) {
		t.Errorf("list = %d %s, want bob's certificate only", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "downloadable") {
		t.Error("operators see whether a key is downloadable")
	}

	if err := put(env.downloads, "ab", "bob"); err != nil {
		t.Fatal(err)
	}
	rec = do(t, env.srv, http.MethodPost, "/api/users/5/certificates/ab/revoke", "")
	if rec.Code != http.StatusOK || env.certs.certs[0].RevokedBy != "admin" {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	if env.downloads.Has("ab", "bob") {
		t.Error("the key of the revoked certificate can still be downloaded")
	}
	if rec := do(t, env.srv, http.MethodPost, "/api/users/5/certificates/ab/revoke", ""); rec.Code != http.StatusConflict {
		t.Errorf("second revoke = %d, want 409", rec.Code)
	}
	// Certificates of other users are not found through bob.
	if rec := do(t, env.srv, http.MethodPost, "/api/users/5/certificates/cd/revoke", ""); rec.Code != http.StatusNotFound {
		t.Errorf("revoke of cat's certificate through bob = %d, want 404", rec.Code)
	}
	if !slices.Contains(actions(env.log), audit.ActionCertificateRevoked) {
		t.Errorf("audit = %v, want a revocation", actions(env.log))
	}
}

func put(p *pki.Pending, serial, username string) error {
	_, err := p.Put(serial, pki.Download{Username: username, Downloader: username, Data: []byte("secret")})
	if err != nil {
		return fmt.Errorf("put: %w", err)
	}
	return nil
}

func TestCertificates_operatorWithoutPrimaryGroup(t *testing.T) {
	t.Parallel()
	// helpdesk manages staff, but bob's primary group teachers is managed by others.
	env := newCertServer(t, staffUser("teachers"), "helpdesk")
	addCertificates(env)
	for _, req := range []struct{ method, target string }{
		{http.MethodGet, "/api/users/5/certificates"},
		{http.MethodPost, "/api/users/5/certificates/ab/revoke"},
	} {
		if rec := do(t, env.srv, req.method, req.target, ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", req.method, req.target, rec.Code)
		}
	}
	if env.certs.certs[0].RevokedAt != nil {
		t.Error("the certificate was revoked")
	}
	if !slices.Contains(actions(env.log), audit.ActionAccessDenied) {
		t.Errorf("audit = %v, want the denied access", actions(env.log))
	}
}

func TestCertificates_outOfScope(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, staffUser("staff"), "nobody")
	addCertificates(env)
	if rec := do(t, env.srv, http.MethodGet, "/api/users/5/certificates", ""); rec.Code != http.StatusNotFound {
		t.Errorf("list = %d, want 404", rec.Code)
	}
}

func TestCertificates_revokeOwn(t *testing.T) {
	t.Parallel()
	// The operator's own account is outside their scope, but its certificates are theirs.
	users := &fakeUsers{user: &authentik.User{Username: "admin", Type: authentik.UserTypeInternal}}
	env := newCertServer(t, users, "nobody")
	env.certs.certs = append(env.certs.certs, certificate.Certificate{Serial: "ab", UserPK: 7, Username: "admin"})
	if rec := do(t, env.srv, http.MethodPost, "/api/users/7/certificates/ab/revoke", ""); rec.Code != http.StatusOK {
		t.Errorf("revoke own = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestCertificates_revokedWithUser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
		wantReason string
	}{
		{name: "deleted", method: http.MethodDelete, wantStatus: http.StatusNoContent, wantReason: "user deleted"},
		{name: "deactivated", method: http.MethodPatch, body: `{"is_active":false}`, wantStatus: http.StatusOK, wantReason: "user deactivated"},
		{name: "renamed", method: http.MethodPatch, body: `{"username":"robert"}`, wantStatus: http.StatusOK, wantReason: "user renamed"},
		{name: "other change", method: http.MethodPatch, body: `{"name":"Bob","username":"bob","is_active":true}`, wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, staffUser("staff"), "admins")
			addCertificates(env)
			if err := put(env.downloads, "ab", "bob"); err != nil {
				t.Fatal(err)
			}

			if rec := do(t, env.srv, tt.method, "/api/users/5", tt.body); rec.Code != tt.wantStatus {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body, tt.wantStatus)
			}
			bob, cat := env.certs.certs[0], env.certs.certs[1]
			if cat.RevokedAt != nil {
				t.Error("another user's certificate was revoked")
			}
			if tt.wantReason == "" {
				if bob.RevokedAt != nil || !env.downloads.Has("ab", "bob") {
					t.Error("the certificate was revoked")
				}
				return
			}
			checkBobRevoked(t, env, tt.wantReason)
		})
	}
}

// checkBobRevoked checks that bob's certificate ab is revoked by admin for
// reason: recorded, listed in the CRL, and its key no longer downloadable.
func checkBobRevoked(t *testing.T, env *certEnv, reason string) {
	t.Helper()
	if bob := env.certs.certs[0]; bob.RevokedAt == nil || bob.RevokedBy != "admin" {
		t.Fatalf("bob's certificate = %+v, want it revoked by admin", bob)
	}
	if env.downloads.Has("ab", "bob") {
		t.Error("the key of the revoked certificate can still be downloaded")
	}
	i := slices.IndexFunc(env.log.recorded, func(e audit.Entry) bool { return e.Action == audit.ActionCertificateRevoked })
	if i < 0 || env.log.recorded[i].Details["serial"] != "ab" || env.log.recorded[i].Details["reason"] != reason ||
		env.log.recorded[i].Target != "bob" {
		t.Errorf("audit = %+v, want the revocation of ab for %q", env.log.recorded, reason)
	}
	crl := fetchCRL(t, env)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Int64() != 0xab {
		t.Errorf("CRL = %v, want serial ab", crl.RevokedCertificateEntries)
	}
}

func TestCertificates_revokeFailureKeepsUser(t *testing.T) {
	t.Parallel()
	users := staffUser("staff")
	env := newCertServer(t, users, "admins")
	addCertificates(env)
	env.certs.err = errors.New("database down")

	rec := do(t, env.srv, http.MethodDelete, "/api/users/5", "")
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "not deleted") {
		t.Errorf("delete = %d %s, want 500", rec.Code, rec.Body)
	}
	if users.mutated {
		t.Error("the user was deleted although their certificates could not be revoked")
	}

	rec = do(t, env.srv, http.MethodPatch, "/api/users/5", `{"is_active":false}`)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "revoke them manually") {
		t.Errorf("deactivate = %d %s, want 500", rec.Code, rec.Body)
	}
}

func TestCertificates_revokedWithUserWithoutCA(t *testing.T) {
	t.Parallel()
	// Certificates issued while a CA was configured are revoked even after it is removed.
	certs := &fakeCertificates{}
	certs.certs = append(certs.certs, certificate.Certificate{Serial: "ab", UserPK: 5, Username: "bob"})
	rules := newFakeRules()
	policy, err := access.NewPolicy([]string{"admins"}, rules)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(server.Deps{
		Users:        staffUser("staff"),
		Auth:         fakeAuth{groups: []string{"admins"}},
		Policy:       policy,
		Rules:        rules,
		Audit:        &fakeAudit{},
		Logger:       slog.New(slog.DiscardHandler),
		Certificates: certs,
	})
	if rec := do(t, srv, http.MethodDelete, "/api/users/5", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if certs.certs[0].RevokedAt == nil {
		t.Error("the certificate was not revoked")
	}
}

// fetchCRL fetches the CRL from env and checks its signature.
func fetchCRL(t *testing.T, env *certEnv) *x509.RevocationList {
	t.Helper()
	rec := do(t, env.srv, http.MethodGet, "/pki/crl", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/pkix-crl" {
		t.Fatalf("crl = %d %v", rec.Code, rec.Header())
	}
	crl, err := x509.ParseRevocationList(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(env.caCert); err != nil {
		t.Fatal(err)
	}
	return crl
}

func TestCertificates_crl(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, staffUser("staff"), "helpdesk")
	addCertificates(env)

	if crl := fetchCRL(t, env); len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("revoked = %v, want none", crl.RevokedCertificateEntries)
	}
	if rec := do(t, env.srv, http.MethodPost, "/api/users/5/certificates/ab/revoke", ""); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	crl := fetchCRL(t, env)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Int64() != 0xab {
		t.Errorf("revoked = %v, want serial ab right after revoking", crl.RevokedCertificateEntries)
	}

	rec := do(t, env.srv, http.MethodGet, "/pki/crl.pem", "")
	if block, _ := pem.Decode(rec.Body.Bytes()); rec.Code != http.StatusOK || block == nil ||
		block.Type != "X509 CRL" || !slices.Equal(block.Bytes, crl.Raw) {
		t.Errorf("crl.pem = %d %s, want the DER CRL as PEM", rec.Code, rec.Body)
	}

	rec = do(t, env.srv, http.MethodGet, "/pki/ca.pem", "")
	block, _ := pem.Decode(rec.Body.Bytes())
	if rec.Code != http.StatusOK || block == nil || !slices.Equal(block.Bytes, env.caCert.Raw) {
		t.Errorf("ca.pem = %d %s", rec.Code, rec.Body)
	}
}

func TestCertificates_storeError(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers())
	env.certs.err = context.DeadlineExceeded
	if rec := do(t, env.srv, http.MethodPost, "/api/certificates/mine", `{"format":"pem"}`); rec.Code != http.StatusInternalServerError {
		t.Errorf("issue = %d, want 500", rec.Code)
	}
	if got := actions(env.log); len(got) != 0 {
		t.Errorf("audit = %v, want nothing recorded for the failed issue", got)
	}
}
