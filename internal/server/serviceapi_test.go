package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
	"authentikManager/internal/certificate"
	"authentikManager/internal/server"
)

// callServiceAPI sends a request to h authenticated with the Authorization header value authz.
func callServiceAPI(t *testing.T, h http.Handler, method, target, authz, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// csrBody returns the JSON body of an issue request for a new key's CSR.
func csrBody(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "root"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestServiceAPI_authentication(t *testing.T) {
	t.Parallel()
	inactive := serviceAccount("staff")
	inactive.IsActive = false
	outpost := serviceAccount("staff")
	outpost.Type = authentik.UserTypeInternalServiceAccount
	expired := time.Now().Add(-time.Minute)
	tests := []struct {
		name string
		user *authentik.User
		// authz builds the Authorization header from a valid key.
		authz     func(key string) string
		expiresAt *time.Time
		usersErr  error
		expected  int
	}{
		{name: "valid key", authz: func(k string) string { return "Bearer " + k }, expected: http.StatusOK},
		{name: "lowercase scheme", authz: func(k string) string { return "bearer " + k }, expected: http.StatusOK},
		{name: "no header", authz: func(string) string { return "" }, expected: http.StatusUnauthorized},
		{name: "basic scheme", authz: func(k string) string { return "Basic " + k }, expected: http.StatusUnauthorized},
		{name: "malformed key", authz: func(string) string { return "Bearer secret" }, expected: http.StatusUnauthorized},
		{
			name:     "unknown key",
			authz:    func(string) string { return "Bearer amk_AAAAAAAAAAAAAAAAAAAAAAAAAA" },
			expected: http.StatusUnauthorized,
		},
		{name: "expired key", authz: func(k string) string { return "Bearer " + k }, expiresAt: &expired, expected: http.StatusUnauthorized},
		{name: "inactive account", user: inactive, authz: func(k string) string { return "Bearer " + k }, expected: http.StatusUnauthorized},
		{name: "internal user", user: member("staff"), authz: func(k string) string { return "Bearer " + k }, expected: http.StatusUnauthorized},
		{name: "internal service account", user: outpost, authz: func(k string) string { return "Bearer " + k }, expected: http.StatusUnauthorized},
		{
			name:     "deleted account",
			authz:    func(k string) string { return "Bearer " + k },
			usersErr: authentik.ErrNotFound,
			expected: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user := tt.user
			if user == nil {
				user = serviceAccount("staff")
			}
			env := newCertServer(t, &fakeUsers{user: user, err: tt.usersErr})
			_, key := env.keys.add(5, tt.expiresAt)
			rec := callServiceAPI(t, env.srv, http.MethodGet, "/service-api/v1/certificates", tt.authz(key), "")
			if rec.Code != tt.expected {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.expected, rec.Body)
			}
			if tt.expected == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 without WWW-Authenticate header")
			}
			// Refused keys are recorded in the audit log.
			rejected := slices.ContainsFunc(env.log.recorded, func(e audit.Entry) bool {
				return e.Action == audit.ActionAPIKeyRejected && e.Details["reason"] != ""
			})
			if rejected != (tt.expected == http.StatusUnauthorized) {
				t.Errorf("audit = %v, want a rejected key recorded: %v", env.log.recorded, !rejected)
			}
		})
	}
}

func TestServiceAPI_rejectedKeyStart(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")})
	callServiceAPI(t, env.srv, http.MethodGet, "/service-api/v1/certificates", "Bearer amk_AAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if len(env.log.recorded) != 1 || env.log.recorded[0].Details["key_start"] != "amk_AAAAAAAA" || env.log.clientIPs[0] == "" {
		t.Errorf("audit = %v from %v, want the start of the unknown key and the client IP", env.log.recorded, env.log.clientIPs)
	}
}

func TestServiceAPI_notConfigured(t *testing.T) {
	t.Parallel()
	rules := newFakeRules()
	policy, err := access.NewPolicy([]string{"admins"}, rules)
	if err != nil {
		t.Fatal(err)
	}
	keys := &fakeAPIKeys{}
	_, key := keys.add(5, nil)
	srv := server.New(server.Deps{
		Users:   &fakeUsers{user: serviceAccount("staff")},
		Auth:    fakeAuth{},
		Policy:  policy,
		Rules:   rules,
		Audit:   &fakeAudit{},
		Logger:  slog.New(slog.DiscardHandler),
		APIKeys: keys,
	})
	rec := callServiceAPI(t, srv, http.MethodGet, "/service-api/v1/certificates", "Bearer "+key, "")
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("without a CA: status = %d, want 501; body %s", rec.Code, rec.Body)
	}

	srv = newServer(t, &fakeUsers{user: serviceAccount("staff")})
	rec = callServiceAPI(t, srv, http.MethodGet, "/service-api/v1/certificates", "Bearer "+key, "")
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("without API keys: status = %d, want 501; body %s", rec.Code, rec.Body)
	}
}

func TestServiceAPI_issue(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")})
	k, key := env.keys.add(5, nil)

	rec := callServiceAPI(t, env.srv, http.MethodPost, "/service-api/v1/certificates", "Bearer "+key, csrBody(t))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue = %d %s", rec.Code, rec.Body)
	}
	var out issueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	c := out.Certificate
	if c.UserPK != 5 || c.Username != "svc" || c.IssuedBy != "svc" || c.KeySource != certificate.KeySourceCSR {
		t.Errorf("certificate = %+v, want a CSR certificate of svc issued by svc", c)
	}
	if out.CertificatePEM == "" || out.ChainPEM == "" || out.DownloadURL != "" {
		t.Errorf("response = %+v, want the certificate and chain without a download", out)
	}
	i := slices.IndexFunc(env.log.recorded, func(e audit.Entry) bool { return e.Action == audit.ActionCertificateIssued })
	if i < 0 || env.log.recorded[i].Actor != "svc" || env.log.recorded[i].Details["api_key_id"] != "1" {
		t.Errorf("audit = %+v, want the issue by svc with key %d", env.log.recorded, k.ID)
	}
	if env.keys.keys[0].key.LastUsedAt == nil {
		t.Error("key use not recorded")
	}
}

func TestServiceAPI_issueRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "generated key", body: `{"format":"pem"}`},
		{name: "prefix", body: `{"csr":"x","prefix":"adm"}`},
		{name: "empty csr", body: `{"csr":" "}`},
		{name: "invalid csr", body: `{"csr":"not a csr"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")})
			_, key := env.keys.add(5, nil)
			rec := callServiceAPI(t, env.srv, http.MethodPost, "/service-api/v1/certificates", "Bearer "+key, tt.body)
			if rec.Code != http.StatusBadRequest || len(env.certs.certs) != 0 {
				t.Errorf("issue = %d %s, want 400 and no certificate", rec.Code, rec.Body)
			}
		})
	}
}

func TestServiceAPI_listAndRevoke(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")})
	_, key := env.keys.add(5, nil)
	authz := "Bearer " + key
	now := time.Now()
	env.certs.certs = []certificate.Certificate{
		{Serial: "a1", UserPK: 5, Username: "svc", NotAfter: now.Add(time.Hour), KeySource: certificate.KeySourceCSR},
		{Serial: "b1", UserPK: 6, Username: "other", NotAfter: now.Add(time.Hour), KeySource: certificate.KeySourceCSR},
	}

	rec := callServiceAPI(t, env.srv, http.MethodGet, "/service-api/v1/certificates", authz, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"a1"`) || strings.Contains(rec.Body.String(), `"b1"`) {
		t.Errorf("list = %d %s, want the own certificate only", rec.Code, rec.Body)
	}

	tests := []struct {
		serial   string
		expected int
	}{
		{serial: "b1", expected: http.StatusNotFound},
		{serial: "zz", expected: http.StatusBadRequest},
		{serial: "a1", expected: http.StatusOK},
		{serial: "a1", expected: http.StatusConflict},
	}
	for _, tt := range tests {
		rec := callServiceAPI(t, env.srv, http.MethodPost, "/service-api/v1/certificates/"+tt.serial+"/revoke", authz, "")
		if rec.Code != tt.expected {
			t.Errorf("revoke %s = %d %s, want %d", tt.serial, rec.Code, rec.Body, tt.expected)
		}
	}
	if own, other := env.certs.certs[0], env.certs.certs[1]; own.RevokedBy != "svc" || other.RevokedAt != nil {
		t.Errorf("certificates = %+v, want only the own one revoked by svc", env.certs.certs)
	}
}

func TestServiceAPI_unknownPath(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")})
	_, key := env.keys.add(5, nil)
	for _, target := range []string{"/service-api/v1/users", "/service-api/v1/certificates/a1/download"} {
		if rec := callServiceAPI(t, env.srv, http.MethodGet, target, "Bearer "+key, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, rec.Code)
		}
	}
	// Unauthenticated requests learn nothing about the paths.
	if rec := callServiceAPI(t, env.srv, http.MethodGet, "/service-api/v1/users", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET = %d, want 401", rec.Code)
	}
}
