package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doFrom is do with the request coming from the client address remote.
func doFrom(t *testing.T, h http.Handler, method, target, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(""))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRateLimit_logins(t *testing.T) {
	t.Parallel()
	srv := newServer(t, &fakeUsers{})
	for i := range 30 {
		if rec := doFrom(t, srv, http.MethodGet, "/auth/login", "203.0.113.1:1000"); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("login %d refused", i+1)
		}
	}
	rec := doFrom(t, srv, http.MethodGet, "/auth/callback", "203.0.113.1:1000")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "2" {
		t.Errorf("login after the burst = %d, Retry-After %q, want 429 after 2s", rec.Code, rec.Header().Get("Retry-After"))
	}
	// Other clients and the other /auth/ endpoints are not limited.
	if rec := doFrom(t, srv, http.MethodGet, "/auth/login", "203.0.113.2:1000"); rec.Code == http.StatusTooManyRequests {
		t.Error("login of another client refused")
	}
	if rec := doFrom(t, srv, http.MethodGet, "/auth/me", "203.0.113.1:1000"); rec.Code == http.StatusTooManyRequests {
		t.Error("/auth/me refused")
	}
}

func TestRateLimit_serviceAPI(t *testing.T) {
	t.Parallel()
	srv := newServer(t, &fakeUsers{})
	for i := range 60 {
		if rec := doFrom(t, srv, http.MethodGet, "/service-api/v1/certificates", "203.0.113.1:1000"); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d refused", i+1)
		}
	}
	if rec := doFrom(t, srv, http.MethodGet, "/service-api/v1/certificates", "203.0.113.1:1000"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("request after the burst = %d, want 429", rec.Code)
	}
	if rec := doFrom(t, srv, http.MethodGet, "/service-api/v1/certificates", "203.0.113.2:1000"); rec.Code == http.StatusTooManyRequests {
		t.Error("request of another client refused")
	}
}

func TestRateLimit_api(t *testing.T) {
	t.Parallel()
	srv := newServer(t, &fakeUsers{})
	for i := range 300 {
		if rec := do(t, srv, http.MethodGet, "/api/version", ""); rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i+1, rec.Code)
		}
	}
	if rec := do(t, srv, http.MethodGet, "/api/version", ""); rec.Code != http.StatusTooManyRequests {
		t.Errorf("request after the burst = %d, want 429", rec.Code)
	}
}

func TestRateLimit_issue(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"csr":` + string(csr) + `}`
	for range 20 {
		issue(t, env, body)
	}
	rec := do(t, env.srv, http.MethodPost, "/api/certificates/mine", body)
	if rec.Code != http.StatusTooManyRequests || len(env.certs.certs) != 20 {
		t.Errorf("issue after the burst = %d with %d certificates stored, want 429 and 20", rec.Code, len(env.certs.certs))
	}
}

func TestRateLimit_pendingKeyDownloads(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers())
	var first issueResponse
	for i := range 5 {
		out := issue(t, env, `{"format":"pem"}`)
		if i == 0 {
			first = out
		}
	}
	// The key is refused before a certificate is issued for it.
	rec := do(t, env.srv, http.MethodPost, "/api/certificates/mine", `{"format":"pem"}`)
	if rec.Code != http.StatusTooManyRequests || len(env.certs.certs) != 5 {
		t.Errorf("sixth pending key = %d %s with %d certificates stored, want 429 and 5", rec.Code, rec.Body, len(env.certs.certs))
	}
	// Downloading a key makes room for another.
	if rec := do(t, env.srv, http.MethodGet, first.DownloadURL, ""); rec.Code != http.StatusOK {
		t.Fatalf("download = %d", rec.Code)
	}
	issue(t, env, `{"format":"pem"}`)
}
