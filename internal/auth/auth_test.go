package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"authentikManager/internal/auth"

	"github.com/go-jose/go-jose/v4"
)

const clientID = "test-client"

// fakeProvider is a minimal OIDC provider: discovery, JWKS, authorize and token.
// /authorize immediately redirects back with a code; the issued ID token
// carries the nonce and PKCE challenge from that authorize request.
type fakeProvider struct {
	t      *testing.T
	srv    *httptest.Server
	signer jose.Signer
	key    *rsa.PrivateKey
	groups []string

	mu        sync.Mutex
	nonce     string
	challenge string
}

func newFakeProvider(t *testing.T, groups []string) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"),
	)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	p := &fakeProvider{t: t, signer: signer, key: key, groups: groups}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	u := p.srv.URL
	writeJSON(p.t, w, map[string]any{
		"issuer":                                u,
		"authorization_endpoint":                u + "/authorize",
		"token_endpoint":                        u + "/token",
		"jwks_uri":                              u + "/jwks",
		"end_session_endpoint":                  u + "/end-session/",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *fakeProvider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(p.t, w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
	}})
}

func (p *fakeProvider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("code_challenge_method") != "S256" {
		p.t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	p.mu.Lock()
	p.nonce = q.Get("nonce")
	p.challenge = q.Get("code_challenge")
	p.mu.Unlock()
	back := q.Get("redirect_uri") + "?" + url.Values{"code": {"the-code"}, "state": {q.Get("state")}}.Encode()
	http.Redirect(w, r, back, http.StatusFound)
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.t.Errorf("parsing token form: %v", err)
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	p.mu.Lock()
	nonce, challenge := p.nonce, p.challenge
	p.mu.Unlock()
	if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	claims, err := json.Marshal(map[string]any{
		"iss":                p.srv.URL,
		"aud":                clientID,
		"sub":                "user-1",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Unix(),
		"nonce":              nonce,
		"preferred_username": "alice",
		"name":               "Alice",
		"email":              "alice@example.com",
		"groups":             p.groups,
	})
	if err != nil {
		p.t.Fatalf("encoding claims: %v", err)
	}
	jws, err := p.signer.Sign(claims)
	if err != nil {
		p.t.Fatalf("signing id token: %v", err)
	}
	idToken, err := jws.CompactSerialize()
	if err != nil {
		p.t.Fatalf("serializing id token: %v", err)
	}
	writeJSON(p.t, w, map[string]any{
		"access_token": "access",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("writing json: %v", err)
	}
}

// newApp starts the app (auth endpoints + a protected /api/ping) and returns
// its URL plus a browser-like client that keeps cookies and follows redirects.
func newApp(t *testing.T, provider *fakeProvider) (string, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	app := httptest.NewServer(mux)
	t.Cleanup(app.Close)

	a, err := auth.New(t.Context(), auth.Config{
		IssuerURL:    provider.srv.URL,
		ClientID:     clientID,
		ClientSecret: "secret",
		RedirectURL:  app.URL + "/auth/callback",
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	mux.Handle("/auth/", a.Handler())
	mux.Handle("/api/ping", a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFromContext(r.Context())
		_, _ = io.WriteString(w, "pong "+u.Username)
	})))

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return app.URL, &http.Client{Jar: jar}
}

// send performs a request bound to the test's context and returns the
// status code and body.
func send(t *testing.T, c *http.Client, method, u string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, u, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close() //nolint:errcheck // closing a fully read test response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return resp.StatusCode, body
}

func get(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	code, body := send(t, c, http.MethodGet, u)
	return code, string(body)
}

func TestLoginFlow(t *testing.T) {
	t.Parallel()
	appURL, client := newApp(t, newFakeProvider(t, []string{"users", "admins"}))

	if code, _ := get(t, client, appURL+"/api/ping"); code != http.StatusUnauthorized {
		t.Fatalf("before login: status = %d, want 401", code)
	}

	// Login ends with a redirect to "/", which this test app does not serve.
	if code, _ := get(t, client, appURL+"/auth/login"); code != http.StatusNotFound {
		t.Fatalf("login flow ended with %d, want 404 from /", code)
	}

	if code, body := get(t, client, appURL+"/api/ping"); code != http.StatusOK || body != "pong alice" {
		t.Fatalf("after login: %d %q, want 200 \"pong alice\"", code, body)
	}

	code, body := get(t, client, appURL+"/auth/me")
	var me auth.User
	if err := json.Unmarshal([]byte(body), &me); err != nil || code != http.StatusOK {
		t.Fatalf("/auth/me = %d %q", code, body)
	}
	if me.Username != "alice" || me.Email != "alice@example.com" {
		t.Errorf("/auth/me = %+v", me)
	}

	_, logoutBody := send(t, client, http.MethodPost, appURL+"/auth/logout")
	var out struct {
		LogoutURL string `json:"logout_url"`
	}
	if err := json.Unmarshal(logoutBody, &out); err != nil {
		t.Fatalf("decoding logout response: %v", err)
	}
	if !strings.Contains(out.LogoutURL, "/end-session/?id_token_hint=") {
		t.Errorf("logout_url = %q, want end-session url with id_token_hint", out.LogoutURL)
	}

	if code, _ := get(t, client, appURL+"/api/ping"); code != http.StatusUnauthorized {
		t.Errorf("after logout: status = %d, want 401", code)
	}
}

// Any authentik user may log in; the access rules decide what they may manage.
func TestLoginFlow_withoutGroups(t *testing.T) {
	t.Parallel()
	appURL, client := newApp(t, newFakeProvider(t, nil))

	if code, _ := get(t, client, appURL+"/auth/login"); code != http.StatusNotFound {
		t.Fatalf("login flow ended with %d, want 404 from /", code)
	}
	if code, body := get(t, client, appURL+"/api/ping"); code != http.StatusOK || body != "pong alice" {
		t.Errorf("after login: %d %q, want 200 \"pong alice\"", code, body)
	}
}

func TestCallback_rejectsForeignState(t *testing.T) {
	t.Parallel()
	appURL, client := newApp(t, newFakeProvider(t, []string{"admins"}))

	// No login cookie: e.g. an attacker sending the victim their own callback URL.
	if code, _ := get(t, client, appURL+"/auth/callback?code=x&state=y"); code != http.StatusBadRequest {
		t.Errorf("callback without login cookie: status = %d, want 400", code)
	}

	// Start a login but stop at the provider, then present a different state.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	send(t, &noRedirect, http.MethodGet, appURL+"/auth/login")
	if code, _ := get(t, &noRedirect, appURL+"/auth/callback?code=x&state=forged"); code != http.StatusBadRequest {
		t.Errorf("callback with forged state: status = %d, want 400", code)
	}
}
