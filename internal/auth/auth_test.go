package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"authentikManager/internal/audit"
	"authentikManager/internal/auth"

	"github.com/go-jose/go-jose/v4"
)

const (
	clientID    = "test-client"
	providerSID = "provider-session-1"
)

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
	// query is the query of the last authorize request.
	query url.Values
	// authTime and amr, when set, are the auth_time and amr claims of ID tokens.
	authTime int64
	amr      []string
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
	p.query = q
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
	nonce, challenge, authTime, amr := p.nonce, p.challenge, p.authTime, p.amr
	p.mu.Unlock()
	if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	claims := map[string]any{
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
		"sid":                providerSID,
	}
	if authTime != 0 {
		claims["auth_time"] = authTime
	}
	if amr != nil {
		claims["amr"] = amr
	}
	idToken := p.sign(claims)
	writeJSON(p.t, w, map[string]any{
		"access_token": "access",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

// sign returns claims as a compact JWS signed with the provider's key.
func (p *fakeProvider) sign(claims map[string]any) string {
	p.t.Helper()
	return signWith(p.t, p.signer, claims)
}

func signWith(t *testing.T, signer jose.Signer, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encoding claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing token: %v", err)
	}
	return token
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
	return newAppWith(t, provider, nil)
}

// newAppWith is newApp with configure applied to the auth.Config. The app
// also serves /api/groups, listing the user's groups.
func newAppWith(t *testing.T, provider *fakeProvider, configure func(*auth.Config)) (string, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	app := httptest.NewServer(mux)
	t.Cleanup(app.Close)

	cfg := auth.Config{
		IssuerURL:    provider.srv.URL,
		ClientID:     clientID,
		ClientSecret: "secret",
		RedirectURL:  app.URL + "/auth/callback",
	}
	if configure != nil {
		configure(&cfg)
	}
	a, err := auth.New(t.Context(), cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	mux.Handle("/auth/", a.Handler())
	mux.Handle("/api/ping", a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFromContext(r.Context())
		_, _ = io.WriteString(w, "pong "+u.Username)
	})))
	mux.Handle("/api/groups", a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFromContext(r.Context())
		_, _ = io.WriteString(w, strings.Join(u.Groups, ","))
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

// logoutClaims returns valid back-channel logout token claims for the
// session the fake provider logs in, with overrides applied (nil deletes).
func logoutClaims(p *fakeProvider, overrides map[string]any) map[string]any {
	claims := map[string]any{
		"iss":    p.srv.URL,
		"aud":    clientID,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(2 * time.Minute).Unix(),
		"jti":    rand.Text(),
		"sub":    "user-1",
		"sid":    providerSID,
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	return claims
}

// postLogoutToken sends a back-channel logout request the way the provider
// does: server to server, without the browser's cookies.
func postLogoutToken(t *testing.T, appURL, token string) int {
	t.Helper()
	form := url.Values{"logout_token": {token}}.Encode()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, appURL+"/auth/backchannel-logout", strings.NewReader(form))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("back-channel logout: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // closing a test response
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	return resp.StatusCode
}

func TestBackchannelLogout(t *testing.T) {
	t.Parallel()
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	otherSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: otherKey},
		(&jose.SignerOptions{}).WithHeader("kid", "k1"),
	)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	tests := []struct {
		name       string
		token      func(p *fakeProvider) string
		wantStatus int
		wantEnded  bool
	}{
		{
			name:       "sub and sid",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, nil)) },
			wantStatus: http.StatusOK,
			wantEnded:  true,
		},
		{
			name:       "sid only",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, map[string]any{"sub": nil})) },
			wantStatus: http.StatusOK,
			wantEnded:  true,
		},
		{
			name:       "sub only ends all sessions of the user",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, map[string]any{"sid": nil})) },
			wantStatus: http.StatusOK,
			wantEnded:  true,
		},
		{
			name:       "without exp",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, map[string]any{"exp": nil})) },
			wantStatus: http.StatusOK,
			wantEnded:  true,
		},
		{
			name:       "other provider session",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, map[string]any{"sid": "other"})) },
			wantStatus: http.StatusOK,
		},
		{
			name:       "other user",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, map[string]any{"sub": "user-2"})) },
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing token",
			token:      func(*fakeProvider) string { return "" },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "foreign signature",
			token:      func(p *fakeProvider) string { return signWith(t, otherSigner, logoutClaims(p, nil)) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "wrong audience",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, map[string]any{"aud": "other-client"})) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "stale iat",
			token: func(p *fakeProvider) string {
				return p.sign(logoutClaims(p, map[string]any{"iat": time.Now().Add(-time.Hour).Unix()}))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "expired",
			token: func(p *fakeProvider) string {
				return p.sign(logoutClaims(p, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing event",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, map[string]any{"events": nil})) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "event is not an object",
			token: func(p *fakeProvider) string {
				return p.sign(logoutClaims(p, map[string]any{"events": map[string]any{
					"http://schemas.openid.net/event/backchannel-logout": true,
				}}))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "with nonce",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, map[string]any{"nonce": "n"})) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "neither sub nor sid",
			token:      func(p *fakeProvider) string { return p.sign(logoutClaims(p, map[string]any{"sub": nil, "sid": nil})) },
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			provider := newFakeProvider(t, nil)
			appURL, client := newApp(t, provider)
			if code, _ := get(t, client, appURL+"/auth/login"); code != http.StatusNotFound {
				t.Fatalf("login flow ended with %d, want 404 from /", code)
			}

			if code := postLogoutToken(t, appURL, tt.token(provider)); code != tt.wantStatus {
				t.Errorf("back-channel logout: status = %d, want %d", code, tt.wantStatus)
			}

			wantPing := http.StatusOK
			if tt.wantEnded {
				wantPing = http.StatusUnauthorized
			}
			if code, _ := get(t, client, appURL+"/api/ping"); code != wantPing {
				t.Errorf("after back-channel logout: status = %d, want %d", code, wantPing)
			}
		})
	}
}

// accountState is what a test AccountChecker reports, changeable while the app runs.
type accountState struct {
	mu     sync.Mutex
	groups []string
	err    error
	calls  int
}

func (s *accountState) set(groups []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups, s.err = groups, err
}

func (s *accountState) check(_ context.Context, u auth.User) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if u.Username != "alice" {
		return nil, auth.ErrAccountGone
	}
	return s.groups, s.err
}

func TestRequire_checksAccount(t *testing.T) {
	t.Parallel()
	state := &accountState{groups: []string{"users", "admins"}}
	appURL, client := newAppWith(t, newFakeProvider(t, []string{"users", "admins"}), func(cfg *auth.Config) {
		cfg.CheckAccount = state.check
		// Every request checks the account.
		cfg.CheckInterval = time.Nanosecond
	})
	if code, _ := get(t, client, appURL+"/auth/login"); code != http.StatusNotFound {
		t.Fatalf("login flow ended with %d, want 404 from /", code)
	}
	if code, body := get(t, client, appURL+"/api/groups"); code != http.StatusOK || body != "users,admins" {
		t.Fatalf("groups = %d %q, want the groups of the login", code, body)
	}

	// Groups withdrawn in the provider apply without a new login.
	state.set([]string{"users"}, nil)
	if code, body := get(t, client, appURL+"/api/groups"); code != http.StatusOK || body != "users" {
		t.Errorf("groups after removal = %d %q, want \"users\"", code, body)
	}

	// A failing check fails the request instead of using the previous groups.
	state.set([]string{"users"}, errors.New("authentik is down"))
	if code, _ := get(t, client, appURL+"/api/groups"); code != http.StatusServiceUnavailable {
		t.Errorf("status while the check fails = %d, want 503", code)
	}

	// A deactivated account ends the session.
	state.set(nil, auth.ErrAccountGone)
	if code, _ := get(t, client, appURL+"/api/groups"); code != http.StatusUnauthorized {
		t.Errorf("status after deactivation = %d, want 401", code)
	}
	state.set([]string{"users"}, nil)
	if code, _ := get(t, client, appURL+"/api/groups"); code != http.StatusUnauthorized {
		t.Errorf("status after reactivation = %d, want 401 until the next login", code)
	}
}

func TestRequire_checksAccountEveryInterval(t *testing.T) {
	t.Parallel()
	state := &accountState{groups: []string{"users"}}
	appURL, client := newAppWith(t, newFakeProvider(t, []string{"users"}), func(cfg *auth.Config) {
		cfg.CheckAccount = state.check
		cfg.CheckInterval = time.Hour
	})
	if code, _ := get(t, client, appURL+"/auth/login"); code != http.StatusNotFound {
		t.Fatalf("login flow ended with %d, want 404 from /", code)
	}
	for range 3 {
		if code, _ := get(t, client, appURL+"/api/ping"); code != http.StatusOK {
			t.Fatalf("ping = %d, want 200", code)
		}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.calls != 0 {
		t.Errorf("account checked %d times within the interval after login, want 0", state.calls)
	}
}

// lastQuery returns the query of the last authorize request.
func (p *fakeProvider) lastQuery() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.query
}

// loginRedirect logs in through login, a path of the app, and returns where
// the callback redirects to.
func loginRedirect(t *testing.T, client *http.Client, appURL, login string) string {
	t.Helper()
	c := *client
	// Stop at the redirect back into the app, to see where it leads.
	c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), appURL) && req.URL.Path != "/auth/callback" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, appURL+login, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.Header.Get("Location")
}

func TestLogin_reauth(t *testing.T) {
	t.Parallel()
	provider := newFakeProvider(t, []string{"admins"})
	authTime := time.Now().Add(-10 * time.Second).Truncate(time.Second)
	provider.authTime = authTime.Unix()
	provider.amr = []string{"pwd", "mfa"}
	appURL, client := newApp(t, provider)

	if got := loginRedirect(t, client, appURL, "/auth/login?reauth=1&return="+url.QueryEscape("/users?page=2")); got != "/users?page=2" {
		t.Errorf("redirect after login = %q, want the return path", got)
	}
	if q := provider.lastQuery(); q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Errorf("authorize query %v, want prompt=login and max_age=0", q)
	}
	code, body := get(t, client, appURL+"/auth/me")
	var me auth.User
	if err := json.Unmarshal([]byte(body), &me); err != nil || code != http.StatusOK {
		t.Fatalf("/auth/me = %d %q", code, body)
	}
	if !me.AuthTime.Equal(authTime) || !me.MFA() {
		t.Errorf("/auth/me auth_time %v, amr %v, want %v with mfa", me.AuthTime, me.AMR, authTime)
	}
}

func TestLogin_returnOnlyToLocalPaths(t *testing.T) {
	t.Parallel()
	provider := newFakeProvider(t, []string{"admins"})
	appURL, client := newApp(t, provider)
	for _, target := range []string{"//evil.example/x", "https://evil.example/", "/\\evil.example", "users"} {
		if got := loginRedirect(t, client, appURL, "/auth/login?return="+url.QueryEscape(target)); got != "/" {
			t.Errorf("return %q: redirect after login = %q, want /", target, got)
		}
	}
	if q := provider.lastQuery(); q.Has("prompt") || q.Has("max_age") {
		t.Errorf("authorize query %v of a normal login, want no prompt or max_age", q)
	}
}

func TestUser_MFA(t *testing.T) {
	t.Parallel()
	tests := []struct {
		amr  []string
		want bool
	}{
		{amr: nil, want: false},
		{amr: []string{"pwd"}, want: false},
		{amr: []string{"pwd", "pwd"}, want: false},
		{amr: []string{"mfa"}, want: true},
		{amr: []string{"pwd", "otp"}, want: true},
	}
	for _, tt := range tests {
		if got := (auth.User{AMR: tt.amr}).MFA(); got != tt.want {
			t.Errorf("MFA with amr %v = %v, want %v", tt.amr, got, tt.want)
		}
	}
}

// auditLog collects the entries an Authenticator records.
type auditLog struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (l *auditLog) record(_ context.Context, e audit.Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
}

func (l *auditLog) actions() []audit.Action {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []audit.Action
	for _, e := range l.entries {
		if e.Details["client_ip"] != "198.51.100.7" {
			return nil
		}
		out = append(out, e.Action)
	}
	return out
}

func TestAudit(t *testing.T) {
	t.Parallel()
	log := &auditLog{}
	appURL, client := newAppWith(t, newFakeProvider(t, []string{"admins"}), func(cfg *auth.Config) {
		cfg.RecordAudit = log.record
		cfg.ClientIP = func(*http.Request) string { return "198.51.100.7" }
	})

	// A callback without a login is refused and recorded.
	get(t, client, appURL+"/auth/callback?code=x&state=y")
	get(t, client, appURL+"/auth/login")
	send(t, client, http.MethodPost, appURL+"/auth/logout")

	want := []audit.Action{audit.ActionLoginFailed, audit.ActionLogin, audit.ActionLogout}
	if got := log.actions(); !slices.Equal(got, want) {
		t.Fatalf("audit = %v, want %v, each naming the client IP", log.entries, want)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if failed := log.entries[0]; failed.Actor != "" || failed.Details["reason"] != "login state missing or expired" {
		t.Errorf("failed login = %+v", failed)
	}
	if login := log.entries[1]; login.Actor != "alice" || login.Details["mfa"] != "false" {
		t.Errorf("login = %+v", login)
	}
}

func TestAudit_sessionEnded(t *testing.T) {
	t.Parallel()
	log := &auditLog{}
	state := &accountState{err: auth.ErrAccountGone}
	appURL, client := newAppWith(t, newFakeProvider(t, []string{"admins"}), func(cfg *auth.Config) {
		cfg.RecordAudit = log.record
		cfg.ClientIP = func(*http.Request) string { return "198.51.100.7" }
		cfg.CheckAccount = state.check
		cfg.CheckInterval = time.Nanosecond
	})
	get(t, client, appURL+"/auth/login")
	get(t, client, appURL+"/api/ping")
	want := []audit.Action{audit.ActionLogin, audit.ActionSessionEnded}
	if got := log.actions(); !slices.Equal(got, want) {
		t.Errorf("audit = %v, want %v", log.entries, want)
	}
}
