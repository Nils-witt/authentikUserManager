// Package auth protects the application with an OpenID Connect login against
// authentik (authorization code flow with PKCE) and server-side sessions.
// Logout works both ways: RP-initiated (the app redirects to the provider's
// end-session endpoint) and OP-initiated via OIDC Back-Channel Logout.
//
// Tokens never reach the browser: it only holds an opaque, HttpOnly session cookie.
package auth

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"authentikManager/internal/audit"
)

const (
	loginCookieName = "am_login"
	loginCookiePath = "/auth/callback"
	loginTTL        = 10 * time.Minute
	httpTimeout     = 15 * time.Second
	// reauthMaxAge is the max_age of re-authentications: the provider asks for
	// the credentials unless the user signed in this recently. It is not 0,
	// because authentik ignores max_age=0, and prompt=login alone forces a new
	// login only once per authentik session.
	reauthMaxAge = "60"

	// backchannelLogoutEvent is the "events" member that marks a logout token.
	backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	// logoutTokenMaxAge bounds how old (by iat) an accepted logout token may be.
	logoutTokenMaxAge = 5 * time.Minute
	// clockSkew tolerates provider clocks running slightly ahead.
	clockSkew = time.Minute
	// maxLogoutRequestBytes bounds the back-channel logout request body.
	maxLogoutRequestBytes = 64 << 10
)

// Config configures the OIDC client.
type Config struct {
	// IssuerURL is the provider's issuer, for authentik
	// https://<host>/application/o/<application-slug>/.
	IssuerURL    string
	ClientID     string
	ClientSecret string
	// RedirectURL is this app's callback URL, ending in /auth/callback.
	RedirectURL string
	// SessionTTL is the maximum lifetime of a session, by default DefaultSessionTTL.
	SessionTTL time.Duration
	// IdleTimeout ends sessions that were not used for this long, by default
	// DefaultIdleTimeout. It is at most SessionTTL.
	IdleTimeout time.Duration
	// CheckAccount, when set, reads the current state of a signed-in user's
	// account, so that changes to it apply during the session instead of at
	// the next login. Require calls it at most every CheckInterval per session.
	CheckAccount AccountChecker
	// CheckInterval defaults to DefaultCheckInterval.
	CheckInterval time.Duration
	// RecordAudit, when set, records logins, failed logins, logouts and
	// sessions ended by CheckAccount in the audit log.
	RecordAudit func(ctx context.Context, e audit.Entry)
	// ClientIP, when set, returns the client IP address of a request, which
	// audit entries name.
	ClientIP func(*http.Request) string
}

// AccountChecker returns the current groups of the account of u, or
// ErrAccountGone when it was deleted or deactivated.
type AccountChecker func(ctx context.Context, u User) (groups []string, err error)

// ErrAccountGone is returned by an AccountChecker when the account of a
// signed-in user was deleted or deactivated; its sessions end.
var ErrAccountGone = errors.New("auth: account deleted or deactivated")

// DefaultCheckInterval is the default of Config.CheckInterval.
const DefaultCheckInterval = 5 * time.Minute

// Defaults of Config.SessionTTL and Config.IdleTimeout.
const (
	DefaultSessionTTL  = 8 * time.Hour
	DefaultIdleTimeout = 30 * time.Minute
)

// BackgroundHeader marks a request the browser sends without the user doing
// anything, such as polling. It does not count as use of the session, so it
// does not keep an idle session alive.
const BackgroundHeader = "X-Background-Request"

// PruneInterval is how often Run deletes the sessions that have ended.
const PruneInterval = time.Minute

// Authenticator serves the /auth/ endpoints and guards other handlers.
type Authenticator struct {
	oauth          oauth2.Config
	verifier       *oidc.IDTokenVerifier
	logoutVerifier *oidc.IDTokenVerifier
	endSessionURL  string
	sessions       *sessionStore
	secure         bool
	sessionCookie  string
	httpClient     *http.Client
	logger         *slog.Logger
	mux            *http.ServeMux
	// checkAccount, when set, refreshes the groups of sessions every checkInterval.
	checkAccount  AccountChecker
	checkInterval time.Duration
	// checks merges the concurrent checks of one session.
	checks singleflight.Group
	// recordAudit and clientIP are Config.RecordAudit and Config.ClientIP.
	recordAudit func(ctx context.Context, e audit.Entry)
	clientIP    func(*http.Request) string
}

// New discovers the provider's configuration. ctx must outlive the
// Authenticator: go-oidc uses it to refresh the provider's signing keys.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (*Authenticator, error) {
	redirect, err := url.Parse(cfg.RedirectURL)
	if err != nil || !redirect.IsAbs() {
		return nil, fmt.Errorf("auth: redirect url %q must be absolute", cfg.RedirectURL)
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = DefaultSessionTTL
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	cfg.IdleTimeout = min(cfg.IdleTimeout, cfg.SessionTTL)
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = DefaultCheckInterval
	}

	httpClient := &http.Client{Timeout: httpTimeout}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: discovering oidc provider: %w", err)
	}
	var meta struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("auth: reading provider metadata: %w", err)
	}

	secure := redirect.Scheme == "https"
	sessionCookie := "am_session"
	if secure {
		// The __Host- prefix makes browsers enforce Secure, Path=/ and no Domain.
		sessionCookie = "__Host-am_session"
	}

	a := &Authenticator{
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		// Logout tokens carry iat but, in older providers, no exp: expiry is
		// checked in backchannelLogout instead.
		logoutVerifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID, SkipExpiryCheck: true}),
		endSessionURL:  meta.EndSessionEndpoint,
		sessions:       newSessionStore(cfg.SessionTTL, cfg.IdleTimeout),
		secure:         secure,
		sessionCookie:  sessionCookie,
		httpClient:     httpClient,
		logger:         logger,
		mux:            http.NewServeMux(),
		checkAccount:   cfg.CheckAccount,
		checkInterval:  cfg.CheckInterval,
		recordAudit:    cfg.RecordAudit,
		clientIP:       cfg.ClientIP,
	}
	a.mux.HandleFunc("GET /auth/login", a.login)
	a.mux.HandleFunc("GET /auth/callback", a.callback)
	a.mux.HandleFunc("POST /auth/logout", a.logout)
	a.mux.HandleFunc("POST /auth/backchannel-logout", a.backchannelLogout)
	a.mux.HandleFunc("GET /auth/me", a.me)
	return a, nil
}

// Handler serves the /auth/ endpoints.
func (a *Authenticator) Handler() http.Handler { return a.mux }

// Run deletes the sessions that have ended every interval until ctx is done,
// so their data does not stay in memory until the next login.
func (a *Authenticator) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sessions.prune()
		}
	}
}

// Require rejects requests without a valid session with 401 and otherwise
// stores the User in the request context (see UserFromContext). Requests
// with BackgroundHeader do not restart the session's idle timeout.
//
// With Config.CheckAccount, the user's groups are read again when they are
// older than the check interval, and the session ends when the account was
// deleted or deactivated. If the check fails, the request fails with 503
// rather than going on with permissions that may have been withdrawn.
func (a *Authenticator) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, sess, ok := a.currentSession(r, r.Header.Get(BackgroundHeader) == "")
		if ok && a.checkAccount != nil && !a.sessions.now().Before(sess.checkedAt.Add(a.checkInterval)) {
			var err error
			sess, ok, err = a.check(r, id)
			if err != nil {
				a.logger.ErrorContext(r.Context(), "checking account", slog.String("username", sess.user.Username), slog.Any("error", err))
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "your account could not be checked"})
				return
			}
		}
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), sess.user)))
	})
}

// check reads the groups of the user of session id again and stores them. It
// ends the session and returns false when the account is gone. Concurrent
// checks of one session share one lookup.
func (a *Authenticator) check(r *http.Request, id string) (session, bool, error) {
	v, err, _ := a.checks.Do(id, func() (any, error) {
		sess, ok := a.sessions.get(id, false)
		if !ok {
			return session{}, nil
		}
		// The request may be cancelled while others still wait for the result.
		ctx := context.WithoutCancel(r.Context())
		checkedAt := a.sessions.now()
		groups, err := a.checkAccount(ctx, sess.user)
		if errors.Is(err, ErrAccountGone) {
			a.sessions.delete(id)
			a.logger.InfoContext(ctx, "session ended: account deleted or deactivated", slog.String("username", sess.user.Username))
			a.audit(r, audit.ActionSessionEnded, "", sess.user.Username, map[string]string{"reason": "account deleted, deactivated or renamed"})
			return session{}, nil
		}
		if err != nil {
			return sess, err
		}
		if groups == nil {
			groups = []string{}
		}
		if updated, ok := a.sessions.setGroups(id, groups, checkedAt); ok {
			return updated, nil
		}
		return session{}, nil
	})
	sess, _ := v.(session)
	if err != nil {
		return sess, false, err
	}
	// A zero session means it has ended.
	return sess, !sess.expiresAt.IsZero(), nil
}

// currentSession returns the ID and the session of the request's cookie;
// touch restarts its idle timeout (see sessionStore.get).
func (a *Authenticator) currentSession(r *http.Request, touch bool) (string, session, bool) {
	c, err := r.Cookie(a.sessionCookie)
	if err != nil {
		return "", session{}, false
	}
	sess, ok := a.sessions.get(c.Value, touch)
	return c.Value, sess, ok
}

// setCookie sets an HttpOnly, SameSite=Lax cookie. maxAge 0 makes a session
// cookie, a negative maxAge deletes it.
func (a *Authenticator) setCookie(w http.ResponseWriter, name, value, path string, maxAge int) {
	//nolint:gosec // G124: Secure is false only when the redirect URL is plain http (local development).
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.secure,
		// Lax (not Strict) is required: the OIDC callback is a top-level
		// cross-site navigation from authentik that must carry the login cookie.
		SameSite: http.SameSiteLaxMode,
	})
}

// loginState is kept in a short-lived HttpOnly cookie between /auth/login and
// /auth/callback. It binds the callback to the browser that started the login
// (login CSRF) and carries the PKCE verifier and nonce.
type loginState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	// Return is the local path the callback redirects to.
	Return string `json:"r,omitempty"`
}

// login starts a login at the provider. With the query parameter reauth=1 the
// provider must authenticate the user again even when they have a session
// there, so the app can confirm the user for critical changes. The query
// parameter return names the local path to come back to; other targets are
// ignored, so the login cannot redirect elsewhere.
func (a *Authenticator) login(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st := loginState{
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
		Return:   localPath(q.Get("return")),
	}
	buf, err := json.Marshal(st)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "encoding login state", slog.Any("error", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, loginCookieName, base64.RawURLEncoding.EncodeToString(buf), loginCookiePath, int(loginTTL.Seconds()))
	opts := []oauth2.AuthCodeOption{oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)}
	if q.Get("reauth") == "1" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", reauthMaxAge))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(st.State, opts...), http.StatusFound)
}

// localPath returns p when it is a path on this host, such as "/users?page=2",
// and "/" otherwise, e.g. for "//evil.example" or "https://evil.example".
func localPath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return "/"
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return p
}

func (a *Authenticator) callback(w http.ResponseWriter, r *http.Request) {
	st, ok := a.takeLoginState(w, r)
	if !ok {
		a.loginFailed(r, "login state missing or expired")
		http.Error(w, "Login session expired or invalid. Please start again at /auth/login.", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		a.logger.WarnContext(r.Context(), "oidc provider returned error", slog.String("error", e))
		a.loginFailed(r, "provider error: "+truncate(e, 64))
		http.Error(w, "Login was not completed.", http.StatusForbidden)
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		a.loginFailed(r, "state mismatch")
		http.Error(w, "Login state mismatch. Please start again at /auth/login.", http.StatusBadRequest)
		return
	}

	user, rawIDToken, sid, err := a.exchange(r.Context(), q.Get("code"), st)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "oidc login failed", slog.Any("error", err))
		a.loginFailed(r, "code exchange or ID token verification failed")
		http.Error(w, "Login failed.", http.StatusBadGateway)
		return
	}
	// A new login replaces the browser's previous session.
	if c, err := r.Cookie(a.sessionCookie); err == nil {
		a.sessions.delete(c.Value)
	}
	id := a.sessions.create(user, rawIDToken, sid)
	a.setCookie(w, a.sessionCookie, id, "/", 0)
	a.logger.InfoContext(r.Context(), "login", slog.String("username", user.Username), slog.Bool("mfa", user.MFA()))
	a.audit(r, audit.ActionLogin, user.Username, user.Username, map[string]string{
		"mfa":       strconv.FormatBool(user.MFA()),
		"auth_time": user.AuthTime.UTC().Format(time.RFC3339),
	})
	http.Redirect(w, r, cmp.Or(st.Return, "/"), http.StatusFound)
}

// loginFailed records a login that could not be completed for reason.
func (a *Authenticator) loginFailed(r *http.Request, reason string) {
	a.audit(r, audit.ActionLoginFailed, "", "", map[string]string{"reason": reason})
}

// audit records an entry of r with Config.RecordAudit, naming the client IP.
func (a *Authenticator) audit(r *http.Request, action audit.Action, actor, target string, details map[string]string) {
	if a.recordAudit == nil {
		return
	}
	if a.clientIP != nil {
		details["client_ip"] = a.clientIP(r)
	}
	a.recordAudit(r.Context(), audit.Entry{Actor: actor, Action: action, Target: target, Details: details})
}

// truncate returns s cut to at most n bytes, for untrusted values in logs.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// takeLoginState reads and clears the login cookie.
func (a *Authenticator) takeLoginState(w http.ResponseWriter, r *http.Request) (loginState, bool) {
	c, err := r.Cookie(loginCookieName)
	if err != nil {
		return loginState{}, false
	}
	a.setCookie(w, loginCookieName, "", loginCookiePath, -1)
	buf, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return loginState{}, false
	}
	var st loginState
	if err := json.Unmarshal(buf, &st); err != nil || st.State == "" || st.Nonce == "" || st.Verifier == "" {
		return loginState{}, false
	}
	return st, true
}

// exchange redeems the authorization code and verifies the ID token. It
// returns the user, the raw ID token and the provider session ID ("sid").
func (a *Authenticator) exchange(ctx context.Context, code string, st loginState) (User, string, string, error) {
	ctx = oidc.ClientContext(ctx, a.httpClient)
	tok, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return User{}, "", "", fmt.Errorf("exchanging code: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return User{}, "", "", errors.New("token response has no id_token")
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return User{}, "", "", fmt.Errorf("verifying id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(st.Nonce)) != 1 {
		return User{}, "", "", errors.New("id token nonce mismatch")
	}
	var claims struct {
		PreferredUsername string   `json:"preferred_username"`
		Name              string   `json:"name"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
		SID               string   `json:"sid"`
		AuthTime          int64    `json:"auth_time"`
		AMR               []string `json:"amr"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return User{}, "", "", fmt.Errorf("decoding id token claims: %w", err)
	}
	// Without auth_time, the user authenticated for this login. A provider
	// clock running ahead must not make the authentication look fresher.
	authTime := time.Now()
	if t := time.Unix(claims.AuthTime, 0); claims.AuthTime > 0 && t.Before(authTime) {
		authTime = t
	}
	return User{
		Subject:  idToken.Subject,
		Username: claims.PreferredUsername,
		Name:     claims.Name,
		Email:    claims.Email,
		Groups:   claims.Groups,
		AuthTime: authTime,
		AMR:      claims.AMR,
	}, rawIDToken, claims.SID, nil
}

// logout ends the local session. The response carries the provider's
// end-session URL (if any) so the frontend can end the authentik session too.
func (a *Authenticator) logout(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		LogoutURL string `json:"logout_url,omitempty"`
	}{}
	if c, err := r.Cookie(a.sessionCookie); err == nil {
		if sess, ok := a.sessions.delete(c.Value); ok {
			a.logger.InfoContext(r.Context(), "logout", slog.String("username", sess.user.Username))
			a.audit(r, audit.ActionLogout, sess.user.Username, sess.user.Username, map[string]string{})
			if a.endSessionURL != "" {
				resp.LogoutURL = a.endSessionURL + "?" + url.Values{"id_token_hint": {sess.idToken}}.Encode()
			}
		}
	}
	a.setCookie(w, a.sessionCookie, "", "/", -1)
	writeJSON(w, http.StatusOK, resp)
}

// backchannelLogout implements OpenID Connect Back-Channel Logout 1.0: the
// provider POSTs a signed logout token when a user's provider session ends,
// and the matching local sessions end too. It needs no session cookie and is
// safe from CSRF because only a token signed by the provider is accepted.
func (a *Authenticator) backchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutRequestBytes)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	sub, sid, err := a.verifyLogoutToken(r.Context(), r.PostForm.Get("logout_token"))
	if err != nil {
		a.logger.WarnContext(r.Context(), "rejected back-channel logout", slog.Any("error", err))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	for _, sess := range a.sessions.deleteMatching(sub, sid) {
		a.logger.InfoContext(r.Context(), "back-channel logout", slog.String("username", sess.user.Username))
		a.audit(r, audit.ActionLogout, sess.user.Username, sess.user.Username, map[string]string{"via": "back-channel logout"})
	}
	w.WriteHeader(http.StatusOK)
}

// verifyLogoutToken validates a logout token as required by OpenID Connect
// Back-Channel Logout 1.0, section 2.6, and returns its sub and sid claims
// (at least one is set).
func (a *Authenticator) verifyLogoutToken(ctx context.Context, raw string) (string, string, error) {
	if raw == "" {
		return "", "", errors.New("missing logout_token")
	}
	// Checks the signature, iss and aud.
	tok, err := a.logoutVerifier.Verify(oidc.ClientContext(ctx, a.httpClient), raw)
	if err != nil {
		return "", "", fmt.Errorf("verifying logout token: %w", err)
	}
	now := time.Now()
	if tok.IssuedAt.IsZero() || tok.IssuedAt.Before(now.Add(-logoutTokenMaxAge)) || tok.IssuedAt.After(now.Add(clockSkew)) {
		return "", "", fmt.Errorf("logout token iat %v is outside the accepted window", tok.IssuedAt)
	}
	if !tok.Expiry.IsZero() && now.After(tok.Expiry.Add(clockSkew)) {
		return "", "", errors.New("logout token expired")
	}
	// A nonce would mean an ID token is replayed as a logout token.
	if tok.Nonce != "" {
		return "", "", errors.New("logout token must not contain a nonce")
	}
	var claims struct {
		SID    string                     `json:"sid"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := tok.Claims(&claims); err != nil {
		return "", "", fmt.Errorf("decoding logout token claims: %w", err)
	}
	var event map[string]any
	if err := json.Unmarshal(claims.Events[backchannelLogoutEvent], &event); err != nil || event == nil {
		return "", "", errors.New("logout token has no back-channel logout event")
	}
	if tok.Subject == "" && claims.SID == "" {
		return "", "", errors.New("logout token has neither sub nor sid")
	}
	return tok.Subject, claims.SID, nil
}

func (a *Authenticator) me(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := a.currentSession(r, true)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	writeJSON(w, http.StatusOK, sess.user)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// The status line is already sent; an encode error means the client went away.
	_ = json.NewEncoder(w).Encode(v)
}
