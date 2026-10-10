// Package auth protects the application with an OpenID Connect login against
// authentik (authorization code flow with PKCE) and server-side sessions.
//
// Tokens never reach the browser: it only holds an opaque, HttpOnly session cookie.
package auth

import (
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
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	loginCookieName = "am_login"
	loginCookiePath = "/auth/callback"
	loginTTL        = 10 * time.Minute
	httpTimeout     = 15 * time.Second
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
	// AllowedGroups lists the authentik groups whose members may log in.
	AllowedGroups []string
	SessionTTL    time.Duration
}

// Authenticator serves the /auth/ endpoints and guards other handlers.
type Authenticator struct {
	oauth         oauth2.Config
	verifier      *oidc.IDTokenVerifier
	endSessionURL string
	allowedGroups []string
	sessions      *sessionStore
	secure        bool
	sessionCookie string
	httpClient    *http.Client
	logger        *slog.Logger
	mux           *http.ServeMux
}

// New discovers the provider's configuration. ctx must outlive the
// Authenticator: go-oidc uses it to refresh the provider's signing keys.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (*Authenticator, error) {
	if len(cfg.AllowedGroups) == 0 {
		return nil, errors.New("auth: at least one allowed group is required")
	}
	redirect, err := url.Parse(cfg.RedirectURL)
	if err != nil || !redirect.IsAbs() {
		return nil, fmt.Errorf("auth: redirect url %q must be absolute", cfg.RedirectURL)
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 8 * time.Hour
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
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		endSessionURL: meta.EndSessionEndpoint,
		allowedGroups: slices.Clone(cfg.AllowedGroups),
		sessions:      newSessionStore(cfg.SessionTTL),
		secure:        secure,
		sessionCookie: sessionCookie,
		httpClient:    httpClient,
		logger:        logger,
		mux:           http.NewServeMux(),
	}
	a.mux.HandleFunc("GET /auth/login", a.login)
	a.mux.HandleFunc("GET /auth/callback", a.callback)
	a.mux.HandleFunc("POST /auth/logout", a.logout)
	a.mux.HandleFunc("GET /auth/me", a.me)
	return a, nil
}

// Handler serves the /auth/ endpoints.
func (a *Authenticator) Handler() http.Handler { return a.mux }

// Require rejects requests without a valid session with 401 and otherwise
// stores the User in the request context (see UserFromContext).
func (a *Authenticator) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := a.currentSession(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), sess.user)))
	})
}

func (a *Authenticator) currentSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(a.sessionCookie)
	if err != nil {
		return session{}, false
	}
	return a.sessions.get(c.Value)
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
}

func (a *Authenticator) login(w http.ResponseWriter, r *http.Request) {
	st := loginState{
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
	}
	buf, err := json.Marshal(st)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "encoding login state", slog.Any("error", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, loginCookieName, base64.RawURLEncoding.EncodeToString(buf), loginCookiePath, int(loginTTL.Seconds()))
	target := a.oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, target, http.StatusFound)
}

func (a *Authenticator) callback(w http.ResponseWriter, r *http.Request) {
	st, ok := a.takeLoginState(w, r)
	if !ok {
		http.Error(w, "Login session expired or invalid. Please start again at /auth/login.", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		a.logger.WarnContext(r.Context(), "oidc provider returned error", slog.String("error", e))
		http.Error(w, "Login was not completed.", http.StatusForbidden)
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		http.Error(w, "Login state mismatch. Please start again at /auth/login.", http.StatusBadRequest)
		return
	}

	user, rawIDToken, err := a.exchange(r.Context(), q.Get("code"), st)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "oidc login failed", slog.Any("error", err))
		http.Error(w, "Login failed.", http.StatusBadGateway)
		return
	}
	if !a.isAllowed(user.Groups) {
		a.logger.WarnContext(r.Context(), "login denied: not in an allowed group", slog.String("username", user.Username))
		http.Error(w, "Access denied: your account is not allowed to use this application.", http.StatusForbidden)
		return
	}

	id := a.sessions.create(user, rawIDToken)
	a.setCookie(w, a.sessionCookie, id, "/", 0)
	a.logger.InfoContext(r.Context(), "login", slog.String("username", user.Username))
	http.Redirect(w, r, "/", http.StatusFound)
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

// exchange redeems the authorization code and verifies the ID token.
func (a *Authenticator) exchange(ctx context.Context, code string, st loginState) (User, string, error) {
	ctx = oidc.ClientContext(ctx, a.httpClient)
	tok, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return User{}, "", fmt.Errorf("exchanging code: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return User{}, "", errors.New("token response has no id_token")
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return User{}, "", fmt.Errorf("verifying id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(st.Nonce)) != 1 {
		return User{}, "", errors.New("id token nonce mismatch")
	}
	var claims struct {
		PreferredUsername string   `json:"preferred_username"`
		Name              string   `json:"name"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return User{}, "", fmt.Errorf("decoding id token claims: %w", err)
	}
	return User{
		Subject:  idToken.Subject,
		Username: claims.PreferredUsername,
		Name:     claims.Name,
		Email:    claims.Email,
		Groups:   claims.Groups,
	}, rawIDToken, nil
}

func (a *Authenticator) isAllowed(groups []string) bool {
	return slices.ContainsFunc(groups, func(g string) bool {
		return slices.Contains(a.allowedGroups, g)
	})
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
			if a.endSessionURL != "" {
				resp.LogoutURL = a.endSessionURL + "?" + url.Values{"id_token_hint": {sess.idToken}}.Encode()
			}
		}
	}
	a.setCookie(w, a.sessionCookie, "", "/", -1)
	writeJSON(w, http.StatusOK, resp)
}

func (a *Authenticator) me(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.currentSession(r)
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
