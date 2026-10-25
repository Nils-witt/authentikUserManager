package server

import (
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"authentikManager/internal/ratelimit"
)

// Rate limits protect against automated use and exhaustion of the server and
// authentik. Each allows a burst and then one request every interval.
const (
	// loginBurst and loginInterval limit starting and completing logins per client IP.
	loginBurst    = 30
	loginInterval = 2 * time.Second
	// serviceAPIBurst and serviceAPIInterval limit service API requests per
	// client IP, before the API key is checked.
	serviceAPIBurst    = 60
	serviceAPIInterval = time.Second
	// apiBurst and apiInterval limit API requests per signed-in user.
	apiBurst    = 300
	apiInterval = 100 * time.Millisecond
	// issueBurst and issueInterval limit the certificates each user or
	// service account issues, since issuing generates keys and signs.
	issueBurst    = 20
	issueInterval = 3 * time.Minute
)

// limiters are the rate limiters of the Server.
type limiters struct {
	login      *ratelimit.Limiter
	serviceAPI *ratelimit.Limiter
	api        *ratelimit.Limiter
	issue      *ratelimit.Limiter
}

func newLimiters(now func() time.Time) limiters {
	return limiters{
		login:      ratelimit.New(loginBurst, loginInterval, now),
		serviceAPI: ratelimit.New(serviceAPIBurst, serviceAPIInterval, now),
		api:        ratelimit.New(apiBurst, apiInterval, now),
		issue:      ratelimit.New(issueBurst, issueInterval, now),
	}
}

// allow takes a token of key from l and answers 429 when none is left.
func (s *Server) allow(w http.ResponseWriter, r *http.Request, l *ratelimit.Limiter, kind, key string) bool {
	ok, wait := l.Allow(key)
	if ok {
		return true
	}
	safePath := strings.ReplaceAll(r.URL.Path, "\n", "")
	safePath = strings.ReplaceAll(safePath, "\r", "")
	s.logger.WarnContext(r.Context(), "rate limit exceeded",
		slog.String("limit", kind),
		slog.String("key", key),
		slog.String("path", safePath),
	)
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
	writeError(w, http.StatusTooManyRequests, "too many requests; try again later", nil)
	return false
}

// limitByIP limits the requests to h per client IP with l.
func (s *Server) limitByIP(l *ratelimit.Limiter, kind string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.allow(w, r, l, kind, s.clientIP(r)) {
			h.ServeHTTP(w, r)
		}
	})
}

// limitByUser limits the requests to h per signed-in user with l. It must
// run after the user is authenticated.
func (s *Server) limitByUser(l *ratelimit.Limiter, kind string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.allow(w, r, l, kind, "user:"+actorName(r)) {
			h.ServeHTTP(w, r)
		}
	})
}

// limitLogins limits the requests starting and completing logins per client
// IP; the other /auth/ endpoints of h are not limited.
func (s *Server) limitLogins(h http.Handler) http.Handler {
	limited := s.limitByIP(s.limits.login, "login", h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/login", "/auth/callback":
			limited.ServeHTTP(w, r)
		default:
			h.ServeHTTP(w, r)
		}
	})
}
