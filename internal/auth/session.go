package auth

import (
	"context"
	"crypto/rand"
	"slices"
	"sync"
	"time"
)

// User is the authenticated operator of this application.
type User struct {
	Subject  string   `json:"sub"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	// AuthTime is when the user last authenticated at the provider: the ID
	// token's auth_time, or the time of the login when it has none. It is zero
	// for callers that did not log in, such as service accounts.
	AuthTime time.Time `json:"auth_time"`
	// AMR lists the authentication methods of that authentication (the ID
	// token's amr claim, RFC 8176), e.g. "pwd" and "mfa".
	AMR []string `json:"amr"`
}

// MFA reports whether the user authenticated with more than one factor:
// the provider says so with "mfa", or names several methods.
func (u User) MFA() bool {
	if slices.Contains(u.AMR, "mfa") {
		return true
	}
	methods := slices.Clone(u.AMR)
	slices.Sort(methods)
	return len(slices.Compact(methods)) >= 2
}

type ctxKey struct{}

// WithUser returns a copy of ctx carrying u.
func WithUser(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// UserFromContext returns the user stored by the Require middleware.
func UserFromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(ctxKey{}).(User)
	return u, ok
}

type session struct {
	user    User
	idToken string // raw ID token, used as id_token_hint on logout
	sid     string // provider session ID ("sid" claim), empty if the provider sent none
	// expiresAt is the end of the session's maximum lifetime.
	expiresAt time.Time
	// lastSeen is when the user last used the session; it ends idleTimeout later.
	lastSeen time.Time
	// checkedAt is when user.Groups were last read from the provider.
	checkedAt time.Time
}

// matchesLogout reports whether a back-channel logout for sub and sid ends
// this session. sid selects one provider session; without a sid on either
// side, all sessions of sub end.
func (s session) matchesLogout(sub, sid string) bool {
	if sid != "" && s.sid != "" {
		return s.sid == sid && (sub == "" || s.user.Subject == sub)
	}
	return sub != "" && s.user.Subject == sub
}

// expired reports whether the session has ended at now, by its lifetime or
// because it was idle for longer than idleTimeout.
func (s session) expired(now time.Time, idleTimeout time.Duration) bool {
	return now.After(s.expiresAt) || now.After(s.lastSeen.Add(idleTimeout))
}

// sessionStore keeps sessions in memory: a restart logs everyone out, and the
// app must run as a single instance.
type sessionStore struct {
	mu sync.Mutex
	// ttl is the maximum lifetime of a session.
	ttl time.Duration
	// idleTimeout ends a session that was not used for this long.
	idleTimeout time.Duration
	now         func() time.Time
	sessions    map[string]session
}

func newSessionStore(ttl, idleTimeout time.Duration) *sessionStore {
	return &sessionStore{ttl: ttl, idleTimeout: idleTimeout, now: time.Now, sessions: map[string]session{}}
}

// create stores a new session and returns its unguessable ID (128 bits from crypto/rand).
func (s *sessionStore) create(u User, idToken, sid string) string {
	id := rand.Text()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	now := s.now()
	s.sessions[id] = session{user: u, idToken: idToken, sid: sid, expiresAt: now.Add(s.ttl), lastSeen: now, checkedAt: now}
	return id
}

// setGroups replaces the groups of the session's user with the ones read
// from the provider at checkedAt. It returns the updated session, or false
// when the session has ended meanwhile.
func (s *sessionStore) setGroups(id string, groups []string, checkedAt time.Time) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return session{}, false
	}
	sess.user.Groups = groups
	sess.checkedAt = checkedAt
	s.sessions[id] = sess
	return sess, true
}

// get returns the session with id unless it has ended. When touch is set, it
// counts as use of the session and restarts its idle timeout; background
// requests the user did not make, such as polling, must not set it.
func (s *sessionStore) get(id string, touch bool) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return session{}, false
	}
	now := s.now()
	if sess.expired(now, s.idleTimeout) {
		delete(s.sessions, id)
		return session{}, false
	}
	if touch {
		sess.lastSeen = now
		s.sessions[id] = sess
	}
	return sess, true
}

// prune deletes the sessions that have ended, with their ID tokens.
func (s *sessionStore) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
}

func (s *sessionStore) pruneLocked() {
	now := s.now()
	for id, sess := range s.sessions {
		if sess.expired(now, s.idleTimeout) {
			delete(s.sessions, id)
		}
	}
}

func (s *sessionStore) delete(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	delete(s.sessions, id)
	return sess, ok
}

// deleteMatching removes the sessions a back-channel logout for sub and sid
// ends (see session.matchesLogout) and returns them.
func (s *sessionStore) deleteMatching(sub, sid string) []session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ended []session
	for id, sess := range s.sessions {
		if sess.matchesLogout(sub, sid) {
			ended = append(ended, sess)
			delete(s.sessions, id)
		}
	}
	return ended
}
