package auth

import (
	"context"
	"crypto/rand"
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
	user      User
	idToken   string // raw ID token, used as id_token_hint on logout
	expiresAt time.Time
}

// sessionStore keeps sessions in memory: a restart logs everyone out, and the
// app must run as a single instance.
type sessionStore struct {
	mu       sync.Mutex
	ttl      time.Duration
	now      func() time.Time
	sessions map[string]session
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{ttl: ttl, now: time.Now, sessions: map[string]session{}}
}

// create stores a new session and returns its unguessable ID (128 bits from crypto/rand).
func (s *sessionStore) create(u User, idToken string) string {
	id := rand.Text()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, sess := range s.sessions {
		if now.After(sess.expiresAt) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = session{user: u, idToken: idToken, expiresAt: now.Add(s.ttl)}
	return id
}

func (s *sessionStore) get(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return session{}, false
	}
	if s.now().After(sess.expiresAt) {
		delete(s.sessions, id)
		return session{}, false
	}
	return sess, true
}

func (s *sessionStore) delete(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	delete(s.sessions, id)
	return sess, ok
}
