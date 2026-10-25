// Package apikey defines the API keys of service accounts, with which they
// issue and revoke their own certificates without signing in.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

// Prefix starts every key, so leaked keys are easy to recognize.
const Prefix = "amk_"

// secretLen is the length of the text rand.Text returns, which follows Prefix.
const secretLen = 26

// shownLen is the length of the start of a key kept to tell keys apart.
const shownLen = len(Prefix) + 8

// ErrNotFound is returned when there is no API key with the given ID or
// secret, or the key has expired.
var ErrNotFound = errors.New("api key not found")

// Key is the record of an API key. The key itself is never stored, only its hash.
type Key struct {
	ID int64 `json:"id"`
	// UserPK is the authentik primary key of the service account the key authenticates as.
	UserPK int `json:"user_pk"`
	// Username is the service account's username when the key was created.
	Username    string `json:"username"`
	Description string `json:"description"`
	// Start is the beginning of the key, to tell keys apart.
	Start string `json:"start"`
	// CreatedAt is set by the store.
	CreatedAt time.Time `json:"created_at"`
	// CreatedBy is the username of the operator who created the key.
	CreatedBy string `json:"created_by"`
	// ExpiresAt is nil for a key that never expires.
	ExpiresAt *time.Time `json:"expires_at"`
	// LastUsedAt is nil while the key has not been used.
	LastUsedAt *time.Time `json:"last_used_at"`
}

// New returns a new random key, its start for Key.Start, and its hash to store.
func New() (key, start string, hash []byte) {
	key = Prefix + rand.Text()
	return key, Start(key), Hash(key)
}

// Start returns the beginning of key that Key.Start keeps to tell keys apart.
// It is not secret, so it may be logged.
func Start(key string) string {
	return key[:min(shownLen, len(key))]
}

// Hash returns the hash of key under which it is stored. Keys are random, so
// a fast hash suffices.
func Hash(key string) []byte {
	sum := sha256.Sum256([]byte(key))
	return sum[:]
}

// WellFormed reports whether key has the form New returns, so malformed keys
// are rejected without looking them up.
func WellFormed(key string) bool {
	secret, ok := strings.CutPrefix(key, Prefix)
	if !ok || len(secret) != secretLen {
		return false
	}
	for _, c := range secret {
		// rand.Text uses the base32 alphabet.
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}
