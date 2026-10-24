package authority

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"authentikManager/internal/pki"
)

// Entry is a loaded CA: its record and the CA that signs with its key.
// Entries are shared and must not be modified.
type Entry struct {
	Authority
	CA *pki.CA
}

// Registry holds the loaded CAs. Load replaces them all at once, so readers
// always see a consistent set. It is safe for concurrent use.
type Registry struct {
	cipher  *pki.KeyCipher
	entries atomic.Pointer[[]*Entry]
}

// NewRegistry returns an empty registry that opens CA keys with cipher.
func NewRegistry(cipher *pki.KeyCipher) *Registry {
	r := &Registry{cipher: cipher}
	r.entries.Store(&[]*Entry{})
	return r
}

// Options returns the options a CA with the settings of a signs with.
func (a Authority) Options() pki.Options {
	return pki.Options{
		Validity:               time.Duration(a.ValidityDays) * 24 * time.Hour,
		CRLURL:                 a.CRLURL,
		CRLValidity:            time.Duration(a.CRLValidityDays) * 24 * time.Hour,
		UserCNSuffix:           a.UserCNSuffix,
		ServiceAccountCNSuffix: a.ServiceAccountCNSuffix,
	}
}

// SealKey normalizes keyPEM to PKCS#8 and encrypts it for the CA named name.
func (r *Registry) SealKey(name string, keyPEM []byte) ([]byte, error) {
	normalized, err := pki.NormalizeKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	defer clear(normalized)
	return r.cipher.Seal(normalized, []byte(name))
}

// Open decrypts the key of a and loads the CA it describes.
func (r *Registry) Open(a Authority) (*pki.CA, error) {
	keyPEM, err := r.cipher.Open(a.KeyCiphertext, []byte(a.Name))
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)
	return pki.LoadCA([]byte(a.CertPEM), keyPEM, a.Options())
}

// Load replaces the loaded CAs with list. When any of them cannot be loaded,
// it returns the errors and keeps the CAs loaded before.
func (r *Registry) Load(list []Authority) error {
	entries := make([]*Entry, 0, len(list))
	var errs []error
	for _, a := range list {
		ca, err := r.Open(a)
		if err != nil {
			errs = append(errs, fmt.Errorf("loading ca %q: %w", a.Name, err))
			continue
		}
		entries = append(entries, &Entry{Authority: a, CA: ca})
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	slices.SortFunc(entries, func(a, b *Entry) int { return cmp.Compare(a.Name, b.Name) })
	r.entries.Store(&entries)
	return nil
}

// All returns every loaded CA, disabled ones included, ordered by name.
func (r *Registry) All() []*Entry {
	return slices.Clone(*r.entries.Load())
}

// ByID returns the CA with id.
func (r *Registry) ByID(id int64) (*Entry, bool) {
	return r.find(func(e *Entry) bool { return e.ID == id })
}

// ByName returns the CA named name.
func (r *Registry) ByName(name string) (*Entry, bool) {
	return r.find(func(e *Entry) bool { return e.Name == name })
}

// Default returns the CA that signs when a request names none.
func (r *Registry) Default() (*Entry, bool) {
	return r.find(func(e *Entry) bool { return e.Default })
}

// Legacy returns the CA imported from CA_CERT_FILE, or the default CA when
// there is none, for the URLs that name no CA.
func (r *Registry) Legacy() (*Entry, bool) {
	if e, ok := r.find(func(e *Entry) bool { return e.Legacy }); ok {
		return e, true
	}
	return r.Default()
}

// Usable returns the enabled CAs that allow an account in groups, the
// default CA first, then by name.
func (r *Registry) Usable(groups []string) []*Entry {
	var usable []*Entry
	for _, e := range *r.entries.Load() {
		if !e.Disabled && e.Allows(groups) {
			usable = append(usable, e)
		}
	}
	// Stable, so the others keep their order by name.
	slices.SortStableFunc(usable, func(a, b *Entry) int {
		switch {
		case a.Default == b.Default:
			return 0
		case a.Default:
			return -1
		default:
			return 1
		}
	})
	return usable
}

func (r *Registry) find(match func(*Entry) bool) (*Entry, bool) {
	entries := *r.entries.Load()
	i := slices.IndexFunc(entries, match)
	if i < 0 {
		return nil, false
	}
	return entries[i], true
}
