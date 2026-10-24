// Package authority defines the certificate authorities that sign client
// certificates: their records, stored with the private key encrypted, and the
// Registry of the loaded CAs.
package authority

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"authentikManager/internal/pki"
)

// Bounds and defaults of the validity settings, in days.
const (
	DefaultValidityDays    = 365
	MaxValidityDays        = 3650
	DefaultCRLValidityDays = 30
	MaxCRLValidityDays     = 365
)

// Bounds of the other settings.
const (
	maxDescriptionLen = 500
	maxGroups         = 100
	maxGroupNameLen   = 255
)

// namePattern is the form of CA names, which appear in URLs such as /pki/{name}/crl.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

var (
	// ErrNotFound is returned when there is no CA with the given ID.
	ErrNotFound = errors.New("authority: not found")
	// ErrExists is returned when creating a CA whose name or certificate is already stored.
	ErrExists = errors.New("authority: name or certificate already exists")
	// ErrDefaultDisabled is returned when disabling the default CA or making a disabled CA the default.
	ErrDefaultDisabled = errors.New("authority: the default ca cannot be disabled")
)

// Settings are the options of a CA that access administrators may change.
type Settings struct {
	Description string `json:"description"`
	// CRLURL, when set, is embedded in issued certificates as their CRL
	// distribution point, normally this app's /pki/{name}/crl.
	CRLURL string `json:"crl_url"`
	// ValidityDays is how long issued certificates are valid, shortened to the CA's expiry.
	ValidityDays int `json:"validity_days"`
	// CRLValidityDays is how long each signed CRL is valid until its next update.
	CRLValidityDays int `json:"crl_validity_days"`
	// UserCNSuffix is appended to the username in the common name of user certificates.
	UserCNSuffix string `json:"user_cn_suffix"`
	// ServiceAccountCNSuffix is appended to the username in the common name of
	// service account certificates.
	ServiceAccountCNSuffix string `json:"service_account_cn_suffix"`
	// AllowedGroups names the authentik groups an account must be a direct
	// member of to get certificates from the CA; empty allows every account.
	AllowedGroups []string `json:"allowed_groups"`
}

// Normalize trims the settings, defaults the validities, sorts and
// deduplicates the groups, then validates them. The returned error lists
// every problem and is safe to show users.
func (s Settings) Normalize() (Settings, error) {
	s.Description = strings.TrimSpace(s.Description)
	s.CRLURL = strings.TrimSpace(s.CRLURL)
	s.UserCNSuffix = strings.TrimSpace(s.UserCNSuffix)
	s.ServiceAccountCNSuffix = strings.TrimSpace(s.ServiceAccountCNSuffix)
	if s.ValidityDays == 0 {
		s.ValidityDays = DefaultValidityDays
	}
	if s.CRLValidityDays == 0 {
		s.CRLValidityDays = DefaultCRLValidityDays
	}
	groups := make([]string, 0, len(s.AllowedGroups))
	for _, g := range s.AllowedGroups {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	slices.Sort(groups)
	s.AllowedGroups = slices.Compact(groups)

	if problems := s.problems(); len(problems) > 0 {
		return Settings{}, errors.New(strings.Join(problems, "; "))
	}
	return s, nil
}

// problems describes what is wrong with the normalized settings s.
func (s Settings) problems() []string {
	var problems []string
	if len(s.Description) > maxDescriptionLen {
		problems = append(problems, fmt.Sprintf("the description must have at most %d characters", maxDescriptionLen))
	}
	if s.CRLURL != "" {
		u, err := url.Parse(s.CRLURL)
		if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
			problems = append(problems, "the CRL URL must be an absolute http or https URL")
		}
	}
	if s.ValidityDays < 1 || s.ValidityDays > MaxValidityDays {
		problems = append(problems, fmt.Sprintf("the validity must be between 1 and %d days", MaxValidityDays))
	}
	if s.CRLValidityDays < 1 || s.CRLValidityDays > MaxCRLValidityDays {
		problems = append(problems, fmt.Sprintf("the CRL validity must be between 1 and %d days", MaxCRLValidityDays))
	}
	for _, suffix := range []string{s.UserCNSuffix, s.ServiceAccountCNSuffix} {
		if err := pki.ValidateCNSuffix(suffix); err != nil {
			problems = append(problems, strings.TrimPrefix(err.Error(), "pki: "))
		}
	}
	if len(s.AllowedGroups) > maxGroups {
		problems = append(problems, fmt.Sprintf("at most %d groups may be allowed", maxGroups))
	}
	if slices.ContainsFunc(s.AllowedGroups, func(g string) bool { return len(g) > maxGroupNameLen }) {
		problems = append(problems, fmt.Sprintf("group names must have at most %d characters", maxGroupNameLen))
	}
	return problems
}

// ValidateName checks that name is 1 to 32 lowercase letters, digits and
// hyphens, starting with a letter or digit. The error is safe to show users.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return errors.New("the name must have 1 to 32 lowercase letters, digits and hyphens, starting with a letter or digit")
	}
	return nil
}

// Authority is the stored record of a CA.
type Authority struct {
	ID int64 `json:"id"`
	// Name identifies the CA in requests and URLs; it never changes.
	Name string `json:"name"`
	Settings
	// CertPEM is the CA certificate, optionally followed by the certificates above it.
	CertPEM string `json:"certificate_pem"`
	// KeyCiphertext is the PKCS#8 PEM private key, sealed with pki.KeyCipher
	// bound to Name.
	KeyCiphertext []byte `json:"-"`
	// Fingerprint is the SHA-256 hash of the CA certificate, unique among CAs.
	Fingerprint []byte `json:"-"`
	// Default is set for the one CA that signs when a request names none.
	Default bool `json:"default"`
	// Legacy is set for the CA imported from CA_CERT_FILE, whose revocation
	// list and chain the unnamed /pki/crl and /pki/ca.pem serve.
	Legacy bool `json:"legacy"`
	// Disabled CAs issue no certificates, but still serve their CRL and chain
	// and can be imported from.
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// Allows reports whether an account in groups may get certificates from the CA.
func (a Authority) Allows(groups []string) bool {
	if len(a.AllowedGroups) == 0 {
		return true
	}
	return slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(a.AllowedGroups, g) })
}
