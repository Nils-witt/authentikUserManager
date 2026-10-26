// Package config loads the application configuration from environment variables.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"authentikManager/internal/clientip"
)

// Config is the runtime configuration.
type Config struct {
	// AuthentikURL is the base URL of the authentik instance, e.g. https://sso.example.com.
	AuthentikURL string
	// AuthentikToken is an authentik API token with user management permissions.
	AuthentikToken string
	// ListenAddr is the address the HTTP server binds to.
	ListenAddr string
	// StaticDir, when set, is served as the frontend instead of the embedded build.
	StaticDir string
	// TrustedProxies are the IP addresses and CIDR prefixes of the reverse
	// proxies whose X-Forwarded-For header names the client.
	TrustedProxies []string
	// RecoveryEmailStage is the UUID of the authentik email stage that sends
	// password recovery emails. When empty, sending them is disabled.
	RecoveryEmailStage string

	// OIDCIssuer is the issuer URL of the authentik OAuth2/OIDC provider,
	// e.g. https://sso.example.com/application/o/authentik-manager/.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	// OIDCRedirectURL is this app's public callback URL, ending in /auth/callback.
	OIDCRedirectURL string
	// SessionLifetime is the maximum lifetime of a login session.
	SessionLifetime time.Duration
	// SessionIdleTimeout ends sessions that were not used for this long. It is
	// at most SessionLifetime.
	SessionIdleTimeout time.Duration
	// ReauthMaxAge is how long ago operators may have authenticated at
	// authentik to make critical changes. Zero disables the check.
	ReauthMaxAge time.Duration

	// DatabaseURL is the PostgreSQL connection URL that stores the access rules
	// and the audit log.
	DatabaseURL string
	// AuditRetention is how long audit log entries are kept. Zero keeps them forever.
	AuditRetention time.Duration
	// AccessAdminGroups lists the groups whose members have full access and may
	// edit the access rules.
	AccessAdminGroups []string

	// CAEncryptionKey encrypts the private keys of the CAs stored in the
	// database. Empty disables certificates.
	CAEncryptionKey []byte
	// CACertFile and CAKeyFile are the PEM files of a CA certificate and its
	// private key, imported into the database at startup unless stored
	// already. Both may be empty.
	CACertFile string
	CAKeyFile  string
	// CertValidity, CertCRLURL, CertCRLValidity, CertUserCNSuffix and
	// CertServiceAccountCNSuffix are the initial settings of the CA imported
	// from CACertFile; access administrators change them afterwards.
	//
	// CertValidity is how long issued user certificates are valid.
	CertValidity time.Duration
	// CertCRLURL, when set, is the public URL of the CRL (this app's /pki/crl),
	// embedded in issued certificates.
	CertCRLURL string
	// CertCRLValidity is how long each signed CRL is valid until its next update.
	CertCRLValidity time.Duration
	// CertUserCNSuffix is appended to the username in the common name of user
	// certificates, e.g. "@example.com".
	CertUserCNSuffix string
	// CertServiceAccountCNSuffix is appended to the username in the common
	// name of service account certificates.
	CertServiceAccountCNSuffix string

	// SMTPHost is the SMTP server that emails notifications. When empty,
	// notifications are delivered in the app only.
	SMTPHost string
	// SMTPPort defaults to the usual port of SMTPTLS.
	SMTPPort int
	// SMTPUsername and SMTPPassword authenticate with the server when SMTPUsername is set.
	SMTPUsername string
	SMTPPassword string
	// SMTPFrom is the sender address of notification emails, e.g. "Manager <noreply@example.com>".
	SMTPFrom string
	// SMTPTLS is "starttls" (default), "tls" for implicit TLS, or "none" for a server on localhost.
	SMTPTLS string
}

const defaultListenAddr = "127.0.0.1:8080"

// maxAuditRetentionDays bounds AUDIT_RETENTION_DAYS (100 years).
const maxAuditRetentionDays = 36500

// Bounds and default of CERT_VALIDITY_DAYS.
const (
	defaultCertValidityDays = 365
	maxCertValidityDays     = 3650
)

// defaultSMTPPorts are the default SMTP_PORT values per SMTP_TLS mode.
var defaultSMTPPorts = map[string]int{"starttls": 587, "tls": 465, "none": 25}

// caEncryptionKeyLen is the length of the decoded CA_ENCRYPTION_KEY (AES-256).
const caEncryptionKeyLen = 32

// Bounds and defaults of SESSION_LIFETIME_HOURS and SESSION_IDLE_TIMEOUT_MINUTES.
const (
	defaultSessionLifetimeHours   = 8
	maxSessionLifetimeHours       = 7 * 24
	defaultSessionIdleTimeoutMins = 30
	maxSessionIdleTimeoutMins     = 24 * 60
	defaultReauthMaxAgeMins       = 15
)

// Bounds and default of CERT_CRL_VALIDITY_DAYS.
const (
	defaultCRLValidityDays = 30
	maxCRLValidityDays     = 365
)

// FromEnv reads the configuration from the environment, using getenv
// (normally os.Getenv) so it can be tested without touching the process env.
func FromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		AuthentikURL:   getenv("AUTHENTIK_URL"),
		AuthentikToken: getenv("AUTHENTIK_TOKEN"),
		ListenAddr:     getenv("LISTEN_ADDR"),
		StaticDir:      getenv("STATIC_DIR"),
		TrustedProxies: splitList(getenv("TRUSTED_PROXIES")),

		RecoveryEmailStage: strings.TrimSpace(getenv("AUTHENTIK_RECOVERY_EMAIL_STAGE")),

		OIDCIssuer:       getenv("OIDC_ISSUER"),
		OIDCClientID:     getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret: getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  getenv("OIDC_REDIRECT_URL"),

		DatabaseURL:       getenv("DATABASE_URL"),
		AccessAdminGroups: splitList(getenv("ACCESS_ADMIN_GROUPS")),

		CACertFile: strings.TrimSpace(getenv("CA_CERT_FILE")),
		CAKeyFile:  strings.TrimSpace(getenv("CA_KEY_FILE")),
		CertCRLURL: strings.TrimSpace(getenv("CERT_CRL_URL")),

		CertUserCNSuffix:           strings.TrimSpace(getenv("CERT_USER_CN_SUFFIX")),
		CertServiceAccountCNSuffix: strings.TrimSpace(getenv("CERT_SERVICE_ACCOUNT_CN_SUFFIX")),

		SMTPHost:     strings.TrimSpace(getenv("SMTP_HOST")),
		SMTPUsername: getenv("SMTP_USERNAME"),
		SMTPPassword: getenv("SMTP_PASSWORD"),
		SMTPFrom:     strings.TrimSpace(getenv("SMTP_FROM")),
		SMTPTLS:      strings.ToLower(strings.TrimSpace(getenv("SMTP_TLS"))),
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultListenAddr
	}

	var errs []error
	required := []struct{ name, value string }{
		{"AUTHENTIK_URL", cfg.AuthentikURL},
		{"AUTHENTIK_TOKEN", cfg.AuthentikToken},
		{"OIDC_ISSUER", cfg.OIDCIssuer},
		{"OIDC_CLIENT_ID", cfg.OIDCClientID},
		{"OIDC_CLIENT_SECRET", cfg.OIDCClientSecret},
		{"OIDC_REDIRECT_URL", cfg.OIDCRedirectURL},
		{"DATABASE_URL", cfg.DatabaseURL},
	}
	for _, r := range required {
		if r.value == "" {
			errs = append(errs, fmt.Errorf("%s is required", r.name))
		}
	}
	if len(cfg.AccessAdminGroups) == 0 {
		errs = append(errs, errors.New("ACCESS_ADMIN_GROUPS is required (comma-separated authentik group names)"))
	}
	retention, err := parseRetention(getenv("AUDIT_RETENTION_DAYS"))
	if err != nil {
		errs = append(errs, err)
	}
	cfg.AuditRetention = retention
	errs = append(errs, cfg.parseSessions(getenv("SESSION_LIFETIME_HOURS"), getenv("SESSION_IDLE_TIMEOUT_MINUTES"))...)
	errs = append(errs, cfg.parseReauth(getenv("REAUTH_MAX_AGE_MINUTES"))...)
	errs = append(errs, cfg.parseCertificates(getenv("CA_ENCRYPTION_KEY"), getenv("CERT_VALIDITY_DAYS"), getenv("CERT_CRL_VALIDITY_DAYS"))...)
	errs = append(errs, cfg.parseSMTP(getenv("SMTP_PORT"))...)
	if _, err := clientip.NewResolver(cfg.TrustedProxies); err != nil {
		errs = append(errs, fmt.Errorf("TRUSTED_PROXIES: %w", err))
	}
	if cfg.StaticDir != "" {
		if fi, err := os.Stat(cfg.StaticDir); err != nil || !fi.IsDir() {
			errs = append(errs, fmt.Errorf("STATIC_DIR %q is not a readable directory", cfg.StaticDir))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Config{}, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// parseRetention parses AUDIT_RETENTION_DAYS; empty means zero, keeping entries forever.
func parseRetention(v string) (time.Duration, error) {
	return parseDays("AUDIT_RETENTION_DAYS", v, 0, maxAuditRetentionDays)
}

// parseSessions sets SessionLifetime from lifetimeHours (SESSION_LIFETIME_HOURS)
// and SessionIdleTimeout from idleMinutes (SESSION_IDLE_TIMEOUT_MINUTES).
func (cfg *Config) parseSessions(lifetimeHours, idleMinutes string) []error {
	var errs []error
	hours, err := parseCount("SESSION_LIFETIME_HOURS", "hours", lifetimeHours, defaultSessionLifetimeHours, maxSessionLifetimeHours)
	if err != nil {
		errs = append(errs, err)
	}
	cfg.SessionLifetime = time.Duration(hours) * time.Hour
	minutes, err := parseCount("SESSION_IDLE_TIMEOUT_MINUTES", "minutes", idleMinutes, defaultSessionIdleTimeoutMins, maxSessionIdleTimeoutMins)
	if err != nil {
		errs = append(errs, err)
	}
	cfg.SessionIdleTimeout = min(time.Duration(minutes)*time.Minute, cfg.SessionLifetime)
	return errs
}

// parseReauth sets ReauthMaxAge from maxAgeMinutes (REAUTH_MAX_AGE_MINUTES,
// where 0 disables the check).
func (cfg *Config) parseReauth(maxAgeMinutes string) []error {
	var errs []error
	minutes := defaultReauthMaxAgeMins
	if v := strings.TrimSpace(maxAgeMinutes); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > maxSessionIdleTimeoutMins {
			errs = append(errs, fmt.Errorf("REAUTH_MAX_AGE_MINUTES must be a number of minutes between 0 and %d", maxSessionIdleTimeoutMins))
		}
		minutes = n
	}
	cfg.ReauthMaxAge = time.Duration(minutes) * time.Minute
	return errs
}

// parseCertificates sets CAEncryptionKey from encryptionKey
// (CA_ENCRYPTION_KEY), validates the CA files and the CRL URL, and sets
// CertValidity from validityDays (CERT_VALIDITY_DAYS) and CertCRLValidity from
// crlValidityDays (CERT_CRL_VALIDITY_DAYS).
func (cfg *Config) parseCertificates(encryptionKey, validityDays, crlValidityDays string) []error {
	var errs []error
	if encryptionKey = strings.TrimSpace(encryptionKey); encryptionKey != "" {
		key, err := base64.StdEncoding.DecodeString(encryptionKey)
		if err != nil || len(key) != caEncryptionKeyLen {
			// The value is a secret; do not echo it.
			errs = append(errs, fmt.Errorf("CA_ENCRYPTION_KEY must be %d random bytes, base64-encoded (openssl rand -base64 %d)",
				caEncryptionKeyLen, caEncryptionKeyLen))
		}
		cfg.CAEncryptionKey = key
	}
	if (cfg.CACertFile == "") != (cfg.CAKeyFile == "") {
		errs = append(errs, errors.New("CA_CERT_FILE and CA_KEY_FILE must be set together"))
	}
	if cfg.CACertFile != "" && encryptionKey == "" {
		errs = append(errs, errors.New("CA_ENCRYPTION_KEY is required with CA_CERT_FILE"))
	}
	validity, err := parseDays("CERT_VALIDITY_DAYS", validityDays, defaultCertValidityDays, maxCertValidityDays)
	if err != nil {
		errs = append(errs, err)
	}
	cfg.CertValidity = validity
	crlValidity, err := parseDays("CERT_CRL_VALIDITY_DAYS", crlValidityDays, defaultCRLValidityDays, maxCRLValidityDays)
	if err != nil {
		errs = append(errs, err)
	}
	cfg.CertCRLValidity = crlValidity
	if cfg.CertCRLURL != "" {
		u, err := url.Parse(cfg.CertCRLURL)
		if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
			errs = append(errs, errors.New("CERT_CRL_URL must be an absolute http or https URL"))
		}
	}
	return errs
}

// parseSMTP validates the SMTP settings and sets SMTPPort from port
// (SMTP_PORT), defaulting SMTPTLS to starttls. Without SMTPHost, email is
// disabled and the other settings are ignored.
func (cfg *Config) parseSMTP(port string) []error {
	if cfg.SMTPHost == "" {
		cfg.SMTPTLS = ""
		return nil
	}
	var errs []error
	if cfg.SMTPTLS == "" {
		cfg.SMTPTLS = "starttls"
	}
	cfg.SMTPPort = defaultSMTPPorts[cfg.SMTPTLS]
	if cfg.SMTPPort == 0 {
		errs = append(errs, errors.New(`SMTP_TLS must be "starttls", "tls" or "none"`))
	}
	if port = strings.TrimSpace(port); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			errs = append(errs, errors.New("SMTP_PORT must be a port number between 1 and 65535"))
		}
		cfg.SMTPPort = n
	}
	if cfg.SMTPFrom == "" {
		errs = append(errs, errors.New("SMTP_FROM is required with SMTP_HOST"))
	}
	return errs
}

// parseDays parses the number of days in the variable name, between 1 and
// maxDays; empty means defaultDays.
func parseDays(name, v string, defaultDays, maxDays int) (time.Duration, error) {
	days, err := parseCount(name, "days", v, defaultDays, maxDays)
	if err != nil {
		return 0, err
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

// parseCount parses the number of units in the variable name, between 1 and
// maxCount; empty means defaultCount.
func parseCount(name, unit, v string, defaultCount, maxCount int) (int, error) {
	if v = strings.TrimSpace(v); v == "" {
		return defaultCount, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > maxCount {
		return 0, fmt.Errorf("%s must be a number of %s between 1 and %d", name, unit, maxCount)
	}
	return n, nil
}

// splitList splits a comma-separated value, dropping empty entries.
func splitList(v string) []string {
	items := []string{}
	for item := range strings.SplitSeq(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}
