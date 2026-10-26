package config_test

import (
	"encoding/base64"
	"maps"
	"strings"
	"testing"
	"time"

	"authentikManager/internal/config"
)

// validEnv returns a complete configuration with overrides applied
// (an empty override value removes the variable).
func validEnv(overrides map[string]string) map[string]string {
	env := map[string]string{
		"AUTHENTIK_URL":       "https://sso.example.com",
		"AUTHENTIK_TOKEN":     "t",
		"OIDC_ISSUER":         "https://sso.example.com/application/o/am/",
		"OIDC_CLIENT_ID":      "id",
		"OIDC_CLIENT_SECRET":  "secret",
		"OIDC_REDIRECT_URL":   "https://am.example.com/auth/callback",
		"DATABASE_URL":        "postgres://am@localhost/am",
		"ACCESS_ADMIN_GROUPS": "admins",
	}
	maps.Copy(env, overrides)
	return env
}

func TestFromEnv(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		env        map[string]string
		wantErr    bool
		wantListen string
	}{
		{name: "defaults listen addr", env: validEnv(nil), wantListen: "127.0.0.1:8080"},
		{name: "custom listen addr", env: validEnv(map[string]string{"LISTEN_ADDR": ":9000"}), wantListen: ":9000"},
		{name: "missing token", env: validEnv(map[string]string{"AUTHENTIK_TOKEN": ""}), wantErr: true},
		{name: "missing oidc client secret", env: validEnv(map[string]string{"OIDC_CLIENT_SECRET": ""}), wantErr: true},
		{name: "missing static dir", env: validEnv(map[string]string{"STATIC_DIR": "/does/not/exist"}), wantErr: true},
		{name: "missing database url", env: validEnv(map[string]string{"DATABASE_URL": ""}), wantErr: true},
		{name: "blank admin groups", env: validEnv(map[string]string{"ACCESS_ADMIN_GROUPS": " , "}), wantErr: true},
		{name: "trusted proxies", env: validEnv(map[string]string{"TRUSTED_PROXIES": "10.0.0.0/8, ::1"}), wantListen: "127.0.0.1:8080"},
		{name: "invalid trusted proxy", env: validEnv(map[string]string{"TRUSTED_PROXIES": "proxy.local"}), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.FromEnv(func(k string) string { return tt.env[k] })
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromEnv error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if cfg.ListenAddr != tt.wantListen {
				t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, tt.wantListen)
			}
		})
	}
}

func TestFromEnv_auditRetention(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value    string
		expected time.Duration
		wantErr  bool
	}{
		{value: "", expected: 0},
		{value: " 90 ", expected: 90 * 24 * time.Hour},
		{value: "36500", expected: 36500 * 24 * time.Hour},
		{value: "0", wantErr: true},
		{value: "-1", wantErr: true},
		{value: "36501", wantErr: true},
		{value: "30d", wantErr: true},
	}
	for _, tt := range tests {
		t.Run("value "+tt.value, func(t *testing.T) {
			t.Parallel()
			env := validEnv(map[string]string{"AUDIT_RETENTION_DAYS": tt.value})
			cfg, err := config.FromEnv(func(k string) string { return env[k] })
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromEnv error = %v, wantErr %v", err, tt.wantErr)
			}
			if cfg.AuditRetention != tt.expected {
				t.Errorf("AuditRetention = %v, want %v", cfg.AuditRetention, tt.expected)
			}
		})
	}
}

func TestFromEnv_certificateCNSuffixes(t *testing.T) {
	t.Parallel()
	env := validEnv(map[string]string{
		"CERT_USER_CN_SUFFIX":            " @example.com ",
		"CERT_SERVICE_ACCOUNT_CN_SUFFIX": "@svc.example.com",
	})
	cfg, err := config.FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CertUserCNSuffix != "@example.com" || cfg.CertServiceAccountCNSuffix != "@svc.example.com" {
		t.Errorf("suffixes = %q and %q, want @example.com and @svc.example.com",
			cfg.CertUserCNSuffix, cfg.CertServiceAccountCNSuffix)
	}
}

// testEncryptionKey is a valid CA_ENCRYPTION_KEY.
var testEncryptionKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))

func TestFromEnv_certificates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		overrides    map[string]string
		wantValidity time.Duration
		wantCRL      time.Duration
		wantKey      bool
		wantErr      bool
	}{
		{name: "disabled", wantValidity: 365 * 24 * time.Hour, wantCRL: 30 * 24 * time.Hour},
		{
			name:         "enabled without a ca file",
			overrides:    map[string]string{"CA_ENCRYPTION_KEY": testEncryptionKey},
			wantValidity: 365 * 24 * time.Hour,
			wantCRL:      30 * 24 * time.Hour,
			wantKey:      true,
		},
		{
			name: "enabled with a ca file",
			overrides: map[string]string{
				"CA_ENCRYPTION_KEY": testEncryptionKey, "CA_CERT_FILE": "ca.crt", "CA_KEY_FILE": "ca.key",
				"CERT_VALIDITY_DAYS": "30", "CERT_CRL_URL": "https://am.example.com/pki/crl", "CERT_CRL_VALIDITY_DAYS": "7",
			},
			wantValidity: 30 * 24 * time.Hour,
			wantCRL:      7 * 24 * time.Hour,
			wantKey:      true,
		},
		{name: "ca file without encryption key", overrides: map[string]string{"CA_CERT_FILE": "ca.crt", "CA_KEY_FILE": "ca.key"}, wantErr: true},
		{name: "short encryption key", overrides: map[string]string{"CA_ENCRYPTION_KEY": base64.StdEncoding.EncodeToString([]byte("short"))}, wantErr: true},
		{name: "encryption key not base64", overrides: map[string]string{"CA_ENCRYPTION_KEY": "not base64!"}, wantErr: true},
		{name: "cert without key", overrides: map[string]string{"CA_ENCRYPTION_KEY": testEncryptionKey, "CA_CERT_FILE": "ca.crt"}, wantErr: true},
		{name: "key without cert", overrides: map[string]string{"CA_ENCRYPTION_KEY": testEncryptionKey, "CA_KEY_FILE": "ca.key"}, wantErr: true},
		{name: "zero validity", overrides: map[string]string{"CERT_VALIDITY_DAYS": "0"}, wantErr: true},
		{name: "validity too long", overrides: map[string]string{"CERT_VALIDITY_DAYS": "3651"}, wantErr: true},
		{name: "zero crl validity", overrides: map[string]string{"CERT_CRL_VALIDITY_DAYS": "0"}, wantErr: true},
		{name: "crl validity too long", overrides: map[string]string{"CERT_CRL_VALIDITY_DAYS": "366"}, wantErr: true},
		{name: "relative crl url", overrides: map[string]string{"CERT_CRL_URL": "/pki/crl"}, wantErr: true},
		{name: "ldap crl url", overrides: map[string]string{"CERT_CRL_URL": "ldap://example.com/crl"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := validEnv(tt.overrides)
			cfg, err := config.FromEnv(func(k string) string { return env[k] })
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromEnv error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && cfg.CertValidity != tt.wantValidity {
				t.Errorf("CertValidity = %v, want %v", cfg.CertValidity, tt.wantValidity)
			}
			if !tt.wantErr && cfg.CertCRLValidity != tt.wantCRL {
				t.Errorf("CertCRLValidity = %v, want %v", cfg.CertCRLValidity, tt.wantCRL)
			}
			if !tt.wantErr && (len(cfg.CAEncryptionKey) == 32) != tt.wantKey {
				t.Errorf("CAEncryptionKey has %d bytes, want key %v", len(cfg.CAEncryptionKey), tt.wantKey)
			}
		})
	}
}

func TestFromEnv_smtp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		env          map[string]string
		expectErr    bool
		expectedPort int
		expectedTLS  string
	}{
		{name: "disabled", env: validEnv(nil)},
		{name: "disabled ignores other settings", env: validEnv(map[string]string{"SMTP_TLS": "bogus", "SMTP_PORT": "x"})},
		{
			name:         "starttls by default",
			env:          validEnv(map[string]string{"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "noreply@example.com"}),
			expectedPort: 587, expectedTLS: "starttls",
		},
		{
			name:         "implicit tls port",
			env:          validEnv(map[string]string{"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "noreply@example.com", "SMTP_TLS": "TLS"}),
			expectedPort: 465, expectedTLS: "tls",
		},
		{
			name: "explicit port",
			env: validEnv(map[string]string{
				"SMTP_HOST": "localhost", "SMTP_FROM": "noreply@example.com", "SMTP_TLS": "none", "SMTP_PORT": "1025",
			}),
			expectedPort: 1025, expectedTLS: "none",
		},
		{name: "missing from", env: validEnv(map[string]string{"SMTP_HOST": "smtp.example.com"}), expectErr: true},
		{
			name:      "invalid tls",
			env:       validEnv(map[string]string{"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "a@example.com", "SMTP_TLS": "ssl"}),
			expectErr: true,
		},
		{
			name:      "invalid port",
			env:       validEnv(map[string]string{"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "a@example.com", "SMTP_PORT": "70000"}),
			expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.FromEnv(func(k string) string { return tt.env[k] })
			if (err != nil) != tt.expectErr {
				t.Fatalf("FromEnv error = %v, want error %v", err, tt.expectErr)
			}
			if err != nil {
				return
			}
			if cfg.SMTPPort != tt.expectedPort || cfg.SMTPTLS != tt.expectedTLS {
				t.Errorf("SMTP port, tls = %d, %q, want %d, %q", cfg.SMTPPort, cfg.SMTPTLS, tt.expectedPort, tt.expectedTLS)
			}
		})
	}
}

func TestFromEnv_sessions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		env          map[string]string
		wantErr      bool
		wantLifetime time.Duration
		wantIdle     time.Duration
	}{
		{name: "defaults", env: validEnv(nil), wantLifetime: 8 * time.Hour, wantIdle: 30 * time.Minute},
		{
			name:         "custom",
			env:          validEnv(map[string]string{"SESSION_LIFETIME_HOURS": "12", "SESSION_IDLE_TIMEOUT_MINUTES": " 15 "}),
			wantLifetime: 12 * time.Hour,
			wantIdle:     15 * time.Minute,
		},
		{
			name:         "idle timeout capped by lifetime",
			env:          validEnv(map[string]string{"SESSION_LIFETIME_HOURS": "1", "SESSION_IDLE_TIMEOUT_MINUTES": "120"}),
			wantLifetime: time.Hour,
			wantIdle:     time.Hour,
		},
		{name: "zero lifetime", env: validEnv(map[string]string{"SESSION_LIFETIME_HOURS": "0"}), wantErr: true},
		{name: "lifetime too long", env: validEnv(map[string]string{"SESSION_LIFETIME_HOURS": "169"}), wantErr: true},
		{name: "idle timeout not a number", env: validEnv(map[string]string{"SESSION_IDLE_TIMEOUT_MINUTES": "1h"}), wantErr: true},
		{name: "idle timeout too long", env: validEnv(map[string]string{"SESSION_IDLE_TIMEOUT_MINUTES": "1441"}), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.FromEnv(func(k string) string { return tt.env[k] })
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromEnv error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if cfg.SessionLifetime != tt.wantLifetime || cfg.SessionIdleTimeout != tt.wantIdle {
				t.Errorf("SessionLifetime = %v, SessionIdleTimeout = %v, want %v and %v",
					cfg.SessionLifetime, cfg.SessionIdleTimeout, tt.wantLifetime, tt.wantIdle)
			}
		})
	}
}

func TestFromEnv_reauth(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		env        map[string]string
		wantErr    bool
		wantMaxAge time.Duration
	}{
		{name: "defaults", env: validEnv(nil), wantMaxAge: 15 * time.Minute},
		{name: "disabled", env: validEnv(map[string]string{"REAUTH_MAX_AGE_MINUTES": "0"}), wantMaxAge: 0},
		{name: "custom", env: validEnv(map[string]string{"REAUTH_MAX_AGE_MINUTES": "5"}), wantMaxAge: 5 * time.Minute},
		{name: "negative", env: validEnv(map[string]string{"REAUTH_MAX_AGE_MINUTES": "-1"}), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.FromEnv(func(k string) string { return tt.env[k] })
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromEnv error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if cfg.ReauthMaxAge != tt.wantMaxAge {
				t.Errorf("ReauthMaxAge = %v, want %v", cfg.ReauthMaxAge, tt.wantMaxAge)
			}
		})
	}
}
