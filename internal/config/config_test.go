package config_test

import (
	"maps"
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

func TestFromEnv_certificates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		overrides    map[string]string
		wantValidity time.Duration
		wantErr      bool
	}{
		{name: "disabled", wantValidity: 365 * 24 * time.Hour},
		{
			name:         "enabled",
			overrides:    map[string]string{"CA_CERT_FILE": "ca.crt", "CA_KEY_FILE": "ca.key", "CERT_VALIDITY_DAYS": "30", "CERT_CRL_URL": "https://am.example.com/pki/crl"},
			wantValidity: 30 * 24 * time.Hour,
		},
		{name: "cert without key", overrides: map[string]string{"CA_CERT_FILE": "ca.crt"}, wantErr: true},
		{name: "key without cert", overrides: map[string]string{"CA_KEY_FILE": "ca.key"}, wantErr: true},
		{name: "zero validity", overrides: map[string]string{"CERT_VALIDITY_DAYS": "0"}, wantErr: true},
		{name: "validity too long", overrides: map[string]string{"CERT_VALIDITY_DAYS": "3651"}, wantErr: true},
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
		})
	}
}
