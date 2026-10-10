package config_test

import (
	"maps"
	"slices"
	"testing"

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
		"OIDC_ALLOWED_GROUPS": "admins, helpdesk ,",
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
		{name: "blank allowed groups", env: validEnv(map[string]string{"OIDC_ALLOWED_GROUPS": " , "}), wantErr: true},
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
			if !slices.Equal(cfg.OIDCAllowedGroups, []string{"admins", "helpdesk"}) {
				t.Errorf("OIDCAllowedGroups = %q, want [admins helpdesk]", cfg.OIDCAllowedGroups)
			}
		})
	}
}
