// Package config loads the application configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
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

	// OIDCIssuer is the issuer URL of the authentik OAuth2/OIDC provider,
	// e.g. https://sso.example.com/application/o/authentik-manager/.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	// OIDCRedirectURL is this app's public callback URL, ending in /auth/callback.
	OIDCRedirectURL string
	// OIDCAllowedGroups lists the authentik groups whose members may log in.
	OIDCAllowedGroups []string

	// DatabaseURL is the PostgreSQL connection URL that stores the access rules.
	DatabaseURL string
	// AccessAdminGroups lists the groups whose members have full access and may
	// edit the access rules.
	AccessAdminGroups []string
}

const defaultListenAddr = "127.0.0.1:8080"

// FromEnv reads the configuration from the environment, using getenv
// (normally os.Getenv) so it can be tested without touching the process env.
func FromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		AuthentikURL:   getenv("AUTHENTIK_URL"),
		AuthentikToken: getenv("AUTHENTIK_TOKEN"),
		ListenAddr:     getenv("LISTEN_ADDR"),
		StaticDir:      getenv("STATIC_DIR"),

		OIDCIssuer:        getenv("OIDC_ISSUER"),
		OIDCClientID:      getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:  getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:   getenv("OIDC_REDIRECT_URL"),
		OIDCAllowedGroups: splitList(getenv("OIDC_ALLOWED_GROUPS")),

		DatabaseURL:       getenv("DATABASE_URL"),
		AccessAdminGroups: splitList(getenv("ACCESS_ADMIN_GROUPS")),
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
	if len(cfg.OIDCAllowedGroups) == 0 {
		errs = append(errs, errors.New("OIDC_ALLOWED_GROUPS is required (comma-separated authentik group names)"))
	}
	if len(cfg.AccessAdminGroups) == 0 {
		errs = append(errs, errors.New("ACCESS_ADMIN_GROUPS is required (comma-separated authentik group names)"))
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
