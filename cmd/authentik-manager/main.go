// Command authentik-manager serves a small REST API and the embedded web
// frontend for managing users in an authentik instance.
//
// Configuration is read from the environment:
//
//	AUTHENTIK_URL    base URL of the authentik instance (required)
//	AUTHENTIK_TOKEN  authentik API token (required)
//	LISTEN_ADDR      listen address (default 127.0.0.1:8080)
//	STATIC_DIR       serve the frontend from this directory instead of the embedded build (optional)
//
//	OIDC_ISSUER          issuer URL of the authentik OIDC provider (required)
//	OIDC_CLIENT_ID       OIDC client ID (required)
//	OIDC_CLIENT_SECRET   OIDC client secret (required)
//	OIDC_REDIRECT_URL    public callback URL, ending in /auth/callback (required)
//	OIDC_ALLOWED_GROUPS  comma-separated authentik groups allowed to log in (required)
//
//	DATABASE_URL         PostgreSQL URL storing the access rules (required)
//	ACCESS_ADMIN_GROUPS  comma-separated authentik groups with full access that may edit
//	                     the access rules (required)
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"authentikManager/internal/access"
	"authentikManager/internal/auth"
	"authentikManager/internal/authentik"
	"authentikManager/internal/config"
	"authentikManager/internal/server"
	"authentikManager/internal/store"
	"authentikManager/internal/web"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}

	client, err := authentik.New(cfg.AuthentikURL, cfg.AuthentikToken)
	if err != nil {
		return fmt.Errorf("creating authentik client: %w", err)
	}

	rules, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer rules.Close()
	policy, err := access.NewPolicy(cfg.AccessAdminGroups, rules)
	if err != nil {
		return err
	}

	authn, err := auth.New(ctx, auth.Config{
		IssuerURL:     cfg.OIDCIssuer,
		ClientID:      cfg.OIDCClientID,
		ClientSecret:  cfg.OIDCClientSecret,
		RedirectURL:   cfg.OIDCRedirectURL,
		AllowedGroups: cfg.OIDCAllowedGroups,
	}, logger)
	if err != nil {
		return fmt.Errorf("setting up oidc login: %w", err)
	}

	var static fs.FS
	if cfg.StaticDir != "" {
		static, err = server.OpenStatic(cfg.StaticDir)
	} else {
		static, err = web.Dist()
	}
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr: cfg.ListenAddr,
		Handler: server.New(server.Deps{
			Users:  client,
			Auth:   authn,
			Policy: policy,
			Rules:  rules,
			Logger: logger,
			Static: static,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("addr", cfg.ListenAddr))
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serving http: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down http server: %w", err)
	}
	return nil
}
