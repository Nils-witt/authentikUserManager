// Command authentik-manager serves a small REST API and the embedded web
// frontend for managing users in an authentik instance.
//
// Configuration is read from the environment:
//
//	AUTHENTIK_URL    base URL of the authentik instance (required)
//	AUTHENTIK_TOKEN  authentik API token (required)
//	LISTEN_ADDR      listen address (default 127.0.0.1:8080)
//	STATIC_DIR       serve the frontend from this directory instead of the embedded build (optional)
//	AUTHENTIK_RECOVERY_EMAIL_STAGE  UUID of the email stage for password recovery emails;
//	                                sending them is disabled when unset (optional)
//
//	OIDC_ISSUER          issuer URL of the authentik OIDC provider (required)
//	OIDC_CLIENT_ID       OIDC client ID (required)
//	OIDC_CLIENT_SECRET   OIDC client secret (required)
//	OIDC_REDIRECT_URL    public callback URL, ending in /auth/callback (required)
//
//	DATABASE_URL         PostgreSQL URL storing the access rules and the audit log (required)
//	AUDIT_RETENTION_DAYS days to keep audit log entries; they are kept forever when unset (optional)
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
	"sync"
	"syscall"
	"time"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
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

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if cfg.AuditRetention > 0 {
		// Deferred after db.Close, so this stops pruning and waits for it before the pool closes.
		pruneCtx, stopPruning := context.WithCancel(ctx)
		var pruning sync.WaitGroup
		defer pruning.Wait()
		defer stopPruning()
		pruning.Go(func() { audit.Retain(pruneCtx, db, cfg.AuditRetention, audit.PruneInterval, logger) })
	}
	policy, err := access.NewPolicy(cfg.AccessAdminGroups, db)
	if err != nil {
		return err
	}

	authn, err := auth.New(ctx, auth.Config{
		IssuerURL:    cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
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
			Rules:  db,
			Audit:  db,
			Logger: logger,
			Static: static,

			RecoveryEmailStage: cfg.RecoveryEmailStage,
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
