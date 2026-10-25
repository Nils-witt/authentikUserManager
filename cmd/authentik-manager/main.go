// Command authentik-manager serves a small REST API and the embedded web
// frontend for managing users in an authentik instance.
//
// Configuration is read from the environment:
//
//	AUTHENTIK_URL    base URL of the authentik instance (required)
//	AUTHENTIK_TOKEN  authentik API token (required)
//	LISTEN_ADDR      listen address (default 127.0.0.1:8080)
//	STATIC_DIR       serve the frontend from this directory instead of the embedded build (optional)
//	TRUSTED_PROXIES  comma-separated IP addresses or CIDR prefixes of reverse proxies whose
//	                 X-Forwarded-For header names the client (optional)
//	AUTHENTIK_RECOVERY_EMAIL_STAGE  UUID of the email stage for password recovery emails;
//	                                sending them is disabled when unset (optional)
//
//	OIDC_ISSUER          issuer URL of the authentik OIDC provider (required)
//	OIDC_CLIENT_ID       OIDC client ID (required)
//	OIDC_CLIENT_SECRET   OIDC client secret (required)
//	OIDC_REDIRECT_URL    public callback URL, ending in /auth/callback (required)
//	SESSION_LIFETIME_HOURS        maximum lifetime of a login session (default 8)
//	SESSION_IDLE_TIMEOUT_MINUTES  ends sessions unused for this long (default 30)
//	REAUTH_MAX_AGE_MINUTES        critical changes require a login this recent (default 15; 0 disables)
//	REQUIRE_MFA                   critical changes require a login with multi-factor authentication
//
//	DATABASE_URL         PostgreSQL URL storing the access rules and the audit log (required)
//	AUDIT_RETENTION_DAYS days to keep audit log entries; they are kept forever when unset (optional)
//	ACCESS_ADMIN_GROUPS  comma-separated authentik groups with full access that may edit
//	                     the access rules (required)
//
//	CA_ENCRYPTION_KEY    32 random bytes, base64-encoded (openssl rand -base64 32), encrypting the
//	                     private keys of the certificate authorities stored in the database;
//	                     certificates are disabled when unset. Access administrators add CAs in the app.
//	CA_CERT_FILE         PEM file of a CA certificate, optionally followed by the certificates above
//	                     it, imported as a CA named "default" unless stored already (optional)
//	CA_KEY_FILE          PEM file of the CA's unencrypted private key (required with CA_CERT_FILE)
//
//	The following settings only apply when CA_CERT_FILE is first imported; access
//	administrators change them in the app afterwards:
//
//	CERT_VALIDITY_DAYS   days user certificates are valid (default 365)
//	CERT_CRL_URL         public URL of this app's /pki/crl, embedded in user certificates (optional)
//	CERT_CRL_VALIDITY_DAYS days each CRL is valid until its next update (default 30)
//	CERT_USER_CN_SUFFIX  appended to the username in the common name of user certificates,
//	                     e.g. @example.com (optional)
//	CERT_SERVICE_ACCOUNT_CN_SUFFIX appended to the username in the common name of service
//	                     account certificates (optional)
//
//	SMTP_HOST            SMTP server emailing notifications; they are shown in the app only when unset (optional)
//	SMTP_PORT            SMTP port (default 587 for starttls, 465 for tls, 25 for none)
//	SMTP_TLS             starttls (default), tls for implicit TLS, or none for a server on localhost
//	SMTP_USERNAME        SMTP username; no authentication when unset (optional)
//	SMTP_PASSWORD        SMTP password (optional)
//	SMTP_FROM            sender address of notification emails, e.g. "Manager <noreply@example.com>"
//	                     (required with SMTP_HOST)
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
	"strings"
	"sync"
	"syscall"
	"time"
	"uuid"

	"authentikManager/internal/access"
	"authentikManager/internal/audit"
	"authentikManager/internal/auth"
	"authentikManager/internal/authentik"
	"authentikManager/internal/authority"
	"authentikManager/internal/clientip"
	"authentikManager/internal/config"
	"authentikManager/internal/mail"
	"authentikManager/internal/notification"
	"authentikManager/internal/pki"
	"authentikManager/internal/reqlog"
	"authentikManager/internal/server"
	"authentikManager/internal/store"
	"authentikManager/internal/web"
)

func main() {
	// Records written for a request carry its ID (see reqlog).
	logger := slog.New(reqlog.NewHandler(slog.NewJSONHandler(os.Stdout, nil)))
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

	cas, err := loadAuthorities(ctx, cfg, db, logger)
	if err != nil {
		return err
	}
	keyDownloads := pki.NewPending(time.Now)
	if cas != nil {
		// Deferred after db.Close like the audit pruning, so it stops before the pool closes.
		pruneCtx, stopPruning := context.WithCancel(ctx)
		var pruning sync.WaitGroup
		defer pruning.Wait()
		defer stopPruning()
		pruning.Go(func() { keyDownloads.Run(pruneCtx, pki.PruneInterval) })
	}

	notifier, err := newNotifier(cfg, db, logger)
	if err != nil {
		return err
	}
	// Deferred after db.Close like the audit pruning, so queued deliveries
	// finish before the pool closes.
	deliverCtx, stopDelivering := context.WithCancel(ctx)
	var delivering sync.WaitGroup
	defer delivering.Wait()
	defer stopDelivering()
	delivering.Go(func() { notifier.Run(deliverCtx) })

	clientIPs, err := clientip.NewResolver(cfg.TrustedProxies)
	if err != nil {
		return err
	}
	authn, err := auth.New(ctx, auth.Config{
		IssuerURL:    cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		SessionTTL:   cfg.SessionLifetime,
		IdleTimeout:  cfg.SessionIdleTimeout,
		CheckAccount: accountChecker(client),
		RecordAudit:  auditRecorder(db, logger),
		ClientIP:     clientIPs.IP,
	}, logger)
	if err != nil {
		return fmt.Errorf("setting up oidc login: %w", err)
	}
	// Deferred after db.Close like the audit pruning; it stops with the server.
	sessionCtx, stopSessions := context.WithCancel(ctx)
	var sessionPruning sync.WaitGroup
	defer sessionPruning.Wait()
	defer stopSessions()
	sessionPruning.Go(func() { authn.Run(sessionCtx, auth.PruneInterval) })

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
			Users:        client,
			Auth:         authn,
			Policy:       policy,
			Rules:        db,
			Audit:        db,
			JoinRequests: db,
			Logger:       logger,
			Static:       static,

			RecoveryEmailStage: cfg.RecoveryEmailStage,
			CAs:                cas,
			Authorities:        db,
			Certificates:       db,
			KeyDownloads:       keyDownloads,
			Notifications:      notifier,
			APIKeys:            db,
			// The public URL tells whether a TLS-terminating proxy serves the app.
			HTTPS:        strings.HasPrefix(cfg.OIDCRedirectURL, "https://"),
			ClientIP:     clientIPs.IP,
			ReauthMaxAge: cfg.ReauthMaxAge,
			RequireMFA:   cfg.RequireMFA,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return serve(ctx, srv, logger)
}

// serve runs srv until it fails or ctx is done, then shuts it down gracefully.
func serve(ctx context.Context, srv *http.Server, logger *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("addr", srv.Addr))
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

// accountChecker returns the auth.AccountChecker reading the groups of
// signed-in users from authentik. Sessions are matched to accounts by
// username, so a session ends when its user is renamed, deleted or deactivated.
func accountChecker(client *authentik.Client) auth.AccountChecker {
	return func(ctx context.Context, u auth.User) ([]string, error) {
		if u.Username == "" {
			return nil, auth.ErrAccountGone
		}
		list, err := client.ListUsers(ctx, authentik.ListUsersParams{Username: u.Username, PageSize: 1})
		if err != nil {
			return nil, fmt.Errorf("looking up user %q: %w", u.Username, err)
		}
		for _, account := range list.Results {
			if account.Username == u.Username && account.IsActive {
				return account.GroupNames(), nil
			}
		}
		return nil, auth.ErrAccountGone
	}
}

// auditRecorder returns the function recording the login events of the
// auth package in the audit log of db and the application log. A failure to
// store an entry is logged, like the server does for its entries.
func auditRecorder(db *store.Store, logger *slog.Logger) func(context.Context, audit.Entry) {
	return func(ctx context.Context, e audit.Entry) {
		logger.LogAttrs(ctx, slog.LevelInfo, "audit",
			slog.String("actor", e.Actor),
			slog.String("action", string(e.Action)),
			slog.String("target", e.Target),
			slog.Any("details", e.Details),
		)
		// Store the entry even when the client has gone away meanwhile.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := db.RecordAudit(ctx, e); err != nil {
			logger.ErrorContext(ctx, "recording audit entry failed", slog.String("action", string(e.Action)), slog.Any("error", err))
		}
	}
}

// newNotifier returns the notifier storing notifications in db and emailing
// them when an SMTP server is configured.
func newNotifier(cfg config.Config, db *store.Store, logger *slog.Logger) (*notification.Notifier, error) {
	var receivers []notification.NotificationReceiver
	if cfg.SMTPHost != "" {
		smtp, err := mail.New(mail.Config{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
			TLS:      mail.TLSMode(cfg.SMTPTLS),
		})
		if err != nil {
			return nil, fmt.Errorf("configuring smtp: %w", err)
		}
		receivers = append(receivers, smtp)
		logger.Info("emailing notifications", slog.String("smtp_host", cfg.SMTPHost), slog.Int("smtp_port", cfg.SMTPPort))
	}
	return notification.NewNotifier(db, logger, receivers...)
}

// legacyCAName is the name of the CA imported from CA_CERT_FILE.
const legacyCAName = "default"

// loadAuthorities returns the registry of the stored CAs, after importing the
// CA of CA_CERT_FILE unless it is stored already, or nil when certificates are
// disabled.
func loadAuthorities(ctx context.Context, cfg config.Config, db *store.Store, logger *slog.Logger) (*authority.Registry, error) {
	if len(cfg.CAEncryptionKey) == 0 {
		return nil, nil
	}
	cipher, err := pki.NewKeyCipher(cfg.CAEncryptionKey)
	if err != nil {
		return nil, err
	}
	cas := authority.NewRegistry(cipher)
	if cfg.CACertFile != "" {
		if err := importCAFile(ctx, cfg, db, cas, logger); err != nil {
			return nil, err
		}
	}
	list, err := db.ListAuthorities(ctx)
	if err != nil {
		return nil, err
	}
	if err := cas.Load(list); err != nil {
		return nil, fmt.Errorf("loading certificate authorities: %w", err)
	}
	logger.Info("loaded certificate authorities", slog.Int("count", len(list)))
	return cas, nil
}

// importCAFile stores the CA of CA_CERT_FILE and CA_KEY_FILE with the CERT_*
// settings, unless its certificate is stored already.
func importCAFile(ctx context.Context, cfg config.Config, db *store.Store, cas *authority.Registry, logger *slog.Logger) error {
	certPEM, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return fmt.Errorf("reading CA_CERT_FILE: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.CAKeyFile)
	if err != nil {
		return fmt.Errorf("reading CA_KEY_FILE: %w", err)
	}
	defer clear(keyPEM)
	settings, err := authority.Settings{
		CRLURL:                 cfg.CertCRLURL,
		ValidityDays:           int(cfg.CertValidity / (24 * time.Hour)),
		CRLValidityDays:        int(cfg.CertCRLValidity / (24 * time.Hour)),
		UserCNSuffix:           cfg.CertUserCNSuffix,
		ServiceAccountCNSuffix: cfg.CertServiceAccountCNSuffix,
	}.Normalize()
	if err != nil {
		return fmt.Errorf("certificate settings: %w", err)
	}
	// The ID is only used when the CA is not stored yet.
	a := authority.Authority{ID: uuid.New(), Name: legacyCAName, Settings: settings, CreatedBy: "CA_CERT_FILE"}
	ca, err := pki.LoadCA(certPEM, keyPEM, a.Options())
	if err != nil {
		return fmt.Errorf("loading certificate authority of CA_CERT_FILE: %w", err)
	}
	a.CertPEM = string(ca.ChainPEM())
	a.Fingerprint = pki.Fingerprint(ca.Certificate())
	if a.KeyCiphertext, err = cas.SealKey(a.ID, keyPEM); err != nil {
		return err
	}
	stored, err := db.ImportLegacyAuthority(ctx, a)
	if errors.Is(err, authority.ErrExists) {
		return fmt.Errorf("importing CA_CERT_FILE: another certificate authority is named %q; "+
			"add the new CA in the app instead and unset CA_CERT_FILE", legacyCAName)
	}
	if err != nil {
		return err
	}
	logger.Info("certificate authority of CA_CERT_FILE is stored",
		slog.String("ca_id", stored.ID.String()), slog.Bool("legacy", stored.Legacy))
	return nil
}
