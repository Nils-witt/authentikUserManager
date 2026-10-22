// Package mail delivers notifications by email through an SMTP server.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"authentikManager/internal/notification"
)

// TLSMode tells how the connection to the SMTP server is secured.
type TLSMode string

// The TLS modes.
const (
	// TLSStartTLS upgrades a plain connection with STARTTLS, which the server must offer.
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit connects with TLS right away (SMTPS), usually on port 465.
	TLSImplicit TLSMode = "tls"
	// TLSNone sends in plain text. It is only allowed for a server on the loopback interface.
	TLSNone TLSMode = "none"
)

// Valid reports whether m is one of the TLS modes.
func (m TLSMode) Valid() bool {
	switch m {
	case TLSStartTLS, TLSImplicit, TLSNone:
		return true
	}
	return false
}

// Config configures the SMTP server.
type Config struct {
	Host string
	Port int
	// Username and Password authenticate with PLAIN when Username is set.
	Username string
	Password string
	// From is the sender address, optionally with a display name.
	From string
	TLS  TLSMode
}

// Channel is the notification channel of email.
const Channel notification.Channel = "email"

// SMTP sends notifications by email. It is safe for concurrent use.
type SMTP struct {
	cfg  Config
	from *mail.Address
	// now returns the current time, for the Date header.
	now func() time.Time
}

var _ notification.NotificationReceiver = (*SMTP)(nil)

// New returns an SMTP receiver for cfg after validating it.
func New(cfg Config) (*SMTP, error) {
	from, err := mail.ParseAddress(cfg.From)
	switch {
	case cfg.Host == "":
		return nil, errors.New("mail: host is required")
	case cfg.Port < 1 || cfg.Port > 65535:
		return nil, fmt.Errorf("mail: invalid port %d", cfg.Port)
	case !cfg.TLS.Valid():
		return nil, fmt.Errorf("mail: invalid tls mode %q", cfg.TLS)
	case cfg.TLS == TLSNone && !isLoopback(cfg.Host):
		return nil, errors.New("mail: tls mode none is only allowed for a server on localhost")
	case err != nil:
		return nil, fmt.Errorf("mail: invalid from address: %w", err)
	}
	return &SMTP{cfg: cfg, from: from, now: time.Now}, nil
}

// isLoopback reports whether host names the loopback interface.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Name returns Channel.
func (*SMTP) Name() notification.Channel { return Channel }

// Label returns the name of the channel shown to users.
func (*SMTP) Label() string { return "Email" }

// Receive emails n to the address of rcpt, with the header as the subject.
// It returns notification.ErrNoAddress when rcpt has no email address.
func (s *SMTP) Receive(ctx context.Context, rcpt notification.Recipient, n notification.Notification) error {
	if rcpt.Email == "" {
		return notification.ErrNoAddress
	}
	to, err := mail.ParseAddress(rcpt.Email)
	if err != nil {
		return fmt.Errorf("mail: invalid recipient address: %w", err)
	}
	msg, err := s.message(to, n)
	if err != nil {
		return err
	}
	return s.send(ctx, to.Address, msg)
}

// footer ends every email, telling the recipient where the email comes from.
const footer = "\n\n-- \nThis notification was sent by authentik Manager. " +
	"You can choose which notifications you receive in its notification settings."

// message returns the RFC 5322 message of n to to.
func (s *SMTP) message(to *mail.Address, n notification.Notification) ([]byte, error) {
	subject := strings.Join(strings.Fields(n.Header), " ")
	var buf bytes.Buffer
	headers := []struct{ name, value string }{
		{"From", s.from.String()},
		{"To", to.String()},
		{"Subject", mime.QEncoding.Encode("utf-8", subject)},
		{"Date", s.now().Format(time.RFC1123Z)},
		{"Message-ID", "<" + rand.Text() + "@" + domain(s.from.Address) + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
		// Tells mail servers not to answer with out-of-office replies.
		{"Auto-Submitted", "auto-generated"},
	}
	for _, h := range headers {
		// security: every value is encoded or parsed above; refuse line breaks anyway (header injection).
		if strings.ContainsAny(h.value, "\r\n") {
			return nil, fmt.Errorf("mail: line break in %s header", h.name)
		}
		buf.WriteString(h.name + ": " + h.value + "\r\n")
	}
	buf.WriteString("\r\n")

	body := strings.ReplaceAll(n.Message+footer, "\r\n", "\n")
	w := quotedprintable.NewWriter(&buf)
	if _, err := w.Write([]byte(body)); err != nil {
		return nil, fmt.Errorf("mail: encoding body: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("mail: encoding body: %w", err)
	}
	return buf.Bytes(), nil
}

// domain returns the domain of an email address.
func domain(address string) string {
	if _, d, ok := strings.Cut(address, "@"); ok && d != "" {
		return d
	}
	return "localhost"
}

// send delivers msg to the address to through the SMTP server.
func (s *SMTP) send(ctx context.Context, to string, msg []byte) error {
	conn, err := s.dial(ctx)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mail: greeting from %s: %w", s.cfg.Host, err)
	}
	defer c.Close() //nolint:errcheck // Quit below reports the errors that matter; this only frees the connection

	if err := s.secure(c); err != nil {
		return err
	}
	if err := c.Mail(s.from.Address); err != nil {
		return fmt.Errorf("mail: sender rejected: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("mail: recipient rejected: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mail: starting data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("mail: writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: message rejected: %w", err)
	}
	if err := c.Quit(); err != nil {
		return fmt.Errorf("mail: quit: %w", err)
	}
	return nil
}

// tlsConfig returns the TLS configuration verifying the SMTP server.
func (s *SMTP) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}
}

// dial connects to the SMTP server, with TLS right away in TLSImplicit mode.
// The connection's deadline is the deadline of ctx, since net/smtp takes no context.
func (s *SMTP) dial(ctx context.Context) (net.Conn, error) {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("mail: connecting to %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("mail: setting deadline: %w", err)
		}
	}
	if s.cfg.TLS != TLSImplicit {
		return conn, nil
	}
	tlsConn := tls.Client(conn, s.tlsConfig())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mail: tls handshake with %s: %w", addr, err)
	}
	return tlsConn, nil
}

// secure upgrades the connection of c with STARTTLS in TLSStartTLS mode and
// authenticates when a username is configured.
func (s *SMTP) secure(c *smtp.Client) error {
	if s.cfg.TLS == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("mail: %s does not offer STARTTLS", s.cfg.Host)
		}
		if err := c.StartTLS(s.tlsConfig()); err != nil {
			return fmt.Errorf("mail: starttls with %s: %w", s.cfg.Host, err)
		}
	}
	if s.cfg.Username == "" {
		return nil
	}
	// PlainAuth refuses to send the password over an unencrypted connection to another host.
	if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
		return fmt.Errorf("mail: authenticating with %s: %w", s.cfg.Host, err)
	}
	return nil
}
