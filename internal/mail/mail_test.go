package mail

import (
	"bufio"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	"authentikManager/internal/notification"
)

func TestNew(t *testing.T) {
	t.Parallel()
	valid := Config{Host: "smtp.example.com", Port: 587, From: "Manager <noreply@example.com>", TLS: TLSStartTLS}
	tests := []struct {
		name      string
		change    func(*Config)
		expectErr bool
	}{
		{name: "valid", change: func(*Config) {}},
		{name: "missing host", change: func(c *Config) { c.Host = "" }, expectErr: true},
		{name: "invalid port", change: func(c *Config) { c.Port = 0 }, expectErr: true},
		{name: "invalid tls mode", change: func(c *Config) { c.TLS = "ssl" }, expectErr: true},
		{name: "plain text to remote host", change: func(c *Config) { c.TLS = TLSNone }, expectErr: true},
		{name: "plain text to localhost", change: func(c *Config) { c.TLS, c.Host = TLSNone, "localhost" }},
		{name: "plain text to loopback ip", change: func(c *Config) { c.TLS, c.Host = TLSNone, "::1" }},
		{name: "invalid from", change: func(c *Config) { c.From = "not an address" }, expectErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tt.change(&cfg)
			if _, err := New(cfg); (err != nil) != tt.expectErr {
				t.Errorf("New error = %v, want error %v", err, tt.expectErr)
			}
		})
	}
}

func newTestSMTP(t *testing.T, host string, port int) *SMTP {
	t.Helper()
	s, err := New(Config{Host: host, Port: port, From: "Manager <noreply@example.com>", TLS: TLSNone})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC) }
	return s
}

func TestSMTP_message(t *testing.T) {
	t.Parallel()
	s := newTestSMTP(t, "localhost", 25)
	to := &netmail.Address{Address: "ann@example.com"}
	n := notification.Notification{Header: "Zertifikat\r\nBcc: evil@example.com widerrufen", Message: "Zeile 1\nZeile 2 – ä"}

	raw, err := s.message(to, n)
	if err != nil {
		t.Fatalf("message: %v", err)
	}
	msg, err := netmail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got := msg.Header.Get("Bcc"); got != "" {
		t.Errorf("Bcc header = %q, want none (header injection)", got)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Zertifikat Bcc: evil@example.com widerrufen" {
		t.Errorf("Subject = %q", subject)
	}
	if got := msg.Header.Get("To"); got != "<ann@example.com>" {
		t.Errorf("To = %q", got)
	}
	if got := msg.Header.Get("Message-Id"); !strings.HasSuffix(got, "@example.com>") {
		t.Errorf("Message-ID = %q, want the sender's domain", got)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "Zeile 1\r\nZeile 2 – ä\r\n") {
		t.Errorf("body = %q, want the message with CRLF line breaks", body)
	}
	if !strings.Contains(string(body), "notification settings") {
		t.Errorf("body = %q, want the footer", body)
	}
}

func TestSMTP_Receive_noAddress(t *testing.T) {
	t.Parallel()
	s := newTestSMTP(t, "localhost", 25)
	err := s.Receive(t.Context(), notification.Recipient{UserPK: 1}, notification.Notification{Header: "h", Message: "m"})
	if !errors.Is(err, notification.ErrNoAddress) {
		t.Errorf("Receive = %v, want ErrNoAddress", err)
	}
}

func TestSMTP_Receive(t *testing.T) {
	t.Parallel()
	srv := startFakeSMTP(t)
	s := newTestSMTP(t, "127.0.0.1", srv.port)

	rcpt := notification.Recipient{UserPK: 1, Email: "ann@example.com"}
	if err := s.Receive(t.Context(), rcpt, notification.Notification{Header: "Hello", Message: "World"}); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	srv.wait()
	if srv.from != "<noreply@example.com>" || srv.to != "<ann@example.com>" {
		t.Errorf("envelope = %q -> %q", srv.from, srv.to)
	}
	if !strings.Contains(srv.data, "Subject: Hello\r\n") || !strings.Contains(srv.data, "World") {
		t.Errorf("data = %q", srv.data)
	}
}

// fakeSMTP is a minimal SMTP server accepting one message on the loopback interface.
type fakeSMTP struct {
	port     int
	done     sync.WaitGroup
	from, to string
	data     string
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %v is not TCP", ln.Addr())
	}
	srv := &fakeSMTP{port: tcpAddr.Port}
	srv.done.Go(func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		srv.serve(conn)
	})
	return srv
}

func (f *fakeSMTP) wait() { f.done.Wait() }

func (f *fakeSMTP) serve(conn net.Conn) {
	r := bufio.NewReader(conn)
	reply := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch upper := strings.ToUpper(cmd); {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			reply("250 fake")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			f.from = cmd[len("MAIL FROM:"):]
			reply("250 ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			f.to = cmd[len("RCPT TO:"):]
			reply("250 ok")
		case upper == "DATA":
			reply("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.data = b.String()
			reply("250 queued")
		case upper == "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unknown")
		}
	}
}
