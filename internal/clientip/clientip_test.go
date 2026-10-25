package clientip_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"authentikManager/internal/clientip"
)

func TestResolver_IP(t *testing.T) {
	t.Parallel()
	r, err := clientip.NewResolver([]string{"10.0.0.0/8", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{name: "direct client", remote: "203.0.113.5:4000", want: "203.0.113.5"},
		{name: "untrusted peer ignores header", remote: "203.0.113.5:4000", xff: []string{"198.51.100.1"}, want: "203.0.113.5"},
		{name: "trusted proxy", remote: "10.1.2.3:4000", xff: []string{"198.51.100.1"}, want: "198.51.100.1"},
		{name: "forged entries left of the client", remote: "10.1.2.3:4000", xff: []string{"1.2.3.4, 198.51.100.1"}, want: "198.51.100.1"},
		{name: "chain of trusted proxies", remote: "10.1.2.3:4000", xff: []string{"198.51.100.1, 192.0.2.1", "10.9.9.9"}, want: "198.51.100.1"},
		{name: "trusted proxy without header", remote: "10.1.2.3:4000", want: "10.1.2.3"},
		{name: "malformed entry", remote: "10.1.2.3:4000", xff: []string{"garbage"}, want: "10.1.2.3"},
		{name: "ipv6 client", remote: "10.1.2.3:4000", xff: []string{"2001:db8::1"}, want: "2001:db8::1"},
		{name: "ipv4-mapped peer", remote: "[::ffff:10.1.2.3]:4000", xff: []string{"198.51.100.1"}, want: "198.51.100.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			if got := r.IP(req); got != tt.want {
				t.Errorf("IP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewResolver_invalid(t *testing.T) {
	t.Parallel()
	if _, err := clientip.NewResolver([]string{"proxy.example.com"}); err == nil {
		t.Error("NewResolver accepted a host name")
	}
}
