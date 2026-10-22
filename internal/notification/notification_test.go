package notification_test

import (
	"strings"
	"testing"

	"authentikManager/internal/notification"
)

func TestCategory_Valid(t *testing.T) {
	t.Parallel()
	for _, c := range notification.Categories {
		if !c.Valid() {
			t.Errorf("%q.Valid() = false, want true", c)
		}
	}
	for _, c := range []notification.Category{"", "PROFILE", "audit"} {
		if c.Valid() {
			t.Errorf("%q.Valid() = true, want false", c)
		}
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		category       notification.Category
		header         string
		message        string
		expectedHeader string
		expectErr      bool
	}{
		{name: "trimmed", category: notification.CategoryProfile, header: " Hi ", message: " body ", expectedHeader: "Hi"},
		{name: "unknown category", category: "other", header: "Hi", message: "body", expectErr: true},
		{name: "empty header", category: notification.CategoryProfile, header: "  ", message: "body", expectErr: true},
		{name: "empty message", category: notification.CategoryProfile, header: "Hi", message: "", expectErr: true},
		{
			name: "header too long", category: notification.CategoryProfile,
			header: strings.Repeat("ä", notification.MaxHeaderLen+1), message: "body", expectErr: true,
		},
		{
			name: "longest header", category: notification.CategoryProfile,
			header: strings.Repeat("ä", notification.MaxHeaderLen), message: "body",
			expectedHeader: strings.Repeat("ä", notification.MaxHeaderLen),
		},
		{
			name: "message too long", category: notification.CategoryProfile,
			header: "Hi", message: strings.Repeat("x", notification.MaxMessageLen+1), expectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n, err := notification.New(tt.category, tt.header, tt.message)
			if (err != nil) != tt.expectErr {
				t.Fatalf("New error = %v, want error %v", err, tt.expectErr)
			}
			if err == nil && n.Header != tt.expectedHeader {
				t.Errorf("Header = %q, want %q", n.Header, tt.expectedHeader)
			}
		})
	}
}

func TestPreferences_Enabled(t *testing.T) {
	t.Parallel()
	p := notification.Preferences{
		notification.CategoryProfile:  {"email": false},
		notification.CategorySettings: {"email": false},
	}
	tests := []struct {
		name     string
		category notification.Category
		channel  notification.Channel
		expected bool
	}{
		{name: "disabled", category: notification.CategoryProfile, channel: "email", expected: false},
		{name: "missing channel defaults on", category: notification.CategoryProfile, channel: notification.ChannelInApp, expected: true},
		{name: "missing category defaults on", category: notification.CategoryCertificate, channel: "email", expected: true},
		{name: "mandatory ignores preference", category: notification.CategorySettings, channel: "email", expected: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := p.Enabled(tt.category, tt.channel); got != tt.expected {
				t.Errorf("Enabled(%q, %q) = %v, want %v", tt.category, tt.channel, got, tt.expected)
			}
		})
	}
}

func TestPreferences_Normalize(t *testing.T) {
	t.Parallel()
	channels := []notification.Channel{notification.ChannelInApp, "email"}
	tests := []struct {
		name      string
		input     notification.Preferences
		expectErr bool
	}{
		{name: "empty", input: notification.Preferences{}},
		{name: "known", input: notification.Preferences{notification.CategoryProfile: {"email": false}}},
		{name: "unknown category", input: notification.Preferences{"other": {"email": false}}, expectErr: true},
		{name: "unknown channel", input: notification.Preferences{notification.CategoryProfile: {"sms": false}}, expectErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.input.Normalize(channels)
			if (err != nil) != tt.expectErr {
				t.Fatalf("Normalize error = %v, want error %v", err, tt.expectErr)
			}
			if err != nil {
				return
			}
			if len(got) != len(notification.Categories) {
				t.Fatalf("Normalize = %v, want every category", got)
			}
			for _, cat := range notification.Categories {
				if len(got[cat]) != len(channels) {
					t.Errorf("Normalize[%q] = %v, want every channel", cat, got[cat])
				}
			}
		})
	}

	got, err := notification.Preferences{notification.CategorySettings: {"email": false}}.Normalize(channels)
	if err != nil || !got[notification.CategorySettings]["email"] {
		t.Errorf("Normalize turned off a mandatory category: %v, %v", got, err)
	}
}

func TestQuery_Normalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		input         notification.Query
		expectedLimit int
		expectErr     bool
	}{
		{name: "default limit", input: notification.Query{}, expectedLimit: notification.DefaultLimit},
		{name: "explicit limit", input: notification.Query{Limit: 5}, expectedLimit: 5},
		{name: "limit too high", input: notification.Query{Limit: notification.MaxLimit + 1}, expectErr: true},
		{name: "negative before", input: notification.Query{Before: -1}, expectErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			q, err := tt.input.Normalize()
			if (err != nil) != tt.expectErr {
				t.Fatalf("Normalize error = %v, want error %v", err, tt.expectErr)
			}
			if err == nil && q.Limit != tt.expectedLimit {
				t.Errorf("Limit = %d, want %d", q.Limit, tt.expectedLimit)
			}
		})
	}
}
