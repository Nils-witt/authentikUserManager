package authentik_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"authentikManager/internal/authentik"
)

func TestTokenIntent_Valid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		intent   authentik.TokenIntent
		expected bool
	}{
		{intent: authentik.TokenIntentAPI, expected: true},
		{intent: authentik.TokenIntentAppPassword, expected: true},
		{intent: "recovery", expected: false},
		{intent: "verification", expected: false},
		{intent: "", expected: false},
	}
	for _, tt := range tests {
		if got := tt.intent.Valid(); got != tt.expected {
			t.Errorf("TokenIntent(%q).Valid() = %v, want %v", tt.intent, got, tt.expected)
		}
	}
}

func TestClient_ListTokens(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/core/tokens/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("user__username"); got != "svc" {
			t.Errorf("user__username = %q", got)
		}
		// The second token belongs to another user, as if the filter were ignored.
		_, _ = io.WriteString(w, `{"pagination":{"count":2},"results":[
			{"identifier":"a","intent":"api","user":7,"expiring":false,"expires":null,"managed":null},
			{"identifier":"b","intent":"api","user":8,"expiring":true,"expires":"2030-01-01T00:00:00Z","managed":"goauthentik.io/outpost"}]}`)
	})

	got, err := c.ListTokens(t.Context(), 7, "svc")
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(got) != 1 || got[0].Identifier != "a" || got[0].IsManaged() {
		t.Errorf("ListTokens = %+v", got)
	}
}

func TestClient_ListTokens_empty(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"pagination":{"count":0},"results":null}`)
	})

	got, err := c.ListTokens(t.Context(), 7, "svc")
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("ListTokens = %#v, want an empty slice", got)
	}
}

func TestClient_CreateToken(t *testing.T) {
	t.Parallel()
	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/core/tokens/" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decoding body: %v", err)
		}
		if body["identifier"] != "am-1" || body["intent"] != "api" || body["user"] != float64(7) ||
			body["expiring"] != true || body["expires"] != "2030-01-01T00:00:00Z" {
			t.Errorf("body = %v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"identifier":"am-1","intent":"api","user":7,"expiring":true,"expires":"2030-01-01T00:00:00Z"}`)
	})

	got, err := c.CreateToken(t.Context(), authentik.CreateTokenRequest{
		Identifier: "am-1",
		Intent:     authentik.TokenIntentAPI,
		UserPK:     7,
		Expiring:   true,
		Expires:    &expires,
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if got.UserPK != 7 || got.Expires == nil || !got.Expires.Equal(expires) {
		t.Errorf("CreateToken = %+v", got)
	}
}

func TestClient_TokenKey(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/core/tokens/am-1/view_key/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"key":"s3cret"}`)
	})

	got, err := c.TokenKey(t.Context(), "am-1")
	if err != nil {
		t.Fatalf("TokenKey: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("TokenKey = %q", got)
	}
}

func TestClient_GetAndDeleteToken(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/core/tokens/am-1/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"detail":"Not found."}`)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("method = %s", r.Method)
		}
	})

	if _, err := c.GetToken(t.Context(), "am-1"); !errors.Is(err, authentik.ErrNotFound) {
		t.Errorf("GetToken error = %v, want ErrNotFound", err)
	}
	if err := c.DeleteToken(t.Context(), "am-1"); err != nil {
		t.Errorf("DeleteToken: %v", err)
	}
}
