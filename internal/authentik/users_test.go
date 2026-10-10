package authentik_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"authentikManager/internal/authentik"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *authentik.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := authentik.New(srv.URL, "secret-token", authentik.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNew(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		baseURL string
		token   string
		wantErr bool
	}{
		{name: "valid", baseURL: "https://sso.example.com", token: "t"},
		{name: "empty token", baseURL: "https://sso.example.com", wantErr: true},
		{name: "relative url", baseURL: "sso.example.com", token: "t", wantErr: true},
		{name: "unsupported scheme", baseURL: "ftp://sso.example.com", token: "t", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := authentik.New(tt.baseURL, tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("New(%q) error = %v, wantErr %v", tt.baseURL, err, tt.wantErr)
			}
		})
	}
}

func TestClient_ListUsers(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/core/users/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("Authorization = %q", got)
		}
		q := r.URL.Query()
		if q.Get("search") != "ann" || q.Get("page") != "2" || q.Get("page_size") != "10" {
			t.Errorf("query = %v", q)
		}
		_, _ = io.WriteString(w, `{"pagination":{"count":11,"current":2,"total_pages":2},"results":[{"pk":7,"username":"ann"}],"autocomplete":{}}`)
	})

	got, err := c.ListUsers(t.Context(), authentik.ListUsersParams{Search: "ann", Page: 2, PageSize: 10})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if got.Pagination.Count != 11 || len(got.Results) != 1 || got.Results[0].Username != "ann" {
		t.Errorf("ListUsers = %+v", got)
	}
}

func TestClient_UpdateUser_sendsOnlySetFields(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v3/core/users/7/" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding body: %v", err)
		}
		if len(body) != 1 || body["is_active"] != false {
			t.Errorf("body = %v, want only is_active=false", body)
		}
		_, _ = io.WriteString(w, `{"pk":7,"is_active":false}`)
	})

	got, err := c.UpdateUser(t.Context(), 7, authentik.UpdateUserRequest{IsActive: new(false)})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if got.IsActive {
		t.Error("IsActive = true, want false")
	}
}

func TestClient_errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		status       int
		body         string
		wantNotFound bool
		wantFields   map[string]int
		wantDetail   string
	}{
		{
			name:         "not found",
			status:       http.StatusNotFound,
			body:         `{"detail":"No User matches the given query."}`,
			wantNotFound: true,
			wantDetail:   "No User matches the given query.",
		},
		{
			name:       "validation",
			status:     http.StatusBadRequest,
			body:       `{"username":["user with this username already exists."],"non_field_errors":["x"],"code":"invalid"}`,
			wantFields: map[string]int{"username": 1, "non_field_errors": 1},
		},
		{
			name:   "non-json body",
			status: http.StatusInternalServerError,
			body:   `<html>oops</html>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			})

			_, err := c.GetUser(t.Context(), 1)
			apiErr, ok := errors.AsType[*authentik.APIError](err)
			if !ok {
				t.Fatalf("error = %v, want *APIError", err)
			}
			if apiErr.StatusCode != tt.status {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tt.status)
			}
			if got := errors.Is(err, authentik.ErrNotFound); got != tt.wantNotFound {
				t.Errorf("errors.Is(ErrNotFound) = %v, want %v", got, tt.wantNotFound)
			}
			if apiErr.Detail != tt.wantDetail {
				t.Errorf("Detail = %q, want %q", apiErr.Detail, tt.wantDetail)
			}
			if len(apiErr.Fields) != len(tt.wantFields) {
				t.Errorf("Fields = %v, want keys %v", apiErr.Fields, tt.wantFields)
			}
			for k, n := range tt.wantFields {
				if len(apiErr.Fields[k]) != n {
					t.Errorf("Fields[%q] = %v, want %d messages", k, apiErr.Fields[k], n)
				}
			}
		})
	}
}

func TestClient_SetPassword(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/core/users/3/set_password/" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.SetPassword(t.Context(), 3, "hunter22"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
}
