package authentik_test

import (
	"context"
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

func TestClient_ListUsers_pathFilter(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("path") != "users" || q.Get("path_startswith") != "users/staff" {
			t.Errorf("query = %v", q)
		}
		_, _ = io.WriteString(w, `{"pagination":{},"results":[]}`)
	})

	params := authentik.ListUsersParams{Path: "users", PathStartsWith: "users/staff"}
	if _, err := c.ListUsers(t.Context(), params); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
}

func TestClient_ListUsers_activeFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		isActive *bool
		want     string
	}{
		{name: "unset", isActive: nil, want: ""},
		{name: "active", isActive: new(true), want: "true"},
		{name: "inactive", isActive: new(false), want: "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if got := q.Get("is_active"); got != tt.want || q.Has("is_active") != (tt.want != "") {
					t.Errorf("is_active = %q, want %q", got, tt.want)
				}
				_, _ = io.WriteString(w, `{"pagination":{},"results":[]}`)
			})
			if _, err := c.ListUsers(t.Context(), authentik.ListUsersParams{IsActive: tt.isActive}); err != nil {
				t.Fatalf("ListUsers: %v", err)
			}
		})
	}
}

func TestClient_ListUsers_groupFilter(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q["groups_by_name"]; len(got) != 2 || got[0] != "staff" || got[1] != "students" {
			t.Errorf("groups_by_name = %v", got)
		}
		if got := q["groups_by_pk"]; len(got) != 1 || got[0] != "g1" {
			t.Errorf("groups_by_pk = %v", got)
		}
		if q.Get("is_superuser") != "false" {
			t.Errorf("is_superuser = %q", q.Get("is_superuser"))
		}
		_, _ = io.WriteString(w, `{"pagination":{},"results":[{"pk":1,"groups_obj":[{"pk":"g1","name":"staff"}]}]}`)
	})

	params := authentik.ListUsersParams{GroupsByName: []string{"staff", "students"}, GroupsByPK: []string{"g1"}, IsSuperuser: new(false)}
	got, err := c.ListUsers(t.Context(), params)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if names := got.Results[0].GroupNames(); len(names) != 1 || names[0] != "staff" {
		t.Errorf("GroupNames = %v", names)
	}
}

func TestClient_ListUsers_usernameFilter(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("username"); got != "ann" {
			t.Errorf("username = %q, want ann", got)
		}
		_, _ = io.WriteString(w, `{"pagination":{},"results":[]}`)
	})
	if _, err := c.ListUsers(t.Context(), authentik.ListUsersParams{Username: "ann"}); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
}

func TestClient_FindGroup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		body         string
		wantPK       string
		wantNotFound bool
	}{
		{name: "found", body: `{"results":[{"pk":"g1","name":"staff","is_superuser":true}]}`, wantPK: "g1"},
		{name: "none", body: `{"results":[]}`, wantNotFound: true},
		{name: "filter ignored", body: `{"results":[{"pk":"g2","name":"staff-old"}]}`, wantNotFound: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v3/core/groups/" || r.URL.Query().Get("name") != "staff" {
					t.Errorf("request = %s", r.URL)
				}
				_, _ = io.WriteString(w, tt.body)
			})

			got, err := c.FindGroup(t.Context(), "staff")
			if got := errors.Is(err, authentik.ErrNotFound); got != tt.wantNotFound {
				t.Fatalf("FindGroup error = %v, want not found %v", err, tt.wantNotFound)
			}
			if !tt.wantNotFound && (got.PK != tt.wantPK || !got.IsSuperuser) {
				t.Errorf("FindGroup = %+v", got)
			}
		})
	}
}

func TestClient_ListGroups(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/api/v3/core/groups/" || q.Get("search") != "sta" || q.Get("include_users") != "false" ||
			q.Get("ordering") != "name" || q.Get("page") != "2" || q.Get("page_size") != "10" {
			t.Errorf("request = %s", r.URL)
		}
		_, _ = io.WriteString(w, `{"pagination":{"count":11},"results":[{"pk":"g1","name":"staff","parent_name":"all"}]}`)
	})

	got, err := c.ListGroups(t.Context(), authentik.ListGroupsParams{Search: "sta", Page: 2, PageSize: 10})
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if got.Pagination.Count != 11 || len(got.Results) != 1 || got.Results[0].Name != "staff" || got.Results[0].ParentName != "all" {
		t.Errorf("ListGroups = %+v", got)
	}
}

func TestClient_ListUserPaths(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v3/core/users/paths/" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"paths":["users","users/staff"]}`)
	})

	got, err := c.ListUserPaths(t.Context())
	if err != nil {
		t.Fatalf("ListUserPaths: %v", err)
	}
	if len(got) != 2 || got[0] != "users" || got[1] != "users/staff" {
		t.Errorf("ListUserPaths = %v", got)
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

func TestClient_groupMembership(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		call     func(ctx context.Context, c *authentik.Client) error
		wantPath string
	}{
		{
			name:     "add",
			call:     func(ctx context.Context, c *authentik.Client) error { return c.AddUserToGroup(ctx, "g-1", 3) },
			wantPath: "/api/v3/core/groups/g-1/add_user/",
		},
		{
			name:     "remove",
			call:     func(ctx context.Context, c *authentik.Client) error { return c.RemoveUserFromGroup(ctx, "g-1", 3) },
			wantPath: "/api/v3/core/groups/g-1/remove_user/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != tt.wantPath {
					t.Errorf("request = %s %s, want POST %s", r.Method, r.URL.Path, tt.wantPath)
				}
				var body struct {
					PK int `json:"pk"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PK != 3 {
					t.Errorf("body pk = %d (err %v), want 3", body.PK, err)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			if err := tt.call(t.Context(), c); err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
		})
	}
}

func TestClient_SendRecoveryEmail(t *testing.T) {
	t.Parallel()
	const stage = "5f2e8a3c-1b4d-4e6f-9a7b-0c1d2e3f4a5b"
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/core/users/3/recovery_email/" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.URL.Query().Get("email_stage"); got != stage {
			t.Errorf("query email_stage = %q, want %q", got, stage)
		}
		var body struct {
			EmailStage string `json:"email_stage"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.EmailStage != stage {
			t.Errorf("body email_stage = %q (err %v), want %q", body.EmailStage, err, stage)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.SendRecoveryEmail(t.Context(), 3, stage); err != nil {
		t.Fatalf("SendRecoveryEmail: %v", err)
	}
}
