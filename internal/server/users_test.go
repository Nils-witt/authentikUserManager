package server_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"authentikManager/internal/auth"
	"authentikManager/internal/authentik"
	"authentikManager/internal/server"
)

// fakeAuth lets every request through as a fixed user, or rejects all when deny is set.
type fakeAuth struct{ deny bool }

func (fakeAuth) Handler() http.Handler { return http.NotFoundHandler() }

func (f fakeAuth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.deny {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), auth.User{Username: "admin"})))
	})
}

// fakeUsers is a UserService whose behavior is set per test.
type fakeUsers struct {
	listParams authentik.ListUsersParams
	created    authentik.CreateUserRequest
	err        error
}

func (f *fakeUsers) ListUsers(_ context.Context, p authentik.ListUsersParams) (*authentik.UserList, error) {
	f.listParams = p
	if f.err != nil {
		return nil, f.err
	}
	return &authentik.UserList{Results: []authentik.User{{PK: 1, Username: "ann"}}}, nil
}

func (f *fakeUsers) GetUser(_ context.Context, id int) (*authentik.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &authentik.User{PK: id}, nil
}

func (f *fakeUsers) CreateUser(_ context.Context, req authentik.CreateUserRequest) (*authentik.User, error) {
	f.created = req
	if f.err != nil {
		return nil, f.err
	}
	return &authentik.User{PK: 9, Username: req.Username, Name: req.Name}, nil
}

func (f *fakeUsers) UpdateUser(_ context.Context, id int, _ authentik.UpdateUserRequest) (*authentik.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &authentik.User{PK: id}, nil
}

func (f *fakeUsers) DeleteUser(context.Context, int) error { return f.err }

func (f *fakeUsers) SetPassword(context.Context, int, string) error { return f.err }

func do(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newServer(users server.UserService) *server.Server {
	return server.New(users, fakeAuth{}, slog.New(slog.DiscardHandler), nil)
}

func TestServer_protection(t *testing.T) {
	t.Parallel()
	discard := slog.New(slog.DiscardHandler)
	tests := []struct {
		name       string
		authn      fakeAuth
		header     http.Header
		wantStatus int
	}{
		{name: "unauthenticated", authn: fakeAuth{deny: true}, wantStatus: http.StatusUnauthorized},
		{
			name:       "cross-site request rejected",
			header:     http.Header{"Sec-Fetch-Site": {"cross-site"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "same-origin request allowed",
			header:     http.Header{"Sec-Fetch-Site": {"same-origin"}},
			wantStatus: http.StatusNoContent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := server.New(&fakeUsers{}, tt.authn, discard, nil)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/users/1", nil)
			maps.Copy(req.Header, tt.header)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestServer_listUsers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		target     string
		wantStatus int
	}{
		{name: "defaults", target: "/api/users", wantStatus: http.StatusOK},
		{name: "search and paging", target: "/api/users?search=ann&page=2&page_size=50", wantStatus: http.StatusOK},
		{name: "bad page", target: "/api/users?page=0", wantStatus: http.StatusBadRequest},
		{name: "page size too large", target: "/api/users?page_size=1000", wantStatus: http.StatusBadRequest},
		{name: "unknown type", target: "/api/users?type=admin", wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(&fakeUsers{}), http.MethodGet, tt.target, "")
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
		})
	}
}

func TestServer_createUser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       string
		err        error
		wantStatus int
		wantField  string
	}{
		{name: "ok", body: `{"username":" ann ","name":"Ann"}`, wantStatus: http.StatusCreated},
		{name: "missing username", body: `{"name":"Ann"}`, wantStatus: http.StatusBadRequest, wantField: "username"},
		{name: "unknown field", body: `{"username":"ann","name":"Ann","is_superuser":true}`, wantStatus: http.StatusBadRequest},
		{name: "malformed json", body: `{`, wantStatus: http.StatusBadRequest},
		{
			name:       "upstream validation passed through",
			body:       `{"username":"ann","name":"Ann"}`,
			err:        &authentik.APIError{StatusCode: 400, Fields: map[string][]string{"username": {"taken"}}},
			wantStatus: http.StatusBadRequest,
			wantField:  "username",
		},
		{
			name:       "upstream failure hidden",
			body:       `{"username":"ann","name":"Ann"}`,
			err:        &authentik.APIError{StatusCode: 403, Detail: "token invalid"},
			wantStatus: http.StatusBadGateway,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{err: tt.err}
			rec := do(t, newServer(fake), http.MethodPost, "/api/users", tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			var body struct {
				Error  string              `json:"error"`
				Fields map[string][]string `json:"fields"`
			}
			if rec.Code >= 400 {
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("decoding error body: %v", err)
				}
				if strings.Contains(body.Error, "token") {
					t.Errorf("error %q leaks upstream detail", body.Error)
				}
			}
			if tt.wantField != "" && len(body.Fields[tt.wantField]) == 0 {
				t.Errorf("fields = %v, want entry for %q", body.Fields, tt.wantField)
			}
			if tt.wantStatus == http.StatusCreated && fake.created.Username != "ann" {
				t.Errorf("username = %q, want trimmed %q", fake.created.Username, "ann")
			}
		})
	}
}

func TestServer_userByID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		method     string
		target     string
		body       string
		err        error
		wantStatus int
	}{
		{name: "get", method: http.MethodGet, target: "/api/users/4", wantStatus: http.StatusOK},
		{name: "get invalid id", method: http.MethodGet, target: "/api/users/abc", wantStatus: http.StatusBadRequest},
		{name: "get negative id", method: http.MethodGet, target: "/api/users/-1", wantStatus: http.StatusBadRequest},
		{
			name:       "get not found",
			method:     http.MethodGet,
			target:     "/api/users/4",
			err:        &authentik.APIError{StatusCode: 404},
			wantStatus: http.StatusNotFound,
		},
		{name: "patch", method: http.MethodPatch, target: "/api/users/4", body: `{"is_active":false}`, wantStatus: http.StatusOK},
		{name: "patch bad type", method: http.MethodPatch, target: "/api/users/4", body: `{"type":"root"}`, wantStatus: http.StatusBadRequest},
		{name: "delete", method: http.MethodDelete, target: "/api/users/4", wantStatus: http.StatusNoContent},
		{name: "password", method: http.MethodPost, target: "/api/users/4/password", body: `{"password":"s3cret!"}`, wantStatus: http.StatusNoContent},
		{name: "empty password", method: http.MethodPost, target: "/api/users/4/password", body: `{"password":""}`, wantStatus: http.StatusBadRequest},
		{name: "unknown api route", method: http.MethodGet, target: "/api/nope", wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newServer(&fakeUsers{err: tt.err}), tt.method, tt.target, tt.body)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
		})
	}
}

func TestServer_static(t *testing.T) {
	t.Parallel()
	static := fstest.MapFS{
		"index.html":    {Data: []byte("<html>app</html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
	h := server.New(&fakeUsers{}, fakeAuth{}, slog.New(slog.DiscardHandler), static)

	tests := []struct {
		name     string
		target   string
		wantBody string
	}{
		{name: "asset", target: "/assets/app.js", wantBody: "console.log(1)"},
		{name: "spa fallback", target: "/users/42", wantBody: "<html>app</html>"},
		{name: "root", target: "/", wantBody: "<html>app</html>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, h, http.MethodGet, tt.target, "")
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("GET %s = %d %q, want 200 containing %q", tt.target, rec.Code, rec.Body, tt.wantBody)
			}
		})
	}
}
