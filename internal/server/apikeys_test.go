package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"authentikManager/internal/apikey"
	"authentikManager/internal/audit"
	"authentikManager/internal/authentik"
)

// storedAPIKey is an API key held by fakeAPIKeys with its hash.
type storedAPIKey struct {
	key  apikey.Key
	hash []byte
}

// fakeAPIKeys is an in-memory API key store. Each test uses its own instance.
type fakeAPIKeys struct {
	keys   []storedAPIKey
	nextID int64
	err    error
}

// add stores a key of the user with userPK expiring at expiresAt and returns it.
func (f *fakeAPIKeys) add(userPK int, expiresAt *time.Time) (apikey.Key, string) {
	key, start, hash := apikey.New()
	f.nextID++
	k := apikey.Key{ID: f.nextID, UserPK: userPK, Username: "svc", Start: start, CreatedAt: time.Now(), CreatedBy: "admin", ExpiresAt: expiresAt}
	f.keys = append(f.keys, storedAPIKey{key: k, hash: hash})
	return k, key
}

func (f *fakeAPIKeys) CreateAPIKey(_ context.Context, k apikey.Key, hash []byte) (apikey.Key, error) {
	if f.err != nil {
		return apikey.Key{}, f.err
	}
	f.nextID++
	k.ID, k.CreatedAt = f.nextID, time.Now()
	f.keys = append(f.keys, storedAPIKey{key: k, hash: hash})
	return k, nil
}

func (f *fakeAPIKeys) ListAPIKeys(_ context.Context, userPK int) ([]apikey.Key, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := []apikey.Key{}
	for _, s := range slices.Backward(f.keys) {
		if s.key.UserPK == userPK {
			out = append(out, s.key)
		}
	}
	return out, nil
}

func (f *fakeAPIKeys) DeleteAPIKey(_ context.Context, userPK int, id int64) (apikey.Key, error) {
	if f.err != nil {
		return apikey.Key{}, f.err
	}
	i := slices.IndexFunc(f.keys, func(s storedAPIKey) bool { return s.key.ID == id && s.key.UserPK == userPK })
	if i < 0 {
		return apikey.Key{}, apikey.ErrNotFound
	}
	k := f.keys[i].key
	f.keys = slices.Delete(f.keys, i, i+1)
	return k, nil
}

func (f *fakeAPIKeys) DeleteUserAPIKeys(_ context.Context, userPK int) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	n := len(f.keys)
	f.keys = slices.DeleteFunc(f.keys, func(s storedAPIKey) bool { return s.key.UserPK == userPK })
	return int64(n - len(f.keys)), nil
}

func (f *fakeAPIKeys) AuthenticateAPIKey(_ context.Context, hash []byte, now time.Time) (apikey.Key, error) {
	if f.err != nil {
		return apikey.Key{}, f.err
	}
	for i, s := range f.keys {
		expired := s.key.ExpiresAt != nil && !s.key.ExpiresAt.After(now)
		if bytes.Equal(s.hash, hash) && !expired {
			f.keys[i].key.LastUsedAt = &now
			return f.keys[i].key, nil
		}
	}
	return apikey.Key{}, apikey.ErrNotFound
}

func TestAPIKeys_notConfigured(t *testing.T) {
	t.Parallel()
	srv := newScopedServer(t, &fakeUsers{user: serviceAccount("staff")}, "helpdesk")
	if rec := do(t, srv, http.MethodGet, "/api/service-accounts/5/api-keys", ""); rec.Code != http.StatusNotImplemented {
		t.Errorf("list = %d %s, want 501", rec.Code, rec.Body)
	}
}

func TestAPIKeys_list(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")}, "helpdesk")
	mine, _ := env.keys.add(5, nil)
	env.keys.add(6, nil)

	rec := do(t, env.srv, http.MethodGet, "/api/service-accounts/5/api-keys", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	var out struct {
		APIKeys []apikey.Key `json:"api_keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.APIKeys) != 1 || out.APIKeys[0].ID != mine.ID {
		t.Errorf("listed = %+v, want key %d of the service account only", out.APIKeys, mine.ID)
	}
}

func TestAPIKeys_create(t *testing.T) {
	t.Parallel()
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	inactive := serviceAccount("staff")
	inactive.IsActive = false
	tests := []struct {
		name     string
		user     *authentik.User
		body     string
		expected int
		field    string
	}{
		{name: "expiring key", user: serviceAccount("staff"), body: `{"description":"deploy","expires":"` + future + `"}`, expected: http.StatusCreated},
		{name: "key that never expires", user: serviceAccount("staff"), body: `{"description":"deploy","expires":null}`, expected: http.StatusCreated},
		{name: "expiry in the past", user: serviceAccount("staff"), body: `{"expires":"` + past + `"}`, expected: http.StatusBadRequest, field: "expires"},
		{
			name:     "description too long",
			user:     serviceAccount("staff"),
			body:     `{"description":"` + strings.Repeat("a", 256) + `"}`,
			expected: http.StatusBadRequest,
			field:    "description",
		},
		{name: "inactive service account", user: inactive, body: `{}`, expected: http.StatusConflict},
		{name: "outside scope", user: serviceAccount("other"), body: `{}`, expected: http.StatusNotFound},
		{name: "internal user", user: member("staff"), body: `{}`, expected: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, &fakeUsers{user: tt.user}, "helpdesk")
			rec := do(t, env.srv, http.MethodPost, "/api/service-accounts/5/api-keys", tt.body)
			if rec.Code != tt.expected {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.expected, rec.Body)
			}
			if tt.field != "" && !strings.Contains(rec.Body.String(), `"`+tt.field+`"`) {
				t.Errorf("body = %s, want an error for %s", rec.Body, tt.field)
			}
			created := tt.expected == http.StatusCreated
			if created != (len(env.keys.keys) == 1) || created != slices.Contains(actions(env.log), audit.ActionAPIKeyCreated) {
				t.Fatalf("keys = %+v, audit = %v", env.keys.keys, actions(env.log))
			}
			if created {
				checkCreatedAPIKey(t, env, rec)
			}
		})
	}
}

// checkCreatedAPIKey checks the response rec to the creation of the only key in env.
func checkCreatedAPIKey(t *testing.T, env *certEnv, rec *httptest.ResponseRecorder) {
	t.Helper()
	var out struct {
		APIKey apikey.Key `json:"api_key"`
		Key    string     `json:"key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	stored := env.keys.keys[0]
	if !apikey.WellFormed(out.Key) || !bytes.Equal(stored.hash, apikey.Hash(out.Key)) {
		t.Errorf("key %q does not match the stored hash", out.Key)
	}
	if k := out.APIKey; k.UserPK != 5 || k.Username != "svc" || k.CreatedBy != "admin" || !strings.HasPrefix(out.Key, k.Start) {
		t.Errorf("api key = %+v, want one of svc created by admin starting the key", k)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("response may be cached")
	}
}

func TestAPIKeys_delete(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		keyID    string
		expected int
	}{
		{name: "own key", keyID: "1", expected: http.StatusNoContent},
		{name: "key of another account", keyID: "2", expected: http.StatusNotFound},
		{name: "unknown key", keyID: "3", expected: http.StatusNotFound},
		{name: "invalid id", keyID: "x", expected: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")}, "helpdesk")
			env.keys.add(5, nil)
			env.keys.add(6, nil)
			rec := do(t, env.srv, http.MethodDelete, "/api/service-accounts/5/api-keys/"+tt.keyID, "")
			if rec.Code != tt.expected {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.expected, rec.Body)
			}
			deleted := tt.expected == http.StatusNoContent
			if deleted != (len(env.keys.keys) == 1) || deleted != slices.Contains(actions(env.log), audit.ActionAPIKeyDeleted) {
				t.Errorf("keys = %+v, audit = %v", env.keys.keys, actions(env.log))
			}
		})
	}
}

func TestAPIKeys_deletedWithServiceAccount(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, &fakeUsers{user: serviceAccount("staff")}, "admins")
	env.keys.add(5, nil)
	env.keys.add(6, nil)

	if rec := do(t, env.srv, http.MethodDelete, "/api/service-accounts/5", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if len(env.keys.keys) != 1 || env.keys.keys[0].key.UserPK != 6 {
		t.Errorf("keys = %+v, want only the key of another account left", env.keys.keys)
	}
	if !slices.Contains(actions(env.log), audit.ActionAPIKeyDeleted) {
		t.Errorf("audit = %v, want the deleted keys", actions(env.log))
	}
}
