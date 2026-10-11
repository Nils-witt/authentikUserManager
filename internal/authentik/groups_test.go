package authentik_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"authentikManager/internal/authentik"
)

func TestClient_GetGroup(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v3/core/groups/g-1/" || r.URL.Query().Get("include_users") != "false" {
			t.Errorf("request = %s %s", r.Method, r.URL)
		}
		_, _ = io.WriteString(w, `{"pk":"g-1","name":"staff","is_superuser":true,"parent_name":null}`)
	})

	got, err := c.GetGroup(t.Context(), "g-1")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got.PK != "g-1" || got.Name != "staff" || !got.IsSuperuser || got.ParentName != "" {
		t.Errorf("GetGroup = %+v", got)
	}
}

func TestClient_UpdateGroup(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v3/core/groups/g-1/" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || body["name"] != "teachers" {
			t.Errorf("body = %v (err %v), want only the name", body, err)
		}
		_, _ = io.WriteString(w, `{"pk":"g-1","name":"teachers"}`)
	})

	got, err := c.UpdateGroup(t.Context(), "g-1", authentik.UpdateGroupRequest{Name: new("teachers")})
	if err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if got.Name != "teachers" {
		t.Errorf("UpdateGroup = %+v", got)
	}
}
