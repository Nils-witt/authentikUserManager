package authentik_test

import (
	"encoding/json"
	"io"
	"maps"
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

func TestClient_ListGroups_attributeFilter(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var attrs map[string]any
		if err := json.Unmarshal([]byte(r.URL.Query().Get("attributes")), &attrs); err != nil || len(attrs) != 1 || attrs["visible"] != true {
			t.Errorf("attributes = %q (err %v), want {\"visible\":true}", r.URL.Query().Get("attributes"), err)
		}
		_, _ = io.WriteString(w, `{"pagination":{},"results":[{"pk":"g1","name":"staff","attributes":{"visible":true}}]}`)
	})

	got, err := c.ListGroups(t.Context(), authentik.ListGroupsParams{Attributes: map[string]any{"visible": true}})
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(got.Results) != 1 || got.Results[0].Attributes["visible"] != true {
		t.Errorf("ListGroups = %+v, want the group with its attributes", got)
	}
}

func TestClient_UpdateGroup_attributes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		attrs    map[string]any
		expected map[string]any
	}{
		{name: "replaced", attrs: map[string]any{"visible": true, "other": "kept"}, expected: map[string]any{"visible": true, "other": "kept"}},
		// An empty map must be sent, or the last attribute could not be removed.
		{name: "cleared", attrs: map[string]any{}, expected: map[string]any{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Name       *string        `json:"name"`
					Attributes map[string]any `json:"attributes"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decoding body: %v", err)
				}
				if body.Name != nil || body.Attributes == nil || !maps.Equal(body.Attributes, tt.expected) {
					t.Errorf("body = %+v, want only attributes %v", body, tt.expected)
				}
				_, _ = io.WriteString(w, `{"pk":"g-1","name":"staff"}`)
			})
			if _, err := c.UpdateGroup(t.Context(), "g-1", authentik.UpdateGroupRequest{Attributes: tt.attrs}); err != nil {
				t.Fatalf("UpdateGroup: %v", err)
			}
		})
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
