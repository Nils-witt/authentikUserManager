package authentik_test

import (
	"fmt"
	"net/http"
	"testing"
)

func TestClient_ListUserApplications(t *testing.T) {
	t.Parallel()
	var pages []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/core/applications/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		q := r.URL.Query()
		if got := q.Get("for_user"); got != "7" {
			t.Errorf("for_user = %q, want 7", got)
		}
		page := q.Get("page")
		pages = append(pages, page)
		// authentik filters each page after paging, so the first page is empty
		// although the second one holds an application.
		switch page {
		case "1":
			_, _ = fmt.Fprint(w, `{"pagination":{"next":2},"results":[]}`)
		default:
			_, _ = fmt.Fprint(w, `{"pagination":{"next":0},"results":[
				{"pk":"a","name":"Wiki","slug":"wiki","group":"Docs","launch_url":"https://wiki.example.com"}]}`)
		}
	})

	got, err := c.ListUserApplications(t.Context(), 7)
	if err != nil {
		t.Fatalf("ListUserApplications: %v", err)
	}
	if len(pages) != 2 {
		t.Errorf("pages read = %v, want 2", pages)
	}
	if len(got) != 1 || got[0].Slug != "wiki" || got[0].LaunchURL == nil || *got[0].LaunchURL != "https://wiki.example.com" {
		t.Errorf("ListUserApplications = %+v", got)
	}
}

func TestClient_ListUserApplications_empty(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"pagination":{"next":0},"results":null}`)
	})

	got, err := c.ListUserApplications(t.Context(), 7)
	if err != nil {
		t.Fatalf("ListUserApplications: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("ListUserApplications = %#v, want an empty slice", got)
	}
}

func TestClient_ListUserApplications_error(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	if _, err := c.ListUserApplications(t.Context(), 7); err == nil {
		t.Error("ListUserApplications succeeded, want an error")
	}
}
