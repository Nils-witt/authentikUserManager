package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"authentikManager/internal/authentik"
)

func TestServer_listUserApplications(t *testing.T) {
	t.Parallel()
	ptr := func(s string) *string { return &s }
	fake := &fakeUsers{
		user: member("students"),
		apps: []authentik.Application{
			{Name: "Wiki", Slug: "wiki", Group: "Docs", LaunchURL: ptr("https://wiki.example.com")},
			{Name: "Evil", Slug: "evil", LaunchURL: ptr("javascript:alert(1)")},
			{Name: "Relative", Slug: "relative", LaunchURL: ptr("/if/user/")},
			{Name: "None", Slug: "none"},
		},
	}

	rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodGet, "/api/users/4/applications", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body)
	}
	if fake.appsUserPK != 4 {
		t.Errorf("listed applications of user %d, want 4", fake.appsUserPK)
	}
	var body struct {
		Applications []struct {
			Slug      string `json:"slug"`
			Group     string `json:"group"`
			LaunchURL string `json:"launch_url"`
		} `json:"applications"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	expected := map[string]string{
		"wiki":     "https://wiki.example.com",
		"evil":     "",
		"relative": "",
		"none":     "",
	}
	if len(body.Applications) != len(expected) {
		t.Fatalf("applications = %+v", body.Applications)
	}
	for _, a := range body.Applications {
		if want, ok := expected[a.Slug]; !ok || a.LaunchURL != want {
			t.Errorf("application %q launch_url = %q, want %q", a.Slug, a.LaunchURL, want)
		}
	}
	if body.Applications[0].Group != "Docs" {
		t.Errorf("group = %q, want Docs", body.Applications[0].Group)
	}
}

func TestServer_listUserApplications_access(t *testing.T) {
	t.Parallel()
	serviceAccount := member("staff")
	serviceAccount.Type = authentik.UserTypeServiceAccount
	tests := []struct {
		name       string
		groups     []string
		target     *authentik.User
		wantStatus int
	}{
		{name: "member of target group", groups: []string{"helpdesk"}, target: member("students"), wantStatus: http.StatusOK},
		{name: "outside target groups", groups: []string{"helpdesk"}, target: member("other"), wantStatus: http.StatusNotFound},
		{name: "own account outside the scope", groups: []string{"guests"}, target: self("other"), wantStatus: http.StatusOK},
		{name: "hidden user for restricted operator", groups: []string{"helpdesk"}, target: hidden(member("students")), wantStatus: http.StatusNotFound},
		{name: "service account", groups: []string{"admins"}, target: serviceAccount, wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeUsers{user: tt.target}
			rec := do(t, newScopedServer(t, fake, tt.groups...), http.MethodGet, "/api/users/4/applications", "")
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
		})
	}
}

func TestServer_listUserApplications_upstreamError(t *testing.T) {
	t.Parallel()
	fake := &fakeUsers{user: member("students"), appsErr: &authentik.APIError{StatusCode: http.StatusInternalServerError}}
	rec := do(t, newScopedServer(t, fake, "helpdesk"), http.MethodGet, "/api/users/4/applications", "")
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (body %s)", rec.Code, rec.Body)
	}
}
