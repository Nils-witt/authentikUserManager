package server

import (
	"net/http"
	"net/url"

	"authentikManager/internal/authentik"
)

// applicationView is an application a user may access, as the frontend shows it.
type applicationView struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Group       string `json:"group"`
	Description string `json:"description"`
	Publisher   string `json:"publisher"`
	// LaunchURL is empty unless it is an absolute http(s) URL, so the
	// frontend can link it without running a javascript: URL.
	LaunchURL string `json:"launch_url"`
}

func newApplicationView(a *authentik.Application) applicationView {
	return applicationView{
		Name:        a.Name,
		Slug:        a.Slug,
		Group:       a.Group,
		Description: a.MetaDescription,
		Publisher:   a.MetaPublisher,
		LaunchURL:   webURL(a.LaunchURL),
	}
}

// webURL returns raw when it is an absolute http(s) URL, and "" otherwise.
func webURL(raw *string) string {
	if raw == nil {
		return ""
	}
	u, err := url.Parse(*raw)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return *raw
}

// listUserApplications returns the applications the user with the {id} path
// value may access. Every operator who may see the user may list them.
func (s *Server) listUserApplications(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.visibleAccount(w, r, userAccounts)
	if !ok {
		return
	}
	apps, err := s.users.ListUserApplications(r.Context(), user.PK)
	if err != nil {
		s.writeUpstreamError(w, r, err)
		return
	}
	views := make([]applicationView, len(apps))
	for i := range apps {
		views[i] = newApplicationView(&apps[i])
	}
	writeJSON(w, http.StatusOK, map[string][]applicationView{"applications": views})
}
