package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

const (
	// applicationPageSize is the page size ListUserApplications requests.
	applicationPageSize = 100
	// maxApplicationPages bounds the pages ListUserApplications reads.
	maxApplicationPages = 20
)

// Application is the subset of authentik's Application serializer this application uses.
type Application struct {
	PK   string `json:"pk"`
	Name string `json:"name"`
	Slug string `json:"slug"`
	// Group is the free-text group the application is listed under in the user's library.
	Group string `json:"group"`
	// LaunchURL is where the user opens the application; nil when it has none.
	LaunchURL       *string `json:"launch_url"`
	MetaDescription string  `json:"meta_description"`
	MetaPublisher   string  `json:"meta_publisher"`
}

// ListUserApplications returns the applications the user with primary key
// userPK may access, as decided by the policies bound to each application.
// It reads at most maxApplicationPages pages of applications.
func (c *Client) ListUserApplications(ctx context.Context, userPK int) ([]Application, error) {
	out := []Application{}
	for page := 1; page <= maxApplicationPages; page++ {
		q := url.Values{
			"for_user":  {strconv.Itoa(userPK)},
			"ordering":  {"name"},
			"page":      {strconv.Itoa(page)},
			"page_size": {strconv.Itoa(applicationPageSize)},
		}
		var list struct {
			Pagination Pagination    `json:"pagination"`
			Results    []Application `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, "core/applications/", q, nil, &list); err != nil {
			return nil, fmt.Errorf("listing applications of user %d: %w", userPK, err)
		}
		// authentik pages all applications before dropping those the user may
		// not access, so a short page does not mean it is the last one.
		out = append(out, list.Results...)
		if list.Pagination.Next == 0 {
			break
		}
	}
	return out, nil
}
