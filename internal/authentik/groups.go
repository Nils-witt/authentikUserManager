package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Group is the subset of authentik's Group serializer this application uses.
type Group struct {
	PK          string `json:"pk"`
	Name        string `json:"name"`
	IsSuperuser bool   `json:"is_superuser"`
	// ParentName is the name of the parent group; empty for a top-level group.
	ParentName string `json:"parent_name"`
}

// GroupList is one page of groups.
type GroupList struct {
	Pagination Pagination `json:"pagination"`
	Results    []Group    `json:"results"`
}

// ListGroupsParams filters and paginates ListGroups. Zero values are omitted.
type ListGroupsParams struct {
	Search   string
	Page     int
	PageSize int
}

// UpdateGroupRequest is a partial update; nil fields are left unchanged.
type UpdateGroupRequest struct {
	Name *string `json:"name,omitempty"`
}

func groupPath(pk string) string {
	return "core/groups/" + url.PathEscape(pk) + "/"
}

// FindGroup returns the group named name, or an error matching ErrNotFound.
func (c *Client) FindGroup(ctx context.Context, name string) (*Group, error) {
	q := url.Values{"name": {name}, "include_users": {"false"}}
	var out struct {
		Results []Group `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, "core/groups/", q, nil, &out); err != nil {
		return nil, fmt.Errorf("finding group %q: %w", name, err)
	}
	// The name filter is exact, but guard against an older authentik ignoring it.
	for _, g := range out.Results {
		if g.Name == name {
			return &g, nil
		}
	}
	return nil, fmt.Errorf("finding group %q: %w", name, ErrNotFound)
}

// ListGroups returns one page of groups matching p, ordered by name.
func (c *Client) ListGroups(ctx context.Context, p ListGroupsParams) (*GroupList, error) {
	q := url.Values{
		"ordering":      {"name"},
		"include_users": {"false"},
	}
	if p.Search != "" {
		q.Set("search", p.Search)
	}
	if p.Page > 0 {
		q.Set("page", strconv.Itoa(p.Page))
	}
	if p.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(p.PageSize))
	}
	var out GroupList
	if err := c.do(ctx, http.MethodGet, "core/groups/", q, nil, &out); err != nil {
		return nil, fmt.Errorf("listing groups: %w", err)
	}
	if out.Results == nil {
		out.Results = []Group{}
	}
	return &out, nil
}

// GetGroup returns the group with primary key pk, without its members.
func (c *Client) GetGroup(ctx context.Context, pk string) (*Group, error) {
	var out Group
	q := url.Values{"include_users": {"false"}}
	if err := c.do(ctx, http.MethodGet, groupPath(pk), q, nil, &out); err != nil {
		return nil, fmt.Errorf("getting group %s: %w", pk, err)
	}
	return &out, nil
}

// UpdateGroup applies a partial update to the group with primary key pk.
func (c *Client) UpdateGroup(ctx context.Context, pk string, req UpdateGroupRequest) (*Group, error) {
	var out Group
	if err := c.do(ctx, http.MethodPatch, groupPath(pk), nil, req, &out); err != nil {
		return nil, fmt.Errorf("updating group %s: %w", pk, err)
	}
	return &out, nil
}

// AddUserToGroup makes the user with primary key userID a member of the group with primary key groupPK.
func (c *Client) AddUserToGroup(ctx context.Context, groupPK string, userID int) error {
	body := struct {
		PK int `json:"pk"`
	}{PK: userID}
	if err := c.do(ctx, http.MethodPost, groupPath(groupPK)+"add_user/", nil, body, nil); err != nil {
		return fmt.Errorf("adding user %d to group %s: %w", userID, groupPK, err)
	}
	return nil
}

// RemoveUserFromGroup removes the user with primary key userID from the group with primary key groupPK.
func (c *Client) RemoveUserFromGroup(ctx context.Context, groupPK string, userID int) error {
	body := struct {
		PK int `json:"pk"`
	}{PK: userID}
	if err := c.do(ctx, http.MethodPost, groupPath(groupPK)+"remove_user/", nil, body, nil); err != nil {
		return fmt.Errorf("removing user %d from group %s: %w", userID, groupPK, err)
	}
	return nil
}
