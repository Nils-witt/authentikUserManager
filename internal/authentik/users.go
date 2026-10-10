package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// UserType mirrors authentik's UserTypeEnum.
type UserType string

// User types known to authentik.
const (
	UserTypeInternal               UserType = "internal"
	UserTypeExternal               UserType = "external"
	UserTypeServiceAccount         UserType = "service_account"
	UserTypeInternalServiceAccount UserType = "internal_service_account"
)

// Valid reports whether t is one of the known user types.
func (t UserType) Valid() bool {
	switch t {
	case UserTypeInternal, UserTypeExternal, UserTypeServiceAccount, UserTypeInternalServiceAccount:
		return true
	default:
		return false
	}
}

// User is the subset of authentik's User serializer this application uses.
type User struct {
	PK          int            `json:"pk"`
	UUID        string         `json:"uuid"`
	Username    string         `json:"username"`
	Name        string         `json:"name"`
	Email       string         `json:"email"`
	IsActive    bool           `json:"is_active"`
	IsSuperuser bool           `json:"is_superuser"`
	Type        UserType       `json:"type"`
	Path        string         `json:"path"`
	Avatar      string         `json:"avatar"`
	LastLogin   *time.Time     `json:"last_login"`
	DateJoined  time.Time      `json:"date_joined"`
	Attributes  map[string]any `json:"attributes"`
	// Groups are the groups the user is a direct member of.
	Groups []UserGroup `json:"groups_obj"`
}

// UserGroup is a group as embedded in a User.
type UserGroup struct {
	PK   string `json:"pk"`
	Name string `json:"name"`
}

// GroupNames returns the names of the user's groups.
func (u *User) GroupNames() []string {
	names := make([]string, len(u.Groups))
	for i, g := range u.Groups {
		names[i] = g.Name
	}
	return names
}

// Group is the subset of authentik's Group serializer this application uses.
type Group struct {
	PK          string `json:"pk"`
	Name        string `json:"name"`
	IsSuperuser bool   `json:"is_superuser"`
}

// Pagination is authentik's pagination envelope.
type Pagination struct {
	Count      int `json:"count"`
	Current    int `json:"current"`
	TotalPages int `json:"total_pages"`
	Next       int `json:"next"`
	Previous   int `json:"previous"`
	StartIndex int `json:"start_index"`
	EndIndex   int `json:"end_index"`
}

// UserList is one page of users.
type UserList struct {
	Pagination Pagination `json:"pagination"`
	Results    []User     `json:"results"`
}

// ListUsersParams filters and paginates ListUsers. Zero values are omitted.
type ListUsersParams struct {
	Search   string
	Ordering string
	Page     int
	PageSize int
	Type     []UserType
	// Path matches users whose path is exactly this value.
	Path string
	// PathStartsWith matches users whose path has this prefix, e.g. a folder and its subfolders.
	PathStartsWith string
	// GroupsByName matches users who are a member of any of these groups.
	GroupsByName []string
	// IsSuperuser, when non-nil, matches only superusers (true) or only other users (false).
	IsSuperuser *bool
}

func (p ListUsersParams) values() url.Values {
	q := url.Values{}
	if p.Search != "" {
		q.Set("search", p.Search)
	}
	if p.Ordering != "" {
		q.Set("ordering", p.Ordering)
	}
	if p.Page > 0 {
		q.Set("page", strconv.Itoa(p.Page))
	}
	if p.PageSize > 0 {
		q.Set("page_size", strconv.Itoa(p.PageSize))
	}
	for _, t := range p.Type {
		q.Add("type", string(t))
	}
	if p.Path != "" {
		q.Set("path", p.Path)
	}
	if p.PathStartsWith != "" {
		q.Set("path_startswith", p.PathStartsWith)
	}
	for _, g := range p.GroupsByName {
		q.Add("groups_by_name", g)
	}
	if p.IsSuperuser != nil {
		q.Set("is_superuser", strconv.FormatBool(*p.IsSuperuser))
	}
	return q
}

// CreateUserRequest is the payload for CreateUser.
type CreateUserRequest struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email,omitempty"`
	IsActive *bool    `json:"is_active,omitempty"`
	Path     string   `json:"path,omitempty"`
	Type     UserType `json:"type,omitempty"`
	// Groups lists the primary keys of the groups the new user joins.
	Groups []string `json:"groups,omitempty"`
}

// UpdateUserRequest is a partial update; nil fields are left unchanged.
type UpdateUserRequest struct {
	Username *string   `json:"username,omitempty"`
	Name     *string   `json:"name,omitempty"`
	Email    *string   `json:"email,omitempty"`
	IsActive *bool     `json:"is_active,omitempty"`
	Path     *string   `json:"path,omitempty"`
	Type     *UserType `json:"type,omitempty"`
}

func userPath(id int) string {
	return "core/users/" + strconv.Itoa(id) + "/"
}

// ListUsers returns one page of users matching p.
func (c *Client) ListUsers(ctx context.Context, p ListUsersParams) (*UserList, error) {
	var out UserList
	if err := c.do(ctx, http.MethodGet, "core/users/", p.values(), nil, &out); err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	if out.Results == nil {
		out.Results = []User{}
	}
	return &out, nil
}

// ListUserPaths returns every distinct user path, such as "users" or "users/staff".
func (c *Client) ListUserPaths(ctx context.Context) ([]string, error) {
	var out struct {
		Paths []string `json:"paths"`
	}
	if err := c.do(ctx, http.MethodGet, "core/users/paths/", nil, nil, &out); err != nil {
		return nil, fmt.Errorf("listing user paths: %w", err)
	}
	if out.Paths == nil {
		out.Paths = []string{}
	}
	return out.Paths, nil
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

// maxGroupResults bounds ListGroups; it serves suggestions, not a full listing.
const maxGroupResults = 100

// ListGroups returns up to 100 groups whose name matches search (all when empty), ordered by name.
func (c *Client) ListGroups(ctx context.Context, search string) ([]Group, error) {
	q := url.Values{
		"ordering":      {"name"},
		"page_size":     {strconv.Itoa(maxGroupResults)},
		"include_users": {"false"},
	}
	if search != "" {
		q.Set("search", search)
	}
	var out struct {
		Results []Group `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, "core/groups/", q, nil, &out); err != nil {
		return nil, fmt.Errorf("listing groups: %w", err)
	}
	if out.Results == nil {
		out.Results = []Group{}
	}
	return out.Results, nil
}

// GetUser returns the user with primary key id.
func (c *Client) GetUser(ctx context.Context, id int) (*User, error) {
	var out User
	if err := c.do(ctx, http.MethodGet, userPath(id), nil, nil, &out); err != nil {
		return nil, fmt.Errorf("getting user %d: %w", id, err)
	}
	return &out, nil
}

// CreateUser creates a user. The user has no password until SetPassword is called.
func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	var out User
	if err := c.do(ctx, http.MethodPost, "core/users/", nil, req, &out); err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}
	return &out, nil
}

// UpdateUser applies a partial update to the user with primary key id.
func (c *Client) UpdateUser(ctx context.Context, id int, req UpdateUserRequest) (*User, error) {
	var out User
	if err := c.do(ctx, http.MethodPatch, userPath(id), nil, req, &out); err != nil {
		return nil, fmt.Errorf("updating user %d: %w", id, err)
	}
	return &out, nil
}

// DeleteUser permanently deletes the user with primary key id.
func (c *Client) DeleteUser(ctx context.Context, id int) error {
	if err := c.do(ctx, http.MethodDelete, userPath(id), nil, nil, nil); err != nil {
		return fmt.Errorf("deleting user %d: %w", id, err)
	}
	return nil
}

// SetPassword sets the password of the user with primary key id.
func (c *Client) SetPassword(ctx context.Context, id int, password string) error {
	body := struct {
		Password string `json:"password"`
	}{Password: password}
	if err := c.do(ctx, http.MethodPost, userPath(id)+"set_password/", nil, body, nil); err != nil {
		return fmt.Errorf("setting password for user %d: %w", id, err)
	}
	return nil
}
