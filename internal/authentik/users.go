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
	Search string
	// Username matches the user with exactly this username.
	Username string
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
	// GroupsByPK matches users who are a member of any of the groups with these primary keys.
	GroupsByPK []string
	// IsSuperuser, when non-nil, matches only superusers (true) or only other users (false).
	IsSuperuser *bool
	// IsActive, when non-nil, matches only active (true) or only inactive (false) users.
	IsActive *bool
}

func (p ListUsersParams) values() url.Values {
	q := url.Values{}
	if p.Search != "" {
		q.Set("search", p.Search)
	}
	if p.Username != "" {
		q.Set("username", p.Username)
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
	for _, g := range p.GroupsByPK {
		q.Add("groups_by_pk", g)
	}
	if p.IsSuperuser != nil {
		q.Set("is_superuser", strconv.FormatBool(*p.IsSuperuser))
	}
	if p.IsActive != nil {
		q.Set("is_active", strconv.FormatBool(*p.IsActive))
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
	// Attributes are the custom attributes of the new user.
	Attributes map[string]any `json:"attributes,omitempty"`
}

// UpdateUserRequest is a partial update; nil fields are left unchanged.
type UpdateUserRequest struct {
	Username *string   `json:"username,omitempty"`
	Name     *string   `json:"name,omitempty"`
	Email    *string   `json:"email,omitempty"`
	IsActive *bool     `json:"is_active,omitempty"`
	Path     *string   `json:"path,omitempty"`
	Type     *UserType `json:"type,omitempty"`
	// Attributes replaces all custom attributes of the user, so pass the
	// current ones with the changes applied. An empty map removes them all.
	Attributes map[string]any `json:"attributes,omitzero"`
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

// GetUser returns the user with primary key id.
func (c *Client) GetUser(ctx context.Context, id int) (*User, error) {
	var out User
	if err := c.do(ctx, http.MethodGet, userPath(id), nil, nil, &out); err != nil {
		return nil, fmt.Errorf("getting user %d: %w", id, err)
	}
	return &out, nil
}

// CreateUser creates a user.
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

// SendRecoveryEmail emails the user with primary key id a link to recover their
// account, using the email stage with UUID emailStage. authentik refuses it
// with a 400 error when the user has no email address or the brand has no recovery flow.
func (c *Client) SendRecoveryEmail(ctx context.Context, id int, emailStage string) error {
	body := struct {
		EmailStage string `json:"email_stage"`
	}{EmailStage: emailStage}
	// Older authentik versions read the stage from the query, newer ones from the body.
	q := url.Values{"email_stage": {emailStage}}
	if err := c.do(ctx, http.MethodPost, userPath(id)+"recovery_email/", q, body, nil); err != nil {
		return fmt.Errorf("sending recovery email to user %d: %w", id, err)
	}
	return nil
}
