package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"
)

// TokenIntent mirrors authentik's IntentEnum, limited to the intents users may create.
type TokenIntent string

// Token intents that can be created through the API.
const (
	// TokenIntentAPI is a token for the authentik API.
	TokenIntentAPI TokenIntent = "api"
	// TokenIntentAppPassword is a password for applications, e.g. LDAP or basic auth.
	TokenIntentAppPassword TokenIntent = "app_password"
)

// Valid reports whether i is an intent that can be created through the API.
func (i TokenIntent) Valid() bool {
	return i == TokenIntentAPI || i == TokenIntentAppPassword
}

// maxTokens bounds how many tokens of one user ListTokens returns.
const maxTokens = 100

// Token is the subset of authentik's Token serializer this application uses.
// It never holds the key; see TokenKey.
type Token struct {
	Identifier  string      `json:"identifier"`
	Intent      TokenIntent `json:"intent"`
	Description string      `json:"description"`
	// UserPK is the primary key of the user the token authenticates as.
	UserPK int `json:"user"`
	// Expiring is false for tokens that never expire.
	Expiring bool       `json:"expiring"`
	Expires  *time.Time `json:"expires"`
	// Managed is set for tokens authentik manages itself, e.g. for outposts.
	Managed *string `json:"managed"`
}

// IsManaged reports whether authentik manages the token itself.
func (t *Token) IsManaged() bool {
	return t.Managed != nil && *t.Managed != ""
}

// CreateTokenRequest is the payload for CreateToken.
type CreateTokenRequest struct {
	Identifier  string      `json:"identifier"`
	Intent      TokenIntent `json:"intent"`
	UserPK      int         `json:"user"`
	Description string      `json:"description,omitempty"`
	// Expiring is false for a token that never expires; Expires must be set otherwise.
	Expiring bool       `json:"expiring"`
	Expires  *time.Time `json:"expires,omitempty"`
}

func tokenPath(identifier string) string {
	return "core/tokens/" + url.PathEscape(identifier) + "/"
}

// ListTokens returns up to 100 tokens of the user with username and primary key
// userPK. Tokens of other users are dropped, since authentik ignores filters it
// does not know.
func (c *Client) ListTokens(ctx context.Context, userPK int, username string) ([]Token, error) {
	q := url.Values{
		"user__username": {username},
		"ordering":       {"identifier"},
		"page_size":      {strconv.Itoa(maxTokens)},
	}
	var out struct {
		Results []Token `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, "core/tokens/", q, nil, &out); err != nil {
		return nil, fmt.Errorf("listing tokens of user %d: %w", userPK, err)
	}
	tokens := slices.DeleteFunc(out.Results, func(t Token) bool { return t.UserPK != userPK })
	if tokens == nil {
		tokens = []Token{}
	}
	return tokens, nil
}

// GetToken returns the token with identifier.
func (c *Client) GetToken(ctx context.Context, identifier string) (*Token, error) {
	var out Token
	if err := c.do(ctx, http.MethodGet, tokenPath(identifier), nil, nil, &out); err != nil {
		return nil, fmt.Errorf("getting token %s: %w", identifier, err)
	}
	return &out, nil
}

// CreateToken creates a token. authentik assigns tokens created by users who are
// not superusers to themselves, so callers must check the returned UserPK.
func (c *Client) CreateToken(ctx context.Context, req CreateTokenRequest) (*Token, error) {
	var out Token
	if err := c.do(ctx, http.MethodPost, "core/tokens/", nil, req, &out); err != nil {
		return nil, fmt.Errorf("creating token: %w", err)
	}
	return &out, nil
}

// TokenKey returns the secret key of the token with identifier.
func (c *Client) TokenKey(ctx context.Context, identifier string) (string, error) {
	var out struct {
		Key string `json:"key"`
	}
	if err := c.do(ctx, http.MethodGet, tokenPath(identifier)+"view_key/", nil, nil, &out); err != nil {
		return "", fmt.Errorf("viewing key of token %s: %w", identifier, err)
	}
	return out.Key, nil
}

// DeleteToken deletes the token with identifier.
func (c *Client) DeleteToken(ctx context.Context, identifier string) error {
	if err := c.do(ctx, http.MethodDelete, tokenPath(identifier), nil, nil, nil); err != nil {
		return fmt.Errorf("deleting token %s: %w", identifier, err)
	}
	return nil
}
