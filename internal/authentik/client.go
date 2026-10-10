// Package authentik is a minimal client for the authentik REST API (v3),
// covering the user management endpoints used by this application.
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultTimeout = 15 * time.Second
	// maxResponseBytes bounds how much of an upstream response is read, so a
	// misbehaving server cannot exhaust memory.
	maxResponseBytes = 10 << 20
)

// Client talks to a single authentik instance using an API token.
// It is safe for concurrent use.
type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient replaces the default HTTP client (15s timeout).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// New returns a client for the authentik instance at baseURL
// (e.g. "https://sso.example.com"). The "/api/v3/" prefix is added automatically.
func New(baseURL, token string, opts ...Option) (*Client, error) {
	if token == "" {
		return nil, errors.New("authentik: token is empty")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("authentik: parsing base url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("authentik: base url %q must be an absolute http(s) url", baseURL)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v3/"
	u.RawQuery = ""
	u.Fragment = ""

	c := &Client{
		baseURL:    u,
		token:      token,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// do performs a JSON request against path (relative to /api/v3/, with trailing
// slash as authentik requires) and decodes the response into out when non-nil.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := c.baseURL.ResolveReference(&url.URL{Path: path, RawQuery: query.Encode()})

	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // close error on a fully-read response body carries no information

	limited := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode >= http.StatusMultipleChoices {
		return newAPIError(resp.StatusCode, limited)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("decoding %s %s response: %w", method, path, err)
	}
	return nil
}
