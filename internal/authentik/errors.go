package authentik

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrNotFound is matched (via errors.Is) by an *APIError with status 404.
var ErrNotFound = errors.New("authentik: not found")

// APIError is a non-2xx response from authentik.
type APIError struct {
	StatusCode int
	// Detail is the generic error message, if authentik sent one.
	Detail string
	// Fields holds validation messages keyed by field name
	// ("non_field_errors" for errors not tied to a field).
	Fields map[string][]string
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "authentik: status %d", e.StatusCode)
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if len(e.Fields) > 0 {
		fmt.Fprintf(&b, " (%d field errors)", len(e.Fields))
	}
	return b.String()
}

// Is reports whether e matches target, so callers can use errors.Is(err, ErrNotFound).
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.StatusCode == http.StatusNotFound
}

// newAPIError parses authentik's GenericError ({"detail": ...}) or
// ValidationError ({"field": ["msg"], ...}) bodies. Unparseable bodies still
// yield an APIError carrying the status code.
func newAPIError(status int, body io.Reader) *APIError {
	apiErr := &APIError{StatusCode: status, Fields: map[string][]string{}}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(body).Decode(&raw); err != nil {
		return apiErr
	}
	for key, val := range raw {
		switch key {
		case "code":
			continue
		case "detail":
			// security: detail is upstream text but only ever rendered as plain text by the frontend.
			if err := json.Unmarshal(val, &apiErr.Detail); err == nil {
				continue
			}
		}
		var msgs []string
		if err := json.Unmarshal(val, &msgs); err == nil {
			apiErr.Fields[key] = msgs
			continue
		}
		var msg string
		if err := json.Unmarshal(val, &msg); err == nil {
			apiErr.Fields[key] = []string{msg}
		}
	}
	return apiErr
}
