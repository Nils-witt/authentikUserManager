package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"authentikManager/internal/buildinfo"
)

func TestServer_getVersion(t *testing.T) {
	t.Parallel()
	rec := do(t, newServer(t, &fakeUsers{}), http.MethodGet, "/api/version", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body struct {
		Repository string `json:"repository"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body.Repository != buildinfo.RepositoryURL {
		t.Errorf("repository = %q, want %q", body.Repository, buildinfo.RepositoryURL)
	}
}
