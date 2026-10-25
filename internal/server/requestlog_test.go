package server_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authentikManager/internal/access"
	"authentikManager/internal/reqlog"
	"authentikManager/internal/server"
)

func TestServer_requestLog(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	policy, err := access.NewPolicy([]string{"admins"}, newFakeRules())
	if err != nil {
		t.Fatal(err)
	}
	log := &fakeAudit{}
	srv := server.New(server.Deps{
		Users:    &fakeUsers{user: member("staff")},
		Auth:     adminAuth,
		Policy:   policy,
		Rules:    newFakeRules(),
		Audit:    log,
		Logger:   slog.New(reqlog.NewHandler(slog.NewJSONHandler(&buf, nil))),
		ClientIP: func(*http.Request) string { return "198.51.100.7" },

		RecoveryEmailStage: testRecoveryStage,
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/users/4/recovery-email", strings.NewReader(""))
	req.Header.Set("User-Agent", "test-agent")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	requestID := rec.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Fatal("no X-Request-ID header")
	}

	var request map[string]any
	audited := false
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		// Every record of the request carries its ID.
		if r["request_id"] != requestID {
			t.Errorf("record %v without request_id %q", r, requestID)
		}
		switch r["msg"] {
		case "http request":
			request = r
		case "audit":
			audited = true
		}
	}
	if request["client_ip"] != "198.51.100.7" || request["user"] != "admin" || request["user_agent"] != "test-agent" {
		t.Errorf("request log = %v, want client IP, user and user agent", request)
	}
	if !audited || len(log.clientIPs) != 1 || log.clientIPs[0] != "198.51.100.7" {
		t.Errorf("audit entries from %v, want one naming the client IP", log.clientIPs)
	}
}
