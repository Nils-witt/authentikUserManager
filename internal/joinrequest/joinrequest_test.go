package joinrequest_test

import (
	"strings"
	"testing"

	"authentikManager/internal/joinrequest"
)

func TestStatus_Valid(t *testing.T) {
	t.Parallel()
	for _, s := range []joinrequest.Status{joinrequest.StatusPending, joinrequest.StatusApproved, joinrequest.StatusRejected} {
		if !s.Valid() {
			t.Errorf("%q.Valid() = false, want true", s)
		}
	}
	for _, s := range []joinrequest.Status{"", "withdrawn", "PENDING"} {
		if s.Valid() {
			t.Errorf("%q.Valid() = true, want false", s)
		}
	}
}

func TestNormalizeMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		expected  string
		expectErr bool
	}{
		{name: "empty", input: "", expected: ""},
		{name: "trimmed", input: "  please add me \n", expected: "please add me"},
		{name: "at the limit in characters", input: strings.Repeat("ä", joinrequest.MaxMessageLen), expected: strings.Repeat("ä", joinrequest.MaxMessageLen)},
		{name: "too long", input: strings.Repeat("a", joinrequest.MaxMessageLen+1), expectErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := joinrequest.NormalizeMessage(tt.input)
			if (err != nil) != tt.expectErr {
				t.Fatalf("NormalizeMessage error = %v, want error %v", err, tt.expectErr)
			}
			if got != tt.expected {
				t.Errorf("NormalizeMessage = %q, want %q", got, tt.expected)
			}
		})
	}
}
