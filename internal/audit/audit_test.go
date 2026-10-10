package audit_test

import (
	"strings"
	"testing"

	"authentikManager/internal/audit"
)

func TestQuery_Normalize(t *testing.T) {
	t.Parallel()
	got, err := audit.Query{Search: "  ann ", Action: audit.ActionUserDeleted}.Normalize()
	expected := audit.Query{Search: "ann", Action: audit.ActionUserDeleted, Limit: audit.DefaultLimit}
	if err != nil || got != expected {
		t.Errorf("Normalize = %+v, %v; want %+v", got, err, expected)
	}

	for name, q := range map[string]audit.Query{
		"long search":     {Search: strings.Repeat("a", 256)},
		"unknown action":  {Action: "user.hacked"},
		"negative before": {Before: -1},
		"negative limit":  {Limit: -1},
		"limit above max": {Limit: audit.MaxLimit + 1},
	} {
		if _, err := q.Normalize(); err == nil {
			t.Errorf("%s: Normalize succeeded", name)
		}
	}
}
