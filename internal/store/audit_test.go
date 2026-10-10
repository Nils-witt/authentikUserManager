package store_test

import (
	"strconv"
	"testing"
	"time"

	"authentikManager/internal/audit"
	"authentikManager/internal/store"
)

// recordTestEntries records three entries by a new, unique actor and returns
// it. The log is append-only, so the actor separates them from earlier runs.
func recordTestEntries(t *testing.T, s *store.Store) string {
	t.Helper()
	actor := "tester_%" + strconv.FormatInt(time.Now().UnixNano(), 10)
	for _, e := range []audit.Entry{
		{Actor: actor, Action: audit.ActionUserCreated, Target: "ann", Details: map[string]string{"user_id": "1"}},
		{Actor: actor, Action: audit.ActionUserUpdated, Target: "ann"},
		{Actor: actor, Action: audit.ActionRuleSaved, Target: "helpdesk", Details: map[string]string{"target_groups": "staff"}},
	} {
		if err := s.RecordAudit(t.Context(), e); err != nil {
			t.Fatalf("RecordAudit(%v): %v", e, err)
		}
	}
	return actor
}

func TestStore_listAudit(t *testing.T) {
	s := openTestStore(t)
	actor := recordTestEntries(t, s)

	all, err := s.ListAudit(t.Context(), audit.Query{Search: actor, Limit: 10})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(all) != 3 || all[0].Action != audit.ActionRuleSaved || all[0].ID <= all[1].ID {
		t.Fatalf("ListAudit = %+v, want 3 entries newest first", all)
	}
	if all[0].Details["target_groups"] != "staff" || all[1].Details == nil || all[0].Time.IsZero() {
		t.Errorf("entry = %+v, want details and time stored", all[0])
	}

	page, err := s.ListAudit(t.Context(), audit.Query{Search: actor, Before: all[0].ID, Limit: 1})
	if err != nil || len(page) != 1 || page[0].ID != all[1].ID {
		t.Errorf("page before %d = %+v, %v; want the second entry", all[0].ID, page, err)
	}
}

func TestStore_pruneAudit(t *testing.T) {
	s := openTestStore(t)
	actor := recordTestEntries(t, s)

	if _, err := s.PruneAudit(t.Context(), time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("PruneAudit in the past: %v", err)
	}
	if got, err := s.ListAudit(t.Context(), audit.Query{Search: actor, Limit: 10}); err != nil || len(got) != 3 {
		t.Fatalf("after pruning older entries = %d entries, %v; want 3 kept", len(got), err)
	}

	n, err := s.PruneAudit(t.Context(), time.Now().Add(time.Minute))
	if err != nil || n < 3 {
		t.Fatalf("PruneAudit = %d, %v; want at least 3 deleted", n, err)
	}
	if got, err := s.ListAudit(t.Context(), audit.Query{Search: actor, Limit: 10}); err != nil || len(got) != 0 {
		t.Errorf("after pruning = %+v, %v; want none", got, err)
	}
}

func TestStore_listAudit_filters(t *testing.T) {
	s := openTestStore(t)
	actor := recordTestEntries(t, s)

	byAction, err := s.ListAudit(t.Context(), audit.Query{Search: actor, Action: audit.ActionUserCreated, Limit: 10})
	if err != nil || len(byAction) != 1 || byAction[0].Details["user_id"] != "1" {
		t.Errorf("by action = %+v, %v; want the created entry", byAction, err)
	}

	// LIKE wildcards in the search text match literally.
	if got, err := s.ListAudit(t.Context(), audit.Query{Search: "tester__", Limit: 10}); err != nil || len(got) != 0 {
		t.Errorf("wildcard search = %+v, %v; want none", got, err)
	}
}
