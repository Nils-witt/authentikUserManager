package store_test

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"authentikManager/internal/access"
	"authentikManager/internal/store"
)

// openTestStore connects to TEST_DATABASE_URL, skipping the test when it is
// unset. The database is wiped, so never point it at real data.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	s, err := store.Open(t.Context(), url)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)
	rules, err := s.ListRules(t.Context())
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	for _, r := range rules {
		if err := s.DeleteRule(t.Context(), r.OperatorGroup); err != nil {
			t.Fatalf("DeleteRule: %v", err)
		}
	}
	return s
}

// The store tests share one database, so they do not run in parallel.

func TestStore_putAndList(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	for _, r := range []access.Rule{
		{OperatorGroup: "helpdesk", TargetGroups: []string{"staff", "students"}},
		{OperatorGroup: "teachers", TargetGroups: []string{"students"}},
		{OperatorGroup: "a/b team", TargetGroups: []string{"*"}},
	} {
		if err := s.PutRule(ctx, r, "tester"); err != nil {
			t.Fatalf("PutRule(%v): %v", r, err)
		}
	}

	rules, err := s.ListRules(ctx)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 3 || rules[0].OperatorGroup != "a/b team" || !slices.Equal(rules[1].TargetGroups, []string{"staff", "students"}) {
		t.Errorf("ListRules = %+v", rules)
	}

	got, err := s.TargetGroups(ctx, []string{"helpdesk", "teachers", "unknown"})
	if err != nil {
		t.Fatalf("TargetGroups: %v", err)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"staff", "students"}) {
		t.Errorf("TargetGroups = %v, want distinct [staff students]", got)
	}
}

func TestStore_replaceAndDelete(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	rule := access.Rule{OperatorGroup: "helpdesk", TargetGroups: []string{"staff", "students"}}
	if err := s.PutRule(ctx, rule, "tester"); err != nil {
		t.Fatalf("PutRule: %v", err)
	}

	// Replacing a rule drops targets that are no longer listed.
	if err := s.PutRule(ctx, access.Rule{OperatorGroup: "helpdesk", TargetGroups: []string{"guests"}}, "tester"); err != nil {
		t.Fatalf("PutRule replace: %v", err)
	}
	if got, err := s.TargetGroups(ctx, []string{"helpdesk"}); err != nil || !slices.Equal(got, []string{"guests"}) {
		t.Errorf("TargetGroups after replace = %v, %v; want [guests]", got, err)
	}

	if err := s.DeleteRule(ctx, "helpdesk"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if err := s.DeleteRule(ctx, "helpdesk"); !errors.Is(err, access.ErrRuleNotFound) {
		t.Errorf("DeleteRule twice = %v, want ErrRuleNotFound", err)
	}
	if got, err := s.TargetGroups(ctx, nil); err != nil || len(got) != 0 {
		t.Errorf("TargetGroups(nil) = %v, %v; want empty", got, err)
	}
}

func TestStore_renameGroup(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	for _, r := range []access.Rule{
		{OperatorGroup: "helpdesk", TargetGroups: []string{"staff", "students"}},
		{OperatorGroup: "teachers", TargetGroups: []string{"staff"}},
		// Already names the new name, so its entry is merged.
		{OperatorGroup: "office", TargetGroups: []string{"staff", "employees"}},
	} {
		if err := s.PutRule(ctx, r, "tester"); err != nil {
			t.Fatalf("PutRule(%v): %v", r, err)
		}
	}
	n, err := s.RenameGroup(ctx, "staff", "employees", "tester")
	if err != nil {
		t.Fatalf("RenameGroup: %v", err)
	}
	if n != 3 {
		t.Errorf("RenameGroup changed %d entries, want 3", n)
	}
	rules, err := s.ListRules(ctx)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	want := []access.Rule{
		{OperatorGroup: "helpdesk", TargetGroups: []string{"employees", "students"}},
		{OperatorGroup: "office", TargetGroups: []string{"employees"}},
		{OperatorGroup: "teachers", TargetGroups: []string{"employees"}},
	}
	if !slices.EqualFunc(rules, want, func(a, b access.Rule) bool {
		return a.OperatorGroup == b.OperatorGroup && slices.Equal(a.TargetGroups, b.TargetGroups)
	}) {
		t.Errorf("rules = %+v, want %+v", rules, want)
	}

	if _, err := s.RenameGroup(ctx, "helpdesk", "support", "tester"); err != nil {
		t.Fatalf("RenameGroup operator group: %v", err)
	}
	got, err := s.TargetGroups(ctx, []string{"support"})
	if err != nil {
		t.Fatalf("TargetGroups: %v", err)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"employees", "students"}) {
		t.Errorf("TargetGroups(support) = %v, want the renamed rule's targets", got)
	}
}

func TestOpen_invalidURLHidesPassword(t *testing.T) {
	t.Parallel()
	_, err := store.Open(t.Context(), "postgres://user:hunter2@[bad")
	if err == nil {
		t.Fatal("Open succeeded")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error %q leaks the password", err)
	}
}
