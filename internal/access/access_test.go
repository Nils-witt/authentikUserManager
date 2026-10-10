package access_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"authentikManager/internal/access"
	"authentikManager/internal/authentik"
)

func TestRule_Normalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rule    access.Rule
		want    access.Rule
		wantErr bool
	}{
		{
			name: "trims, sorts and deduplicates",
			rule: access.Rule{OperatorGroup: " helpdesk ", TargetGroups: []string{"students", " staff", "students"}},
			want: access.Rule{OperatorGroup: "helpdesk", TargetGroups: []string{"staff", "students"}},
		},
		{
			name: "wildcard",
			rule: access.Rule{OperatorGroup: "admins", TargetGroups: []string{"*"}},
			want: access.Rule{OperatorGroup: "admins", TargetGroups: []string{"*"}},
		},
		{name: "empty operator", rule: access.Rule{OperatorGroup: " ", TargetGroups: []string{"staff"}}, wantErr: true},
		{name: "no targets", rule: access.Rule{OperatorGroup: "helpdesk"}, wantErr: true},
		{name: "empty target", rule: access.Rule{OperatorGroup: "helpdesk", TargetGroups: []string{"staff", ""}}, wantErr: true},
		{
			name:    "too long",
			rule:    access.Rule{OperatorGroup: string(make([]byte, 256)), TargetGroups: []string{"staff"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.rule.Normalize()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Normalize error = %v, wantErr %v", err, tt.wantErr)
			}
			if got.OperatorGroup != tt.want.OperatorGroup || !slices.Equal(got.TargetGroups, tt.want.TargetGroups) {
				t.Errorf("Normalize = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// fakeStore serves rules from a map of operator group to target groups.
type fakeStore struct {
	rules map[string][]string
	err   error
}

func (f fakeStore) TargetGroups(_ context.Context, operatorGroups []string) ([]string, error) {
	var out []string
	for _, g := range operatorGroups {
		out = append(out, f.rules[g]...)
	}
	return out, f.err
}

func TestNewPolicy_requiresAdminGroup(t *testing.T) {
	t.Parallel()
	if _, err := access.NewPolicy(nil, fakeStore{}); err == nil {
		t.Error("NewPolicy without admin groups succeeded")
	}
}

func TestPolicy_ScopeFor(t *testing.T) {
	t.Parallel()
	store := fakeStore{rules: map[string][]string{
		"superhelp": {"*"},
		"helpdesk":  {"staff", "students"},
		"teachers":  {"students"},
	}}
	policy, err := access.NewPolicy([]string{"admins"}, store)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		groups     []string
		wantAll    bool
		wantGroups []string
		wantAdmin  bool
	}{
		{name: "admin group", groups: []string{"admins"}, wantAll: true, wantGroups: []string{}, wantAdmin: true},
		{name: "wildcard rule", groups: []string{"teachers", "superhelp"}, wantAll: true, wantGroups: []string{}},
		{name: "single rule", groups: []string{"teachers"}, wantGroups: []string{"students"}},
		{name: "union without duplicates", groups: []string{"teachers", "helpdesk"}, wantGroups: []string{"staff", "students"}},
		{name: "no matching rule", groups: []string{"guests"}, wantGroups: []string{}},
		{name: "no groups", groups: nil, wantGroups: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := policy.ScopeFor(t.Context(), tt.groups)
			if err != nil {
				t.Fatalf("ScopeFor: %v", err)
			}
			if got.All != tt.wantAll || !slices.Equal(got.Groups, tt.wantGroups) {
				t.Errorf("ScopeFor(%v) = %+v, want All=%v Groups=%v", tt.groups, got, tt.wantAll, tt.wantGroups)
			}
			if got.Empty() != (!tt.wantAll && len(tt.wantGroups) == 0) {
				t.Errorf("Empty() = %v", got.Empty())
			}
			if policy.IsAdmin(tt.groups) != tt.wantAdmin {
				t.Errorf("IsAdmin(%v) = %v, want %v", tt.groups, !tt.wantAdmin, tt.wantAdmin)
			}
		})
	}
}

func TestPolicy_ScopeFor_storeError(t *testing.T) {
	t.Parallel()
	errDown := errors.New("database down")
	policy, err := access.NewPolicy([]string{"admins"}, fakeStore{err: errDown})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.ScopeFor(t.Context(), []string{"helpdesk"}); !errors.Is(err, errDown) {
		t.Errorf("ScopeFor error = %v, want %v", err, errDown)
	}
	// Admins do not depend on the store.
	if scope, err := policy.ScopeFor(t.Context(), []string{"admins"}); err != nil || !scope.All {
		t.Errorf("ScopeFor(admins) = %+v, %v; want full access", scope, err)
	}
}

func TestScope_Allows(t *testing.T) {
	t.Parallel()
	member := func(groups ...string) *authentik.User {
		u := &authentik.User{}
		for _, g := range groups {
			u.Groups = append(u.Groups, authentik.UserGroup{Name: g})
		}
		return u
	}
	superuser := member("staff")
	superuser.IsSuperuser = true

	restricted := access.Scope{Groups: []string{"staff"}}
	tests := []struct {
		name  string
		scope access.Scope
		user  *authentik.User
		want  bool
	}{
		{name: "member", scope: restricted, user: member("other", "staff"), want: true},
		{name: "not a member", scope: restricted, user: member("students"), want: false},
		{name: "no groups", scope: restricted, user: member(), want: false},
		{name: "superuser denied for restricted", scope: restricted, user: superuser, want: false},
		{name: "full access", scope: access.Scope{All: true}, user: superuser, want: true},
		{name: "empty scope", scope: access.Scope{}, user: member("staff"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.scope.Allows(tt.user); got != tt.want {
				t.Errorf("Allows = %v, want %v", got, tt.want)
			}
		})
	}
}
