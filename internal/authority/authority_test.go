package authority_test

import (
	"slices"
	"strings"
	"testing"

	"authentikManager/internal/authority"
)

func TestSettings_Normalize(t *testing.T) {
	t.Parallel()
	got, err := authority.Settings{
		Description:   "  staff  ",
		CRLURL:        " https://am.example.com/pki/staff/crl ",
		UserCNSuffix:  " @example.com ",
		AllowedGroups: []string{"staff", " admins", "", "staff"},
	}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	want := authority.Settings{
		Description:     "staff",
		CRLURL:          "https://am.example.com/pki/staff/crl",
		ValidityDays:    authority.DefaultValidityDays,
		CRLValidityDays: authority.DefaultCRLValidityDays,
		UserCNSuffix:    "@example.com",
		AllowedGroups:   []string{"admins", "staff"},
	}
	if got.Description != want.Description || got.CRLURL != want.CRLURL || got.ValidityDays != want.ValidityDays ||
		got.CRLValidityDays != want.CRLValidityDays || got.UserCNSuffix != want.UserCNSuffix ||
		!slices.Equal(got.AllowedGroups, want.AllowedGroups) {
		t.Errorf("Normalize = %+v, want %+v", got, want)
	}
}

func TestSettings_Normalize_errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		settings authority.Settings
		message  string
	}{
		{name: "relative crl url", settings: authority.Settings{CRLURL: "/pki/crl"}, message: "CRL URL"},
		{name: "ldap crl url", settings: authority.Settings{CRLURL: "ldap://example.com/crl"}, message: "CRL URL"},
		{name: "negative validity", settings: authority.Settings{ValidityDays: -1}, message: "validity"},
		{name: "validity too long", settings: authority.Settings{ValidityDays: authority.MaxValidityDays + 1}, message: "validity"},
		{name: "crl validity too long", settings: authority.Settings{CRLValidityDays: authority.MaxCRLValidityDays + 1}, message: "CRL validity"},
		{name: "description too long", settings: authority.Settings{Description: strings.Repeat("a", 501)}, message: "description"},
		{name: "suffix too long", settings: authority.Settings{ServiceAccountCNSuffix: strings.Repeat("a", 65)}, message: "suffix"},
		{name: "too many groups", settings: authority.Settings{AllowedGroups: manyGroups(101)}, message: "groups"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tt.settings.Normalize(); err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Errorf("Normalize error = %v, want one mentioning %q", err, tt.message)
			}
		})
	}
}

func manyGroups(n int) []string {
	groups := make([]string, n)
	for i := range groups {
		groups[i] = "g" + strings.Repeat("x", i)
	}
	return groups
}

func TestValidateName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"a", "main", "staff-ca", "2026", strings.Repeat("a", 32)} {
		if err := authority.ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"", "-ca", "Main", "staff ca", "a/b", "ca.", strings.Repeat("a", 33)} {
		if err := authority.ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) succeeded, want an error", name)
		}
	}
}

func TestAuthority_Allows(t *testing.T) {
	t.Parallel()
	open := authority.Authority{}
	if !open.Allows(nil) {
		t.Error("a CA without allowed groups refuses an account without groups")
	}
	staff := authority.Authority{AllowedGroups: []string{"staff"}}
	if !staff.Allows([]string{"teachers", "staff"}) || staff.Allows([]string{"teachers"}) || staff.Allows(nil) {
		t.Error("a CA for staff must allow staff members only")
	}
}
