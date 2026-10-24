package store_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"
	"uuid"

	"authentikManager/internal/authority"
	"authentikManager/internal/store"
)

// newTestAuthority returns a CA record with a fresh name and fingerprint,
// since the table is not wiped. Its certificate and key are placeholders: the
// store does not parse them.
func newTestAuthority(t *testing.T) authority.Authority {
	t.Helper()
	fingerprint := make([]byte, 32)
	if _, err := rand.Read(fingerprint); err != nil {
		t.Fatal(err)
	}
	return authority.Authority{
		Name:            "t-" + hex.EncodeToString(fingerprint[:8]),
		ValidityDays:    365,
		CRLValidityDays: 30,
		AllowedGroups:   []string{"staff"},
		CertPEM:         "cert",
		KeyCiphertext:   []byte("sealed"),
		Fingerprint:     fingerprint,
		CreatedBy:       "admin",
	}
}

// createTestAuthority stores a new CA.
func createTestAuthority(t *testing.T, s *store.Store) authority.Authority {
	t.Helper()
	a, err := s.CreateAuthority(t.Context(), newTestAuthority(t))
	if err != nil {
		t.Fatalf("CreateAuthority: %v", err)
	}
	return a
}

// defaultAuthorities returns the names of the default CAs, at most one.
func defaultAuthorities(t *testing.T, s *store.Store) []string {
	t.Helper()
	list, err := s.ListAuthorities(t.Context())
	if err != nil {
		t.Fatalf("ListAuthorities: %v", err)
	}
	var names []string
	for _, a := range list {
		if a.Default {
			names = append(names, a.Name)
		}
	}
	return names
}

func TestStore_listAuthorities(t *testing.T) {
	s := openTestStore(t)
	a := createTestAuthority(t, s)

	list, err := s.ListAuthorities(t.Context())
	if err != nil {
		t.Fatalf("ListAuthorities: %v", err)
	}
	i := slices.IndexFunc(list, func(got authority.Authority) bool { return got.ID == a.ID })
	if i < 0 {
		t.Fatalf("ListAuthorities lacks %q", a.Name)
	}
	if got := list[i]; got.Name != a.Name || string(got.KeyCiphertext) != "sealed" || !slices.Equal(got.AllowedGroups, []string{"staff"}) {
		t.Errorf("listed = %+v, want %+v", got, a)
	}
	if !slices.IsSortedFunc(list, func(x, y authority.Authority) int {
		switch {
		case x.Name < y.Name:
			return -1
		case x.Name > y.Name:
			return 1
		}
		return 0
	}) {
		t.Error("ListAuthorities is not ordered by name")
	}
}

func TestStore_createAuthority(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	a := createTestAuthority(t, s)
	if a.ID == (uuid.UUID{}) || a.CreatedAt.IsZero() || a.Legacy || a.Disabled {
		t.Errorf("created = %+v, want an enabled, non-legacy CA with ID and creation time", a)
	}
	if names := defaultAuthorities(t, s); len(names) != 1 {
		t.Errorf("default CAs = %v, want exactly one", names)
	}

	sameName := newTestAuthority(t)
	sameName.Name = a.Name
	if _, err := s.CreateAuthority(ctx, sameName); !errors.Is(err, authority.ErrExists) {
		t.Errorf("CreateAuthority(same name) = %v, want ErrExists", err)
	}
	sameCert := newTestAuthority(t)
	sameCert.Fingerprint = a.Fingerprint
	if _, err := s.CreateAuthority(ctx, sameCert); !errors.Is(err, authority.ErrExists) {
		t.Errorf("CreateAuthority(same certificate) = %v, want ErrExists", err)
	}
}

func TestStore_updateAuthority(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	a := createTestAuthority(t, s)

	settings := authority.Settings{
		Description:     "staff CA",
		CRLURL:          "https://am.example.com/pki/" + a.Name + "/crl",
		ValidityDays:    90,
		CRLValidityDays: 7,
		UserCNSuffix:    "@example.com",
		AllowedGroups:   []string{"admins", "staff"},
	}
	if err := s.SetDefaultAuthority(ctx, a.ID); err != nil {
		t.Fatalf("SetDefaultAuthority: %v", err)
	}
	if _, err := s.UpdateAuthority(ctx, a.ID, settings, true); !errors.Is(err, authority.ErrDefaultDisabled) {
		t.Errorf("UpdateAuthority(disable default) = %v, want ErrDefaultDisabled", err)
	}

	other := createTestAuthority(t, s)
	if err := s.SetDefaultAuthority(ctx, other.ID); err != nil {
		t.Fatalf("SetDefaultAuthority(other): %v", err)
	}
	if names := defaultAuthorities(t, s); !slices.Equal(names, []string{other.Name}) {
		t.Errorf("default CAs = %v, want [%s]", names, other.Name)
	}
	updated, err := s.UpdateAuthority(ctx, a.ID, settings, true)
	if err != nil {
		t.Fatalf("UpdateAuthority: %v", err)
	}
	if !updated.Disabled || updated.Description != "staff CA" || updated.ValidityDays != 90 ||
		!slices.Equal(updated.AllowedGroups, settings.AllowedGroups) || updated.Name != a.Name {
		t.Errorf("updated = %+v, want the new settings, disabled", updated)
	}
	if err := s.SetDefaultAuthority(ctx, a.ID); !errors.Is(err, authority.ErrDefaultDisabled) {
		t.Errorf("SetDefaultAuthority(disabled) = %v, want ErrDefaultDisabled", err)
	}

	if _, err := s.UpdateAuthority(ctx, uuid.New(), settings, false); !errors.Is(err, authority.ErrNotFound) {
		t.Errorf("UpdateAuthority(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.SetDefaultAuthority(ctx, uuid.New()); !errors.Is(err, authority.ErrNotFound) {
		t.Errorf("SetDefaultAuthority(unknown) = %v, want ErrNotFound", err)
	}
}

func TestStore_importLegacyAuthority(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	before := createCACertificate(t, s, uuid.UUID{}, uniqueUserPK(), "ann", time.Now().Add(time.Hour))

	a := newTestAuthority(t)
	stored, err := s.ImportLegacyAuthority(ctx, a)
	if err != nil {
		t.Fatalf("ImportLegacyAuthority: %v", err)
	}
	got, err := s.GetCertificate(ctx, before.Serial)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	// The table is not wiped, so an earlier run may have imported the legacy CA.
	if stored.Legacy && got.CAID != stored.ID {
		t.Errorf("certificate recorded before CAs has CA %v, want the legacy CA %v", got.CAID, stored.ID)
	}
	if !stored.Legacy && got.CAID != (uuid.UUID{}) {
		t.Errorf("certificate recorded before CAs has CA %v, want none: there was a legacy CA", got.CAID)
	}

	again := a
	again.Name = a.Name + "-x"
	again.Description = "changed"
	restored, err := s.ImportLegacyAuthority(ctx, again)
	if err != nil {
		t.Fatalf("second ImportLegacyAuthority: %v", err)
	}
	if restored.ID != stored.ID || restored.Name != a.Name || restored.Description != "" {
		t.Errorf("second import = %+v, want the stored CA %+v unchanged", restored, stored)
	}

	clash := newTestAuthority(t)
	clash.Name = a.Name
	if _, err := s.ImportLegacyAuthority(ctx, clash); !errors.Is(err, authority.ErrExists) {
		t.Errorf("ImportLegacyAuthority(another CA, same name) = %v, want ErrExists", err)
	}
}
