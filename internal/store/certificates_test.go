package store_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"authentikManager/internal/certificate"
	"authentikManager/internal/store"
)

// createTestCertificate stores a certificate with a fresh serial, since the table is not wiped.
func createTestCertificate(t *testing.T, s *store.Store, userPK int, notAfter time.Time) certificate.Certificate {
	t.Helper()
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		t.Fatal(err)
	}
	c, err := s.CreateCertificate(t.Context(), certificate.Certificate{
		Serial:    "f" + hex.EncodeToString(serial),
		UserPK:    userPK,
		Username:  "ann",
		Subject:   "CN=ann",
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  notAfter,
		IssuedBy:  "ann",
		KeySource: certificate.KeySourceGenerated,
	})
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return c
}

// uniqueUserPK returns a user key no other test run used, since the table is not wiped.
func uniqueUserPK() int {
	return int(time.Now().UnixNano() % 1_000_000_000)
}

func TestStore_createCertificate(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	c := createTestCertificate(t, s, uniqueUserPK(), time.Now().Add(time.Hour))
	if c.IssuedAt.IsZero() || c.RevokedAt != nil || c.RevokedBy != "" || c.KeySource != certificate.KeySourceGenerated {
		t.Errorf("created = %+v, want an unrevoked certificate with issue time", c)
	}
	got, err := s.GetCertificate(ctx, c.Serial)
	if err != nil || got.Serial != c.Serial || got.Subject != "CN=ann" {
		t.Errorf("GetCertificate = %+v, %v, want the created certificate", got, err)
	}
	if _, err := s.GetCertificate(ctx, "0"); !errors.Is(err, certificate.ErrNotFound) {
		t.Errorf("GetCertificate(unknown) = %v, want ErrNotFound", err)
	}
}

func TestStore_listCertificates(t *testing.T) {
	s := openTestStore(t)
	userPK := uniqueUserPK()

	first := createTestCertificate(t, s, userPK, time.Now().Add(time.Hour))
	second := createTestCertificate(t, s, userPK, time.Now().Add(time.Hour))
	createTestCertificate(t, s, userPK+1, time.Now().Add(time.Hour))

	list, err := s.ListCertificates(t.Context(), userPK)
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	serials := []string{}
	for _, c := range list {
		serials = append(serials, c.Serial)
	}
	if len(serials) != 2 || !slices.Contains(serials, first.Serial) || !slices.Contains(serials, second.Serial) {
		t.Errorf("ListCertificates = %v, want the user's two certificates", serials)
	}
	empty, err := s.ListCertificates(t.Context(), -1)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Errorf("ListCertificates(unknown) = %v, %v, want an empty list", empty, err)
	}
}

func TestStore_revokeCertificate(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	userPK := uniqueUserPK()

	valid := createTestCertificate(t, s, userPK, time.Now().Add(time.Hour))
	expired := createTestCertificate(t, s, userPK, time.Now().Add(-time.Second))

	revoked, err := s.RevokeCertificate(ctx, valid.Serial, "admin")
	if err != nil || revoked.RevokedAt == nil || revoked.RevokedBy != "admin" {
		t.Fatalf("RevokeCertificate = %+v, %v, want it revoked by admin", revoked, err)
	}
	if _, err := s.RevokeCertificate(ctx, valid.Serial, "admin"); !errors.Is(err, certificate.ErrRevoked) {
		t.Errorf("second RevokeCertificate = %v, want ErrRevoked", err)
	}
	if _, err := s.RevokeCertificate(ctx, "0", "admin"); !errors.Is(err, certificate.ErrNotFound) {
		t.Errorf("RevokeCertificate(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := s.RevokeCertificate(ctx, expired.Serial, "admin"); err != nil {
		t.Fatalf("RevokeCertificate(expired): %v", err)
	}

	list, err := s.ListRevokedCertificates(ctx, time.Now())
	if err != nil {
		t.Fatalf("ListRevokedCertificates: %v", err)
	}
	hasSerial := func(serial string) bool {
		return slices.ContainsFunc(list, func(r certificate.Revoked) bool { return r.Serial == serial })
	}
	if !hasSerial(valid.Serial) || hasSerial(expired.Serial) {
		t.Errorf("ListRevokedCertificates = %+v, want the valid revoked certificate only", list)
	}
}

func TestStore_revokeUserCertificates(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	userPK := uniqueUserPK()

	first := createTestCertificate(t, s, userPK, time.Now().Add(time.Hour))
	second := createTestCertificate(t, s, userPK, time.Now().Add(time.Hour))
	already := createTestCertificate(t, s, userPK, time.Now().Add(time.Hour))
	other := createTestCertificate(t, s, userPK+1, time.Now().Add(time.Hour))
	if _, err := s.RevokeCertificate(ctx, already.Serial, "ann"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	serials, err := s.RevokeUserCertificates(ctx, userPK, "admin")
	if err != nil {
		t.Fatalf("RevokeUserCertificates: %v", err)
	}
	slices.Sort(serials)
	want := []string{first.Serial, second.Serial}
	slices.Sort(want)
	if !slices.Equal(serials, want) {
		t.Errorf("RevokeUserCertificates = %v, want %v", serials, want)
	}
	for _, c := range []certificate.Certificate{first, second, already, other} {
		got, err := s.GetCertificate(ctx, c.Serial)
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		switch c.Serial {
		case other.Serial:
			if got.RevokedAt != nil {
				t.Error("another user's certificate was revoked")
			}
		case already.Serial:
			if got.RevokedBy != "ann" {
				t.Errorf("already revoked certificate now revoked by %q, want ann", got.RevokedBy)
			}
		default:
			if got.RevokedAt == nil || got.RevokedBy != "admin" {
				t.Errorf("certificate %s = %+v, want it revoked by admin", c.Serial, got)
			}
		}
	}

	none, err := s.RevokeUserCertificates(ctx, userPK, "admin")
	if err != nil || len(none) != 0 {
		t.Errorf("second RevokeUserCertificates = %v, %v, want an empty list", none, err)
	}
}
