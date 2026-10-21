package store_test

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"authentikManager/internal/certificate"
	"authentikManager/internal/store"
)

// createTestCertificate stores a certificate of ann with a fresh serial, since the table is not wiped.
func createTestCertificate(t *testing.T, s *store.Store, userPK int, notAfter time.Time) certificate.Certificate {
	t.Helper()
	return createUserCertificate(t, s, userPK, "ann", notAfter)
}

// createUserCertificate stores a certificate of username with a fresh serial.
func createUserCertificate(t *testing.T, s *store.Store, userPK int, username string, notAfter time.Time) certificate.Certificate {
	t.Helper()
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		t.Fatal(err)
	}
	c, err := s.CreateCertificate(t.Context(), certificate.Certificate{
		Serial:    "f" + hex.EncodeToString(serial),
		UserPK:    userPK,
		Username:  username,
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

	duplicate := c
	duplicate.KeySource = certificate.KeySourceImported
	if _, err := s.CreateCertificate(ctx, duplicate); !errors.Is(err, certificate.ErrExists) {
		t.Errorf("CreateCertificate(duplicate serial) = %v, want ErrExists", err)
	}
	imported := duplicate
	imported.Serial = "d" + c.Serial[1:]
	got, err = s.CreateCertificate(ctx, imported)
	if err != nil || got.KeySource != certificate.KeySourceImported {
		t.Errorf("CreateCertificate(imported) = %+v, %v, want an imported certificate", got, err)
	}
}

func TestStore_getCertificateDER(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	stored, err := s.CreateCertificate(ctx, certificate.Certificate{
		Serial:    "e" + strings.Repeat("0", 20) + strconv.Itoa(uniqueUserPK()),
		UserPK:    uniqueUserPK(),
		Username:  "ann",
		Subject:   "CN=ann",
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		IssuedBy:  "ann",
		KeySource: certificate.KeySourceCSR,
		DER:       []byte{0x30, 0x03, 0x02, 0x01, 0x01},
	})
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if !stored.Stored || stored.DER != nil {
		t.Errorf("created = %+v, want it marked as stored, without its encoding", stored)
	}
	der, err := s.GetCertificateDER(ctx, stored.Serial)
	if err != nil || !slices.Equal(der, []byte{0x30, 0x03, 0x02, 0x01, 0x01}) {
		t.Errorf("GetCertificateDER = %x, %v, want the stored encoding", der, err)
	}

	old := createTestCertificate(t, s, uniqueUserPK(), time.Now().Add(time.Hour))
	if old.Stored {
		t.Error("a certificate without encoding is marked as stored")
	}
	if _, err := s.GetCertificateDER(ctx, old.Serial); !errors.Is(err, certificate.ErrNotStored) {
		t.Errorf("GetCertificateDER(without encoding) = %v, want ErrNotStored", err)
	}
	if _, err := s.GetCertificateDER(ctx, "0"); !errors.Is(err, certificate.ErrNotFound) {
		t.Errorf("GetCertificateDER(unknown) = %v, want ErrNotFound", err)
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

func TestStore_listAllCertificates(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	userPK := uniqueUserPK()
	// The underscore must match literally, not any character like in LIKE.
	prefix := fmt.Sprintf("list%d_", userPK)
	username := prefix + "ann"
	now := time.Now()

	active := createUserCertificate(t, s, userPK, username, now.Add(time.Hour))
	expired := createUserCertificate(t, s, userPK, username, now.Add(-time.Second))
	revoked := createUserCertificate(t, s, userPK, username, now.Add(time.Hour))
	if _, err := s.RevokeCertificate(ctx, revoked.Serial, "admin"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	createUserCertificate(t, s, userPK+1, fmt.Sprintf("list%dxann", userPK), now.Add(time.Hour))

	tests := []struct {
		name        string
		query       certificate.Query
		wantSerials []string
		wantTotal   int
	}{
		{name: "username", query: certificate.Query{Search: strings.ToUpper(prefix)}, wantSerials: []string{revoked.Serial, expired.Serial, active.Serial}, wantTotal: 3},
		{name: "serial prefix", query: certificate.Query{Search: strings.ToUpper(active.Serial[:20])}, wantSerials: []string{active.Serial}, wantTotal: 1},
		{name: "active", query: certificate.Query{Search: prefix, Status: certificate.StatusActive}, wantSerials: []string{active.Serial}, wantTotal: 1},
		{name: "revoked", query: certificate.Query{Search: prefix, Status: certificate.StatusRevoked}, wantSerials: []string{revoked.Serial}, wantTotal: 1},
		{name: "expired", query: certificate.Query{Search: prefix, Status: certificate.StatusExpired}, wantSerials: []string{expired.Serial}, wantTotal: 1},
		{name: "second page", query: certificate.Query{Search: prefix, Page: 2, PageSize: 2}, wantSerials: []string{active.Serial}, wantTotal: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := tt.query
			q.Page, q.PageSize = max(q.Page, 1), cmp.Or(q.PageSize, 10)
			list, total, err := s.ListAllCertificates(ctx, q, now)
			if err != nil {
				t.Fatalf("ListAllCertificates: %v", err)
			}
			serials := []string{}
			for _, c := range list {
				serials = append(serials, c.Serial)
			}
			if !slices.Equal(serials, tt.wantSerials) || total != tt.wantTotal {
				t.Errorf("ListAllCertificates = %v of %d, want %v of %d", serials, total, tt.wantSerials, tt.wantTotal)
			}
		})
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
