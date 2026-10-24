package authority_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"
	"uuid"

	"authentikManager/internal/authority"
	"authentikManager/internal/pki"
)

// newRecord returns the record of a new self-signed CA named name with a new
// ID, its key sealed by r.
func newRecord(t *testing.T, r *authority.Registry, name string) authority.Authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	sealed, err := r.SealKey(id, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return authority.Authority{
		ID:           id,
		Name:         name,
		ValidityDays: 1, CRLValidityDays: 1,
		CertPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyCiphertext: sealed,
	}
}

func newRegistry(t *testing.T) *authority.Registry {
	t.Helper()
	cipher, err := pki.NewKeyCipher(make([]byte, pki.KeyCipherKeyLen))
	if err != nil {
		t.Fatal(err)
	}
	return authority.NewRegistry(cipher)
}

func names(entries []*authority.Entry) []string {
	out := []string{}
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out
}

func TestRegistry_Load(t *testing.T) {
	t.Parallel()
	r := newRegistry(t)
	if _, ok := r.Default(); ok || len(r.All()) != 0 {
		t.Fatal("a new registry is not empty")
	}

	zeta, alpha := newRecord(t, r, "zeta"), newRecord(t, r, "alpha")
	zeta.Default = true
	if err := r.Load([]authority.Authority{zeta, alpha}); err != nil {
		t.Fatal(err)
	}
	if got := names(r.All()); len(got) != 2 || got[0] != "alpha" || got[1] != "zeta" {
		t.Errorf("All = %v, want [alpha zeta]", got)
	}
	if e, ok := r.ByID(alpha.ID); !ok || e.Name != "alpha" || e.CA.Certificate().Subject.CommonName != "alpha" {
		t.Errorf("ByID(alpha's id) = %v, %v, want alpha", e, ok)
	}
	if _, ok := r.ByID(uuid.New()); ok {
		t.Error("ByID(unknown id) found a CA")
	}

	// A CA whose key does not open keeps the CAs loaded before.
	broken := newRecord(t, r, "broken")
	broken.ID = uuid.New()
	if err := r.Load([]authority.Authority{broken}); err == nil {
		t.Error("Load with a key sealed for another id succeeded")
	}
	if len(r.All()) != 2 {
		t.Errorf("after a failed Load, %d CAs are loaded, want the 2 before", len(r.All()))
	}
}

func TestRegistry_DefaultAndLegacy(t *testing.T) {
	t.Parallel()
	r := newRegistry(t)
	main, other := newRecord(t, r, "main"), newRecord(t, r, "other")
	other.Default = true
	if err := r.Load([]authority.Authority{main, other}); err != nil {
		t.Fatal(err)
	}
	if e, ok := r.Legacy(); !ok || e.Name != "other" {
		t.Errorf("Legacy without a legacy CA = %v, want the default CA", e)
	}
	main.Legacy = true
	if err := r.Load([]authority.Authority{main, other}); err != nil {
		t.Fatal(err)
	}
	if e, ok := r.Legacy(); !ok || e.Name != "main" {
		t.Errorf("Legacy = %v, want main", e)
	}
	if e, ok := r.Default(); !ok || e.Name != "other" {
		t.Errorf("Default = %v, want other", e)
	}
}

func TestRegistry_Usable(t *testing.T) {
	t.Parallel()
	r := newRegistry(t)
	a, b, c, d := newRecord(t, r, "a"), newRecord(t, r, "b"), newRecord(t, r, "c"), newRecord(t, r, "d")
	c.Default = true
	b.AllowedGroups = []string{"staff"}
	d.Disabled = true
	if err := r.Load([]authority.Authority{a, b, c, d}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		groups   []string
		expected []string
	}{
		{name: "no groups", expected: []string{"c", "a"}},
		{name: "staff", groups: []string{"staff"}, expected: []string{"c", "a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := names(r.Usable(tt.groups)); !slices.Equal(got, tt.expected) {
				t.Errorf("Usable = %v, want %v", got, tt.expected)
			}
		})
	}
}
