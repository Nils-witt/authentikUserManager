package pki_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"authentikManager/internal/pki"
)

// testCA describes a self-signed CA for the tests.
type testCA struct {
	certPEM, keyPEM []byte
	cert            *x509.Certificate
}

// newTestCA returns a self-signed CA with key, valid for validFor, with usage.
func newTestCA(t *testing.T, key crypto.Signer, isCA bool, usage x509.KeyUsage, validFor time.Duration) testCA {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validFor),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		cert:    cert,
	}
}

const caUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func loadCA(t *testing.T, ca testCA, opts pki.Options) *pki.CA {
	t.Helper()
	loaded, err := pki.LoadCA(ca.certPEM, ca.keyPEM, opts)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return loaded
}

var defaultOpts = pki.Options{Validity: 365 * 24 * time.Hour}

func TestLoadCA(t *testing.T) {
	t.Parallel()
	key := ecKey(t)
	good := newTestCA(t, key, true, caUsage, 24*time.Hour)
	other := newTestCA(t, ecKey(t), true, caUsage, 24*time.Hour)
	notCA := newTestCA(t, key, false, x509.KeyUsageDigitalSignature, 24*time.Hour)
	noCRLSign := newTestCA(t, key, true, x509.KeyUsageCertSign, 24*time.Hour)
	ecDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sec1 := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	rsaCAKey := rsaKey(t, 2048)
	rsaCA := newTestCA(t, rsaCAKey, true, caUsage, 24*time.Hour)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaCAKey)})

	tests := []struct {
		name    string
		certPEM []byte
		keyPEM  []byte
		opts    pki.Options
		wantErr string
	}{
		{name: "pkcs8 ecdsa", certPEM: good.certPEM, keyPEM: good.keyPEM, opts: defaultOpts},
		{name: "sec1 ecdsa", certPEM: good.certPEM, keyPEM: sec1, opts: defaultOpts},
		{name: "pkcs1 rsa", certPEM: rsaCA.certPEM, keyPEM: pkcs1, opts: defaultOpts},
		{name: "key mismatch", certPEM: good.certPEM, keyPEM: other.keyPEM, opts: defaultOpts, wantErr: "does not match"},
		{name: "not a ca", certPEM: notCA.certPEM, keyPEM: good.keyPEM, opts: defaultOpts, wantErr: "not a ca"},
		{name: "missing crl sign", certPEM: noCRLSign.certPEM, keyPEM: good.keyPEM, opts: defaultOpts, wantErr: "cRLSign"},
		{name: "no certificate", certPEM: good.keyPEM, keyPEM: good.keyPEM, opts: defaultOpts, wantErr: "no CERTIFICATE"},
		{name: "no key", certPEM: good.certPEM, keyPEM: good.certPEM, opts: defaultOpts, wantErr: "no private key"},
		{
			name:    "encrypted key",
			certPEM: good.certPEM,
			keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}),
			opts:    defaultOpts,
			wantErr: "encrypted",
		},
		{name: "zero validity", certPEM: good.certPEM, keyPEM: good.keyPEM, wantErr: "validity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := pki.LoadCA(tt.certPEM, tt.keyPEM, tt.opts)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("LoadCA: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("LoadCA = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCA_ChainPEM(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, ecKey(t), true, caUsage, 24*time.Hour)
	loaded := loadCA(t, ca, defaultOpts)
	if got := loaded.ChainPEM(); !bytes.Equal(got, ca.certPEM) {
		t.Errorf("ChainPEM = %q, want the CA certificate", got)
	}
}

func TestCA_Issue(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, ecKey(t), true, caUsage, 30*24*time.Hour)
	loaded := loadCA(t, ca, pki.Options{Validity: 365 * 24 * time.Hour, CRLURL: "https://example.com/pki/crl"})
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	now := time.Now()

	tests := []struct {
		name      string
		pub       crypto.PublicKey
		uuid      string
		wantURIs  string
		wantUsage x509.KeyUsage
	}{
		{
			name:      "ecdsa with uuid",
			pub:       ecKey(t).Public(),
			uuid:      "6F1C2A9E-3B4D-4E5F-8A9B-0C1D2E3F4A5B",
			wantURIs:  "urn:uuid:6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
			wantUsage: x509.KeyUsageDigitalSignature,
		},
		{name: "rsa without uuid", pub: rsaKey(t, 2048).Public(), wantUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert, err := loaded.Issue(tt.pub, pki.Subject{Username: "ann", UUID: tt.uuid}, now)
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Errorf("Verify: %v", err)
			}
			if cert.Subject.CommonName != "ann" || cert.IsCA || cert.KeyUsage != tt.wantUsage {
				t.Errorf("cert subject %q, CA %v, usage %v", cert.Subject.CommonName, cert.IsCA, cert.KeyUsage)
			}
			checkSANs(t, cert, tt.wantURIs)
			if !cert.NotAfter.Equal(ca.cert.NotAfter) {
				t.Errorf("NotAfter = %v, want it clamped to the CA's %v", cert.NotAfter, ca.cert.NotAfter)
			}
			if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != "https://example.com/pki/crl" {
				t.Errorf("CRLDistributionPoints = %v", cert.CRLDistributionPoints)
			}
			if cert.SerialNumber.Sign() <= 0 {
				t.Errorf("serial %v is not positive", cert.SerialNumber)
			}
		})
	}
}

// checkSANs checks that the only SANs of cert are the comma-separated wantURIs.
func checkSANs(t *testing.T, cert *x509.Certificate, wantURIs string) {
	t.Helper()
	var uris []string
	for _, u := range cert.URIs {
		uris = append(uris, u.String())
	}
	if got := strings.Join(uris, ","); got != wantURIs {
		t.Errorf("URIs = %q, want %q", got, wantURIs)
	}
	if len(cert.EmailAddresses) != 0 || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Errorf("unexpected SANs: email %v, DNS %v, IP %v", cert.EmailAddresses, cert.DNSNames, cert.IPAddresses)
	}
}

func TestCA_Issue_errors(t *testing.T) {
	t.Parallel()
	ca := loadCA(t, newTestCA(t, ecKey(t), true, caUsage, 24*time.Hour), defaultOpts)
	if _, err := ca.Issue(rsaKey(t, 1024).Public(), pki.Subject{Username: "ann"}, time.Now()); err == nil {
		t.Error("Issue with a 1024-bit RSA key succeeded")
	}
	if _, err := ca.Issue(ecKey(t).Public(), pki.Subject{}, time.Now()); err == nil {
		t.Error("Issue without a username succeeded")
	}
	for _, uuid := range []string{"not-a-uuid", "6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5", "6f1c2a9e/3b4d-4e5f-8a9b-0c1d2e3f4a5b", "6f1c2a9e-3b4d-4e5f-8a9b-0c1d2e3f4a5g"} {
		if _, err := ca.Issue(ecKey(t).Public(), pki.Subject{Username: "ann", UUID: uuid}, time.Now()); err == nil {
			t.Errorf("Issue with uuid %q succeeded", uuid)
		}
	}
	if _, err := ca.Issue(ecKey(t).Public(), pki.Subject{Username: "ann"}, time.Now().Add(48*time.Hour)); !errors.Is(err, pki.ErrCAExpired) {
		t.Errorf("Issue after the CA expired = %v, want ErrCAExpired", err)
	}
}

func TestParseSerial(t *testing.T) {
	t.Parallel()
	serial := new(big.Int).Lsh(big.NewInt(1), 127)
	tests := []struct {
		name  string
		input string
		ok    bool
	}{
		{name: "formatted serial", input: pki.SerialText(serial), ok: true},
		{name: "empty", input: ""},
		{name: "upper case", input: "ABC"},
		{name: "leading zero", input: "0abc"},
		{name: "zero", input: "0"},
		{name: "negative", input: "-1"},
		{name: "not hex", input: "xyz"},
		{name: "too long", input: strings.Repeat("f", 41)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := pki.ParseSerial(tt.input)
			if ok != tt.ok || ok && pki.SerialText(got) != tt.input {
				t.Errorf("ParseSerial(%q) = %v, %v, want ok %v", tt.input, got, ok, tt.ok)
			}
		})
	}
}

func TestValidatePublicKey(t *testing.T) {
	t.Parallel()
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		pub  crypto.PublicKey
		ok   bool
	}{
		{name: "ecdsa p-256", pub: ecKey(t).Public(), ok: true},
		{name: "rsa 2048", pub: rsaKey(t, 2048).Public(), ok: true},
		{name: "ed25519", pub: edPub, ok: true},
		{name: "rsa 1024", pub: rsaKey(t, 1024).Public()},
		{name: "ecdsa p-224", pub: p224.Public()},
		{name: "unknown type", pub: "key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := pki.ValidatePublicKey(tt.pub); (err == nil) != tt.ok {
				t.Errorf("ValidatePublicKey = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

// newCSR returns a PEM CSR signed by key.
func newCSR(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "root"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestParseCSR(t *testing.T) {
	t.Parallel()
	key := ecKey(t)
	valid := newCSR(t, key)
	block, _ := pem.Decode([]byte(valid))
	tampered := bytes.Clone(block.Bytes)
	tampered[len(tampered)-1] ^= 0xff
	badSig := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}))

	tests := []struct {
		name  string
		input string
		ok    bool
	}{
		{name: "valid", input: "\n" + valid, ok: true},
		{name: "weak rsa key", input: newCSR(t, rsaKey(t, 1024))},
		{name: "bad signature", input: badSig},
		{name: "not pem", input: "hello"},
		{name: "wrong block type", input: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pub, err := pki.ParseCSR(tt.input)
			if (err == nil) != tt.ok {
				t.Fatalf("ParseCSR = %v, want ok %v", err, tt.ok)
			}
			if tt.ok && !key.PublicKey.Equal(pub) {
				t.Error("ParseCSR returned another public key")
			}
		})
	}
}

func TestCA_PEMBundle(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, ecKey(t), true, caUsage, 24*time.Hour)
	loaded := loadCA(t, ca, defaultOpts)
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := loaded.Issue(key.Public(), pki.Subject{Username: "ann"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := loaded.PEMBundle(cert, key)
	if err != nil {
		t.Fatalf("PEMBundle: %v", err)
	}
	var types []string
	for rest := bundle; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		types = append(types, block.Type)
	}
	if got := strings.Join(types, ","); got != "PRIVATE KEY,CERTIFICATE,CERTIFICATE" {
		t.Errorf("bundle blocks = %s, want key, certificate and CA", got)
	}
}

func TestCA_PKCS12(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, ecKey(t), true, caUsage, 24*time.Hour)
	loaded := loadCA(t, ca, defaultOpts)
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := loaded.Issue(key.Public(), pki.Subject{Username: "ann"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.PKCS12(cert, key, "short"); err == nil {
		t.Error("PKCS12 with a short password succeeded")
	}
	pfx, err := loaded.PKCS12(cert, key, "correct horse")
	if err != nil {
		t.Fatalf("PKCS12: %v", err)
	}
	gotKey, gotCert, chain, err := pkcs12.DecodeChain(pfx, "correct horse")
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	signer, ok := gotKey.(crypto.Signer)
	if !ok || !gotCert.Equal(cert) || len(chain) != 1 || !chain[0].Equal(ca.cert) || !key.Public().(*ecdsa.PublicKey).Equal(signer.Public()) {
		t.Error("PKCS12 does not round-trip the key, certificate and CA")
	}
}

func TestCA_CRL(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, ecKey(t), true, caUsage, 24*time.Hour)
	loaded := loadCA(t, ca, defaultOpts)
	now := time.Now().Truncate(time.Second)
	der, err := loaded.CRL([]pki.Revoked{{Serial: big.NewInt(42), RevokedAt: now.Add(-time.Hour)}}, now)
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("CheckSignatureFrom: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Int64() != 42 {
		t.Errorf("revoked = %+v, want serial 42", crl.RevokedCertificateEntries)
	}
	later, err := loaded.CRL(nil, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	laterCRL, err := x509.ParseRevocationList(later)
	if err != nil {
		t.Fatal(err)
	}
	if laterCRL.Number.Cmp(crl.Number) <= 0 {
		t.Errorf("CRL number %v did not grow from %v", laterCRL.Number, crl.Number)
	}
}
