// Package pki issues X.509 client certificates for users, signed by a CA whose
// certificate and private key are provided as PEM, and publishes the CA's
// certificate revocation list.
package pki

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
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// Key size limits for RSA public keys.
const (
	minRSABits = 2048
	maxRSABits = 8192
)

// MinPasswordLen is the minimum length of a PKCS#12 password.
const MinPasswordLen = 8

// clockSkew backdates NotBefore so clients with slightly wrong clocks accept new certificates.
const clockSkew = time.Minute

// crlLifetime is how long a CRL is valid; clients fetch a new one after it.
const crlLifetime = 24 * time.Hour

// pkcs12Iterations is the PBKDF2 iteration count of PKCS#12 bundles; the
// library default of 2048 is too low for user-chosen passwords.
const pkcs12Iterations = 100_000

// ErrCAExpired is returned when issuing with a CA certificate that is no longer valid.
var ErrCAExpired = errors.New("pki: ca certificate has expired")

// Options configure a CA.
type Options struct {
	// Validity is how long issued certificates are valid. It is shortened to
	// the CA certificate's own expiry.
	Validity time.Duration
	// CRLURL, when set, is embedded in issued certificates as their CRL distribution point.
	CRLURL string
}

// CA signs user certificates and revocation lists. It is safe for concurrent use.
type CA struct {
	cert *x509.Certificate
	// chain is the CA certificate followed by the intermediates from its PEM file.
	chain []*x509.Certificate
	// chainPEM is chain as PEM, served to clients.
	chainPEM []byte
	signer   crypto.Signer
	opts     Options
}

// LoadCA parses the CA certificate (optionally followed by the certificates
// above it) and its unencrypted private key, in PKCS#8, PKCS#1 or SEC 1 form.
// The first certificate must be a CA allowed to sign certificates and CRLs,
// and must match the key.
func LoadCA(certPEM, keyPEM []byte, opts Options) (*CA, error) {
	if opts.Validity <= 0 {
		return nil, errors.New("pki: validity must be positive")
	}
	chain, err := parseCertificates(certPEM)
	if err != nil {
		return nil, err
	}
	cert := chain[0]
	if !cert.IsCA {
		return nil, errors.New("pki: certificate is not a ca certificate")
	}
	const usage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage&usage != usage {
		return nil, errors.New("pki: ca certificate must allow the certSign and cRLSign key usages")
	}
	signer, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := signer.Public().(interface{ Equal(x crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("pki: private key does not match the ca certificate")
	}
	var chainPEM bytes.Buffer
	for _, c := range chain {
		chainPEM.Write(EncodeCertificate(c))
	}
	return &CA{cert: cert, chain: chain, chainPEM: chainPEM.Bytes(), signer: signer, opts: opts}, nil
}

// parseCertificates decodes every CERTIFICATE block of data, at least one.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parsing ca certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("pki: no CERTIFICATE block in ca certificate file")
	}
	return certs, nil
}

// parsePrivateKey decodes the first private key block of data.
func parsePrivateKey(data []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("pki: no private key block in ca key file")
		}
		var (
			key any
			err error
		)
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("pki: encrypted ca keys are not supported")
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("pki: parsing ca key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("pki: unsupported ca key type %T", key)
		}
		return signer, nil
	}
}

// ChainPEM returns the CA certificate and the certificates above it, as PEM.
func (ca *CA) ChainPEM() []byte {
	return bytes.Clone(ca.chainPEM)
}

// Subject identifies the user a certificate is issued to. The user's email
// address is deliberately not part of it: users and their operators can set
// it to any address without verification.
type Subject struct {
	Username string
	// UUID, when set, is the user's immutable ID, added as a urn:uuid URI SAN,
	// so relying parties can tell apart users who held the same username.
	UUID string
}

// Issue signs a client certificate for pub, which must pass ValidatePublicKey.
// The subject's common name is the username. The certificate is valid from
// shortly before now until the configured validity or the CA's expiry,
// whichever comes first.
func (ca *CA) Issue(pub crypto.PublicKey, s Subject, now time.Time) (*x509.Certificate, error) {
	if err := ValidatePublicKey(pub); err != nil {
		return nil, err
	}
	if s.Username == "" {
		return nil, errors.New("pki: username is required")
	}
	if s.UUID != "" && !isUUID(s.UUID) {
		return nil, fmt.Errorf("pki: invalid user uuid %q", s.UUID)
	}
	notAfter := now.Add(ca.opts.Validity)
	if ca.cert.NotAfter.Before(notAfter) {
		notAfter = ca.cert.NotAfter
	}
	if !notAfter.After(now) {
		return nil, ErrCAExpired
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	usage := x509.KeyUsageDigitalSignature
	if _, isRSA := pub.(*rsa.PublicKey); isRSA {
		usage |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: s.Username},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if s.UUID != "" {
		tmpl.URIs = []*url.URL{{Scheme: "urn", Opaque: "uuid:" + strings.ToLower(s.UUID)}}
	}
	if ca.opts.CRLURL != "" {
		tmpl.CRLDistributionPoints = []string{ca.opts.CRLURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("pki: signing certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parsing issued certificate: %w", err)
	}
	return cert, nil
}

// ParseCertificatesPEM decodes the CERTIFICATE blocks of data, at most limit
// of them, for importing. Other blocks, such as private keys, are ignored.
// The error is safe to show users.
func ParseCertificatesPEM(data string, limit int) ([]*x509.Certificate, error) {
	rest := []byte(data)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if len(certs) == limit {
			return nil, fmt.Errorf("at most %d certificates can be imported at once", limit)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d cannot be parsed", len(certs)+1)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM CERTIFICATE block found")
	}
	return certs, nil
}

// InChain reports whether cert is the CA certificate or one above it, as
// found in bundles next to the certificates the CA issued.
func (ca *CA) InChain(cert *x509.Certificate) bool {
	for _, c := range ca.chain {
		if c.Equal(cert) {
			return true
		}
	}
	return false
}

// CheckIssued checks that cert is an end-entity certificate the CA signed,
// identified by a serial number SerialText formats, and still valid at now,
// so that it can be imported. The error is safe to show users.
func (ca *CA) CheckIssued(cert *x509.Certificate, now time.Time) error {
	if cert.IsCA {
		return errors.New("it is a CA certificate")
	}
	if err := cert.CheckSignatureFrom(ca.cert); err != nil {
		return errors.New("it is not signed by the configured CA")
	}
	if _, ok := ParseSerial(SerialText(cert.SerialNumber)); !ok {
		return errors.New("its serial number is not a positive number of at most 160 bits")
	}
	if !now.Before(cert.NotAfter) {
		return errors.New("it has expired")
	}
	return nil
}

// IssuedSubject returns the subject Issue certified in cert: the common name
// as username and the urn:uuid URI SAN, if any, as UUID.
func IssuedSubject(cert *x509.Certificate) Subject {
	s := Subject{Username: cert.Subject.CommonName}
	for _, u := range cert.URIs {
		if id, ok := strings.CutPrefix(u.Opaque, "uuid:"); ok && u.Scheme == "urn" && isUUID(id) {
			s.UUID = strings.ToLower(id)
			break
		}
	}
	return s
}

// newSerial returns a random positive 128-bit serial number.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("pki: generating serial number: %w", err)
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

// isUUID reports whether s is a UUID in its 8-4-4-4-12 hex form.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range []byte(s) {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
			if !isHex {
				return false
			}
		}
	}
	return true
}

// SerialText formats a serial number as used to identify certificates: lowercase hex.
func SerialText(serial *big.Int) string {
	return serial.Text(16)
}

// ParseSerial parses a serial number formatted by SerialText.
func ParseSerial(s string) (*big.Int, bool) {
	if s == "" || len(s) > 40 {
		return nil, false
	}
	serial, ok := new(big.Int).SetString(s, 16)
	if !ok || serial.Sign() <= 0 || SerialText(serial) != s {
		return nil, false
	}
	return serial, true
}

// ValidatePublicKey accepts RSA keys of 2048 to 8192 bits, ECDSA keys on
// P-256, P-384 or P-521, and Ed25519 keys. The error is safe to show users.
func ValidatePublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < minRSABits || bits > maxRSABits {
			return fmt.Errorf("the key must be an RSA key of %d to %d bits", minRSABits, maxRSABits)
		}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return errors.New("the key must be an ECDSA key on the P-256, P-384 or P-521 curve")
		}
	case ed25519.PublicKey:
	default:
		return errors.New("the key type is not supported; use RSA, ECDSA or Ed25519")
	}
	return nil
}

// ParseCSR decodes a PEM certificate signing request, checks its signature and
// returns its public key. The requested subject and extensions are ignored:
// the certificate is issued for the user. The error is safe to show users.
func ParseCSR(data string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(data)))
	if block == nil || block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, errors.New("the CSR must be a PEM CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.New("the CSR cannot be parsed")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("the CSR signature is invalid")
	}
	if err := ValidatePublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr.PublicKey, nil
}

// GenerateKey returns a new ECDSA P-256 key for a user certificate.
func GenerateKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generating key: %w", err)
	}
	return key, nil
}

// EncodeCertificate returns cert as a PEM CERTIFICATE block.
func EncodeCertificate(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// PEMBundle returns the unencrypted PKCS#8 key, the certificate and the CA
// chain in one PEM file.
func (ca *CA) PEMBundle(cert *x509.Certificate, key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: encoding key: %w", err)
	}
	var buf bytes.Buffer
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	clear(der)
	buf.Write(EncodeCertificate(cert))
	buf.Write(ca.chainPEM)
	return buf.Bytes(), nil
}

// PKCS12 returns the key, the certificate and the CA chain as a PKCS#12 file
// encrypted with password, which must have at least MinPasswordLen characters.
func (ca *CA) PKCS12(cert *x509.Certificate, key crypto.Signer, password string) ([]byte, error) {
	if len([]rune(password)) < MinPasswordLen {
		return nil, fmt.Errorf("pki: password must have at least %d characters", MinPasswordLen)
	}
	pfx, err := pkcs12.Modern2023.WithIterations(pkcs12Iterations).Encode(key, cert, ca.chain, password)
	if err != nil {
		return nil, fmt.Errorf("pki: encoding pkcs12: %w", err)
	}
	return pfx, nil
}

// Revoked is a revoked certificate listed in the CRL.
type Revoked struct {
	Serial    *big.Int
	RevokedAt time.Time
}

// CRL returns a DER certificate revocation list of revoked, valid from now for
// a day. Its CRL number is derived from now, so it grows with every new CRL.
func (ca *CA) CRL(revoked []Revoked, now time.Time) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: r.Serial, RevocationTime: r.RevokedAt})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(now.UnixNano()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(crlLifetime),
	}, ca.cert, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("pki: signing crl: %w", err)
	}
	return der, nil
}
