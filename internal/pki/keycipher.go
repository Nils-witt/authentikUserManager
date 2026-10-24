package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// KeyCipherKeyLen is the length of the key of a KeyCipher (AES-256).
const KeyCipherKeyLen = 32

// KeyCipher encrypts CA private keys at rest with AES-256-GCM, so that the
// database alone cannot sign certificates. It is safe for concurrent use.
type KeyCipher struct {
	aead cipher.AEAD
}

// NewKeyCipher returns a KeyCipher with key, which must have KeyCipherKeyLen bytes.
func NewKeyCipher(key []byte) (*KeyCipher, error) {
	if len(key) != KeyCipherKeyLen {
		return nil, fmt.Errorf("pki: key cipher key must have %d bytes", KeyCipherKeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pki: creating key cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pki: creating key cipher: %w", err)
	}
	return &KeyCipher{aead: aead}, nil
}

// Seal encrypts plaintext bound to aad, e.g. the name of the CA whose key it
// is, so a sealed key cannot be moved to another CA. The nonce is prepended.
func (c *KeyCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize(), c.aead.NonceSize()+len(plaintext)+c.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("pki: generating nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open decrypts what Seal returned for the same aad.
func (c *KeyCipher) Open(sealed, aad []byte) ([]byte, error) {
	n := c.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("pki: sealed key is too short")
	}
	plaintext, err := c.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, errors.New("pki: decrypting key failed; is CA_ENCRYPTION_KEY the key it was stored with?")
	}
	return plaintext, nil
}

// NormalizeKeyPEM returns the first private key of keyPEM, in any form
// LoadCA accepts, as an unencrypted PKCS#8 PEM block, dropping everything
// else the file holds.
func NormalizeKeyPEM(keyPEM []byte) ([]byte, error) {
	signer, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("pki: encoding ca key: %w", err)
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Fingerprint returns the SHA-256 hash of the DER encoding of cert.
func Fingerprint(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}
