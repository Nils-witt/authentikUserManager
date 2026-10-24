package pki_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"authentikManager/internal/pki"
)

func TestNewKeyCipher(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := pki.NewKeyCipher(make([]byte, n)); err == nil {
			t.Errorf("NewKeyCipher(%d bytes) succeeded, want an error", n)
		}
	}
}

func TestKeyCipher_SealOpen(t *testing.T) {
	t.Parallel()
	c, err := pki.NewKeyCipher(bytes.Repeat([]byte{1}, pki.KeyCipherKeyLen))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("-----BEGIN PRIVATE KEY-----")
	sealed, err := c.Seal(plaintext, []byte("main"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Error("sealed key holds the plaintext")
	}
	again, err := c.Seal(plaintext, []byte("main"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sealed, again) {
		t.Error("sealing twice gave the same ciphertext; the nonce must be random")
	}
	got, err := c.Open(sealed, []byte("main"))
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Errorf("Open = %q, %v, want the plaintext", got, err)
	}

	other, err := pki.NewKeyCipher(bytes.Repeat([]byte{2}, pki.KeyCipherKeyLen))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	tests := []struct {
		name   string
		cipher *pki.KeyCipher
		sealed []byte
		aad    string
	}{
		{name: "other ca name", cipher: c, sealed: sealed, aad: "other"},
		{name: "other key", cipher: other, sealed: sealed, aad: "main"},
		{name: "tampered", cipher: c, sealed: tampered, aad: "main"},
		{name: "too short", cipher: c, sealed: sealed[:5], aad: "main"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tt.cipher.Open(tt.sealed, []byte(tt.aad)); err == nil {
				t.Error("Open succeeded, want an error")
			}
		})
	}
}

func TestNormalizeKeyPEM(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, ecKey(t), true, caUsage, 24*time.Hour)
	// A key file may hold other blocks, such as the certificate.
	normalized, err := pki.NormalizeKeyPEM(append(bytes.Clone(ca.certPEM), ca.keyPEM...))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(normalized), "BEGIN") != 1 || !strings.HasPrefix(string(normalized), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("normalized = %s, want a single PKCS#8 block", normalized)
	}
	if _, err := pki.NormalizeKeyPEM(ca.certPEM); err == nil {
		t.Error("NormalizeKeyPEM without a key succeeded, want an error")
	}
}
