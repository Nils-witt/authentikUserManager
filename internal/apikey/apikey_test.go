package apikey_test

import (
	"bytes"
	"strings"
	"testing"

	"authentikManager/internal/apikey"
)

func TestNew(t *testing.T) {
	t.Parallel()
	key, start, hash := apikey.New()
	if !apikey.WellFormed(key) {
		t.Errorf("New() key %q is not well formed", key)
	}
	if !strings.HasPrefix(key, start) || len(start) >= len(key) {
		t.Errorf("New() start %q is not a proper start of %q", start, key)
	}
	if !bytes.Equal(hash, apikey.Hash(key)) {
		t.Error("New() hash differs from Hash(key)")
	}
	other, _, _ := apikey.New()
	if other == key {
		t.Error("New() returned the same key twice")
	}
}

func TestHash(t *testing.T) {
	t.Parallel()
	if !bytes.Equal(apikey.Hash("a"), apikey.Hash("a")) {
		t.Error("Hash is not stable")
	}
	if bytes.Equal(apikey.Hash("a"), apikey.Hash("b")) {
		t.Error("Hash of different keys is equal")
	}
}

func TestWellFormed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{name: "valid", key: "amk_ABCDEFGHIJKLMNOPQRSTUVWXYZ", expected: true},
		{name: "empty", key: "", expected: false},
		{name: "missing prefix", key: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", expected: false},
		{name: "too short", key: "amk_ABCDEFGHIJKLMNOPQRSTUVWXY", expected: false},
		{name: "too long", key: "amk_ABCDEFGHIJKLMNOPQRSTUVWXYZA", expected: false},
		{name: "lowercase", key: "amk_abcdefghijklmnopqrstuvwxyz", expected: false},
		{name: "outside alphabet", key: "amk_ABCDEFGHIJKLMNOPQRSTUVWXY1", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := apikey.WellFormed(tt.key); got != tt.expected {
				t.Errorf("WellFormed(%q) = %v, want %v", tt.key, got, tt.expected)
			}
		})
	}
}
