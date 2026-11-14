package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func newVault(t *testing.T) *Vault {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSealOpen(t *testing.T) {
	t.Parallel()
	v := newVault(t)
	// Built at run time, so that secret scanners do not report a fake.
	secret := strings.Repeat("sk", 20)

	sealed, err := v.Seal(secret, "AKLABEL")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(secret)) {
		t.Fatal("the sealed value contains the secret")
	}
	got, err := v.Open(sealed, "AKLABEL")
	if err != nil || got != secret {
		t.Fatalf("Open = %q, %v", got, err)
	}

	again, err := v.Seal(secret, "AKLABEL")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sealed, again) {
		t.Fatal("two seals of one secret are equal: the nonce is not random")
	}
}

func TestOpenRefuses(t *testing.T) {
	t.Parallel()
	v := newVault(t)
	sealed, err := v.Seal("secret", "A")
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1

	for name, tc := range map[string]struct {
		v      *Vault
		sealed []byte
		label  string
	}{
		"other label": {v, sealed, "B"},
		"other key":   {newVault(t), sealed, "A"},
		"tampered":    {v, tampered, "A"},
		"short":       {v, sealed[:4], "A"},
	} {
		if _, err := tc.v.Open(tc.sealed, tc.label); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: Open error = %v, want ErrOpen", name, err)
		}
	}
}

func TestNewChecksKeyLength(t *testing.T) {
	t.Parallel()
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("New accepted a 16-byte key")
	}
}
