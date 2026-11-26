package csms

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestSealAndOpen(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	plain := []byte("top-secret-connection-string")
	ct, err := seal(key, "sec-1", "v1", plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := open(key, "sec-1", "v1", ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("open = %q, want %q", got, plain)
	}

	// Wrong secret ID or version ID fails AAD verification.
	if _, err := open(key, "sec-2", "v1", ct); err == nil {
		t.Fatal("open succeeded with wrong secretID")
	}
	if _, err := open(key, "sec-1", "v2", ct); err == nil {
		t.Fatal("open succeeded with wrong versionID")
	}

	// Wrong key fails authentication.
	otherKey := make([]byte, 32)
	if _, err := rand.Read(otherKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if _, err := open(otherKey, "sec-1", "v1", ct); err == nil {
		t.Fatal("open succeeded with wrong data key")
	}
}

func TestDecodeSecretValue(t *testing.T) {
	t.Parallel()

	str := "hello"
	bin := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})

	if _, _, err := decodeSecretValue(nil, nil); !errors.Is(err, errParam) {
		t.Fatalf("neither: err = %v, want errParam", err)
	}
	if _, _, err := decodeSecretValue(&str, &bin); !errors.Is(err, errParam) {
		t.Fatalf("both: err = %v, want errParam", err)
	}
	badB64 := "not-valid-base64!!!"
	if _, _, err := decodeSecretValue(nil, &badB64); !errors.Is(err, errParam) {
		t.Fatalf("invalid base64: err = %v, want errParam", err)
	}

	maxStr := strings.Repeat("a", maxValueBytes)
	if raw, isBin, err := decodeSecretValue(&maxStr, nil); err != nil || isBin || len(raw) != maxValueBytes {
		t.Fatalf("64 KB string: len=%d isBin=%v err=%v", len(raw), isBin, err)
	}
	tooLong := strings.Repeat("a", maxValueBytes+1)
	if _, _, err := decodeSecretValue(&tooLong, nil); !errors.Is(err, errParam) {
		t.Fatalf("64 KB + 1 string: err = %v, want errParam", err)
	}

	maxBinRaw := bytes.Repeat([]byte{0x42}, maxValueBytes)
	maxBin := base64.StdEncoding.EncodeToString(maxBinRaw)
	if raw, isBin, err := decodeSecretValue(nil, &maxBin); err != nil || !isBin || len(raw) != maxValueBytes {
		t.Fatalf("64 KB binary: len=%d isBin=%v err=%v", len(raw), isBin, err)
	}
	tooLongBin := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, maxValueBytes+1))
	if _, _, err := decodeSecretValue(nil, &tooLongBin); !errors.Is(err, errParam) {
		t.Fatalf("64 KB + 1 binary: err = %v, want errParam", err)
	}
}
