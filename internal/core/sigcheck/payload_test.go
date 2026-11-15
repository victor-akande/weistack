package sigcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCheckPayload(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("hello"))
	good := hex.EncodeToString(sum[:])

	if got, err := io.ReadAll(CheckPayload(io.NopCloser(strings.NewReader("hello")), good)); err != nil || string(got) != "hello" {
		t.Fatalf("matching body = %q, %v", got, err)
	}
	if _, err := io.ReadAll(CheckPayload(io.NopCloser(strings.NewReader("hellO")), good)); !errors.Is(err, ErrPayloadHash) {
		t.Fatalf("changed body: %v", err)
	}
	// A value that is not a hash leaves the body unchecked.
	if _, err := io.ReadAll(CheckPayload(io.NopCloser(strings.NewReader("x")), "UNSIGNED-PAYLOAD")); err != nil {
		t.Fatalf("UNSIGNED-PAYLOAD: %v", err)
	}
	for payload, want := range map[string]bool{
		good: true, strings.ToUpper(good): false, "UNSIGNED-PAYLOAD": false,
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD": false, good[:63]: false,
	} {
		if SignedPayloadHash(payload) != want {
			t.Errorf("SignedPayloadHash(%q) != %v", payload, want)
		}
	}
}
