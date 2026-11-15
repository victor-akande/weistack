package obs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

// awsExampleBody is Amazon's documented streaming upload: 65,536 then
// 1,024 bytes of "a", then the final chunk, with their documented
// signatures (see sigcheck's TestChunkSignatures).
func awsExampleBody(firstByte byte) string {
	first := []byte(strings.Repeat("a", 65536))
	first[0] = firstByte
	return "10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n" + string(first) + "\r\n" +
		"400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n" + strings.Repeat("a", 1024) + "\r\n" +
		"0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n\r\n"
}

func awsExampleVerifier() *sigcheck.ChunkVerifier {
	secret := "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY" // Amazon's published example key
	return sigcheck.NewChunkVerifier(secret, "20130524T000000Z", "us-east-1", "s3",
		"4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
}

func TestChunkSignaturesChecked(t *testing.T) {
	t.Parallel()
	got, err := io.ReadAll(newAWSChunkedReader(strings.NewReader(awsExampleBody('a')), awsExampleVerifier()))
	if err != nil || len(got) != 66560 {
		t.Fatalf("read %d bytes, %v", len(got), err)
	}
	// One changed byte fails the first chunk.
	if _, err := io.ReadAll(newAWSChunkedReader(strings.NewReader(awsExampleBody('b')), awsExampleVerifier())); !errors.Is(err, sigcheck.ErrChunk) {
		t.Fatalf("a changed chunk: %v", err)
	}
	// Without a verifier, signatures are ignored.
	if _, err := io.ReadAll(newAWSChunkedReader(strings.NewReader(awsExampleBody('b')), nil)); err != nil {
		t.Fatalf("unchecked: %v", err)
	}
}

// TestPayloadHashMismatch serves an upload whose body the server wrapped
// in a SHA-256 check, as it does with -iam=enforce: a body that does not
// match is refused with ContentSHA256Mismatch, and nothing is stored.
func TestPayloadHashMismatch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "hashed")
	sum := sha256.Sum256([]byte("declared"))

	for body, want := range map[string]int{"declared": http.StatusOK, "changed!": http.StatusBadRequest} {
		r := httptest.NewRequest(http.MethodPut, "/hashed/k", nil)
		r.Host = testHost
		r.Header.Set("Authorization", alice)
		r.Body = sigcheck.CheckPayload(io.NopCloser(strings.NewReader(body)), hex.EncodeToString(sum[:]))
		r.ContentLength = int64(len(body))
		w := httptest.NewRecorder()
		e.handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%q: %d %s", body, w.Code, w.Body)
		}
		if want == http.StatusBadRequest && !strings.Contains(w.Body.String(), "<Code>ContentSHA256Mismatch</Code>") {
			t.Fatalf("%q: %s", body, w.Body)
		}
	}
	if n := e.blobFiles(t); n != 1 {
		t.Fatalf("%d bodies stored, want only the matching one", n)
	}
}
