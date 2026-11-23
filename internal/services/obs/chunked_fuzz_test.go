package obs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// encodeChunked encodes payload as aws-chunked, in chunks of size.
func encodeChunked(payload []byte, size int) []byte {
	var b bytes.Buffer
	for len(payload) > 0 {
		n := min(size, len(payload))
		fmt.Fprintf(&b, "%x;chunk-signature=%s\r\n", n, strings.Repeat("0", 64))
		b.Write(payload[:n])
		b.WriteString("\r\n")
		payload = payload[n:]
	}
	fmt.Fprintf(&b, "0;chunk-signature=%s\r\n\r\n", strings.Repeat("0", 64))
	return b.Bytes()
}

// FuzzAWSChunked: no body crashes or hangs the decoder, which reads at
// most what it is given.
func FuzzAWSChunked(f *testing.F) {
	f.Add(encodeChunked([]byte("hello world"), 4))
	f.Add([]byte("5\r\nabc"))
	f.Add([]byte("ffffffffffffffff\r\n"))
	f.Add([]byte("-1\r\n"))
	f.Add([]byte("0\r\nx-amz-checksum: abc\r\n\r\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		out, err := io.ReadAll(newAWSChunkedReader(bytes.NewReader(body), nil))
		if err == nil && len(out) > len(body) {
			t.Fatalf("decoded %d bytes from %d", len(out), len(body))
		}
	})
}

// FuzzAWSChunkedRoundTrip: any payload, in any chunk size, decodes to
// itself.
func FuzzAWSChunkedRoundTrip(f *testing.F) {
	f.Add([]byte("hello world"), uint16(4))
	f.Add([]byte{}, uint16(1))
	f.Add([]byte("\r\n0\r\n\r\n"), uint16(2))
	f.Fuzz(func(t *testing.T, payload []byte, size uint16) {
		if size == 0 {
			return
		}
		out, err := io.ReadAll(newAWSChunkedReader(bytes.NewReader(encodeChunked(payload, int(size))), nil))
		if err != nil || !bytes.Equal(out, payload) {
			t.Fatalf("round trip of %q in chunks of %d = %q, %v", payload, size, out, err)
		}
	})
}

func TestAWSChunkedLongLine(t *testing.T) {
	t.Parallel()
	body := io.MultiReader(strings.NewReader("1"), bytes.NewReader(bytes.Repeat([]byte("0"), 1<<20)))
	_, err := io.ReadAll(newAWSChunkedReader(body, nil))
	if !errors.Is(err, errBadChunk) {
		t.Fatalf("a 1 MiB header line: %v, want errBadChunk", err)
	}
}
