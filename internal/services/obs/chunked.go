package obs

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

// AWS SDKs may send an upload in "aws-chunked" encoding: the body is a
// series of chunks, each with its own signature, optionally followed by
// trailing headers:
//
//	<hex size>;chunk-signature=<sig>\r\n
//	<data>\r\n
//	...
//	0;chunk-signature=<sig>\r\n
//	[trailer: value\r\n]...
//	\r\n
//
// The framing must be removed or it would be stored as part of the
// object. When credentials are enforced, the request carries a
// sigcheck.ChunkVerifier and each chunk's signature is checked as the
// chunk ends; otherwise they are ignored.

// isAWSChunked reports whether a request body uses the encoding.
func isAWSChunked(r *http.Request) bool {
	if strings.HasPrefix(r.Header.Get("x-amz-content-sha256"), "STREAMING-") {
		return true
	}
	for _, enc := range r.Header.Values("Content-Encoding") {
		if strings.Contains(enc, "aws-chunked") {
			return true
		}
	}
	return false
}

var errBadChunk = errors.New("obs: malformed aws-chunked body")

// awsChunkedReader yields the payload of an aws-chunked body.
type awsChunkedReader struct {
	src       *bufio.Reader
	remaining int64 // bytes left in the current chunk
	done      bool
	// verify checks chunk signatures, if set; sig is the current
	// chunk's, and hash its data's.
	verify *sigcheck.ChunkVerifier
	sig    string
	hash   hash.Hash
}

func newAWSChunkedReader(r io.Reader, verify *sigcheck.ChunkVerifier) *awsChunkedReader {
	return &awsChunkedReader{src: bufio.NewReader(r), verify: verify, hash: sha256.New()}
}

// checkChunk verifies the chunk just read, if signatures are checked.
func (c *awsChunkedReader) checkChunk() error {
	if c.verify == nil {
		return nil
	}
	err := c.verify.Check(c.sig, c.hash.Sum(nil))
	c.hash.Reset()
	return err
}

func (c *awsChunkedReader) Read(p []byte) (int, error) {
	for c.remaining == 0 {
		if c.done {
			return 0, io.EOF
		}
		if err := c.nextChunk(); err != nil {
			return 0, err
		}
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.src.Read(p)
	c.hash.Write(p[:n])
	c.remaining -= int64(n)
	if errors.Is(err, io.EOF) && c.remaining > 0 {
		return n, io.ErrUnexpectedEOF
	}
	if c.remaining == 0 && err == nil {
		if err = c.expectCRLF(); err == nil {
			err = c.checkChunk()
		}
	}
	return n, err
}

// nextChunk reads a chunk header and, for the final chunk, consumes the
// trailers.
func (c *awsChunkedReader) nextChunk() error {
	line, err := c.src.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	size, ext, _ := strings.Cut(strings.TrimRight(line, "\r\n"), ";")
	n, err := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("%w: bad chunk size %q", errBadChunk, size)
	}
	c.sig = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ext), "chunk-signature="))
	if n == 0 {
		c.done = true
		// The final, empty chunk is signed too.
		if err := c.checkChunk(); err != nil {
			return err
		}
		// Trailing headers, if any, end with an empty line. A body
		// that simply stops after the last chunk is accepted too.
		for {
			line, err := c.src.ReadString('\n')
			if errors.Is(err, io.EOF) || strings.TrimRight(line, "\r\n") == "" {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
	c.remaining = n
	return nil
}

func (c *awsChunkedReader) expectCRLF() error {
	var crlf [2]byte
	if _, err := io.ReadFull(c.src, crlf[:]); err != nil {
		return io.ErrUnexpectedEOF
	}
	if crlf != [2]byte{'\r', '\n'} {
		return fmt.Errorf("%w: chunk data not followed by CRLF", errBadChunk)
	}
	return nil
}
