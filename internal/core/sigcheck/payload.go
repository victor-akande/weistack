package sigcheck

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"regexp"
)

// ErrPayloadHash is a body whose SHA-256 is not the one the client signed
// in x-amz-content-sha256.
var ErrPayloadHash = errors.New("sigcheck: the body does not match its signed SHA-256")

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SignedPayloadHash reports whether payload, the x-amz-content-sha256 of
// a request, is the hex SHA-256 of its body, rather than
// UNSIGNED-PAYLOAD or a STREAMING-* scheme.
func SignedPayloadHash(payload string) bool { return sha256HexRE.MatchString(payload) }

// CheckPayload wraps body so that reading it to the end fails with
// ErrPayloadHash unless its SHA-256 is wantHex. A body not read to the
// end is not checked: a reader that stops early has rejected it anyway.
func CheckPayload(body io.ReadCloser, wantHex string) io.ReadCloser {
	want, err := hex.DecodeString(wantHex)
	if err != nil || len(want) != sha256.Size {
		return body
	}
	return &payloadChecker{body: body, hash: sha256.New(), want: want}
}

type payloadChecker struct {
	body io.ReadCloser
	hash hash.Hash
	want []byte
}

func (p *payloadChecker) Read(b []byte) (int, error) {
	n, err := p.body.Read(b)
	p.hash.Write(b[:n])
	if errors.Is(err, io.EOF) && subtle.ConstantTimeCompare(p.hash.Sum(nil), p.want) != 1 {
		return n, ErrPayloadHash
	}
	return n, err
}

func (p *payloadChecker) Close() error { return p.body.Close() }
