// Package ids generates identifiers in the formats Huawei Cloud uses.
package ids

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	mrand "math/rand/v2"
	"sync"
)

// Generator produces identifiers. It is safe for concurrent use.
type Generator struct {
	mu  sync.Mutex
	src io.Reader
}

// New returns a Generator backed by the operating system's CSPRNG.
func New() *Generator {
	return &Generator{src: crand.Reader}
}

// NewSeeded returns a deterministic Generator: the same seed always yields
// the same sequence of identifiers. For reproducible tests only.
func NewSeeded(seed uint64) *Generator {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:8], seed)
	return &Generator{src: mrand.NewChaCha8(key)}
}

// UUID returns a lowercase RFC 4122 version 4 UUID, the resource ID format
// of VPC, ECS, IMS and RDS, for example
// "3d7f0c1e-9a4b-4c2d-8e5f-0a1b2c3d4e5f".
func (g *Generator) UUID() string {
	var b [16]byte
	g.read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

// Hex32 returns 32 lowercase hex characters, the format of project IDs,
// asynchronous job IDs and request IDs.
func (g *Generator) Hex32() string {
	var b [16]byte
	g.read(b[:])
	return hex.EncodeToString(b[:])
}

func (g *Generator) read(p []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, err := io.ReadFull(g.src, p); err != nil {
		// crypto/rand and ChaCha8 never fail; an error here means the
		// process cannot produce safe identifiers at all.
		panic("ids: random source failed: " + err.Error())
	}
}
