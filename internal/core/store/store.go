// Package store holds emulator state: opaque, versioned records grouped
// by region, project and resource kind.
//
// Two implementations satisfy Store: Memory (the default) and Bolt (an
// embedded on-disk database used when persistence is enabled). Services
// normally use the typed Collection wrapper rather than Store directly.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Errors returned by every Store implementation.
var (
	// ErrNotFound means no record has the requested ID in the scope.
	ErrNotFound = errors.New("store: record not found")
	// ErrExists means Create found a record with the same ID.
	ErrExists = errors.New("store: record already exists")
	// ErrConflict means the record changed since the version the caller read.
	ErrConflict = errors.New("store: version conflict")
	// ErrInvalidScope means a Scope field is empty or contains a separator.
	ErrInvalidScope = errors.New("store: invalid scope")
	// ErrClosed means the store was used after Close.
	ErrClosed = errors.New("store: closed")
)

// Global is the ProjectID to use for records that belong to no project,
// such as public images.
const Global = "_"

const scopeSep = "/"

// Scope addresses one collection of records.
type Scope struct {
	Region    string
	ProjectID string
	Kind      string
}

// String returns the canonical "region/project/kind" form used as the
// collection key and in state dumps.
func (s Scope) String() string {
	return s.Region + scopeSep + s.ProjectID + scopeSep + s.Kind
}

// ParseScope is the inverse of Scope.String.
func ParseScope(key string) (Scope, error) {
	parts := strings.Split(key, scopeSep)
	if len(parts) != 3 {
		return Scope{}, fmt.Errorf("%w: %q", ErrInvalidScope, key)
	}
	s := Scope{Region: parts[0], ProjectID: parts[1], Kind: parts[2]}
	if _, err := s.key(); err != nil {
		return Scope{}, err
	}
	return s, nil
}

func (s Scope) key() (string, error) {
	for _, part := range []string{s.Region, s.ProjectID, s.Kind} {
		if part == "" || strings.Contains(part, scopeSep) {
			return "", fmt.Errorf("%w: %q", ErrInvalidScope, s.String())
		}
	}
	return s.String(), nil
}

// Record is one stored value.
type Record struct {
	// ID is unique within the Scope.
	ID string
	// Version starts at 1 and increases by one on every write.
	Version uint64
	// Seq orders records by creation within a Scope; it survives updates.
	Seq uint64
	// Data is the caller's payload. The caller owns the returned slice.
	Data []byte
}

// Store is a concurrency-safe record store.
type Store interface {
	// Get returns the record or ErrNotFound.
	Get(ctx context.Context, scope Scope, id string) (Record, error)
	// List returns every record in the scope in creation order.
	List(ctx context.Context, scope Scope) ([]Record, error)
	// Create inserts a new record or returns ErrExists.
	Create(ctx context.Context, scope Scope, id string, data []byte) (Record, error)
	// Put inserts or unconditionally replaces a record.
	Put(ctx context.Context, scope Scope, id string, data []byte) (Record, error)
	// CompareAndSwap replaces the record only if its version still equals
	// version. It returns ErrConflict otherwise, or ErrNotFound.
	CompareAndSwap(ctx context.Context, scope Scope, id string, version uint64, data []byte) (Record, error)
	// Delete removes the record or returns ErrNotFound.
	Delete(ctx context.Context, scope Scope, id string) error
	// Reset removes every record in every scope.
	Reset(ctx context.Context) error
	// Dump returns all records keyed by Scope.String(), each in creation order.
	Dump(ctx context.Context) (map[string][]Record, error)
	// Close releases resources. The store must not be used afterwards.
	Close() error
}

// Update applies fn to a record with optimistic concurrency: it reads the
// record, calls fn on its data without holding any lock, and writes the
// result only if nobody else wrote in between, retrying otherwise. fn may
// therefore run more than once and must not have side effects. An error
// from fn aborts the update and is returned unchanged.
func Update(ctx context.Context, s Store, scope Scope, id string, fn func(data []byte) ([]byte, error)) (Record, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Record{}, err
		}
		cur, err := s.Get(ctx, scope, id)
		if err != nil {
			return Record{}, err
		}
		next, err := fn(cur.Data)
		if err != nil {
			return Record{}, err
		}
		rec, err := s.CompareAndSwap(ctx, scope, id, cur.Version, next)
		if errors.Is(err, ErrConflict) {
			continue
		}
		return rec, err
	}
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
