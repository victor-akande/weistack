// Package cmk is how services that encrypt with KMS keys (OBS's SSE-KMS,
// encrypted disks, encrypted RDS storage) reach them. KMS implements
// Keys; a service depends on this interface, not on KMS.
package cmk

import (
	"context"
	"errors"
)

// Errors a service maps to its own documented codes.
var (
	// ErrNotFound is a key that does not exist, or is not the caller's.
	ErrNotFound = errors.New("cmk: the key does not exist")
	// ErrDisabled is a key that is disabled or pending deletion.
	ErrDisabled = errors.New("cmk: the key is disabled")
)

// DataKey is a fresh data key: in clear, to encrypt with now, and sealed
// by its master key, to keep beside what it encrypted.
type DataKey struct {
	// KeyID is the master key's ID; KeyURN its full name,
	// <region>:<account-id>:key/<key-id>, as OBS shows it.
	KeyID, KeyURN string
	Plain, Sealed []byte
}

// Keys gives services the KMS keys of the caller (the account ctx
// acts for). A key ID of "" names the service's default key
// (<service>/default), which is made on first use.
type Keys interface {
	// NewDataKey makes a data key under a key of the caller's project in
	// region.
	NewDataKey(ctx context.Context, region, keyID, service string) (DataKey, error)
	// OpenDataKey opens a sealed data key, whoever asks: the service has
	// already authorized the request for what the key protects.
	OpenDataKey(ctx context.Context, region string, sealed []byte) ([]byte, error)
	// Check returns the ID of a usable key of the caller's project, as
	// NewDataKey would use it.
	Check(ctx context.Context, region, projectID, keyID, service string) (string, error)
}
