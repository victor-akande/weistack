package store

import (
	"errors"
	"fmt"
	"io"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// ErrInUse means another process has the database open.
var ErrInUse = errors.New("store: the database is in use by another process")

// Snapshot is a consistent copy of a database, as of one moment.
type Snapshot struct {
	// Size is the number of bytes WriteTo writes.
	Size int64
	// Format is the database's format version.
	Format uint64
	// WriteTo writes the copy.
	WriteTo func(io.Writer) (int64, error)
}

// Snapshot calls fn with a consistent copy of the open database. Writes
// go on meanwhile; the copy does not see them.
func (b *Bolt) Snapshot(fn func(Snapshot) error) error {
	return b.db.View(func(tx *bolt.Tx) error { return snapshotTx(tx, fn) })
}

// SnapshotFile calls fn with a copy of the database at path, which no
// process may have open. The file is opened read-only and not migrated.
func SnapshotFile(path string, fn func(Snapshot) error) error {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 2 * time.Second})
	if errors.Is(err, bolterrors.ErrTimeout) {
		return fmt.Errorf("%w: %s", ErrInUse, path)
	}
	if err != nil {
		return fmt.Errorf("store: opening %s: %w", path, err)
	}
	defer func() { _ = db.Close() }()
	return db.View(func(tx *bolt.Tx) error { return snapshotTx(tx, fn) })
}

func snapshotTx(tx *bolt.Tx, fn func(Snapshot) error) error {
	format := uint64(FormatVersion)
	if meta := tx.Bucket([]byte(metaBucket)); meta != nil {
		v, err := readFormat(meta)
		if err != nil {
			return err
		}
		format = v
	} else if hasScopes(tx) {
		format = 1 // written by v0.1, which recorded no format
	}
	return fn(Snapshot{Size: tx.Size(), Format: format, WriteTo: tx.WriteTo})
}
