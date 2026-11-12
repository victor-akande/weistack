package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

// The data format.
//
// A database records the version of the format it was written in, so a
// release can tell whether it can read a file, and upgrade it if it is
// older. The version changes only when a release changes how something
// already stored is laid out; adding a new kind of resource does not
// change it.
//
// Files written by v0.1 releases carry no version: they are format 1.

// FormatVersion is the format this release writes.
const FormatVersion = 1

// ErrNewerFormat reports a database written by a newer WeiStack.
var ErrNewerFormat = errors.New("store: database written by a newer WeiStack")

// metaBucket holds the database's own metadata. Scope names always
// contain "/", so it cannot collide with stored resources.
const metaBucket = "_weistack"

var formatKey = []byte("format")

// migration upgrades a database from one format to the next inside one
// transaction.
type migration func(tx *bolt.Tx) error

// migrations[n] upgrades format n to n+1. There are none yet.
var migrations = map[uint64]migration{}

// prepareFormat records or checks the format of an open database, backs
// it up and migrates it when it is older than current.
func prepareFormat(db *bolt.DB, path string, current uint64, steps map[uint64]migration) error {
	// Read first, in a read-only transaction: a file this release refuses
	// must be left exactly as it was.
	var found uint64
	recorded := false
	err := db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte(metaBucket))
		if meta == nil {
			return nil
		}
		recorded = true
		v, err := readFormat(meta)
		found = v
		return err
	})
	if err != nil {
		return err
	}
	if !recorded {
		// No metadata: either a new file or one written by v0.1.
		err := db.Update(func(tx *bolt.Tx) error {
			found = current
			if hasScopes(tx) {
				found = 1
			}
			return writeFormat(tx, found)
		})
		if err != nil {
			return err
		}
	}

	switch {
	case found > current:
		return fmt.Errorf("%w: %s is format %d, and this release reads up to format %d; use that release or a newer one",
			ErrNewerFormat, path, found, current)
	case found == current:
		return nil
	}

	backup := fmt.Sprintf("%s.format%d.bak", path, found)
	if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) {
		if err := db.View(func(tx *bolt.Tx) error { return tx.CopyFile(backup, 0o600) }); err != nil {
			return fmt.Errorf("store: backing up %s before upgrading it: %w", path, err)
		}
	}
	for v := found; v < current; v++ {
		step, ok := steps[v]
		if !ok {
			return fmt.Errorf("store: no upgrade from format %d to %d", v, v+1)
		}
		err := db.Update(func(tx *bolt.Tx) error {
			if err := step(tx); err != nil {
				return err
			}
			return writeFormat(tx, v+1)
		})
		if err != nil {
			return fmt.Errorf("store: upgrading %s from format %d to %d (the original is in %s): %w", path, v, v+1, backup, err)
		}
	}
	return nil
}

func hasScopes(tx *bolt.Tx) bool {
	found := false
	_ = tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		if string(name) != metaBucket {
			found = true
		}
		return nil
	})
	return found
}

// The version is stored like any record, a 16-byte header then JSON, so
// a v0.1 binary that opens the file shows it as one more record instead
// of failing on an unexpected value.
func writeFormat(tx *bolt.Tx, v uint64) error {
	meta, err := tx.CreateBucketIfNotExists([]byte(metaBucket))
	if err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return meta.Put(formatKey, encodeBolt(1, v, data))
}

func readFormat(meta *bolt.Bucket) (uint64, error) {
	raw := meta.Get(formatKey)
	if len(raw) < boltHeaderLen {
		return 0, errors.New("store: the database's format record is missing or corrupt")
	}
	var v uint64
	if err := json.Unmarshal(raw[boltHeaderLen:], &v); err != nil || v == 0 {
		return 0, fmt.Errorf("store: the database's format record is corrupt: %q", raw[boltHeaderLen:])
	}
	return v, nil
}

// Format returns the format version recorded in the database.
func (b *Bolt) Format() (uint64, error) {
	var v uint64
	err := b.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte(metaBucket))
		if meta == nil {
			return errors.New("store: the database records no format")
		}
		var err error
		v, err = readFormat(meta)
		return err
	})
	return v, err
}
