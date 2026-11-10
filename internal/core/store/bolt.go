package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// Bolt is a Store persisted in a single bbolt database file. Each Scope
// is a bucket; each value is a 16-byte header (creation sequence and
// version, big-endian) followed by the caller's data.
type Bolt struct {
	db *bolt.DB

	closeOnce sync.Once
	closeErr  error
}

const boltHeaderLen = 16

// OpenBolt opens, creating if necessary, the database at path.
//
// Writes are not fsynced one by one: an emulator favours low latency, and
// a killed process loses nothing because the kernel still holds the
// written pages. The file is synced on Close. Only a machine crash or
// power loss can cost recent writes.
func OpenBolt(path string) (*Bolt, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("store: creating data directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{
		// Fail fast instead of hanging when another weistack holds the file.
		Timeout:        2 * time.Second,
		NoSync:         true,
		NoFreelistSync: true,
	})
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	return &Bolt{db: db}, nil
}

var _ Store = (*Bolt)(nil)

func encodeBolt(seq, version uint64, data []byte) []byte {
	buf := make([]byte, boltHeaderLen+len(data))
	binary.BigEndian.PutUint64(buf[0:8], seq)
	binary.BigEndian.PutUint64(buf[8:16], version)
	copy(buf[boltHeaderLen:], data)
	return buf
}

func decodeBolt(id string, raw []byte) (Record, error) {
	if len(raw) < boltHeaderLen {
		return Record{}, fmt.Errorf("store: record %q is corrupt (%d bytes)", id, len(raw))
	}
	return Record{
		ID:      id,
		Seq:     binary.BigEndian.Uint64(raw[0:8]),
		Version: binary.BigEndian.Uint64(raw[8:16]),
		// bbolt memory is only valid inside the transaction: always copy.
		Data: append([]byte{}, raw[boltHeaderLen:]...),
	}, nil
}

func mapBoltErr(err error) error {
	if errors.Is(err, bolterrors.ErrDatabaseNotOpen) {
		return ErrClosed
	}
	return err
}

func prepare(ctx context.Context, scope Scope) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := scope.key()
	if err != nil {
		return nil, err
	}
	return []byte(key), nil
}

// Get implements Store.
func (b *Bolt) Get(ctx context.Context, scope Scope, id string) (Record, error) {
	key, err := prepare(ctx, scope)
	if err != nil {
		return Record{}, err
	}
	var rec Record
	err = b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(key)
		if bkt == nil {
			return ErrNotFound
		}
		raw := bkt.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var derr error
		rec, derr = decodeBolt(id, raw)
		return derr
	})
	return rec, mapBoltErr(err)
}

// List implements Store.
func (b *Bolt) List(ctx context.Context, scope Scope) ([]Record, error) {
	key, err := prepare(ctx, scope)
	if err != nil {
		return nil, err
	}
	out := []Record{}
	err = b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(key)
		if bkt == nil {
			return nil
		}
		var lerr error
		out, lerr = bucketRecords(bkt)
		return lerr
	})
	return out, mapBoltErr(err)
}

func bucketRecords(bkt *bolt.Bucket) ([]Record, error) {
	out := make([]Record, 0, bkt.Stats().KeyN)
	err := bkt.ForEach(func(k, v []byte) error {
		rec, err := decodeBolt(string(k), v)
		if err != nil {
			return err
		}
		out = append(out, rec)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

// write runs fn against the scope's bucket in a read-write transaction.
// fn receives the current record (ok is false when absent) and returns
// the sequence, version and whether to proceed with storing data.
func (b *Bolt) write(ctx context.Context, scope Scope, id string, data []byte,
	decide func(cur Record, ok bool) error,
) (Record, error) {
	key, err := prepare(ctx, scope)
	if err != nil {
		return Record{}, err
	}
	var rec Record
	err = b.db.Update(func(tx *bolt.Tx) error {
		bkt, err := tx.CreateBucketIfNotExists(key)
		if err != nil {
			return err
		}
		var (
			cur Record
			ok  bool
		)
		if raw := bkt.Get([]byte(id)); raw != nil {
			if cur, err = decodeBolt(id, raw); err != nil {
				return err
			}
			ok = true
		}
		if err := decide(cur, ok); err != nil {
			return err
		}
		rec = Record{ID: id, Seq: cur.Seq, Version: cur.Version + 1, Data: clone(data)}
		if !ok {
			if rec.Seq, err = bkt.NextSequence(); err != nil {
				return err
			}
		}
		return bkt.Put([]byte(id), encodeBolt(rec.Seq, rec.Version, data))
	})
	if err != nil {
		return Record{}, mapBoltErr(err)
	}
	return rec, nil
}

// Create implements Store.
func (b *Bolt) Create(ctx context.Context, scope Scope, id string, data []byte) (Record, error) {
	return b.write(ctx, scope, id, data, func(_ Record, ok bool) error {
		if ok {
			return ErrExists
		}
		return nil
	})
}

// Put implements Store.
func (b *Bolt) Put(ctx context.Context, scope Scope, id string, data []byte) (Record, error) {
	return b.write(ctx, scope, id, data, func(Record, bool) error { return nil })
}

// CompareAndSwap implements Store.
func (b *Bolt) CompareAndSwap(ctx context.Context, scope Scope, id string, version uint64, data []byte) (Record, error) {
	return b.write(ctx, scope, id, data, func(cur Record, ok bool) error {
		if !ok {
			return ErrNotFound
		}
		if cur.Version != version {
			return ErrConflict
		}
		return nil
	})
}

// Delete implements Store.
func (b *Bolt) Delete(ctx context.Context, scope Scope, id string) error {
	key, err := prepare(ctx, scope)
	if err != nil {
		return err
	}
	err = b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(key)
		if bkt == nil || bkt.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return bkt.Delete([]byte(id))
	})
	return mapBoltErr(err)
}

// Reset implements Store.
func (b *Bolt) Reset(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := b.db.Update(func(tx *bolt.Tx) error {
		var names [][]byte
		err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			names = append(names, append([]byte{}, name...))
			return nil
		})
		if err != nil {
			return err
		}
		for _, name := range names {
			if err := tx.DeleteBucket(name); err != nil {
				return err
			}
		}
		return nil
	})
	return mapBoltErr(err)
}

// Dump implements Store.
func (b *Bolt) Dump(ctx context.Context) (map[string][]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make(map[string][]Record)
	err := b.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, bkt *bolt.Bucket) error {
			recs, err := bucketRecords(bkt)
			if err != nil {
				return err
			}
			if len(recs) > 0 {
				out[string(name)] = recs
			}
			return nil
		})
	})
	if err != nil {
		return nil, mapBoltErr(err)
	}
	return out, nil
}

// Close flushes the database to disk and releases the file lock. It is
// safe to call more than once.
func (b *Bolt) Close() error {
	b.closeOnce.Do(func() {
		if err := b.db.Sync(); err != nil {
			_ = b.db.Close()
			b.closeErr = fmt.Errorf("store: syncing database: %w", err)
			return
		}
		b.closeErr = b.db.Close()
	})
	return b.closeErr
}
