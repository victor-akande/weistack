package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// FuzzFormat1To2 opens a format-1 file holding any server record. The
// upgrade succeeds, or fails leaving the file at format 1, and never
// crashes: v0.1 data must open, or say why, in every release.
func FuzzFormat1To2(f *testing.F) {
	f.Add([]byte(`{"id":"s","root_volume":{"id":"v","type":"SSD","size":40,"device":"/dev/vda"},"data_volumes":[{"id":"d","size":1}]}`), true)
	f.Add([]byte(`{"root_volume":null,"data_volumes":{}}`), true)
	f.Add([]byte(`not json`), true)
	f.Add([]byte{1, 2}, false)
	srv := Scope{Region: "ap-southeast-1", ProjectID: "0123456789abcdef0123456789abcdef", Kind: "ecs.server"}
	f.Fuzz(func(t *testing.T, data []byte, header bool) {
		path := filepath.Join(t.TempDir(), "weistack.db")
		db, err := bolt.Open(path, 0o600, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw := data
		if header {
			raw = encodeBolt(1, 1, data)
		}
		err = db.Update(func(tx *bolt.Tx) error {
			if err := writeFormat(tx, 1); err != nil {
				return err
			}
			key, err := srv.key()
			if err != nil {
				return err
			}
			bkt, err := tx.CreateBucket([]byte(key))
			if err != nil {
				return err
			}
			return bkt.Put([]byte("s"), raw)
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}

		b, err := OpenBolt(path)
		if err == nil {
			if v, err := b.Format(); err != nil || v != FormatVersion {
				t.Fatalf("opened at format %d, %v", v, err)
			}
			_ = b.Close()
			return
		}
		if errors.Is(err, ErrNewerFormat) {
			t.Fatalf("a format-1 file was taken for a newer one: %v", err)
		}
		// A failed upgrade leaves the file as it was, and its backup.
		if _, statErr := os.Stat(path + ".format1.bak"); statErr != nil {
			t.Fatalf("a failed upgrade left no backup: %v (%v)", statErr, err)
		}
		again, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer again.Close()
		_ = again.View(func(tx *bolt.Tx) error {
			if v, err := readFormat(tx.Bucket([]byte(metaBucket))); err != nil || v != 1 {
				t.Fatalf("after a failed upgrade the file is format %d, %v", v, err)
			}
			return nil
		})
	})
}
