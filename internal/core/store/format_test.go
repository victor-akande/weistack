package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

var testScope = Scope{Region: "ap-southeast-1", ProjectID: "0123456789abcdef0123456789abcdef", Kind: "vpc.vpc"}

func TestNewFileRecordsTheFormat(t *testing.T) {
	t.Parallel()
	b, err := OpenBolt(filepath.Join(t.TempDir(), "new.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if v, err := b.Format(); err != nil || v != FormatVersion {
		t.Fatalf("Format() = %d, %v; want %d", v, err, FormatVersion)
	}
}

// writeV01 writes a file the way v0.1 did: scope buckets, no metadata.
func writeV01(t *testing.T, path string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		bkt, err := tx.CreateBucket([]byte(mustKey(t, testScope)))
		if err != nil {
			return err
		}
		return bkt.Put([]byte("vpc-1"), encodeBolt(1, 1, []byte(`{"name":"old"}`)))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustKey(t *testing.T, s Scope) string {
	t.Helper()
	k, err := s.key()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestV01FileIsFormatOne(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "weistack.db")
	writeV01(t, path)

	b, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("opening a v0.1 file: %v", err)
	}
	defer b.Close()
	if v, err := b.Format(); err != nil || v != 1 {
		t.Fatalf("Format() = %d, %v; want 1", v, err)
	}
	rec, err := b.Get(context.Background(), testScope, "vpc-1")
	if err != nil || string(rec.Data) != `{"name":"old"}` {
		t.Fatalf("v0.1 record = %+v, %v", rec, err)
	}
	// Format 1 is current: nothing to back up.
	if _, err := os.Stat(path + ".format1.bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a backup was made of a current file: %v", err)
	}
}

func TestNewerFormatIsRefused(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "weistack.db")
	b, err := openBolt(path, 5, map[uint64]migration{1: noop, 2: noop, 3: noop, 4: noop})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = OpenBolt(path)
	if !errors.Is(err, ErrNewerFormat) || !strings.Contains(err.Error(), "format 5") || !strings.Contains(err.Error(), "up to format 1") {
		t.Fatalf("opening a newer file: %v", err)
	}
	// Refusing leaves the file alone and releases it.
	if b, err := openBolt(path, 5, nil); err != nil {
		t.Fatalf("reopening with the newer release: %v", err)
	} else {
		_ = b.Close()
	}
}

func noop(*bolt.Tx) error { return nil }

func TestMigrationBacksUpThenUpgradesStepByStep(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "weistack.db")
	writeV01(t, path)

	var ran []uint64
	steps := map[uint64]migration{
		1: func(*bolt.Tx) error { ran = append(ran, 1); return nil },
		2: func(tx *bolt.Tx) error {
			ran = append(ran, 2)
			// A step may rewrite records.
			return tx.Bucket([]byte(mustKey(t, testScope))).Put([]byte("vpc-1"), encodeBolt(1, 2, []byte(`{"name":"new"}`)))
		},
	}
	b, err := openBolt(path, 3, steps)
	if err != nil {
		t.Fatalf("upgrading: %v", err)
	}
	if v, _ := b.Format(); v != 3 || len(ran) != 2 || ran[0] != 1 || ran[1] != 2 {
		t.Fatalf("format %d after steps %v", v, ran)
	}
	rec, _ := b.Get(context.Background(), testScope, "vpc-1")
	if string(rec.Data) != `{"name":"new"}` {
		t.Fatalf("migrated record = %s", rec.Data)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	// The backup is the file as it was, still readable as format 1.
	backup, err := OpenBolt(path + ".format1.bak")
	if err != nil {
		t.Fatalf("opening the backup: %v", err)
	}
	defer backup.Close()
	old, _ := backup.Get(context.Background(), testScope, "vpc-1")
	if string(old.Data) != `{"name":"old"}` {
		t.Fatalf("backup record = %s", old.Data)
	}
}

func TestFailedMigrationKeepsTheLastGoodFormat(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "weistack.db")
	writeV01(t, path)

	steps := map[uint64]migration{
		1: noop,
		2: func(*bolt.Tx) error { return errors.New("disk on fire") },
	}
	_, err := openBolt(path, 3, steps)
	if err == nil || !strings.Contains(err.Error(), "from format 2 to 3") || !strings.Contains(err.Error(), ".format1.bak") ||
		!strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("failed migration: %v", err)
	}
	// Step 1 committed; step 2 rolled back. A fixed release resumes there.
	b, err := openBolt(path, 2, steps)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if v, _ := b.Format(); v != 2 {
		t.Fatalf("format after a failed step = %d, want 2", v)
	}
}

func TestMissingMigrationStep(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "weistack.db")
	writeV01(t, path)
	if _, err := openBolt(path, 2, nil); err == nil || !strings.Contains(err.Error(), "no upgrade from format 1 to 2") {
		t.Fatalf("missing step: %v", err)
	}
}

func TestResetAndDumpLeaveTheFormatAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b, err := OpenBolt(filepath.Join(t.TempDir(), "weistack.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Create(ctx, testScope, "vpc-1", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	dump, err := b.Dump(ctx)
	if err != nil || len(dump) != 1 {
		t.Fatalf("Dump = %v, %v; want only the VPC scope", dump, err)
	}
	if _, ok := dump[metaBucket]; ok {
		t.Fatal("Dump shows the metadata")
	}
	if err := b.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if v, err := b.Format(); err != nil || v != FormatVersion {
		t.Fatalf("format after Reset = %d, %v", v, err)
	}
}

func TestCorruptFormatRecord(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "weistack.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Update(func(tx *bolt.Tx) error {
		meta, _ := tx.CreateBucket([]byte(metaBucket))
		return meta.Put(formatKey, []byte("short"))
	})
	_ = db.Close()
	if _, err := OpenBolt(path); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt format record: %v", err)
	}
}
