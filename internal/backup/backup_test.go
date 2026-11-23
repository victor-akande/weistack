package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/store"
)

var scope = store.Scope{Region: "ap-southeast-1", ProjectID: "p", Kind: "thing"}

func writeFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func source(dir string, snapshot func(func(store.Snapshot) error) error) Source {
	return Source{
		Dir: dir, Database: "weistack.db", Snapshot: snapshot, VaultKey: "vault-key.json",
		Exclude: []string{"backups", "objects/tmp"}, Version: "v0.3.0-test",
	}
}

func TestBackupAndRestore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := t.TempDir()
	db, err := store.OpenBolt(filepath.Join(src, "weistack.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Put(ctx, scope, "a", []byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	for rel, body := range map[string]string{
		"account.json": "{}", "project_id": "p", "vault-key.json": "k", "objects/b/o1": "object",
		"objects/tmp/upload-1": "partial", "backups/reset-1.tar.gz": "old", "weistack.db.format1.bak": "old db",
	} {
		writeFile(t, src, rel, body)
	}

	var archive bytes.Buffer
	m, err := Write(&archive, source(src, db.Snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != store.FormatVersion || !m.VaultKey || m.Version != "v0.3.0-test" {
		t.Fatalf("manifest %+v", m)
	}
	// Writes after the backup are not in it.
	if _, err := db.Put(ctx, scope, "later", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(bytes.NewReader(archive.Bytes()), dst, store.FormatVersion); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{"account.json": "{}", "project_id": "p", "vault-key.json": "k", "objects/b/o1": "object"} {
		if got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel))); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v", rel, got, err)
		}
	}
	for _, rel := range []string{"objects/tmp", "backups", "weistack.db.format1.bak"} {
		if _, err := os.Stat(filepath.Join(dst, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was restored: %v", rel, err)
		}
	}
	restored, err := store.OpenBolt(filepath.Join(dst, "weistack.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if r, err := restored.Get(ctx, scope, "a"); err != nil || string(r.Data) != `{"n":1}` {
		t.Errorf("record a = %+v, %v", r, err)
	}
	if _, err := restored.Get(ctx, scope, "later"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a record written after the backup: %v", err)
	}

	// Restoring never overwrites data.
	if _, err := Restore(bytes.NewReader(archive.Bytes()), dst, store.FormatVersion); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("restore over data: %v", err)
	}
	// A release refuses a newer format.
	if _, err := Restore(bytes.NewReader(archive.Bytes()), filepath.Join(t.TempDir(), "x"), store.FormatVersion-1); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("restore of a newer format: %v", err)
	}
}

func TestSnapshotFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "weistack.db")
	db, err := store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	snap := func(fn func(store.Snapshot) error) error { return store.SnapshotFile(path, fn) }
	if _, err := Write(&bytes.Buffer{}, source(dir, snap)); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("backup of an open database: %v, want ErrInUse", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err := Write(&archive, source(dir, snap)); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(&archive, filepath.Join(t.TempDir(), "r"), store.FormatVersion); err != nil {
		t.Fatal(err)
	}
}

// archiveOf builds an archive with a valid manifest and the given entries.
func archiveOf(t testing.TB, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	manifest, _ := json.Marshal(Manifest{Format: 1})
	all := append([]*tar.Header{{Name: ManifestName, Size: int64(len(manifest)), Mode: 0o600, Typeflag: tar.TypeReg}}, entries...)
	for i, h := range all {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			_, _ = tw.Write(manifest)
		} else if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestRestoreRefusesForeignEntries(t *testing.T) {
	t.Parallel()
	for name, h := range map[string]*tar.Header{
		"a parent path":    {Name: "../escape", Size: 1, Typeflag: tar.TypeReg},
		"a nested parent":  {Name: "objects/../../escape", Size: 1, Typeflag: tar.TypeReg},
		"an absolute path": {Name: "/etc/escape", Size: 1, Typeflag: tar.TypeReg},
		"a symlink":        {Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink},
		"a backslash":      {Name: `..\escape`, Size: 1, Typeflag: tar.TypeReg},
	} {
		parent := t.TempDir()
		dir := filepath.Join(parent, "data")
		if _, err := Restore(bytes.NewReader(archiveOf(t, h)), dir, store.FormatVersion); err == nil {
			t.Errorf("%s: restored", name)
		}
		entries, _ := os.ReadDir(parent)
		if len(entries) != 0 {
			t.Errorf("%s: left %v behind", name, entries)
		}
	}
	if _, err := Restore(strings.NewReader("not an archive"), filepath.Join(t.TempDir(), "d"), store.FormatVersion); err == nil {
		t.Error("restored a non-archive")
	}
}

func TestPrune(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, n := range []string{"reset-20261101T000000Z.tar.gz", "reset-20261102T000000Z.tar.gz", "reset-20261103T000000Z.tar.gz", "other"} {
		writeFile(t, dir, n, "")
	}
	if err := Prune(dir, "reset-", 2); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "other,reset-20261102T000000Z.tar.gz,reset-20261103T000000Z.tar.gz" {
		t.Errorf("left %v", names)
	}
}
