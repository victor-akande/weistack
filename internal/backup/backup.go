// Package backup writes and restores archives of a WeiStack data
// directory: a consistent copy of the database, taken while WeiStack
// runs, and the files beside it (the account, the project ID, object
// data and, when it is kept with the data, the vault key).
//
// An archive is a gzipped tar whose first entry is a manifest naming the
// release and the store format that wrote it. A release restores archives
// of its own format and older ones, which it then migrates on start like
// any older data directory; it refuses archives of a newer format.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/store"
)

// ManifestName is the archive's first entry.
const ManifestName = "weistack-backup.json"

// Manifest describes an archive.
type Manifest struct {
	Version  string    `json:"weistack_version"`
	Format   uint64    `json:"store_format"`
	Created  time.Time `json:"created"`
	VaultKey bool      `json:"vault_key_included"`
}

// Source is a data directory to archive.
type Source struct {
	// Dir is the data directory.
	Dir string
	// Database is the database's file name in Dir, and Snapshot copies
	// it: the open store's Snapshot, or store.SnapshotFile's.
	Database string
	Snapshot func(func(store.Snapshot) error) error
	// VaultKey is the vault key's file name in Dir.
	VaultKey string
	// Exclude are paths in Dir, slash-separated, left out with
	// everything under them.
	Exclude []string
	// Version is the release writing the archive.
	Version string
	Now     func() time.Time
}

// Write writes an archive of src to w.
func Write(w io.Writer, src Source) (Manifest, error) {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := time.Now
	if src.Now != nil {
		now = src.Now
	}
	m := Manifest{Version: src.Version, Created: now().UTC().Truncate(time.Second)}
	if _, err := os.Stat(filepath.Join(src.Dir, src.VaultKey)); err == nil {
		m.VaultKey = true
	}
	// The database first, inside its snapshot, which holds up writers
	// that grow the file: the other files are copied after it.
	err := src.Snapshot(func(s store.Snapshot) error {
		m.Format = s.Format
		manifest, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		if err := writeEntry(tw, ManifestName, m.Created, int64(len(manifest)), func(w io.Writer) error {
			_, err := w.Write(manifest)
			return err
		}); err != nil {
			return err
		}
		return writeEntry(tw, src.Database, m.Created, s.Size, func(w io.Writer) error {
			_, err := s.WriteTo(w)
			return err
		})
	})
	if err != nil {
		return Manifest{}, fmt.Errorf("backup: the database: %w", err)
	}
	if err := writeFiles(tw, src); err != nil {
		return Manifest{}, err
	}
	if err := tw.Close(); err != nil {
		return Manifest{}, err
	}
	return m, gz.Close()
}

// writeFiles adds the regular files in src.Dir, but the database and
// excluded paths, in a stable order.
func writeFiles(tw *tar.Writer, src Source) error {
	skip := func(rel string) bool {
		if rel == src.Database || strings.HasPrefix(rel, src.Database+".") { // the database, its upgrade backups
			return true
		}
		for _, e := range src.Exclude {
			if rel == e || strings.HasPrefix(rel, e+"/") {
				return true
			}
		}
		return false
	}
	var files []string
	err := filepath.WalkDir(src.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src.Dir, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if skip(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			files = append(files, rel)
		}
		return nil // directories are implied, links are not followed
	})
	if err != nil {
		return fmt.Errorf("backup: reading %s: %w", src.Dir, err)
	}
	sort.Strings(files)
	for _, rel := range files {
		if err := addFile(tw, src.Dir, rel); err != nil {
			return err
		}
	}
	return nil
}

func addFile(tw *tar.Writer, dir, rel string) error {
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(rel))) //nolint:gosec // a file in the data directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil // deleted since the walk, as an object can be
	}
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	return writeEntry(tw, rel, info.ModTime(), info.Size(), func(w io.Writer) error {
		_, err := io.CopyN(w, f, info.Size())
		return err
	})
}

func writeEntry(tw *tar.Writer, name string, mod time.Time, size int64, body func(io.Writer) error) error {
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: mod, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("backup: %s: %w", name, err)
	}
	if err := body(tw); err != nil {
		return fmt.Errorf("backup: %s: %w", name, err)
	}
	return nil
}

// Restore unpacks the archive in r into dir, which must be missing or
// empty: an existing data directory is never overwritten. It refuses an
// archive of a store format newer than maxFormat. The directory appears
// complete or not at all.
func Restore(r io.Reader, dir string, maxFormat uint64) (Manifest, error) {
	if err := mustBeEmpty(dir); err != nil {
		return Manifest{}, err
	}
	parent := filepath.Dir(filepath.Clean(dir))
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return Manifest{}, fmt.Errorf("restore: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(dir)+".restoring-")
	if err != nil {
		return Manifest{}, fmt.Errorf("restore: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }() // harmless once renamed
	m, err := unpack(r, tmp, maxFormat)
	if err != nil {
		return Manifest{}, err
	}
	// An empty directory is replaced; mustBeEmpty checked it.
	if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, fmt.Errorf("restore: %w", err)
	}
	if err := os.Rename(tmp, dir); err != nil {
		return Manifest{}, fmt.Errorf("restore: %w", err)
	}
	return m, nil
}

func mustBeEmpty(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("restore: %w", err)
	case len(entries) > 0:
		return fmt.Errorf("restore: %s is not empty; move it aside or choose another -data-dir: restoring never overwrites data", dir)
	}
	return nil
}

func unpack(r io.Reader, dir string, maxFormat uint64) (Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return Manifest{}, errors.New("restore: not a WeiStack backup (not gzip)")
	}
	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != ManifestName || hdr.Size > 1<<16 {
		return Manifest{}, errors.New("restore: not a WeiStack backup (no manifest)")
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(tr, 1<<16)).Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("restore: reading the manifest: %w", err)
	}
	if m.Format > maxFormat {
		return Manifest{}, fmt.Errorf("restore: the backup is store format %d, made by WeiStack %s, and this release reads up to format %d; restore it with that release or a newer one",
			m.Format, m.Version, maxFormat)
	}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return m, nil
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("restore: %w", err)
		}
		if err := extract(tr, hdr, dir); err != nil {
			return Manifest{}, err
		}
	}
}

// extract writes one regular file, refusing names that would land
// outside dir and every other kind of entry.
func extract(tr *tar.Reader, hdr *tar.Header, dir string) error {
	name := path.Clean(hdr.Name)
	if hdr.Typeflag != tar.TypeReg || name == "." || name == ManifestName || path.IsAbs(name) ||
		name == ".." || strings.HasPrefix(name, "../") || strings.Contains(hdr.Name, "\\") {
		return fmt.Errorf("restore: the backup holds an entry WeiStack does not write: %q", hdr.Name)
	}
	dst := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // checked to be inside dir
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if _, err := io.CopyN(f, tr, hdr.Size); err != nil {
		_ = f.Close()
		return fmt.Errorf("restore: %s: %w", name, err)
	}
	return f.Close()
}

// Prune deletes all but the newest keep files in dir whose names start
// with prefix. Names carry a sortable timestamp.
func Prune(dir, prefix string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), prefix) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var errs []error
	for len(names) > keep {
		errs = append(errs, os.Remove(filepath.Join(dir, names[0])))
		names = names[1:]
	}
	return errors.Join(errs...)
}
