package obs

import (
	"crypto/md5" //nolint:gosec // ETags are MD5 by protocol, not for security
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// blobStore keeps object bodies as files under one directory. A body is
// immutable once stored: overwriting an object stores a new blob, so a
// download in progress keeps reading the old file undisturbed.
type blobStore struct {
	dir string
}

const blobTempDir = "tmp"

func newBlobStore(dir string) (*blobStore, error) {
	if err := os.MkdirAll(filepath.Join(dir, blobTempDir), 0o750); err != nil {
		return nil, fmt.Errorf("obs: creating data directory: %w", err)
	}
	return &blobStore{dir: dir}, nil
}

// path spreads blobs over 256 subdirectories by the first two characters
// of their ID, so no directory grows without bound.
func (b *blobStore) path(id string) string {
	return filepath.Join(b.dir, id[:2], id)
}

// put streams body into a new blob named id and returns its size and
// hex MD5. The body is written to a temporary file and moved into place
// only when complete, so a failed or aborted upload leaves nothing.
func (b *blobStore) put(id string, body io.Reader) (size int64, sum string, err error) {
	tmp, err := os.CreateTemp(filepath.Join(b.dir, blobTempDir), "upload-*")
	if err != nil {
		return 0, "", fmt.Errorf("obs: creating upload file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	hash := md5.New() //nolint:gosec // see import
	if size, err = io.Copy(io.MultiWriter(tmp, hash), body); err != nil {
		return 0, "", err // the client's fault as often as ours: returned as is
	}
	if err = tmp.Close(); err != nil {
		return 0, "", fmt.Errorf("obs: closing upload file: %w", err)
	}
	if err = b.install(tmp.Name(), id); err != nil {
		return 0, "", err
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}

// install moves a finished temporary file into place as blob id.
func (b *blobStore) install(tmpName, id string) error {
	dst := b.path(id)
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return fmt.Errorf("obs: creating blob directory: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("obs: storing blob: %w", err)
	}
	return nil
}

// link makes blob dst share the content of blob src. Blobs are
// immutable, so a hard link is a safe, instant copy; if the filesystem
// refuses, the bytes are copied.
func (b *blobStore) link(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(b.path(dst)), 0o750); err != nil {
		return fmt.Errorf("obs: creating blob directory: %w", err)
	}
	if err := os.Link(b.path(src), b.path(dst)); err == nil {
		return nil
	}
	in, err := b.open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_, _, err = b.put(dst, in)
	return err
}

// open returns a blob for reading.
func (b *blobStore) open(id string) (*os.File, error) {
	f, err := os.Open(b.path(id))
	if err != nil {
		return nil, fmt.Errorf("obs: opening blob: %w", err)
	}
	return f, nil
}

// remove deletes a blob. A blob that is already gone is not an error.
func (b *blobStore) remove(id string) error {
	if err := os.Remove(b.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("obs: removing blob: %w", err)
	}
	return nil
}

// reset removes every stored body.
func (b *blobStore) reset() error {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return fmt.Errorf("obs: reading data directory: %w", err)
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(b.dir, e.Name())); err != nil {
			return fmt.Errorf("obs: clearing data directory: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Join(b.dir, blobTempDir), 0o750); err != nil {
		return fmt.Errorf("obs: recreating data directory: %w", err)
	}
	return nil
}
