package obs

import (
	"fmt"
	"os"
	"path/filepath"
)

// blobStore keeps object bodies as files under one directory.
type blobStore struct {
	dir string
}

func newBlobStore(dir string) (*blobStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("obs: creating data directory: %w", err)
	}
	return &blobStore{dir: dir}, nil
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
	return nil
}
