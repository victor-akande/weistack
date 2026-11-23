package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/store"
)

// FuzzRestore restores any bytes. A restore either succeeds inside its
// directory or leaves nothing behind, and never writes beside it.
func FuzzRestore(f *testing.F) {
	f.Add(archiveOf(f))
	f.Add([]byte("\x1f\x8b\x08\x00"))
	f.Add([]byte("not an archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "data")
		_, err := Restore(strings.NewReader(string(data)), dir, store.FormatVersion)
		entries, _ := os.ReadDir(parent)
		switch {
		case err != nil && len(entries) != 0:
			t.Fatalf("a failed restore left %v", entries)
		case err == nil && (len(entries) != 1 || entries[0].Name() != "data"):
			t.Fatalf("a restore wrote %v", entries)
		}
	})
}
