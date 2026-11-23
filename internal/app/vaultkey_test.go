package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
)

func TestVaultKeyFile(t *testing.T) {
	t.Parallel()
	seal := func(t *testing.T, cfg config.Config) []byte {
		t.Helper()
		v, err := loadVault(cfg)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := v.Seal("secret", "test")
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	open := func(t *testing.T, cfg config.Config, sealed []byte) {
		t.Helper()
		v, err := loadVault(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := v.Open(sealed, "test"); err != nil || got != "secret" {
			t.Fatalf("Open = %q, %v", got, err)
		}
	}

	t.Run("a new key is created in the file, not the data", func(t *testing.T) {
		t.Parallel()
		data, keys := t.TempDir(), t.TempDir()
		cfg := config.Config{Persist: true, DataDir: data, VaultKeyFile: filepath.Join(keys, "vault.json")}
		sealed := seal(t, cfg)
		if _, err := os.Stat(filepath.Join(data, vaultKeyFile)); !os.IsNotExist(err) {
			t.Fatalf("the data directory has a key: %v", err)
		}
		open(t, cfg, sealed)
	})

	t.Run("a key moved out of the data still opens it", func(t *testing.T) {
		t.Parallel()
		data, keys := t.TempDir(), t.TempDir()
		inData := config.Config{Persist: true, DataDir: data}
		sealed := seal(t, inData)
		moved := filepath.Join(keys, "vault.json")
		if err := os.Rename(filepath.Join(data, vaultKeyFile), moved); err != nil {
			t.Fatal(err)
		}
		open(t, config.Config{Persist: true, DataDir: data, VaultKeyFile: moved}, sealed)
	})

	t.Run("naming the data's own key file is the default", func(t *testing.T) {
		t.Parallel()
		data := t.TempDir()
		sealed := seal(t, config.Config{Persist: true, DataDir: data})
		open(t, config.Config{Persist: true, DataDir: data, VaultKeyFile: filepath.Join(data, vaultKeyFile)}, sealed)
	})

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, data, file string)
		want  string
	}{
		{"a key left in the data", func(t *testing.T, data, _ string) {
			seal(t, config.Config{Persist: true, DataDir: data})
		}, "move that file"},
		{"a copy left in the data", func(t *testing.T, data, file string) {
			seal(t, config.Config{Persist: true, DataDir: data})
			copyFile(t, filepath.Join(data, vaultKeyFile), file)
		}, "delete it from there"},
		{"two different keys", func(t *testing.T, data, file string) {
			seal(t, config.Config{Persist: true, DataDir: data})
			seal(t, config.Config{Persist: true, DataDir: t.TempDir(), VaultKeyFile: file})
		}, "different vault keys"},
	} {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			t.Parallel()
			data, file := t.TempDir(), filepath.Join(t.TempDir(), "vault.json")
			tc.setup(t, data, file)
			before, _ := os.ReadFile(filepath.Join(data, vaultKeyFile))
			_, err := loadVault(config.Config{Persist: true, DataDir: data, VaultKeyFile: file})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadVault = %v, want an error with %q", err, tc.want)
			}
			if after, _ := os.ReadFile(filepath.Join(data, vaultKeyFile)); string(after) != string(before) {
				t.Fatal("the data's key changed")
			}
		})
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
