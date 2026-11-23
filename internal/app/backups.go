package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/victor-akande/weistack/internal/backup"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/obs"
	"github.com/victor-akande/weistack/internal/version"
)

const (
	// backupsDir keeps the archives taken before resets, in the data
	// directory.
	backupsDir = "backups"
	// resetBackupPrefix names those archives; resetBackupsKept are kept.
	resetBackupPrefix = "reset-"
	resetBackupsKept  = 3
)

// backupSource describes the data directory to archive, with the
// database copied by snapshot.
func backupSource(cfg config.Config, snapshot func(func(store.Snapshot) error) error) backup.Source {
	return backup.Source{
		Dir: cfg.DataDir, Database: databaseFile, Snapshot: snapshot, VaultKey: vaultKeyFile,
		Exclude: []string{backupsDir, objectsDir + "/" + obs.TempDir},
		Version: version.Version,
	}
}

// dataBackups archives a running WeiStack's persisted data.
type dataBackups struct {
	cfg config.Config
	db  *store.Bolt
	log *slog.Logger
	now func() time.Time
}

func (b *dataBackups) Write(_ context.Context, w io.Writer) error {
	_, err := backup.Write(w, backupSource(b.cfg, b.db.Snapshot))
	return err
}

// BeforeReset archives the data into the backups directory, keeping the
// newest few.
func (b *dataBackups) BeforeReset(ctx context.Context) (string, error) {
	dir := filepath.Join(b.cfg.DataDir, backupsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, resetBackupPrefix+b.now().UTC().Format("20060102T150405.000Z")+".tar.gz")
	if err := writeArchive(path, func(w io.Writer) error { return b.Write(ctx, w) }); err != nil {
		return "", err
	}
	if err := backup.Prune(dir, resetBackupPrefix, resetBackupsKept); err != nil {
		b.log.WarnContext(ctx, "removing old reset backups", "error", err)
	}
	return path, nil
}

// writeArchive writes a file that appears complete or not at all.
func writeArchive(path string, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".backup-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // harmless once renamed
	if err := write(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := errors.Join(tmp.Sync(), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// checkDataDir refuses a data directory other users may write to: they
// could change WeiStack's data, or the vault key kept with it. Inside a
// container, where a mounted volume's mode is often widened to fit the
// container's user, it only warns. Windows has no such mode bits.
func checkDataDir(cfg config.Config, log *slog.Logger) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(cfg.DataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil // created private
	}
	if err != nil {
		return fmt.Errorf("the data directory: %w", err)
	}
	if info.Mode().Perm()&0o022 == 0 {
		return nil
	}
	msg := fmt.Sprintf("the data directory %s can be written by other users (mode %04o): they could change WeiStack's data and its vault key", cfg.DataDir, info.Mode().Perm())
	fix := "chmod go-w " + cfg.DataDir
	if cfg.InContainer {
		log.Warn(msg, "fix", fix)
		return nil
	}
	return fmt.Errorf("%s; run %s", msg, fix)
}
