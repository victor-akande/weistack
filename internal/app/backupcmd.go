package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/backup"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/store"
)

// fileAndFlags splits "COMMAND [FILE] [flags]".
func fileAndFlags(args []string) (string, []string) {
	if len(args) > 0 && (args[0] == "-" || !strings.HasPrefix(args[0], "-")) {
		return args[0], args[1:]
	}
	return "", args
}

// backupCommand archives the data directory: weistack backup [FILE]
// [flags], FILE "-" for stdout. A data directory no WeiStack has open is
// read directly; one in use is archived by the WeiStack running on it,
// through its admin API.
func backupCommand(ctx context.Context, env Env) error {
	file, args := fileAndFlags(env.Args[1:])
	cfg, err := config.Load(args, env.Getenv, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if file == "" {
		file = "weistack-backup-" + time.Now().UTC().Format("20060102T150405Z") + ".tar.gz"
	}
	db := filepath.Join(cfg.DataDir, databaseFile)
	if _, err := os.Stat(db); err != nil {
		return fmt.Errorf("backup: no WeiStack data in %s (-data-dir): %w", cfg.DataDir, err)
	}

	write := func(w io.Writer) error {
		snapshot := func(fn func(store.Snapshot) error) error { return store.SnapshotFile(db, fn) }
		_, err := backup.Write(w, backupSource(cfg, snapshot))
		return err
	}
	if err := probeOffline(db); errors.Is(err, store.ErrInUse) {
		fmt.Fprintf(env.Stderr, "%s is in use; asking the WeiStack on port %d for the backup\n", db, cfg.Port)
		write = func(w io.Writer) error { return backupFromServer(ctx, cfg, env, w) }
	} else if err != nil {
		return err
	}

	if file == "-" {
		return write(env.Stdout)
	}
	if err := writeArchive(file, write); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	fmt.Fprintf(env.Stderr, "backed up %s to %s\n", cfg.DataDir, file)
	return nil
}

// probeOffline reports store.ErrInUse when a process has db open.
func probeOffline(db string) error {
	return store.SnapshotFile(db, func(store.Snapshot) error { return nil })
}

func backupFromServer(ctx context.Context, cfg config.Config, env Env, w io.Writer) error {
	res, err := adminRequest(ctx, cfg, env, http.MethodGet, adminPrefixPath+"/backup", "")
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		return fmt.Errorf("backup: the WeiStack on port %d answered %s: %s", cfg.Port, res.Status, bytes.TrimSpace(out))
	}
	_, err = io.Copy(w, res.Body)
	return err
}

// restoreCommand unpacks an archive into the data directory, which must
// be missing or empty: weistack restore FILE [flags].
func restoreCommand(env Env) error {
	file, args := fileAndFlags(env.Args[1:])
	cfg, err := config.Load(args, env.Getenv, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if file == "" {
		return errors.New("usage: weistack restore FILE [flags]; the data goes to -data-dir, which must be missing or empty")
	}
	var r io.Reader = os.Stdin
	if file != "-" {
		f, err := os.Open(file) //nolint:gosec // the operator's archive
		if err != nil {
			return fmt.Errorf("restore: %w", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	m, err := backup.Restore(r, cfg.DataDir, store.FormatVersion)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stderr, "restored a backup made by WeiStack %s on %s into %s; start WeiStack with -persist -data-dir %s\n",
		m.Version, m.Created.Format(time.RFC3339), cfg.DataDir, cfg.DataDir)
	if !m.VaultKey {
		fmt.Fprintln(env.Stderr, "the backup holds no vault key: it was kept apart (-vault-key-file); start WeiStack with that same key file")
	}
	return nil
}
