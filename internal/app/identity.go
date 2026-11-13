package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
)

const (
	// accountFile keeps the account with the data under -persist.
	accountFile = "account.json"
	// adminCredentialsFile keeps the administrator's keys beside the CA.
	adminCredentialsFile = "admin-credentials.json" //nolint:gosec // a file name, not a credential
)

// loadAccount returns the emulator's account: kept in the data directory
// with -persist, new on every start without it, like the project ID.
func loadAccount(cfg config.Config) (identity.Account, error) {
	if !cfg.Persist {
		return identity.NewAccount()
	}
	path := filepath.Join(cfg.DataDir, accountFile)
	acct, err := loadOrCreate(path, identity.NewAccount, identity.Account.Valid)
	switch {
	case errors.Is(err, errInvalid):
		return identity.Account{}, fmt.Errorf("%s does not describe a valid account; delete it to create a new one", path)
	case err != nil:
		return identity.Account{}, fmt.Errorf("the account: %w", err)
	}
	return acct, nil
}

// loadAdmin returns the bootstrap administrator's credentials: the
// configured ones, or those kept beside the CA, generated on first use.
// Like the CA they do not depend on -persist, so clients configured with
// them keep working. The second result says where they came from.
func loadAdmin(cfg config.Config, log *slog.Logger) (identity.Credentials, string, error) {
	if cfg.AdminAccessKey != "" {
		return identity.Credentials{AccessKey: cfg.AdminAccessKey, SecretKey: cfg.AdminSecretKey}, "the configuration", nil
	}
	dir := tlsDir(cfg)
	if dir != "" {
		creds, err := adminFromDir(dir)
		if err == nil {
			return creds, filepath.Join(dir, adminCredentialsFile), nil
		}
		if cfg.TLSDir != "" {
			return identity.Credentials{}, "", err // an explicit choice must work
		}
		log.Warn("keeping the administrator's credentials in memory", "error", err)
	}
	creds, err := identity.NewCredentials()
	return creds, "memory (new on every start)", err
}

func adminFromDir(dir string) (identity.Credentials, error) {
	path := filepath.Join(dir, adminCredentialsFile)
	creds, err := loadOrCreate(path, identity.NewCredentials, identity.Credentials.Valid)
	switch {
	case errors.Is(err, errInvalid):
		return identity.Credentials{}, fmt.Errorf("%s does not hold valid credentials; delete it to generate new ones", path)
	case err != nil:
		return identity.Credentials{}, fmt.Errorf("the administrator's credentials: %w", err)
	}
	return creds, nil
}

var errInvalid = errors.New("invalid contents")

// loadOrCreate reads the JSON value kept at path, or creates it with
// fresh() if there is none. Emulators starting at once with the same
// directory agree on one value: the file appears complete or not at all,
// is never overwritten, and whoever loses the race reads the winner's.
func loadOrCreate[T any](path string, fresh func() (T, error), valid func(T) bool) (T, error) {
	var zero T
	for range 2 {
		v, err := readJSON[T](path)
		switch {
		case err == nil && valid(v):
			return v, nil
		case err == nil:
			return zero, errInvalid
		case !errors.Is(err, fs.ErrNotExist):
			return zero, fmt.Errorf("reading %s: %w", path, err)
		}
		if v, err = fresh(); err != nil {
			return zero, err
		}
		err = createJSON(path, v)
		switch {
		case err == nil:
			return v, nil
		case !errors.Is(err, fs.ErrExist):
			return zero, fmt.Errorf("saving %s: %w", path, err)
		}
		// Another emulator created it first: read theirs.
	}
	return zero, fmt.Errorf("%s keeps appearing and disappearing", path)
}

func readJSON[T any](path string) (T, error) {
	var v T
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-chosen directory
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(raw, &v)
}

// createJSON writes v to path, readable by its owner only. It writes a
// temporary file and links it into place, so path appears complete, and
// fails with fs.ErrExist if path already exists.
func createJSON(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Link(tmp, path)
}

// printCredentials writes the administrator's credentials as shell
// exports, for the SDKs and Terraform:
//
//	eval "$(weistack credentials)"
func printCredentials(env Env) error {
	cfg, err := config.Load(env.Args[1:], env.Getenv, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	creds, from, err := loadAdmin(cfg, slog.New(slog.NewTextHandler(env.Stderr, nil)))
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stderr, "WeiStack administrator, from %s\n", from)
	_, err = fmt.Fprintf(env.Stdout,
		"export HUAWEICLOUD_SDK_AK=%[1]s HUAWEICLOUD_SDK_SK=%[2]s\nexport HW_ACCESS_KEY=%[1]s HW_SECRET_KEY=%[2]s\n",
		creds.AccessKey, creds.SecretKey)
	return err
}
