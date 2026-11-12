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
	var acct identity.Account
	if err := readJSON(path, &acct); err == nil {
		if !acct.Valid() {
			return identity.Account{}, fmt.Errorf("%s does not describe a valid account; delete it to create a new one", path)
		}
		return acct, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return identity.Account{}, fmt.Errorf("reading the account: %w", err)
	}
	acct, err := identity.NewAccount()
	if err != nil {
		return identity.Account{}, err
	}
	if err := writeJSON(path, acct); err != nil {
		return identity.Account{}, fmt.Errorf("saving the account: %w", err)
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
	var creds identity.Credentials
	err := readJSON(path, &creds)
	switch {
	case err == nil && creds.Valid():
		return creds, nil
	case err == nil:
		return identity.Credentials{}, fmt.Errorf("%s does not hold valid credentials; delete it to generate new ones", path)
	case !errors.Is(err, fs.ErrNotExist):
		return identity.Credentials{}, fmt.Errorf("reading the administrator's credentials: %w", err)
	}
	if creds, err = identity.NewCredentials(); err != nil {
		return identity.Credentials{}, err
	}
	if err := writeJSON(path, creds); err != nil {
		return identity.Credentials{}, fmt.Errorf("saving the administrator's credentials: %w", err)
	}
	return creds, nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-chosen directory
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// writeJSON creates path, readable by its owner only, and fails if it
// exists: two emulators starting at once must not overwrite each other.
func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // an operator-chosen directory
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
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
