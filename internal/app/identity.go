package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/vault"
)

const (
	// accountFile keeps the account with the data under -persist.
	accountFile = "account.json"
	// adminCredentialsFile keeps the administrator's keys beside the CA.
	adminCredentialsFile = "admin-credentials.json" //nolint:gosec // a file name, not a credential
	// vaultKeyFile keeps the key that seals secrets in the store, with
	// the data under -persist.
	vaultKeyFile = "vault-key.json"
)

// vaultKey is the contents of vaultKeyFile.
type vaultKey struct {
	Key []byte `json:"key"`
}

func newVaultKey() (vaultKey, error) {
	k, err := vault.NewKey()
	return vaultKey{Key: k}, err
}

func (k vaultKey) valid() bool { return len(k.Key) == vault.KeyLen }

// loadVault returns the vault that seals secrets in the store. Its key is
// kept with the data under -persist, since the data cannot be read
// without it, or in -vault-key-file, and is new on every start without
// -persist.
func loadVault(cfg config.Config) (*vault.Vault, error) {
	key, err := newVaultKey()
	if err != nil {
		return nil, err
	}
	if cfg.Persist {
		path, err := vaultKeyPath(cfg)
		if err != nil {
			return nil, dataError(err)
		}
		key, err = loadOrCreate(path, newVaultKey, vaultKey.valid)
		switch {
		case errors.Is(err, errInvalid):
			return nil, dataError(fmt.Errorf("%s does not hold a valid key; the access keys stored with it cannot be used", path))
		case err != nil:
			return nil, dataError(fmt.Errorf("the vault key: %w", err))
		}
	}
	return vault.New(key.Key)
}

// vaultKeyPath is where the vault key is kept. A -vault-key-file must
// not leave behind or contradict a key already in the data directory:
// the data was sealed with that one, and a new key could not open it.
func vaultKeyPath(cfg config.Config) (string, error) {
	inData := filepath.Join(cfg.DataDir, vaultKeyFile)
	if cfg.VaultKeyFile == "" {
		return inData, nil
	}
	file := cfg.VaultKeyFile
	if same, err := samePath(file, inData); err != nil || same {
		return file, err
	}
	old, err := readJSON[vaultKey](inData)
	if errors.Is(err, fs.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", inData, err)
	}
	cur, err := readJSON[vaultKey](file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("the data in %s is sealed with %s; move that file to %s (-vault-key-file), or unset -vault-key-file", cfg.DataDir, inData, file)
	case err != nil:
		return "", fmt.Errorf("reading %s: %w", file, err)
	case !bytes.Equal(cur.Key, old.Key):
		return "", fmt.Errorf("%s and %s hold different vault keys; keep the one the data was sealed with and delete the other", file, inData)
	}
	return "", fmt.Errorf("%s is also in %s; delete it from there, now that -vault-key-file keeps it", vaultKeyFile, cfg.DataDir)
}

// samePath reports whether a and b name the same file, or would.
func samePath(a, b string) (bool, error) {
	absA, err := filepath.Abs(a)
	if err != nil {
		return false, err
	}
	absB, err := filepath.Abs(b)
	if err != nil {
		return false, err
	}
	return absA == absB, nil
}

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
		return identity.Account{}, dataError(fmt.Errorf("%s does not describe a valid account; delete it to create a new one", path))
	case err != nil:
		return identity.Account{}, dataError(fmt.Errorf("the account: %w", err))
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

// adminFileExists reports whether cfg's TLS directory already holds the
// administrator's keys.
func adminFileExists(cfg config.Config) bool {
	dir := tlsDir(cfg)
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, adminCredentialsFile))
	return err == nil
}

func adminFromDir(dir string) (identity.Credentials, error) {
	path := filepath.Join(dir, adminCredentialsFile)
	creds, err := loadOrCreate(path, identity.NewCredentials, identity.Credentials.Valid)
	switch {
	case errors.Is(err, errInvalid):
		return identity.Credentials{}, dataError(fmt.Errorf("%s does not hold valid credentials; delete it to generate new ones", path))
	case err != nil:
		return identity.Credentials{}, dataError(fmt.Errorf("the administrator's credentials: %w", err))
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

type credentialsEnvOutput struct {
	HuaweiCloudSDKAK string `json:"HUAWEICLOUD_SDK_AK"`
	HuaweiCloudSDKSK string `json:"HUAWEICLOUD_SDK_SK"`
	HWAccessKey      string `json:"HW_ACCESS_KEY"`
	HWSecretKey      string `json:"HW_SECRET_KEY"`
}

type credentialsOutput struct {
	Source string `json:"source"`
	// Created is true when there were no keys to print, so these were
	// made now: no running WeiStack uses them unless it started from
	// the same -tls-dir after this.
	Created   bool                 `json:"created"`
	AccessKey string               `json:"access_key"`
	SecretKey string               `json:"secret_key"`
	Env       credentialsEnvOutput `json:"env"`
}

// printCredentials writes the administrator's credentials as shell
// exports, for the SDKs and Terraform:
//
//	eval "$(weistack credentials)"
func printCredentials(env Env) error {
	cfg, help, err := loadConfig(env.Args[1:], env)
	if help {
		return nil
	}
	if err != nil {
		return err
	}
	created := cfg.AdminAccessKey == "" && !adminFileExists(cfg)
	creds, from, err := loadAdmin(cfg, slog.New(slog.NewTextHandler(env.Stderr, nil)))
	if err != nil {
		return err
	}
	if cfg.Output == config.OutputJSON {
		return writeJSON(env.Stdout, credentialsOutput{
			Source:    from,
			Created:   created,
			AccessKey: creds.AccessKey,
			SecretKey: creds.SecretKey,
			Env: credentialsEnvOutput{
				HuaweiCloudSDKAK: creds.AccessKey,
				HuaweiCloudSDKSK: creds.SecretKey,
				HWAccessKey:      creds.AccessKey,
				HWSecretKey:      creds.SecretKey,
			},
		})
	}
	fmt.Fprintf(env.Stderr, "WeiStack administrator, from %s\n", from)
	if created {
		fmt.Fprintln(env.Stderr, "warning: there were no administrator keys, so these were made now; "+
			"a WeiStack started before with another -tls-dir does not know them. "+
			"To print a running WeiStack's keys, give -tls-dir the directory it was started with.")
	}
	_, err = fmt.Fprintf(env.Stdout,
		"export HUAWEICLOUD_SDK_AK=%[1]s HUAWEICLOUD_SDK_SK=%[2]s\nexport HW_ACCESS_KEY=%[1]s HW_SECRET_KEY=%[2]s\n",
		creds.AccessKey, creds.SecretKey)
	return err
}
