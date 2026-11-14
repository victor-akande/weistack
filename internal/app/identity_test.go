package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
)

var (
	testAccount = identity.Account{ID: "fedcba9876543210fedcba9876543210", Name: identity.AccountName}
	testAdmin   = identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "ADMINSECRET0000000000000000000000000000000"}
)

func readAdminFile(t *testing.T, dir string) identity.Credentials {
	t.Helper()
	path := filepath.Join(dir, adminCredentialsFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the administrator's credentials file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s has mode %v, want 0600", path, info.Mode().Perm())
	}
	var c identity.Credentials
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &c); err != nil || !c.Valid() {
		t.Fatalf("credentials file %s: %v", raw, err)
	}
	return c
}

type servicesInfo struct {
	ProjectID   string `json:"project_id"`
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
}

func (i *instance) services(t *testing.T) servicesInfo {
	t.Helper()
	_, body := i.get(t, "/_weistack/services")
	var out servicesInfo
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAdminCredentialsAreGeneratedOnceBesideTheCA(t *testing.T) {
	t.Parallel()
	tls := t.TempDir()
	first := startInstance(t, map[string]string{"WEISTACK_TLS_DIR": tls})
	creds := readAdminFile(t, tls)
	if len(creds.AccessKey) != identity.AccessKeyLen || len(creds.SecretKey) != identity.SecretKeyLen {
		t.Fatalf("generated credentials %+v", creds)
	}
	logs := first.stdout.String()
	if err := first.stop(t); err != nil {
		t.Fatal(err)
	}
	// The access key is logged; the secret key never is.
	if !strings.Contains(logs, creds.AccessKey) || strings.Contains(logs, creds.SecretKey) {
		t.Fatalf("startup logs: access key logged %v, secret key logged %v", strings.Contains(logs, creds.AccessKey), strings.Contains(logs, creds.SecretKey))
	}

	// Like the CA, they stay the same across restarts, with or without
	// -persist.
	second := startInstance(t, map[string]string{"WEISTACK_TLS_DIR": tls, "WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": t.TempDir()})
	if again := readAdminFile(t, tls); again != creds {
		t.Fatal("the administrator's credentials changed across a restart")
	}
	if strings.Contains(second.stdout.String(), creds.SecretKey) {
		t.Fatal("the secret key was logged")
	}
}

func TestAccountIsKeptWithPersistentData(t *testing.T) {
	t.Parallel()
	vars := map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": t.TempDir()}
	first := startInstance(t, vars)
	acct := first.services(t)
	if len(acct.AccountID) != 32 || acct.AccountName != "weistack" {
		t.Fatalf("services = %+v", acct)
	}
	if err := first.stop(t); err != nil {
		t.Fatal(err)
	}
	second := startInstance(t, vars)
	if got := second.services(t); got.AccountID != acct.AccountID {
		t.Fatalf("account changed across a restart: %s then %s", acct.AccountID, got.AccountID)
	}

	// Without -persist the account is new on every start, like the
	// project ID.
	a := startInstance(t, nil).services(t).AccountID
	b := startInstance(t, nil).services(t).AccountID
	if a == b {
		t.Fatal("two in-memory emulators share an account")
	}
}

func TestConfiguredAdminKeysActForTheAccount(t *testing.T) {
	t.Parallel()
	tls := t.TempDir()
	inst := startInstance(t, map[string]string{
		"WEISTACK_TLS_DIR":          tls,
		"WEISTACK_ADMIN_ACCESS_KEY": testAdmin.AccessKey,
		"WEISTACK_ADMIN_SECRET_KEY": testAdmin.SecretKey,
	})
	// Configured keys are used as they are, never written down.
	if _, err := os.Stat(filepath.Join(tls, adminCredentialsFile)); !os.IsNotExist(err) {
		t.Fatalf("configured keys were saved: %v", err)
	}
	acct := inst.services(t).AccountID

	put := func(auth string) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, "http://"+inst.addr+"/obs/admin-bucket", nil)
		req.Header.Set("Authorization", auth)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if status := put("OBS " + testAdmin.AccessKey + ":c2ln"); status != http.StatusOK {
		t.Fatalf("creating a bucket as the administrator: %d", status)
	}
	status, body := inst.getAuthorized(t, "/obs/", "OBS "+testAdmin.AccessKey+":c2ln")
	if status != http.StatusOK || !strings.Contains(body, "<ID>"+acct+"</ID>") {
		t.Fatalf("the administrator's bucket list does not show the account as owner: %d %s", status, body)
	}
	// An unknown key is still a separate owner, as in v0.1.
	if status := put("OBS AKSTRANGER:c2ln"); status != http.StatusConflict {
		t.Fatalf("another key creating the account's bucket: %d", status)
	}
	if strings.Contains(inst.stdout.String(), testAdmin.SecretKey) {
		t.Fatal("the configured secret key was logged")
	}
}

func TestCredentialsCommand(t *testing.T) {
	t.Parallel()
	tls := t.TempDir()
	run := func(env map[string]string, args ...string) (string, string, error) {
		var out, errOut bytes.Buffer
		err := Run(context.Background(), Env{
			Args: append([]string{"credentials"}, args...), Getenv: func(k string) string { return env[k] },
			Stdout: &out, Stderr: &errOut,
		})
		return out.String(), errOut.String(), err
	}

	out, note, err := run(map[string]string{"WEISTACK_TLS_DIR": tls})
	if err != nil {
		t.Fatal(err)
	}
	creds := readAdminFile(t, tls)
	want := "export HUAWEICLOUD_SDK_AK=" + creds.AccessKey + " HUAWEICLOUD_SDK_SK=" + creds.SecretKey + "\n" +
		"export HW_ACCESS_KEY=" + creds.AccessKey + " HW_SECRET_KEY=" + creds.SecretKey + "\n"
	if out != want || !strings.Contains(note, filepath.Join(tls, adminCredentialsFile)) {
		t.Fatalf("credentials = %q (note %q)", out, note)
	}
	// It prints what a running emulator uses: the same keys every time.
	if again, _, _ := run(map[string]string{"WEISTACK_TLS_DIR": tls}); again != out {
		t.Fatal("credentials changed between runs")
	}

	out, note, err = run(map[string]string{"WEISTACK_ADMIN_ACCESS_KEY": testAdmin.AccessKey, "WEISTACK_ADMIN_SECRET_KEY": testAdmin.SecretKey})
	if err != nil || !strings.Contains(out, "HW_ACCESS_KEY="+testAdmin.AccessKey) || !strings.Contains(note, "configuration") {
		t.Fatalf("configured credentials = %q, %q, %v", out, note, err)
	}

	if _, _, err := run(map[string]string{"WEISTACK_ADMIN_ACCESS_KEY": testAdmin.AccessKey}); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("only an access key: %v", err)
	}
	if _, _, err := run(nil, "-h"); err != nil {
		t.Fatalf("credentials -h: %v", err)
	}
}

func TestCorruptIdentityFiles(t *testing.T) {
	t.Parallel()
	data, tls := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(data, accountFile), []byte(`{"id":"nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), Env{
		Getenv: func(k string) string {
			return map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": data, "WEISTACK_PORT": "0", "WEISTACK_TLS_DIR": tls}[k]
		},
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "valid account") {
		t.Fatalf("a corrupt account file: %v", err)
	}

	if err := os.WriteFile(filepath.Join(tls, adminCredentialsFile), []byte(`{"access_key":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadAdmin(mustConfig(t, map[string]string{"WEISTACK_TLS_DIR": tls}), nil)
	if err == nil || !strings.Contains(err.Error(), "valid credentials") {
		t.Fatalf("a corrupt credentials file: %v", err)
	}
}

func mustConfig(t *testing.T, env map[string]string) config.Config {
	t.Helper()
	cfg, err := config.Load(nil, func(k string) string { return env[k] }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func (i *instance) getAuthorized(t *testing.T, path, authorization string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+i.addr+path, nil)
	req.Header.Set("Authorization", authorization)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

// Emulators starting at once with the same directories agree on one
// account and one set of administrator credentials, and none fails.
func TestConcurrentStartsAgreeOnIdentity(t *testing.T) {
	t.Parallel()
	data, tls := t.TempDir(), t.TempDir()
	cfg := mustConfig(t, map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": data, "WEISTACK_TLS_DIR": tls})

	const n = 16
	accts := make([]identity.Account, n)
	creds := make([]identity.Credentials, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			if accts[i], errs[i] = loadAccount(cfg); errs[i] == nil {
				creds[i], _, errs[i] = loadAdmin(cfg, nil)
			}
		})
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("start %d: %v", i, errs[i])
		}
		if accts[i] != accts[0] || creds[i] != creds[0] {
			t.Fatalf("start %d got a different identity", i)
		}
	}
	if got := readAdminFile(t, tls); got != creds[0] {
		t.Fatal("the credentials file differs from what the starts returned")
	}
	for _, dir := range []string{data, tls} {
		left, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
		if len(left) != 0 {
			t.Fatalf("temporary files left behind: %v", left)
		}
	}
}

// The vault key is kept with persistent data, so secrets sealed before a
// restart open after it.
func TestVaultKeyIsKeptWithPersistentData(t *testing.T) {
	t.Parallel()
	data := t.TempDir()
	cfg := mustConfig(t, map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": data})
	first, err := loadVault(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := first.Seal("secret", "AK")
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadVault(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := second.Open(sealed, "AK"); err != nil || got != "secret" {
		t.Fatalf("after a restart: %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(data, vaultKeyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("vault key file: %v, %v", info, err)
	}

	// Without -persist the key is new on every start.
	mem, err := loadVault(mustConfig(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mem.Open(sealed, "AK"); err == nil {
		t.Fatal("an in-memory vault opened a persisted secret")
	}

	if err := os.WriteFile(filepath.Join(data, vaultKeyFile), []byte(`{"key":"AAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVault(cfg); err == nil || !strings.Contains(err.Error(), "valid key") {
		t.Fatalf("a corrupt vault key: %v", err)
	}
}
