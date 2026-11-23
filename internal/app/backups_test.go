package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/backup"
	"github.com/victor-akande/weistack/internal/core/store"
)

const backupProject = "0123456789abcdef0123456789abcdef"

func persistVars(dataDir string) map[string]string {
	return map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": dataDir, "WEISTACK_PROJECT_ID": backupProject}
}

func createVPC(t *testing.T, inst *instance, name string) {
	t.Helper()
	res, err := http.Post("http://"+inst.addr+"/vpc/v1/"+backupProject+"/vpcs", "application/json",
		strings.NewReader(`{"vpc":{"name":"`+name+`","cidr":"10.0.0.0/16"}}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create VPC %s = %d", name, res.StatusCode)
	}
}

func hasVPC(t *testing.T, inst *instance, name string) bool {
	t.Helper()
	_, body := inst.get(t, "/vpc/v1/"+backupProject+"/vpcs")
	return strings.Contains(body, `"`+name+`"`)
}

func runCommand(t *testing.T, vars map[string]string, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := Run(context.Background(), Env{Args: args, Getenv: func(k string) string { return vars[k] }, Stdout: &out, Stderr: &errOut})
	if err != nil {
		return errOut.String(), err
	}
	return errOut.String(), nil
}

func TestResetKeepsABackup(t *testing.T) {
	t.Parallel()
	data := t.TempDir()
	inst := startInstance(t, persistVars(data))
	var backups []string
	for i := range 4 {
		createVPC(t, inst, "before-reset")
		res, err := http.Post("http://"+inst.addr+"/_weistack/reset", "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		var out struct{ Backup string }
		_ = json.NewDecoder(res.Body).Decode(&out)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK || !strings.HasPrefix(out.Backup, filepath.Join(data, backupsDir)) {
			t.Fatalf("reset %d = %d, backup %q", i, res.StatusCode, out.Backup)
		}
		backups = append(backups, out.Backup)
	}
	if hasVPC(t, inst, "before-reset") {
		t.Fatal("the reset kept the VPC")
	}
	entries, _ := os.ReadDir(filepath.Join(data, backupsDir))
	if len(entries) != resetBackupsKept {
		t.Fatalf("%d reset backups kept, want %d", len(entries), resetBackupsKept)
	}

	// The newest holds the VPC the last reset wiped.
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err := runCommand(t, persistVars(restored), "restore", backups[len(backups)-1]); err != nil {
		t.Fatal(err)
	}
	again := startInstance(t, persistVars(restored))
	if !hasVPC(t, again, "before-reset") {
		t.Fatal("the reset backup does not hold the wiped VPC")
	}
}

func TestBackupCommand(t *testing.T) {
	t.Parallel()
	data, tls := t.TempDir(), t.TempDir()
	vars := persistVars(data)
	vars["WEISTACK_TLS_DIR"] = tls
	vars["WEISTACK_IAM"] = "enforce" // the command signs its request
	inst := startInstance(t, vars)
	_, port, _ := net.SplitHostPort(inst.addr)
	cmdVars := map[string]string{"WEISTACK_DATA_DIR": data, "WEISTACK_TLS_DIR": tls}

	// While WeiStack runs, through its admin API.
	online := filepath.Join(t.TempDir(), "online.tar.gz")
	if msg, err := runCommand(t, cmdVars, "backup", online, "-port", port); err != nil || !strings.Contains(msg, "in use") {
		t.Fatalf("backup while running: %v (%s)", err, msg)
	}
	if err := inst.stop(t); err != nil {
		t.Fatal(err)
	}
	// Once it has stopped, from the files.
	offline := filepath.Join(t.TempDir(), "offline.tar.gz")
	if msg, err := runCommand(t, cmdVars, "backup", offline); err != nil || strings.Contains(msg, "in use") {
		t.Fatalf("backup of a stopped WeiStack: %v (%s)", err, msg)
	}

	for _, archive := range []string{online, offline} {
		dst := filepath.Join(t.TempDir(), "data")
		if _, err := runCommand(t, map[string]string{"WEISTACK_DATA_DIR": dst}, "restore", archive); err != nil {
			t.Fatalf("restore %s: %v", archive, err)
		}
		for _, f := range []string{databaseFile, accountFile, vaultKeyFile} { // the project ID is configured, so not saved
			if _, err := os.Stat(filepath.Join(dst, f)); err != nil {
				t.Errorf("%s: %v", filepath.Base(archive), err)
			}
		}
	}

	// Restoring never overwrites a data directory.
	if _, err := runCommand(t, map[string]string{"WEISTACK_DATA_DIR": data}, "restore", offline); err == nil {
		t.Fatal("restored over existing data")
	}
	if _, err := runCommand(t, map[string]string{"WEISTACK_DATA_DIR": t.TempDir() + "/none"}, "backup", filepath.Join(t.TempDir(), "x.tar.gz")); err == nil {
		t.Fatal("backed up a directory without data")
	}
}

func TestDataDirOthersMayWrite(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits")
	}
	data := t.TempDir()
	if err := os.Chmod(data, 0o777); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	vars := persistVars(data)
	vars["WEISTACK_PORT"], vars["WEISTACK_TLS_DIR"] = "0", t.TempDir()
	err := Run(context.Background(), Env{Getenv: func(k string) string { return vars[k] }, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "chmod go-w") {
		t.Fatalf("Run = %v, want a refusal", err)
	}
	vars["WEISTACK_IN_CONTAINER"] = "1"
	startInstance(t, vars) // a warning only
}

// TestBackupOfReleasedData: a v0.1.0 data directory is backed up as it
// is, untouched, and the restored copy opens in this release.
func TestBackupOfReleasedData(t *testing.T) {
	t.Parallel()
	src := filepath.Join("testdata", "upgrade", "v0.1.0", "data")
	before, err := os.ReadFile(filepath.Join(src, databaseFile))
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "v010.tar.gz")
	if _, err := runCommand(t, map[string]string{"WEISTACK_DATA_DIR": src}, "backup", archive); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(src, databaseFile)); !bytes.Equal(before, after) {
		t.Fatal("backing up changed the released data")
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dst := filepath.Join(t.TempDir(), "data")
	m, err := backup.Restore(f, dst, store.FormatVersion)
	if err != nil || m.Format != 1 {
		t.Fatalf("restore: format %d, %v", m.Format, err)
	}
	db, err := store.OpenBolt(filepath.Join(dst, databaseFile))
	if err != nil {
		t.Fatalf("the restored v0.1.0 data does not open: %v", err)
	}
	_ = db.Close()
}
