package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/tlsca"
	"github.com/victor-akande/weistack/internal/version"
)

type mainResult struct {
	code   int
	stdout string
	stderr string
}

func runMain(t *testing.T, vars map[string]string, args ...string) mainResult {
	t.Helper()
	env := map[string]string{
		"WEISTACK_TLS_DIR":  t.TempDir(),
		"WEISTACK_DATA_DIR": t.TempDir(),
	}
	for k, v := range vars {
		env[k] = v
	}
	var out, errOut bytes.Buffer
	code := Main(context.Background(), Env{
		Args:   args,
		Getenv: func(k string) string { return env[k] },
		Stdout: &out,
		Stderr: &errOut,
	})
	return mainResult{
		code:   code,
		stdout: out.String(),
		stderr: errOut.String(),
	}
}

func decodeOneJSON[T any](t *testing.T, raw string) T {
	t.Helper()
	if !strings.HasSuffix(raw, "\n") {
		t.Fatalf("JSON output does not end with a newline: %q", raw)
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var got T
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decoding %q: %v", raw, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing data after JSON value in %q: %v", raw, err)
	}
	return got
}

func assertFieldOrder(t *testing.T, raw string, keys ...string) {
	t.Helper()
	last := -1
	for _, k := range keys {
		needle := `"` + k + `":`
		idx := strings.Index(raw, needle)
		if idx < 0 {
			t.Fatalf("missing key %q in %s", k, raw)
		}
		if idx <= last {
			t.Fatalf("key %q out of order in %s (want %v)", k, raw, keys)
		}
		last = idx
	}
}

func TestJSONOutputCommands(t *testing.T) {
	t.Parallel()

	data, tls := t.TempDir(), t.TempDir()
	srvVars := persistVars(data)
	srvVars["WEISTACK_TLS_DIR"] = tls
	srvVars["WEISTACK_IAM"] = "enforce"
	inst := startInstance(t, srvVars)
	_, port, _ := net.SplitHostPort(inst.addr)

	cmdVars := map[string]string{
		"WEISTACK_DATA_DIR": data,
		"WEISTACK_TLS_DIR":  tls,
	}

	// version
	res := runMain(t, cmdVars, "version", "-output", "json")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("version -output json: code=%d stderr=%q", res.code, res.stderr)
	}
	ver := decodeOneJSON[struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
		Built   string `json:"built"`
	}](t, res.stdout)
	if ver.Version != version.Version || ver.Commit != version.Commit || ver.Built != version.Date {
		t.Fatalf("version JSON = %+v", ver)
	}
	assertFieldOrder(t, res.stdout, "version", "commit", "built")

	// healthcheck
	res = runMain(t, cmdVars, "healthcheck", "-port", port, "-output", "json")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("healthcheck -output json: code=%d stderr=%q", res.code, res.stderr)
	}
	hc := decodeOneJSON[struct {
		Status        string  `json:"status"`
		Version       string  `json:"version"`
		UptimeSeconds float64 `json:"uptime_seconds"`
	}](t, res.stdout)
	if hc.Status != "ok" || hc.Version != version.Version {
		t.Fatalf("healthcheck JSON = %+v", hc)
	}

	// ca
	res = runMain(t, cmdVars, "ca", "-output", "json")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("ca -output json: code=%d stderr=%q", res.code, res.stderr)
	}
	caOut := decodeOneJSON[struct {
		Path           string `json:"path"`
		CertificatePEM string `json:"certificate_pem"`
	}](t, res.stdout)
	if caOut.Path != filepath.Join(tls, tlsca.CertFile) || !strings.HasPrefix(caOut.CertificatePEM, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("ca JSON = %+v", caOut)
	}
	assertFieldOrder(t, res.stdout, "path", "certificate_pem")

	// credentials
	res = runMain(t, cmdVars, "credentials", "-output", "json")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("credentials -output json: code=%d stderr=%q", res.code, res.stderr)
	}
	credsFile := readAdminFile(t, tls)
	credsOut := decodeOneJSON[struct {
		Source    string `json:"source"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
		Env       struct {
			HuaweiCloudSDKAK string `json:"HUAWEICLOUD_SDK_AK"`
			HuaweiCloudSDKSK string `json:"HUAWEICLOUD_SDK_SK"`
			HWAccessKey      string `json:"HW_ACCESS_KEY"`
			HWSecretKey      string `json:"HW_SECRET_KEY"`
		} `json:"env"`
	}](t, res.stdout)
	if credsOut.Source != filepath.Join(tls, adminCredentialsFile) ||
		credsOut.AccessKey != credsFile.AccessKey ||
		credsOut.SecretKey != credsFile.SecretKey ||
		credsOut.Env.HuaweiCloudSDKAK != credsFile.AccessKey ||
		credsOut.Env.HuaweiCloudSDKSK != credsFile.SecretKey ||
		credsOut.Env.HWAccessKey != credsFile.AccessKey ||
		credsOut.Env.HWSecretKey != credsFile.SecretKey {
		t.Fatalf("credentials JSON = %+v, want keys %+v", credsOut, credsFile)
	}
	assertFieldOrder(t, res.stdout,
		"source", "access_key", "secret_key", "env",
		"HUAWEICLOUD_SDK_AK", "HUAWEICLOUD_SDK_SK", "HW_ACCESS_KEY", "HW_SECRET_KEY",
	)

	// admin (JSON endpoint and raw PEM pass-through)
	res = runMain(t, cmdVars, "admin", "GET", "services", "-port", port, "-output", "json")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("admin GET services -output json: code=%d stderr=%q", res.code, res.stderr)
	}
	var adminServices struct {
		ProjectID string `json:"project_id"`
		AccountID string `json:"account_id"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &adminServices); err != nil || adminServices.ProjectID != backupProject {
		t.Fatalf("admin GET services = %q, %v", res.stdout, err)
	}
	caAdminJSON := runMain(t, cmdVars, "admin", "GET", "ca", "-port", port, "-output", "json")
	caAdminText := runMain(t, cmdVars, "admin", "GET", "ca", "-port", port)
	if caAdminJSON.code != 0 || caAdminJSON.stdout != caAdminText.stdout || !strings.HasPrefix(caAdminJSON.stdout, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("admin GET ca pass-through: code=%d json=%q text=%q", caAdminJSON.code, caAdminJSON.stdout, caAdminText.stdout)
	}

	// backup while server is running ("from": "server")
	onlineArchive := filepath.Join(t.TempDir(), "online.tar.gz")
	res = runMain(t, cmdVars, "backup", onlineArchive, "-port", port, "-output", "json")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("online backup -output json: code=%d stderr=%q", res.code, res.stderr)
	}
	bOnline := decodeOneJSON[struct {
		File    string `json:"file"`
		DataDir string `json:"data_dir"`
		From    string `json:"from"`
	}](t, res.stdout)
	if bOnline.File != onlineArchive || bOnline.DataDir != data || bOnline.From != "server" {
		t.Fatalf("online backup JSON = %+v", bOnline)
	}
	assertFieldOrder(t, res.stdout, "file", "data_dir", "from")

	// backup after server stops ("from": "directory")
	if err := inst.stop(t); err != nil {
		t.Fatal(err)
	}
	offlineArchive := filepath.Join(t.TempDir(), "offline.tar.gz")
	res = runMain(t, cmdVars, "backup", offlineArchive, "-output", "json")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("offline backup -output json: code=%d stderr=%q", res.code, res.stderr)
	}
	bOffline := decodeOneJSON[struct {
		File    string `json:"file"`
		DataDir string `json:"data_dir"`
		From    string `json:"from"`
	}](t, res.stdout)
	if bOffline.File != offlineArchive || bOffline.DataDir != data || bOffline.From != "directory" {
		t.Fatalf("offline backup JSON = %+v", bOffline)
	}

	// restore archive with vault_key: true
	restoreDir := filepath.Join(t.TempDir(), "restored")
	res = runMain(t, map[string]string{"WEISTACK_DATA_DIR": restoreDir, "WEISTACK_TLS_DIR": tls},
		"restore", offlineArchive, "-output", "json")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("restore -output json: code=%d stderr=%q", res.code, res.stderr)
	}
	rWithKey := decodeOneJSON[struct {
		DataDir  string `json:"data_dir"`
		MadeBy   string `json:"made_by"`
		MadeAt   string `json:"made_at"`
		VaultKey bool   `json:"vault_key"`
	}](t, res.stdout)
	if rWithKey.DataDir != restoreDir || rWithKey.MadeBy != version.Version || !rWithKey.VaultKey {
		t.Fatalf("restore JSON = %+v", rWithKey)
	}
	if ts, err := time.Parse(time.RFC3339, rWithKey.MadeAt); err != nil || !strings.HasSuffix(rWithKey.MadeAt, "Z") || ts.IsZero() {
		t.Fatalf("restore made_at = %q, %v", rWithKey.MadeAt, err)
	}
	assertFieldOrder(t, res.stdout, "data_dir", "made_by", "made_at", "vault_key")

	// restore archive with vault_key: false (-vault-key-file kept apart)
	apartData := t.TempDir()
	apartKey := filepath.Join(t.TempDir(), "vault.json")
	apartVars := persistVars(apartData)
	apartVars["WEISTACK_TLS_DIR"] = t.TempDir()
	apartVars["WEISTACK_VAULT_KEY_FILE"] = apartKey
	apartInst := startInstance(t, apartVars)
	if err := apartInst.stop(t); err != nil {
		t.Fatal(err)
	}
	apartArchive := filepath.Join(t.TempDir(), "apart.tar.gz")
	if bRes := runMain(t, map[string]string{"WEISTACK_DATA_DIR": apartData}, "backup", apartArchive, "-output", "json"); bRes.code != 0 {
		t.Fatalf("apart backup: code=%d stderr=%q", bRes.code, bRes.stderr)
	}
	apartRestore := filepath.Join(t.TempDir(), "restored-apart")
	res = runMain(t, map[string]string{"WEISTACK_DATA_DIR": apartRestore}, "restore", apartArchive, "-output", "json")
	if res.code != 0 || res.stderr != "" {
		t.Fatalf("restore without vault key -output json: code=%d stderr=%q", res.code, res.stderr)
	}
	rWithoutKey := decodeOneJSON[struct {
		DataDir  string `json:"data_dir"`
		MadeBy   string `json:"made_by"`
		MadeAt   string `json:"made_at"`
		VaultKey bool   `json:"vault_key"`
	}](t, res.stdout)
	if rWithoutKey.VaultKey {
		t.Fatalf("expected vault_key=false, got %+v", rWithoutKey)
	}
}

func TestTextOutputUnchanged(t *testing.T) {
	t.Parallel()

	data, tls := t.TempDir(), t.TempDir()
	srvVars := persistVars(data)
	srvVars["WEISTACK_TLS_DIR"] = tls
	inst := startInstance(t, srvVars)
	_, port, _ := net.SplitHostPort(inst.addr)

	cmdVars := map[string]string{
		"WEISTACK_DATA_DIR": data,
		"WEISTACK_TLS_DIR":  tls,
	}

	if res := runMain(t, cmdVars, "version"); res.code != 0 || res.stdout != version.String()+"\n" || res.stderr != "" {
		t.Fatalf("version text = %+v", res)
	}
	if res := runMain(t, cmdVars, "healthcheck", "-port", port); res.code != 0 || res.stdout != "ok\n" || res.stderr != "" {
		t.Fatalf("healthcheck text = %+v", res)
	}
	caRes := runMain(t, cmdVars, "ca")
	wantCANote := "WeiStack CA certificate, from " + filepath.Join(tls, tlsca.CertFile) + "\n"
	if caRes.code != 0 || !strings.HasPrefix(caRes.stdout, "-----BEGIN CERTIFICATE-----") || caRes.stderr != wantCANote {
		t.Fatalf("ca text = %+v", caRes)
	}

	creds := readAdminFile(t, tls)
	wantCreds := "export HUAWEICLOUD_SDK_AK=" + creds.AccessKey + " HUAWEICLOUD_SDK_SK=" + creds.SecretKey + "\n" +
		"export HW_ACCESS_KEY=" + creds.AccessKey + " HW_SECRET_KEY=" + creds.SecretKey + "\n"
	wantCredsNote := "WeiStack administrator, from " + filepath.Join(tls, adminCredentialsFile) + "\n"
	if res := runMain(t, cmdVars, "credentials"); res.code != 0 || res.stdout != wantCreds || res.stderr != wantCredsNote {
		t.Fatalf("credentials text = %+v", res)
	}

	adminRes := runMain(t, cmdVars, "admin", "GET", "health", "-port", port)
	if adminRes.code != 0 || !strings.Contains(adminRes.stdout, `"status":"ok"`) || adminRes.stderr != "" {
		t.Fatalf("admin text = %+v", adminRes)
	}

	onlineArchive := filepath.Join(t.TempDir(), "online.tar.gz")
	onlineRes := runMain(t, cmdVars, "backup", onlineArchive, "-port", port)
	if onlineRes.code != 0 || onlineRes.stdout != "" ||
		!strings.Contains(onlineRes.stderr, "is in use") ||
		!strings.Contains(onlineRes.stderr, "backed up "+data+" to "+onlineArchive+"\n") {
		t.Fatalf("online backup text = %+v", onlineRes)
	}

	if err := inst.stop(t); err != nil {
		t.Fatal(err)
	}
	offlineArchive := filepath.Join(t.TempDir(), "offline.tar.gz")
	offlineRes := runMain(t, cmdVars, "backup", offlineArchive)
	if offlineRes.code != 0 || offlineRes.stdout != "" || offlineRes.stderr != "backed up "+data+" to "+offlineArchive+"\n" {
		t.Fatalf("offline backup text = %+v", offlineRes)
	}

	restoreDir := filepath.Join(t.TempDir(), "restored")
	restoreRes := runMain(t, map[string]string{"WEISTACK_DATA_DIR": restoreDir, "WEISTACK_TLS_DIR": tls}, "restore", offlineArchive)
	if restoreRes.code != 0 || restoreRes.stdout != "" || !strings.HasPrefix(restoreRes.stderr, "restored a backup made by WeiStack ") {
		t.Fatalf("restore text = %+v", restoreRes)
	}
}

func TestVersionFlags(t *testing.T) {
	t.Parallel()

	if res := runMain(t, nil, "version", "-h"); res.code != 0 || res.stdout != "" || !strings.Contains(res.stderr, "-output") {
		t.Fatalf("version -h = %+v", res)
	}
	for _, args := range [][]string{
		{"version", "-port", "8780"},
		{"version", "extra"},
		{"version", "-output", "yaml"},
	} {
		if res := runMain(t, nil, args...); res.code != 2 || res.stdout != "" {
			t.Fatalf("%v = %+v, want exit 2", args, res)
		}
	}
	res := runMain(t, nil, "version", "-port", "8780", "-output", "json")
	if res.code != 2 || res.stdout != "" {
		t.Fatalf("version bad flag JSON = %+v", res)
	}
	env := decodeOneJSON[expectedErrorEnvelope](t, res.stderr)
	if env.Error.Kind != "usage" || env.Error.ExitCode != 2 {
		t.Fatalf("version bad flag JSON error = %+v", env)
	}
}

type expectedErrorEnvelope struct {
	Error struct {
		Kind     string          `json:"kind"`
		ExitCode int             `json:"exit_code"`
		Message  string          `json:"message"`
		Status   *int            `json:"status"`
		Response json.RawMessage `json:"response"`
		Hint     string          `json:"hint"`
	} `json:"error"`
}

func TestExitCodesAndJSONErrors(t *testing.T) {
	t.Parallel()

	data, tls := t.TempDir(), t.TempDir()
	srvVars := persistVars(data)
	srvVars["WEISTACK_TLS_DIR"] = tls
	inst := startInstance(t, srvVars)
	_, port, _ := net.SplitHostPort(inst.addr)

	baseVars := map[string]string{
		"WEISTACK_DATA_DIR": data,
		"WEISTACK_TLS_DIR":  tls,
	}

	// Exit 0: -h
	for _, args := range [][]string{
		{"-h"},
		{"healthcheck", "-h"},
		{"admin", "-h"},
		{"version", "-h"},
	} {
		if res := runMain(t, baseVars, args...); res.code != 0 || res.stdout != "" {
			t.Fatalf("%v = %+v, want exit 0", args, res)
		}
	}

	// Exit 1 (internal): server fails to bind an occupied port
	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busyLn.Close() })
	busyPort := strconv.Itoa(busyLn.Addr().(*net.TCPAddr).Port)
	if res := runMain(t, baseVars, "-port", busyPort); res.code != 1 {
		t.Fatalf("occupied port text = %+v, want exit 1", res)
	}
	res := runMain(t, baseVars, "-port", busyPort, "-output", "json")
	if res.code != 1 {
		t.Fatalf("occupied port JSON = %+v, want exit 1", res)
	}
	errEnv := decodeOneJSON[expectedErrorEnvelope](t, res.stderr)
	if errEnv.Error.Kind != "internal" || errEnv.Error.ExitCode != 1 ||
		strings.HasPrefix(errEnv.Error.Message, "weistack: ") ||
		errEnv.Error.Status != nil || errEnv.Error.Response != nil {
		t.Fatalf("internal JSON error = %+v", errEnv)
	}

	// Exit 2 (usage): bad flag, -output yaml, admin with one argument, restore without file, backup - with json
	if res := runMain(t, baseVars, "-output", "yaml"); res.code != 2 || res.stdout != "" || !strings.HasPrefix(res.stderr, "weistack: ") {
		t.Fatalf("-output yaml = %+v, want exit 2 in text fallback", res)
	}
	if res := runMain(t, baseVars, "backup", "-", "-output", "json"); res.code != 2 || res.stdout != "" {
		t.Fatalf("backup - -output json = %+v, want exit 2", res)
	}
	for _, args := range [][]string{
		{"-no-such-flag"},
		{"admin", "GET"},
		{"restore"},
	} {
		if r := runMain(t, baseVars, args...); r.code != 2 || r.stdout != "" {
			t.Fatalf("%v (text) = %+v, want exit 2", args, r)
		}
		jsonArgs := slices.Concat(args, []string{"-output", "json"})
		r := runMain(t, baseVars, jsonArgs...)
		if r.code != 2 || r.stdout != "" {
			t.Fatalf("%v (json) = %+v, want exit 2", jsonArgs, r)
		}
		got := decodeOneJSON[expectedErrorEnvelope](t, r.stderr)
		if got.Error.Kind != "usage" || got.Error.ExitCode != 2 ||
			got.Error.Message == "" || strings.HasPrefix(got.Error.Message, "weistack: ") ||
			got.Error.Status != nil || got.Error.Response != nil {
			t.Fatalf("%v JSON error = %+v", jsonArgs, got)
		}
	}

	// Exit 3 (unreachable): healthcheck against a closed port
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := strconv.Itoa(closedLn.Addr().(*net.TCPAddr).Port)
	_ = closedLn.Close()
	if r := runMain(t, baseVars, "healthcheck", "-port", closedPort); r.code != 3 || r.stdout != "" {
		t.Fatalf("healthcheck closed port (text) = %+v, want exit 3", r)
	}
	r := runMain(t, baseVars, "healthcheck", "-port", closedPort, "-output", "json")
	if r.code != 3 || r.stdout != "" {
		t.Fatalf("healthcheck closed port (json) = %+v, want exit 3", r)
	}
	unreach := decodeOneJSON[expectedErrorEnvelope](t, r.stderr)
	if unreach.Error.Kind != "unreachable" || unreach.Error.ExitCode != 3 ||
		strings.HasPrefix(unreach.Error.Message, "weistack: ") ||
		unreach.Error.Status != nil || unreach.Error.Response != nil {
		t.Fatalf("unreachable JSON error = %+v", unreach)
	}

	// Exit 4 (api): admin GET nothing (checks status, JSON response object, and hint)
	apiText := runMain(t, baseVars, "admin", "GET", "nothing", "-port", port)
	if apiText.code != 4 || apiText.stdout != "" ||
		!strings.HasPrefix(apiText.stderr, "weistack: admin: GET /_weistack/nothing returned 404") ||
		!strings.Contains(apiText.stderr, "\nhint: ") {
		t.Fatalf("admin GET nothing (text) = %+v, want exit 4 with second-line hint", apiText)
	}
	apiJSON := runMain(t, baseVars, "admin", "GET", "nothing", "-port", port, "-output", "json")
	if apiJSON.code != 4 || apiJSON.stdout != "" {
		t.Fatalf("admin GET nothing (json) = %+v, want exit 4", apiJSON)
	}
	apiErr := decodeOneJSON[expectedErrorEnvelope](t, apiJSON.stderr)
	if apiErr.Error.Kind != "api" || apiErr.Error.ExitCode != 4 ||
		strings.HasPrefix(apiErr.Error.Message, "weistack: ") ||
		apiErr.Error.Status == nil || *apiErr.Error.Status != http.StatusNotFound ||
		apiErr.Error.Hint == "" {
		t.Fatalf("admin GET nothing JSON error = %+v", apiErr)
	}
	var respObj struct {
		ErrorCode string `json:"error_code"`
		ErrorMsg  string `json:"error_msg"`
	}
	if err := json.Unmarshal(apiErr.Error.Response, &respObj); err != nil || respObj.ErrorCode == "" {
		t.Fatalf("api response JSON = %s, %v", apiErr.Error.Response, err)
	}

	// Non-JSON API error body becomes a JSON string in response
	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	plainSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("plain failure"))
		}),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = plainSrv.Serve(plainLn) }()
	t.Cleanup(func() { _ = plainSrv.Close() })
	plainPort := strconv.Itoa(plainLn.Addr().(*net.TCPAddr).Port)
	plainRes := runMain(t, baseVars, "healthcheck", "-port", plainPort, "-output", "json")
	if plainRes.code != 4 || plainRes.stdout != "" {
		t.Fatalf("healthcheck non-JSON 503 = %+v", plainRes)
	}
	plainErr := decodeOneJSON[expectedErrorEnvelope](t, plainRes.stderr)
	var respStr string
	if plainErr.Error.Status == nil || *plainErr.Error.Status != http.StatusServiceUnavailable ||
		json.Unmarshal(plainErr.Error.Response, &respStr) != nil || respStr != "plain failure" {
		t.Fatalf("non-JSON response encoded = %s (%+v)", plainErr.Error.Response, plainErr)
	}

	// Exit 5 (data): backup with empty -data-dir, restore into non-empty directory, corrupt data dir on server start
	archive := filepath.Join(t.TempDir(), "valid.tar.gz")
	if b := runMain(t, baseVars, "backup", archive, "-port", port); b.code != 0 {
		t.Fatalf("preparing archive: %+v", b)
	}
	emptyDir := t.TempDir()
	nonEmptyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(nonEmptyDir, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	corruptData := t.TempDir()
	if err := os.WriteFile(filepath.Join(corruptData, projectIDFile), []byte("bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"backup empty data dir", []string{"backup", filepath.Join(t.TempDir(), "out.tar.gz"), "-data-dir", emptyDir}},
		{"restore non-empty data dir", []string{"restore", archive, "-data-dir", nonEmptyDir}},
		{"server corrupt project_id", []string{"-persist", "-data-dir", corruptData, "-port", "0"}},
	} {
		if r := runMain(t, baseVars, tc.args...); r.code != 5 || r.stdout != "" {
			t.Fatalf("%s (text) = %+v, want exit 5", tc.name, r)
		}
		jsonArgs := slices.Concat(tc.args, []string{"-output", "json"})
		r := runMain(t, baseVars, jsonArgs...)
		if r.code != 5 || r.stdout != "" {
			t.Fatalf("%s (json) = %+v, want exit 5", tc.name, r)
		}
		got := decodeOneJSON[expectedErrorEnvelope](t, r.stderr)
		if got.Error.Kind != "data" || got.Error.ExitCode != 5 ||
			strings.HasPrefix(got.Error.Message, "weistack: ") ||
			got.Error.Status != nil || got.Error.Response != nil {
			t.Fatalf("%s JSON error = %+v", tc.name, got)
		}
	}
}

func TestOutputEnvAndFlagPrecedence(t *testing.T) {
	t.Parallel()

	inst := startInstance(t, nil)
	_, port, _ := net.SplitHostPort(inst.addr)

	// WEISTACK_OUTPUT=json works without -output
	for _, args := range [][]string{
		{"version"},
		{"healthcheck", "-port", port},
	} {
		res := runMain(t, map[string]string{"WEISTACK_OUTPUT": "json"}, args...)
		if res.code != 0 || res.stderr != "" || !strings.HasPrefix(res.stdout, "{") {
			t.Fatalf("WEISTACK_OUTPUT=json %v = %+v", args, res)
		}
	}

	// -output text overrides WEISTACK_OUTPUT=json
	if res := runMain(t, map[string]string{"WEISTACK_OUTPUT": "json"}, "version", "-output", "text"); res.code != 0 || res.stdout != version.String()+"\n" {
		t.Fatalf("-output text override on version = %+v", res)
	}
	if res := runMain(t, map[string]string{"WEISTACK_OUTPUT": "json"}, "healthcheck", "-port", port, "-output", "text"); res.code != 0 || res.stdout != "ok\n" {
		t.Fatalf("-output text override on healthcheck = %+v", res)
	}

	// -output json overrides WEISTACK_OUTPUT=text
	res := runMain(t, map[string]string{"WEISTACK_OUTPUT": "text"}, "version", "-output", "json")
	if res.code != 0 || !strings.HasPrefix(res.stdout, "{") {
		t.Fatalf("-output json override on version = %+v", res)
	}
}
