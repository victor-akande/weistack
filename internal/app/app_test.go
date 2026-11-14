package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
)

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// instance is an emulator running in-process on a free port.
type instance struct {
	addr   string
	stdout *safeBuffer
	cancel context.CancelFunc
	done   chan error
}

func startInstance(t *testing.T, vars map[string]string) *instance {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	inst := &instance{stdout: &safeBuffer{}, cancel: cancel, done: make(chan error, 1)}
	ready := make(chan net.Addr, 1)

	// Each instance gets its own CA directory: tests must never write
	// to the user's real configuration directory.
	env := map[string]string{"WEISTACK_PORT": "0", "WEISTACK_LIFECYCLE_DELAY": "0", "WEISTACK_TLS_DIR": t.TempDir()}
	for k, v := range vars {
		env[k] = v
	}
	go func() {
		inst.done <- Run(ctx, Env{
			Getenv:  func(k string) string { return env[k] },
			Stdout:  inst.stdout,
			Stderr:  io.Discard,
			OnReady: func(a net.Addr) { ready <- a },
		})
	}()

	select {
	case a := <-ready:
		inst.addr = a.String()
	case err := <-inst.done:
		cancel()
		t.Fatalf("emulator exited during startup: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("emulator did not become ready")
	}
	t.Cleanup(func() { _ = inst.stop(t) })
	return inst
}

// stop shuts the instance down and returns Run's error. Safe to repeat.
func (i *instance) stop(t *testing.T) error {
	t.Helper()
	i.cancel()
	select {
	case err := <-i.done:
		i.done <- err
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("emulator did not shut down")
		return nil
	}
}

func (i *instance) get(t *testing.T, path string) (int, string) {
	t.Helper()
	res, err := http.Get("http://" + i.addr + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

func (i *instance) projectID(t *testing.T) string {
	t.Helper()
	_, body := i.get(t, "/_weistack/services")
	var out struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	return out.ProjectID
}

func TestServeAndGracefulShutdown(t *testing.T) {
	t.Parallel()

	inst := startInstance(t, nil)

	status, body := inst.get(t, "/_weistack/health")
	if status != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("health = %d %s", status, body)
	}
	if id := inst.projectID(t); !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("generated project ID %q is not 32 hex characters", id)
	}

	if err := inst.stop(t); err != nil {
		t.Fatalf("Run returned %v on a clean shutdown", err)
	}
	if _, err := net.DialTimeout("tcp", inst.addr, time.Second); err == nil {
		t.Fatal("port is still accepting connections after shutdown")
	}
	logs := inst.stdout.String()
	for _, sub := range []string{`"msg":"weistack started"`, `"msg":"shutting down"`, `"msg":"stopped"`} {
		if !strings.Contains(logs, sub) {
			t.Errorf("log does not contain %s", sub)
		}
	}
}

func TestProjectIDConfiguredWins(t *testing.T) {
	t.Parallel()

	const fixed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inst := startInstance(t, map[string]string{"WEISTACK_PROJECT_ID": fixed})
	if got := inst.projectID(t); got != fixed {
		t.Fatalf("project ID = %q, want the configured %q", got, fixed)
	}
}

func TestPersistenceSurvivesRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	vars := map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": dir}

	first := startInstance(t, vars)
	id := first.projectID(t)

	// A resource created before the restart...
	res, err := http.Post("http://"+first.addr+"/vpc/v1/"+id+"/vpcs", "application/json",
		strings.NewReader(`{"vpc": {"name": "survivor", "cidr": "192.168.0.0/16"}}`))
	if err != nil {
		t.Fatalf("creating VPC: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("creating VPC: status %d", res.StatusCode)
	}

	if err := first.stop(t); err != nil {
		t.Fatalf("first run: %v", err)
	}
	for _, name := range []string{databaseFile, projectIDFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s in the data directory: %v", name, err)
		}
	}

	second := startInstance(t, vars)
	if got := second.projectID(t); got != id {
		t.Fatalf("project ID changed across restart: %q then %q", id, got)
	}

	// ...is still there afterwards, and has finished creating.
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, body := second.get(t, "/vpc/v1/"+id+"/vpcs")
		if status == http.StatusOK && strings.Contains(body, `"name":"survivor"`) && strings.Contains(body, `"status":"OK"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("VPC did not survive the restart in status OK: %d %s", status, body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCorruptProjectIDFileIsReported(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, projectIDFile), []byte("not-an-id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), Env{
		Getenv: func(k string) string {
			return map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": dir, "WEISTACK_PORT": "0"}[k]
		},
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "valid project ID") {
		t.Fatalf("err = %v, want a clear project ID error", err)
	}
}

func TestStartupErrors(t *testing.T) {
	t.Parallel()

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup, not defer: the parallel subtests below run after this
	// function returns and need the port to stay taken.
	t.Cleanup(func() { _ = busy.Close() })
	busyPort := strconv.Itoa(busy.Addr().(*net.TCPAddr).Port)

	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		wantSub string
	}{
		{"invalid flag value", []string{"-port", "99999"}, nil, "out of range"},
		{"port in use", []string{"-port", busyPort}, nil, "listening"},
		{"unknown service", []string{"-port", "0", "-services", "vpc,nope"}, nil, `unknown service "nope"`},
		{"unusable data dir", []string{"-port", "0", "-persist", "-data-dir", notADir}, nil, "store"},
	}
	tlsDir := t.TempDir() // never the user's real CA directory
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := Run(context.Background(), Env{
				Args: tt.args,
				Getenv: func(k string) string {
					if k == "WEISTACK_TLS_DIR" {
						return tlsDir
					}
					return tt.env[k]
				},
				Stdout: io.Discard, Stderr: io.Discard,
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantSub)
			}
		})
	}
}

func TestVersionAndHelp(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	if err := Run(context.Background(), Env{Args: []string{"version"}, Stdout: &out, Stderr: io.Discard}); err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.HasPrefix(out.String(), "weistack dev") {
		t.Fatalf("version output = %q", out.String())
	}

	var usage bytes.Buffer
	env := Env{Args: []string{"-h"}, Getenv: func(string) string { return "" }, Stdout: io.Discard, Stderr: &usage}
	if err := Run(context.Background(), env); err != nil {
		t.Fatalf("-h: %v", err)
	}
	if !strings.Contains(usage.String(), "-lifecycle-delay") {
		t.Fatalf("usage = %q", usage.String())
	}
}

func TestHealthcheckCommand(t *testing.T) {
	t.Parallel()

	inst := startInstance(t, nil)
	_, port, _ := net.SplitHostPort(inst.addr)

	check := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := Run(context.Background(), Env{
			Args:   append([]string{"healthcheck"}, args...),
			Getenv: func(string) string { return "" },
			Stdout: &out, Stderr: io.Discard,
		})
		return out.String(), err
	}

	if out, err := check("-port", port); err != nil || strings.TrimSpace(out) != "ok" {
		t.Fatalf("healthcheck against a live emulator = %q, %v", out, err)
	}
	// The Docker image binds 0.0.0.0; the probe must still reach it.
	if _, err := check("-port", port, "-host", "0.0.0.0"); err != nil {
		t.Fatalf("healthcheck with a wildcard host: %v", err)
	}
	if _, err := check("-h"); err != nil {
		t.Fatalf("healthcheck -h: %v", err)
	}
	if _, err := check("-port", "notaport"); err == nil {
		t.Fatal("healthcheck accepted an invalid flag")
	}

	if err := inst.stop(t); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := check("-port", port); err == nil {
		t.Fatal("healthcheck succeeded against a stopped emulator")
	}
}

func TestHealthcheckRejectsNon200(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	err = Run(context.Background(), Env{
		Args:   []string{"healthcheck", "-port", port},
		Getenv: func(string) string { return "" },
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err = %v, want a 503 failure", err)
	}
}

func TestTextLogFormat(t *testing.T) {
	t.Parallel()

	inst := startInstance(t, map[string]string{"WEISTACK_LOG_FORMAT": "text"})
	if err := inst.stop(t); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if logs := inst.stdout.String(); !strings.Contains(logs, `msg="weistack started"`) {
		t.Fatalf("text logs = %q", logs)
	}
}

// Many systems resolve localhost, and {service}.localhost, to ::1 only.
func TestDefaultHostAlsoListensOnIPv6Loopback(t *testing.T) {
	t.Parallel()

	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this machine: %v", err)
	}
	probe.Close()

	inst := startInstance(t, nil)
	_, port, _ := net.SplitHostPort(inst.addr)

	res, err := http.Get("http://[::1]:" + port + "/_weistack/health")
	if err != nil {
		t.Fatalf("GET over the IPv6 loopback: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}

	if err := inst.stop(t); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if conn, err := net.DialTimeout("tcp6", "[::1]:"+port, time.Second); err == nil {
		conn.Close()
		t.Fatal("the IPv6 listener is still accepting connections after shutdown")
	}
}

// An explicitly chosen bind address is honoured exactly: nothing extra.
func TestExplicitHostDoesNotAddListeners(t *testing.T) {
	t.Parallel()

	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this machine: %v", err)
	}
	probe.Close()

	inst := startInstance(t, map[string]string{"WEISTACK_HOST": "127.0.0.2"})
	_, port, _ := net.SplitHostPort(inst.addr)
	if conn, err := net.DialTimeout("tcp6", "[::1]:"+port, time.Second); err == nil {
		conn.Close()
		t.Fatal("an explicit host also opened the IPv6 loopback")
	}
}

func TestServicePortServesOneService(t *testing.T) {
	t.Parallel()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
	probe.Close()

	inst := startInstance(t, map[string]string{"WEISTACK_SERVICE_PORTS": "obs=" + port})
	base := "http://127.0.0.1:" + port

	// Every path goes to OBS, so a bucket is addressed path-style on the
	// bare address, as S3 clients do with an IP endpoint.
	req, _ := http.NewRequest(http.MethodPut, base+"/port-bucket", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Server") != "OBS" {
		t.Fatalf("PUT bucket on the OBS port: %d %v", res.StatusCode, res.Header)
	}
	res, err = http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), "<Name>port-bucket</Name>") {
		t.Fatalf("bucket listing on the OBS port: %s", body)
	}
	// The same bucket through the main listener's path prefix.
	if status, _ := inst.get(t, "/obs/port-bucket?location"); status != http.StatusOK {
		t.Fatalf("bucket through the main listener: %d", status)
	}
	// The admin API stays reachable on the service port.
	if res, err := http.Get(base + "/_weistack/health"); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("health on the OBS port: %v", err)
	} else {
		res.Body.Close()
	}

	if err := inst.stop(t); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second); err == nil {
		conn.Close()
		t.Fatal("the service port still accepts connections after shutdown")
	}
}

func TestServicePortForAnUnknownService(t *testing.T) {
	t.Parallel()
	tlsDir := t.TempDir()
	err := Run(context.Background(), Env{
		Getenv: func(k string) string {
			return map[string]string{"WEISTACK_PORT": "0", "WEISTACK_SERVICE_PORTS": "dns=9999", "WEISTACK_TLS_DIR": tlsDir}[k]
		},
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), `"dns"`) {
		t.Fatalf("err = %v, want it to name the unknown service", err)
	}
}

func TestCACommand(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "tls")
	env := map[string]string{"WEISTACK_TLS_DIR": dir}
	run := func(args ...string) (string, string, error) {
		var out, errOut bytes.Buffer
		err := Run(context.Background(), Env{
			Args: append([]string{"ca"}, args...), Getenv: func(k string) string { return env[k] },
			Stdout: &out, Stderr: &errOut,
		})
		return out.String(), errOut.String(), err
	}

	first, note, err := run()
	if err != nil || !strings.HasPrefix(first, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("ca = %q, %v", first, err)
	}
	if !strings.Contains(note, filepath.Join(dir, "ca.pem")) {
		t.Fatalf("ca did not say where the certificate lives: %q", note)
	}
	info, err := os.Stat(filepath.Join(dir, "ca-key.pem"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("CA key file: %v, %v", info, err)
	}
	// The CA is stable: clients trust it once.
	if again, _, err := run(); err != nil || again != first {
		t.Fatalf("second ca printed a different certificate (%v)", err)
	}
	if _, _, err := run("-h"); err != nil {
		t.Fatalf("ca -h: %v", err)
	}
	if _, _, err := run("-no-such-flag"); err == nil {
		t.Fatal("ca accepted an invalid flag")
	}
}

func TestBannerAndLogFormat(t *testing.T) {
	t.Parallel()

	// Output that is not a terminal (a buffer, a pipe, a container's log)
	// gets JSON logs under "auto" and no banner.
	var buf bytes.Buffer
	if isTerminal(&buf) {
		t.Fatal("a buffer is a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Fatal("a regular file is a terminal")
	}
	newLogger(config.Config{LogFormat: "auto"}, &buf).Info("hello")
	if !strings.HasPrefix(buf.String(), `{"time":`) {
		t.Fatalf("auto, not at a terminal: %q, want JSON", buf.String())
	}
	buf.Reset()
	newLogger(config.Config{LogFormat: "text"}, &buf).Info("hello")
	if !strings.HasPrefix(buf.String(), "time=") {
		t.Fatalf("text: %q", buf.String())
	}

	buf.Reset()
	printBanner(&buf, config.Config{}, "127.0.0.1:8780", "0123456789abcdef0123456789abcdef", testAccount, testAdmin)
	for _, want := range []string{
		"ready on http://127.0.0.1:8780", "0123456789abcdef0123456789abcdef", "new on every start",
		"export HTTPS_PROXY=http://127.0.0.1:8780", "http://127.0.0.1:8780/_weistack/ca",
		"/vpc/v1/0123456789abcdef0123456789abcdef/vpcs", "docs/getting-started.md",
		"weistack  fedcba9876543210fedcba9876543210", "ADMINKEY000000000000  ADMINSECRET0000000000000000000000000000000  (weistack credentials)",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("banner lacks %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	printBanner(&buf, config.Config{Persist: true, DataDir: "/srv/weistack"}, "127.0.0.1:8780", "0123456789abcdef0123456789abcdef", testAccount, testAdmin)
	if !strings.Contains(buf.String(), "kept in /srv/weistack") {
		t.Errorf("persistent banner:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "any accepted") {
		t.Errorf("accept-mode banner:\n%s", buf.String())
	}
	buf.Reset()
	printBanner(&buf, config.Config{IAM: config.IAMEnforce}, "127.0.0.1:8780", "0123456789abcdef0123456789abcdef", testAccount, testAdmin)
	if !strings.Contains(buf.String(), "enforced: every request needs a valid signature or IAM token") {
		t.Errorf("enforce-mode banner:\n%s", buf.String())
	}
}
