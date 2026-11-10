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

	env := map[string]string{"WEISTACK_PORT": "0", "WEISTACK_LIFECYCLE_DELAY": "0"}
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := Run(context.Background(), Env{
				Args:   tt.args,
				Getenv: func(k string) string { return tt.env[k] },
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
