package kps

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/kms"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	testProject = "0123456789abcdef0123456789abcdef"
	testRegion  = "ap-southeast-1"
	testHost    = "kms." + testRegion + ".myhuaweicloud.com"
	testDelay   = 2 * time.Second
)

var (
	testTenant = Tenant{Region: testRegion, ProjectID: testProject}
	testEpoch  = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
)

// fakeServer holds an in-memory ECS server record for KPS unit tests.
type fakeServer struct {
	Name    string
	KeyName string
}

// fakeServers implements Servers for unit tests.
type fakeServers struct {
	mu      sync.Mutex
	servers map[string]*fakeServer
}

func newFakeServers() *fakeServers {
	return &fakeServers{servers: map[string]*fakeServer{}}
}

func (f *fakeServers) add(id, name, keyName string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.servers[id] = &fakeServer{Name: name, KeyName: keyName}
}

func (f *fakeServers) keyName(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.servers[id]; ok {
		return s.KeyName
	}
	return ""
}

func (f *fakeServers) ServerExists(_ context.Context, _, _, serverID string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[serverID]
	if !ok {
		return "", false, nil
	}
	return s.Name, true, nil
}

func (f *fakeServers) SetKeyName(_ context.Context, _, _, serverID, keyName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[serverID]
	if !ok {
		return apierr.New(http.StatusNotFound, "Ecs.0114", "The ECS %s does not exist.", serverID)
	}
	s.KeyName = keyName
	return nil
}

// env is a KPS service mounted on a real KMS service behind the real server
// router, driven by a fake clock.
type env struct {
	svc     *Service
	kms     *kms.Service
	servers *fakeServers
	store   store.Store
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	dir     *identity.Directory
	vault   *vault.Vault
	logs    *syncBuffer
	handler http.Handler
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvOpts(t, store.NewMemory(), nil)
}

func newEnvFaulty(t *testing.T, faults lifecycle.FaultInjector) *env {
	t.Helper()
	return newEnvOpts(t, store.NewMemory(), faults)
}

func newEnvOpts(t *testing.T, st store.Store, faults lifecycle.FaultInjector) *env {
	t.Helper()
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	clock := lifecycle.NewFakeClock(testEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock, Logger: log, Faults: faults})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(42)
	acct, err := identity.NewAccount()
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	adm, err := identity.NewCredentials()
	if err != nil {
		t.Fatalf("NewCredentials: %v", err)
	}
	dir := identity.NewDirectory(acct, adm)
	vkey, err := vault.NewKey()
	if err != nil {
		t.Fatalf("vault.NewKey: %v", err)
	}
	vlt, err := vault.New(vkey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	kmsSvc, err := kms.New(kms.Deps{
		Store: st, Logger: log, IDs: gen, Vault: vlt, Directory: dir,
		DefaultRegion: testRegion, DefaultProjectID: testProject, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	servers := newFakeServers()
	svc, err := New(Deps{
		Store: st, IDs: gen, Engine: engine, Logger: log, Vault: vlt,
		Keys: kmsSvc, Servers: servers, Directory: dir, Clock: clock.Now,
	})
	if err != nil {
		t.Fatalf("kps.New: %v", err)
	}
	kmsSvc.Extend(svc.KMSExtension())

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Directory: dir, Sealer: vlt,
		Services: []server.Service{kmsSvc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &env{
		svc: svc, kms: kmsSvc, servers: servers, store: st, engine: engine,
		clock: clock, dir: dir, vault: vlt, logs: logs, handler: srv.Handler(),
	}
}

func (e *env) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, strings.ReplaceAll(path, "{project}", testProject), rd)
	r.Host = testHost
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return res.StatusCode, out
}

func (e *env) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "golden", goldenName+".json"), status, out)
	return out
}

func (e *env) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(testDelay + time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for e.engine.Pending() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e.engine.Pending() > 0 {
		t.Fatalf("lifecycle tasks did not settle (%d pending)", e.engine.Pending())
	}
}

func decodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}
