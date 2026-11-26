package csms

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

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/iam"
	"github.com/victor-akande/weistack/internal/services/kms"
	"github.com/victor-akande/weistack/internal/services/sts"
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
	testEpoch  = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
)

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

// env is a CSMS service mounted on a real KMS service behind the real server
// router, driven by a fake clock.
type env struct {
	svc     *Service
	kms     *kms.Service
	iam     *iam.Service
	store   store.Store
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	dir     *identity.Directory
	admin   identity.Credentials
	vault   *vault.Vault
	logs    *syncBuffer
	handler http.Handler
}

type envOptions struct {
	store  store.Store
	faults lifecycle.FaultInjector
	quotas quota.Limits
	iam    string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, envOptions{})
}

func newEnvQuotas(t *testing.T, q quota.Limits) *env {
	t.Helper()
	return newEnvWith(t, envOptions{quotas: q})
}

func newEnvFaulty(t *testing.T, f lifecycle.FaultInjector) *env {
	t.Helper()
	return newEnvWith(t, envOptions{faults: f})
}

func newEnvWith(t *testing.T, opts envOptions) *env {
	t.Helper()
	st := opts.store
	if st == nil {
		st = store.NewMemory()
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	clock := lifecycle.NewFakeClock(testEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock, Logger: log, Faults: opts.faults})

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
		Quotas: opts.quotas,
		Store:  st, Logger: log, IDs: gen, Vault: vlt, Directory: dir,
		DefaultRegion: testRegion, DefaultProjectID: testProject, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	svc, err := New(Deps{
		Store: st, IDs: gen, Engine: engine, Logger: log, Vault: vlt,
		Keys: kmsSvc, Quotas: opts.quotas, Directory: dir, Clock: clock.Now,
	})
	if err != nil {
		t.Fatalf("csms.New: %v", err)
	}
	kmsSvc.Extend(svc.KMSExtension())
	if err := svc.Resume(ctx); err != nil {
		t.Fatalf("csms.Resume: %v", err)
	}

	iamSvc, err := iam.New(iam.Deps{
		Quotas: opts.quotas, IDs: gen, Vault: vlt, Store: st, Logger: log,
		Directory: dir, DefaultRegion: testRegion, DefaultProjectID: testProject,
	})
	if err != nil {
		t.Fatalf("iam.New: %v", err)
	}
	if err := iamSvc.Resume(ctx); err != nil {
		t.Fatalf("iam.Resume: %v", err)
	}
	stsSvc, err := sts.New(log, dir, vlt, iamSvc)
	if err != nil {
		t.Fatalf("sts.New: %v", err)
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.Quotas = opts.quotas
	if opts.iam != "" {
		cfg.IAM = opts.iam
	}

	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Directory: dir, Tokens: iamSvc, Permissions: iamSvc, Accounts: iamSvc, Temporary: iamSvc,
		Sealer:   vlt,
		Services: []server.Service{kmsSvc, iamSvc, stsSvc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &env{
		svc: svc, kms: kmsSvc, iam: iamSvc, store: st, engine: engine,
		clock: clock, dir: dir, admin: adm, vault: vlt, logs: logs, handler: srv.Handler(),
	}
}

func (e *env) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callHost(t, testHost, method, path, body, "")
}

func (e *env) callHost(t *testing.T, host, method, path, body, token string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, strings.ReplaceAll(path, "{project}", testProject), rd)
	r.Host = host
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("X-Auth-Token", token)
	}
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

func (e *env) settle(t *testing.T, d time.Duration) {
	t.Helper()
	e.clock.Advance(d)
	deadline := time.Now().Add(2 * time.Second)
	for e.engine.Pending() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
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
