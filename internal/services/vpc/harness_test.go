package vpc

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	testProject = "0123456789abcdef0123456789abcdef"
	testRegion  = "ap-southeast-1"
	testHost    = "vpc." + testRegion + ".myhuaweicloud.com"
	testDelay   = 2 * time.Second
)

var (
	testTenant = Tenant{Region: testRegion, ProjectID: testProject}
	testEpoch  = time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
)

// env is a VPC service behind the real server router, driven by a fake
// clock so lifecycle transitions are deterministic.
type env struct {
	svc     *Service
	store   store.Store
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	handler http.Handler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWithStore(t, store.NewMemory())
}

func newEnvWithStore(t *testing.T, st store.Store) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(testEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(7)
	svc, err := New(Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &env{svc: svc, store: st, engine: engine, clock: clock, handler: srv.Handler()}
}

// settle lets every pending lifecycle transition complete.
func (e *env) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(testDelay)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

// call sends a request the way a real client would: to the service's
// endpoint host, with the project in the path.
func (e *env) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callAs(t, testProject, method, path, body)
}

func (e *env) callAs(t *testing.T, project, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v1/"+project+path, rd)
	r.Host = testHost
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if res.Header.Get("X-Request-Id") == "" {
		t.Errorf("%s %s: response has no X-Request-Id", method, path)
	}
	return res.StatusCode, out
}

// expect sends a request and compares the response with a golden file.
func (e *env) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "golden", goldenName+".json"), status, out)
	return out
}

func decodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

// mustCreateVPC creates a VPC over HTTP and waits for it to become OK.
func (e *env) mustCreateVPC(t *testing.T, name, cidr string) VPC {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"vpc": map[string]any{"name": name, "cidr": cidr}})
	status, out := e.call(t, http.MethodPost, "/vpcs", string(body))
	if status != http.StatusOK {
		t.Fatalf("creating VPC %q: %d %s", name, status, out)
	}
	e.settle(t)
	return decodeInto[vpcResponse](t, out).VPC
}

func ptr[T any](v T) *T { return &v }

// mustCreateSubnet creates a subnet over HTTP and waits for ACTIVE.
func (e *env) mustCreateSubnet(t *testing.T, vpcID, name, cidr, gateway string) Subnet {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"subnet": map[string]any{
		"name": name, "cidr": cidr, "gateway_ip": gateway, "vpc_id": vpcID,
	}})
	status, out := e.call(t, http.MethodPost, "/subnets", string(body))
	if status != http.StatusOK {
		t.Fatalf("creating subnet %q: %d %s", name, status, out)
	}
	e.settle(t)
	return decodeInto[subnetResponse](t, out).Subnet
}
