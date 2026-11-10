package ecs

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
	testHost    = "ecs." + testRegion + ".myhuaweicloud.com"
	testDelay   = 2 * time.Second
)

var (
	testTenant = Tenant{Region: testRegion, ProjectID: testProject}
	testEpoch  = time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
)

// env is an ECS service behind the real server router, driven by a fake
// clock.
type env struct {
	svc     *Service
	store   store.Store
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	handler http.Handler
}

func newEnv(t *testing.T) *env { return newEnvWith(t, store.NewMemory(), "") }

func newEnvWith(t *testing.T, st store.Store, seedDir string) *env {
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

	gen := ids.NewSeeded(13)
	svc, err := New(Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now, SeedDir: seedDir})
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

// call sends a request to the ECS endpoint host. path starts at the API
// version, for example "/v1/{project}/cloudservers/flavors"; the literal
// {project} is replaced by the test project.
func (e *env) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, strings.ReplaceAll(path, "{project}", testProject), rd)
	r.Host = testHost
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

// newRecorder serves a prepared request and returns the response body.
func newRecorder(e *env, r *http.Request) string {
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	return w.Body.String()
}
