package obs

import (
	"crypto/md5"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

const (
	testRegion  = "ap-southeast-1"
	testHost    = "obs." + testRegion + ".myhuaweicloud.com"
	testProject = "0123456789abcdef0123456789abcdef"
	// Two callers, one per dialect's signature scheme.
	alice = "OBS AKALICE:c2ln"
	bob   = "AWS AKBOB:c2ln"
)

var testEpoch = time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)

// env is an OBS service behind the real server router.
type env struct {
	svc     *Service
	store   store.Store
	dir     string
	handler http.Handler
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, store.NewMemory(), t.TempDir())
}

func newEnvWith(t *testing.T, st store.Store, dir string) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{store: st, dir: dir, now: testEpoch}
	t.Cleanup(func() { _ = st.Close() })

	gen := ids.NewSeeded(17)
	svc, err := New(Deps{Store: st, IDs: gen, Logger: log, DataDir: dir, Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: st,
		Engine: lifecycle.New(lifecycle.Options{Logger: log}), IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	e.svc, e.handler = svc, srv.Handler()
	return e
}

// req describes a request. Host defaults to the service endpoint, so a
// path of "/bucket/key" is path-style; set Host for virtual-hosted style.
type req struct {
	Method  string
	Host    string
	Path    string
	Auth    string
	Body    string
	Headers map[string]string
}

type resp struct {
	Status int
	Header http.Header
	Body   string
}

func (e *env) do(t *testing.T, q req) resp {
	t.Helper()
	var rd io.Reader
	if q.Body != "" {
		rd = strings.NewReader(q.Body)
	}
	if q.Path == "" {
		q.Path = "/"
	}
	r := httptest.NewRequest(q.Method, q.Path, rd)
	r.Host = testHost
	if q.Host != "" {
		r.Host = q.Host
	}
	if q.Auth != "" {
		r.Header.Set("Authorization", q.Auth)
	}
	for k, v := range q.Headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return resp{Status: res.StatusCode, Header: res.Header, Body: string(body)}
}

// as sends a request as the given caller.
func (e *env) as(t *testing.T, auth, method, path string) resp {
	t.Helper()
	return e.do(t, req{Method: method, Path: path, Auth: auth})
}

// wantError asserts an S3-style error response.
func wantError(t *testing.T, got resp, status int, code string) {
	t.Helper()
	if got.Status != status {
		t.Errorf("status = %d, want %d (body %s)", got.Status, status, got.Body)
	}
	if !strings.Contains(got.Body, "<Code>"+code+"</Code>") {
		t.Errorf("body does not carry code %s: %s", code, got.Body)
	}
	if !strings.HasPrefix(got.Body, `<?xml version="1.0" encoding="UTF-8"?>`) || !strings.Contains(got.Body, "<RequestId>") {
		t.Errorf("error is not a well-formed <Error> document: %s", got.Body)
	}
	if ct := got.Header.Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func mustStatus(t *testing.T, got resp, want int) resp {
	t.Helper()
	if got.Status != want {
		t.Fatalf("status = %d, want %d (body %s)", got.Status, want, got.Body)
	}
	return got
}

func newMemory() store.Store { return store.NewMemory() }

func openBolt(path string) (store.Store, error) { return store.OpenBolt(path) }

// discardRecorder is a ResponseWriter that hashes and counts a body
// instead of keeping it, for tests with large objects.
type discardRecorder struct {
	header http.Header
	status int
	n      int
	hash   hash.Hash
}

func newDiscardRecorder() *discardRecorder {
	return &discardRecorder{header: http.Header{}, status: http.StatusOK, hash: md5.New()}
}

func (d *discardRecorder) Header() http.Header { return d.header }
func (d *discardRecorder) WriteHeader(s int)   { d.status = s }
func (d *discardRecorder) Write(p []byte) (int, error) {
	d.n += len(p)
	return d.hash.Write(p)
}
