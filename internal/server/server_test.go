package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
)

const testProject = "0123456789abcdef0123456789abcdef"

// fakeService is a stand-in for a real emulated service.
type fakeService struct {
	name     string
	maxBody  *int64
	resets   int
	resetErr error
}

func (f *fakeService) Name() string    { return f.name }
func (f *fakeService) Version() string { return "v1" }

func (f *fakeService) Routes(r chi.Router) {
	// Echoes what the service saw, so tests can assert on routing.
	r.Get("/v1/{project_id}/things", func(w http.ResponseWriter, req *http.Request) {
		info := reqctx.From(req.Context())
		info.SetOperation("ListThings")
		_ = httpx.WriteJSON(w, http.StatusOK, map[string]string{
			"service":    f.name,
			"path":       req.URL.Path,
			"project_id": chi.URLParam(req, "project_id"),
			"region":     info.Region,
			"access_key": auth.FromContext(req.Context()).AccessKey,
		})
	})
	r.Post("/v1/echo", func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = w.Write(body)
	})
	r.Get("/v1/panic", func(http.ResponseWriter, *http.Request) { panic("kaboom") })
	r.Get("/v1/late-panic", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("partial"))
		panic("after write")
	})
	r.Get("/v1/abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
}

type limitedService struct{ *fakeService }

func (l limitedService) MaxBodyBytes() int64 { return *l.maxBody }

type resettableService struct{ *fakeService }

func (r resettableService) Reset(context.Context) error {
	r.resets++
	return r.resetErr
}

type harness struct {
	srv    *Server
	store  *store.Memory
	engine *lifecycle.Engine
	logs   *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newHarness(t *testing.T, mutate func(*config.Config), services ...Service) *harness {
	t.Helper()
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if mutate != nil {
		mutate(&cfg)
	}
	logs := &syncBuffer{}
	h := &harness{
		store:  store.NewMemory(),
		engine: lifecycle.New(lifecycle.Options{Delay: time.Hour}),
		logs:   logs,
	}
	t.Cleanup(func() { _ = h.store.Close() })

	h.srv, err = New(Options{
		Config:    cfg,
		ProjectID: testProject,
		Logger:    slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Store:     h.store,
		Engine:    h.engine,
		IDs:       ids.NewSeeded(1),
		Services:  services,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func (h *harness) do(t *testing.T, method, target string, body io.Reader, mutate func(*http.Request)) *http.Response {
	t.Helper()
	r := httptest.NewRequest(method, target, body)
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, r)
	return w.Result()
}

func readJSON(t *testing.T, res *http.Response, dst any) {
	t.Helper()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		t.Fatalf("decoding %q: %v", body, err)
	}
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(body)
}

func host(h string) func(*http.Request) { return func(r *http.Request) { r.Host = h } }

func TestRouting(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"}, &fakeService{name: "obs"})
	things := "/v1/" + testProject + "/things"

	tests := []struct {
		name        string
		host        string
		path        string
		wantStatus  int
		wantService string
		wantPath    string
		wantRegion  string
	}{
		{"huawei endpoint host", "vpc.af-south-1.myhuaweicloud.com", things, 200, "vpc", things, "af-south-1"},
		{"host with port", "vpc.cn-north-4.myhuaweicloud.com:8780", things, 200, "vpc", things, "cn-north-4"},
		{"host is case-insensitive", "VPC.AP-Southeast-3.MyHuaweiCloud.com", things, 200, "vpc", things, "ap-southeast-3"},
		{"virtual-hosted bucket", "my-bucket.obs.ap-southeast-1.myhuaweicloud.com", things, 200, "obs", things, "ap-southeast-1"},
		{"bucket named like a service", "vpc.obs.ap-southeast-1.myhuaweicloud.com", things, 200, "obs", things, "ap-southeast-1"},
		{"service.localhost uses the default region", "vpc.localhost:8780", things, 200, "vpc", things, "ap-southeast-1"},
		{"path prefix fallback", "localhost:8780", "/vpc" + things, 200, "vpc", things, "ap-southeast-1"},
		{"path prefix on a bare IP", "127.0.0.1:8780", "/obs" + things, 200, "obs", things, "ap-southeast-1"},
		{"host wins over path", "obs.ap-southeast-1.myhuaweicloud.com", things, 200, "obs", things, "ap-southeast-1"},
		{"unknown service host and path", "nope.ap-southeast-1.myhuaweicloud.com", "/nope/v1/x", 404, "", "", ""},
		{"service name alone is not a prefix match", "localhost", "/vpcx/v1/things", 404, "", "", ""},
		{"root", "localhost", "/", 404, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := h.do(t, http.MethodGet, tt.path, nil, host(tt.host))
			if res.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", res.StatusCode, tt.wantStatus, readBody(t, res))
			}
			if tt.wantStatus != http.StatusOK {
				if got, want := readBody(t, res), `{"error_code":"APIGW.0101","error_msg":"The API does not exist or has not been published in the environment"}`; got != want {
					t.Fatalf("body = %s\nwant %s", got, want)
				}
				return
			}
			var got map[string]string
			readJSON(t, res, &got)
			if got["service"] != tt.wantService || got["path"] != tt.wantPath || got["region"] != tt.wantRegion {
				t.Fatalf("handler saw %v; want service %q path %q region %q", got, tt.wantService, tt.wantPath, tt.wantRegion)
			}
			if got["project_id"] != testProject {
				t.Fatalf("project_id = %q", got["project_id"])
			}
		})
	}
}

func TestPathPrefixPreservesEscapedPaths(t *testing.T) {
	t.Parallel()

	var seenPath, seenRaw string
	svc := &routeFunc{name: "obs", routes: func(r chi.Router) {
		r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
			seenPath, seenRaw = req.URL.Path, req.URL.RawPath
			w.WriteHeader(http.StatusNoContent)
		})
	}}
	h := newHarness(t, nil, svc)

	res := h.do(t, http.MethodGet, "/obs/bucket/a%2Fb.txt", nil, host("localhost"))
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if seenPath != "/bucket/a/b.txt" || seenRaw != "/bucket/a%2Fb.txt" {
		t.Fatalf("service saw Path %q RawPath %q", seenPath, seenRaw)
	}
}

type routeFunc struct {
	name   string
	routes func(chi.Router)
}

func (r *routeFunc) Name() string        { return r.name }
func (r *routeFunc) Version() string     { return "v1" }
func (r *routeFunc) Routes(c chi.Router) { r.routes(c) }

func TestUnimplementedOperationNamesTheGap(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"})

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/vpc/v1/not-a-real-operation"},
		{http.MethodDelete, "/vpc/v1/echo"}, // route exists, method does not
	} {
		res := h.do(t, tc.method, tc.path, nil, host("localhost"))
		if res.StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s %s: status = %d, want 501", tc.method, tc.path, res.StatusCode)
		}
		var body struct {
			Code string `json:"error_code"`
			Msg  string `json:"error_msg"`
		}
		readJSON(t, res, &body)
		if body.Code != "WeiStack.0501" {
			t.Errorf("error_code = %q", body.Code)
		}
		for _, sub := range []string{"vpc", tc.method, strings.TrimPrefix(tc.path, "/vpc")} {
			if !strings.Contains(body.Msg, sub) {
				t.Errorf("message %q does not mention %q", body.Msg, sub)
			}
		}
	}
}

func TestRequestIDOnEveryResponse(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"})
	re := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}

	for _, path := range []string{"/_weistack/health", "/vpc/v1/p/things", "/missing", "/vpc/v1/panic"} {
		res := h.do(t, http.MethodGet, path, nil, host("localhost"))
		res.Body.Close()
		id := res.Header.Get("X-Request-Id")
		if !re.MatchString(id) {
			t.Errorf("%s: X-Request-Id = %q, want 32 hex characters", path, id)
		}
		if seen[id] {
			t.Errorf("%s: request ID %q reused", path, id)
		}
		seen[id] = true
	}
}

func TestPanicBecomesInternalError(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"})

	res := h.do(t, http.MethodGet, "/vpc/v1/panic", nil, host("localhost"))
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if got, want := readBody(t, res), `{"error_code":"WeiStack.0500","error_msg":"internal error in weistack"}`; got != want {
		t.Fatalf("body = %s\nwant %s", got, want)
	}
	logs := h.logs.String()
	for _, sub := range []string{"handler panicked", "kaboom", `"status":500`} {
		if !strings.Contains(logs, sub) {
			t.Errorf("logs do not contain %q", sub)
		}
	}

	// After the handler has started writing, the response is left alone.
	res = h.do(t, http.MethodGet, "/vpc/v1/late-panic", nil, host("localhost"))
	if got := readBody(t, res); got != "partial" {
		t.Fatalf("late panic body = %q, want the partial write only", got)
	}
}

func TestAbortHandlerPanicPropagates(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"})
	defer func() {
		if rec := recover(); rec != http.ErrAbortHandler { //nolint:errorlint // identity comparison of the sentinel
			t.Fatalf("recovered %v, want http.ErrAbortHandler to pass through", rec)
		}
	}()
	h.do(t, http.MethodGet, "/vpc/v1/abort", nil, host("localhost"))
}

func TestBodyLimit(t *testing.T) {
	t.Parallel()

	small, unlimited := int64(16), int64(0)
	h := newHarness(t, func(c *config.Config) { c.MaxBodyBytes = 64 },
		&fakeService{name: "vpc"},
		limitedService{&fakeService{name: "ims", maxBody: &small}},
		limitedService{&fakeService{name: "obs", maxBody: &unlimited}},
	)
	payload := strings.Repeat("x", 40)

	tests := []struct {
		service string
		want    int
	}{
		{"vpc", http.StatusOK},                    // 40 <= default 64
		{"ims", http.StatusRequestEntityTooLarge}, // 40 > its own 16
		{"obs", http.StatusOK},                    // unlimited
	}
	for _, tt := range tests {
		res := h.do(t, http.MethodPost, "/"+tt.service+"/v1/echo", strings.NewReader(payload), host("localhost"))
		res.Body.Close()
		if res.StatusCode != tt.want {
			t.Errorf("%s: status = %d, want %d", tt.service, res.StatusCode, tt.want)
		}
	}

	res := h.do(t, http.MethodPost, "/vpc/v1/echo", strings.NewReader(strings.Repeat("x", 65)), host("localhost"))
	res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("default limit: status = %d, want 413", res.StatusCode)
	}
}

func TestCORS(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"})
	origin := func(r *http.Request) { r.Host = "localhost"; r.Header.Set("Origin", "http://localhost:3000") }

	// Preflight is answered without reaching the service.
	res := h.do(t, http.MethodOptions, "/vpc/v1/p/things", nil, func(r *http.Request) {
		origin(r)
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "x-sdk-date, authorization")
	})
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", res.StatusCode)
	}
	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q", got)
	}
	if got := res.Header.Get("Access-Control-Allow-Headers"); got != "x-sdk-date, authorization" {
		t.Errorf("Allow-Headers = %q", got)
	}
	if !strings.Contains(res.Header.Get("Access-Control-Allow-Methods"), "DELETE") {
		t.Errorf("Allow-Methods = %q", res.Header.Get("Access-Control-Allow-Methods"))
	}

	// Actual cross-origin request.
	res = h.do(t, http.MethodGet, "/vpc/v1/p/things", nil, origin)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("cross-origin GET: status %d, Allow-Origin %q", res.StatusCode, res.Header.Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(res.Header.Get("Access-Control-Expose-Headers"), "X-Request-Id") {
		t.Errorf("Expose-Headers = %q", res.Header.Get("Access-Control-Expose-Headers"))
	}

	// A plain OPTIONS (no preflight header) is the service's business.
	res = h.do(t, http.MethodOptions, "/vpc/v1/p/things", nil, origin)
	res.Body.Close()
	if res.StatusCode != http.StatusNotImplemented {
		t.Errorf("plain OPTIONS status = %d, want it routed to the service (501)", res.StatusCode)
	}

	// Same-origin requests get no CORS headers.
	res = h.do(t, http.MethodGet, "/vpc/v1/p/things", nil, host("localhost"))
	res.Body.Close()
	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("non-CORS request got Allow-Origin %q", got)
	}
}

func TestAuthIdentityReachesHandlers(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"})
	res := h.do(t, http.MethodGet, "/vpc/v1/p/things", nil, func(r *http.Request) {
		r.Host = "localhost"
		r.Header.Set("Authorization", "SDK-HMAC-SHA256 Access=AKLEARNER, SignedHeaders=host, Signature=00")
	})
	var got map[string]string
	readJSON(t, res, &got)
	if got["access_key"] != "AKLEARNER" {
		t.Fatalf("handler saw access key %q", got["access_key"])
	}
}

func TestRequestLog(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"})
	res := h.do(t, http.MethodGet, "/v1/"+testProject+"/things", nil, host("vpc.af-south-1.myhuaweicloud.com"))
	res.Body.Close()
	res = h.do(t, http.MethodGet, "/_weistack/health", nil, host("localhost"))
	res.Body.Close()

	var entry, health map[string]any
	for _, line := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %s", line)
		}
		if m["msg"] != "request" {
			continue
		}
		if m["service"] == "vpc" {
			entry = m
		} else {
			health = m
		}
	}
	if entry == nil || health == nil {
		t.Fatalf("request log entries missing:\n%s", h.logs.String())
	}

	want := map[string]any{
		"level": "INFO", "method": "GET", "path": "/v1/" + testProject + "/things",
		"service": "vpc", "operation": "ListThings", "region": "af-south-1",
		"status": float64(200),
	}
	for k, v := range want {
		if entry[k] != v {
			t.Errorf("log %s = %v, want %v", k, entry[k], v)
		}
	}
	for _, k := range []string{"request_id", "latency", "bytes"} {
		if _, ok := entry[k]; !ok {
			t.Errorf("log entry has no %q field", k)
		}
	}
	if health["level"] != "DEBUG" || health["operation"] != "Health" {
		t.Errorf("health probe logged as %v/%v, want DEBUG/Health", health["level"], health["operation"])
	}
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	base := func() Options {
		cfg, _ := config.Load(nil, func(string) string { return "" }, io.Discard)
		return Options{
			Config: cfg,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Store:  store.NewMemory(),
			Engine: lifecycle.New(lifecycle.Options{}),
			IDs:    ids.New(),
		}
	}

	t.Run("missing dependency", func(t *testing.T) {
		t.Parallel()
		o := base()
		o.Store = nil
		if _, err := New(o); err == nil {
			t.Fatal("New succeeded without a store")
		}
	})
	t.Run("duplicate service", func(t *testing.T) {
		t.Parallel()
		o := base()
		o.Services = []Service{&fakeService{name: "vpc"}, &fakeService{name: "vpc"}}
		if _, err := New(o); err == nil || !strings.Contains(err.Error(), "twice") {
			t.Fatalf("err = %v, want duplicate-service error", err)
		}
	})
	t.Run("invalid service name", func(t *testing.T) {
		t.Parallel()
		o := base()
		o.Services = []Service{&fakeService{name: "_weistack"}}
		if _, err := New(o); err == nil || !strings.Contains(err.Error(), "invalid service name") {
			t.Fatalf("err = %v, want invalid-name error", err)
		}
	})
	t.Run("unknown service requested", func(t *testing.T) {
		t.Parallel()
		o := base()
		o.Config.Services = []string{"vpc", "ecz"}
		o.Services = []Service{&fakeService{name: "vpc"}, &fakeService{name: "ecs"}}
		if _, err := New(o); err == nil || !strings.Contains(err.Error(), `"ecz"`) {
			t.Fatalf("err = %v, want unknown-service error naming ecz", err)
		}
	})
	t.Run("subset enables only the listed services", func(t *testing.T) {
		t.Parallel()
		o := base()
		o.Config.Services = []string{"vpc"}
		o.Services = []Service{&fakeService{name: "ecs"}, &fakeService{name: "vpc"}}
		s, err := New(o)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if got := s.ServiceNames(); len(got) != 1 || got[0] != "vpc" {
			t.Fatalf("ServiceNames() = %v, want [vpc]", got)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://localhost/ecs/v1/p/things", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("disabled service answered with %d, want 404", w.Code)
		}
	})
}

var errSeed = errors.New("seed failed")
