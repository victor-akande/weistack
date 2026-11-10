package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

func TestHealth(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil)
	res := h.do(t, http.MethodGet, "/_weistack/health", nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var body struct {
		Status  string   `json:"status"`
		Version string   `json:"version"`
		Uptime  *float64 `json:"uptime_seconds"`
	}
	readJSON(t, res, &body)
	if body.Status != "ok" || body.Version != "dev" || body.Uptime == nil {
		t.Fatalf("health = %+v", body)
	}
}

func TestServices(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"}, &fakeService{name: "ecs"})
	res := h.do(t, http.MethodGet, "/_weistack/services", nil, nil)
	if got, want := readBody(t, res),
		`{"version":"dev","region":"ap-southeast-1","project_id":"`+testProject+`","persist":false,`+
			`"services":[{"name":"ecs","version":"v1"},{"name":"vpc","version":"v1"}]}`; got != want {
		t.Fatalf("body = %s\nwant %s", got, want)
	}

	// With nothing enabled the list is an empty array, not null.
	empty := newHarness(t, nil)
	res = empty.do(t, http.MethodGet, "/_weistack/services", nil, nil)
	if got := readBody(t, res); !strings.Contains(got, `"services":[]`) {
		t.Fatalf("body = %s, want an empty services array", got)
	}
}

func seed(t *testing.T, s store.Store) {
	t.Helper()
	ctx := context.Background()
	vpcs := store.Scope{Region: "ap-southeast-1", ProjectID: testProject, Kind: "vpc"}
	subnets := store.Scope{Region: "ap-southeast-1", ProjectID: testProject, Kind: "subnet"}
	for _, rec := range []struct {
		scope    store.Scope
		id, data string
	}{
		{vpcs, "vpc-1", `{"name":"prod"}`},
		{vpcs, "vpc-2", `{"name":"dev"}`},
		{subnets, "sub-1", `not json`},
	} {
		if _, err := s.Create(ctx, rec.scope, rec.id, []byte(rec.data)); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}
}

func TestStateAndReset(t *testing.T) {
	t.Parallel()

	svc := resettableService{&fakeService{name: "ims"}}
	h := newHarness(t, nil, svc)
	seed(t, h.store)
	h.engine.Schedule(lifecycle.Task{Key: "vpc-1", Run: func(context.Context, error) {}})

	res := h.do(t, http.MethodGet, "/_weistack/state", nil, nil)
	want := `{"resources":{` +
		`"ap-southeast-1/` + testProject + `/subnet":[{"id":"sub-1","version":1,"data":"not json"}],` +
		`"ap-southeast-1/` + testProject + `/vpc":[{"id":"vpc-1","version":1,"data":{"name":"prod"}},{"id":"vpc-2","version":1,"data":{"name":"dev"}}]}}`
	if got := readBody(t, res); got != want {
		t.Fatalf("state = %s\n want %s", got, want)
	}

	// Reset must be a POST.
	res = h.do(t, http.MethodGet, "/_weistack/reset", nil, nil)
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET reset: status = %d, want 405", res.StatusCode)
	}
	if got := readBody(t, res); !strings.Contains(got, "WeiStack.0405") {
		t.Fatalf("GET reset body = %s", got)
	}

	res = h.do(t, http.MethodPost, "/_weistack/reset", nil, nil)
	if got, want := readBody(t, res), `{"status":"reset","cancelled_tasks":1}`; got != want {
		t.Fatalf("reset = %s, want %s", got, want)
	}
	if svc.resets != 1 {
		t.Fatalf("service Reset called %d times, want 1", svc.resets)
	}
	if h.engine.Pending() != 0 {
		t.Fatalf("%d lifecycle tasks survived the reset", h.engine.Pending())
	}

	res = h.do(t, http.MethodGet, "/_weistack/state", nil, nil)
	if got, want := readBody(t, res), `{"resources":{}}`; got != want {
		t.Fatalf("state after reset = %s, want %s", got, want)
	}
}

func TestResetReportsServiceFailure(t *testing.T) {
	t.Parallel()

	svc := resettableService{&fakeService{name: "ims", resetErr: errSeed}}
	h := newHarness(t, nil, svc)

	res := h.do(t, http.MethodPost, "/_weistack/reset", nil, nil)
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if got := readBody(t, res); strings.Contains(got, errSeed.Error()) {
		t.Fatalf("response leaks the internal cause: %s", got)
	}
	if !strings.Contains(h.logs.String(), errSeed.Error()) {
		t.Fatal("the cause was not logged")
	}
}

func TestAdminFailsCleanlyWhenStoreIsClosed(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(c *config.Config) { c.Metrics = true })
	_ = h.store.Close()

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/_weistack/state"},
		{http.MethodPost, "/_weistack/reset"},
		{http.MethodGet, "/_weistack/metrics"},
	} {
		res := h.do(t, tc.method, tc.path, nil, nil)
		if res.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s %s: status = %d, want 500", tc.method, tc.path, res.StatusCode)
		}
		if got := readBody(t, res); !strings.Contains(got, "WeiStack.0500") {
			t.Errorf("%s %s: body = %s", tc.method, tc.path, got)
		}
	}
}

func TestAdminUnknownPath(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil)
	for _, path := range []string{"/_weistack", "/_weistack/nope"} {
		res := h.do(t, http.MethodGet, path, nil, nil)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, res.StatusCode)
		}
		if got := readBody(t, res); !strings.Contains(got, "APIGW.0101") {
			t.Errorf("%s: body = %s", path, got)
		}
	}
}

func TestMetrics(t *testing.T) {
	t.Parallel()

	// Off by default.
	off := newHarness(t, nil)
	res := off.do(t, http.MethodGet, "/_weistack/metrics", nil, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("metrics disabled: status = %d, want 404", res.StatusCode)
	}

	h := newHarness(t, func(c *config.Config) { c.Metrics = true }, &fakeService{name: "vpc"})
	seed(t, h.store)
	h.engine.Schedule(lifecycle.Task{Run: func(context.Context, error) {}})

	for range 3 {
		res := h.do(t, http.MethodGet, "/vpc/v1/p/things", nil, host("localhost"))
		res.Body.Close()
	}
	res = h.do(t, "BREW", "/vpc/v1/p/things", nil, host("localhost"))
	res.Body.Close()
	res = h.do(t, http.MethodGet, "/nowhere", nil, host("localhost"))
	res.Body.Close()

	res = h.do(t, http.MethodGet, "/_weistack/metrics", nil, nil)
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type = %q", ct)
	}
	out := readBody(t, res)

	for _, line := range []string{
		`weistack_build_info{version="dev"} 1`,
		`weistack_http_requests_total{service="vpc",method="GET",code="200"} 3`,
		`weistack_http_requests_total{service="vpc",method="OTHER",code="501"} 1`,
		`weistack_http_requests_total{service="unrouted",method="GET",code="404"} 1`,
		`weistack_http_request_duration_seconds_bucket{service="vpc",le="+Inf"} 4`,
		`weistack_http_request_duration_seconds_count{service="vpc"} 4`,
		`weistack_resources{kind="subnet"} 1`,
		`weistack_resources{kind="vpc"} 2`,
		`weistack_lifecycle_pending_tasks 1`,
		`# TYPE weistack_http_request_duration_seconds histogram`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("metrics output is missing %q", line)
		}
	}
	if strings.Contains(out, "BREW") {
		t.Error("an arbitrary HTTP method became a label value")
	}
}

func TestHistogramBuckets(t *testing.T) {
	t.Parallel()

	m := newMetrics()
	m.observe("vpc", http.MethodGet, 200, 400_000)       // 0.4ms -> le 0.0005
	m.observe("vpc", http.MethodGet, 200, 3_000_000)     // 3ms   -> le 0.005
	m.observe("vpc", http.MethodGet, 200, 9_000_000_000) // 9s    -> +Inf only

	var out strings.Builder
	m.write(&out, nil, 0)
	for _, line := range []string{
		`weistack_http_request_duration_seconds_bucket{service="vpc",le="0.0005"} 1`,
		`weistack_http_request_duration_seconds_bucket{service="vpc",le="0.0025"} 1`,
		`weistack_http_request_duration_seconds_bucket{service="vpc",le="0.005"} 2`,
		`weistack_http_request_duration_seconds_bucket{service="vpc",le="2.5"} 2`,
		`weistack_http_request_duration_seconds_bucket{service="vpc",le="+Inf"} 3`,
		`weistack_http_request_duration_seconds_sum{service="vpc"} 9.0034`,
	} {
		if !strings.Contains(out.String(), line+"\n") {
			t.Errorf("missing %q in:\n%s", line, out.String())
		}
	}
}
