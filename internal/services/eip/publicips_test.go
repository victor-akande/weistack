package eip

import (
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
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	pipTestProject  = "0123456789abcdef0123456789abcdef"
	pipTestProjectB = "fedcba9876543210fedcba9876543210"
	pipTestRegion   = "ap-southeast-1"
	pipTestHost     = "vpc." + pipTestRegion + ".myhuaweicloud.com"
	pipTestDelay    = 2 * time.Second
	pipPortID1      = "11111111-1111-4111-8111-111111111111"
	pipPortID2      = "22222222-2222-4222-8222-222222222222"
	pipSharedBWID   = "33333333-3333-4333-8333-333333333333"
	pipUnknownID    = "00000000-0000-4000-8000-000000000000"
)

var (
	pipTestTenant  = Tenant{Region: pipTestRegion, ProjectID: pipTestProject}
	pipTestTenantB = Tenant{Region: pipTestRegion, ProjectID: pipTestProjectB}
	pipTestEpoch   = time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
)

type pipPortStub struct {
	ports map[string]vpc.Port
}

func (p pipPortStub) Port(_ context.Context, _ vpc.Tenant, id string) (vpc.Port, bool, error) {
	if p.ports == nil {
		return vpc.Port{}, false, nil
	}
	port, ok := p.ports[id]
	return port, ok, nil
}

type pipEnv struct {
	svc     *Service
	store   store.Store
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	handler http.Handler
	ports   *pipPortStub
}

func newPIPEnv(t *testing.T) *pipEnv {
	t.Helper()
	return newPIPEnvWithOptions(t, pipTestDelay, DefaultMaxPerProject)
}

func newPIPEnvWithOptions(t *testing.T, delay time.Duration, maxPerProject int) *pipEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(pipTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: delay, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	ports := &pipPortStub{
		ports: map[string]vpc.Port{
			pipPortID1: {ID: pipPortID1, IP: "192.168.0.10", MAC: "fa:16:3e:00:00:01"},
			pipPortID2: {ID: pipPortID2, IP: "192.168.0.11", MAC: "fa:16:3e:00:00:02"},
		},
	}

	gen := ids.NewSeeded(7)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	svc, err := New(Deps{
		Store:         st,
		Engine:        engine,
		IDs:           gen,
		Logger:        log,
		Ports:         ports,
		MaxPerProject: maxPerProject,
		Now:           clock.Now,
	})
	if err != nil {
		t.Fatalf("eip.New: %v", err)
	}
	vpcSvc.Extend(svc)

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: pipTestProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{vpcSvc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &pipEnv{svc: svc, store: st, engine: engine, clock: clock, handler: srv.Handler(), ports: ports}
}

func (e *pipEnv) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(pipTestDelay)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

func (e *pipEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callAs(t, pipTestProject, method, path, body)
}

func (e *pipEnv) callAs(t *testing.T, project, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v1/"+project+path, rd)
	r.Host = pipTestHost
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

func (e *pipEnv) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "publicips", goldenName+".json"), status, out)
	return out
}

func pipDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func pipPtr[T any](v T) *T { return &v }

func pipPerReq(name string, size int) createPublicIPRequest {
	return createPublicIPRequest{
		PublicIP: &createPublicIPOption{Type: "5_bgp"},
		Bandwidth: &createPublicIPBandwidthOption{
			Name:      pipPtr(name),
			Size:      pipPtr(size),
			ShareType: ShareTypePer,
		},
	}
}

func TestPublicIPLifecycleTransitionZeroDelay(t *testing.T) {
	t.Parallel()
	e := newPIPEnvWithOptions(t, 0, DefaultMaxPerProject)
	ctx := t.Context()

	// Unbound EIP moves from PENDING_CREATE -> DOWN.
	unbound, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("bw-unbound", 5))
	if err != nil {
		t.Fatalf("createPublicIP unbound: %v", err)
	}
	if unbound.Status != StatusPendingCreate {
		t.Fatalf("initial status = %q, want PENDING_CREATE", unbound.Status)
	}

	// Bound EIP moves from PENDING_CREATE -> ACTIVE.
	boundReq := pipPerReq("bw-bound", 5)
	boundReq.PublicIP.PortID = pipPtr(pipPortID1)
	bound, err := e.svc.createPublicIP(ctx, pipTestTenant, boundReq)
	if err != nil {
		t.Fatalf("createPublicIP bound: %v", err)
	}
	if bound.Status != StatusPendingCreate {
		t.Fatalf("initial bound status = %q, want PENDING_CREATE", bound.Status)
	}

	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	gotUnbound, err := e.svc.getPublicIP(ctx, pipTestTenant, unbound.ID)
	if err != nil || gotUnbound.Status != StatusDown {
		t.Fatalf("unbound after transition = %q, %v; want DOWN", gotUnbound.Status, err)
	}
	gotBound, err := e.svc.getPublicIP(ctx, pipTestTenant, bound.ID)
	if err != nil || gotBound.Status != StatusActive || gotBound.PrivateIP != "192.168.0.10" {
		t.Fatalf("bound after transition = %+v, %v; want ACTIVE with 192.168.0.10", gotBound, err)
	}
}

func TestPublicIPPerProjectQuota(t *testing.T) {
	t.Parallel()
	e := newPIPEnvWithOptions(t, 0, 2)
	ctx := t.Context()

	for i := range 2 {
		if _, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("bw", 5)); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if _, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("bw-over", 5)); addrCodeOf(err) != "VPC.0521" {
		t.Fatalf("3rd create in project A err = %v, want VPC.0521", err)
	}

	// Another project has its own quota and gets the next address from the regional pool.
	pipB, err := e.svc.createPublicIP(ctx, pipTestTenantB, pipPerReq("bw-b", 5))
	if err != nil {
		t.Fatalf("create in project B: %v", err)
	}
	if pipB.Address != "192.0.2.3" {
		t.Fatalf("project B address = %q, want 192.0.2.3", pipB.Address)
	}
}

func TestPublicIPUpdatePortIDRules(t *testing.T) {
	t.Parallel()
	e := newPIPEnvWithOptions(t, 0, DefaultMaxPerProject)
	ctx := t.Context()

	created, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("bw-update", 5))
	if err != nil {
		t.Fatalf("createPublicIP: %v", err)
	}
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	steps := []struct {
		name       string
		spec       updatePublicIPSpec
		wantStatus string
		wantPort   string
		wantPrivIP string
		wantAlias  string
	}{
		{
			name:       "set port_id binds and sets ACTIVE",
			spec:       updatePublicIPSpec{PortIDPresent: true, PortID: pipPtr(pipPortID1)},
			wantStatus: StatusActive,
			wantPort:   pipPortID1,
			wantPrivIP: "192.168.0.10",
		},
		{
			name:       "same port_id is a no-op",
			spec:       updatePublicIPSpec{PortIDPresent: true, PortID: pipPtr(pipPortID1)},
			wantStatus: StatusActive,
			wantPort:   pipPortID1,
			wantPrivIP: "192.168.0.10",
		},
		{
			name:       "port_id absent with alias leaves binding alone",
			spec:       updatePublicIPSpec{PortIDPresent: false, Alias: pipPtr("renamed-eip")},
			wantStatus: StatusActive,
			wantPort:   pipPortID1,
			wantPrivIP: "192.168.0.10",
			wantAlias:  "renamed-eip",
		},
		{
			name:       "port_id absent with ip_version 4 leaves binding alone",
			spec:       updatePublicIPSpec{PortIDPresent: false, IPVersion: pipPtr(4)},
			wantStatus: StatusActive,
			wantPort:   pipPortID1,
			wantPrivIP: "192.168.0.10",
			wantAlias:  "renamed-eip",
		},
		{
			name:       "port_id absent with empty object {} unbinds",
			spec:       updatePublicIPSpec{PortIDPresent: false},
			wantStatus: StatusDown,
			wantPort:   "",
			wantPrivIP: "",
			wantAlias:  "renamed-eip",
		},
		{
			name:       "rebind to port 2",
			spec:       updatePublicIPSpec{PortIDPresent: true, PortID: pipPtr(pipPortID2)},
			wantStatus: StatusActive,
			wantPort:   pipPortID2,
			wantPrivIP: "192.168.0.11",
			wantAlias:  "renamed-eip",
		},
		{
			name:       "port_id present as empty string unbinds",
			spec:       updatePublicIPSpec{PortIDPresent: true, PortID: pipPtr("")},
			wantStatus: StatusDown,
			wantPort:   "",
			wantPrivIP: "",
			wantAlias:  "renamed-eip",
		},
		{
			name:       "rebind to port 1",
			spec:       updatePublicIPSpec{PortIDPresent: true, PortID: pipPtr(pipPortID1)},
			wantStatus: StatusActive,
			wantPort:   pipPortID1,
			wantPrivIP: "192.168.0.10",
			wantAlias:  "renamed-eip",
		},
		{
			name:       "port_id present as null unbinds even when alias is also set",
			spec:       updatePublicIPSpec{PortIDPresent: true, PortID: nil, Alias: pipPtr("after-null-unbind")},
			wantStatus: StatusDown,
			wantPort:   "",
			wantPrivIP: "",
			wantAlias:  "after-null-unbind",
		},
	}

	for _, tc := range steps {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.svc.updatePublicIP(ctx, pipTestTenant, created.ID, tc.spec)
			if err != nil {
				t.Fatalf("updatePublicIP: %v", err)
			}
			if got.Status != tc.wantStatus || got.PortID != tc.wantPort || got.PrivateIP != tc.wantPrivIP || got.Alias != tc.wantAlias {
				t.Fatalf("got status=%q port=%q priv=%q alias=%q; want status=%q port=%q priv=%q alias=%q",
					got.Status, got.PortID, got.PrivateIP, got.Alias,
					tc.wantStatus, tc.wantPort, tc.wantPrivIP, tc.wantAlias)
			}
		})
	}
}

func TestPublicIPRegionTypeRules(t *testing.T) {
	t.Parallel()
	e := newPIPEnvWithOptions(t, 0, DefaultMaxPerProject)
	ctx := t.Context()

	tests := []struct {
		region   string
		typ      string
		wantCode string
	}{
		{"ap-southeast-1", "5_bgp", ""},
		{"ap-southeast-1", "5_sbgp", "VPC.0501"},
		{"cn-north-4", "5_bgp", ""},
		{"cn-north-4", "5_sbgp", ""},
		{"cn-southwest-2", "5_sbgp", ""},
		{"cn-southwest-2", "5_bgp", "VPC.0501"},
		{"cn-south-1", "5_sbgp", ""},
		{"cn-east-2", "5_sbgp", ""},
		{"cn-east-3", "5_sbgp", ""},
		{"cn-north-1", "5_sbgp", ""},
		{"ap-southeast-1", "5_telcom", "VPC.0501"},
		{"ap-southeast-1", "", "VPC.0501"},
	}

	for _, tc := range tests {
		req := pipPerReq("bw-region", 5)
		req.PublicIP.Type = tc.typ
		_, err := e.svc.createPublicIP(ctx, Tenant{Region: tc.region, ProjectID: pipTestProject}, req)
		if got := addrCodeOf(err); got != tc.wantCode {
			t.Errorf("region=%s type=%q: code = %q (%v), want %q", tc.region, tc.typ, got, err, tc.wantCode)
		}
	}
}

func TestPublicIPConcurrentCreatesAcrossTwoProjects(t *testing.T) {
	t.Parallel()
	e := newPIPEnvWithOptions(t, 0, DefaultMaxPerProject)
	ctx := t.Context()

	const goroutines = 8
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		addrs = make([]string, 0, goroutines)
	)

	for i := range goroutines {
		wg.Add(1)
		tenant := pipTestTenant
		if i%2 == 1 {
			tenant = pipTestTenantB
		}
		go func(tn Tenant) {
			defer wg.Done()
			pip, err := e.svc.createPublicIP(ctx, tn, pipPerReq("bw-concurrent", 5))
			if err != nil {
				t.Errorf("createPublicIP: %v", err)
				return
			}
			mu.Lock()
			addrs = append(addrs, pip.Address)
			mu.Unlock()
		}(tenant)
	}
	wg.Wait()

	if len(addrs) != goroutines {
		t.Fatalf("created %d EIPs, want %d", len(addrs), goroutines)
	}
	seen := make(map[string]bool, goroutines)
	for _, a := range addrs {
		if seen[a] {
			t.Fatalf("duplicate address allocated across concurrent goroutines: %q (all: %v)", a, addrs)
		}
		seen[a] = true
	}
}

func TestV3ErrorAndModelShapes(t *testing.T) {
	t.Parallel()
	if err := errInvalidV3Input(""); err.Code != "EIP.7901" || err.Message != "Invalid input parameter." {
		t.Fatalf("errInvalidV3Input(\"\") = %+v", err)
	}
	if err := errInvalidV3Input("bad %s", "field"); err.Code != "EIP.7901" || err.Message != "bad field" {
		t.Fatalf("errInvalidV3Input(format) = %+v", err)
	}
	resp := publicIPSingleShowResp{
		ID:        "id-1",
		Vnic:      &vnicInfo{PortID: "port-1"},
		Bandwidth: &publicIPBandwidthInfo{ID: "bw-1", Size: 5},
	}
	if resp.Vnic.PortID != "port-1" || resp.Bandwidth.Size != 5 {
		t.Fatalf("unexpected v3 model values: %+v", resp)
	}
}
