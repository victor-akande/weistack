package elb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/ecs"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/evs"
	"github.com/victor-akande/weistack/internal/services/ims"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	memTestProject = "0123456789abcdef0123456789abcdef"
	memTestRegion  = "ap-southeast-1"
	memTestHost    = "elb." + memTestRegion + ".myhuaweicloud.com"
	memUbuntuImage = "455b5860-f96d-5d89-baaa-ec6adb758c5b"
	memUnknownUUID = "00000000-0000-4000-8000-000000000000"
	memCustomEP    = "11111111-1111-4111-8111-111111111111"
)

var (
	memTestTenant = Tenant{Region: memTestRegion, ProjectID: memTestProject}
	memTestEpoch  = time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
)

type memStubEIPs struct{}

func (memStubEIPs) BindToELB(context.Context, vpc.Tenant, string, string, string, string) (string, error) {
	return "", nil
}

func (memStubEIPs) CreateForELB(context.Context, vpc.Tenant, string, string, string, eip.ServerIP) (string, string, error) {
	return "", "", nil
}

func (memStubEIPs) UnbindFromELB(context.Context, vpc.Tenant, string, string) error {
	return nil
}

func (memStubEIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type memEnv struct {
	svc     *Service
	vpcSvc  *vpc.Service
	ecsSvc  *ecs.Service
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	handler http.Handler

	vpc1     vpc.VPC
	subnet1  vpc.Subnet
	subnet1b vpc.Subnet
	vpc2     vpc.VPC
	subnet2  vpc.Subnet
}

func newMemEnv(t *testing.T) *memEnv {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(memTestEpoch)
	// Zero delay so ECS server lifecycle transitions complete immediately on WaitIdle.
	engine := lifecycle.New(lifecycle.Options{Delay: 0, Clock: clock, Logger: log})
	st := store.NewMemory()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(41)
	vlt, err := vault.New(make([]byte, vault.KeyLen))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	imsSvc, err := ims.New(ims.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now, DefaultProjectID: memTestProject})
	if err != nil {
		t.Fatalf("ims.New: %v", err)
	}
	evsSvc, err := evs.New(evs.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Images: imsSvc, Now: clock.Now})
	if err != nil {
		t.Fatalf("evs.New: %v", err)
	}
	ecsSvc, err := ecs.New(ecs.Deps{
		Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now,
		Network: vpcSvc, Images: imsSvc, Volumes: evsSvc,
	})
	if err != nil {
		t.Fatalf("ecs.New: %v", err)
	}
	evsSvc.SetServers(ecsSvc)
	elbSvc, err := New(Deps{
		Store: st, IDs: gen, Logger: log, Vault: vlt,
		VPC: vpcSvc, EIPs: memStubEIPs{}, Servers: ecsSvc, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("elb.New: %v", err)
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: memTestProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{elbSvc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	e := &memEnv{
		svc:     elbSvc,
		vpcSvc:  vpcSvc,
		ecsSvc:  ecsSvc,
		engine:  engine,
		clock:   clock,
		handler: srv.Handler(),
	}

	tctx := t.Context()
	cidr1 := "192.168.0.0/16"
	v1, err := vpcSvc.CreateVPC(tctx, memTestTenant, vpc.CreateVPCOption{CIDR: &cidr1})
	if err != nil {
		t.Fatalf("CreateVPC 1: %v", err)
	}
	sn1, err := vpcSvc.CreateSubnet(tctx, memTestTenant, vpc.CreateSubnetOption{
		Name: "sub-1a", CIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1", VPCID: v1.ID,
	})
	if err != nil {
		t.Fatalf("CreateSubnet 1a: %v", err)
	}
	sn1b, err := vpcSvc.CreateSubnet(tctx, memTestTenant, vpc.CreateSubnetOption{
		Name: "sub-1b", CIDR: "192.168.2.0/24", GatewayIP: "192.168.2.1", VPCID: v1.ID,
	})
	if err != nil {
		t.Fatalf("CreateSubnet 1b: %v", err)
	}

	cidr2 := "10.0.0.0/16"
	v2, err := vpcSvc.CreateVPC(tctx, memTestTenant, vpc.CreateVPCOption{CIDR: &cidr2})
	if err != nil {
		t.Fatalf("CreateVPC 2: %v", err)
	}
	sn2, err := vpcSvc.CreateSubnet(tctx, memTestTenant, vpc.CreateSubnetOption{
		Name: "sub-2", CIDR: "10.0.1.0/24", GatewayIP: "10.0.1.1", VPCID: v2.ID,
	})
	if err != nil {
		t.Fatalf("CreateSubnet 2: %v", err)
	}
	if err := engine.WaitIdle(tctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	e.vpc1 = v1
	e.subnet1 = sn1
	e.subnet1b = sn1b
	e.vpc2 = v2
	e.subnet2 = sn2
	return e
}

func (e *memEnv) seedLB(t *testing.T, lb loadBalancer) loadBalancer {
	t.Helper()
	if lb.ID == "" {
		lb.ID = e.svc.ids.UUID()
	}
	if lb.VPCID == "" {
		lb.VPCID = e.vpc1.ID
	}
	if lb.EnterpriseProjectID == "" {
		lb.EnterpriseProjectID = defaultEnterpriseProjectID
	}
	lb.CreatedAt = memTestEpoch
	lb.UpdatedAt = memTestEpoch
	if err := e.svc.loadBalancers(memTestTenant).Create(t.Context(), lb.ID, lb); err != nil {
		t.Fatalf("seedLB: %v", err)
	}
	return lb
}

func (e *memEnv) seedPool(t *testing.T, p pool) pool {
	t.Helper()
	if p.ID == "" {
		p.ID = e.svc.ids.UUID()
	}
	if p.Protocol == "" {
		p.Protocol = "HTTP"
	}
	if p.LBAlgorithm == "" {
		p.LBAlgorithm = "ROUND_ROBIN"
	}
	if p.EnterpriseProjectID == "" {
		p.EnterpriseProjectID = defaultEnterpriseProjectID
	}
	p.CreatedAt = memTestEpoch
	p.UpdatedAt = memTestEpoch
	if err := e.svc.pools(memTestTenant).Create(t.Context(), p.ID, p); err != nil {
		t.Fatalf("seedPool: %v", err)
	}
	return p
}

func (e *memEnv) seedHealthMonitor(t *testing.T, hm healthMonitor) healthMonitor {
	t.Helper()
	if hm.ID == "" {
		hm.ID = e.svc.ids.UUID()
	}
	if hm.Type == "" {
		hm.Type = "HTTP"
	}
	hm.CreatedAt = memTestEpoch
	hm.UpdatedAt = memTestEpoch
	if err := e.svc.healthMonitors(memTestTenant).Create(t.Context(), hm.ID, hm); err != nil {
		t.Fatalf("seedHealthMonitor: %v", err)
	}
	if hm.PoolID != "" {
		if _, err := e.svc.pools(memTestTenant).Update(t.Context(), hm.PoolID, func(p *pool) error {
			p.HealthMonitorID = hm.ID
			return nil
		}); err != nil {
			t.Fatalf("bind health monitor to pool: %v", err)
		}
	}
	return hm
}

func (e *memEnv) seedListener(t *testing.T, l listener) listener {
	t.Helper()
	if l.ID == "" {
		l.ID = e.svc.ids.UUID()
	}
	l.CreatedAt = memTestEpoch
	l.UpdatedAt = memTestEpoch
	if err := e.svc.listeners(memTestTenant).Create(t.Context(), l.ID, l); err != nil {
		t.Fatalf("seedListener: %v", err)
	}
	return l
}

func (e *memEnv) seedL7Policy(t *testing.T, pol l7Policy) l7Policy {
	t.Helper()
	if pol.ID == "" {
		pol.ID = e.svc.ids.UUID()
	}
	pol.CreatedAt = memTestEpoch
	pol.UpdatedAt = memTestEpoch
	if err := e.svc.l7Policies(memTestTenant).Create(t.Context(), pol.ID, pol); err != nil {
		t.Fatalf("seedL7Policy: %v", err)
	}
	return pol
}

func (e *memEnv) mustECSServer(t *testing.T, name, vpcID, subnetID, ip string) string {
	t.Helper()
	ctx := t.Context()
	et := ecs.Tenant{Region: memTestRegion, ProjectID: memTestProject}
	_, serverIDs, err := e.ecsSvc.CreateServers(ctx, et, ecs.CreateServerOption{
		Name:       name,
		ImageRef:   memUbuntuImage,
		FlavorRef:  "s6.large.2",
		VPCID:      vpcID,
		NICs:       []ecs.CreateNIC{{SubnetID: subnetID, IPAddress: ip}},
		RootVolume: &ecs.CreateVolume{VolumeType: "GPSSD"},
	})
	if err != nil {
		t.Fatalf("CreateServers: %v", err)
	}
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
	return serverIDs[0]
}

func (e *memEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	fullPath := "/v3/" + memTestProject + "/elb" + path
	r := httptest.NewRequest(method, fullPath, rd)
	r.Host = memTestHost
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

func (e *memEnv) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "members", goldenName+".json"), status, out)
	return out
}

func memDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func memIntPtr(v int) *int       { return &v }
func memBoolPtr(v bool) *bool    { return &v }
func memStrPtr(v string) *string { return &v }

func memAssertErrCode(t *testing.T, err error, wantStatus int, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got nil error, want %d %s", wantStatus, wantCode)
	}
	var apiErr *apierr.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("got non-API error %v, want %d %s", err, wantStatus, wantCode)
	}
	if apiErr.Status != wantStatus || apiErr.Code != wantCode {
		t.Fatalf("got %d %s (%s), want %d %s", apiErr.Status, apiErr.Code, apiErr.Message, wantStatus, wantCode)
	}
}

// TestMemberHealthAllCases verifies every rule of §3.5, including a real
// *ecs.Service with zero lifecycle delay where a server is stopped and started.
func TestMemberHealthAllCases(t *testing.T) {
	t.Parallel()
	e := newMemEnv(t)
	ctx := t.Context()
	et := ecs.Tenant{Region: memTestRegion, ProjectID: memTestProject}

	lb := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID, IPTargetEnable: true})
	p := e.seedPool(t, pool{LoadBalancerID: lb.ID, VPCID: e.vpc1.ID, Protocol: "HTTP", AdminStateUp: true})

	// Create an instance member (in subnet1) and an IP member (in subnet1b, same VPC).
	instView, err := e.svc.createMember(ctx, memTestTenant, p.ID, createMemberInput{
		Name:         "inst-member",
		Address:      "192.168.1.10",
		ProtocolPort: memIntPtr(80),
		SubnetCIDRID: e.subnet1.NeutronSubnetID,
	})
	if err != nil {
		t.Fatalf("create instance member: %v", err)
	}
	ipView, err := e.svc.createMember(ctx, memTestTenant, p.ID, createMemberInput{
		Name:         "ip-member",
		Address:      "192.168.2.20",
		ProtocolPort: memIntPtr(8080),
	})
	if err != nil {
		t.Fatalf("create ip member: %v", err)
	}

	// Rule 2: No health monitor -> NO_MONITOR for both instance and IP members.
	if instView.OperatingStatus != StatusNoMonitor {
		t.Fatalf("instance member without monitor = %s, want %s", instView.OperatingStatus, StatusNoMonitor)
	}
	if ipView.OperatingStatus != StatusNoMonitor {
		t.Fatalf("ip member without monitor = %s, want %s", ipView.OperatingStatus, StatusNoMonitor)
	}

	// Rule 1 (no monitor, member admin_state_up=false) -> OFFLINE takes precedence over NO_MONITOR.
	if _, err := e.svc.updateMember(ctx, memTestTenant, p.ID, instView.Member.ID, updateMemberInput{
		AdminStateUp: memBoolPtr(false),
	}); err != nil {
		t.Fatalf("disable member: %v", err)
	}
	got, err := e.svc.showMember(ctx, memTestTenant, p.ID, instView.Member.ID)
	if err != nil {
		t.Fatalf("show disabled member: %v", err)
	}
	if got.OperatingStatus != StatusOffline {
		t.Fatalf("disabled member without monitor = %s, want %s", got.OperatingStatus, StatusOffline)
	}
	// Re-enable member.
	if _, err := e.svc.updateMember(ctx, memTestTenant, p.ID, instView.Member.ID, updateMemberInput{
		AdminStateUp: memBoolPtr(true),
	}); err != nil {
		t.Fatalf("re-enable member: %v", err)
	}

	// Attach an enabled health monitor -> no ECS servers exist yet -> OFFLINE.
	hm := e.seedHealthMonitor(t, healthMonitor{PoolID: p.ID, Type: "HTTP", AdminStateUp: true})
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, instView.Member.ID); err != nil || v.OperatingStatus != StatusOffline {
		t.Fatalf("instance member with no server = (%s, %v), want %s", v.OperatingStatus, err, StatusOffline)
	}
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, ipView.Member.ID); err != nil || v.OperatingStatus != StatusOffline {
		t.Fatalf("ip member with no server = (%s, %v), want %s", v.OperatingStatus, err, StatusOffline)
	}

	// Boot real ECS servers at both addresses (zero lifecycle delay -> ACTIVE immediately).
	srv1ID := e.mustECSServer(t, "backend-1", e.vpc1.ID, e.subnet1.ID, "192.168.1.10")
	srv2ID := e.mustECSServer(t, "backend-2", e.vpc1.ID, e.subnet1b.ID, "192.168.2.20")

	// Rule 3 & 4: Running ECS servers -> ONLINE.
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, instView.Member.ID); err != nil || v.OperatingStatus != StatusOnline {
		t.Fatalf("instance member with ACTIVE server = (%s, %v), want %s", v.OperatingStatus, err, StatusOnline)
	}
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, ipView.Member.ID); err != nil || v.OperatingStatus != StatusOnline {
		t.Fatalf("ip member with ACTIVE server in LB VPC = (%s, %v), want %s", v.OperatingStatus, err, StatusOnline)
	}

	// IP member matching a server in ANOTHER VPC must remain OFFLINE.
	_ = e.mustECSServer(t, "other-vpc-srv", e.vpc2.ID, e.subnet2.ID, "10.0.1.50")
	otherVPCMember, err := e.svc.createMember(ctx, memTestTenant, p.ID, createMemberInput{
		Name:         "other-vpc-ip",
		Address:      "10.0.1.50",
		ProtocolPort: memIntPtr(80),
	})
	if err != nil {
		t.Fatalf("create other-vpc ip member: %v", err)
	}
	if otherVPCMember.OperatingStatus != StatusOffline {
		t.Fatalf("ip member in another VPC = %s, want %s", otherVPCMember.OperatingStatus, StatusOffline)
	}

	// Stop server 1 -> instance member becomes OFFLINE on next read; IP member stays ONLINE.
	if _, err := e.ecsSvc.StopServers(ctx, et, []string{srv1ID}, "SOFT"); err != nil {
		t.Fatalf("StopServers: %v", err)
	}
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle stop: %v", err)
	}
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, instView.Member.ID); err != nil || v.OperatingStatus != StatusOffline {
		t.Fatalf("instance member with SHUTOFF server = (%s, %v), want %s", v.OperatingStatus, err, StatusOffline)
	}
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, ipView.Member.ID); err != nil || v.OperatingStatus != StatusOnline {
		t.Fatalf("ip member still running = (%s, %v), want %s", v.OperatingStatus, err, StatusOnline)
	}

	// Start server 1 -> instance member becomes ONLINE again.
	if _, err := e.ecsSvc.StartServers(ctx, et, []string{srv1ID}); err != nil {
		t.Fatalf("StartServers: %v", err)
	}
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle start: %v", err)
	}
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, instView.Member.ID); err != nil || v.OperatingStatus != StatusOnline {
		t.Fatalf("instance member after StartServers = (%s, %v), want %s", v.OperatingStatus, err, StatusOnline)
	}

	// Rule 1: Health monitor admin_state_up=false -> OFFLINE.
	if _, err := e.svc.healthMonitors(memTestTenant).Update(ctx, hm.ID, func(rec *healthMonitor) error {
		rec.AdminStateUp = false
		return nil
	}); err != nil {
		t.Fatalf("disable hm: %v", err)
	}
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, instView.Member.ID); err != nil || v.OperatingStatus != StatusOffline {
		t.Fatalf("member with disabled monitor = (%s, %v), want %s", v.OperatingStatus, err, StatusOffline)
	}
	// Re-enable monitor.
	if _, err := e.svc.healthMonitors(memTestTenant).Update(ctx, hm.ID, func(rec *healthMonitor) error {
		rec.AdminStateUp = true
		return nil
	}); err != nil {
		t.Fatalf("enable hm: %v", err)
	}

	// Rule 1: Pool admin_state_up=false -> OFFLINE.
	if _, err := e.svc.pools(memTestTenant).Update(ctx, p.ID, func(rec *pool) error {
		rec.AdminStateUp = false
		return nil
	}); err != nil {
		t.Fatalf("disable pool: %v", err)
	}
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, instView.Member.ID); err != nil || v.OperatingStatus != StatusOffline {
		t.Fatalf("member with disabled pool = (%s, %v), want %s", v.OperatingStatus, err, StatusOffline)
	}
	// Re-enable pool.
	if _, err := e.svc.pools(memTestTenant).Update(ctx, p.ID, func(rec *pool) error {
		rec.AdminStateUp = true
		return nil
	}); err != nil {
		t.Fatalf("enable pool: %v", err)
	}

	// Delete server 2 -> IP member becomes OFFLINE.
	if _, err := e.ecsSvc.DeleteServers(ctx, et, []string{srv2ID}); err != nil {
		t.Fatalf("DeleteServers: %v", err)
	}
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle delete: %v", err)
	}
	if v, err := e.svc.showMember(ctx, memTestTenant, p.ID, ipView.Member.ID); err != nil || v.OperatingStatus != StatusOffline {
		t.Fatalf("ip member after DeleteServers = (%s, %v), want %s", v.OperatingStatus, err, StatusOffline)
	}

	// Also verify direct memberOperatingStatus unit table for BUILD / ERROR / SHUTOFF / ACTIVE.
	tableCases := []struct {
		name     string
		member   member
		pool     pool
		hm       *healthMonitor
		serverSt string
		serverOK bool
		want     string
	}{
		{
			name:   "member admin down",
			member: member{MemberType: memberTypeInstance, AdminStateUp: false, Address: "192.168.1.10", SubnetID: e.subnet1.ID},
			pool:   pool{AdminStateUp: true},
			hm:     &healthMonitor{AdminStateUp: true},
			want:   StatusOffline,
		},
		{
			name:   "pool admin down",
			member: member{MemberType: memberTypeInstance, AdminStateUp: true, Address: "192.168.1.10", SubnetID: e.subnet1.ID},
			pool:   pool{AdminStateUp: false},
			hm:     &healthMonitor{AdminStateUp: true},
			want:   StatusOffline,
		},
		{
			name:   "hm admin down",
			member: member{MemberType: memberTypeInstance, AdminStateUp: true, Address: "192.168.1.10", SubnetID: e.subnet1.ID},
			pool:   pool{AdminStateUp: true},
			hm:     &healthMonitor{AdminStateUp: false},
			want:   StatusOffline,
		},
		{
			name:   "no health monitor",
			member: member{MemberType: memberTypeInstance, AdminStateUp: true, Address: "192.168.1.10", SubnetID: e.subnet1.ID},
			pool:   pool{AdminStateUp: true},
			hm:     nil,
			want:   StatusNoMonitor,
		},
		{
			name:     "server BUILD -> OFFLINE",
			member:   member{MemberType: memberTypeInstance, AdminStateUp: true, Address: "192.168.1.10", SubnetID: e.subnet1.ID},
			pool:     pool{AdminStateUp: true},
			hm:       &healthMonitor{AdminStateUp: true},
			serverSt: ecs.StatusBuild,
			serverOK: true,
			want:     StatusOffline,
		},
		{
			name:     "server ERROR -> OFFLINE",
			member:   member{MemberType: memberTypeInstance, AdminStateUp: true, Address: "192.168.1.10", SubnetID: e.subnet1.ID},
			pool:     pool{AdminStateUp: true},
			hm:       &healthMonitor{AdminStateUp: true},
			serverSt: ecs.StatusError,
			serverOK: true,
			want:     StatusOffline,
		},
		{
			name:     "server SHUTOFF -> OFFLINE",
			member:   member{MemberType: memberTypeIP, AdminStateUp: true, Address: "192.168.1.10"},
			pool:     pool{AdminStateUp: true},
			hm:       &healthMonitor{AdminStateUp: true},
			serverSt: ecs.StatusShutoff,
			serverOK: true,
			want:     StatusOffline,
		},
		{
			name:     "server ACTIVE -> ONLINE",
			member:   member{MemberType: memberTypeIP, AdminStateUp: true, Address: "192.168.1.10"},
			pool:     pool{AdminStateUp: true},
			hm:       &healthMonitor{AdminStateUp: true},
			serverSt: ecs.StatusActive,
			serverOK: true,
			want:     StatusOnline,
		},
	}

	for _, tc := range tableCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeSvc := &Service{servers: memFakeServers{status: tc.serverSt, ok: tc.serverOK}}
			got, err := fakeSvc.memberOperatingStatus(ctx, memTestTenant, tc.member, tc.pool, tc.hm, e.vpc1.ID)
			if err != nil {
				t.Fatalf("memberOperatingStatus: %v", err)
			}
			if got != tc.want {
				t.Fatalf("memberOperatingStatus = %s, want %s", got, tc.want)
			}
		})
	}
}

type memFakeServers struct {
	status string
	ok     bool
	err    error
}

func (f memFakeServers) ServerAt(context.Context, vpc.Tenant, string, string, string) (string, bool, error) {
	return f.status, f.ok, f.err
}

func TestMemberValidationAndRules(t *testing.T) {
	t.Parallel()
	e := newMemEnv(t)
	ctx := t.Context()

	lbNoIP := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID, IPTargetEnable: false})
	lbWithIP := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID, IPTargetEnable: true})

	poolNoIP := e.seedPool(t, pool{LoadBalancerID: lbNoIP.ID, VPCID: e.vpc1.ID, Protocol: "HTTP", AdminStateUp: true})
	poolWithIP := e.seedPool(t, pool{LoadBalancerID: lbWithIP.ID, VPCID: e.vpc1.ID, Protocol: "TCP", AdminStateUp: true})
	poolBadProto := e.seedPool(t, pool{LoadBalancerID: lbWithIP.ID, VPCID: e.vpc1.ID, Protocol: "IP", AdminStateUp: true})
	poolAnyPort := e.seedPool(t, pool{LoadBalancerID: lbWithIP.ID, VPCID: e.vpc1.ID, Protocol: "HTTP", AdminStateUp: true, AnyPortEnable: true})
	poolStandalone := e.seedPool(t, pool{VPCID: e.vpc1.ID, Type: "ip", Protocol: "GRPC", AdminStateUp: true})

	tests := []struct {
		name       string
		poolID     string
		in         createMemberInput
		wantStatus int
		wantCode   string
	}{
		{
			name:       "unknown pool",
			poolID:     memUnknownUUID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID},
			wantStatus: http.StatusNotFound,
			wantCode:   "ELB.8904",
		},
		{
			name:       "empty address",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "invalid IP address",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "not-an-ip", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "IPv6 address rejected with ELB.8902",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "2001:db8::1", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "name too long",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Name: strings.Repeat("a", 256), Address: "192.168.1.10", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "missing protocol_port when any_port_enable is false",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "192.168.1.10", SubnetCIDRID: e.subnet1.NeutronSubnetID},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "protocol_port 0 when any_port_enable is false",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(0), SubnetCIDRID: e.subnet1.NeutronSubnetID},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "protocol_port 65536",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(65536), SubnetCIDRID: e.subnet1.NeutronSubnetID},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "weight negative",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID, Weight: memIntPtr(-1)},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "weight above 100",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID, Weight: memIntPtr(101)},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "unknown subnet_cidr_id",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(80), SubnetCIDRID: memUnknownUUID},
			wantStatus: http.StatusNotFound,
			wantCode:   "ELB.8904",
		},
		{
			name:       "subnet in another VPC",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "10.0.1.10", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet2.NeutronSubnetID},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "address outside subnet CIDR",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "192.168.2.10", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "availability_zone rejected on instance member",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID, AvailabilityZone: memTestRegion + "a"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name:       "IP member on LB with ip_target_enable=false -> ELB.8939",
			poolID:     poolNoIP.ID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(80)},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8939",
		},
		{
			name:       "IP member on pool with unsupported protocol -> ELB.8938",
			poolID:     poolBadProto.ID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(80)},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8938",
		},
		{
			name:       "IP member with unknown availability_zone",
			poolID:     poolWithIP.ID,
			in:         createMemberInput{Address: "192.168.1.10", ProtocolPort: memIntPtr(80), AvailabilityZone: "no-such-az"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.svc.createMember(ctx, memTestTenant, tc.poolID, tc.in)
			memAssertErrCode(t, err, tc.wantStatus, tc.wantCode)
		})
	}

	// any_port_enable allows omitting protocol_port and forbids updating protocol_port.
	anyPortMem, err := e.svc.createMember(ctx, memTestTenant, poolAnyPort.ID, createMemberInput{
		Name:         "any-port",
		Address:      "192.168.1.30",
		SubnetCIDRID: e.subnet1.NeutronSubnetID,
	})
	if err != nil {
		t.Fatalf("create any_port member: %v", err)
	}
	if anyPortMem.Member.ProtocolPort != 0 {
		t.Fatalf("any_port protocol_port = %d, want 0", anyPortMem.Member.ProtocolPort)
	}
	_, err = e.svc.updateMember(ctx, memTestTenant, poolAnyPort.ID, anyPortMem.Member.ID, updateMemberInput{
		ProtocolPort: memIntPtr(8080),
	})
	memAssertErrCode(t, err, http.StatusBadRequest, "ELB.8902")

	// Standalone IP pool (no LB) allows IP member directly.
	standaloneMem, err := e.svc.createMember(ctx, memTestTenant, poolStandalone.ID, createMemberInput{
		Name:             "standalone-ip",
		Address:          "10.10.0.5",
		ProtocolPort:     memIntPtr(50051),
		AvailabilityZone: memTestRegion + "a",
	})
	if err != nil {
		t.Fatalf("create standalone ip member: %v", err)
	}
	if standaloneMem.Member.MemberType != memberTypeIP || standaloneMem.Member.Weight != 1 {
		t.Fatalf("standalone member = %+v, want type=ip weight=1", standaloneMem.Member)
	}

	// Duplicate (address, protocol_port) in same pool -> ELB.8907.
	first, err := e.svc.createMember(ctx, memTestTenant, poolWithIP.ID, createMemberInput{
		Address:      "192.168.1.40",
		ProtocolPort: memIntPtr(80),
	})
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	_, err = e.svc.createMember(ctx, memTestTenant, poolWithIP.ID, createMemberInput{
		Address:      "192.168.1.40",
		ProtocolPort: memIntPtr(80),
	})
	memAssertErrCode(t, err, http.StatusConflict, "ELB.8907")

	// Same address on different port succeeds, and updating its port to collide -> ELB.8907.
	second, err := e.svc.createMember(ctx, memTestTenant, poolWithIP.ID, createMemberInput{
		Address:      "192.168.1.40",
		ProtocolPort: memIntPtr(81),
	})
	if err != nil {
		t.Fatalf("create second: %v", err)
	}
	_, err = e.svc.updateMember(ctx, memTestTenant, poolWithIP.ID, second.Member.ID, updateMemberInput{
		ProtocolPort: memIntPtr(80),
	})
	memAssertErrCode(t, err, http.StatusConflict, "ELB.8907")

	// Show/Update/Delete with member from another pool -> ELB.8904.
	_, err = e.svc.showMember(ctx, memTestTenant, poolNoIP.ID, first.Member.ID)
	memAssertErrCode(t, err, http.StatusNotFound, "ELB.8904")
	_, err = e.svc.updateMember(ctx, memTestTenant, poolNoIP.ID, first.Member.ID, updateMemberInput{Name: memStrPtr("x")})
	memAssertErrCode(t, err, http.StatusNotFound, "ELB.8904")
	err = e.svc.deleteMember(ctx, memTestTenant, poolNoIP.ID, first.Member.ID)
	memAssertErrCode(t, err, http.StatusNotFound, "ELB.8904")
}

func TestMemberListenerStatusesAndListFilters(t *testing.T) {
	t.Parallel()
	e := newMemEnv(t)
	ctx := t.Context()

	lb1 := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID, IPTargetEnable: true, EnterpriseProjectID: memCustomEP})
	lb2 := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID, IPTargetEnable: true})
	p1 := e.seedPool(t, pool{LoadBalancerID: lb1.ID, VPCID: e.vpc1.ID, Protocol: "HTTP", AdminStateUp: true, EnterpriseProjectID: memCustomEP})
	p2 := e.seedPool(t, pool{LoadBalancerID: lb2.ID, VPCID: e.vpc1.ID, Protocol: "HTTP", AdminStateUp: true})
	e.seedHealthMonitor(t, healthMonitor{PoolID: p1.ID, Type: "HTTP", AdminStateUp: true})

	// Two listeners use p1: lsnDefault via DefaultPoolID, lsnL7 via an L7 policy.
	lsnDefault := e.seedListener(t, listener{LoadBalancerID: lb1.ID, Protocol: "HTTP", ProtocolPort: 80, DefaultPoolID: p1.ID, AdminStateUp: true})
	lsnL7 := e.seedListener(t, listener{LoadBalancerID: lb1.ID, Protocol: "HTTP", ProtocolPort: 8080, AdminStateUp: true})
	e.seedL7Policy(t, l7Policy{ListenerID: lsnL7.ID, Action: "REDIRECT_TO_POOL", RedirectPoolID: p1.ID, AdminStateUp: true})
	// Duplicate L7 policy from lsnDefault to p1 should be deduplicated in status.
	e.seedL7Policy(t, l7Policy{ListenerID: lsnDefault.ID, Action: "REDIRECT_TO_POOL", RedirectPoolID: p1.ID, AdminStateUp: true})

	_ = e.mustECSServer(t, "web-1", e.vpc1.ID, e.subnet1.ID, "192.168.1.10")

	m1, err := e.svc.createMember(ctx, memTestTenant, p1.ID, createMemberInput{
		Name: "m-online", Address: "192.168.1.10", ProtocolPort: memIntPtr(80), SubnetCIDRID: e.subnet1.NeutronSubnetID, Weight: memIntPtr(10),
	})
	if err != nil {
		t.Fatalf("create m1: %v", err)
	}
	m2, err := e.svc.createMember(ctx, memTestTenant, p1.ID, createMemberInput{
		Name: "m-offline", Address: "192.168.1.11", ProtocolPort: memIntPtr(81), Weight: memIntPtr(20), AvailabilityZone: memTestRegion + "a",
	})
	if err != nil {
		t.Fatalf("create m2: %v", err)
	}
	m3, err := e.svc.createMember(ctx, memTestTenant, p2.ID, createMemberInput{
		Name: "m-nomon", Address: "192.168.1.12", ProtocolPort: memIntPtr(82), SubnetCIDRID: e.subnet1.NeutronSubnetID, Weight: memIntPtr(30),
	})
	if err != nil {
		t.Fatalf("create m3: %v", err)
	}

	// Verify per-listener status deduplication and values on m1.
	if len(m1.Statuses) != 2 {
		t.Fatalf("m1.Statuses = %+v, want 2 listener entries", m1.Statuses)
	}
	for _, st := range m1.Statuses {
		if st.OperatingStatus != StatusOnline {
			t.Fatalf("listener status = %+v, want ONLINE", st)
		}
		if st.ListenerID != lsnDefault.ID && st.ListenerID != lsnL7.ID {
			t.Fatalf("unexpected listener_id %s", st.ListenerID)
		}
	}

	// ListMembers filters.
	items, _, err := e.svc.listMembers(ctx, memTestTenant, p1.ID, listMembersFilter{
		OperatingStatuses:    []string{StatusOnline},
		MemberTypes:          []string{memberTypeInstance},
		EnterpriseProjectIDs: []string{memCustomEP},
	}, pagination.Marker{Limit: 2000})
	if err != nil || len(items) != 1 || items[0].Member.ID != m1.Member.ID {
		t.Fatalf("listMembers filtered = (%+v, %v), want [%s]", items, err, m1.Member.ID)
	}

	// ListAllMembers with pool_id and loadbalancer_id filters and marker pagination.
	allPage1, pi1, err := e.svc.listAllMembers(ctx, memTestTenant, listAllMembersFilter{}, pagination.Marker{Limit: 2})
	if err != nil {
		t.Fatalf("listAllMembers page 1: %v", err)
	}
	if len(allPage1) != 2 || pi1.CurrentCount != 2 || pi1.NextMarker == nil {
		t.Fatalf("page 1 = len %d, pi=%+v", len(allPage1), pi1)
	}
	allPage2, pi2, err := e.svc.listAllMembers(ctx, memTestTenant, listAllMembersFilter{}, pagination.Marker{ID: *pi1.NextMarker, Limit: 2})
	if err != nil {
		t.Fatalf("listAllMembers page 2: %v", err)
	}
	if len(allPage2) != 1 || pi2.CurrentCount != 1 || pi2.NextMarker != nil {
		t.Fatalf("page 2 = len %d, pi=%+v", len(allPage2), pi2)
	}

	byLB, _, err := e.svc.listAllMembers(ctx, memTestTenant, listAllMembersFilter{
		LoadBalancerIDs: []string{lb2.ID},
		PoolIDs:         []string{p2.ID},
	}, pagination.Marker{Limit: 2000})
	if err != nil || len(byLB) != 1 || byLB[0].Member.ID != m3.Member.ID {
		t.Fatalf("listAllMembers by LB/pool = (%+v, %v), want [%s]", byLB, err, m3.Member.ID)
	}
	_ = m2
}

func TestMemberCreateConcurrency(t *testing.T) {
	t.Parallel()
	e := newMemEnv(t)
	ctx := t.Context()

	lb := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID})
	p := e.seedPool(t, pool{LoadBalancerID: lb.ID, VPCID: e.vpc1.ID, Protocol: "HTTP", AdminStateUp: true})

	const workers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		created  int
		conflict int
	)
	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := e.svc.createMember(ctx, memTestTenant, p.ID, createMemberInput{
				Name:         fmt.Sprintf("m-%d", idx),
				Address:      "192.168.1.55",
				ProtocolPort: memIntPtr(8080),
				SubnetCIDRID: e.subnet1.NeutronSubnetID,
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				created++
				return
			}
			var apiErr *apierr.Error
			if errors.As(err, &apiErr) && apiErr.Code == "ELB.8907" {
				conflict++
				return
			}
			t.Errorf("unexpected error: %v", err)
		}(i)
	}
	wg.Wait()
	if created != 1 || conflict != workers-1 {
		t.Fatalf("created=%d conflict=%d, want 1 and %d", created, conflict, workers-1)
	}
}
