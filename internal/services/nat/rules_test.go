package nat

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
	"github.com/victor-akande/weistack/internal/core/faults"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	rulesTestProject = "0123456789abcdef0123456789abcdef"
	rulesTestRegion  = "ap-southeast-1"
	rulesTestHost    = "nat." + rulesTestRegion + ".myhuaweicloud.com"
	rulesTestDelay   = 2 * time.Second

	rulesVPC1ID     = "11111111-1111-4111-8111-111111111111"
	rulesVPC2ID     = "22222222-2222-4222-8222-222222222222"
	rulesSub1ID     = "33333333-3333-4333-8333-333333333333"
	rulesSub2ID     = "44444444-4444-4444-8444-444444444444"
	rulesSubOtherID = "55555555-5555-4555-8555-555555555555"
	rulesGW1ID      = "66666666-6666-4666-8666-666666666666"
	rulesGW2ID      = "77777777-7777-4777-8777-777777777777"
	rulesGWPending  = "88888888-8888-4888-8888-888888888888"
	rulesPort1ID    = "99999999-9999-4999-8999-999999999999"
	rulesPort2ID    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	rulesPortOther  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	rulesUnknownID  = "00000000-0000-4000-8000-000000000000"

	rulesEIP1ID      = "e1111111-1111-4111-8111-111111111111"
	rulesEIP2ID      = "e2222222-2222-4222-8222-222222222222"
	rulesEIP3ID      = "e3333333-3333-4333-8333-333333333333"
	rulesEIPBoundID  = "eb000000-0000-4000-8000-000000000001"
	rulesEIPHeldID   = "ee000000-0000-4000-8000-000000000002"
	rulesEIPPendID   = "ef000000-0000-4000-8000-000000000003"
	rulesOtherGWID   = "f0000000-0000-4000-8000-000000000004"
	rulesBoundPortID = "f1111111-1111-4111-8111-111111111111"
)

var (
	rulesTestTenant = Tenant{Region: rulesTestRegion, ProjectID: rulesTestProject}
	rulesTestEpoch  = time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
)

type fakeNetwork struct {
	mu      sync.Mutex
	vpcs    map[string]vpc.VPC
	subnets map[string]vpc.Subnet
	ports   map[string]vpc.Port
}

func (f *fakeNetwork) GetVPC(_ context.Context, _ vpc.Tenant, id string) (vpc.VPC, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vpcs[id]
	if !ok {
		return vpc.VPC{}, apierr.New(http.StatusNotFound, "VPC.0102", "vpc %s not found", id)
	}
	return v, nil
}

func (f *fakeNetwork) GetSubnet(_ context.Context, _ vpc.Tenant, id string) (vpc.Subnet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sn, ok := f.subnets[id]
	if !ok {
		return vpc.Subnet{}, apierr.New(http.StatusNotFound, "VPC.0202", "subnet %s not found", id)
	}
	return sn, nil
}

func (f *fakeNetwork) ListSubnets(_ context.Context, _ vpc.Tenant, filter vpc.ListSubnetsFilter) ([]vpc.Subnet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []vpc.Subnet
	for _, sn := range f.subnets {
		if filter.VPCID == "" || sn.VPCID == filter.VPCID {
			out = append(out, sn)
		}
	}
	return out, nil
}

func (f *fakeNetwork) Port(_ context.Context, _ vpc.Tenant, id string) (vpc.Port, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.ports[id]
	return p, ok, nil
}

func (f *fakeNetwork) AllocateIP(_ context.Context, _ vpc.Tenant, _, _, want string) (string, error) {
	if want != "" {
		return want, nil
	}
	return "10.0.1.10", nil
}

func (f *fakeNetwork) ReleaseIP(_ context.Context, _ vpc.Tenant, _, _ string) error {
	return nil
}

type fakeEIPRecord struct {
	ID           string
	Address      string
	Pending      bool
	PortID       string
	NATGatewayID string
}

type fakePublicIPs struct {
	mu   sync.Mutex
	eips map[string]*fakeEIPRecord
}

func newFakePublicIPs() *fakePublicIPs {
	return &fakePublicIPs{
		eips: map[string]*fakeEIPRecord{
			rulesEIP1ID:     {ID: rulesEIP1ID, Address: "198.51.100.1"},
			rulesEIP2ID:     {ID: rulesEIP2ID, Address: "198.51.100.2"},
			rulesEIP3ID:     {ID: rulesEIP3ID, Address: "198.51.100.3"},
			rulesEIPBoundID: {ID: rulesEIPBoundID, Address: "198.51.100.10", PortID: rulesBoundPortID},
			rulesEIPHeldID:  {ID: rulesEIPHeldID, Address: "198.51.100.11", NATGatewayID: rulesOtherGWID},
			rulesEIPPendID:  {ID: rulesEIPPendID, Address: "198.51.100.12", Pending: true},
		},
	}
}

func (f *fakePublicIPs) add(id, addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.eips[id] = &fakeEIPRecord{ID: id, Address: addr}
}

func (f *fakePublicIPs) holderOf(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rec, ok := f.eips[id]; ok {
		return rec.NATGatewayID
	}
	return ""
}

func (f *fakePublicIPs) HoldForNAT(_ context.Context, _ vpc.Tenant, eipID, gatewayID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.eips[eipID]
	if !ok {
		return "", eip.ErrNATNotFound
	}
	if rec.Pending {
		return "", eip.ErrNATNotReady
	}
	if rec.PortID != "" {
		return "", fmt.Errorf("%w: %s", eip.ErrNATBound, rec.PortID)
	}
	if rec.NATGatewayID != "" && rec.NATGatewayID != gatewayID {
		return "", fmt.Errorf("%w: %s", eip.ErrNATHeld, rec.NATGatewayID)
	}
	rec.NATGatewayID = gatewayID
	return rec.Address, nil
}

func (f *fakePublicIPs) ReleaseFromNAT(_ context.Context, _ vpc.Tenant, eipID, gatewayID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.eips[eipID]
	if !ok || rec.NATGatewayID != gatewayID {
		return nil
	}
	rec.NATGatewayID = ""
	return nil
}

func (f *fakePublicIPs) PublicIPByAddress(_ context.Context, _ vpc.Tenant, address string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rec := range f.eips {
		if rec.Address == address {
			return rec.ID, true, nil
		}
	}
	return "", false, nil
}

func (f *fakePublicIPs) PublicIPAddress(_ context.Context, _ vpc.Tenant, eipID string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.eips[eipID]
	if !ok {
		return "", false, nil
	}
	return rec.Address, true, nil
}

type rulesEnv struct {
	svc     *Service
	store   store.Store
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	faults  *faults.Registry
	handler http.Handler
	net     *fakeNetwork
	eips    *fakePublicIPs
}

func newRulesEnv(t *testing.T) *rulesEnv {
	t.Helper()
	return newRulesEnvWithDelay(t, rulesTestDelay)
}

func newRulesEnvWithDelay(t *testing.T, delay time.Duration) *rulesEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(rulesTestEpoch)
	flt := faults.New(clock.Now)
	engine := lifecycle.New(lifecycle.Options{Delay: delay, Clock: clock, Logger: log, Faults: flt})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	netStub := &fakeNetwork{
		vpcs: map[string]vpc.VPC{
			rulesVPC1ID: {ID: rulesVPC1ID, Name: "vpc-1", CIDR: "10.0.0.0/16"},
			rulesVPC2ID: {ID: rulesVPC2ID, Name: "vpc-2", CIDR: "10.1.0.0/16"},
		},
		subnets: map[string]vpc.Subnet{
			rulesSub1ID:     {ID: rulesSub1ID, VPCID: rulesVPC1ID, CIDR: "10.0.1.0/24"},
			rulesSub2ID:     {ID: rulesSub2ID, VPCID: rulesVPC1ID, CIDR: "10.0.2.0/24"},
			rulesSubOtherID: {ID: rulesSubOtherID, VPCID: rulesVPC2ID, CIDR: "10.1.1.0/24"},
		},
		ports: map[string]vpc.Port{
			rulesPort1ID:   {ID: rulesPort1ID, SubnetID: rulesSub1ID, IP: "10.0.1.10"},
			rulesPort2ID:   {ID: rulesPort2ID, SubnetID: rulesSub2ID, IP: "10.0.2.10"},
			rulesPortOther: {ID: rulesPortOther, SubnetID: rulesSubOtherID, IP: "10.1.1.10"},
		},
	}
	eipsStub := newFakePublicIPs()

	gen := ids.NewSeeded(11)
	svc, err := New(Deps{
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		VPC:    netStub,
		EIPs:   eipsStub,
		Now:    clock.Now,
	})
	if err != nil {
		t.Fatalf("nat.New: %v", err)
	}

	// Seed two ACTIVE gateways (in VPC 1 and VPC 2) and one PENDING_CREATE gateway.
	for _, g := range []gateway{
		{
			ID: rulesGW1ID, Name: "gw-1", Spec: "1", Status: StatusActive,
			RouterID: rulesVPC1ID, InternalNetworkID: rulesSub1ID, NgportIP: "10.0.1.5",
			EnterpriseProjectID: defaultEnterpriseProjectID, Session: defaultSessionConf, CreatedAt: rulesTestEpoch,
		},
		{
			ID: rulesGW2ID, Name: "gw-2", Spec: "1", Status: StatusActive,
			RouterID: rulesVPC2ID, InternalNetworkID: rulesSubOtherID, NgportIP: "10.1.1.5",
			EnterpriseProjectID: defaultEnterpriseProjectID, Session: defaultSessionConf, CreatedAt: rulesTestEpoch,
		},
		{
			ID: rulesGWPending, Name: "gw-pending", Spec: "1", Status: StatusPendingCreate,
			RouterID: rulesVPC1ID, InternalNetworkID: rulesSub1ID, NgportIP: "10.0.1.6",
			EnterpriseProjectID: defaultEnterpriseProjectID, Session: defaultSessionConf, CreatedAt: rulesTestEpoch,
		},
	} {
		if err := svc.gateways(rulesTestTenant).Create(t.Context(), g.ID, g); err != nil {
			t.Fatalf("seed gateway %s: %v", g.ID, err)
		}
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: rulesTestProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &rulesEnv{
		svc: svc, store: st, engine: engine, clock: clock, faults: flt,
		handler: srv.Handler(), net: netStub, eips: eipsStub,
	}
}

func (e *rulesEnv) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(rulesTestDelay)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

func (e *rulesEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v2/"+rulesTestProject+path, rd)
	r.Host = rulesTestHost
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

func (e *rulesEnv) expect(t *testing.T, dir, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", dir, goldenName+".json"), status, out)
	return out
}

func rulesDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func rulePtr[T any](v T) *T { return &v }

func rulesErrCode(err error) string {
	var ae *apierr.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// --- SNAT unit tests ---

func TestSnatCreateValidationAndOverlaps(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("validation and EIP errors", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)

		// Seed one subnet rule on sub1 and one CIDR rule on sub2's lower half, plus an `any` DNAT on EIP3.
		if _, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
			NatGatewayID: rulesGW1ID,
			NetworkID:    rulePtr(rulesSub1ID),
			FloatingIPID: rulesEIP1ID,
		}); err != nil {
			t.Fatalf("seed subnet snat: %v", err)
		}
		if _, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
			NatGatewayID: rulesGW1ID,
			CIDR:         rulePtr("10.0.2.0/25"),
			FloatingIPID: rulesEIP1ID,
		}); err != nil {
			t.Fatalf("seed cidr snat: %v", err)
		}
		if _, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
			NatGatewayID: rulesGW1ID,
			CIDR:         rulePtr("172.16.0.0/24"),
			SourceType:   rulePtr(1),
			FloatingIPID: rulesEIP1ID,
		}); err != nil {
			t.Fatalf("seed dc snat: %v", err)
		}
		if _, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID:        rulesGW1ID,
			PortID:              rulePtr(rulesPort1ID),
			Protocol:            "any",
			InternalServicePort: rulePtr(0),
			ExternalServicePort: rulePtr(0),
			FloatingIPID:        rulesEIP3ID,
		}); err != nil {
			t.Fatalf("seed any dnat: %v", err)
		}

		// Build 21 valid UUIDs for NAT.0211.
		twentyOne := make([]string, 21)
		for i := range twentyOne {
			twentyOne[i] = fmt.Sprintf("10000000-0000-4000-8000-%012d", i+1)
		}

		tests := []struct {
			name     string
			opt      createSnatRuleOption
			wantCode string
		}{
			{
				name:     "global_eip_id not implemented",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID, GlobalEIPID: rulePtr("g1")},
				wantCode: apierr.CodeNotImplemented,
			},
			{
				name:     "missing nat_gateway_id",
				opt:      createSnatRuleOption{CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0002",
			},
			{
				name:     "invalid description angle brackets",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID, Description: rulePtr("<bad>")},
				wantCode: "NAT.0014",
			},
			{
				name:     "invalid description too long",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID, Description: rulePtr(strings.Repeat("a", 256))},
				wantCode: "NAT.0014",
			},
			{
				name:     "invalid source_type",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(2), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0002",
			},
			{
				name:     "neither network_id nor cidr",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0202",
			},
			{
				name:     "both network_id and cidr",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSub2ID), CIDR: rulePtr("10.0.2.128/25"), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0202",
			},
			{
				name:     "source_type 1 with network_id",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSub2ID), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0204",
			},
			{
				name:     "non-canonical cidr",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("10.0.2.1/25"), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0203",
			},
			{
				name:     "ipv6 cidr",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("2001:db8::/64"), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0203",
			},
			{
				name:     "malformed cidr",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("not-a-cidr"), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0203",
			},
			{
				name:     "empty floating_ip_id",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1)},
				wantCode: "NAT.0002",
			},
			{
				name:     "more than 20 floating_ip_ids",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: strings.Join(twentyOne, ",")},
				wantCode: "NAT.0211",
			},
			{
				name:     "invalid floating_ip_id UUID",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: "not-a-uuid"},
				wantCode: "NAT.0210",
			},
			{
				name:     "duplicate floating_ip_id",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID + "," + rulesEIP2ID},
				wantCode: "NAT.0403",
			},
			{
				name:     "unknown gateway",
				opt:      createSnatRuleOption{NatGatewayID: rulesUnknownID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0105",
			},
			{
				name:     "gateway not ACTIVE",
				opt:      createSnatRuleOption{NatGatewayID: rulesGWPending, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0103",
			},
			{
				name:     "unknown network_id",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesUnknownID), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0019",
			},
			{
				name:     "network_id in other VPC",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSubOtherID), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0008",
			},
			{
				name:     "duplicate network_id on gateway",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSub1ID), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0208",
			},
			{
				name:     "source_type 0 cidr outside VPC subnets",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("192.168.1.0/24"), SourceType: rulePtr(0), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0205",
			},
			{
				name:     "cidr overlaps existing network_id subnet",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("10.0.1.0/25"), SourceType: rulePtr(0), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0207",
			},
			{
				name:     "network_id overlaps existing cidr rule",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSub2ID), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0207",
			},
			{
				name:     "cidr overlaps existing cidr rule",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("10.0.2.0/26"), SourceType: rulePtr(0), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0207",
			},
			{
				name:     "dc cidr overlaps existing dc cidr",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.0.128/25"), SourceType: rulePtr(1), FloatingIPID: rulesEIP2ID},
				wantCode: "NAT.0207",
			},
			{
				name:     "EIP used by DNAT any rule on same gateway",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIP3ID},
				wantCode: "NAT.0409",
			},
			{
				name:     "EIP not found",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesUnknownID},
				wantCode: "NAT.0026",
			},
			{
				name:     "EIP bound to port",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIPBoundID},
				wantCode: "NAT.0402",
			},
			{
				name:     "EIP held by other gateway",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIPHeldID},
				wantCode: "NAT.0404",
			},
			{
				name:     "EIP pending / not ready",
				opt:      createSnatRuleOption{NatGatewayID: rulesGW1ID, CIDR: rulePtr("172.16.1.0/24"), SourceType: rulePtr(1), FloatingIPID: rulesEIPPendID},
				wantCode: "NAT.0405",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, tc.opt)
				if got := rulesErrCode(err); got != tc.wantCode {
					t.Fatalf("createSnatRule(%s) err = %v (code %q), want %q", tc.name, err, got, tc.wantCode)
				}
			})
		}

		// Adjacent non-overlapping CIDR inside sub2 succeeds, and EIP2 is now held.
		rule, addrs, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
			NatGatewayID: rulesGW1ID,
			CIDR:         rulePtr("10.0.2.128/25"),
			FloatingIPID: rulesEIP2ID + "," + rulesEIP1ID,
		})
		if err != nil {
			t.Fatalf("adjacent cidr failed: %v", err)
		}
		if strings.Join(addrs, ",") != "198.51.100.2,198.51.100.1" {
			t.Fatalf("addrs order = %v, want [198.51.100.2 198.51.100.1]", addrs)
		}
		if rule.SourceType != 0 {
			t.Fatalf("source_type = %d, want 0", rule.SourceType)
		}
	})

	t.Run("create rollback preserves existing EIP hold and releases newly held EIP", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)

		// Rule 1 holds EIP1 on GW1.
		if _, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
			NatGatewayID: rulesGW1ID,
			NetworkID:    rulePtr(rulesSub1ID),
			FloatingIPID: rulesEIP1ID,
		}); err != nil {
			t.Fatalf("rule 1: %v", err)
		}

		// Rule 2 asks for [EIP1, EIP2, EIP_BOUND] -> fails on EIP_BOUND.
		// EIP1 must remain held by GW1; EIP2 must be released!
		if _, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
			NatGatewayID: rulesGW1ID,
			NetworkID:    rulePtr(rulesSub2ID),
			FloatingIPID: strings.Join([]string{rulesEIP1ID, rulesEIP2ID, rulesEIPBoundID}, ","),
		}); rulesErrCode(err) != "NAT.0402" {
			t.Fatalf("expected NAT.0402, got %v", err)
		}
		if got := e.eips.holderOf(rulesEIP1ID); got != rulesGW1ID {
			t.Fatalf("EIP1 holder = %q, want %q", got, rulesGW1ID)
		}
		if got := e.eips.holderOf(rulesEIP2ID); got != "" {
			t.Fatalf("EIP2 holder = %q, want empty (rolled back)", got)
		}
	})
}

func TestSnatUpdateAndDelete(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newRulesEnvWithDelay(t, 0)

	rule, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
		NatGatewayID: rulesGW1ID,
		NetworkID:    rulePtr(rulesSub1ID),
		FloatingIPID: rulesEIP1ID,
		Description:  rulePtr("initial"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Mismatched gateway -> NAT.0002.
	if _, _, err := e.svc.updateSnatRule(ctx, rulesTestTenant, rule.ID, updateSnatRuleOption{
		NatGatewayID: rulesGW2ID,
	}); rulesErrCode(err) != "NAT.0002" {
		t.Fatalf("wrong gateway err = %v, want NAT.0002", err)
	}

	// Unknown address -> NAT.0026.
	if _, _, err := e.svc.updateSnatRule(ctx, rulesTestTenant, rule.ID, updateSnatRuleOption{
		NatGatewayID:    rulesGW1ID,
		PublicIPAddress: rulePtr("203.0.113.99"),
	}); rulesErrCode(err) != "NAT.0026" {
		t.Fatalf("unknown addr err = %v, want NAT.0026", err)
	}

	// Duplicate address -> NAT.0403.
	if _, _, err := e.svc.updateSnatRule(ctx, rulesTestTenant, rule.ID, updateSnatRuleOption{
		NatGatewayID:    rulesGW1ID,
		PublicIPAddress: rulePtr("198.51.100.2,198.51.100.2"),
	}); rulesErrCode(err) != "NAT.0403" {
		t.Fatalf("dup addr err = %v, want NAT.0403", err)
	}

	// Update replaces EIP1 with [EIP2, EIP3], releasing EIP1.
	updated, addrs, err := e.svc.updateSnatRule(ctx, rulesTestTenant, rule.ID, updateSnatRuleOption{
		NatGatewayID:    rulesGW1ID,
		PublicIPAddress: rulePtr("198.51.100.2,198.51.100.3"),
		Description:     rulePtr("updated"),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Description != "updated" || strings.Join(updated.FloatingIPIDs, ",") != rulesEIP2ID+","+rulesEIP3ID {
		t.Fatalf("updated = %+v", updated)
	}
	if strings.Join(addrs, ",") != "198.51.100.2,198.51.100.3" {
		t.Fatalf("addrs = %v", addrs)
	}
	if got := e.eips.holderOf(rulesEIP1ID); got != "" {
		t.Fatalf("EIP1 should be released, holder = %q", got)
	}
	if got := e.eips.holderOf(rulesEIP2ID); got != rulesGW1ID {
		t.Fatalf("EIP2 holder = %q, want %q", got, rulesGW1ID)
	}

	// Delete with wrong gateway ID -> NAT.0209.
	if err := e.svc.deleteSnatRule(ctx, rulesTestTenant, rulesGW2ID, rule.ID); rulesErrCode(err) != "NAT.0209" {
		t.Fatalf("delete wrong gw err = %v, want NAT.0209", err)
	}

	// Delete with right gateway releases EIP2 and EIP3.
	if err := e.svc.deleteSnatRule(ctx, rulesTestTenant, rulesGW1ID, rule.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if e.eips.holderOf(rulesEIP2ID) != "" || e.eips.holderOf(rulesEIP3ID) != "" {
		t.Fatalf("EIPs not released on delete: eip2=%q eip3=%q", e.eips.holderOf(rulesEIP2ID), e.eips.holderOf(rulesEIP3ID))
	}
}

// --- DNAT unit tests ---

func TestDnatCreateValidationAndConflicts(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("field validation", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)

		tests := []struct {
			name     string
			opt      createDnatRuleOption
			wantCode string
		}{
			{
				name: "global_eip_id not implemented",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID, GlobalEIPID: rulePtr("g1"),
				},
				wantCode: apierr.CodeNotImplemented,
			},
			{
				name: "both port_id and private_ip",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), PrivateIP: rulePtr("10.0.1.10"),
					Protocol: "tcp", InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0317",
			},
			{
				name: "neither port_id nor private_ip",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0310",
			},
			{
				name: "unknown port_id",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesUnknownID), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0023",
			},
			{
				name: "port_id in another VPC",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPortOther), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0315",
			},
			{
				name: "invalid private_ip",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("not-an-ip"), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0311",
			},
			{
				name: "ipv6 private_ip rejected",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("2001:db8::1"), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0311",
			},
			{
				name: "invalid protocol",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "icmp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0302",
			},
			{
				name: "port out of range high",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
					InternalServicePort: rulePtr(65536), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0303",
			},
			{
				name: "port out of range negative",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(-1),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0303",
			},
			{
				name: "any with non-zero port",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "any",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(0),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0306",
			},
			{
				name: "tcp with zero port",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
					InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(80),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0306",
			},
			{
				name: "any with port range",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "any",
					InternalServicePortRange: rulePtr("8000-8010"), ExternalServicePortRange: rulePtr("9000-9010"),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0306",
			},
			{
				name: "only internal range given",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
					InternalServicePortRange: rulePtr("8000-8010"),
					FloatingIPID:             rulesEIP1ID,
				},
				wantCode: "NAT.0303",
			},
			{
				name: "range lengths differ",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
					InternalServicePortRange: rulePtr("8000-8010"), ExternalServicePortRange: rulePtr("9000-9005"),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0303",
			},
			{
				name: "range reversed a > b",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
					InternalServicePortRange: rulePtr("8010-8000"), ExternalServicePortRange: rulePtr("9010-9000"),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0303",
			},
			{
				name: "range starts at 0",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
					InternalServicePortRange: rulePtr("0-10"), ExternalServicePortRange: rulePtr("1-11"),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0303",
			},
			{
				name: "gateway not found",
				opt: createDnatRuleOption{
					NatGatewayID: rulesUnknownID, PrivateIP: rulePtr("192.168.10.5"), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0105",
			},
			{
				name: "gateway not ACTIVE",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGWPending, PrivateIP: rulePtr("192.168.10.5"), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0103",
			},
			{
				name: "invalid description",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.10.5"), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080),
					FloatingIPID: rulesEIP1ID, Description: rulePtr("bad>desc"),
				},
				wantCode: "NAT.0014",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, tc.opt)
				if got := rulesErrCode(err); got != tc.wantCode {
					t.Fatalf("createDnatRule(%s) err = %v (code %q), want %q", tc.name, err, got, tc.wantCode)
				}
			})
		}

		// Protocol integer representations 6, 17, 0 are stored as tcp, udp, any.
		r6, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "6",
			InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
		})
		if err != nil || r6.Protocol != "tcp" {
			t.Fatalf("proto 6 = %+v, %v", r6, err)
		}
		r17, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "17",
			InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
		})
		if err != nil || r17.Protocol != "udp" {
			t.Fatalf("proto 17 = %+v, %v", r17, err)
		}
		// Range ignores single ports and stores them as 0.
		rRange, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.50.1"), Protocol: "TCP",
			InternalServicePort: rulePtr(999), ExternalServicePort: rulePtr(999),
			InternalServicePortRange: rulePtr("8000-8010"), ExternalServicePortRange: rulePtr("9000-9010"),
			FloatingIPID: rulesEIP2ID,
		})
		if err != nil || rRange.Protocol != "tcp" || rRange.InternalPort != 0 || rRange.ExternalPort != 0 {
			t.Fatalf("range rule = %+v, %v", rRange, err)
		}
		r0, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.50.2"), Protocol: "0",
			InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: rulesEIP3ID,
		})
		if err != nil || r0.Protocol != "any" {
			t.Fatalf("proto 0 = %+v, %v", r0, err)
		}
	})

	t.Run("all 5 conflict rules including ranges", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)
		eip4 := "e4444444-4444-4444-8444-444444444444"
		eip5 := "e5555555-5555-4555-8555-555555555555"
		eip6 := "e6666666-6666-4666-8666-666666666666"
		e.eips.add(eip4, "198.51.100.4")
		e.eips.add(eip5, "198.51.100.5")
		e.eips.add(eip6, "198.51.100.6")

		// Seed:
		// 1. SNAT rule using EIP5.
		if _, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
			NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSub1ID), FloatingIPID: eip5,
		}); err != nil {
			t.Fatalf("seed snat: %v", err)
		}
		// 2. TCP range rule on EIP1 + port1: internal 8000-8010 -> external 9000-9010.
		if _, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
			InternalServicePortRange: rulePtr("8000-8010"), ExternalServicePortRange: rulePtr("9000-9010"),
			FloatingIPID: rulesEIP1ID,
		}); err != nil {
			t.Fatalf("seed tcp range: %v", err)
		}
		// 3. TCP single rule on EIP1 + private_ip 192.168.1.10: internal 443 -> external 8443.
		if _, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.10"), Protocol: "tcp",
			InternalServicePort: rulePtr(443), ExternalServicePort: rulePtr(8443), FloatingIPID: rulesEIP1ID,
		}); err != nil {
			t.Fatalf("seed tcp single: %v", err)
		}
		// 4. ANY rule on EIP2 + port2.
		if _, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort2ID), Protocol: "any",
			InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: rulesEIP2ID,
		}); err != nil {
			t.Fatalf("seed any port2: %v", err)
		}
		// 5. ANY rule on EIP3 + private_ip 192.168.1.20.
		if _, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.20"), Protocol: "any",
			InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: rulesEIP3ID,
		}); err != nil {
			t.Fatalf("seed any priv20: %v", err)
		}

		tests := []struct {
			name     string
			opt      createDnatRuleOption
			wantCode string
		}{
			{
				name: "NAT.0305 external single overlaps range endpoint",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.99"), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(9010), FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0305",
			},
			{
				name: "NAT.0305 external range overlaps range",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.99"), Protocol: "tcp",
					InternalServicePortRange: rulePtr("7000-7005"), ExternalServicePortRange: rulePtr("8995-9000"),
					FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0305",
			},
			{
				name: "NAT.0305 two any rules on same EIP",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.99"), Protocol: "any",
					InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: rulesEIP2ID,
				},
				wantCode: "NAT.0305",
			},
			{
				name: "NAT.0304 internal port_id range overlap",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
					InternalServicePort: rulePtr(8005), ExternalServicePort: rulePtr(9500), FloatingIPID: eip4,
				},
				wantCode: "NAT.0304",
			},
			{
				name: "NAT.0304 internal private_ip single overlap",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.10"), Protocol: "tcp",
					InternalServicePort: rulePtr(443), ExternalServicePort: rulePtr(9501), FloatingIPID: eip4,
				},
				wantCode: "NAT.0304",
			},
			{
				name: "NAT.0307 any on port_id that has tcp rule",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "any",
					InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: eip4,
				},
				wantCode: "NAT.0307",
			},
			{
				name: "NAT.0307 tcp on port_id that has any rule",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort2ID), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(9502), FloatingIPID: eip4,
				},
				wantCode: "NAT.0307",
			},
			{
				name: "NAT.0307 any on port_id that already has any rule",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort2ID), Protocol: "any",
					InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: eip4,
				},
				wantCode: "NAT.0307",
			},
			{
				name: "NAT.0308 any on private_ip that has tcp rule",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.10"), Protocol: "any",
					InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: eip4,
				},
				wantCode: "NAT.0308",
			},
			{
				name: "NAT.0308 tcp on private_ip that has any rule",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.20"), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(9503), FloatingIPID: eip4,
				},
				wantCode: "NAT.0308",
			},
			{
				name: "NAT.0408 any on EIP that has tcp rule",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.99"), Protocol: "any",
					InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: rulesEIP1ID,
				},
				wantCode: "NAT.0408",
			},
			{
				name: "NAT.0408 tcp on EIP that has any rule",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.99"), Protocol: "tcp",
					InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(9504), FloatingIPID: rulesEIP2ID,
				},
				wantCode: "NAT.0408",
			},
			{
				name: "NAT.0409 any on EIP used by SNAT rule",
				opt: createDnatRuleOption{
					NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.99"), Protocol: "any",
					InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: eip5,
				},
				wantCode: "NAT.0409",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, tc.opt)
				if got := rulesErrCode(err); got != tc.wantCode {
					t.Fatalf("createDnatRule(%s) err = %v (code %q), want %q", tc.name, err, got, tc.wantCode)
				}
			})
		}

		// Non-overlapping adjacent range & UDP on same ports & TCP sharing EIP with SNAT all succeed!
		if _, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
			InternalServicePortRange: rulePtr("8011-8020"), ExternalServicePortRange: rulePtr("9011-9020"),
			FloatingIPID: rulesEIP1ID,
		}); err != nil {
			t.Fatalf("adjacent range failed: %v", err)
		}
		if _, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "udp",
			InternalServicePortRange: rulePtr("8000-8010"), ExternalServicePortRange: rulePtr("9000-9010"),
			FloatingIPID: rulesEIP1ID,
		}); err != nil {
			t.Fatalf("udp on same range failed: %v", err)
		}
		if _, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.99"), Protocol: "tcp",
			InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: eip5,
		}); err != nil {
			t.Fatalf("tcp sharing SNAT EIP failed: %v", err)
		}
		_ = eip6
	})

	t.Run("dnat_rules_limit NAT.0309", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)

		for i := range publicDnatRulesLimit {
			p := i + 1
			r := dnatRule{
				ID: fmt.Sprintf("d0000000-0000-4000-8000-%012d", p), GatewayID: rulesGW1ID,
				PrivateIP: "192.168.1.10", Protocol: "tcp", InternalPort: p, ExternalPort: p,
				FloatingIPID: rulesEIP1ID, Status: StatusActive, CreatedAt: rulesTestEpoch,
			}
			if err := e.svc.dnatRules(rulesTestTenant).Create(ctx, r.ID, r); err != nil {
				t.Fatalf("seed %d: %v", i, err)
			}
		}

		_, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.10"), Protocol: "tcp",
			InternalServicePort: rulePtr(3000), ExternalServicePort: rulePtr(3000), FloatingIPID: rulesEIP1ID,
		})
		if got := rulesErrCode(err); got != "NAT.0309" {
			t.Fatalf("201st dnat err = %v (code %q), want NAT.0309", err, got)
		}
	})
}

func TestDnatBatchCreate(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("empty list NAT.0002", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)
		if _, _, err := e.svc.batchCreateDnatRules(ctx, rulesTestTenant, nil); rulesErrCode(err) != "NAT.0002" {
			t.Fatalf("empty batch err = %v, want NAT.0002", err)
		}
	})

	t.Run("intra-batch conflict rolls back everything", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)
		_, _, err := e.svc.batchCreateDnatRules(ctx, rulesTestTenant, []createDnatRuleOption{
			{
				NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.1"), Protocol: "tcp",
				InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
			},
			{
				NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.2"), Protocol: "tcp",
				InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
			},
		})
		if got := rulesErrCode(err); got != "NAT.0305" {
			t.Fatalf("intra-batch conflict err = %v, want NAT.0305", err)
		}
		if e.eips.holderOf(rulesEIP1ID) != "" {
			t.Fatalf("EIP1 should not be held after failed batch")
		}
		rules, _, err := e.svc.listDnatRules(ctx, rulesTestTenant, listDnatRulesFilter{Page: listLimitsMarker()})
		if err != nil || len(rules) != 0 {
			t.Fatalf("rules after failed batch = %d, %v; want 0", len(rules), err)
		}
	})

	t.Run("mid-batch EIP hold failure rolls back earlier holds", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)
		_, _, err := e.svc.batchCreateDnatRules(ctx, rulesTestTenant, []createDnatRuleOption{
			{
				NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.1"), Protocol: "tcp",
				InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
			},
			{
				NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.2"), Protocol: "tcp",
				InternalServicePort: rulePtr(81), ExternalServicePort: rulePtr(8081), FloatingIPID: rulesEIPBoundID,
			},
		})
		if got := rulesErrCode(err); got != "NAT.0402" {
			t.Fatalf("mid-batch bound EIP err = %v, want NAT.0402", err)
		}
		if e.eips.holderOf(rulesEIP1ID) != "" {
			t.Fatalf("EIP1 should be rolled back, holder = %q", e.eips.holderOf(rulesEIP1ID))
		}
	})

	t.Run("batch remaining limit NAT.0314", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)
		for i := range publicDnatRulesLimit - 1 {
			p := i + 1
			r := dnatRule{
				ID: fmt.Sprintf("d1000000-0000-4000-8000-%012d", p), GatewayID: rulesGW1ID,
				PrivateIP: "192.168.1.10", Protocol: "tcp", InternalPort: p, ExternalPort: p,
				FloatingIPID: rulesEIP1ID, Status: StatusActive, CreatedAt: rulesTestEpoch,
			}
			if err := e.svc.dnatRules(rulesTestTenant).Create(ctx, r.ID, r); err != nil {
				t.Fatalf("seed %d: %v", i, err)
			}
		}

		_, _, err := e.svc.batchCreateDnatRules(ctx, rulesTestTenant, []createDnatRuleOption{
			{
				NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.10"), Protocol: "tcp",
				InternalServicePort: rulePtr(3001), ExternalServicePort: rulePtr(3001), FloatingIPID: rulesEIP1ID,
			},
			{
				NatGatewayID: rulesGW1ID, PrivateIP: rulePtr("192.168.1.10"), Protocol: "tcp",
				InternalServicePort: rulePtr(3002), ExternalServicePort: rulePtr(3002), FloatingIPID: rulesEIP1ID,
			},
		})
		if got := rulesErrCode(err); got != "NAT.0314" {
			t.Fatalf("batch limit err = %v (code %q), want NAT.0314", err, got)
		}
		var ae *apierr.Error
		if errors.As(err, &ae) && !strings.Contains(ae.Message, "1") {
			t.Fatalf("expected remaining count 1 in message, got %q", ae.Message)
		}
	})

	t.Run("multi-gateway batch succeeds", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)
		rules, addrs, err := e.svc.batchCreateDnatRules(ctx, rulesTestTenant, []createDnatRuleOption{
			{
				NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
				InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
			},
			{
				NatGatewayID: rulesGW2ID, PrivateIP: rulePtr("192.168.10.2"), Protocol: "any",
				InternalServicePort: rulePtr(0), ExternalServicePort: rulePtr(0), FloatingIPID: rulesEIP2ID,
			},
		})
		if err != nil {
			t.Fatalf("multi-gw batch: %v", err)
		}
		if len(rules) != 2 || addrs[0] != "198.51.100.1" || addrs[1] != "198.51.100.2" {
			t.Fatalf("batch result = %+v, %v", rules, addrs)
		}
		if e.eips.holderOf(rulesEIP1ID) != rulesGW1ID || e.eips.holderOf(rulesEIP2ID) != rulesGW2ID {
			t.Fatalf("holders = (%q, %q)", e.eips.holderOf(rulesEIP1ID), e.eips.holderOf(rulesEIP2ID))
		}
	})
}

func TestDnatUpdateAndDelete(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newRulesEnvWithDelay(t, 0)

	r1, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
		NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
		InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
		Description: rulePtr("r1"),
	})
	if err != nil {
		t.Fatalf("create r1: %v", err)
	}
	if _, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
		NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort2ID), Protocol: "tcp",
		InternalServicePort: rulePtr(81), ExternalServicePort: rulePtr(8081), FloatingIPID: rulesEIP1ID,
	}); err != nil {
		t.Fatalf("create r2: %v", err)
	}

	// Description-only update excludes self from conflict check.
	upd, addr, err := e.svc.updateDnatRule(ctx, rulesTestTenant, r1.ID, updateDnatRuleOption{
		NatGatewayID: rulesGW1ID,
		Description:  rulePtr("r1-desc"),
	})
	if err != nil || upd.Description != "r1-desc" || addr != "198.51.100.1" {
		t.Fatalf("desc update = %+v, %q, %v", upd, addr, err)
	}

	// Conflicting port update against r2 fails with NAT.0305.
	if _, _, err := e.svc.updateDnatRule(ctx, rulesTestTenant, r1.ID, updateDnatRuleOption{
		NatGatewayID:        rulesGW1ID,
		ExternalServicePort: rulePtr(8081),
	}); rulesErrCode(err) != "NAT.0305" {
		t.Fatalf("conflict update err = %v, want NAT.0305", err)
	}

	// Switch to EIP2, private_ip, uppercase UDP, and port ranges.
	// EIP1 stays held because r2 still uses it; EIP2 becomes held.
	upd, addr, err = e.svc.updateDnatRule(ctx, rulesTestTenant, r1.ID, updateDnatRuleOption{
		NatGatewayID:             rulesGW1ID,
		FloatingIPID:             rulePtr(rulesEIP2ID),
		PrivateIP:                rulePtr("192.168.5.5"),
		Protocol:                 rulePtr("UDP"),
		InternalServicePortRange: rulePtr("5000-5005"),
		ExternalServicePortRange: rulePtr("6000-6005"),
	})
	if err != nil {
		t.Fatalf("full update: %v", err)
	}
	if upd.Protocol != "udp" || upd.PortID != "" || upd.PrivateIP != "192.168.5.5" ||
		upd.InternalPort != 0 || upd.ExternalPort != 0 ||
		upd.InternalRange != "5000-5005" || upd.ExternalRange != "6000-6005" ||
		addr != "198.51.100.2" {
		t.Fatalf("unexpected updated rule: %+v addr=%q", upd, addr)
	}
	if e.eips.holderOf(rulesEIP1ID) != rulesGW1ID || e.eips.holderOf(rulesEIP2ID) != rulesGW1ID {
		t.Fatalf("holders = (%q, %q)", e.eips.holderOf(rulesEIP1ID), e.eips.holderOf(rulesEIP2ID))
	}

	// Switch back from range to single port and EIP3; EIP2 is released.
	upd, addr, err = e.svc.updateDnatRule(ctx, rulesTestTenant, r1.ID, updateDnatRuleOption{
		NatGatewayID:        rulesGW1ID,
		FloatingIPID:        rulePtr(rulesEIP3ID),
		InternalServicePort: rulePtr(53),
		ExternalServicePort: rulePtr(5353),
	})
	if err != nil {
		t.Fatalf("range-to-single update: %v", err)
	}
	if upd.InternalRange != "" || upd.ExternalRange != "" || upd.InternalPort != 53 || upd.ExternalPort != 5353 || addr != "198.51.100.3" {
		t.Fatalf("range-to-single = %+v addr=%q", upd, addr)
	}
	if e.eips.holderOf(rulesEIP2ID) != "" {
		t.Fatalf("EIP2 should have been released, holder = %q", e.eips.holderOf(rulesEIP2ID))
	}

	// Wrong gateway on update -> NAT.0002; wrong gateway on delete -> NAT.0319.
	if _, _, err := e.svc.updateDnatRule(ctx, rulesTestTenant, r1.ID, updateDnatRuleOption{
		NatGatewayID: rulesGW2ID,
	}); rulesErrCode(err) != "NAT.0002" {
		t.Fatalf("update wrong gw err = %v, want NAT.0002", err)
	}
	if err := e.svc.deleteDnatRule(ctx, rulesTestTenant, rulesGW2ID, r1.ID); rulesErrCode(err) != "NAT.0319" {
		t.Fatalf("delete wrong gw err = %v, want NAT.0319", err)
	}
	if err := e.svc.deleteDnatRule(ctx, rulesTestTenant, rulesGW1ID, r1.ID); err != nil {
		t.Fatalf("delete r1: %v", err)
	}
	if e.eips.holderOf(rulesEIP3ID) != "" {
		t.Fatalf("EIP3 should be released after delete, holder = %q", e.eips.holderOf(rulesEIP3ID))
	}
}

// --- EIP sharing & release-on-last ---

func TestRulesEIPHoldSharingAndReleaseOnLast(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newRulesEnvWithDelay(t, 0)

	sn1, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
		NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSub1ID), FloatingIPID: rulesEIP1ID,
	})
	if err != nil {
		t.Fatalf("sn1: %v", err)
	}
	sn2, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
		NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSub2ID), FloatingIPID: rulesEIP1ID,
	})
	if err != nil {
		t.Fatalf("sn2: %v", err)
	}
	dn1, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
		NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
		InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
	})
	if err != nil {
		t.Fatalf("dn1: %v", err)
	}

	// Gateway 2 cannot take EIP1 while GW1 holds it.
	if _, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
		NatGatewayID: rulesGW2ID, NetworkID: rulePtr(rulesSubOtherID), FloatingIPID: rulesEIP1ID,
	}); rulesErrCode(err) != "NAT.0404" {
		t.Fatalf("gw2 steal EIP1 err = %v, want NAT.0404", err)
	}

	// Deleting sn1 and dn1 must NOT release EIP1 while sn2 still references it.
	if err := e.svc.deleteSnatRule(ctx, rulesTestTenant, rulesGW1ID, sn1.ID); err != nil {
		t.Fatalf("delete sn1: %v", err)
	}
	if e.eips.holderOf(rulesEIP1ID) != rulesGW1ID {
		t.Fatalf("EIP1 released prematurely after sn1 delete")
	}
	if err := e.svc.deleteDnatRule(ctx, rulesTestTenant, rulesGW1ID, dn1.ID); err != nil {
		t.Fatalf("delete dn1: %v", err)
	}
	if e.eips.holderOf(rulesEIP1ID) != rulesGW1ID {
		t.Fatalf("EIP1 released prematurely after dn1 delete")
	}

	// Deleting sn2 (the last rule using EIP1 on GW1) releases EIP1, allowing GW2 to claim it.
	if err := e.svc.deleteSnatRule(ctx, rulesTestTenant, rulesGW1ID, sn2.ID); err != nil {
		t.Fatalf("delete sn2: %v", err)
	}
	if e.eips.holderOf(rulesEIP1ID) != "" {
		t.Fatalf("EIP1 not released after last rule deleted: holder=%q", e.eips.holderOf(rulesEIP1ID))
	}
	if _, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
		NatGatewayID: rulesGW2ID, NetworkID: rulePtr(rulesSubOtherID), FloatingIPID: rulesEIP1ID,
	}); err != nil {
		t.Fatalf("gw2 claim released EIP1: %v", err)
	}
	if e.eips.holderOf(rulesEIP1ID) != rulesGW2ID {
		t.Fatalf("EIP1 holder = %q, want %q", e.eips.holderOf(rulesEIP1ID), rulesGW2ID)
	}
}

// --- Lifecycle transitions (ACTIVE & fault INACTIVE) ---

func TestRulesLifecycleTransitions(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("zero delay PENDING_CREATE to ACTIVE", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)

		sn, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
			NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSub1ID), FloatingIPID: rulesEIP1ID,
		})
		if err != nil || sn.Status != StatusPendingCreate {
			t.Fatalf("create snat = %q, %v; want PENDING_CREATE", sn.Status, err)
		}
		dn, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
			InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
		})
		if err != nil || dn.Status != StatusPendingCreate {
			t.Fatalf("create dnat = %q, %v; want PENDING_CREATE", dn.Status, err)
		}

		if err := e.engine.WaitIdle(ctx); err != nil {
			t.Fatalf("WaitIdle: %v", err)
		}

		gotSn, _, err := e.svc.getSnatRule(ctx, rulesTestTenant, sn.ID)
		if err != nil || gotSn.Status != StatusActive {
			t.Fatalf("snat after settle = %q, %v; want ACTIVE", gotSn.Status, err)
		}
		gotDn, _, err := e.svc.getDnatRule(ctx, rulesTestTenant, dn.ID)
		if err != nil || gotDn.Status != StatusActive {
			t.Fatalf("dnat after settle = %q, %v; want ACTIVE", gotDn.Status, err)
		}
	})

	t.Run("injected faults transition to INACTIVE", func(t *testing.T) {
		t.Parallel()
		e := newRulesEnvWithDelay(t, 0)

		if _, err := e.faults.Add(faults.Rule{Type: faults.TypeLifecycle, Transition: taskSnatCreate, Times: 1}); err != nil {
			t.Fatalf("add snat fault: %v", err)
		}
		if _, err := e.faults.Add(faults.Rule{Type: faults.TypeLifecycle, Transition: taskDnatCreate, Times: 1}); err != nil {
			t.Fatalf("add dnat fault: %v", err)
		}

		sn, _, err := e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
			NatGatewayID: rulesGW1ID, NetworkID: rulePtr(rulesSub1ID), FloatingIPID: rulesEIP1ID,
		})
		if err != nil {
			t.Fatalf("create snat: %v", err)
		}
		dn, _, err := e.svc.createDnatRule(ctx, rulesTestTenant, createDnatRuleOption{
			NatGatewayID: rulesGW1ID, PortID: rulePtr(rulesPort1ID), Protocol: "tcp",
			InternalServicePort: rulePtr(80), ExternalServicePort: rulePtr(8080), FloatingIPID: rulesEIP1ID,
		})
		if err != nil {
			t.Fatalf("create dnat: %v", err)
		}

		if err := e.engine.WaitIdle(ctx); err != nil {
			t.Fatalf("WaitIdle: %v", err)
		}

		gotSn, _, err := e.svc.getSnatRule(ctx, rulesTestTenant, sn.ID)
		if err != nil || gotSn.Status != StatusInactive {
			t.Fatalf("snat after fault = %q, %v; want INACTIVE", gotSn.Status, err)
		}
		gotDn, _, err := e.svc.getDnatRule(ctx, rulesTestTenant, dn.ID)
		if err != nil || gotDn.Status != StatusInactive {
			t.Fatalf("dnat after fault = %q, %v; want INACTIVE", gotDn.Status, err)
		}
	})
}

// --- Concurrency race test (§7) ---

func TestSnatConcurrentEIPHoldRace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newRulesEnvWithDelay(t, 0)

	// Add 4 shared EIPs to race over across 2 gateways using 8 goroutines.
	eipIDs := make([]string, 4)
	for i := range eipIDs {
		id := fmt.Sprintf("c0000000-0000-4000-8000-%012d", i+1)
		eipIDs[i] = id
		e.eips.add(id, fmt.Sprintf("203.0.113.%d", i+1))
	}

	const workers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			<-start
			gwID := rulesGW1ID
			if idx%2 == 1 {
				gwID = rulesGW2ID
			}
			for j, eipID := range eipIDs {
				cidr := fmt.Sprintf("172.%d.%d.0/24", 20+idx, j)
				_, _, _ = e.svc.createSnatRule(ctx, rulesTestTenant, createSnatRuleOption{
					NatGatewayID: gwID,
					CIDR:         rulePtr(cidr),
					SourceType:   rulePtr(1),
					FloatingIPID: eipID,
				})
			}
		}(i)
	}
	close(start)
	wg.Wait()

	// Every EIP must be held by exactly one gateway, and every SNAT rule using
	// that EIP must belong to that same gateway.
	rules, _, err := e.svc.listSnatRules(ctx, rulesTestTenant, listSnatRulesFilter{Page: listLimitsMarker()})
	if err != nil {
		t.Fatalf("list snats: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("expected at least some SNAT rules created")
	}
	for _, eipID := range eipIDs {
		holder := e.eips.holderOf(eipID)
		if holder != rulesGW1ID && holder != rulesGW2ID {
			t.Fatalf("EIP %s holder = %q, want one of (%s, %s)", eipID, holder, rulesGW1ID, rulesGW2ID)
		}
		var count int
		for _, r := range rules {
			for _, id := range r.FloatingIPIDs {
				if id == eipID {
					count++
					if r.GatewayID != holder {
						t.Fatalf("EIP %s used by rule on %s but held by %s", eipID, r.GatewayID, holder)
					}
				}
			}
		}
		if count == 0 {
			t.Fatalf("EIP %s held by %s with 0 rules", eipID, holder)
		}
	}
}

func listLimitsMarker() pagination.Marker {
	return pagination.Marker{Limit: listLimits.Default}
}
