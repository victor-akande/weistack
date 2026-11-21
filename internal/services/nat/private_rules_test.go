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
	"sync/atomic"
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
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	prTestProject = "0123456789abcdef0123456789abcdef"
	prTestRegion  = "ap-southeast-1"
	prTestHost    = "nat." + prTestRegion + ".myhuaweicloud.com"

	prVPC1ID       = "11111111-1111-4111-8111-111111111111"
	prVPC2ID       = "22222222-2222-4222-8222-222222222222"
	prTransitVPCID = "33333333-3333-4333-8333-333333333333"

	prSub1ID        = "44444444-4444-4444-8444-444444444444"
	prSub2ID        = "55555555-5555-4555-8555-555555555555"
	prSubOtherID    = "66666666-6666-4666-8666-666666666666"
	prTransitVirID  = "77777777-7777-4777-8777-777777777777"
	prTransitSubID  = "88888888-8888-4888-8888-888888888888"
	prTransitVir2ID = "99999999-9999-4999-8999-999999999999"
	prTransitSub2ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

	prGW1ID       = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	prGW2ID       = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	prPort1ID     = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	prPort2ID     = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	prPortOtherID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	prUnknownID   = "00000000-0000-4000-8000-000000000000"
	prCustomEP    = "12345678-1234-4123-8123-123456789012"
)

var (
	prTestTenant = Tenant{Region: prTestRegion, ProjectID: prTestProject}
	prTestEpoch  = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
)

type prFakeNetwork struct {
	mu      sync.Mutex
	vpcs    map[string]vpc.VPC
	subnets map[string]vpc.Subnet
	ports   map[string]vpc.Port
	allocs  map[string]map[string]string
	fullSub map[string]bool
}

func newPRFakeNetwork() *prFakeNetwork {
	return &prFakeNetwork{
		vpcs: map[string]vpc.VPC{
			prVPC1ID:       {ID: prVPC1ID, Name: "vpc-1", CIDR: "10.0.0.0/16"},
			prVPC2ID:       {ID: prVPC2ID, Name: "vpc-2", CIDR: "10.1.0.0/16"},
			prTransitVPCID: {ID: prTransitVPCID, Name: "vpc-transit", CIDR: "172.16.0.0/16"},
		},
		subnets: map[string]vpc.Subnet{
			prSub1ID:        {ID: prSub1ID, VPCID: prVPC1ID, CIDR: "10.0.1.0/24", GatewayIP: "10.0.1.1"},
			prSub2ID:        {ID: prSub2ID, VPCID: prVPC1ID, CIDR: "10.0.2.0/24", GatewayIP: "10.0.2.1"},
			prSubOtherID:    {ID: prSubOtherID, VPCID: prVPC2ID, CIDR: "10.1.1.0/24", GatewayIP: "10.1.1.1"},
			prTransitVirID:  {ID: prTransitVirID, VPCID: prTransitVPCID, CIDR: "172.16.1.0/24", GatewayIP: "172.16.1.1"},
			prTransitVir2ID: {ID: prTransitVir2ID, VPCID: prTransitVPCID, CIDR: "172.16.2.0/24", GatewayIP: "172.16.2.1"},
		},
		ports: map[string]vpc.Port{
			prPort1ID:     {ID: prPort1ID, SubnetID: prSub1ID, IP: "10.0.1.10"},
			prPort2ID:     {ID: prPort2ID, SubnetID: prSub2ID, IP: "10.0.2.10"},
			prPortOtherID: {ID: prPortOtherID, SubnetID: prSubOtherID, IP: "10.1.1.10"},
		},
		allocs:  make(map[string]map[string]string),
		fullSub: make(map[string]bool),
	}
}

func (f *prFakeNetwork) GetVPC(_ context.Context, _ vpc.Tenant, id string) (vpc.VPC, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vpcs[id]
	if !ok {
		return vpc.VPC{}, apierr.New(http.StatusNotFound, "VPC.0102", "vpc %s not found", id)
	}
	return v, nil
}

func (f *prFakeNetwork) GetSubnet(_ context.Context, _ vpc.Tenant, id string) (vpc.Subnet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sn, ok := f.subnets[id]
	if !ok {
		return vpc.Subnet{}, apierr.New(http.StatusNotFound, "VPC.0202", "subnet %s not found", id)
	}
	return sn, nil
}

func (f *prFakeNetwork) ListSubnets(_ context.Context, _ vpc.Tenant, filter vpc.ListSubnetsFilter) ([]vpc.Subnet, error) {
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

func (f *prFakeNetwork) Port(_ context.Context, _ vpc.Tenant, id string) (vpc.Port, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.ports[id]
	return p, ok, nil
}

func (f *prFakeNetwork) AllocateIP(_ context.Context, _ vpc.Tenant, subnetID, owner, want string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sn, ok := f.subnets[subnetID]
	if !ok {
		return "", vpc.ErrSubnetNotFound
	}
	if f.fullSub[subnetID] && want == "" {
		return "", vpc.ErrSubnetFull
	}
	taken := f.allocs[subnetID]
	if taken == nil {
		taken = make(map[string]string)
		f.allocs[subnetID] = taken
	}
	if want != "" {
		if want == "172.16.1.1" || want == "172.16.1.0" || want == "bad-ip" || !strings.HasPrefix(want, strings.Split(sn.CIDR, ".")[0]+".") {
			return "", vpc.ErrIPNotUsable
		}
		if _, used := taken[want]; used {
			return "", vpc.ErrIPInUse
		}
		taken[want] = owner
		return want, nil
	}
	base := strings.TrimSuffix(strings.Split(sn.CIDR, "/")[0], ".0")
	for host := 2; host < 250; host++ {
		cand := fmt.Sprintf("%s.%d", base, host)
		if _, used := taken[cand]; !used {
			taken[cand] = owner
			return cand, nil
		}
	}
	return "", vpc.ErrSubnetFull
}

func (f *prFakeNetwork) ReleaseIP(_ context.Context, _ vpc.Tenant, subnetID, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if taken := f.allocs[subnetID]; taken != nil {
		delete(taken, ip)
	}
	return nil
}

func (f *prFakeNetwork) isAllocated(subnetID, ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if taken := f.allocs[subnetID]; taken != nil {
		_, ok := taken[ip]
		return ok
	}
	return false
}

type prFakeEIPs struct{}

func (prFakeEIPs) HoldForNAT(context.Context, vpc.Tenant, string, string) (string, error) {
	return "", nil
}
func (prFakeEIPs) ReleaseFromNAT(context.Context, vpc.Tenant, string, string) error { return nil }
func (prFakeEIPs) PublicIPByAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}
func (prFakeEIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type prEnv struct {
	svc     *Service
	store   store.Store
	net     *prFakeNetwork
	handler http.Handler
}

func newPREnv(t *testing.T) *prEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(prTestEpoch)
	flt := faults.New(clock.Now)
	engine := lifecycle.New(lifecycle.Options{Delay: 0, Clock: clock, Logger: log, Faults: flt})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	netStub := newPRFakeNetwork()
	gen := ids.NewSeeded(42)
	svc, err := New(Deps{
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		VPC:    netStub,
		EIPs:   prFakeEIPs{},
		Now:    clock.Now,
	})
	if err != nil {
		t.Fatalf("nat.New: %v", err)
	}

	// Seed two private gateways (in VPC1 and VPC2) and two transit subnets (in TransitVPC).
	for _, gw := range []privateGateway{
		{
			ID: prGW1ID, Name: "pgw-1", Spec: "Small",
			VPCID: prVPC1ID, SubnetID: prSub1ID, NgportIP: "10.0.1.5",
			EnterpriseProjectID: defaultEnterpriseProjectID, CreatedAt: prTestEpoch, UpdatedAt: prTestEpoch,
		},
		{
			ID: prGW2ID, Name: "pgw-2", Spec: "Small",
			VPCID: prVPC2ID, SubnetID: prSubOtherID, NgportIP: "10.1.1.5",
			EnterpriseProjectID: prCustomEP, CreatedAt: prTestEpoch, UpdatedAt: prTestEpoch,
		},
	} {
		if err := svc.privateGateways(prTestTenant).Create(t.Context(), gw.ID, gw); err != nil {
			t.Fatalf("seed private gateway %s: %v", gw.ID, err)
		}
	}
	for _, ts := range []transitSubnet{
		{
			ID: prTransitSubID, Name: "ts-1", SubnetID: prTransitVirID,
			VPCID: prTransitVPCID, CIDR: "172.16.1.0/24", CreatedAt: prTestEpoch, UpdatedAt: prTestEpoch,
		},
		{
			ID: prTransitSub2ID, Name: "ts-2", SubnetID: prTransitVir2ID,
			VPCID: prTransitVPCID, CIDR: "172.16.2.0/24", CreatedAt: prTestEpoch, UpdatedAt: prTestEpoch,
		},
	} {
		if err := svc.transitSubnets(prTestTenant).Create(t.Context(), ts.ID, ts); err != nil {
			t.Fatalf("seed transit subnet %s: %v", ts.ID, err)
		}
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: prTestProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &prEnv{svc: svc, store: st, net: netStub, handler: srv.Handler()}
}

func (e *prEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v3/"+prTestProject+"/private-nat"+path, rd)
	r.Host = prTestHost
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

func (e *prEnv) expect(t *testing.T, dir, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", dir, goldenName+".json"), status, out)
	return out
}

func prDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func prErrCode(err error) string {
	var ae *apierr.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestTransitIPCreateListShowDeleteAndValidation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newPREnv(t)

	// Auto IP allocation.
	ti1, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{
		VirsubnetID: prTransitVirID,
		Tags:        []tag{{Key: "env", Value: "prod"}},
	})
	if err != nil {
		t.Fatalf("create auto transit IP: %v", err)
	}
	if ti1.Address != "172.16.1.2" || ti1.GatewayID != "" || ti1.NetworkInterfaceID == "" {
		t.Fatalf("unexpected ti1: %+v", ti1)
	}
	if !e.net.isAllocated(prTransitVirID, ti1.Address) {
		t.Fatalf("expected IP %s to be allocated in VPC", ti1.Address)
	}

	// Explicit IP + custom EP on second transit subnet.
	ti2, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{
		VirsubnetID:         prTransitVir2ID,
		IPAddress:           "172.16.2.68",
		EnterpriseProjectID: prCustomEP,
	})
	if err != nil {
		t.Fatalf("create explicit transit IP: %v", err)
	}

	// Mark prTransitVir2ID full for NAT.1404 test.
	e.net.fullSub[prTransitVir2ID] = true

	var tooManyTags []tag
	for i := range maxTags + 1 {
		tooManyTags = append(tooManyTags, tag{Key: fmt.Sprintf("k%d", i), Value: "v"})
	}

	errCases := []struct {
		name     string
		in       createTransitIPInput
		wantCode string
	}{
		{"missing virsubnet_id", createTransitIPInput{}, "NAT.1010"},
		{"invalid enterprise_project_id", createTransitIPInput{VirsubnetID: prTransitVirID, EnterpriseProjectID: "bad-ep"}, "VPC.0011"},
		{"invalid tag", createTransitIPInput{VirsubnetID: prTransitVirID, Tags: []tag{{Key: "", Value: "v"}}}, "NAT.1015"},
		{"too many tags", createTransitIPInput{VirsubnetID: prTransitVirID, Tags: tooManyTags}, "NAT.1016"},
		{"unknown subnet", createTransitIPInput{VirsubnetID: prUnknownID}, "NAT.1002"},
		{"non-transit subnet", createTransitIPInput{VirsubnetID: prSub1ID}, "NAT.1101"},
		{"unusable ip", createTransitIPInput{VirsubnetID: prTransitVirID, IPAddress: "172.16.1.1"}, "NAT.1405"},
		{"ip in use", createTransitIPInput{VirsubnetID: prTransitVirID, IPAddress: ti1.Address}, "NAT.1403"},
		{"subnet full", createTransitIPInput{VirsubnetID: prTransitVir2ID}, "NAT.1404"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.svc.createTransitIP(ctx, prTestTenant, tc.in); prErrCode(err) != tc.wantCode {
				t.Fatalf("got %q (%v), want %q", prErrCode(err), err, tc.wantCode)
			}
		})
	}

	// List filter by transit_subnet_id, virsubnet_id, enterprise_project_id, gateway_id.
	win, all, err := e.svc.listTransitIPs(ctx, prTestTenant, listTransitIPsFilter{
		TransitSubnetIDs: []string{prTransitSubID},
		Page:             pagination.Marker{Limit: 2000},
	})
	if err != nil || len(win) != 1 || len(all) != 1 || win[0].ID != ti1.ID {
		t.Fatalf("list by transit_subnet_id = (%v, %v, %v)", win, all, err)
	}
	win, _, err = e.svc.listTransitIPs(ctx, prTestTenant, listTransitIPsFilter{
		EnterpriseProjectIDs: []string{allGrantedEPs},
		Page:                 pagination.Marker{Limit: 2000},
	})
	if err != nil || len(win) != 2 {
		t.Fatalf("list all_granted_eps = (%d, %v), want 2", len(win), err)
	}

	// Delete releases IP.
	if err := e.svc.deleteTransitIP(ctx, prTestTenant, ti2.ID); err != nil {
		t.Fatalf("delete ti2: %v", err)
	}
	if e.net.isAllocated(prTransitVir2ID, ti2.Address) {
		t.Fatalf("expected IP %s to be released", ti2.Address)
	}
	if err := e.svc.deleteTransitIP(ctx, prTestTenant, ti2.ID); prErrCode(err) != "NAT.1002" {
		t.Fatalf("delete missing err = %q, want NAT.1002", prErrCode(err))
	}
}

func TestPrivateSnatValidationAndTransitIPLinking(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newPREnv(t)

	// Seed a transit IP in gateway 1's own VPC (by adding a transit subnet in VPC1) for NAT.1303.
	sameVPCTransitVir := "77777777-7777-4777-8777-777777777700"
	e.net.mu.Lock()
	e.net.subnets[sameVPCTransitVir] = vpc.Subnet{ID: sameVPCTransitVir, VPCID: prVPC1ID, CIDR: "10.0.99.0/24", GatewayIP: "10.0.99.1"}
	e.net.mu.Unlock()
	if err := e.svc.transitSubnets(prTestTenant).Create(ctx, "ts-same-vpc", transitSubnet{
		ID: "ts-same-vpc", Name: "ts-same", SubnetID: sameVPCTransitVir, VPCID: prVPC1ID, CIDR: "10.0.99.0/24",
	}); err != nil {
		t.Fatalf("seed same-vpc transit subnet: %v", err)
	}
	tiSameVPC, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: sameVPCTransitVir})
	if err != nil {
		t.Fatalf("create tiSameVPC: %v", err)
	}

	ti1, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	if err != nil {
		t.Fatalf("create ti1: %v", err)
	}
	ti2, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	if err != nil {
		t.Fatalf("create ti2: %v", err)
	}
	ti3, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	if err != nil {
		t.Fatalf("create ti3: %v", err)
	}
	tiDNAT, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	if err != nil {
		t.Fatalf("create tiDNAT: %v", err)
	}
	tiGW2, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	if err != nil {
		t.Fatalf("create tiGW2: %v", err)
	}

	// Seed SNAT rule on GW1 using sub1 + ti1, SNAT on GW2 using tiGW2, DNAT on GW1 using tiDNAT.
	sn1, err := e.svc.createPrivateSnat(ctx, prTestTenant, createPrivateSnatInput{
		GatewayID:    prGW1ID,
		VirsubnetID:  prSub1ID,
		TransitIPIDs: []string{ti1.ID},
		Description:  "snat-1",
	})
	if err != nil {
		t.Fatalf("seed sn1: %v", err)
	}
	if gotTI, _ := e.svc.getTransitIP(ctx, prTestTenant, ti1.ID); gotTI.GatewayID != prGW1ID {
		t.Fatalf("ti1.GatewayID = %q, want %q", gotTI.GatewayID, prGW1ID)
	}

	if _, err := e.svc.createPrivateSnat(ctx, prTestTenant, createPrivateSnatInput{
		GatewayID:    prGW1ID,
		CIDR:         "10.0.50.0/24",
		TransitIPIDs: []string{ti1.ID, ti2.ID},
	}); err != nil {
		t.Fatalf("seed sn2 sharing ti1: %v", err)
	}

	if _, err := e.svc.createPrivateSnat(ctx, prTestTenant, createPrivateSnatInput{
		GatewayID:    prGW2ID,
		VirsubnetID:  prSubOtherID,
		TransitIPIDs: []string{tiGW2.ID},
	}); err != nil {
		t.Fatalf("seed snGW2: %v", err)
	}

	if _, err := e.svc.createPrivateDnat(ctx, prTestTenant, createPrivateDnatInput{
		GatewayID:        prGW1ID,
		TransitIPID:      tiDNAT.ID,
		PrivateIPAddress: "10.0.1.99",
	}); err != nil {
		t.Fatalf("seed dn1: %v", err)
	}

	// Deleting ti1 while used -> NAT.1409.
	if err := e.svc.deleteTransitIP(ctx, prTestTenant, ti1.ID); prErrCode(err) != "NAT.1409" {
		t.Fatalf("delete in-use transit IP = %q, want NAT.1409", prErrCode(err))
	}

	twentyOne := make([]string, 21)
	for i := range twentyOne {
		twentyOne[i] = fmt.Sprintf("10000000-0000-4000-8000-%012d", i+1)
	}

	errCases := []struct {
		name     string
		in       createPrivateSnatInput
		wantCode string
	}{
		{"missing gateway_id", createPrivateSnatInput{CIDR: "10.0.60.0/24", TransitIPIDs: []string{ti3.ID}}, "NAT.1010"},
		{"invalid description", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24", TransitIPIDs: []string{ti3.ID}, Description: "<bad>"}, "NAT.1010"},
		{"neither cidr nor virsubnet_id", createPrivateSnatInput{GatewayID: prGW1ID, TransitIPIDs: []string{ti3.ID}}, "NAT.1501"},
		{"both cidr and virsubnet_id", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24", VirsubnetID: prSub2ID, TransitIPIDs: []string{ti3.ID}}, "NAT.1501"},
		{"non-canonical cidr", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.1/24", TransitIPIDs: []string{ti3.ID}}, "NAT.1502"},
		{"ipv6 cidr", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "2001:db8::/64", TransitIPIDs: []string{ti3.ID}}, "NAT.1502"},
		{"empty transit_ip_ids", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24"}, "NAT.1010"},
		{"more than 20 transit_ip_ids", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24", TransitIPIDs: twentyOne}, "NAT.1506"},
		{"non-uuid transit_ip_id", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24", TransitIPIDs: []string{"bad"}}, "NAT.1507"},
		{"duplicate transit_ip_id", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24", TransitIPIDs: []string{ti3.ID, ti3.ID}}, "NAT.1010"},
		{"unknown gateway", createPrivateSnatInput{GatewayID: prUnknownID, CIDR: "10.0.60.0/24", TransitIPIDs: []string{ti3.ID}}, "NAT.1002"},
		{"unknown subnet", createPrivateSnatInput{GatewayID: prGW1ID, VirsubnetID: prUnknownID, TransitIPIDs: []string{ti3.ID}}, "NAT.1003"},
		{"subnet in another VPC", createPrivateSnatInput{GatewayID: prGW1ID, VirsubnetID: prSubOtherID, TransitIPIDs: []string{ti3.ID}}, "NAT.1003"},
		{"duplicate subnet on gateway", createPrivateSnatInput{GatewayID: prGW1ID, VirsubnetID: prSub1ID, TransitIPIDs: []string{ti3.ID}}, "NAT.1503"},
		{"duplicate cidr on gateway", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.50.0/24", TransitIPIDs: []string{ti3.ID}}, "NAT.1505"},
		{"unknown transit_ip_id", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24", TransitIPIDs: []string{prUnknownID}}, "NAT.1002"},
		{"transit ip in gateway VPC", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24", TransitIPIDs: []string{tiSameVPC.ID}}, "NAT.1303"},
		{"transit ip linked to another gateway", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24", TransitIPIDs: []string{tiGW2.ID}}, "NAT.1406"},
		{"transit ip used by DNAT", createPrivateSnatInput{GatewayID: prGW1ID, CIDR: "10.0.60.0/24", TransitIPIDs: []string{tiDNAT.ID}}, "NAT.1305"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.svc.createPrivateSnat(ctx, prTestTenant, tc.in); prErrCode(err) != tc.wantCode {
				t.Fatalf("got %q (%v), want %q", prErrCode(err), err, tc.wantCode)
			}
		})
	}

	// Update sn1 from [ti1] to [ti3]: ti1 stays linked (sn2 still uses it), ti3 becomes linked.
	updated, err := e.svc.updatePrivateSnat(ctx, prTestTenant, sn1.Rule.ID, updatePrivateSnatInput{
		TransitIPIDs: rulePtr([]string{ti3.ID}),
		Description:  rulePtr("snat-1-updated"),
	})
	if err != nil {
		t.Fatalf("update sn1: %v", err)
	}
	if updated.Rule.Description != "snat-1-updated" || len(updated.Associations) != 1 || updated.Associations[0].TransitIPID != ti3.ID {
		t.Fatalf("unexpected updated: %+v", updated)
	}
	if gotTI, _ := e.svc.getTransitIP(ctx, prTestTenant, ti1.ID); gotTI.GatewayID != prGW1ID {
		t.Fatalf("ti1 should stay linked while sn2 uses it, got %q", gotTI.GatewayID)
	}
	if gotTI, _ := e.svc.getTransitIP(ctx, prTestTenant, ti3.ID); gotTI.GatewayID != prGW1ID {
		t.Fatalf("ti3.GatewayID = %q, want %q", gotTI.GatewayID, prGW1ID)
	}

	// Delete sn1 -> ti3 is now unused and unlinked!
	if err := e.svc.deletePrivateSnat(ctx, prTestTenant, sn1.Rule.ID); err != nil {
		t.Fatalf("delete sn1: %v", err)
	}
	if gotTI, _ := e.svc.getTransitIP(ctx, prTestTenant, ti3.ID); gotTI.GatewayID != "" {
		t.Fatalf("ti3 should be unlinked, got %q", gotTI.GatewayID)
	}
}

func TestPrivateDnatValidationAndAllConflictRules(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newPREnv(t)

	// Add a transit subnet in VPC1 for NAT.1303.
	sameVPCTransitVir := "77777777-7777-4777-8777-777777777701"
	e.net.mu.Lock()
	e.net.subnets[sameVPCTransitVir] = vpc.Subnet{ID: sameVPCTransitVir, VPCID: prVPC1ID, CIDR: "10.0.98.0/24", GatewayIP: "10.0.98.1"}
	e.net.mu.Unlock()
	_ = e.svc.transitSubnets(prTestTenant).Create(ctx, "ts-same-vpc-dnat", transitSubnet{
		ID: "ts-same-vpc-dnat", Name: "ts-same", SubnetID: sameVPCTransitVir, VPCID: prVPC1ID, CIDR: "10.0.98.0/24",
	})
	tiSameVPC, _ := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: sameVPCTransitVir})
	ti1, _ := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	ti2, _ := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	ti3, _ := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	tiSnat, _ := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	tiGW2, _ := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})

	// Seed SNAT on GW1 (tiSnat) and GW2 (tiGW2).
	if _, err := e.svc.createPrivateSnat(ctx, prTestTenant, createPrivateSnatInput{
		GatewayID: prGW1ID, CIDR: "10.0.80.0/24", TransitIPIDs: []string{tiSnat.ID},
	}); err != nil {
		t.Fatalf("seed snat: %v", err)
	}
	if _, err := e.svc.createPrivateSnat(ctx, prTestTenant, createPrivateSnatInput{
		GatewayID: prGW2ID, CIDR: "10.1.80.0/24", TransitIPIDs: []string{tiGW2.ID},
	}); err != nil {
		t.Fatalf("seed gw2 snat: %v", err)
	}

	// Seed DNAT rules on GW1:
	// 1) ti1:8080/tcp -> port1:80/tcp (COMPUTE)
	// 2) ti2:0/any -> port2:0/any (COMPUTE)
	// 3) ti3:0/any -> 10.0.9.10:0/any (CUSTOMIZE)
	d1, err := e.svc.createPrivateDnat(ctx, prTestTenant, createPrivateDnatInput{
		GatewayID:           prGW1ID,
		TransitIPID:         ti1.ID,
		NetworkInterfaceID:  prPort1ID,
		Protocol:            rulePtr("tcp"),
		InternalServicePort: rulePtr("80"),
		TransitServicePort:  rulePtr("8080"),
	})
	if err != nil {
		t.Fatalf("seed d1: %v", err)
	}
	if d1.Rule.Type != "COMPUTE" || d1.Rule.PrivateIP != "10.0.1.10" {
		t.Fatalf("unexpected d1: %+v", d1.Rule)
	}

	if _, err := e.svc.createPrivateDnat(ctx, prTestTenant, createPrivateDnatInput{
		GatewayID:          prGW1ID,
		TransitIPID:        ti2.ID,
		NetworkInterfaceID: prPort2ID,
	}); err != nil {
		t.Fatalf("seed d2: %v", err)
	}
	if _, err := e.svc.createPrivateDnat(ctx, prTestTenant, createPrivateDnatInput{
		GatewayID:        prGW1ID,
		TransitIPID:      ti3.ID,
		PrivateIPAddress: "10.0.9.10",
	}); err != nil {
		t.Fatalf("seed d3: %v", err)
	}

	tiFree, _ := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})

	cases := []struct {
		name     string
		in       createPrivateDnatInput
		wantCode string
	}{
		// Field validation
		{"missing gateway_id", createPrivateDnatInput{TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.20"}, "NAT.1010"},
		{"missing transit_ip_id", createPrivateDnatInput{GatewayID: prGW1ID, PrivateIPAddress: "10.0.9.20"}, "NAT.1010"},
		{"non-uuid transit_ip_id", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: "bad", PrivateIPAddress: "10.0.9.20"}, "NAT.1507"},
		{"invalid description", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.20", Description: "<bad>"}, "NAT.1010"},
		{"invalid protocol", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.20", Protocol: rulePtr("icmp")}, "NAT.1010"},
		{"invalid port out of range", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.20", Protocol: rulePtr("tcp"), InternalServicePort: rulePtr("65536"), TransitServicePort: rulePtr("80")}, "NAT.1010"},
		{"invalid port leading zero", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.20", Protocol: rulePtr("tcp"), InternalServicePort: rulePtr("080"), TransitServicePort: rulePtr("80")}, "NAT.1010"},
		{"any with non-zero port", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.20", Protocol: rulePtr("any"), InternalServicePort: rulePtr("80"), TransitServicePort: rulePtr("0")}, "NAT.1306"},
		{"tcp with zero port", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.20", Protocol: rulePtr("tcp"), InternalServicePort: rulePtr("0"), TransitServicePort: rulePtr("80")}, "NAT.1306"},
		{"both nic and private ip", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, NetworkInterfaceID: prPort1ID, PrivateIPAddress: "10.0.9.20"}, "NAT.1311"},
		{"neither nic nor private ip", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID}, "NAT.1311"},
		{"invalid private ip", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "999.0.0.1"}, "NAT.1405"},
		{"ipv6 private ip", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "2001:db8::1"}, "NAT.1405"},
		{"unknown gateway", createPrivateDnatInput{GatewayID: prUnknownID, TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.20"}, "NAT.1002"},
		{"unknown transit ip", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: prUnknownID, PrivateIPAddress: "10.0.9.20"}, "NAT.1002"},
		{"transit ip in gateway VPC", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiSameVPC.ID, PrivateIPAddress: "10.0.9.20"}, "NAT.1303"},
		{"transit ip linked elsewhere", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiGW2.ID, PrivateIPAddress: "10.0.9.20"}, "NAT.1406"},
		{"transit ip used by snat", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiSnat.ID, PrivateIPAddress: "10.0.9.20"}, "NAT.1308"},
		{"unknown port", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, NetworkInterfaceID: prUnknownID}, "NAT.1009"},
		{"port in another VPC", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, NetworkInterfaceID: prPortOtherID}, "NAT.1304"},

		// §3.9 Conflicts
		{"NAT.1310 same transit IP + port + proto (tcp)", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: ti1.ID, PrivateIPAddress: "10.0.9.20", Protocol: rulePtr("tcp"), InternalServicePort: rulePtr("81"), TransitServicePort: rulePtr("8080")}, "NAT.1310"},
		{"NAT.1310 same transit IP (any + any)", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: ti2.ID, PrivateIPAddress: "10.0.9.20"}, "NAT.1310"},
		{"NAT.1410 any on transit IP with tcp rule", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: ti1.ID, PrivateIPAddress: "10.0.9.20"}, "NAT.1410"},
		{"NAT.1410 tcp on transit IP with any rule", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: ti2.ID, PrivateIPAddress: "10.0.9.20", Protocol: rulePtr("tcp"), InternalServicePort: rulePtr("81"), TransitServicePort: rulePtr("8081")}, "NAT.1410"},
		{"NAT.1307 same port + internal port + proto", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, NetworkInterfaceID: prPort1ID, Protocol: rulePtr("tcp"), InternalServicePort: rulePtr("80"), TransitServicePort: rulePtr("8081")}, "NAT.1307"},
		{"NAT.1307 same private_ip (any + any)", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.10"}, "NAT.1307"},
		{"NAT.1309 any on port with tcp rule", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, NetworkInterfaceID: prPort1ID}, "NAT.1309"},
		{"NAT.1309 tcp on port with any rule", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, NetworkInterfaceID: prPort2ID, Protocol: rulePtr("tcp"), InternalServicePort: rulePtr("81"), TransitServicePort: rulePtr("8081")}, "NAT.1309"},
		{"NAT.1309 tcp on private_ip with any rule", createPrivateDnatInput{GatewayID: prGW1ID, TransitIPID: tiFree.ID, PrivateIPAddress: "10.0.9.10", Protocol: rulePtr("tcp"), InternalServicePort: rulePtr("81"), TransitServicePort: rulePtr("8081")}, "NAT.1309"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.svc.createPrivateDnat(ctx, prTestTenant, tc.in); prErrCode(err) != tc.wantCode {
				t.Fatalf("createPrivateDnat(%s) = %q (%v), want %q", tc.name, prErrCode(err), err, tc.wantCode)
			}
		})
	}

	// Same transit IP + port with UDP (different protocol) succeeds!
	dUDP, err := e.svc.createPrivateDnat(ctx, prTestTenant, createPrivateDnatInput{
		GatewayID:           prGW1ID,
		TransitIPID:         ti1.ID,
		NetworkInterfaceID:  prPort1ID,
		Protocol:            rulePtr("UDP"),
		InternalServicePort: rulePtr("80"),
		TransitServicePort:  rulePtr("8080"),
	})
	if err != nil {
		t.Fatalf("create UDP sharing ti1+port1: %v", err)
	}

	// Update dUDP: switch to tiFree + CUSTOMIZE IP, then delete d1 and dUDP -> ti1 unlinks only after both gone.
	upd, err := e.svc.updatePrivateDnat(ctx, prTestTenant, dUDP.Rule.ID, updatePrivateDnatInput{
		TransitIPID:      rulePtr(tiFree.ID),
		PrivateIPAddress: rulePtr("10.0.9.50"),
		Description:      rulePtr("switched-to-custom"),
	})
	if err != nil {
		t.Fatalf("update dUDP: %v", err)
	}
	if upd.Rule.Type != "CUSTOMIZE" || upd.Rule.NetworkInterfaceID != "" || upd.Rule.PrivateIP != "10.0.9.50" {
		t.Fatalf("unexpected upd: %+v", upd.Rule)
	}
	if gotTI, _ := e.svc.getTransitIP(ctx, prTestTenant, ti1.ID); gotTI.GatewayID != prGW1ID {
		t.Fatalf("ti1 should still be linked (d1 remains), got %q", gotTI.GatewayID)
	}
	if gotTI, _ := e.svc.getTransitIP(ctx, prTestTenant, tiFree.ID); gotTI.GatewayID != prGW1ID {
		t.Fatalf("tiFree should be linked, got %q", gotTI.GatewayID)
	}

	if err := e.svc.deletePrivateDnat(ctx, prTestTenant, d1.Rule.ID); err != nil {
		t.Fatalf("delete d1: %v", err)
	}
	if gotTI, _ := e.svc.getTransitIP(ctx, prTestTenant, ti1.ID); gotTI.GatewayID != "" {
		t.Fatalf("ti1 should be unlinked after d1 deleted, got %q", gotTI.GatewayID)
	}
}

func TestPrivateRulesLimitAndRollback(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newPREnv(t)

	ti1, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	if err != nil {
		t.Fatalf("create ti1: %v", err)
	}
	ti2, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	if err != nil {
		t.Fatalf("create ti2: %v", err)
	}
	// Seed 19 private DNAT rules (on ti1) + 1 private SNAT (on ti2) = 20 (Small spec rule_max).
	for i := range 19 {
		portStr := fmt.Sprintf("%d", 1000+i)
		id := fmt.Sprintf("d1000000-0000-4000-8000-%012d", i)
		if err := e.svc.privateDnats(prTestTenant).Create(ctx, id, privateDnat{
			ID: id, GatewayID: prGW1ID, TransitIPID: ti1.ID, PrivateIP: "10.0.5.5",
			Type: "CUSTOMIZE", Protocol: "tcp", InternalPort: portStr, TransitPort: portStr,
		}); err != nil {
			t.Fatalf("seed dnat %d: %v", i, err)
		}
	}
	if err := e.svc.privateSnats(prTestTenant).Create(ctx, "s1000000-0000-4000-8000-000000000001", privateSnat{
		ID: "s1000000-0000-4000-8000-000000000001", GatewayID: prGW1ID, CIDR: "10.0.50.0/24", TransitIPIDs: []string{ti2.ID},
	}); err != nil {
		t.Fatalf("seed snat: %v", err)
	}

	if _, err := e.svc.createPrivateDnat(ctx, prTestTenant, createPrivateDnatInput{
		GatewayID: prGW1ID, TransitIPID: ti1.ID, PrivateIPAddress: "10.0.5.5",
		Protocol: rulePtr("tcp"), InternalServicePort: rulePtr("2000"), TransitServicePort: rulePtr("2000"),
	}); prErrCode(err) != "NAT.1207" {
		t.Fatalf("dnat over rule_max = %q, want NAT.1207", prErrCode(err))
	}

	if _, err := e.svc.createPrivateSnat(ctx, prTestTenant, createPrivateSnatInput{
		GatewayID: prGW1ID, CIDR: "10.0.60.0/24", TransitIPIDs: []string{ti2.ID},
	}); prErrCode(err) != "NAT.1207" {
		t.Fatalf("snat over rule_max = %q, want NAT.1207", prErrCode(err))
	}
}

func TestPrivateRulesConcurrentTransitIPLinking(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	e := newPREnv(t)

	tiShared, err := e.svc.createTransitIP(ctx, prTestTenant, createTransitIPInput{VirsubnetID: prTransitVirID})
	if err != nil {
		t.Fatalf("create shared transit IP: %v", err)
	}

	const workers = 8
	var gw1Wins, gw2Wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			gwID := prGW1ID
			if idx%2 == 1 {
				gwID = prGW2ID
			}
			cidr := fmt.Sprintf("10.%d.%d.0/24", idx%2, idx+10)
			_, err := e.svc.createPrivateSnat(ctx, prTestTenant, createPrivateSnatInput{
				GatewayID:    gwID,
				CIDR:         cidr,
				TransitIPIDs: []string{tiShared.ID},
			})
			if err == nil {
				if gwID == prGW1ID {
					gw1Wins.Add(1)
				} else {
					gw2Wins.Add(1)
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if (gw1Wins.Load() > 0) == (gw2Wins.Load() > 0) {
		t.Fatalf("expected exactly one gateway to win shared transit IP: gw1=%d gw2=%d", gw1Wins.Load(), gw2Wins.Load())
	}
	gotTI, err := e.svc.getTransitIP(ctx, prTestTenant, tiShared.ID)
	if err != nil {
		t.Fatalf("getTransitIP: %v", err)
	}
	if gw1Wins.Load() > 0 && gotTI.GatewayID != prGW1ID {
		t.Fatalf("tiShared.GatewayID = %q, want %q", gotTI.GatewayID, prGW1ID)
	}
	if gw2Wins.Load() > 0 && gotTI.GatewayID != prGW2ID {
		t.Fatalf("tiShared.GatewayID = %q, want %q", gotTI.GatewayID, prGW2ID)
	}
}
