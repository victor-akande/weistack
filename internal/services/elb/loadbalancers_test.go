package elb

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	lbTestProject  = "0123456789abcdef0123456789abcdef"
	lbTestProjectB = "fedcba9876543210fedcba9876543210"
	lbTestRegion   = "ap-southeast-1"
	lbTestHost     = "elb." + lbTestRegion + ".myhuaweicloud.com"
	lbUnknownUUID  = "00000000-0000-4000-8000-000000000000"
	lbCustomEP     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

var (
	lbTestTenant  = Tenant{Region: lbTestRegion, ProjectID: lbTestProject}
	lbTestTenantB = Tenant{Region: lbTestRegion, ProjectID: lbTestProjectB}
	lbTestEpoch   = time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
)

type lbStubServers struct{}

func (lbStubServers) ServerAt(_ context.Context, _ vpc.Tenant, _, _, _ string) (string, bool, error) {
	return "", false, nil
}

type lbEnv struct {
	svc                 *Service
	vpcSvc              *vpc.Service
	eipSvc              *eip.Service
	store               store.Store
	engine              *lifecycle.Engine
	clock               *lifecycle.FakeClock
	handler             http.Handler
	vpcID               string
	subnetID            string
	neutronSubnetID     string
	subnet2ID           string
	neutronSubnet2ID    string
	vpc2ID              string
	vpc2SubnetID        string
	vpc2NeutronSubnetID string
	l4SmallID           string
	l4MediumID          string
	l7SmallID           string
	l7MediumID          string
}

func newLBEnv(t *testing.T) *lbEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(lbTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: 0, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(19)
	vlt, err := vault.New(make([]byte, vault.KeyLen))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	eipSvc, err := eip.New(eip.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Ports: vpcSvc, Now: clock.Now})
	if err != nil {
		t.Fatalf("eip.New: %v", err)
	}
	vpcSvc.Extend(eipSvc)

	svc, err := New(Deps{
		Store:   st,
		IDs:     gen,
		Logger:  log,
		Vault:   vlt,
		VPC:     vpcSvc,
		EIPs:    eipSvc,
		Servers: lbStubServers{},
		Now:     clock.Now,
	})
	if err != nil {
		t.Fatalf("elb.New: %v", err)
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: lbTestProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{vpcSvc, svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	e := &lbEnv{
		svc:     svc,
		vpcSvc:  vpcSvc,
		eipSvc:  eipSvc,
		store:   st,
		engine:  engine,
		clock:   clock,
		handler: srv.Handler(),
	}

	for _, f := range seededFlavors(lbTestRegion, lbTestProject) {
		switch f.Name {
		case "L4_flavor.elb.s2.small":
			e.l4SmallID = f.ID
		case "L4_flavor.elb.s1.medium":
			e.l4MediumID = f.ID
		case "L7_flavor.elb.s1.small":
			e.l7SmallID = f.ID
		case "L7_flavor.elb.s1.medium":
			e.l7MediumID = f.ID
		}
	}

	// Seed VPC 1 with two subnets, and VPC 2 with one subnet.
	v1, sn1 := e.seedVPCSubnet(t, lbTestTenant, "vpc-1", "192.168.0.0/16", "sub-1", "192.168.0.0/24", "192.168.0.1")
	sn1b := e.seedSubnet(t, lbTestTenant, v1.ID, "sub-1b", "192.168.1.0/24", "192.168.1.1")
	v2, sn2 := e.seedVPCSubnet(t, lbTestTenant, "vpc-2", "10.0.0.0/16", "sub-2", "10.0.0.0/24", "10.0.0.1")

	e.vpcID = v1.ID
	e.subnetID = sn1.ID
	e.neutronSubnetID = sn1.NeutronSubnetID
	e.subnet2ID = sn1b.ID
	e.neutronSubnet2ID = sn1b.NeutronSubnetID
	e.vpc2ID = v2.ID
	e.vpc2SubnetID = sn2.ID
	e.vpc2NeutronSubnetID = sn2.NeutronSubnetID

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := e.engine.WaitIdle(waitCtx); err != nil {
		t.Fatalf("WaitIdle seed: %v", err)
	}
	return e
}

func (e *lbEnv) seedVPCSubnet(t *testing.T, tenant Tenant, vpcName, vpcCIDR, subName, subCIDR, gwIP string) (vpc.VPC, vpc.Subnet) {
	t.Helper()
	ctx := t.Context()
	v, err := e.vpcSvc.CreateVPC(ctx, tenant, vpc.CreateVPCOption{
		Name: lbPtr(vpcName),
		CIDR: lbPtr(vpcCIDR),
	})
	if err != nil {
		t.Fatalf("CreateVPC %s: %v", vpcName, err)
	}
	sn := e.seedSubnet(t, tenant, v.ID, subName, subCIDR, gwIP)
	return v, sn
}

func (e *lbEnv) seedSubnet(t *testing.T, tenant Tenant, vpcID, subName, subCIDR, gwIP string) vpc.Subnet {
	t.Helper()
	sn, err := e.vpcSvc.CreateSubnet(t.Context(), tenant, vpc.CreateSubnetOption{
		Name:      subName,
		CIDR:      subCIDR,
		GatewayIP: gwIP,
		VPCID:     vpcID,
	})
	if err != nil {
		t.Fatalf("CreateSubnet %s: %v", subName, err)
	}
	return sn
}

func (e *lbEnv) createFreeEIP(t *testing.T, bwName string) (string, string) {
	t.Helper()
	body := `{"publicip":{"type":"5_bgp"},"bandwidth":{"name":"` + bwName + `","size":5,"share_type":"PER"}}`
	r := httptest.NewRequest(http.MethodPost, "/v1/"+lbTestProject+"/publicips", strings.NewReader(body))
	r.Host = "vpc." + lbTestRegion + ".myhuaweicloud.com"
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("createFreeEIP: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		PublicIP struct {
			ID              string `json:"id"`
			PublicIPAddress string `json:"public_ip_address"`
		} `json:"publicip"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode createFreeEIP: %v", err)
	}
	if err := e.engine.WaitIdle(t.Context()); err != nil {
		t.Fatalf("WaitIdle createFreeEIP: %v", err)
	}
	return resp.PublicIP.ID, resp.PublicIP.PublicIPAddress
}

func (e *lbEnv) createSharedBW(t *testing.T, name string) string {
	t.Helper()
	body := `{"bandwidth":{"name":"` + name + `","size":20}}`
	r := httptest.NewRequest(http.MethodPost, "/v2.0/"+lbTestProject+"/bandwidths", strings.NewReader(body))
	r.Host = "vpc." + lbTestRegion + ".myhuaweicloud.com"
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("createSharedBW: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Bandwidth struct {
			ID string `json:"id"`
		} `json:"bandwidth"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode createSharedBW: %v", err)
	}
	return resp.Bandwidth.ID
}

func (e *lbEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callAs(t, lbTestProject, method, path, body)
}

func (e *lbEnv) callAs(t *testing.T, project, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v3/"+project+"/elb"+path, rd)
	r.Host = lbTestHost
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

func (e *lbEnv) expect(t *testing.T, subdir, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", subdir, goldenName+".json"), status, out)
	return out
}

func lbPtr[T any](v T) *T { return &v }

func lbDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func lbCodeOf(err error) string {
	if err == nil {
		return ""
	}
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return err.Error()
}

func TestLoadBalancerCreateUpdateDeleteLifecycle(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)
	ctx := t.Context()

	// 1. Create with VIP + explicit existing EIP.
	eipID, eipAddr := e.createFreeEIP(t, "bw-lb-existing")
	lb, err := e.svc.createLoadBalancer(ctx, lbTestTenant, createLoadBalancerInput{
		Name:                 "lb-primary",
		Description:          "main dedicated lb",
		VIPSubnetCIDRID:      e.neutronSubnetID,
		VIPAddress:           "192.168.0.25",
		L4FlavorID:           e.l4SmallID,
		L7FlavorID:           e.l7SmallID,
		AvailabilityZoneList: []string{"ap-southeast-1a"},
		PublicIPIDs:          []string{eipID},
		Tags:                 []tag{{Key: "env", Value: "prod"}},
	})
	if err != nil {
		t.Fatalf("createLoadBalancer: %v", err)
	}
	if lb.VPCID != e.vpcID || lb.VIPAddress != "192.168.0.25" || lb.VIPPortID == "" ||
		len(lb.ELBVirsubnetIDs) != 1 || lb.ELBVirsubnetIDs[0] != e.subnetID ||
		len(lb.EIPIDs) != 1 || lb.EIPIDs[0] != eipID {
		t.Fatalf("created LB = %+v", lb)
	}

	if _, err := e.svc.getLoadBalancer(ctx, lbTestTenantB, lb.ID); lbCodeOf(err) != "ELB.8904" {
		t.Fatalf("getLoadBalancer(other project) = %v, want ELB.8904", err)
	}

	// Verify EIP is bound and resolves on wire view.
	wire, err := e.svc.toLoadBalancerWire(ctx, lbTestTenant, lb)
	if err != nil {
		t.Fatalf("toLoadBalancerWire: %v", err)
	}
	if len(wire.EIPs) != 1 || wire.EIPs[0].EIPID != eipID || wire.EIPs[0].EIPAddress != eipAddr ||
		len(wire.PublicIPs) != 1 || wire.PublicIPs[0].PublicIPID != eipID || wire.PublicIPs[0].PublicIPAddress != eipAddr {
		t.Fatalf("wire EIPs=%+v PublicIPs=%+v", wire.EIPs, wire.PublicIPs)
	}

	// 2. Removing VIP while EIP is bound refuses with ELB.8907.
	if _, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{
		VIPSubnetCIDRIDPresent: true,
		VIPSubnetCIDRID:        nil,
	}); lbCodeOf(err) != "ELB.8907" {
		t.Fatalf("remove VIP with EIP bound = %v, want ELB.8907", err)
	}

	// 3. Update flavors (same type), move VIP to another subnet, enable ip_target_enable.
	e.clock.Advance(30 * time.Second)
	updated, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{
		Name:            lbPtr("lb-renamed"),
		Description:     lbPtr("updated"),
		L4FlavorID:      lbPtr(e.l4MediumID),
		L7FlavorID:      lbPtr(e.l7MediumID),
		VIPSubnetCIDRID: lbPtr(e.neutronSubnet2ID),
		VIPAddress:      lbPtr("192.168.1.30"),
		IPTargetEnable:  lbPtr(true),
		ELBVirsubnetIDs: &[]string{e.subnetID, e.subnet2ID},
	})
	if err != nil {
		t.Fatalf("updateLoadBalancer: %v", err)
	}
	if updated.Name != "lb-renamed" || updated.L4FlavorID != e.l4MediumID || updated.L7FlavorID != e.l7MediumID ||
		updated.VIPSubnetCIDRID != e.neutronSubnet2ID || updated.VIPAddress != "192.168.1.30" || !updated.IPTargetEnable {
		t.Fatalf("updated LB = %+v", updated)
	}

	// Old VIP address 192.168.0.25 was released and can be reallocated.
	if got, err := e.vpcSvc.AllocateIP(ctx, lbTestTenant, e.subnetID, "test:recheck", "192.168.0.25"); err != nil || got != "192.168.0.25" {
		t.Fatalf("old VIP not released: got=%q err=%v", got, err)
	}
	_ = e.vpcSvc.ReleaseIP(ctx, lbTestTenant, e.subnetID, "192.168.0.25")

	// 4. Flavor cross-type change returns ELB.8959.
	if _, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{
		L4FlavorID: lbPtr(e.l7SmallID),
	}); lbCodeOf(err) != "ELB.8959" {
		t.Fatalf("L4->L7 update = %v, want ELB.8959", err)
	}
	if _, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{
		L7FlavorID: lbPtr(e.l4SmallID),
	}); lbCodeOf(err) != "ELB.8959" {
		t.Fatalf("L7->L4 update = %v, want ELB.8959", err)
	}

	// 5. Turning ip_target_enable off with an IP member in a pool refuses with ELB.8907.
	poolID := "11111111-1111-4111-8111-111111111111"
	memID := "22222222-2222-4222-8222-222222222222"
	if err := e.svc.pools(lbTestTenant).Create(ctx, poolID, pool{ID: poolID, LoadBalancerID: lb.ID}); err != nil {
		t.Fatalf("seed pool: %v", err)
	}
	if err := e.svc.members(lbTestTenant).Create(ctx, memID, member{ID: memID, PoolID: poolID, MemberType: "ip", Address: "172.16.0.5"}); err != nil {
		t.Fatalf("seed ip member: %v", err)
	}
	if _, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{
		IPTargetEnable: lbPtr(false),
	}); lbCodeOf(err) != "ELB.8907" {
		t.Fatalf("disable ip_target_enable with IP member = %v, want ELB.8907", err)
	}
	_ = e.svc.members(lbTestTenant).Delete(ctx, memID)
	if _, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{
		IPTargetEnable: lbPtr(false),
	}); err != nil {
		t.Fatalf("disable ip_target_enable after member removed: %v", err)
	}

	// 6. Delete refuses while pool exists, and while deletion_protection_enable is true.
	if err := e.svc.deleteLoadBalancer(ctx, lbTestTenant, lb.ID); lbCodeOf(err) != "ELB.8907" {
		t.Fatalf("delete with pool = %v, want ELB.8907", err)
	}
	_ = e.svc.pools(lbTestTenant).Delete(ctx, poolID)

	if _, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{
		DeletionProtectionEnable: lbPtr(true),
	}); err != nil {
		t.Fatalf("enable deletion protection: %v", err)
	}
	if err := e.svc.deleteLoadBalancer(ctx, lbTestTenant, lb.ID); lbCodeOf(err) != "ELB.8907" {
		t.Fatalf("delete with protection = %v, want ELB.8907", err)
	}
	if _, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{
		DeletionProtectionEnable: lbPtr(false),
	}); err != nil {
		t.Fatalf("disable deletion protection: %v", err)
	}

	// 7. Delete succeeds: EIP is unbound (stays in EIP service), VIP is released.
	if err := e.svc.deleteLoadBalancer(ctx, lbTestTenant, lb.ID); err != nil {
		t.Fatalf("deleteLoadBalancer: %v", err)
	}
	if _, err := e.svc.getLoadBalancer(ctx, lbTestTenant, lb.ID); lbCodeOf(err) != "ELB.8904" {
		t.Fatalf("getLoadBalancer after delete = %v, want ELB.8904", err)
	}
	if addr, ok, err := e.eipSvc.PublicIPAddress(ctx, lbTestTenant, eipID); err != nil || !ok || addr != eipAddr {
		t.Fatalf("EIP should remain after LB delete: addr=%q ok=%v err=%v", addr, ok, err)
	}
	// EIP is unbound, so another LB can bind it and old VIP 192.168.1.30 can be reallocated.
	if _, err := e.vpcSvc.AllocateIP(ctx, lbTestTenant, e.subnet2ID, "test:recheck2", "192.168.1.30"); err != nil {
		t.Fatalf("VIP not released after LB delete: %v", err)
	}
}

func TestLoadBalancerCreateWithNewEIPAndNoVIP(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)
	ctx := t.Context()

	// Create LB with new PER EIP.
	lbPer, err := e.svc.createLoadBalancer(ctx, lbTestTenant, createLoadBalancerInput{
		Name:                 "lb-new-eip-per",
		VIPSubnetCIDRID:      e.neutronSubnetID,
		L7FlavorID:           e.l7SmallID,
		AvailabilityZoneList: []string{"ap-southeast-1a"},
		PublicIP: &createLoadBalancerPublicIPInput{
			NetworkType: "5_bgp",
			Description: lbPtr("auto created"),
			Bandwidth: &createLoadBalancerBandwidthInput{
				Name:       lbPtr("bw-per-elb"),
				Size:       lbPtr(5),
				ShareType:  lbPtr("PER"),
				ChargeMode: lbPtr("bandwidth"),
			},
		},
	})
	if err != nil {
		t.Fatalf("createLoadBalancer(new PER EIP): %v", err)
	}
	if len(lbPer.EIPIDs) != 1 {
		t.Fatalf("expected 1 EIP created, got %v", lbPer.EIPIDs)
	}

	// Create LB with new EIP on WHOLE shared bandwidth.
	sharedBWID := e.createSharedBW(t, "shared-bw-elb")
	lbWhole, err := e.svc.createLoadBalancer(ctx, lbTestTenant, createLoadBalancerInput{
		Name:                 "lb-new-eip-whole",
		VIPSubnetCIDRID:      e.neutronSubnetID,
		L4FlavorID:           e.l4SmallID,
		AvailabilityZoneList: []string{"ap-southeast-1b"},
		PublicIP: &createLoadBalancerPublicIPInput{
			NetworkType: "5_bgp",
			Bandwidth: &createLoadBalancerBandwidthInput{
				ID: lbPtr(sharedBWID),
			},
		},
	})
	if err != nil {
		t.Fatalf("createLoadBalancer(new WHOLE EIP): %v", err)
	}
	if len(lbWhole.EIPIDs) != 1 {
		t.Fatalf("expected 1 EIP created on WHOLE bw, got %v", lbWhole.EIPIDs)
	}

	// Create LB with only elb_virsubnet_ids (no private VIP), then add VIP via update, then remove VIP via null.
	lbNoVIP, err := e.svc.createLoadBalancer(ctx, lbTestTenant, createLoadBalancerInput{
		Name:                 "lb-no-vip",
		ELBVirsubnetIDs:      []string{e.subnetID},
		L4FlavorID:           e.l4SmallID,
		AvailabilityZoneList: []string{"ap-southeast-1a"},
	})
	if err != nil {
		t.Fatalf("createLoadBalancer(no VIP): %v", err)
	}
	if lbNoVIP.VIPAddress != "" || lbNoVIP.VIPPortID != "" || lbNoVIP.VPCID != e.vpcID {
		t.Fatalf("no-VIP LB = %+v", lbNoVIP)
	}
	withVIP, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lbNoVIP.ID, updateLoadBalancerInput{
		VIPSubnetCIDRIDPresent: true,
		VIPSubnetCIDRID:        lbPtr(e.neutronSubnetID),
	})
	if err != nil {
		t.Fatalf("add VIP via update: %v", err)
	}
	if withVIP.VIPAddress == "" || withVIP.VIPPortID == "" {
		t.Fatalf("expected VIP after update, got %+v", withVIP)
	}
	removedVIP, err := e.svc.updateLoadBalancer(ctx, lbTestTenant, lbNoVIP.ID, updateLoadBalancerInput{
		VIPSubnetCIDRIDPresent: true,
		VIPSubnetCIDRID:        nil,
	})
	if err != nil {
		t.Fatalf("remove VIP via null: %v", err)
	}
	if removedVIP.VIPAddress != "" || removedVIP.VIPPortID != "" || removedVIP.VIPSubnetCIDRID != "" {
		t.Fatalf("expected VIP removed, got %+v", removedVIP)
	}
}

func TestLoadBalancerCreateValidationAndRollback(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)
	ctx := t.Context()

	// Seed an EIP bound to a NAT gateway to verify conflict & VIP rollback.
	natEIPID, _ := e.createFreeEIP(t, "bw-nat-held")
	if _, err := e.eipSvc.HoldForNAT(ctx, lbTestTenant, natEIPID, "99999999-1111-4111-8111-111111111111"); err != nil {
		t.Fatalf("HoldForNAT: %v", err)
	}

	// Fill a /29 subnet to verify ELB.8934.
	_, tinySub := e.seedVPCSubnet(t, lbTestTenant, "vpc-tiny", "172.16.0.0/16", "sub-tiny", "172.16.1.0/29", "172.16.1.1")
	for i := range 3 {
		if _, err := e.svc.createLoadBalancer(ctx, lbTestTenant, createLoadBalancerInput{
			Name:                 "tiny",
			VIPSubnetCIDRID:      tinySub.NeutronSubnetID,
			L4FlavorID:           e.l4SmallID,
			AvailabilityZoneList: []string{"ap-southeast-1a"},
		}); err != nil {
			t.Fatalf("fill tiny %d: %v", i, err)
		}
	}

	cases := []struct {
		name     string
		in       createLoadBalancerInput
		wantCode string
	}{
		{
			name: "missing AZs",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID: e.neutronSubnetID,
				L4FlavorID:      e.l4SmallID,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "unknown AZ",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1z"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "duplicate AZ",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a", "ap-southeast-1a"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "no flavor",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "unknown L4 flavor",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L4FlavorID:           lbUnknownUUID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8904",
		},
		{
			name: "L7 flavor in l4_flavor_id",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L4FlavorID:           e.l7SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "L4 flavor in l7_flavor_id",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L7FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "no subnet",
			in: createLoadBalancerInput{
				VPCID:                e.vpcID,
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "unknown vpc_id",
			in: createLoadBalancerInput{
				VPCID:                lbUnknownUUID,
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8904",
		},
		{
			name: "unknown vip_subnet_cidr_id",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      lbUnknownUUID,
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8904",
		},
		{
			name: "vip subnet not in vpc",
			in: createLoadBalancerInput{
				VPCID:                e.vpc2ID,
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "virsubnet in another vpc",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				ELBVirsubnetIDs:      []string{e.vpc2SubnetID},
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "vip_address out of cidr",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				VIPAddress:           "10.99.0.5",
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "subnet full",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      tinySub.NeutronSubnetID,
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8934",
		},
		{
			name: "guaranteed false",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L4FlavorID:           e.l4SmallID,
				Guaranteed:           lbPtr(false),
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "publicip and publicip_ids exclusive",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
				PublicIPIDs:          []string{natEIPID},
				PublicIP: &createLoadBalancerPublicIPInput{
					NetworkType: "5_bgp",
					Bandwidth:   &createLoadBalancerBandwidthInput{ID: lbPtr(lbUnknownUUID)},
				},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "publicip_ids without VIP",
			in: createLoadBalancerInput{
				ELBVirsubnetIDs:      []string{e.subnetID},
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
				PublicIPIDs:          []string{natEIPID},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "unknown publicip_ids rolls back VIP",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				VIPAddress:           "192.168.0.77",
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
				PublicIPIDs:          []string{lbUnknownUUID},
			},
			wantCode: "ELB.8904",
		},
		{
			name: "NAT-held publicip_ids returns ELB.8907 and rolls back VIP",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				VIPAddress:           "192.168.0.78",
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
				PublicIPIDs:          []string{natEIPID},
			},
			wantCode: "ELB.8907",
		},
		{
			name: "out-of-scope feature",
			in: createLoadBalancerInput{
				VIPSubnetCIDRID:      e.neutronSubnetID,
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
				OutOfScopeFeature:    "prepaid_options",
			},
			wantCode: "WeiStack.0501",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.svc.createLoadBalancer(ctx, lbTestTenant, tc.in)
			if got := lbCodeOf(err); got != tc.wantCode {
				t.Fatalf("createLoadBalancer(%s) = %v (code %q), want %q", tc.name, err, got, tc.wantCode)
			}
		})
	}

	// Verify both rolled-back VIP addresses are free.
	for _, ip := range []string{"192.168.0.77", "192.168.0.78"} {
		if _, err := e.vpcSvc.AllocateIP(ctx, lbTestTenant, e.subnetID, "verify:free", ip); err != nil {
			t.Fatalf("VIP %s was not rolled back: %v", ip, err)
		}
		_ = e.vpcSvc.ReleaseIP(ctx, lbTestTenant, e.subnetID, ip)
	}
}

func TestLoadBalancerForceDeleteAndStatusTree(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)
	ctx := t.Context()

	eipID, _ := e.createFreeEIP(t, "bw-force")
	lb, err := e.svc.createLoadBalancer(ctx, lbTestTenant, createLoadBalancerInput{
		Name:                 "lb-tree",
		VIPSubnetCIDRID:      e.neutronSubnetID,
		VIPAddress:           "192.168.0.88",
		L4FlavorID:           e.l4SmallID,
		L7FlavorID:           e.l7SmallID,
		AvailabilityZoneList: []string{"ap-southeast-1a"},
		PublicIPIDs:          []string{eipID},
	})
	if err != nil {
		t.Fatalf("createLoadBalancer: %v", err)
	}

	// Seed listener, pool, health monitor, member, L7 policy, and L7 rule.
	pID := "10000000-0000-4000-8000-000000000001"
	lID := "20000000-0000-4000-8000-000000000001"
	hmID := "30000000-0000-4000-8000-000000000001"
	mID := "40000000-0000-4000-8000-000000000001"
	polID := "50000000-0000-4000-8000-000000000001"
	ruleID := "60000000-0000-4000-8000-000000000001"

	_ = e.svc.pools(lbTestTenant).Create(ctx, pID, pool{ID: pID, Name: "pool-1", LoadBalancerID: lb.ID, HealthMonitorID: hmID, AdminStateUp: true})
	_ = e.svc.listeners(lbTestTenant).Create(ctx, lID, listener{ID: lID, Name: "lsn-1", LoadBalancerID: lb.ID, DefaultPoolID: pID, AdminStateUp: true})
	_ = e.svc.healthMonitors(lbTestTenant).Create(ctx, hmID, healthMonitor{ID: hmID, PoolID: pID, Name: "hm-1", Type: "TCP", AdminStateUp: true})
	_ = e.svc.members(lbTestTenant).Create(ctx, mID, member{ID: mID, PoolID: pID, Address: "192.168.0.99", ProtocolPort: 8080, AdminStateUp: true})
	_ = e.svc.l7Policies(lbTestTenant).Create(ctx, polID, l7Policy{ID: polID, ListenerID: lID, Name: "pol-1", Action: "REDIRECT_TO_POOL", RedirectPoolID: pID})
	_ = e.svc.l7Rules(lbTestTenant).Create(ctx, ruleID, l7Rule{ID: ruleID, PolicyID: polID, Type: "PATH", CompareType: "STARTS_WITH", Value: "/api"})

	// Check status tree.
	st, err := e.svc.loadBalancerStatus(ctx, lbTestTenant, lb.ID)
	if err != nil {
		t.Fatalf("loadBalancerStatus: %v", err)
	}
	if st.Loadbalancer.ID != lb.ID || st.Loadbalancer.ProvisioningStatus != StatusActive || st.Loadbalancer.OperatingStatus != StatusOnline {
		t.Fatalf("status LB = %+v", st.Loadbalancer)
	}
	if len(st.Loadbalancer.Listeners) != 1 || len(st.Loadbalancer.Pools) != 1 {
		t.Fatalf("status tree counts: listeners=%d pools=%d", len(st.Loadbalancer.Listeners), len(st.Loadbalancer.Pools))
	}
	lsn := st.Loadbalancer.Listeners[0]
	if len(lsn.Pools) != 1 || len(lsn.L7Policies) != 1 || len(lsn.L7Policies[0].Rules) != 1 {
		t.Fatalf("status listener = %+v", lsn)
	}
	pl := lsn.Pools[0]
	if pl.Healthmonitor == nil || pl.Healthmonitor.ID != hmID || len(pl.Members) != 1 || pl.Members[0].ProtocolPort != 8080 {
		t.Fatalf("status pool = %+v", pl)
	}

	// Protection blocks force delete too.
	_, _ = e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{DeletionProtectionEnable: lbPtr(true)})
	if err := e.svc.deleteLoadBalancerForce(ctx, lbTestTenant, lb.ID); lbCodeOf(err) != "ELB.8907" {
		t.Fatalf("force delete with protection = %v, want ELB.8907", err)
	}
	_, _ = e.svc.updateLoadBalancer(ctx, lbTestTenant, lb.ID, updateLoadBalancerInput{DeletionProtectionEnable: lbPtr(false)})

	// Force delete removes LB and all children, unbinds EIP, releases VIP.
	if err := e.svc.deleteLoadBalancerForce(ctx, lbTestTenant, lb.ID); err != nil {
		t.Fatalf("deleteLoadBalancerForce: %v", err)
	}
	if lsns, _ := e.svc.listeners(lbTestTenant).List(ctx, nil); len(lsns) != 0 {
		t.Fatalf("listeners remain: %+v", lsns)
	}
	if pls, _ := e.svc.pools(lbTestTenant).List(ctx, nil); len(pls) != 0 {
		t.Fatalf("pools remain: %+v", pls)
	}
	if mems, _ := e.svc.members(lbTestTenant).List(ctx, nil); len(mems) != 0 {
		t.Fatalf("members remain: %+v", mems)
	}
	if hms, _ := e.svc.healthMonitors(lbTestTenant).List(ctx, nil); len(hms) != 0 {
		t.Fatalf("health monitors remain: %+v", hms)
	}
	if pols, _ := e.svc.l7Policies(lbTestTenant).List(ctx, nil); len(pols) != 0 {
		t.Fatalf("l7 policies remain: %+v", pols)
	}
	if rules, _ := e.svc.l7Rules(lbTestTenant).List(ctx, nil); len(rules) != 0 {
		t.Fatalf("l7 rules remain: %+v", rules)
	}
	if _, ok, _ := e.eipSvc.PublicIPAddress(ctx, lbTestTenant, eipID); !ok {
		t.Fatalf("EIP should remain after force delete")
	}
	if _, err := e.vpcSvc.AllocateIP(ctx, lbTestTenant, e.subnetID, "verify:force", "192.168.0.88"); err != nil {
		t.Fatalf("VIP not released after force delete: %v", err)
	}
}

func TestLoadBalancerBatchAZsAndFilters(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)
	ctx := t.Context()

	lb, err := e.svc.createLoadBalancer(ctx, lbTestTenant, createLoadBalancerInput{
		Name:                   "lb-az",
		VIPSubnetCIDRID:        e.neutronSubnetID,
		L4FlavorID:             e.l4SmallID,
		AvailabilityZoneList:   []string{"ap-southeast-1a"},
		EnterpriseProjectID:    lbCustomEP,
		EnterpriseProjectIDSet: true,
	})
	if err != nil {
		t.Fatalf("createLoadBalancer: %v", err)
	}

	// Add AZs b and c.
	lb, err = e.svc.batchAddAvailableZones(ctx, lbTestTenant, lb.ID, []string{"ap-southeast-1b", "ap-southeast-1c"})
	if err != nil || len(lb.AvailabilityZoneList) != 3 {
		t.Fatalf("batchAddAvailableZones = %+v, %v", lb.AvailabilityZoneList, err)
	}
	// Adding already-present AZ or unknown AZ fails with ELB.8902.
	if _, err := e.svc.batchAddAvailableZones(ctx, lbTestTenant, lb.ID, []string{"ap-southeast-1b"}); lbCodeOf(err) != "ELB.8902" {
		t.Fatalf("add existing AZ = %v, want ELB.8902", err)
	}
	if _, err := e.svc.batchAddAvailableZones(ctx, lbTestTenant, lb.ID, []string{"ap-southeast-1z"}); lbCodeOf(err) != "ELB.8902" {
		t.Fatalf("add unknown AZ = %v, want ELB.8902", err)
	}
	if _, err := e.svc.batchAddAvailableZones(ctx, lbTestTenant, lbUnknownUUID, []string{"ap-southeast-1b"}); lbCodeOf(err) != "ELB.8904" {
		t.Fatalf("add AZ unknown LB = %v, want ELB.8904", err)
	}

	// Remove AZ b.
	lb, err = e.svc.batchRemoveAvailableZones(ctx, lbTestTenant, lb.ID, []string{"ap-southeast-1b"})
	if err != nil || len(lb.AvailabilityZoneList) != 2 {
		t.Fatalf("batchRemoveAvailableZones = %+v, %v", lb.AvailabilityZoneList, err)
	}
	// Removing AZ not on LB or removing all remaining AZs fails with ELB.8902.
	if _, err := e.svc.batchRemoveAvailableZones(ctx, lbTestTenant, lb.ID, []string{"ap-southeast-1b"}); lbCodeOf(err) != "ELB.8902" {
		t.Fatalf("remove absent AZ = %v, want ELB.8902", err)
	}
	if _, err := e.svc.batchRemoveAvailableZones(ctx, lbTestTenant, lb.ID, []string{"ap-southeast-1a", "ap-southeast-1c"}); lbCodeOf(err) != "ELB.8902" {
		t.Fatalf("remove all AZs = %v, want ELB.8902", err)
	}

	// List pagination & EP filtering.
	lb2, err := e.svc.createLoadBalancer(ctx, lbTestTenant, createLoadBalancerInput{
		Name:                 "lb-default-ep",
		VIPSubnetCIDRID:      e.neutronSubnetID,
		L7FlavorID:           e.l7SmallID,
		AvailabilityZoneList: []string{"ap-southeast-1a"},
	})
	if err != nil {
		t.Fatalf("createLoadBalancer(2): %v", err)
	}
	gotAll, pi, err := e.svc.listLoadBalancers(ctx, lbTestTenant, listLoadBalancersFilter{
		EnterpriseProjectIDs: []string{allGrantedEPs},
		Page:                 pagination.Marker{Limit: 1},
	})
	if err != nil || len(gotAll) != 1 || pi.NextMarker == nil || pi.CurrentCount != 1 {
		t.Fatalf("page 1 = len %d, pi=%+v, err=%v", len(gotAll), pi, err)
	}
	gotPage2, pi2, err := e.svc.listLoadBalancers(ctx, lbTestTenant, listLoadBalancersFilter{
		EnterpriseProjectIDs: []string{allGrantedEPs},
		Page:                 pagination.Marker{ID: *pi.NextMarker, Limit: 1},
	})
	if err != nil || len(gotPage2) != 1 || pi2.NextMarker != nil {
		t.Fatalf("page 2 = len %d, pi=%+v, err=%v", len(gotPage2), pi2, err)
	}
	if gotAll[0].ID >= gotPage2[0].ID {
		t.Fatalf("expected ascending ID order: %s >= %s", gotAll[0].ID, gotPage2[0].ID)
	}

	// Specific EP matches only lb.
	gotEP, _, err := e.svc.listLoadBalancers(ctx, lbTestTenant, listLoadBalancersFilter{
		EnterpriseProjectIDs: []string{lbCustomEP},
		Page:                 pagination.Marker{Limit: 2000},
	})
	if err != nil || len(gotEP) != 1 || gotEP[0].ID != lb.ID {
		t.Fatalf("EP filter = %+v, err=%v", gotEP, err)
	}
	_ = lb2
}

func TestLoadBalancerConcurrentVIPAllocation(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)
	ctx := t.Context()

	const goroutines = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		wins      int
		conflicts int
	)
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.createLoadBalancer(ctx, lbTestTenant, createLoadBalancerInput{
				Name:                 "lb-race",
				VIPSubnetCIDRID:      e.neutronSubnetID,
				VIPAddress:           "192.168.0.150",
				L4FlavorID:           e.l4SmallID,
				AvailabilityZoneList: []string{"ap-southeast-1a"},
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
				return
			}
			if lbCodeOf(err) == "ELB.8907" {
				conflicts++
				return
			}
			t.Errorf("unexpected error: %v", err)
		}()
	}
	wg.Wait()

	if wins != 1 || conflicts != goroutines-1 {
		t.Fatalf("wins=%d conflicts=%d, want 1 and %d", wins, conflicts, goroutines-1)
	}
}
