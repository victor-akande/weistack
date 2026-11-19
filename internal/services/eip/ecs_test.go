package eip

import (
	"errors"
	"testing"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

func ecsErrCode(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestECSAttachToServerCreatePER(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	addr1, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "web-01", ServerIP{
		Type:              "5_bgp",
		ShareType:         ShareTypePer,
		Size:              5,
		ReleaseWithServer: true,
	})
	if err != nil {
		t.Fatalf("AttachToServer(1): %v", err)
	}
	if addr1 != "192.0.2.1" {
		t.Fatalf("addr1 = %q, want 192.0.2.1", addr1)
	}

	all, err := e.svc.publicips(pipTestTenant).List(ctx, nil)
	if err != nil || len(all) != 1 {
		t.Fatalf("publicips = %+v, %v", all, err)
	}
	pip := all[0]
	if pip.Status != StatusPendingCreate || pip.PortID != pipPortID1 || pip.PrivateIP != "192.168.0.10" ||
		!pip.ReleaseWithPort || pip.EnterpriseProjectID != defaultEnterpriseProjectID {
		t.Fatalf("pip = %+v", pip)
	}

	bw, err := e.svc.bandwidths(pipTestTenant).Get(ctx, pip.BandwidthID)
	if err != nil {
		t.Fatalf("Get bandwidth: %v", err)
	}
	wantBWName := "web-01-bandwidth-" + pip.ID[:4]
	if bw.Name != wantBWName || bw.Size != 5 || bw.ShareType != ShareTypePer ||
		bw.ChargeMode != ChargeModeBandwidth || len(bw.PublicIPIDs) != 1 || bw.PublicIPIDs[0] != pip.ID {
		t.Fatalf("bw = %+v, want name %q", bw, wantBWName)
	}

	byPort, err := e.svc.AddressesByPort(ctx, pipTestTenant)
	if err != nil {
		t.Fatalf("AddressesByPort: %v", err)
	}
	if byPort[pipPortID1] != "192.0.2.1" || len(byPort) != 1 {
		t.Fatalf("AddressesByPort = %v", byPort)
	}

	e.settle(t)
	got, err := e.svc.getPublicIP(ctx, pipTestTenant, pip.ID)
	if err != nil || got.Status != StatusActive {
		t.Fatalf("after settle: %+v, %v; want ACTIVE", got, err)
	}

	// Traffic charge mode on a second port.
	addr2, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID2, "web-02", ServerIP{
		Type:       "5_bgp",
		ShareType:  ShareTypePer,
		Size:       10,
		ChargeMode: ChargeModeTraffic,
	})
	if err != nil {
		t.Fatalf("AttachToServer(2): %v", err)
	}
	if addr2 != "192.0.2.2" {
		t.Fatalf("addr2 = %q, want 192.0.2.2", addr2)
	}
	bws, err := e.svc.bandwidths(pipTestTenant).List(ctx, func(b bandwidth) bool { return b.Size == 10 })
	if err != nil || len(bws) != 1 || bws[0].ChargeMode != ChargeModeTraffic {
		t.Fatalf("traffic bw = %+v, %v", bws, err)
	}
}

func TestECSAttachToServerCreateWHOLE(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	bw, err := e.svc.CreateSharedBandwidth(ctx, pipTestTenant, createSharedBandwidthOption{
		Name: "shared-ecs",
		Size: 20,
	})
	if err != nil {
		t.Fatalf("createSharedBandwidth: %v", err)
	}

	addr, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "app-01", ServerIP{
		Type:        "5_bgp",
		ShareType:   ShareTypeWhole,
		BandwidthID: bw.ID,
	})
	if err != nil {
		t.Fatalf("AttachToServer(WHOLE): %v", err)
	}
	if addr != "192.0.2.1" {
		t.Fatalf("addr = %q, want 192.0.2.1", addr)
	}

	e.settle(t)
	pips, err := e.svc.publicips(pipTestTenant).List(ctx, nil)
	if err != nil || len(pips) != 1 || pips[0].Status != StatusActive || pips[0].BandwidthID != bw.ID {
		t.Fatalf("pips = %+v, %v", pips, err)
	}
	updatedBW, err := e.svc.bandwidths(pipTestTenant).Get(ctx, bw.ID)
	if err != nil || len(updatedBW.PublicIPIDs) != 1 || updatedBW.PublicIPIDs[0] != pips[0].ID {
		t.Fatalf("updatedBW = %+v, %v", updatedBW, err)
	}
}

func TestECSAttachToServerBindExisting(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	bwName := "precreated-bw"
	size := 5
	created, err := e.svc.createPublicIP(ctx, pipTestTenant, createPublicIPRequest{
		PublicIP:  &createPublicIPOption{Type: "5_bgp"},
		Bandwidth: &createPublicIPBandwidthOption{Name: &bwName, ShareType: ShareTypePer, Size: &size},
	})
	if err != nil {
		t.Fatalf("createPublicIP: %v", err)
	}
	// Still PENDING_CREATE must fail with VPC.0512.
	if _, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "srv", ServerIP{ID: created.ID}); ecsErrCode(err) != "VPC.0512" {
		t.Fatalf("AttachToServer while PENDING_CREATE: %v, want VPC.0512", err)
	}

	e.settle(t)
	addr, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "srv", ServerIP{ID: created.ID})
	if err != nil {
		t.Fatalf("AttachToServer(existing): %v", err)
	}
	if addr != created.Address {
		t.Fatalf("addr = %q, want %q", addr, created.Address)
	}

	got, err := e.svc.getPublicIP(ctx, pipTestTenant, created.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if got.Status != StatusActive || got.PortID != pipPortID1 || got.PrivateIP != "192.168.0.10" || got.ReleaseWithPort {
		t.Fatalf("bound pip = %+v", got)
	}

	byPort, err := e.svc.AddressesByPort(ctx, pipTestTenant)
	if err != nil || byPort[pipPortID1] != created.Address {
		t.Fatalf("AddressesByPort = %v, %v", byPort, err)
	}
}

func TestECSAttachToServerErrors(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	// Create two EIPs: one bound to pipPortID1, one unbound DOWN.
	bw1 := "bw-bound"
	bw2 := "bw-free"
	size := 5
	boundPIP, err := e.svc.createPublicIP(ctx, pipTestTenant, createPublicIPRequest{
		PublicIP:  &createPublicIPOption{Type: "5_bgp", PortID: ptrStr(pipPortID1)},
		Bandwidth: &createPublicIPBandwidthOption{Name: &bw1, ShareType: ShareTypePer, Size: &size},
	})
	if err != nil {
		t.Fatalf("create bound: %v", err)
	}
	freePIP, err := e.svc.createPublicIP(ctx, pipTestTenant, createPublicIPRequest{
		PublicIP:  &createPublicIPOption{Type: "5_bgp"},
		Bandwidth: &createPublicIPBandwidthOption{Name: &bw2, ShareType: ShareTypePer, Size: &size},
	})
	if err != nil {
		t.Fatalf("create free: %v", err)
	}
	e.settle(t)

	tests := []struct {
		name     string
		portID   string
		ip       ServerIP
		wantCode string
	}{
		{"unknown existing id", pipPortID2, ServerIP{ID: pipUnknownID}, "VPC.0504"},
		{"existing id empty port", "", ServerIP{ID: freePIP.ID}, "VPC.0501"},
		{"existing id unknown port", pipUnknownID, ServerIP{ID: freePIP.ID}, "VPC.0501"},
		{"existing id already bound", pipPortID2, ServerIP{ID: boundPIP.ID}, "VPC.0510"},
		{"existing id port already bound", pipPortID1, ServerIP{ID: freePIP.ID}, "VPC.0511"},
		{"invalid type", pipPortID2, ServerIP{Type: "bad", ShareType: ShareTypePer, Size: 5}, "VPC.0501"},
		{"sbgp wrong region", pipPortID2, ServerIP{Type: "5_sbgp", ShareType: ShareTypePer, Size: 5}, "VPC.0501"},
		{"invalid share type", pipPortID2, ServerIP{Type: "5_bgp", ShareType: "BAD", Size: 5}, "VPC.0501"},
		{"per size zero", pipPortID2, ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 0}, "VPC.0301"},
		{"per size too large", pipPortID2, ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 301}, "VPC.0301"},
		{"per bad charge mode", pipPortID2, ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 5, ChargeMode: "weird"}, "VPC.0301"},
		{"whole missing bw id", pipPortID2, ServerIP{Type: "5_bgp", ShareType: ShareTypeWhole}, "VPC.0301"},
		{"whole unknown bw id", pipPortID2, ServerIP{Type: "5_bgp", ShareType: ShareTypeWhole, BandwidthID: pipUnknownID}, "VPC.0306"},
		{"whole with per bw id", pipPortID2, ServerIP{Type: "5_bgp", ShareType: ShareTypeWhole, BandwidthID: freePIP.BandwidthID}, "VPC.0306"},
		{"create empty port", "", ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 5}, "VPC.0508"},
		{"create unknown port", pipUnknownID, ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 5}, "VPC.0508"},
		{"create port already bound", pipPortID1, ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 5}, "VPC.0511"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := e.svc.AttachToServer(ctx, pipTestTenant, tt.portID, "srv", tt.ip); ecsErrCode(err) != tt.wantCode {
				t.Errorf("AttachToServer(%s) = %v (code %q), want %q", tt.name, err, ecsErrCode(err), tt.wantCode)
			}
		})
	}

	// Quota exceeded.
	qEnv := newPIPEnvWithOptions(t, pipTestDelay, 1)
	if _, err := qEnv.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "s1", ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5,
	}); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if _, err := qEnv.svc.AttachToServer(ctx, pipTestTenant, pipPortID2, "s2", ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5,
	}); ecsErrCode(err) != "VPC.0521" {
		t.Fatalf("quota attach = %v, want VPC.0521", err)
	}

	// Pool exhausted.
	pEnv := newPIPEnv(t)
	pEnv.svc.pool = []string{"192.0.2.1"}
	if _, err := pEnv.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "s1", ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5,
	}); err != nil {
		t.Fatalf("first pool attach: %v", err)
	}
	if _, err := pEnv.svc.AttachToServer(ctx, pipTestTenant, pipPortID2, "s2", ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5,
	}); ecsErrCode(err) != "VPC.0532" {
		t.Fatalf("exhausted pool attach = %v, want VPC.0532", err)
	}
}

func TestECSPortsRemovedReleaseAndUnbind(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	// 1. Unbind when release=false and ReleaseWithPort=false.
	addr1, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "s1", ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5, ReleaseWithServer: false,
	})
	if err != nil {
		t.Fatalf("AttachToServer(1): %v", err)
	}
	e.settle(t)

	e.svc.PortsRemoved(ctx, pipTestTenant, []string{pipPortID1}, false)
	pips, err := e.svc.publicips(pipTestTenant).List(ctx, nil)
	if err != nil || len(pips) != 1 {
		t.Fatalf("after unbind: pips = %+v, %v", pips, err)
	}
	if pips[0].Status != StatusDown || pips[0].PortID != "" || pips[0].PrivateIP != "" {
		t.Fatalf("unbound pip = %+v, want DOWN and empty port/private_ip", pips[0])
	}
	byPort, err := e.svc.AddressesByPort(ctx, pipTestTenant)
	if err != nil || len(byPort) != 0 {
		t.Fatalf("AddressesByPort after unbind = %v, %v", byPort, err)
	}

	// Rebind that EIP and remove with release=true -> deletes EIP, PER bandwidth, and claim.
	if _, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "s1", ServerIP{ID: pips[0].ID}); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	bwID := pips[0].BandwidthID
	e.svc.PortsRemoved(ctx, pipTestTenant, []string{pipPortID1}, true)

	pips, _ = e.svc.publicips(pipTestTenant).List(ctx, nil)
	if len(pips) != 0 {
		t.Fatalf("after release=true: %d EIPs left", len(pips))
	}
	if _, err := e.svc.bandwidths(pipTestTenant).Get(ctx, bwID); err == nil {
		t.Fatalf("PER bandwidth %s survived release", bwID)
	}

	// 2. ReleaseWithPort=true releases even when release=false, and frees the address back to the pool.
	addr2, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "s2", ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5, ReleaseWithServer: true,
	})
	if err != nil {
		t.Fatalf("AttachToServer(2): %v", err)
	}
	if addr2 != addr1 {
		t.Fatalf("reclaimed address = %q, want %q", addr2, addr1)
	}
	e.settle(t)
	e.svc.PortsRemoved(ctx, pipTestTenant, []string{pipPortID1}, false)
	pips, _ = e.svc.publicips(pipTestTenant).List(ctx, nil)
	if len(pips) != 0 {
		t.Fatalf("ReleaseWithPort=true did not release EIP: %+v", pips)
	}

	// 3. Release of an EIP in a WHOLE bandwidth removes it from PublicIPIDs and keeps the shared bandwidth.
	sharedBW, err := e.svc.CreateSharedBandwidth(ctx, pipTestTenant, createSharedBandwidthOption{
		Name: "shared-keep",
		Size: 10,
	})
	if err != nil {
		t.Fatalf("createSharedBandwidth: %v", err)
	}
	if _, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "s3", ServerIP{
		Type: "5_bgp", ShareType: ShareTypeWhole, BandwidthID: sharedBW.ID,
	}); err != nil {
		t.Fatalf("AttachToServer(WHOLE): %v", err)
	}
	e.settle(t)
	e.svc.PortsRemoved(ctx, pipTestTenant, []string{pipPortID1}, true)
	gotBW, err := e.svc.bandwidths(pipTestTenant).Get(ctx, sharedBW.ID)
	if err != nil {
		t.Fatalf("WHOLE bandwidth deleted on release: %v", err)
	}
	if len(gotBW.PublicIPIDs) != 0 {
		t.Fatalf("WHOLE bandwidth still lists EIP: %+v", gotBW.PublicIPIDs)
	}

	// 4. PortsRemoved while EIP is still PENDING_CREATE cancels the activation task cleanly.
	if _, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "s4", ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5, ReleaseWithServer: false,
	}); err != nil {
		t.Fatalf("AttachToServer(pending-unbind): %v", err)
	}
	if _, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID2, "s5", ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5, ReleaseWithServer: true,
	}); err != nil {
		t.Fatalf("AttachToServer(pending-release): %v", err)
	}
	e.svc.PortsRemoved(ctx, pipTestTenant, []string{pipPortID1, pipPortID2, pipUnknownID}, false)
	if n := e.engine.Pending(); n != 0 {
		t.Fatalf("%d pending tasks left after PortsRemoved on PENDING_CREATE EIPs", n)
	}
	pips, _ = e.svc.publicips(pipTestTenant).List(ctx, nil)
	if len(pips) != 1 || pips[0].Status != StatusDown || pips[0].PortID != "" {
		t.Fatalf("after pending PortsRemoved: %+v, want 1 DOWN unbound EIP", pips)
	}
}

func TestECSAddressesByPortIsolation(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	// Empty tenant returns empty map.
	got, err := e.svc.AddressesByPort(ctx, pipTestTenant)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty AddressesByPort = %v, %v", got, err)
	}

	// Unbound EIP is excluded; bound EIP in tenant A is invisible in tenant B.
	bwName := "unbound-bw"
	size := 5
	if _, err := e.svc.createPublicIP(ctx, pipTestTenant, createPublicIPRequest{
		PublicIP:  &createPublicIPOption{Type: "5_bgp"},
		Bandwidth: &createPublicIPBandwidthOption{Name: &bwName, ShareType: ShareTypePer, Size: &size},
	}); err != nil {
		t.Fatalf("create unbound: %v", err)
	}
	addr, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "s1", ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5,
	})
	if err != nil {
		t.Fatalf("AttachToServer: %v", err)
	}

	gotA, err := e.svc.AddressesByPort(ctx, pipTestTenant)
	if err != nil || len(gotA) != 1 || gotA[pipPortID1] != addr {
		t.Fatalf("tenant A AddressesByPort = %v, %v", gotA, err)
	}
	gotB, err := e.svc.AddressesByPort(ctx, vpc.Tenant{Region: pipTestRegion, ProjectID: pipTestProjectB})
	if err != nil || len(gotB) != 0 {
		t.Fatalf("tenant B AddressesByPort = %v, %v", gotB, err)
	}
}

func ptrStr(s string) *string { return &s }
