package eip

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	elbID1      = "88888888-1111-4111-8111-111111111111"
	elbID2      = "88888888-2222-4222-8222-222222222222"
	elbVIPPort1 = "77777777-1111-4111-8111-111111111111"
	elbVIPPort2 = "77777777-2222-4222-8222-222222222222"
	elbVIPAddr1 = "192.168.0.50"
	elbVIPAddr2 = "192.168.0.51"
	elbCustomEP = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

func TestELBBindAndUnbindErrorsAndIdempotency(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	// Unknown EIP returns ErrNATNotFound.
	if _, err := e.svc.BindToELB(ctx, pipTestTenant, pipUnknownID, elbID1, elbVIPPort1, elbVIPAddr1); !errors.Is(err, ErrNATNotFound) {
		t.Fatalf("BindToELB(unknown) = %v, want ErrNATNotFound", err)
	}

	// PENDING_CREATE EIP returns ErrNATNotReady.
	pending, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("bw-pending", 5))
	if err != nil {
		t.Fatalf("createPublicIP(pending): %v", err)
	}
	if _, err := e.svc.BindToELB(ctx, pipTestTenant, pending.ID, elbID1, elbVIPPort1, elbVIPAddr1); !errors.Is(err, ErrNATNotReady) {
		t.Fatalf("BindToELB(pending) = %v, want ErrNATNotReady", err)
	}

	// Port-bound EIP returns ErrNATBound.
	portBoundReq := pipPerReq("bw-port", 5)
	portBoundReq.PublicIP.PortID = pipPtr(pipPortID1)
	portBound, err := e.svc.createPublicIP(ctx, pipTestTenant, portBoundReq)
	if err != nil {
		t.Fatalf("createPublicIP(portBound): %v", err)
	}
	// NAT-held EIP returns ErrNATHeld.
	natPIP, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("bw-nat", 5))
	if err != nil {
		t.Fatalf("createPublicIP(natPIP): %v", err)
	}
	e.settle(t)

	if _, err := e.svc.HoldForNAT(ctx, pipTestTenant, natPIP.ID, natGatewayID1); err != nil {
		t.Fatalf("HoldForNAT: %v", err)
	}

	if _, err := e.svc.BindToELB(ctx, pipTestTenant, portBound.ID, elbID1, elbVIPPort1, elbVIPAddr1); !errors.Is(err, ErrNATBound) || !strings.Contains(err.Error(), pipPortID1) {
		t.Fatalf("BindToELB(port-bound) = %v, want ErrNATBound wrapping %s", err, pipPortID1)
	}
	if _, err := e.svc.BindToELB(ctx, pipTestTenant, natPIP.ID, elbID1, elbVIPPort1, elbVIPAddr1); !errors.Is(err, ErrNATHeld) || !strings.Contains(err.Error(), natGatewayID1) {
		t.Fatalf("BindToELB(nat-held) = %v, want ErrNATHeld wrapping %s", err, natGatewayID1)
	}

	// Wrong project cannot see EIP.
	if _, err := e.svc.BindToELB(ctx, pipTestTenantB, pending.ID, elbID1, elbVIPPort1, elbVIPAddr1); !errors.Is(err, ErrNATNotFound) {
		t.Fatalf("BindToELB(wrong project) = %v, want ErrNATNotFound", err)
	}

	// Bind free EIP to elbID1.
	e.clock.Advance(10 * time.Second)
	addr, err := e.svc.BindToELB(ctx, pipTestTenant, pending.ID, elbID1, elbVIPPort1, elbVIPAddr1)
	if err != nil || addr != pending.Address {
		t.Fatalf("BindToELB(free) = %q, %v; want %q, nil", addr, err, pending.Address)
	}
	got, err := e.svc.getPublicIP(ctx, pipTestTenant, pending.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if got.Status != StatusActive || got.ELBLoadBalancerID != elbID1 || got.PortID != elbVIPPort1 || got.PrivateIP != elbVIPAddr1 {
		t.Fatalf("after bind: %+v", got)
	}
	boundUpdatedAt := got.UpdatedAt

	// Re-binding by the same load balancer is an idempotent no-op.
	e.clock.Advance(5 * time.Second)
	addrAgain, err := e.svc.BindToELB(ctx, pipTestTenant, pending.ID, elbID1, elbVIPPort1, elbVIPAddr1)
	if err != nil || addrAgain != pending.Address {
		t.Fatalf("BindToELB(same lb) = %q, %v", addrAgain, err)
	}
	got, err = e.svc.getPublicIP(ctx, pipTestTenant, pending.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if !got.UpdatedAt.Equal(boundUpdatedAt) {
		t.Fatalf("idempotent bind altered UpdatedAt: got %v, want %v", got.UpdatedAt, boundUpdatedAt)
	}

	// Binding by a different load balancer returns ErrNATBound.
	if _, err := e.svc.BindToELB(ctx, pipTestTenant, pending.ID, elbID2, elbVIPPort2, elbVIPAddr2); !errors.Is(err, ErrNATBound) {
		t.Fatalf("BindToELB(other lb) = %v, want ErrNATBound", err)
	}

	// NAT HoldForNAT refuses an ELB-bound EIP with ErrNATBound.
	if _, err := e.svc.HoldForNAT(ctx, pipTestTenant, pending.ID, natGatewayID2); !errors.Is(err, ErrNATBound) {
		t.Fatalf("HoldForNAT(elb-bound) = %v, want ErrNATBound", err)
	}

	// Unbind by non-owning LB is a no-op.
	if err := e.svc.UnbindFromELB(ctx, pipTestTenant, pending.ID, elbID2); err != nil {
		t.Fatalf("UnbindFromELB(other lb): %v", err)
	}
	got, _ = e.svc.getPublicIP(ctx, pipTestTenant, pending.ID)
	if got.ELBLoadBalancerID != elbID1 || got.Status != StatusActive {
		t.Fatalf("non-owning unbind altered EIP: %+v", got)
	}

	// Unbind of unknown EIP is a no-op.
	if err := e.svc.UnbindFromELB(ctx, pipTestTenant, pipUnknownID, elbID1); err != nil {
		t.Fatalf("UnbindFromELB(unknown): %v", err)
	}

	// Unbind by owning LB clears PortID, PrivateIP, ELBLoadBalancerID, and flips to DOWN.
	e.clock.Advance(5 * time.Second)
	if err := e.svc.UnbindFromELB(ctx, pipTestTenant, pending.ID, elbID1); err != nil {
		t.Fatalf("UnbindFromELB(owner): %v", err)
	}
	got, err = e.svc.getPublicIP(ctx, pipTestTenant, pending.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if got.Status != StatusDown || got.ELBLoadBalancerID != "" || got.PortID != "" || got.PrivateIP != "" {
		t.Fatalf("after unbind: %+v", got)
	}

	// Unbinding again is a no-op.
	if err := e.svc.UnbindFromELB(ctx, pipTestTenant, pending.ID, elbID1); err != nil {
		t.Fatalf("UnbindFromELB(again): %v", err)
	}

	// After unbind, another LB can bind it.
	if _, err := e.svc.BindToELB(ctx, pipTestTenant, pending.ID, elbID2, elbVIPPort2, elbVIPAddr2); err != nil {
		t.Fatalf("BindToELB(lb2 after unbind): %v", err)
	}
}

func TestELBCreateForELB(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	// Create with PER bandwidth: immediately ACTIVE, bound to VIP port and LB.
	id1, addr1, err := e.svc.CreateForELB(ctx, pipTestTenant, elbID1, elbVIPPort1, elbVIPAddr1, ServerIP{
		Type:                "5_bgp",
		ShareType:           ShareTypePer,
		Size:                10,
		ChargeMode:          ChargeModeTraffic,
		BandwidthName:       "elb-bw-1",
		Description:         "elb public ip",
		EnterpriseProjectID: elbCustomEP,
	})
	if err != nil {
		t.Fatalf("CreateForELB(PER): %v", err)
	}
	if id1 == "" || addr1 == "" {
		t.Fatalf("CreateForELB returned empty id/addr: %q %q", id1, addr1)
	}
	pip1, err := e.svc.getPublicIP(ctx, pipTestTenant, id1)
	if err != nil {
		t.Fatalf("getPublicIP(1): %v", err)
	}
	if pip1.Status != StatusActive || pip1.PortID != elbVIPPort1 || pip1.PrivateIP != elbVIPAddr1 ||
		pip1.ELBLoadBalancerID != elbID1 || pip1.Description != "elb public ip" || pip1.EnterpriseProjectID != elbCustomEP {
		t.Fatalf("created PER EIP = %+v", pip1)
	}
	bw1, err := e.svc.bandwidths(pipTestTenant).Get(ctx, pip1.BandwidthID)
	if err != nil {
		t.Fatalf("get PER bandwidth: %v", err)
	}
	if bw1.Name != "elb-bw-1" || bw1.Size != 10 || bw1.ChargeMode != ChargeModeTraffic || bw1.ShareType != ShareTypePer {
		t.Fatalf("created PER bandwidth = %+v", bw1)
	}

	// Create with WHOLE shared bandwidth.
	sharedBW, err := e.svc.CreateSharedBandwidth(ctx, pipTestTenant, createSharedBandwidthOption{
		Name: "shared-elb-bw",
		Size: 20,
	})
	if err != nil {
		t.Fatalf("createSharedBandwidth: %v", err)
	}
	id2, addr2, err := e.svc.CreateForELB(ctx, pipTestTenant, elbID2, elbVIPPort2, elbVIPAddr2, ServerIP{
		Type:        "5_bgp",
		ShareType:   ShareTypeWhole,
		BandwidthID: sharedBW.ID,
	})
	if err != nil {
		t.Fatalf("CreateForELB(WHOLE): %v", err)
	}
	if id2 == "" || addr2 == "" || addr2 == addr1 {
		t.Fatalf("CreateForELB(WHOLE) = %q, %q", id2, addr2)
	}
	gotShared, err := e.svc.bandwidths(pipTestTenant).Get(ctx, sharedBW.ID)
	if err != nil {
		t.Fatalf("get shared bw: %v", err)
	}
	if len(gotShared.PublicIPIDs) != 1 || gotShared.PublicIPIDs[0] != id2 {
		t.Fatalf("shared bw PublicIPIDs = %v, want [%s]", gotShared.PublicIPIDs, id2)
	}

	// Validation & error cases.
	cases := []struct {
		name      string
		vipPortID string
		ip        ServerIP
		wantCode  string
	}{
		{"invalid type", "p-a", ServerIP{Type: "bad", ShareType: ShareTypePer, Size: 5}, "VPC.0501"},
		{"invalid share_type", "p-a", ServerIP{Type: "5_bgp", ShareType: "BAD", Size: 5}, "VPC.0501"},
		{"per size 0", "p-a", ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 0}, "VPC.0301"},
		{"per size too large", "p-a", ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 2001}, "VPC.0301"},
		{"per bad charge mode", "p-a", ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 5, ChargeMode: "weird"}, "VPC.0301"},
		{"per bad bw name", "p-a", ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 5, BandwidthName: "bad name!"}, "VPC.0301"},
		{"whole missing bw id", "p-a", ServerIP{Type: "5_bgp", ShareType: ShareTypeWhole}, "VPC.0301"},
		{"whole unknown bw id", "p-a", ServerIP{Type: "5_bgp", ShareType: ShareTypeWhole, BandwidthID: pipUnknownID}, "VPC.0306"},
		{"whole with per bw id", "p-a", ServerIP{Type: "5_bgp", ShareType: ShareTypeWhole, BandwidthID: bw1.ID}, "VPC.0306"},
		{"vip port already bound", elbVIPPort1, ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 5}, "VPC.0511"},
		{"invalid ep id", "p-a", ServerIP{Type: "5_bgp", ShareType: ShareTypePer, Size: 5, EnterpriseProjectID: "not-a-uuid"}, "VPC.0011"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := e.svc.CreateForELB(ctx, pipTestTenant, elbID1, tc.vipPortID, elbVIPAddr1, tc.ip)
			if got := ecsErrCode(err); got != tc.wantCode {
				t.Fatalf("CreateForELB(%s) error = %v (code %q), want %q", tc.name, err, got, tc.wantCode)
			}
		})
	}

	// Quota exceeded -> VPC.0521.
	qEnv := newPIPEnvWithOptions(t, 0, 1)
	if _, _, err := qEnv.svc.CreateForELB(ctx, pipTestTenant, elbID1, elbVIPPort1, elbVIPAddr1, ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5,
	}); err != nil {
		t.Fatalf("quota first CreateForELB: %v", err)
	}
	if _, _, err := qEnv.svc.CreateForELB(ctx, pipTestTenant, elbID2, elbVIPPort2, elbVIPAddr2, ServerIP{
		Type: "5_bgp", ShareType: ShareTypePer, Size: 5,
	}); ecsErrCode(err) != "VPC.0521" {
		t.Fatalf("quota second CreateForELB = %v, want VPC.0521", err)
	}
}

func TestELBBoundEIPEffectsV1V3AndECS(t *testing.T) {
	t.Parallel()
	e := newV3Env(t)
	ctx := t.Context()

	// Create an EIP via v1, settle it, then bind it to elbID1.
	st, raw1 := e.callV1(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "alias": "elb-eip"},
		"bandwidth": {"name": "bw-elb", "size": 10, "share_type": "PER"}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create eip: %d %s", st, raw1)
	}
	eip1 := pipDecodeInto[createPublicIPResponse](t, raw1).PublicIP
	e.settle(t)

	addr, err := e.svc.BindToELB(ctx, pipTestTenant, eip1.ID, elbID1, elbVIPPort1, elbVIPAddr1)
	if err != nil || addr != eip1.PublicIPAddress {
		t.Fatalf("BindToELB: addr=%q err=%v", addr, err)
	}

	// Effect 1: v1 Show and List show ACTIVE with port_id and private_ip_address.
	st, raw := e.callV1(t, http.MethodGet, "/publicips/"+eip1.ID, "")
	if st != http.StatusOK {
		t.Fatalf("v1 show: %d %s", st, raw)
	}
	showV1 := pipDecodeInto[showPublicIPResponse](t, raw).PublicIP
	if showV1.Status != StatusActive || showV1.PortID != elbVIPPort1 || showV1.PrivateIPAddress != elbVIPAddr1 {
		t.Fatalf("v1 show while ELB-bound = %+v", showV1)
	}

	st, raw = e.callV1(t, http.MethodGet, "/publicips?port_id="+elbVIPPort1, "")
	if st != http.StatusOK {
		t.Fatalf("v1 list: %d %s", st, raw)
	}
	listV1 := pipDecodeInto[listPublicIPsResponse](t, raw).PublicIPs
	if len(listV1) != 1 || listV1[0].ID != eip1.ID || listV1[0].Status != StatusActive {
		t.Fatalf("v1 list while ELB-bound = %+v", listV1)
	}

	// Effect 2: v3 Show and List show associate_instance_type "ELB",
	// associate_instance_id elbID1, and vnic with vip port/ip.
	st, raw = e.callV3(t, http.MethodGet, "/publicips/"+eip1.ID, "")
	if st != http.StatusOK {
		t.Fatalf("v3 show: %d %s", st, raw)
	}
	showV3 := pipDecodeInto[showPublicIPV3Response](t, raw).PublicIP
	if showV3.Status != StatusActive ||
		showV3.AssociateInstanceType == nil || *showV3.AssociateInstanceType != "ELB" ||
		showV3.AssociateInstanceID == nil || *showV3.AssociateInstanceID != elbID1 ||
		showV3.Vnic == nil || showV3.Vnic.PortID != elbVIPPort1 || showV3.Vnic.PrivateIPAddress != elbVIPAddr1 {
		t.Fatalf("v3 show while ELB-bound = %+v", showV3)
	}

	st, raw = e.callV3(t, http.MethodGet, "/publicips?associate_instance_type=ELB&associate_instance_id="+elbID1, "")
	if st != http.StatusOK {
		t.Fatalf("v3 list: %d %s", st, raw)
	}
	if resp := pipDecodeInto[listPublicIPsV3Response](t, raw); resp.TotalCount != 1 || resp.PublicIPs[0].ID != eip1.ID {
		t.Fatalf("v3 list ELB filter = %+v", resp)
	}

	// Effect 3: Binding elsewhere returns VPC.0510 across v1 update, v3 associate,
	// v3 update, and ECS AttachToServer.
	st, raw = e.callV1(t, http.MethodPut, "/publicips/"+eip1.ID, `{"publicip": {"port_id": "`+pipPortID1+`"}}`)
	if st != http.StatusConflict || pipDecodeInto[v1ErrBody](t, raw).Code != "VPC.0510" {
		t.Fatalf("v1 bind ELB EIP: %d %s, want 409 VPC.0510", st, raw)
	}
	st, raw = e.callV3(t, http.MethodPost, "/publicips/"+eip1.ID+"/associate-instance",
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)
	if st != http.StatusConflict || pipDecodeInto[v3ErrBody](t, raw).ErrorCode != "VPC.0510" {
		t.Fatalf("v3 associate ELB EIP: %d %s, want 409 VPC.0510", st, raw)
	}
	st, raw = e.callV3(t, http.MethodPut, "/publicips/"+eip1.ID,
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)
	if st != http.StatusConflict || pipDecodeInto[v3ErrBody](t, raw).ErrorCode != "VPC.0510" {
		t.Fatalf("v3 update bind ELB EIP: %d %s, want 409 VPC.0510", st, raw)
	}
	if _, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "web-01", ServerIP{ID: eip1.ID}); ecsErrCode(err) != "VPC.0510" {
		t.Fatalf("ECS AttachToServer ELB EIP = %v, want VPC.0510", err)
	}

	// Unbind / disassociate calls on an ELB-bound EIP do not clear the ELB binding.
	st, raw = e.callV1(t, http.MethodPut, "/publicips/"+eip1.ID, `{"publicip": {"port_id": null}}`)
	if st != http.StatusOK || pipDecodeInto[updatePublicIPResponse](t, raw).PublicIP.Status != StatusActive {
		t.Fatalf("v1 unbind ELB EIP altered status: %d %s", st, raw)
	}
	st, raw = e.callV3(t, http.MethodPost, "/publicips/"+eip1.ID+"/disassociate-instance", "")
	if st != http.StatusOK {
		t.Fatalf("v3 disassociate ELB EIP: %d %s", st, raw)
	}
	updV3 := pipDecodeInto[publicIPInstanceV3Response](t, raw).PublicIP
	if updV3.Status != StatusActive || updV3.AssociateInstanceType == nil || *updV3.AssociateInstanceType != "ELB" {
		t.Fatalf("v3 disassociate cleared ELB binding: %+v", updV3)
	}

	// Effect 4: Deleting an ELB-bound EIP returns VPC.0517 (409).
	st, raw = e.callV1(t, http.MethodDelete, "/publicips/"+eip1.ID, "")
	if st != http.StatusConflict || pipDecodeInto[v1ErrBody](t, raw).Code != "VPC.0517" {
		t.Fatalf("delete ELB EIP: %d %s, want 409 VPC.0517", st, raw)
	}

	// UnbindFromELB restores DOWN, clears v3 association, and allows delete.
	if err := e.svc.UnbindFromELB(ctx, pipTestTenant, eip1.ID, elbID1); err != nil {
		t.Fatalf("UnbindFromELB: %v", err)
	}
	st, raw = e.callV3(t, http.MethodGet, "/publicips/"+eip1.ID, "")
	if st != http.StatusOK {
		t.Fatalf("v3 show after unbind: %d %s", st, raw)
	}
	afterV3 := pipDecodeInto[showPublicIPV3Response](t, raw).PublicIP
	if afterV3.Status != StatusDown || afterV3.AssociateInstanceType != nil || afterV3.AssociateInstanceID != nil || afterV3.Vnic != nil {
		t.Fatalf("v3 show after unbind = %+v", afterV3)
	}
	st, raw = e.callV1(t, http.MethodDelete, "/publicips/"+eip1.ID, "")
	if st != http.StatusNoContent {
		t.Fatalf("delete after unbind: %d %s, want 204", st, raw)
	}
}

func TestELBConcurrentBinds(t *testing.T) {
	t.Parallel()
	e := newPIPEnvWithOptions(t, 0, 0)
	ctx := t.Context()

	pip, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("bw-race", 5))
	if err != nil {
		t.Fatalf("createPublicIP: %v", err)
	}
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	const goroutines = 8
	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		winnerLB    string
		lb1Success  int
		lb2Success  int
		boundErrors int
	)
	for i := range goroutines {
		wg.Add(1)
		lb, port, addr := elbID1, elbVIPPort1, elbVIPAddr1
		if i%2 == 1 {
			lb, port, addr = elbID2, elbVIPPort2, elbVIPAddr2
		}
		go func(lbID, vipPort, vipAddr string) {
			defer wg.Done()
			gotAddr, err := e.svc.BindToELB(ctx, pipTestTenant, pip.ID, lbID, vipPort, vipAddr)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				if gotAddr != pip.Address {
					t.Errorf("BindToELB(%s) addr = %q, want %q", lbID, gotAddr, pip.Address)
				}
				if winnerLB == "" {
					winnerLB = lbID
				}
				if lbID == elbID1 {
					lb1Success++
				} else {
					lb2Success++
				}
				return
			}
			if !errors.Is(err, ErrNATBound) {
				t.Errorf("BindToELB(%s) unexpected error: %v", lbID, err)
				return
			}
			boundErrors++
		}(lb, port, addr)
	}
	wg.Wait()

	if (lb1Success != 4 || lb2Success != 0) && (lb1Success != 0 || lb2Success != 4) {
		t.Fatalf("lb1Success=%d lb2Success=%d boundErrors=%d; want one LB 4/0", lb1Success, lb2Success, boundErrors)
	}
	if boundErrors != 4 {
		t.Fatalf("boundErrors = %d, want 4", boundErrors)
	}

	got, err := e.svc.getPublicIP(ctx, pipTestTenant, pip.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if got.ELBLoadBalancerID != winnerLB || got.Status != StatusActive {
		t.Fatalf("final EIP: elb_loadbalancer_id=%q status=%q, want %q ACTIVE", got.ELBLoadBalancerID, got.Status, winnerLB)
	}
}
