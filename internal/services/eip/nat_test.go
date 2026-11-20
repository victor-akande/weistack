package eip

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	natGatewayID1 = "99999999-1111-4111-8111-111111111111"
	natGatewayID2 = "99999999-2222-4222-8222-222222222222"
)

type v1ErrBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type v3ErrBody struct {
	ErrorCode string `json:"error_code"`
	ErrorMsg  string `json:"error_msg"`
	RequestID string `json:"request_id"`
}

func TestNATHoldAndReleaseErrorsAndIdempotency(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	// Unknown EIP returns ErrNATNotFound.
	if _, err := e.svc.HoldForNAT(ctx, pipTestTenant, pipUnknownID, natGatewayID1); !errors.Is(err, ErrNATNotFound) {
		t.Fatalf("HoldForNAT(unknown) = %v, want ErrNATNotFound", err)
	}

	// Create an EIP: while PENDING_CREATE, HoldForNAT returns ErrNATNotReady.
	pending, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("bw-pending", 5))
	if err != nil {
		t.Fatalf("createPublicIP(pending): %v", err)
	}
	if _, err := e.svc.HoldForNAT(ctx, pipTestTenant, pending.ID, natGatewayID1); !errors.Is(err, ErrNATNotReady) {
		t.Fatalf("HoldForNAT(pending) = %v, want ErrNATNotReady", err)
	}

	// Create an EIP bound to a port.
	boundReq := pipPerReq("bw-bound", 5)
	boundReq.PublicIP.PortID = pipPtr(pipPortID1)
	bound, err := e.svc.createPublicIP(ctx, pipTestTenant, boundReq)
	if err != nil {
		t.Fatalf("createPublicIP(bound): %v", err)
	}
	e.settle(t)

	// Port-bound EIP returns ErrNATBound wrapped with the port ID.
	if _, err := e.svc.HoldForNAT(ctx, pipTestTenant, bound.ID, natGatewayID1); !errors.Is(err, ErrNATBound) || !strings.Contains(err.Error(), pipPortID1) {
		t.Fatalf("HoldForNAT(port-bound) = %v, want ErrNATBound wrapping %s", err, pipPortID1)
	}

	// Another project cannot see pipTestTenant's EIP.
	if _, err := e.svc.HoldForNAT(ctx, pipTestTenantB, pending.ID, natGatewayID1); !errors.Is(err, ErrNATNotFound) {
		t.Fatalf("HoldForNAT(wrong project) = %v, want ErrNATNotFound", err)
	}

	// Hold the free EIP for gateway 1.
	e.clock.Advance(10 * time.Second)
	addr, err := e.svc.HoldForNAT(ctx, pipTestTenant, pending.ID, natGatewayID1)
	if err != nil {
		t.Fatalf("HoldForNAT(free): %v", err)
	}
	if addr != pending.Address {
		t.Fatalf("HoldForNAT address = %q, want %q", addr, pending.Address)
	}
	got, err := e.svc.getPublicIP(ctx, pipTestTenant, pending.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if got.Status != StatusActive || got.NATGatewayID != natGatewayID1 || got.PortID != "" {
		t.Fatalf("after hold: status=%q nat_gateway_id=%q port_id=%q", got.Status, got.NATGatewayID, got.PortID)
	}
	heldUpdatedAt := got.UpdatedAt

	// Holding again by the same gateway is a no-op returning the address.
	e.clock.Advance(5 * time.Second)
	addrAgain, err := e.svc.HoldForNAT(ctx, pipTestTenant, pending.ID, natGatewayID1)
	if err != nil {
		t.Fatalf("HoldForNAT(same gw): %v", err)
	}
	if addrAgain != pending.Address {
		t.Fatalf("HoldForNAT(same gw) address = %q, want %q", addrAgain, pending.Address)
	}
	got, err = e.svc.getPublicIP(ctx, pipTestTenant, pending.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if !got.UpdatedAt.Equal(heldUpdatedAt) {
		t.Fatalf("idempotent hold modified UpdatedAt: got %v, want %v", got.UpdatedAt, heldUpdatedAt)
	}

	// Holding by a different gateway fails with ErrNATHeld wrapped with gateway 1's ID.
	if _, err := e.svc.HoldForNAT(ctx, pipTestTenant, pending.ID, natGatewayID2); !errors.Is(err, ErrNATHeld) || !strings.Contains(err.Error(), natGatewayID1) {
		t.Fatalf("HoldForNAT(other gw) = %v, want ErrNATHeld wrapping %s", err, natGatewayID1)
	}

	// Release by non-owning gateway is a no-op; gateway 1 still holds it.
	if err := e.svc.ReleaseFromNAT(ctx, pipTestTenant, pending.ID, natGatewayID2); err != nil {
		t.Fatalf("ReleaseFromNAT(other gw): %v", err)
	}
	got, err = e.svc.getPublicIP(ctx, pipTestTenant, pending.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if got.Status != StatusActive || got.NATGatewayID != natGatewayID1 {
		t.Fatalf("non-owning release altered EIP: status=%q nat_gateway_id=%q", got.Status, got.NATGatewayID)
	}

	// Release of unknown EIP is a no-op.
	if err := e.svc.ReleaseFromNAT(ctx, pipTestTenant, pipUnknownID, natGatewayID1); err != nil {
		t.Fatalf("ReleaseFromNAT(unknown): %v", err)
	}

	// Release of port-bound EIP is a no-op and preserves port binding.
	if err := e.svc.ReleaseFromNAT(ctx, pipTestTenant, bound.ID, natGatewayID1); err != nil {
		t.Fatalf("ReleaseFromNAT(port-bound): %v", err)
	}
	gotBound, err := e.svc.getPublicIP(ctx, pipTestTenant, bound.ID)
	if err != nil {
		t.Fatalf("getPublicIP(bound): %v", err)
	}
	if gotBound.Status != StatusActive || gotBound.PortID != pipPortID1 {
		t.Fatalf("release altered port-bound EIP: %+v", gotBound)
	}

	// Release by owning gateway clears NATGatewayID and returns status to DOWN.
	e.clock.Advance(5 * time.Second)
	if err := e.svc.ReleaseFromNAT(ctx, pipTestTenant, pending.ID, natGatewayID1); err != nil {
		t.Fatalf("ReleaseFromNAT(owner): %v", err)
	}
	got, err = e.svc.getPublicIP(ctx, pipTestTenant, pending.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if got.Status != StatusDown || got.NATGatewayID != "" || !got.UpdatedAt.After(heldUpdatedAt) {
		t.Fatalf("after release: status=%q nat_gateway_id=%q updated_at=%v", got.Status, got.NATGatewayID, got.UpdatedAt)
	}

	// Releasing again is a no-op.
	if err := e.svc.ReleaseFromNAT(ctx, pipTestTenant, pending.ID, natGatewayID1); err != nil {
		t.Fatalf("ReleaseFromNAT(again): %v", err)
	}

	// After release, gateway 2 can hold the EIP.
	addr2, err := e.svc.HoldForNAT(ctx, pipTestTenant, pending.ID, natGatewayID2)
	if err != nil || addr2 != pending.Address {
		t.Fatalf("HoldForNAT(gw2 after release) = %q, %v", addr2, err)
	}
}

func TestNATPublicIPLookups(t *testing.T) {
	t.Parallel()
	e := newPIPEnvWithOptions(t, 0, DefaultMaxPerProject)
	ctx := t.Context()

	pipA, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("bw-a", 5))
	if err != nil {
		t.Fatalf("createPublicIP(A): %v", err)
	}
	pipB, err := e.svc.createPublicIP(ctx, pipTestTenantB, pipPerReq("bw-b", 5))
	if err != nil {
		t.Fatalf("createPublicIP(B): %v", err)
	}
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	// PublicIPByAddress finds project's own EIP and not another project's.
	id, ok, err := e.svc.PublicIPByAddress(ctx, pipTestTenant, pipA.Address)
	if err != nil || !ok || id != pipA.ID {
		t.Fatalf("PublicIPByAddress(A) = %q, %v, %v; want %q, true, nil", id, ok, err, pipA.ID)
	}
	if id, ok, err := e.svc.PublicIPByAddress(ctx, pipTestTenant, pipB.Address); err != nil || ok || id != "" {
		t.Fatalf("PublicIPByAddress(other project) = %q, %v, %v; want empty, false, nil", id, ok, err)
	}
	if id, ok, err := e.svc.PublicIPByAddress(ctx, pipTestTenant, "192.0.2.250"); err != nil || ok || id != "" {
		t.Fatalf("PublicIPByAddress(unknown) = %q, %v, %v; want empty, false, nil", id, ok, err)
	}
	if id, ok, err := e.svc.PublicIPByAddress(ctx, pipTestTenant, ""); err != nil || ok || id != "" {
		t.Fatalf("PublicIPByAddress(empty) = %q, %v, %v; want empty, false, nil", id, ok, err)
	}

	// PublicIPAddress finds project's own EIP and not unknown/other project's.
	addr, ok, err := e.svc.PublicIPAddress(ctx, pipTestTenant, pipA.ID)
	if err != nil || !ok || addr != pipA.Address {
		t.Fatalf("PublicIPAddress(A) = %q, %v, %v; want %q, true, nil", addr, ok, err, pipA.Address)
	}
	if addr, ok, err := e.svc.PublicIPAddress(ctx, pipTestTenant, pipB.ID); err != nil || ok || addr != "" {
		t.Fatalf("PublicIPAddress(other project) = %q, %v, %v; want empty, false, nil", addr, ok, err)
	}
	if addr, ok, err := e.svc.PublicIPAddress(ctx, pipTestTenant, pipUnknownID); err != nil || ok || addr != "" {
		t.Fatalf("PublicIPAddress(unknown) = %q, %v, %v; want empty, false, nil", addr, ok, err)
	}

	// After deletion, both lookups report not found.
	if err := e.svc.deletePublicIP(ctx, pipTestTenant, pipA.ID); err != nil {
		t.Fatalf("deletePublicIP(A): %v", err)
	}
	if _, ok, err := e.svc.PublicIPByAddress(ctx, pipTestTenant, pipA.Address); err != nil || ok {
		t.Fatalf("PublicIPByAddress(deleted) = %v, %v; want false, nil", ok, err)
	}
	if _, ok, err := e.svc.PublicIPAddress(ctx, pipTestTenant, pipA.ID); err != nil || ok {
		t.Fatalf("PublicIPAddress(deleted) = %v, %v; want false, nil", ok, err)
	}
}

func TestNATHeldEIPEffectsV1V3AndECS(t *testing.T) {
	t.Parallel()
	e := newV3Env(t)
	ctx := t.Context()

	// Create two EIPs: one will be held by NAT, one stays free for comparison.
	st, raw1 := e.callV1(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "alias": "nat-eip"},
		"bandwidth": {"name": "bw-nat", "size": 10, "share_type": "PER"}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create eip 1: %d %s", st, raw1)
	}
	eip1 := pipDecodeInto[createPublicIPResponse](t, raw1).PublicIP

	st, raw2 := e.callV1(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "alias": "free-eip"},
		"bandwidth": {"name": "bw-free", "size": 10, "share_type": "PER"}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create eip 2: %d %s", st, raw2)
	}
	eip2 := pipDecodeInto[createPublicIPResponse](t, raw2).PublicIP
	e.settle(t)

	// Hold eip1 for natGatewayID1.
	addr, err := e.svc.HoldForNAT(ctx, pipTestTenant, eip1.ID, natGatewayID1)
	if err != nil || addr != eip1.PublicIPAddress {
		t.Fatalf("HoldForNAT: addr=%q err=%v", addr, err)
	}

	// Effect 1: v1 Show and List show status ACTIVE with no port_id / private_ip_address.
	st, raw := e.callV1(t, http.MethodGet, "/publicips/"+eip1.ID, "")
	if st != http.StatusOK {
		t.Fatalf("v1 show: %d %s", st, raw)
	}
	showV1 := pipDecodeInto[showPublicIPResponse](t, raw).PublicIP
	if showV1.Status != StatusActive || showV1.PortID != "" || showV1.PrivateIPAddress != "" {
		t.Fatalf("v1 show while held = %+v", showV1)
	}
	// Ensure port_id is omitted from JSON wire representation when empty.
	var rawMap map[string]map[string]any
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		t.Fatalf("unmarshal raw v1 show: %v", err)
	}
	if _, hasPortID := rawMap["publicip"]["port_id"]; hasPortID {
		t.Fatalf("v1 show unexpectedly included port_id: %s", raw)
	}

	st, raw = e.callV1(t, http.MethodGet, "/publicips?id="+eip1.ID, "")
	if st != http.StatusOK {
		t.Fatalf("v1 list: %d %s", st, raw)
	}
	listV1 := pipDecodeInto[listPublicIPsResponse](t, raw).PublicIPs
	if len(listV1) != 1 || listV1[0].Status != StatusActive || listV1[0].PortID != "" {
		t.Fatalf("v1 list while held = %+v", listV1)
	}

	// Effect 2: v3 Show and List show associate_instance_type "NATGW",
	// associate_instance_id natGatewayID1, and vnic null.
	st, raw = e.callV3(t, http.MethodGet, "/publicips/"+eip1.ID, "")
	if st != http.StatusOK {
		t.Fatalf("v3 show: %d %s", st, raw)
	}
	showV3 := pipDecodeInto[showPublicIPV3Response](t, raw).PublicIP
	if showV3.Status != StatusActive || showV3.Vnic != nil ||
		showV3.AssociateInstanceType == nil || *showV3.AssociateInstanceType != "NATGW" ||
		showV3.AssociateInstanceID == nil || *showV3.AssociateInstanceID != natGatewayID1 {
		t.Fatalf("v3 show while held = %+v", showV3)
	}

	// v3 List filters work for NATGW, gateway ID, status, and vnic.
	v3ListCount := func(query string) int {
		t.Helper()
		st, out := e.callV3(t, http.MethodGet, "/publicips"+query, "")
		if st != http.StatusOK {
			t.Fatalf("v3 list %s: %d %s", query, st, out)
		}
		resp := pipDecodeInto[listPublicIPsV3Response](t, out)
		return resp.TotalCount
	}
	if n := v3ListCount("?associate_instance_type=NATGW"); n != 1 {
		t.Fatalf("v3 list associate_instance_type=NATGW count = %d, want 1", n)
	}
	if n := v3ListCount("?associate_instance_id=" + natGatewayID1); n != 1 {
		t.Fatalf("v3 list associate_instance_id=%s count = %d, want 1", natGatewayID1, n)
	}
	if n := v3ListCount("?associate_instance_id=" + natGatewayID2); n != 0 {
		t.Fatalf("v3 list associate_instance_id=%s count = %d, want 0", natGatewayID2, n)
	}
	if n := v3ListCount("?status=ACTIVE"); n != 1 {
		t.Fatalf("v3 list status=ACTIVE count = %d, want 1", n)
	}
	if n := v3ListCount("?vnic.port_id=" + pipPortID1); n != 0 {
		t.Fatalf("v3 list vnic.port_id count = %d, want 0", n)
	}

	// Effect 3: Binding to a port returns VPC.0510 (409) across v1 update,
	// v3 associate, v3 update, and ECS AttachToServer.
	st, raw = e.callV1(t, http.MethodPut, "/publicips/"+eip1.ID, `{"publicip": {"port_id": "`+pipPortID1+`"}}`)
	if st != http.StatusConflict || pipDecodeInto[v1ErrBody](t, raw).Code != "VPC.0510" {
		t.Fatalf("v1 bind held EIP: %d %s, want 409 VPC.0510", st, raw)
	}

	st, raw = e.callV3(t, http.MethodPost, "/publicips/"+eip1.ID+"/associate-instance",
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)
	if st != http.StatusConflict || pipDecodeInto[v3ErrBody](t, raw).ErrorCode != "VPC.0510" {
		t.Fatalf("v3 associate held EIP: %d %s, want 409 VPC.0510", st, raw)
	}

	st, raw = e.callV3(t, http.MethodPut, "/publicips/"+eip1.ID,
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)
	if st != http.StatusConflict || pipDecodeInto[v3ErrBody](t, raw).ErrorCode != "VPC.0510" {
		t.Fatalf("v3 update bind held EIP: %d %s, want 409 VPC.0510", st, raw)
	}

	if _, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "web-01", ServerIP{ID: eip1.ID}); ecsErrCode(err) != "VPC.0510" {
		t.Fatalf("ECS AttachToServer held EIP = %v, want VPC.0510", err)
	}

	// Metadata-only updates (v1 alias, v3 alias/description) preserve the NAT hold.
	st, raw = e.callV1(t, http.MethodPut, "/publicips/"+eip1.ID, `{"publicip": {"alias": "nat-eip-renamed"}}`)
	if st != http.StatusOK {
		t.Fatalf("v1 alias update on held EIP: %d %s", st, raw)
	}
	updV1 := pipDecodeInto[updatePublicIPResponse](t, raw).PublicIP
	if updV1.Alias != "nat-eip-renamed" || updV1.Status != StatusActive || updV1.PortID != "" {
		t.Fatalf("v1 alias update result = %+v", updV1)
	}

	st, raw = e.callV3(t, http.MethodPut, "/publicips/"+eip1.ID, `{"publicip": {"description": "for nat"}}`)
	if st != http.StatusOK {
		t.Fatalf("v3 description update on held EIP: %d %s", st, raw)
	}
	updV3 := pipDecodeInto[publicIPInstanceV3Response](t, raw).PublicIP
	if updV3.Description != "for nat" || updV3.Status != StatusActive || updV3.Vnic != nil ||
		updV3.AssociateInstanceType == nil || *updV3.AssociateInstanceType != "NATGW" ||
		updV3.AssociateInstanceID == nil || *updV3.AssociateInstanceID != natGatewayID1 {
		t.Fatalf("v3 description update result = %+v", updV3)
	}

	// Unbind / disassociate calls on a NAT-held EIP must NOT clear the NAT hold
	// or flip status to DOWN.
	for _, body := range []string{
		`{"publicip": {}}`,
		`{"publicip": {"port_id": ""}}`,
		`{"publicip": {"port_id": null}}`,
	} {
		st, raw = e.callV1(t, http.MethodPut, "/publicips/"+eip1.ID, body)
		if st != http.StatusOK {
			t.Fatalf("v1 unbind %s: %d %s", body, st, raw)
		}
		got := pipDecodeInto[updatePublicIPResponse](t, raw).PublicIP
		if got.Status != StatusActive {
			t.Fatalf("v1 unbind %s flipped status to %q", body, got.Status)
		}
	}

	st, raw = e.callV3(t, http.MethodPut, "/publicips/"+eip1.ID,
		`{"publicip": {"associate_instance_type": null, "associate_instance_id": null}}`)
	if st != http.StatusOK {
		t.Fatalf("v3 update unbind: %d %s", st, raw)
	}
	updV3 = pipDecodeInto[publicIPInstanceV3Response](t, raw).PublicIP
	if updV3.Status != StatusActive || updV3.AssociateInstanceType == nil || *updV3.AssociateInstanceType != "NATGW" ||
		updV3.AssociateInstanceID == nil || *updV3.AssociateInstanceID != natGatewayID1 {
		t.Fatalf("v3 update unbind cleared NAT hold: %+v", updV3)
	}

	st, raw = e.callV3(t, http.MethodPost, "/publicips/"+eip1.ID+"/disassociate-instance", "")
	if st != http.StatusOK {
		t.Fatalf("v3 disassociate: %d %s", st, raw)
	}
	updV3 = pipDecodeInto[publicIPInstanceV3Response](t, raw).PublicIP
	if updV3.Status != StatusActive || updV3.AssociateInstanceType == nil || *updV3.AssociateInstanceType != "NATGW" ||
		updV3.AssociateInstanceID == nil || *updV3.AssociateInstanceID != natGatewayID1 {
		t.Fatalf("v3 disassociate cleared NAT hold: %+v", updV3)
	}

	// Effect 4: Deleting a NAT-held EIP returns VPC.0517 (409).
	st, raw = e.callV1(t, http.MethodDelete, "/publicips/"+eip1.ID, "")
	if st != http.StatusConflict || pipDecodeInto[v1ErrBody](t, raw).Code != "VPC.0517" {
		t.Fatalf("delete held EIP: %d %s, want 409 VPC.0517", st, raw)
	}

	// Effect 5: validateAssociateInstanceType still refuses NATGW with WeiStack.0501
	// on both associate-instance and v3 update.
	st, raw = e.callV3(t, http.MethodPost, "/publicips/"+eip2.ID+"/associate-instance",
		`{"publicip": {"associate_instance_type": "NATGW", "associate_instance_id": "`+natGatewayID1+`"}}`)
	if st != http.StatusNotImplemented || pipDecodeInto[v3ErrBody](t, raw).ErrorCode != "WeiStack.0501" {
		t.Fatalf("v3 associate NATGW: %d %s, want 501 WeiStack.0501", st, raw)
	}
	st, raw = e.callV3(t, http.MethodPut, "/publicips/"+eip2.ID,
		`{"publicip": {"associate_instance_type": "NATGW", "associate_instance_id": "`+natGatewayID1+`"}}`)
	if st != http.StatusNotImplemented || pipDecodeInto[v3ErrBody](t, raw).ErrorCode != "WeiStack.0501" {
		t.Fatalf("v3 update NATGW: %d %s, want 501 WeiStack.0501", st, raw)
	}

	// Release the NAT hold: v1 goes back to DOWN, v3 clears associate_instance_*,
	// and binding or deleting succeeds again.
	if err := e.svc.ReleaseFromNAT(ctx, pipTestTenant, eip1.ID, natGatewayID1); err != nil {
		t.Fatalf("ReleaseFromNAT: %v", err)
	}

	st, raw = e.callV1(t, http.MethodGet, "/publicips/"+eip1.ID, "")
	if st != http.StatusOK {
		t.Fatalf("v1 show after release: %d %s", st, raw)
	}
	if got := pipDecodeInto[showPublicIPResponse](t, raw).PublicIP; got.Status != StatusDown || got.PortID != "" {
		t.Fatalf("v1 show after release = %+v, want DOWN", got)
	}

	st, raw = e.callV3(t, http.MethodGet, "/publicips/"+eip1.ID, "")
	if st != http.StatusOK {
		t.Fatalf("v3 show after release: %d %s", st, raw)
	}
	if got := pipDecodeInto[showPublicIPV3Response](t, raw).PublicIP; got.Status != StatusDown ||
		got.AssociateInstanceType != nil || got.AssociateInstanceID != nil || got.Vnic != nil {
		t.Fatalf("v3 show after release = %+v, want DOWN with nil association", got)
	}

	// ECS AttachToServer now works on eip1, then unbind, then delete succeeds.
	attachedAddr, err := e.svc.AttachToServer(ctx, pipTestTenant, pipPortID1, "web-01", ServerIP{ID: eip1.ID})
	if err != nil || attachedAddr != eip1.PublicIPAddress {
		t.Fatalf("AttachToServer after release = %q, %v", attachedAddr, err)
	}
	st, raw = e.callV3(t, http.MethodPost, "/publicips/"+eip1.ID+"/disassociate-instance", "")
	if st != http.StatusOK {
		t.Fatalf("disassociate after port bind: %d %s", st, raw)
	}
	st, raw = e.callV1(t, http.MethodDelete, "/publicips/"+eip1.ID, "")
	if st != http.StatusNoContent {
		t.Fatalf("delete after release: %d %s, want 204", st, raw)
	}
}

func TestNATConcurrentHolds(t *testing.T) {
	t.Parallel()
	e := newPIPEnvWithOptions(t, 0, DefaultMaxPerProject)
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
		wg         sync.WaitGroup
		mu         sync.Mutex
		winnerGW   string
		gw1Success int
		gw2Success int
		heldErrors int
	)

	for i := range goroutines {
		wg.Add(1)
		gw := natGatewayID1
		if i%2 == 1 {
			gw = natGatewayID2
		}
		go func(gwID string) {
			defer wg.Done()
			addr, err := e.svc.HoldForNAT(ctx, pipTestTenant, pip.ID, gwID)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				if addr != pip.Address {
					t.Errorf("HoldForNAT(%s) addr = %q, want %q", gwID, addr, pip.Address)
				}
				if winnerGW == "" {
					winnerGW = gwID
				}
				if gwID == natGatewayID1 {
					gw1Success++
				} else {
					gw2Success++
				}
				return
			}
			if !errors.Is(err, ErrNATHeld) {
				t.Errorf("HoldForNAT(%s) unexpected error: %v", gwID, err)
				return
			}
			heldErrors++
		}(gw)
	}
	wg.Wait()

	// Exactly one gateway won (all 4 of its goroutines succeeded via idempotent hold),
	// and all 4 goroutines of the losing gateway got ErrNATHeld.
	if (gw1Success != 4 || gw2Success != 0) && (gw1Success != 0 || gw2Success != 4) {
		t.Fatalf("gw1Success=%d gw2Success=%d heldErrors=%d; want one gateway 4/0", gw1Success, gw2Success, heldErrors)
	}
	if heldErrors != 4 {
		t.Fatalf("heldErrors = %d, want 4", heldErrors)
	}

	got, err := e.svc.getPublicIP(ctx, pipTestTenant, pip.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	if got.NATGatewayID != winnerGW || got.Status != StatusActive {
		t.Fatalf("final EIP: nat_gateway_id=%q status=%q, want %q ACTIVE", got.NATGatewayID, got.Status, winnerGW)
	}
}
