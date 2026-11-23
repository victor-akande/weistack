package eip

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

type quotaListResp struct {
	Quotas struct {
		Resources []vpc.QuotaResource `json:"resources"`
	} `json:"quotas"`
}

func newPIPEnvWithQuotas(t *testing.T, st store.Store, limits quota.Limits) *pipEnv {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(pipTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: pipTestDelay, Clock: clock, Logger: log})

	ctx := t.Context()
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
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
	vpcSvc, err := vpc.New(vpc.Deps{Quotas: limits, Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	svc, err := New(Deps{
		Quotas: limits,
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		Ports:  ports,
		Now:    clock.Now,
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

func TestEIPQuotasThroughVPCEndpoint(t *testing.T) {
	t.Parallel()
	defaults := quota.Limits{}
	e := newPIPEnvWithQuotas(t, store.NewMemory(), defaults)

	// Empty state: VPC's 4 resources followed by EIP's 3 resources in exact order.
	status, raw := e.call(t, http.MethodGet, "/quotas", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas: %d %s", status, raw)
	}
	got := pipDecodeInto[quotaListResp](t, raw).Quotas.Resources
	want := []vpc.QuotaResource{
		{Type: "vpc", Used: 0, Quota: defaults.Get(quota.VPCVPC), Min: 0},
		{Type: "subnet", Used: 0, Quota: defaults.Get(quota.VPCSubnet), Min: 0},
		{Type: "securityGroup", Used: 0, Quota: defaults.Get(quota.VPCSecurityGroup), Min: 0},
		{Type: "securityGroupRule", Used: 0, Quota: defaults.Get(quota.VPCSecurityGroupRule), Min: 0},
		{Type: "publicIp", Used: 0, Quota: defaults.Get(quota.VPCPublicIP), Min: 0},
		{Type: "shareBandwidth", Used: 0, Quota: defaults.Get(quota.VPCShareBandwidth), Min: 0},
		{Type: "shareBandwidthIP", Used: 0, Quota: defaults.Get(quota.VPCShareBandwidthIP), Min: 0},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("initial quotas =\n%+v\nwant\n%+v", got, want)
	}

	// Create 3 EIPs (with PER bandwidths) and 2 WHOLE shared bandwidths.
	ctx := t.Context()
	pip1, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("per-1", 5))
	if err != nil {
		t.Fatalf("create pip1: %v", err)
	}
	pip2, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("per-2", 5))
	if err != nil {
		t.Fatalf("create pip2: %v", err)
	}
	pip3, err := e.svc.createPublicIP(ctx, pipTestTenant, pipPerReq("per-3", 5))
	if err != nil {
		t.Fatalf("create pip3: %v", err)
	}
	e.settle(t)

	bw1, err := e.svc.CreateSharedBandwidth(ctx, pipTestTenant, createSharedBandwidthOption{Name: "share-1", Size: 10})
	if err != nil {
		t.Fatalf("create bw1: %v", err)
	}
	bw2, err := e.svc.CreateSharedBandwidth(ctx, pipTestTenant, createSharedBandwidthOption{Name: "share-2", Size: 10})
	if err != nil {
		t.Fatalf("create bw2: %v", err)
	}

	// Add 2 EIPs to bw1 and 1 EIP to bw2; shareBandwidthIP used should report the max (2).
	if _, err := e.svc.AddPublicIPsIntoSharedBandwidth(ctx, pipTestTenant, bw1.ID, addPublicIPsIntoSharedBandwidthOption{
		PublicIPInfo: []insertPublicIPInfo{{PublicIPID: pip1.ID}, {PublicIPID: pip2.ID}},
	}); err != nil {
		t.Fatalf("add to bw1: %v", err)
	}
	if _, err := e.svc.AddPublicIPsIntoSharedBandwidth(ctx, pipTestTenant, bw2.ID, addPublicIPsIntoSharedBandwidthOption{
		PublicIPInfo: []insertPublicIPInfo{{PublicIPID: pip3.ID}},
	}); err != nil {
		t.Fatalf("add to bw2: %v", err)
	}

	// Verify filtered queries for each EIP quota type.
	for _, tc := range []struct {
		typ  string
		want vpc.QuotaResource
	}{
		{"publicIp", vpc.QuotaResource{Type: "publicIp", Used: 3, Quota: defaults.Get(quota.VPCPublicIP), Min: 0}},
		{"shareBandwidth", vpc.QuotaResource{Type: "shareBandwidth", Used: 2, Quota: defaults.Get(quota.VPCShareBandwidth), Min: 0}},
		{"shareBandwidthIP", vpc.QuotaResource{Type: "shareBandwidthIP", Used: 2, Quota: defaults.Get(quota.VPCShareBandwidthIP), Min: 0}},
	} {
		status, raw := e.call(t, http.MethodGet, "/quotas?type="+tc.typ, "")
		if status != http.StatusOK {
			t.Fatalf("GET /quotas?type=%s: %d %s", tc.typ, status, raw)
		}
		got := pipDecodeInto[quotaListResp](t, raw).Quotas.Resources
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("type=%s: got %+v, want [%+v]", tc.typ, got, tc.want)
		}
	}

	// Remove one EIP from bw1 -> max shared bandwidth IPs drops from 2 to 1.
	if err := e.svc.RemovePublicIPsFromSharedBandwidth(ctx, pipTestTenant, bw1.ID, removeFromSharedBandwidthOption{
		ChargeMode:   ChargeModeBandwidth,
		Size:         5,
		PublicIPInfo: []removePublicIPInfo{{PublicIPID: pip1.ID}},
	}); err != nil {
		t.Fatalf("remove from bw1: %v", err)
	}
	status, raw = e.call(t, http.MethodGet, "/quotas?type=shareBandwidthIP", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas?type=shareBandwidthIP after remove: %d %s", status, raw)
	}
	gotShareIP := pipDecodeInto[quotaListResp](t, raw).Quotas.Resources
	if len(gotShareIP) != 1 || gotShareIP[0].Used != 1 {
		t.Fatalf("shareBandwidthIP after remove = %+v, want used=1", gotShareIP)
	}

	// CountPublicIPs matches tenant A and stays 0 for tenant B.
	nA, err := e.svc.CountPublicIPs(ctx, pipTestTenant)
	if err != nil || nA != 3 {
		t.Fatalf("CountPublicIPs(A) = %d (err %v), want 3", nA, err)
	}
	nB, err := e.svc.CountPublicIPs(ctx, pipTestTenantB)
	if err != nil || nB != 0 {
		t.Fatalf("CountPublicIPs(B) = %d (err %v), want 0", nB, err)
	}

	// Unknown type returns 400 VPC.1207.
	status, raw = e.call(t, http.MethodGet, "/quotas?type=nope", "")
	if status != http.StatusBadRequest {
		t.Fatalf("GET /quotas?type=nope: status %d, want 400: %s", status, raw)
	}
	var errBody struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &errBody); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if errBody.Code != "VPC.1207" || errBody.Message != "Invalid resource type." {
		t.Fatalf("got (%q, %q), want (VPC.1207, Invalid resource type.)", errBody.Code, errBody.Message)
	}
}

func TestEIPQuotasCustomLimitsAndOverLimit(t *testing.T) {
	t.Parallel()
	pipLimit, seeded := 1, 3
	shareBWLimit := 2
	st := store.NewMemory()
	col := store.Of[publicIP](st, store.Scope{Region: pipTestRegion, ProjectID: pipTestProject, Kind: kindPublicIP})
	for i := range seeded {
		id := fmt.Sprintf("00000000-0000-0000-0000-00000000000%d", i+1)
		if err := col.Create(t.Context(), id, publicIP{
			ID:      id,
			Type:    "5_bgp",
			Address: fmt.Sprintf("192.0.2.%d", i+1),
			Status:  StatusDown,
		}); err != nil {
			t.Fatalf("seed publicip: %v", err)
		}
	}

	limits := quota.For(map[quota.Key]int{
		quota.VPCPublicIP:         pipLimit,
		quota.VPCShareBandwidth:   shareBWLimit,
		quota.VPCShareBandwidthIP: quota.Unlimited,
	})
	e := newPIPEnvWithQuotas(t, st, limits)

	status, raw := e.call(t, http.MethodGet, "/quotas?type=publicIp", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas?type=publicIp: %d %s", status, raw)
	}
	got := pipDecodeInto[quotaListResp](t, raw).Quotas.Resources
	want := vpc.QuotaResource{Type: "publicIp", Used: seeded, Quota: pipLimit, Min: 0}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("over-limit publicIp = %+v, want [%+v]", got, want)
	}

	status, raw = e.call(t, http.MethodGet, "/quotas?type=shareBandwidthIP", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas?type=shareBandwidthIP: %d %s", status, raw)
	}
	gotUnlim := pipDecodeInto[quotaListResp](t, raw).Quotas.Resources
	wantUnlim := vpc.QuotaResource{Type: "shareBandwidthIP", Used: 0, Quota: quota.Unlimited, Min: 0}
	if len(gotUnlim) != 1 || gotUnlim[0] != wantUnlim {
		t.Fatalf("unlimited shareBandwidthIP = %+v, want [%+v]", gotUnlim, wantUnlim)
	}
}
