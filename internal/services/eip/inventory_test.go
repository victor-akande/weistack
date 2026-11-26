package eip

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

type invPortStub struct {
	ports     map[string]vpc.Port
	subnets   map[string]vpc.Subnet
	portErr   error
	subnetErr error
}

func (p *invPortStub) Port(_ context.Context, _ vpc.Tenant, id string) (vpc.Port, bool, error) {
	if p.portErr != nil {
		return vpc.Port{}, false, p.portErr
	}
	port, ok := p.ports[id]
	return port, ok, nil
}

func (p *invPortStub) GetSubnet(_ context.Context, _ vpc.Tenant, id string) (vpc.Subnet, error) {
	if p.subnetErr != nil {
		return vpc.Subnet{}, p.subnetErr
	}
	sn, ok := p.subnets[id]
	if !ok {
		return vpc.Subnet{}, errPublicIPNotFound()
	}
	return sn, nil
}

type peerReporter []inventory.Resource

func (p peerReporter) ReportResources(_ context.Context, emit func(inventory.Resource) error) error {
	for _, r := range p {
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}

func TestReportResources(t *testing.T) {
	t.Parallel()

	const (
		computePortID  = "11111111-aaaa-4111-8111-111111111111"
		vanishedPortID = "22222222-bbbb-4222-8222-222222222222"
		serverID       = "33333333-cccc-4333-8333-333333333333"
		vpcID          = "44444444-dddd-4444-8444-444444444444"
		subnetID       = "55555555-eeee-4555-8555-555555555555"
		missingSubID   = "66666666-ffff-4666-8666-666666666666"
		customEP       = "77777777-aaaa-4777-8777-777777777777"
		accountA       = "acct-primary"
		accountB       = "acct-secondary"
	)

	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(pipTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: pipTestDelay, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	ports := &invPortStub{
		ports: map[string]vpc.Port{
			computePortID: {
				ID:          computePortID,
				SubnetID:    subnetID,
				IP:          "192.168.0.10",
				MAC:         "fa:16:3e:00:00:01",
				DeviceID:    serverID,
				DeviceOwner: "compute:ap-southeast-1a",
			},
			elbVIPPort1: {
				ID:          elbVIPPort1,
				SubnetID:    missingSubID,
				IP:          elbVIPAddr1,
				MAC:         "fa:16:3e:00:00:02",
				DeviceID:    elbID1,
				DeviceOwner: "neutron:LOADBALANCERV2",
			},
			vanishedPortID: {
				ID:          vanishedPortID,
				SubnetID:    subnetID,
				IP:          "192.168.0.30",
				MAC:         "fa:16:3e:00:00:03",
				DeviceID:    serverID,
				DeviceOwner: "compute:ap-southeast-1a",
			},
		},
		subnets: map[string]vpc.Subnet{
			subnetID: {ID: subnetID, VPCID: vpcID},
		},
	}

	gen := ids.NewSeeded(29)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	svc, err := New(Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Ports: ports, Now: clock.Now})
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
	handler := srv.Handler()

	call := func(method, fullPath, body string) (int, []byte) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		r := httptest.NewRequest(method, fullPath, rd)
		r.Host = pipTestHost
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		res := w.Result()
		defer res.Body.Close()
		out, readErr := io.ReadAll(res.Body)
		if readErr != nil {
			t.Fatalf("reading response: %v", readErr)
		}
		return res.StatusCode, out
	}

	settle := func() {
		t.Helper()
		clock.Advance(pipTestDelay)
		wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer wcancel()
		if werr := engine.WaitIdle(wctx); werr != nil {
			t.Fatalf("WaitIdle: %v", werr)
		}
	}

	// 1. Shared bandwidth over the v2.0 HTTP API.
	status, raw := call(http.MethodPost, "/v2.0/"+pipTestProject+"/bandwidths",
		fmt.Sprintf(`{"bandwidth": {"name": "bw-shared", "size": 20, "enterprise_project_id": %q}}`, customEP))
	if status != http.StatusOK {
		t.Fatalf("creating shared bandwidth: %d %s", status, raw)
	}
	sharedBW := pipDecodeInto[bandwidthResponse](t, raw).Bandwidth

	// 2. EIP in the shared bandwidth with alias, custom EP, tag, and bound to a compute port in a VPC subnet.
	status, raw = call(http.MethodPost, "/v1/"+pipTestProject+"/publicips",
		fmt.Sprintf(`{"publicip": {"type": "5_bgp", "alias": "web-eip"}, "bandwidth": {"share_type": "WHOLE", "id": %q}, "enterprise_project_id": %q}`,
			sharedBW.ID, customEP))
	if status != http.StatusOK {
		t.Fatalf("creating compute EIP: %d %s", status, raw)
	}
	computeEIPID := pipDecodeInto[createPublicIPResponse](t, raw).PublicIP.ID

	// 3. Second EIP in the shared bandwidth (no alias, no tags), bound to a NAT gateway.
	status, raw = call(http.MethodPost, "/v1/"+pipTestProject+"/publicips",
		fmt.Sprintf(`{"publicip": {"type": "5_bgp"}, "bandwidth": {"share_type": "WHOLE", "id": %q}}`, sharedBW.ID))
	if status != http.StatusOK {
		t.Fatalf("creating NAT EIP: %d %s", status, raw)
	}
	natEIPID := pipDecodeInto[createPublicIPResponse](t, raw).PublicIP.ID

	// 4. EIP with dedicated PER bandwidth, bound to an ELB whose VIP port has a non-compute owner and missing subnet.
	status, raw = call(http.MethodPost, "/v1/"+pipTestProject+"/publicips",
		`{"publicip": {"type": "5_bgp", "alias": "elb-eip"}, "bandwidth": {"name": "bw-elb", "size": 10, "share_type": "PER"}}`)
	if status != http.StatusOK {
		t.Fatalf("creating ELB EIP: %d %s", status, raw)
	}
	elbEIPID := pipDecodeInto[createPublicIPResponse](t, raw).PublicIP.ID

	// 5. EIP bound to a port that disappears before collection (missing port case).
	status, raw = call(http.MethodPost, "/v1/"+pipTestProject+"/publicips",
		fmt.Sprintf(`{"publicip": {"type": "5_bgp", "alias": "orphan-eip", "port_id": %q}, "bandwidth": {"name": "bw-orphan", "size": 5, "share_type": "PER"}}`,
			vanishedPortID))
	if status != http.StatusOK {
		t.Fatalf("creating orphan-port EIP: %d %s", status, raw)
	}
	orphanEIPID := pipDecodeInto[createPublicIPResponse](t, raw).PublicIP.ID

	settle()

	clock.Advance(3 * time.Second)
	status, raw = call(http.MethodPut, "/v1/"+pipTestProject+"/publicips/"+computeEIPID,
		fmt.Sprintf(`{"publicip": {"port_id": %q}}`, computePortID))
	if status != http.StatusOK {
		t.Fatalf("binding compute EIP: %d %s", status, raw)
	}
	status, raw = call(http.MethodPost, "/v2.0/"+pipTestProject+"/publicips/"+computeEIPID+"/tags",
		`{"tag": {"key": "env", "value": "prod"}}`)
	if status != http.StatusNoContent {
		t.Fatalf("tagging compute EIP: %d %s", status, raw)
	}

	if _, err := svc.HoldForNAT(t.Context(), pipTestTenant, natEIPID, natGatewayID1); err != nil {
		t.Fatalf("HoldForNAT: %v", err)
	}
	if _, err := svc.BindToELB(t.Context(), pipTestTenant, elbEIPID, elbID1, elbVIPPort1, elbVIPAddr1); err != nil {
		t.Fatalf("BindToELB: %v", err)
	}
	delete(ports.ports, vanishedPortID)

	// 6. EIP in a second project, left in PENDING_CREATE.
	status, raw = call(http.MethodPost, "/v1/"+pipTestProjectB+"/publicips",
		`{"publicip": {"type": "5_bgp", "alias": "pending-b"}, "bandwidth": {"name": "bw-b", "size": 5, "share_type": "PER"}}`)
	if status != http.StatusOK {
		t.Fatalf("creating second-project EIP: %d %s", status, raw)
	}
	otherEIPID := pipDecodeInto[createPublicIPResponse](t, raw).PublicIP.ID

	elbRec, err := svc.getPublicIP(t.Context(), pipTestTenant, elbEIPID)
	if err != nil {
		t.Fatalf("getPublicIP(elb): %v", err)
	}
	orphanRec, err := svc.getPublicIP(t.Context(), pipTestTenant, orphanEIPID)
	if err != nil {
		t.Fatalf("getPublicIP(orphan): %v", err)
	}
	otherRec, err := svc.getPublicIP(t.Context(), pipTestTenantB, otherEIPID)
	if err != nil {
		t.Fatalf("getPublicIP(other): %v", err)
	}

	peers := peerReporter{
		{Type: inventory.ECSServers, ID: serverID, RegionID: pipTestRegion, ProjectID: pipTestProject},
		{Type: inventory.VPCs, ID: vpcID, RegionID: pipTestRegion, ProjectID: pipTestProject},
		{Type: inventory.NATGateways, ID: natGatewayID1, RegionID: pipTestRegion, ProjectID: pipTestProject},
		{Type: inventory.ELBLoadBalancers, ID: elbID1, RegionID: pipTestRegion, ProjectID: pipTestProject},
	}
	owners := map[string]string{
		pipTestProject:  accountA,
		pipTestProjectB: accountB,
	}

	inv := inventory.New(inventory.Options{
		Reporters: []inventory.Reporter{svc, peers},
		Owner: func(projectID, _ string) (string, bool) {
			acct, ok := owners[projectID]
			return acct, ok
		},
	})
	snap, err := inv.Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := make(map[string]inventory.Resource, len(snap.Resources))
	for _, r := range snap.Resources {
		got[r.Type.String()+"/"+r.ProjectID+"/"+r.ID] = r
	}
	at := func(typ inventory.Type, project, id string) inventory.Resource {
		t.Helper()
		r, ok := got[typ.String()+"/"+project+"/"+id]
		if !ok {
			t.Fatalf("%s %s in %s is not reported; got %v", typ, id, project, snap.Resources)
		}
		return r
	}

	comp := at(inventory.EIPPublicIPs, pipTestProject, computeEIPID)
	if comp.Name != "web-eip" || comp.RegionID != pipTestRegion || comp.AccountID != accountA ||
		comp.EnterpriseProjectID != customEP || comp.State != inventory.Succeeded ||
		comp.Created.IsZero() || !comp.Updated.After(comp.Created) ||
		!reflect.DeepEqual(comp.Tags, map[string]string{"env": "prod"}) {
		t.Errorf("compute EIP = %+v", comp)
	}
	wantCompRels := []inventory.Ref{
		{Relation: inventory.IsAttachedTo, Type: inventory.ECSServers, ID: serverID},
		{Relation: inventory.IsContainedIn, Type: inventory.EIPBandwidths, ID: sharedBW.ID},
		{Relation: inventory.IsContainedIn, Type: inventory.VPCs, ID: vpcID},
	}
	if !reflect.DeepEqual(comp.Relations, wantCompRels) {
		t.Errorf("compute EIP relations = %+v, want %+v", comp.Relations, wantCompRels)
	}

	natEIP := at(inventory.EIPPublicIPs, pipTestProject, natEIPID)
	if natEIP.Name != "" || natEIP.RegionID != pipTestRegion || natEIP.AccountID != accountA ||
		natEIP.EnterpriseProjectID != "0" || natEIP.State != inventory.Succeeded ||
		natEIP.Created.IsZero() || len(natEIP.Tags) != 0 {
		t.Errorf("NAT EIP = %+v", natEIP)
	}
	wantNATRels := []inventory.Ref{
		{Relation: inventory.IsAttachedTo, Type: inventory.NATGateways, ID: natGatewayID1},
		{Relation: inventory.IsContainedIn, Type: inventory.EIPBandwidths, ID: sharedBW.ID},
	}
	if !reflect.DeepEqual(natEIP.Relations, wantNATRels) {
		t.Errorf("NAT EIP relations = %+v, want %+v", natEIP.Relations, wantNATRels)
	}

	elbEIP := at(inventory.EIPPublicIPs, pipTestProject, elbEIPID)
	if elbEIP.Name != "elb-eip" || elbEIP.State != inventory.Succeeded || elbEIP.Created.IsZero() {
		t.Errorf("ELB EIP = %+v", elbEIP)
	}
	wantELBRels := []inventory.Ref{
		{Relation: inventory.IsAttachedTo, Type: inventory.ELBLoadBalancers, ID: elbID1},
		{Relation: inventory.IsContainedIn, Type: inventory.EIPBandwidths, ID: elbRec.BandwidthID},
	}
	if !reflect.DeepEqual(elbEIP.Relations, wantELBRels) {
		t.Errorf("ELB EIP relations = %+v, want %+v", elbEIP.Relations, wantELBRels)
	}

	orphanEIP := at(inventory.EIPPublicIPs, pipTestProject, orphanEIPID)
	wantOrphanRels := []inventory.Ref{
		{Relation: inventory.IsContainedIn, Type: inventory.EIPBandwidths, ID: orphanRec.BandwidthID},
	}
	if !reflect.DeepEqual(orphanEIP.Relations, wantOrphanRels) {
		t.Errorf("orphan-port EIP relations = %+v, want %+v", orphanEIP.Relations, wantOrphanRels)
	}

	otherEIP := at(inventory.EIPPublicIPs, pipTestProjectB, otherEIPID)
	if otherEIP.Name != "pending-b" || otherEIP.RegionID != pipTestRegion || otherEIP.AccountID != accountB ||
		otherEIP.State != inventory.Processing || otherEIP.Created.IsZero() {
		t.Errorf("second-project EIP = %+v", otherEIP)
	}
	wantOtherRels := []inventory.Ref{
		{Relation: inventory.IsContainedIn, Type: inventory.EIPBandwidths, ID: otherRec.BandwidthID},
	}
	if !reflect.DeepEqual(otherEIP.Relations, wantOtherRels) {
		t.Errorf("second-project EIP relations = %+v, want %+v", otherEIP.Relations, wantOtherRels)
	}

	sbw := at(inventory.EIPBandwidths, pipTestProject, sharedBW.ID)
	if sbw.Name != "bw-shared" || sbw.RegionID != pipTestRegion || sbw.AccountID != accountA ||
		sbw.EnterpriseProjectID != customEP || sbw.State != inventory.Succeeded ||
		sbw.Created.IsZero() || len(sbw.Tags) != 0 {
		t.Errorf("shared bandwidth = %+v", sbw)
	}
	sharedIPs := []string{computeEIPID, natEIPID}
	slices.SortFunc(sharedIPs, cmp.Compare[string])
	wantSharedBWRels := []inventory.Ref{
		{Relation: inventory.Contains, Type: inventory.EIPPublicIPs, ID: sharedIPs[0]},
		{Relation: inventory.Contains, Type: inventory.EIPPublicIPs, ID: sharedIPs[1]},
	}
	if !reflect.DeepEqual(sbw.Relations, wantSharedBWRels) {
		t.Errorf("shared bandwidth relations = %+v, want %+v", sbw.Relations, wantSharedBWRels)
	}

	ebw := at(inventory.EIPBandwidths, pipTestProject, elbRec.BandwidthID)
	if ebw.Name != "bw-elb" || ebw.State != inventory.Succeeded ||
		!reflect.DeepEqual(ebw.Relations, []inventory.Ref{{Relation: inventory.Contains, Type: inventory.EIPPublicIPs, ID: elbEIPID}}) {
		t.Errorf("ELB bandwidth = %+v", ebw)
	}

	obw := at(inventory.EIPBandwidths, pipTestProject, orphanRec.BandwidthID)
	if obw.Name != "bw-orphan" || obw.State != inventory.Succeeded ||
		!reflect.DeepEqual(obw.Relations, []inventory.Ref{{Relation: inventory.Contains, Type: inventory.EIPPublicIPs, ID: orphanEIPID}}) {
		t.Errorf("orphan bandwidth = %+v", obw)
	}

	otherBW := at(inventory.EIPBandwidths, pipTestProjectB, otherRec.BandwidthID)
	if otherBW.Name != "bw-b" || otherBW.AccountID != accountB || otherBW.State != inventory.Succeeded ||
		!reflect.DeepEqual(otherBW.Relations, []inventory.Ref{{Relation: inventory.Contains, Type: inventory.EIPPublicIPs, ID: otherEIPID}}) {
		t.Errorf("second-project bandwidth = %+v", otherBW)
	}

	// Exact per-type counts prove internal eip.address records are not reported.
	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.EIPPublicIPs:     5,
		inventory.EIPBandwidths:    4,
		inventory.ECSServers:       1,
		inventory.VPCs:             1,
		inventory.NATGateways:      1,
		inventory.ELBLoadBalancers: 1,
	}
	if !reflect.DeepEqual(count, want) {
		t.Errorf("reported %v, want %v", count, want)
	}

	// Non-not-found errors from port and subnet lookups are returned.
	boom := errors.New("store read failure")
	ports.subnetErr = boom
	if _, err := inv.Collect(t.Context()); !errors.Is(err, boom) {
		t.Errorf("Collect with subnet error = %v, want %v", err, boom)
	}
	ports.subnetErr = nil
	ports.portErr = boom
	if _, err := inv.Collect(t.Context()); !errors.Is(err, boom) {
		t.Errorf("Collect with port error = %v, want %v", err, boom)
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	for status, want := range map[string]inventory.State{
		StatusPendingCreate: inventory.Processing,
		StatusDown:          inventory.Succeeded,
		StatusActive:        inventory.Succeeded,
		"ERROR":             inventory.Failed,
	} {
		if got := publicIPState(status); got != want {
			t.Errorf("publicIPState(%s) = %s, want %s", status, got, want)
		}
	}
}
