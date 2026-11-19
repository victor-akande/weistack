package eip

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	v3DeviceID1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	v3VPCID1    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	v3SubnetID1 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	v3DeviceID2 = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	v3VPCID2    = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	v3SubnetID2 = "ffffffff-ffff-4fff-8fff-ffffffffffff"
)

type v3PortStub struct {
	ports   map[string]vpc.Port
	subnets map[string]vpc.Subnet
}

func (p v3PortStub) Port(_ context.Context, _ vpc.Tenant, id string) (vpc.Port, bool, error) {
	port, ok := p.ports[id]
	return port, ok, nil
}

func (p v3PortStub) GetSubnet(_ context.Context, _ vpc.Tenant, id string) (vpc.Subnet, error) {
	sn, ok := p.subnets[id]
	if !ok {
		return vpc.Subnet{}, errPublicIPNotFound()
	}
	return sn, nil
}

type v3Env struct {
	svc     *Service
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	handler http.Handler
}

func newV3Env(t *testing.T) *v3Env {
	t.Helper()
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

	ports := &v3PortStub{
		ports: map[string]vpc.Port{
			pipPortID1: {
				ID:          pipPortID1,
				SubnetID:    v3SubnetID1,
				IP:          "192.168.0.10",
				MAC:         "fa:16:3e:00:00:01",
				DeviceID:    v3DeviceID1,
				DeviceOwner: "compute:ap-southeast-1a",
			},
			pipPortID2: {
				ID:          pipPortID2,
				SubnetID:    v3SubnetID2,
				IP:          "192.168.1.20",
				MAC:         "fa:16:3e:00:00:02",
				DeviceID:    v3DeviceID2,
				DeviceOwner: "compute:ap-southeast-1b",
			},
		},
		subnets: map[string]vpc.Subnet{
			v3SubnetID1: {ID: v3SubnetID1, VPCID: v3VPCID1},
			v3SubnetID2: {ID: v3SubnetID2, VPCID: v3VPCID2},
		},
	}

	gen := ids.NewSeeded(11)
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
		MaxPerProject: DefaultMaxPerProject,
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
	return &v3Env{svc: svc, engine: engine, clock: clock, handler: srv.Handler()}
}

func (e *v3Env) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(pipTestDelay)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

func (e *v3Env) callRaw(t *testing.T, method, fullPath, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, fullPath, rd)
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

func (e *v3Env) callV3(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callRaw(t, method, "/v3/"+pipTestProject+"/eip"+path, body)
}

func (e *v3Env) callV1(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callRaw(t, method, "/v1/"+pipTestProject+path, body)
}

func (e *v3Env) callV20(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callRaw(t, method, "/v2.0/"+pipTestProject+path, body)
}

func (e *v3Env) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.callV3(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "v3", goldenName+".json"), status, out)
	return out
}

func TestV3PublicIPLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newV3Env(t)

	e.expect(t, "list_publicips_empty", http.MethodGet, "/publicips", "")

	status, raw := e.callV1(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "alias": "eip-v3"},
		"bandwidth": {"name": "bw-v3", "size": 10, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("v1 create: %d %s", status, raw)
	}
	id := pipDecodeInto[createPublicIPResponse](t, raw).PublicIP.ID

	// Still PENDING_CREATE: binding, unbinding, and disassociating return VPC.0512 in v3 envelope.
	e.expect(t, "error_publicip_busy", http.MethodPost, "/publicips/"+id+"/associate-instance",
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)
	e.expect(t, "error_publicip_busy", http.MethodPost, "/publicips/"+id+"/disassociate-instance", "")
	e.expect(t, "error_publicip_busy", http.MethodPut, "/publicips/"+id,
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)
	e.expect(t, "error_publicip_busy", http.MethodPut, "/publicips/"+id,
		`{"publicip": {"associate_instance_type": null, "associate_instance_id": null}}`)

	e.settle(t)

	e.expect(t, "show_publicip", http.MethodGet, "/publicips/"+id, "")
	e.expect(t, "list_publicips", http.MethodGet, "/publicips", "")

	// Update alias and description only.
	e.expect(t, "update_publicip_meta", http.MethodPut, "/publicips/"+id,
		`{"publicip": {"alias": "eip-renamed", "description": "web frontend"}}`)

	// Associate to port 1 via associate-instance.
	e.expect(t, "associate_publicip", http.MethodPost, "/publicips/"+id+"/associate-instance",
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)

	// Add a tag via v2.0 and verify ShowPublicipV3 returns vnic, bandwidth, tags.
	status, raw = e.callV20(t, http.MethodPost, "/publicips/"+id+"/tags", `{"tag": {"key": "env", "value": "prod"}}`)
	if status != http.StatusNoContent {
		t.Fatalf("v2.0 create tag: %d %s", status, raw)
	}
	e.expect(t, "show_publicip_bound", http.MethodGet, "/publicips/"+id, "")

	// Disassociate via disassociate-instance.
	e.expect(t, "disassociate_publicip", http.MethodPost, "/publicips/"+id+"/disassociate-instance", "")

	// Disassociating an already-unbound EIP is not an error.
	e.expect(t, "disassociate_publicip_unbound", http.MethodPost, "/publicips/"+id+"/disassociate-instance", "")

	// Bind and unbind via v3 UpdatePublicip.
	e.expect(t, "update_publicip_bind", http.MethodPut, "/publicips/"+id,
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)
	e.expect(t, "update_publicip_unbind", http.MethodPut, "/publicips/"+id,
		`{"publicip": {"associate_instance_type": null, "associate_instance_id": null}}`)

	// Delete via v1, then all v3 single-resource endpoints return VPC.0504 in v3 envelope.
	status, raw = e.callV1(t, http.MethodDelete, "/publicips/"+id, "")
	if status != http.StatusNoContent {
		t.Fatalf("v1 delete: %d %s", status, raw)
	}
	e.expect(t, "error_not_found", http.MethodGet, "/publicips/"+id, "")
	e.expect(t, "error_not_found", http.MethodPut, "/publicips/"+id, `{"publicip": {"alias": "x"}}`)
	e.expect(t, "error_not_found", http.MethodPost, "/publicips/"+id+"/associate-instance",
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)
	e.expect(t, "error_not_found", http.MethodPost, "/publicips/"+id+"/disassociate-instance", "")
}

func TestV3AssociateErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newV3Env(t)

	// EIP 1 bound to port 1; EIP 2 unbound.
	status, raw1 := e.callV1(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "port_id": "`+pipPortID1+`"},
		"bandwidth": {"name": "bw-1", "size": 5, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("create 1: %d %s", status, raw1)
	}
	id1 := pipDecodeInto[createPublicIPResponse](t, raw1).PublicIP.ID

	status, raw2 := e.callV1(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp"},
		"bandwidth": {"name": "bw-2", "size": 5, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("create 2: %d %s", status, raw2)
	}
	id2 := pipDecodeInto[createPublicIPResponse](t, raw2).PublicIP.ID
	e.settle(t)

	// Associating EIP 1 with the same port it is already bound to is a no-op (200).
	status, raw := e.callV3(t, http.MethodPost, "/publicips/"+id1+"/associate-instance",
		`{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "`+pipPortID1+`"}}`)
	if status != http.StatusOK {
		t.Fatalf("associate same port: %d %s", status, raw)
	}

	tests := []struct {
		name   string
		eipID  string
		body   string
		golden string
	}{
		{"empty body", id2, ``, "error_invalid_input"},
		{"malformed json", id2, `{"publicip": `, "error_invalid_input"},
		{"missing publicip object", id2, `{}`, "error_invalid_input"},
		{"missing type", id2, `{"publicip": {"associate_instance_id": "` + pipPortID2 + `"}}`, "error_invalid_input"},
		{"missing id", id2, `{"publicip": {"associate_instance_type": "PORT"}}`, "error_invalid_input"},
		{"unknown type", id2, `{"publicip": {"associate_instance_type": "OTHER", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_invalid_input"},
		{"NATGW not implemented", id2, `{"publicip": {"associate_instance_type": "NATGW", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_not_implemented"},
		{"ELB not implemented", id2, `{"publicip": {"associate_instance_type": "ELB", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_not_implemented"},
		{"ELBV1 not implemented", id2, `{"publicip": {"associate_instance_type": "ELBV1", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_not_implemented"},
		{"VPN not implemented", id2, `{"publicip": {"associate_instance_type": "VPN", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_not_implemented"},
		{"unknown port", id2, `{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "` + pipUnknownID + `"}}`, "error_invalid_port"},
		{"port already bound", id2, `{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "` + pipPortID1 + `"}}`, "error_port_already_bound"},
		{"eip already bound to other port", id1, `{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_publicip_already_bound"},
		{"unknown eip", pipUnknownID, `{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_not_found"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, tc.golden, http.MethodPost, "/publicips/"+tc.eipID+"/associate-instance", tc.body)
		})
	}
}

func TestV3UpdateErrorCodesAndEdgeCases(t *testing.T) {
	t.Parallel()
	e := newV3Env(t)

	status, raw1 := e.callV1(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "alias": "initial", "port_id": "`+pipPortID1+`"},
		"bandwidth": {"name": "bw-1", "size": 5, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("create 1: %d %s", status, raw1)
	}
	id1 := pipDecodeInto[createPublicIPResponse](t, raw1).PublicIP.ID

	status, raw2 := e.callV1(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp"},
		"bandwidth": {"name": "bw-2", "size": 5, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("create 2: %d %s", status, raw2)
	}
	id2 := pipDecodeInto[createPublicIPResponse](t, raw2).PublicIP.ID
	e.settle(t)

	// Empty publicip object leaves binding and metadata intact.
	status, raw := e.callV3(t, http.MethodPut, "/publicips/"+id1, `{"publicip": {}}`)
	if status != http.StatusOK {
		t.Fatalf("empty update: %d %s", status, raw)
	}
	got := pipDecodeInto[publicIPInstanceV3Response](t, raw).PublicIP
	if got.Status != StatusActive || got.Alias != "initial" || got.AssociateInstanceID == nil || *got.AssociateInstanceID != pipPortID1 {
		t.Fatalf("empty update altered EIP: %+v", got)
	}

	// Clearing alias with "" and setting description leaves binding intact.
	status, raw = e.callV3(t, http.MethodPut, "/publicips/"+id1, `{"publicip": {"alias": "", "description": "cleared"}}`)
	if status != http.StatusOK {
		t.Fatalf("clear alias: %d %s", status, raw)
	}
	got = pipDecodeInto[publicIPInstanceV3Response](t, raw).PublicIP
	if got.Alias != "" || got.Description != "cleared" || got.Status != StatusActive {
		t.Fatalf("clear alias result = %+v", got)
	}

	tests := []struct {
		name   string
		eipID  string
		body   string
		golden string
	}{
		{"empty body", id2, ``, "error_invalid_input"},
		{"malformed json", id2, `{"publicip": `, "error_invalid_input"},
		{"missing publicip object", id2, `{}`, "error_invalid_input"},
		{"unknown field", id2, `{"publicip": {"bogus": 1}}`, "error_invalid_input"},
		{"invalid alias with space", id2, `{"publicip": {"alias": "bad name"}}`, "error_invalid_input"},
		{"alias over 64 chars", id2, `{"publicip": {"alias": "` + strings.Repeat("a", 65) + `"}}`, "error_invalid_input"},
		{"description over 255 chars", id2, `{"publicip": {"description": "` + strings.Repeat("d", 256) + `"}}`, "error_invalid_input"},
		{"description with angle bracket", id2, `{"publicip": {"description": "<script>"}}`, "error_invalid_input"},
		{"only associate_instance_type set", id2, `{"publicip": {"associate_instance_type": "PORT"}}`, "error_invalid_input"},
		{"only associate_instance_id set", id2, `{"publicip": {"associate_instance_id": "` + pipPortID2 + `"}}`, "error_invalid_input"},
		{"only associate_instance_type null", id2, `{"publicip": {"associate_instance_type": null}}`, "error_invalid_input"},
		{"unknown associate_instance_type", id2, `{"publicip": {"associate_instance_type": "FOO", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_invalid_input"},
		{"NATGW not implemented", id2, `{"publicip": {"associate_instance_type": "NATGW", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_not_implemented"},
		{"ELB not implemented", id2, `{"publicip": {"associate_instance_type": "ELB", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_not_implemented"},
		{"unknown port", id2, `{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "` + pipUnknownID + `"}}`, "error_invalid_port"},
		{"port already bound", id2, `{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "` + pipPortID1 + `"}}`, "error_port_already_bound"},
		{"eip already bound to other port", id1, `{"publicip": {"associate_instance_type": "PORT", "associate_instance_id": "` + pipPortID2 + `"}}`, "error_publicip_already_bound"},
		{"unknown eip", pipUnknownID, `{"publicip": {"alias": "x"}}`, "error_not_found"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, tc.golden, http.MethodPut, "/publicips/"+tc.eipID, tc.body)
		})
	}
}

func TestV3ListFiltersSortingAndPagination(t *testing.T) {
	t.Parallel()
	e := newV3Env(t)

	// Golden pagination page test with 2 unbound EIPs.
	for i, name := range []string{"alpha", "beta"} {
		st, out := e.callV1(t, http.MethodPost, "/publicips", `{
			"publicip": {"type": "5_bgp", "alias": "`+name+`"},
			"bandwidth": {"name": "bw-`+name+`", "size": 5, "share_type": "PER"}
		}`)
		if st != http.StatusOK {
			t.Fatalf("create %d: %d %s", i, st, out)
		}
	}
	e.settle(t)
	e.expect(t, "list_publicips_page", http.MethodGet, "/publicips?limit=1", "")

	// Add a 3rd EIP bound to port 1 in a custom enterprise project with traffic charge mode.
	const epCustom = "0aad99bc-f5f6-4f78-8404-c598d76b0ed2"
	st, raw3 := e.callV1(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "alias": "gamma-web", "ip_address": "198.51.100.7", "port_id": "`+pipPortID1+`"},
		"bandwidth": {"name": "bw-gamma-traffic", "size": 20, "share_type": "PER", "charge_mode": "traffic"},
		"enterprise_project_id": "`+epCustom+`"
	}`)
	if st != http.StatusOK {
		t.Fatalf("create 3: %d %s", st, raw3)
	}
	id3 := pipDecodeInto[createPublicIPResponse](t, raw3).PublicIP.ID
	e.settle(t)

	// Give EIP 3 a description via v3 Update.
	st, rawUpd := e.callV3(t, http.MethodPut, "/publicips/"+id3, `{"publicip": {"description": "edge proxy"}}`)
	if st != http.StatusOK {
		t.Fatalf("update 3: %d %s", st, rawUpd)
	}
	bw3ID := pipDecodeInto[publicIPInstanceV3Response](t, rawUpd).PublicIP.Bandwidth.ID

	list := func(query string) listPublicIPsV3Response {
		t.Helper()
		status, out := e.callV3(t, http.MethodGet, "/publicips"+query, "")
		if status != http.StatusOK {
			t.Fatalf("list %s: %d %s", query, status, out)
		}
		return pipDecodeInto[listPublicIPsV3Response](t, out)
	}

	all := list("")
	if all.TotalCount != 3 || len(all.PublicIPs) != 3 || all.PageInfo.CurrentCount != 3 || all.PageInfo.NextMarker != nil {
		t.Fatalf("list all = total:%d len:%d page:%+v", all.TotalCount, len(all.PublicIPs), all.PageInfo)
	}
	if all.PublicIPs[0].ID >= all.PublicIPs[1].ID || all.PublicIPs[1].ID >= all.PublicIPs[2].ID {
		t.Fatalf("default sort not ascending ID")
	}

	// Marker pagination across 2 pages.
	p1 := list("?limit=2")
	if p1.TotalCount != 3 || len(p1.PublicIPs) != 2 || p1.PageInfo.CurrentCount != 2 || p1.PageInfo.NextMarker == nil || *p1.PageInfo.NextMarker != all.PublicIPs[1].ID {
		t.Fatalf("page1 = total:%d len:%d page:%+v", p1.TotalCount, len(p1.PublicIPs), p1.PageInfo)
	}
	p2 := list("?limit=2&marker=" + *p1.PageInfo.NextMarker)
	if p2.TotalCount != 3 || len(p2.PublicIPs) != 1 || p2.PublicIPs[0].ID != all.PublicIPs[2].ID || p2.PageInfo.NextMarker != nil {
		t.Fatalf("page2 = total:%d len:%d page:%+v", p2.TotalCount, len(p2.PublicIPs), p2.PageInfo)
	}

	// Offset pagination and limit=0.
	off := list("?offset=1&limit=1")
	if off.TotalCount != 3 || len(off.PublicIPs) != 1 || off.PublicIPs[0].ID != all.PublicIPs[1].ID || off.PageInfo.NextMarker == nil {
		t.Fatalf("offset page = %+v", off)
	}
	zero := list("?limit=0")
	if zero.TotalCount != 3 || len(zero.PublicIPs) != 0 || zero.PageInfo.CurrentCount != 0 {
		t.Fatalf("limit=0 = %+v", zero)
	}

	// Sorting by public_ip_address desc.
	sorted := list("?sort_key=public_ip_address&sort_dir=desc")
	if sorted.PublicIPs[0].PublicIPAddress != "198.51.100.7" {
		t.Fatalf("sort desc first IP = %q, want 198.51.100.7", sorted.PublicIPs[0].PublicIPAddress)
	}

	// Query filters.
	filterChecks := []struct {
		query string
		want  int
	}{
		{"?id=" + all.PublicIPs[0].ID + "&id=" + all.PublicIPs[2].ID, 2},
		{"?ip_version=4", 3},
		{"?ip_version=6", 0},
		{"?public_ip_address=198.51.100.7", 1},
		{"?public_ip_address_like=198.51", 1},
		{"?public_ipv6_address=::1", 0},
		{"?type=EIP", 3},
		{"?type=DUALSTACK", 0},
		{"?network_type=5_bgp", 3},
		{"?publicip_pool_name=5_bgp", 3},
		{"?publicip_pool_name=5_sbgp", 0},
		{"?status=ACTIVE", 1},
		{"?status=DOWN", 2},
		{"?alias=gamma-web", 1},
		{"?alias_like=gamma", 1},
		{"?description=edge+proxy", 1},
		{"?vnic.port_id=" + pipPortID1, 1},
		{"?vnic.private_ip_address=192.168.0.10", 1},
		{"?vnic.private_ip_address_like=192.168.0", 1},
		{"?vnic.device_id=" + v3DeviceID1, 1},
		{"?vnic.device_owner=compute:ap-southeast-1a", 1},
		{"?vnic.device_owner_prefixlike=compute:", 1},
		{"?vnic.vpc_id=" + v3VPCID1, 1},
		{"?vnic.vpc_id=" + v3VPCID2, 0},
		{"?bandwidth.id=" + bw3ID, 1},
		{"?bandwidth.name=bw-gamma-traffic", 1},
		{"?bandwidth.name_like=gamma", 1},
		{"?bandwidth.size=20", 1},
		{"?bandwidth.share_type=PER", 3},
		{"?bandwidth.share_type=WHOLE", 0},
		{"?bandwidth.charge_mode=traffic", 1},
		{"?billing_mode=PAY_PER_USE", 3},
		{"?billing_mode=YEARLY_MONTHLY", 0},
		{"?associate_instance_type=PORT", 1},
		{"?associate_instance_id=" + pipPortID1, 1},
		{"?enterprise_project_id=0", 2},
		{"?enterprise_project_id=" + epCustom, 1},
		{"?enterprise_project_id=all_granted_eps", 3},
		{"?public_border_group=center", 3},
		{"?public_border_group=edge-1", 0},
	}
	for _, tc := range filterChecks {
		t.Run(tc.query, func(t *testing.T) {
			got := list(tc.query)
			if got.TotalCount != tc.want || len(got.PublicIPs) != tc.want {
				t.Errorf("GET /publicips%s: got total=%d len=%d, want %d", tc.query, got.TotalCount, len(got.PublicIPs), tc.want)
			}
		})
	}

	// List error goldens.
	e.expect(t, "error_invalid_publicip", http.MethodGet, "/publicips?limit=-1", "")
	e.expect(t, "error_invalid_publicip", http.MethodGet, "/publicips?limit=abc", "")
	e.expect(t, "error_invalid_publicip", http.MethodGet, "/publicips?limit=2001", "")
	e.expect(t, "error_invalid_publicip", http.MethodGet, "/publicips?offset=-1", "")
	e.expect(t, "error_invalid_publicip", http.MethodGet, "/publicips?offset=100000", "")
	e.expect(t, "error_invalid_publicip", http.MethodGet, "/publicips?sort_key=bogus", "")
	e.expect(t, "error_invalid_publicip", http.MethodGet, "/publicips?sort_dir=sideways", "")
	e.expect(t, "error_not_found", http.MethodGet, "/publicips?marker="+pipUnknownID, "")
}

type staticPortSource struct {
	ports []vpc.Port
}

func (s staticPortSource) Ports(_ context.Context, _ vpc.Tenant) ([]vpc.Port, error) {
	return s.ports, nil
}

func TestV3ResolvesVPCIDViaRealVPCService(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(pipTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: 0, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(23)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	v, err := vpcSvc.CreateVPC(ctx, pipTestTenant, vpc.CreateVPCOption{Name: pipPtr("vpc-v3"), CIDR: pipPtr("10.0.0.0/16")})
	if err != nil {
		t.Fatalf("CreateVPC: %v", err)
	}
	sn, err := vpcSvc.CreateSubnet(ctx, pipTestTenant, vpc.CreateSubnetOption{
		Name:      "sn-v3",
		CIDR:      "10.0.1.0/24",
		GatewayIP: "10.0.1.1",
		VPCID:     v.ID,
	})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	vpcSvc.SetPorts(staticPortSource{
		ports: []vpc.Port{{
			ID:          pipPortID1,
			SubnetID:    sn.ID,
			IP:          "10.0.1.10",
			MAC:         "fa:16:3e:11:22:33",
			DeviceID:    v3DeviceID1,
			DeviceOwner: "compute:ap-southeast-1a",
		}},
	})

	eipSvc, err := New(Deps{
		Store:         st,
		Engine:        engine,
		IDs:           gen,
		Logger:        log,
		Ports:         vpcSvc,
		MaxPerProject: DefaultMaxPerProject,
		Now:           clock.Now,
	})
	if err != nil {
		t.Fatalf("eip.New: %v", err)
	}
	req := pipPerReq("bw-real-vpc", 5)
	req.PublicIP.PortID = pipPtr(pipPortID1)
	created, err := eipSvc.createPublicIP(ctx, pipTestTenant, req)
	if err != nil {
		t.Fatalf("createPublicIP: %v", err)
	}
	if err := engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
	got, err := eipSvc.getPublicIP(ctx, pipTestTenant, created.ID)
	if err != nil {
		t.Fatalf("getPublicIP: %v", err)
	}
	resp, err := eipSvc.toPublicIPSingleShowResp(ctx, pipTestTenant, got)
	if err != nil {
		t.Fatalf("toPublicIPSingleShowResp: %v", err)
	}
	if resp.Vnic == nil {
		t.Fatalf("expected non-nil vnic")
	}
	if resp.Vnic.VPCID != v.ID || resp.Vnic.PortID != pipPortID1 || resp.Vnic.PrivateIPAddress != "10.0.1.10" || resp.Vnic.MAC != "fa:16:3e:11:22:33" || resp.Vnic.DeviceID != v3DeviceID1 {
		t.Fatalf("unexpected vnic = %+v, want VPCID=%s", resp.Vnic, v.ID)
	}
}
