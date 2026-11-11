package vpc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type fakePorts struct {
	ports []Port
	err   error
}

func (f *fakePorts) Ports(_ context.Context, t Tenant) ([]Port, error) {
	if t != testTenant {
		return nil, nil
	}
	return f.ports, f.err
}

func TestPorts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v, err := e.svc.CreateVPC(t.Context(), testTenant, CreateVPCOption{CIDR: ptr("192.168.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	sn, err := e.svc.CreateSubnet(t.Context(), testTenant, CreateSubnetOption{Name: "sn", CIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1", VPCID: v.ID})
	if err != nil {
		t.Fatal(err)
	}
	const (
		portA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		portB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		portC = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	)
	e.svc.SetPorts(&fakePorts{ports: []Port{
		{ID: portA, SubnetID: sn.ID, IP: "192.168.1.10", MAC: "fa:16:3e:00:00:01", DeviceID: "srv-1", DeviceOwner: "compute:az1", SecurityGroups: []string{"sg-1"}},
		{ID: portB, SubnetID: sn.ID, IP: "192.168.1.11", MAC: "fa:16:3e:00:00:02", DeviceID: "srv-1", DeviceOwner: "compute:az1"},
		{ID: portC, SubnetID: "gone", IP: "10.0.0.5", MAC: "fa:16:3e:00:00:03", DeviceID: "srv-2", DeviceOwner: "compute:az2"},
	}})

	status, out := e.call(t, http.MethodGet, "/ports/"+portA, "")
	if status != http.StatusOK {
		t.Fatalf("ShowPort: %d %s", status, out)
	}
	p := decodeInto[showPortResponse](t, out).Port
	if p.NetworkID != sn.ID || len(p.FixedIPs) != 1 || p.FixedIPs[0].SubnetID != sn.NeutronSubnetID || p.FixedIPs[0].IPAddress != "192.168.1.10" ||
		p.MACAddress != "fa:16:3e:00:00:01" || p.DeviceID != "srv-1" || p.Status != "ACTIVE" || p.TenantID != testProject ||
		len(p.SecurityGroups) != 1 || p.AllowedAddressPairs == nil || !p.PortSecurityEnabled {
		t.Fatalf("port = %+v", p)
	}
	// Empty lists are lists: the provider derives source_dest_check from them.
	if !strings.Contains(string(out), `"allowed_address_pairs":[]`) || !strings.Contains(string(out), `"security_groups":["sg-1"]`) {
		t.Fatalf("port JSON = %s", out)
	}
	if _, out = e.call(t, http.MethodGet, "/ports/"+portB, ""); !strings.Contains(string(out), `"security_groups":[]`) {
		t.Fatalf("port without groups = %s", out)
	}
	// A port whose subnet is gone still renders.
	if status, _ = e.call(t, http.MethodGet, "/ports/"+portC, ""); status != http.StatusOK {
		t.Fatalf("port of a deleted subnet: %d", status)
	}

	status, out = e.call(t, http.MethodGet, "/ports/dddddddd-dddd-4ddd-8ddd-dddddddddddd", "")
	wantCode(t, status, out, http.StatusNotFound, "VPC.2502")

	count := func(query string) int {
		t.Helper()
		status, out := e.call(t, http.MethodGet, "/ports"+query, "")
		if status != http.StatusOK {
			t.Fatalf("ListPorts%s: %d %s", query, status, out)
		}
		return len(decodeInto[listPortsResponse](t, out).Ports)
	}
	for query, want := range map[string]int{
		"": 3, "?device_id=srv-1": 2, "?device_id=srv-1&limit=100": 2, "?network_id=" + sn.ID: 2,
		"?mac_address=fa:16:3e:00:00:03": 1, "?id=" + portB: 1, "?status=DOWN": 0, "?name=x": 0,
		"?limit=1": 1, "?marker=" + portA: 2,
	} {
		if got := count(query); got != want {
			t.Errorf("ListPorts%s: %d ports, want %d", query, got, want)
		}
	}
	status, out = e.call(t, http.MethodGet, "/ports?limit=x", "")
	wantCode(t, status, out, http.StatusBadRequest, "VPC.2500")
	status, out = e.call(t, http.MethodGet, "/ports?marker=dddddddd-dddd-4ddd-8ddd-dddddddddddd", "")
	wantCode(t, status, out, http.StatusNotFound, "VPC.2502")

	// Another project sees no ports.
	if status, out = e.callAs(t, "ffffffffffffffffffffffffffffffff", http.MethodGet, "/ports", ""); status != http.StatusOK ||
		len(decodeInto[listPortsResponse](t, out).Ports) != 0 {
		t.Fatalf("another project: %d %s", status, out)
	}
	// Writes are not emulated.
	if status, _ = e.call(t, http.MethodPut, "/ports/"+portA, `{"port": {}}`); status != http.StatusNotImplemented {
		t.Fatalf("UpdatePort: %d", status)
	}
}

func TestPortsWithoutASource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if status, out := e.call(t, http.MethodGet, "/ports", ""); status != http.StatusOK || len(decodeInto[listPortsResponse](t, out).Ports) != 0 {
		t.Fatalf("no source: %d %s", status, out)
	}
	e.svc.SetPorts(&fakePorts{err: errors.New("broken")})
	if status, _ := e.call(t, http.MethodGet, "/ports", ""); status != http.StatusInternalServerError {
		t.Fatalf("failing source: %d", status)
	}
	if status, _ := e.call(t, http.MethodGet, "/ports/x", ""); status != http.StatusInternalServerError {
		t.Fatalf("failing source: %d", status)
	}
}

// wantCode asserts a v1 error response, {"code": ..., "message": ...}.
func wantCode(t *testing.T, status int, body []byte, wantStatus int, code string) {
	t.Helper()
	got := decodeInto[struct {
		Code string `json:"code"`
	}](t, body)
	if status != wantStatus || got.Code != code {
		t.Fatalf("got %d %s, want %d %s", status, body, wantStatus, code)
	}
}
