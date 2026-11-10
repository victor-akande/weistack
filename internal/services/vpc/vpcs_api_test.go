package vpc

import (
	"net/http"
	"strings"
	"testing"
)

func TestVPCLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	e.expect(t, "list_vpcs_empty", http.MethodGet, "/vpcs", "")

	out := e.expect(t, "create_vpc", http.MethodPost, "/vpcs",
		`{"vpc": {"name": "vpc", "description": "test", "cidr": "192.168.0.0/16"}}`)
	id := decodeInto[vpcResponse](t, out).VPC.ID

	// Still CREATING until the lifecycle delay has passed.
	e.expect(t, "error_vpc_busy", http.MethodDelete, "/vpcs/"+id, "")
	e.settle(t)
	e.expect(t, "show_vpc", http.MethodGet, "/vpcs/"+id, "")

	e.mustCreateVPC(t, "vpc-2", "10.0.0.0/8")
	e.expect(t, "list_vpcs", http.MethodGet, "/vpcs", "")

	e.expect(t, "update_vpc", http.MethodPut, "/vpcs/"+id,
		`{"vpc": {"name": "vpc1", "description": "test1"}}`)

	e.expect(t, "delete_vpc", http.MethodDelete, "/vpcs/"+id, "")
	e.expect(t, "error_vpc_not_found", http.MethodGet, "/vpcs/"+id, "")
	e.expect(t, "error_vpc_not_found", http.MethodDelete, "/vpcs/"+id, "")
	e.expect(t, "error_vpc_not_found", http.MethodPut, "/vpcs/"+id, `{"vpc": {"name": "x"}}`)
}

func TestCreateVPCRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mustCreateVPC(t, "taken", "192.168.0.0/16")

	tests := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_vpc_invalid"},
		{"malformed json", `{"vpc": `, "error_vpc_invalid"},
		{"missing vpc object", `{}`, "error_vpc_invalid"},
		{"wrong field type", `{"vpc": {"name": 5}}`, "error_vpc_invalid"},
		{"name too long", `{"vpc": {"name": "` + strings.Repeat("a", 65) + `"}}`, "error_vpc_invalid"},
		{"name with a space", `{"vpc": {"name": "my vpc"}}`, "error_vpc_invalid"},
		{"description with angle bracket", `{"vpc": {"description": "<script>"}}`, "error_vpc_invalid"},
		{"description too long", `{"vpc": {"description": "` + strings.Repeat("d", 256) + `"}}`, "error_vpc_invalid"},
		{"cidr not a cidr", `{"vpc": {"cidr": "192.168.0.0"}}`, "error_vpc_invalid"},
		{"cidr with host bits", `{"vpc": {"cidr": "192.168.1.1/16"}}`, "error_vpc_invalid"},
		{"cidr mask too long", `{"vpc": {"cidr": "192.168.0.0/25"}}`, "error_vpc_invalid"},
		{"cidr mask too short", `{"vpc": {"cidr": "8.0.0.0/7"}}`, "error_vpc_invalid"},
		{"cidr in a reserved range", `{"vpc": {"cidr": "169.254.0.0/16"}}`, "error_vpc_invalid"},
		{"ipv6 cidr", `{"vpc": {"cidr": "2001:db8::/32"}}`, "error_vpc_invalid"},
		{"bad enterprise project", `{"vpc": {"enterprise_project_id": "nope"}}`, "error_vpc_invalid"},
		{"bad block state", `{"vpc": {"block_service_endpoint_states": "maybe"}}`, "error_vpc_invalid"},
		{"duplicate name", `{"vpc": {"name": "taken"}}`, "error_vpc_name_exists"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, "/vpcs", tt.body)
		})
	}

	// None of the rejected requests may have left a VPC behind.
	_, out := e.call(t, http.MethodGet, "/vpcs", "")
	if got := len(decodeInto[listVPCsResponse](t, out).VPCs); got != 1 {
		t.Fatalf("%d VPCs exist after rejected creates, want 1", got)
	}
}

func TestCreateVPCDefaultsAndOptionalFields(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	// Every field is optional; unnamed VPCs may coexist.
	for range 2 {
		status, out := e.call(t, http.MethodPost, "/vpcs", `{"vpc": {}}`)
		if status != http.StatusOK {
			t.Fatalf("minimal create: %d %s", status, out)
		}
		v := decodeInto[vpcResponse](t, out).VPC
		if v.Name != "" || v.CIDR != "" || v.EnterpriseProjectID != "0" || v.TenantID != testProject {
			t.Fatalf("defaults = %+v", v)
		}
	}

	status, out := e.call(t, http.MethodPost, "/vpcs", `{"vpc": {
		"name": "网络-1.prod_a", "cidr": "172.16.0.0/12",
		"enterprise_project_id": "0aad99bc-f5f6-4f78-8404-c598d76b0ed2",
		"block_service_endpoint_states": "on", "enable_network_address_usage_metrics": true,
		"tags": ["env*prod"]}}`)
	if status != http.StatusOK {
		t.Fatalf("full create: %d %s", status, out)
	}
	v := decodeInto[vpcResponse](t, out).VPC
	if v.Name != "网络-1.prod_a" || v.EnterpriseProjectID != "0aad99bc-f5f6-4f78-8404-c598d76b0ed2" ||
		v.BlockServiceEndpointStates != "on" || !v.EnableNetworkAddressUsageMetrics {
		t.Fatalf("created = %+v", v)
	}
	if got := v.CreatedAt; !timeEqual(got, testEpoch) {
		t.Fatalf("created_at = %v, want the clock's %v", got, testEpoch)
	}
}

func TestUpdateVPC(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.mustCreateVPC(t, "a", "192.168.0.0/16")
	e.mustCreateVPC(t, "b", "10.0.0.0/8")

	e.clock.Advance(90 * 1e9)
	status, out := e.call(t, http.MethodPut, "/vpcs/"+a.ID, `{"vpc": {
		"cidr": "192.168.0.0/18", "enable_network_address_usage_metrics": true,
		"routes": [{"destination": "0.0.0.0/0", "nexthop": "192.168.0.5"}]}}`)
	if status != http.StatusOK {
		t.Fatalf("update: %d %s", status, out)
	}
	v := decodeInto[vpcResponse](t, out).VPC
	if v.Name != "a" || v.CIDR != "192.168.0.0/18" || !v.EnableNetworkAddressUsageMetrics ||
		len(v.Routes) != 1 || v.Routes[0].Nexthop != "192.168.0.5" {
		t.Fatalf("updated = %+v", v)
	}
	if timeEqual(v.UpdatedAt, testEpoch) || !timeEqual(v.CreatedAt, testEpoch) {
		t.Fatalf("timestamps: created %v updated %v", v.CreatedAt, v.UpdatedAt)
	}

	// Renaming to itself is allowed; taking another VPC's name is not.
	if status, out := e.call(t, http.MethodPut, "/vpcs/"+a.ID, `{"vpc": {"name": "a"}}`); status != http.StatusOK {
		t.Fatalf("rename to own name: %d %s", status, out)
	}
	e.expect(t, "error_vpc_name_exists", http.MethodPut, "/vpcs/"+a.ID, `{"vpc": {"name": "b"}}`)

	for name, body := range map[string]string{
		"missing vpc object": `{}`,
		"malformed":          `nope`,
		"bad name":           `{"vpc": {"name": "a b"}}`,
		"bad description":    `{"vpc": {"description": ">"}}`,
		"bad cidr":           `{"vpc": {"cidr": "10.0.0.0/33"}}`,
		"bad route":          `{"vpc": {"routes": [{"destination": "everywhere"}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			e.expect(t, "error_vpc_invalid", http.MethodPut, "/vpcs/"+a.ID, body)
		})
	}
	e.expect(t, "error_vpc_invalid", http.MethodPut, "/vpcs/not-a-uuid", `{"vpc": {}}`)
}

func TestMalformedVPCIDs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.expect(t, "error_vpc_invalid", http.MethodGet, "/vpcs/not-a-uuid", "")
	e.expect(t, "error_vpc_invalid", http.MethodDelete, "/vpcs/not-a-uuid", "")
}

func TestListVPCsFiltersAndPaging(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var ids []string
	for _, name := range []string{"a", "b", "c", "d"} {
		ids = append(ids, e.mustCreateVPC(t, name, "10.0.0.0/8").ID)
	}

	list := func(query string) []string {
		t.Helper()
		status, out := e.call(t, http.MethodGet, "/vpcs"+query, "")
		if status != http.StatusOK {
			t.Fatalf("list %s: %d %s", query, status, out)
		}
		var names []string
		for _, v := range decodeInto[listVPCsResponse](t, out).VPCs {
			names = append(names, v.Name)
		}
		return names
	}

	tests := []struct {
		query string
		want  string
	}{
		{"", "a,b,c,d"},
		{"?limit=2", "a,b"},
		{"?limit=2&marker=" + ids[1], "c,d"},
		{"?marker=" + ids[3], ""},
		{"?limit=0", ""},
		{"?id=" + ids[2], "c"},
		{"?id=" + testUnknownID, ""},
		{"?enterprise_project_id=0", "a,b,c,d"},
		{"?enterprise_project_id=0aad99bc-f5f6-4f78-8404-c598d76b0ed2", ""},
	}
	for _, tt := range tests {
		if got := strings.Join(list(tt.query), ","); got != tt.want {
			t.Errorf("list %q = %q, want %q", tt.query, got, tt.want)
		}
	}

	e.expect(t, "error_vpc_invalid", http.MethodGet, "/vpcs?limit=-1", "")
	e.expect(t, "error_vpc_invalid", http.MethodGet, "/vpcs?limit=many", "")
	e.expect(t, "error_vpc_invalid", http.MethodGet, "/vpcs?marker="+testUnknownID, "")
}

func TestVPCsAreIsolatedByProjectAndRegion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.mustCreateVPC(t, "mine", "10.0.0.0/8")

	const otherProject = "ffffffffffffffffffffffffffffffff"
	if status, _ := e.callAs(t, otherProject, http.MethodGet, "/vpcs/"+v.ID, ""); status != http.StatusNotFound {
		t.Errorf("another project can read the VPC: status %d", status)
	}
	_, out := e.callAs(t, otherProject, http.MethodGet, "/vpcs", "")
	if n := len(decodeInto[listVPCsResponse](t, out).VPCs); n != 0 {
		t.Errorf("another project lists %d VPCs", n)
	}
	// Names are unique per project, not globally.
	if status, out := e.callAs(t, otherProject, http.MethodPost, "/vpcs", `{"vpc": {"name": "mine"}}`); status != http.StatusOK {
		t.Errorf("same name in another project: %d %s", status, out)
	}

	other := Tenant{Region: "af-south-1", ProjectID: testProject}
	got, err := e.svc.ListVPCs(t.Context(), other, ListVPCsFilter{})
	if err != nil || len(got) != 0 {
		t.Errorf("another region lists %v, %v", got, err)
	}
}

func TestUnimplementedVPCOperationIsReportedAsAGap(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	status, out := e.call(t, http.MethodGet, "/vpcs/"+testUnknownID+"/routes", "")
	if status != http.StatusNotImplemented || !strings.Contains(string(out), "WeiStack.0501") {
		t.Fatalf("got %d %s, want 501 WeiStack.0501", status, out)
	}
}
