package nat

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestListPrivateSpecsGolden(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)

	e.expect(t, "private_gateways", "list_specs", http.MethodGet, "/specs", "")
}

func TestPrivateGatewayLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)

	e.expect(t, "private_gateways", "list_gateways_empty", http.MethodGet, "/gateways", "")

	out := e.expect(t, "private_gateways", "create_gateway", http.MethodPost, "/gateways", fmt.Sprintf(`{
		"gateway": {
			"name": "private-nat-gw-1",
			"description": "primary private nat",
			"spec": "Small",
			"enterprise_project_id": "0",
			"downlink_vpcs": [{"virsubnet_id": %q}],
			"tags": [{"key": "env", "value": "prod"}]
		}
	}`, e.subnetID))
	id := gwDecodeInto[privateNatEnvelope](t, out).Gateway.ID

	e.expect(t, "private_gateways", "show_gateway", http.MethodGet, "/gateways/"+id, "")
	e.expect(t, "private_gateways", "list_gateways", http.MethodGet, "/gateways", "")

	e.expect(t, "private_gateways", "update_gateway", http.MethodPut, "/gateways/"+id, `{
		"gateway": {
			"name": "private-nat-gw-updated",
			"description": "updated private nat",
			"spec": "Medium"
		}
	}`)

	e.expect(t, "private_gateways", "delete_gateway", http.MethodDelete, "/gateways/"+id, "")

	// Deleted gateway returns NAT.1002 on show, update, and delete.
	e.expect(t, "private_gateways", "error_not_found", http.MethodGet, "/gateways/"+id, "")
	e.expect(t, "private_gateways", "error_not_found", http.MethodPut, "/gateways/"+id, `{"gateway": {"name": "x"}}`)
	e.expect(t, "private_gateways", "error_not_found", http.MethodDelete, "/gateways/"+id, "")
}

func TestPrivateGatewayCreateErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)

	// Seed one gateway at 192.168.0.20 for NAT.1403.
	st, raw := e.call(t, http.MethodPost, "/gateways", fmt.Sprintf(`{
		"gateway": {
			"name": "seed-pgw",
			"downlink_vpcs": [{"virsubnet_id": %q, "ngport_ip_address": "192.168.0.20"}]
		}
	}`, e.subnetID))
	if st != http.StatusCreated {
		t.Fatalf("seed create: %d %s", st, raw)
	}

	// Fill a /29 subnet for NAT.1404.
	_, fullSub := e.seedVPCSubnet(t, gwTestTenant, "pgw-tiny-vpc", "172.16.0.0/16", "pgw-tiny-sub", "172.16.1.0/29", "172.16.1.1")
	for i := range 3 {
		status, out := e.call(t, http.MethodPost, "/gateways", fmt.Sprintf(`{
			"gateway": {
				"name": "tiny-%d",
				"downlink_vpcs": [{"virsubnet_id": %q}]
			}
		}`, i, fullSub))
		if status != http.StatusCreated {
			t.Fatalf("fill tiny %d: %d %s", i, status, out)
		}
	}

	tooManyTags := make([]string, maxTags+1)
	for i := range tooManyTags {
		tooManyTags[i] = fmt.Sprintf(`{"key":"k%d","value":"v%d"}`, i, i)
	}

	tests := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_bad_json"},
		{"malformed json", `{"gateway": `, "error_bad_json"},
		{"wrong field type", `{"gateway": {"name": 123}}`, "error_bad_json"},
		{"missing gateway wrapper", `{}`, "error_bad_json"},
		{"empty downlink_vpcs", `{"gateway": {"name": "pgw1", "downlink_vpcs": []}}`, "error_bad_json"},
		{
			name:   "invalid name",
			body:   fmt.Sprintf(`{"gateway": {"name": "bad name", "downlink_vpcs": [{"virsubnet_id": %q}]}}`, e.subnetID),
			golden: "error_bad_json",
		},
		{
			name:   "invalid description",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "description": "<bad>", "downlink_vpcs": [{"virsubnet_id": %q}]}}`, e.subnetID),
			golden: "error_bad_json",
		},
		{
			name:   "invalid spec",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "spec": "1", "downlink_vpcs": [{"virsubnet_id": %q}]}}`, e.subnetID),
			golden: "error_bad_json",
		},
		{
			name:   "invalid enterprise_project_id",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "enterprise_project_id": "bad-ep", "downlink_vpcs": [{"virsubnet_id": %q}]}}`, e.subnetID),
			golden: "error_invalid_enterprise_project",
		},
		{
			name:   "invalid tag",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "downlink_vpcs": [{"virsubnet_id": %q}], "tags": [{"key": "", "value": "v"}]}}`, e.subnetID),
			golden: "error_invalid_tag",
		},
		{
			name:   "too many tags",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "downlink_vpcs": [{"virsubnet_id": %q}], "tags": [%s]}}`, e.subnetID, strings.Join(tooManyTags, ",")),
			golden: "error_too_many_tags",
		},
		{
			name:   "multiple downlink_vpcs",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "downlink_vpcs": [{"virsubnet_id": %q}, {"virsubnet_id": %q}]}}`, e.subnetID, e.subnet2),
			golden: "error_downlink_vpc_limit",
		},
		{
			name:   "unknown virsubnet_id",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "downlink_vpcs": [{"virsubnet_id": %q}]}}`, gwUnknownUUID),
			golden: "error_not_found",
		},
		{
			name:   "invalid ngport_ip_address",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "downlink_vpcs": [{"virsubnet_id": %q, "ngport_ip_address": "10.0.0.5"}]}}`, e.subnetID),
			golden: "error_invalid_ip",
		},
		{
			name:   "ngport_ip_address in use",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "downlink_vpcs": [{"virsubnet_id": %q, "ngport_ip_address": "192.168.0.20"}]}}`, e.subnetID),
			golden: "error_ip_in_use",
		},
		{
			name:   "subnet full",
			body:   fmt.Sprintf(`{"gateway": {"name": "pgw1", "downlink_vpcs": [{"virsubnet_id": %q}]}}`, fullSub),
			golden: "error_subnet_full",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "private_gateways", tc.golden, http.MethodPost, "/gateways", tc.body)
		})
	}
}

func TestPrivateGatewayUpdateDeleteAndListGolden(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)
	ctx := t.Context()

	st1, raw1 := e.call(t, http.MethodPost, "/gateways", fmt.Sprintf(`{
		"gateway": {
			"name": "pgw-http-1",
			"description": "first",
			"spec": "Medium",
			"enterprise_project_id": %q,
			"downlink_vpcs": [{"virsubnet_id": %q}]
		}
	}`, gwCustomEP, e.subnetID))
	if st1 != http.StatusCreated {
		t.Fatalf("create 1: %d %s", st1, raw1)
	}
	gw1 := gwDecodeInto[privateNatEnvelope](t, raw1).Gateway

	st2, raw2 := e.call(t, http.MethodPost, "/gateways", fmt.Sprintf(`{
		"gateway": {
			"name": "pgw-http-2",
			"spec": "Small",
			"downlink_vpcs": [{"virsubnet_id": %q}]
		}
	}`, e.subnet2))
	if st2 != http.StatusCreated {
		t.Fatalf("create 2: %d %s", st2, raw2)
	}

	// Update errors.
	e.expect(t, "private_gateways", "error_bad_json", http.MethodPut, "/gateways/"+gw1.ID, `{`)
	e.expect(t, "private_gateways", "error_bad_json", http.MethodPut, "/gateways/"+gw1.ID, `{}`)
	e.expect(t, "private_gateways", "error_bad_json", http.MethodPut, "/gateways/"+gw1.ID, `{"gateway": {"name": "bad name"}}`)
	e.expect(t, "private_gateways", "error_same_spec", http.MethodPut, "/gateways/"+gw1.ID, `{"gateway": {"spec": "Medium"}}`)

	// Seed rules above Small's cap on gw1 -> downgrade to Small fails with NAT.1207, delete fails with NAT.1202.
	overSmall := privateRuleMax("Small") + 1
	for i := range overSmall {
		rid := fmt.Sprintf("77777777-7777-4777-8777-%012d", i)
		if err := e.svc.privateSnats(gwTestTenant).Create(ctx, rid, privateSnat{ID: rid, GatewayID: gw1.ID}); err != nil {
			t.Fatalf("seed snat %d: %v", i, err)
		}
	}
	e.expect(t, "private_gateways", "error_rule_limit", http.MethodPut, "/gateways/"+gw1.ID, `{"gateway": {"spec": "Small"}}`)
	e.expect(t, "private_gateways", "error_has_dependencies", http.MethodDelete, "/gateways/"+gw1.ID, "")

	// List pagination & filters.
	e.expect(t, "private_gateways", "error_bad_json", http.MethodGet, "/gateways?limit=0", "")
	e.expect(t, "private_gateways", "error_bad_json", http.MethodGet, "/gateways?limit=2001", "")
	e.expect(t, "private_gateways", "error_bad_json", http.MethodGet, "/gateways?marker="+gwUnknownUUID, "")
	e.expect(t, "private_gateways", "list_gateways_paged", http.MethodGet, "/gateways?limit=1", "")

	q := url.Values{}
	q.Set("id", gw1.ID)
	q.Set("project_id", gwTestProject)
	q.Set("name", "pgw-http-1")
	q.Set("description", "first")
	q.Add("spec", "Small")
	q.Add("spec", "Medium")
	q.Set("status", "ACTIVE")
	q.Set("vpc_id", e.vpcID)
	q.Set("virsubnet_id", e.subnetID)
	q.Set("enterprise_project_id", allGrantedEPs)
	q.Set("page_reverse", "true")
	status, out := e.call(t, http.MethodGet, "/gateways?"+q.Encode(), "")
	if status != http.StatusOK {
		t.Fatalf("filtered list: %d %s", status, out)
	}
	listed := gwDecodeInto[listPrivateNatsResponse](t, out).Gateways
	if len(listed) != 1 || listed[0].ID != gw1.ID {
		t.Fatalf("filtered list = %+v, want [%s]", listed, gw1.ID)
	}
}

func TestTransitSubnetLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)
	ctx := t.Context()

	e.expect(t, "transit_subnets", "list_transit_subnets_empty", http.MethodGet, "/transit-subnets", "")

	out := e.expect(t, "transit_subnets", "create_transit_subnet", http.MethodPost, "/transit-subnets", fmt.Sprintf(`{
		"transit_subnet": {
			"name": "transit-subnet-1",
			"description": "primary transit subnet",
			"virsubnet_id": %q,
			"virsubnet_project_id": %q,
			"tags": [{"key": "env", "value": "prod"}]
		}
	}`, e.subnetID, gwTestProject))
	id := gwDecodeInto[transitSubnetEnvelope](t, out).TransitSubnet.ID

	e.expect(t, "transit_subnets", "show_transit_subnet", http.MethodGet, "/transit-subnets/"+id, "")
	e.expect(t, "transit_subnets", "list_transit_subnets", http.MethodGet, "/transit-subnets", "")

	// Seed a transit IP in e.subnetID and verify ip_count=1 and NAT.1202 on delete.
	tiID := "88888888-8888-4888-8888-888888888888"
	if err := e.svc.transitIPs(gwTestTenant).Create(ctx, tiID, transitIP{ID: tiID, SubnetID: e.subnetID, Address: "192.168.0.99"}); err != nil {
		t.Fatalf("seed transit ip: %v", err)
	}
	e.expect(t, "transit_subnets", "error_has_dependencies", http.MethodDelete, "/transit-subnets/"+id, "")
	if err := e.svc.transitIPs(gwTestTenant).Delete(ctx, tiID); err != nil {
		t.Fatalf("delete transit ip: %v", err)
	}

	e.expect(t, "transit_subnets", "update_transit_subnet", http.MethodPut, "/transit-subnets/"+id, `{
		"transit_subnet": {
			"name": "transit-subnet-updated",
			"description": "updated transit subnet"
		}
	}`)

	e.expect(t, "transit_subnets", "delete_transit_subnet", http.MethodDelete, "/transit-subnets/"+id, "")

	e.expect(t, "transit_subnets", "error_not_found", http.MethodGet, "/transit-subnets/"+id, "")
	e.expect(t, "transit_subnets", "error_not_found", http.MethodPut, "/transit-subnets/"+id, `{"transit_subnet": {"name": "x"}}`)
	e.expect(t, "transit_subnets", "error_not_found", http.MethodDelete, "/transit-subnets/"+id, "")
}

func TestTransitSubnetErrorsAndListGolden(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)

	// Seed a private gateway on e.subnet2 so CreateTransitSubnet on e.subnet2 returns NAT.1101.
	stGW, rawGW := e.call(t, http.MethodPost, "/gateways", fmt.Sprintf(`{
		"gateway": {"name": "pgw-sub2", "downlink_vpcs": [{"virsubnet_id": %q}]}
	}`, e.subnet2))
	if stGW != http.StatusCreated {
		t.Fatalf("seed pgw: %d %s", stGW, rawGW)
	}

	// Seed two transit subnets on e.subnetID and sub3 for list pagination and NAT.1101 duplicate check.
	st1, raw1 := e.call(t, http.MethodPost, "/transit-subnets", fmt.Sprintf(`{
		"transit_subnet": {"name": "ts-1", "description": "first", "virsubnet_id": %q, "virsubnet_project_id": %q}
	}`, e.subnetID, gwTestProject))
	if st1 != http.StatusCreated {
		t.Fatalf("seed ts1: %d %s", st1, raw1)
	}
	ts1 := gwDecodeInto[transitSubnetEnvelope](t, raw1).TransitSubnet

	vpc3, sub3 := e.seedVPCSubnet(t, gwTestTenant, "pgw-vpc-3", "172.16.0.0/16", "pgw-sub-3", "172.16.0.0/24", "172.16.0.1")
	st2, raw2 := e.call(t, http.MethodPost, "/transit-subnets", fmt.Sprintf(`{
		"transit_subnet": {"name": "ts-2", "virsubnet_id": %q, "virsubnet_project_id": %q}
	}`, sub3, gwTestProject))
	if st2 != http.StatusCreated {
		t.Fatalf("seed ts2: %d %s", st2, raw2)
	}
	_ = vpc3

	tooManyTags := make([]string, maxTags+1)
	for i := range tooManyTags {
		tooManyTags[i] = fmt.Sprintf(`{"key":"k%d","value":"v"}`, i)
	}

	tests := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_bad_json"},
		{"malformed json", `{"transit_subnet": `, "error_bad_json"},
		{"missing wrapper", `{}`, "error_bad_json"},
		{"bad name", fmt.Sprintf(`{"transit_subnet": {"name": "bad name", "virsubnet_id": %q, "virsubnet_project_id": %q}}`, e.subnetID, gwTestProject), "error_bad_json"},
		{"mismatched virsubnet_project_id", fmt.Sprintf(`{"transit_subnet": {"name": "ok", "virsubnet_id": %q, "virsubnet_project_id": %q}}`, e.subnetID, gwTestProjectB), "error_bad_json"},
		{"invalid tag", fmt.Sprintf(`{"transit_subnet": {"name": "ok", "virsubnet_id": %q, "virsubnet_project_id": %q, "tags": [{"key": "", "value": "v"}]}}`, e.subnetID, gwTestProject), "error_invalid_tag"},
		{"too many tags", fmt.Sprintf(`{"transit_subnet": {"name": "ok", "virsubnet_id": %q, "virsubnet_project_id": %q, "tags": [%s]}}`, e.subnetID, gwTestProject, strings.Join(tooManyTags, ",")), "error_too_many_tags"},
		{"unknown virsubnet_id", fmt.Sprintf(`{"transit_subnet": {"name": "ok", "virsubnet_id": %q, "virsubnet_project_id": %q}}`, gwUnknownUUID, gwTestProject), "error_not_found"},
		{"already transit subnet", fmt.Sprintf(`{"transit_subnet": {"name": "ok", "virsubnet_id": %q, "virsubnet_project_id": %q}}`, e.subnetID, gwTestProject), "error_subnet_unavailable"},
		{"subnet used by private gateway", fmt.Sprintf(`{"transit_subnet": {"name": "ok", "virsubnet_id": %q, "virsubnet_project_id": %q}}`, e.subnet2, gwTestProject), "error_subnet_unavailable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "transit_subnets", tc.golden, http.MethodPost, "/transit-subnets", tc.body)
		})
	}

	// Update errors & list pagination/filters.
	e.expect(t, "transit_subnets", "error_bad_json", http.MethodPut, "/transit-subnets/"+ts1.ID, `{"transit_subnet": {"name": "bad name"}}`)
	e.expect(t, "transit_subnets", "error_bad_json", http.MethodGet, "/transit-subnets?limit=0", "")
	e.expect(t, "transit_subnets", "error_bad_json", http.MethodGet, "/transit-subnets?marker="+gwUnknownUUID, "")
	e.expect(t, "transit_subnets", "list_transit_subnets_paged", http.MethodGet, "/transit-subnets?limit=1", "")

	q := url.Values{}
	q.Set("id", ts1.ID)
	q.Set("name", "ts-1")
	q.Set("description", "first")
	q.Set("virsubnet_project_id", gwTestProject)
	q.Set("vpc_id", e.vpcID)
	q.Set("virsubnet_id", e.subnetID)
	q.Set("status", "ACTIVE")
	status, out := e.call(t, http.MethodGet, "/transit-subnets?"+q.Encode(), "")
	if status != http.StatusOK {
		t.Fatalf("filtered list: %d %s", status, out)
	}
	listed := gwDecodeInto[listTransitSubnetsResponse](t, out).TransitSubnets
	if len(listed) != 1 || listed[0].ID != ts1.ID {
		t.Fatalf("filtered list = %+v, want [%s]", listed, ts1.ID)
	}
}
