package nat

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestListNatGatewaySpecs(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)

	e.expect(t, "list_specs", http.MethodGet, "/nat_gateway_specs", "")
}

func TestGatewayLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newGWEnv(t)

	e.expect(t, "list_gateways_empty", http.MethodGet, "/nat_gateways", "")

	out := e.expect(t, "create_gateway", http.MethodPost, "/nat_gateways", fmt.Sprintf(`{
		"nat_gateway": {
			"name": "nat-gw-1",
			"description": "primary nat gateway",
			"router_id": %q,
			"internal_network_id": %q,
			"spec": "1"
		}
	}`, e.vpcID, e.subnetID))
	id := gwDecodeInto[natGatewayEnvelope](t, out).NatGateway.ID

	// Still PENDING_CREATE before lifecycle delay settles: update & delete return NAT.0103.
	e.expect(t, "error_gateway_not_active", http.MethodPut, "/nat_gateways/"+id,
		`{"nat_gateway": {"name": "nat-gw-updated"}}`)
	e.expect(t, "error_gateway_not_active", http.MethodDelete, "/nat_gateways/"+id, "")

	e.settle(t)

	e.expect(t, "show_gateway", http.MethodGet, "/nat_gateways/"+id, "")
	e.expect(t, "list_gateways", http.MethodGet, "/nat_gateways", "")

	e.expect(t, "update_gateway", http.MethodPut, "/nat_gateways/"+id, `{
		"nat_gateway": {
			"name": "nat-gw-updated",
			"description": "updated description",
			"spec": "3",
			"session_conf": {
				"tcp_session_expire_time": 1200,
				"icmp_session_expire_time": 20
			}
		}
	}`)

	e.expect(t, "delete_gateway", http.MethodDelete, "/nat_gateways/"+id, "")

	// Deleted gateway returns NAT.0105 on show, update, and delete.
	e.expect(t, "error_gateway_not_found", http.MethodGet, "/nat_gateways/"+id, "")
	e.expect(t, "error_gateway_not_found", http.MethodPut, "/nat_gateways/"+id, `{"nat_gateway": {"name": "x"}}`)
	e.expect(t, "error_gateway_not_found", http.MethodDelete, "/nat_gateways/"+id, "")
}

func TestGatewayCreateErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)

	// Seed one gateway at 192.168.0.20 so we can trigger IP-in-use (NAT.0002).
	status, raw := e.call(t, http.MethodPost, "/nat_gateways", fmt.Sprintf(`{
		"nat_gateway": {
			"name": "seed-gw",
			"router_id": %q,
			"internal_network_id": %q,
			"ngport_ip_address": "192.168.0.20",
			"spec": "1"
		}
	}`, e.vpcID, e.subnetID))
	if status != http.StatusCreated {
		t.Fatalf("seed create: %d %s", status, raw)
	}

	// Fill a /29 subnet to trigger NAT.1404.
	fullVPC, fullSub := e.seedVPCSubnet(t, gwTestTenant, "vpc-tiny", "172.16.0.0/16", "sub-tiny", "172.16.1.0/29", "172.16.1.1")
	for i := range 3 {
		st, out := e.call(t, http.MethodPost, "/nat_gateways", fmt.Sprintf(`{
			"nat_gateway": {
				"name": "tiny-%d",
				"router_id": %q,
				"internal_network_id": %q,
				"spec": "1"
			}
		}`, i, fullVPC, fullSub))
		if st != http.StatusCreated {
			t.Fatalf("fill tiny %d: %d %s", i, st, out)
		}
	}

	tooManyTags := make([]string, 21)
	for i := range tooManyTags {
		tooManyTags[i] = fmt.Sprintf(`"k%d*v%d"`, i, i)
	}

	tests := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_bad_json"},
		{"malformed json", `{"nat_gateway": `, "error_bad_json"},
		{"wrong field type", `{"nat_gateway": {"name": 123}}`, "error_invalid_params"},
		{"missing nat_gateway wrapper", `{}`, "error_invalid_params"},
		{"missing required fields", `{"nat_gateway": {}}`, "error_invalid_params"},
		{
			name:   "invalid name",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "bad name", "router_id": %q, "internal_network_id": %q, "spec": "1"}}`, e.vpcID, e.subnetID),
			golden: "error_invalid_params",
		},
		{
			name:   "invalid description",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "description": "bad<desc>", "router_id": %q, "internal_network_id": %q, "spec": "1"}}`, e.vpcID, e.subnetID),
			golden: "error_invalid_description",
		},
		{
			name:   "invalid spec",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "9"}}`, e.vpcID, e.subnetID),
			golden: "error_invalid_spec",
		},
		{
			name:   "unknown router_id",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "1"}}`, gwUnknownUUID, e.subnetID),
			golden: "error_router_not_found",
		},
		{
			name:   "unknown internal_network_id",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "1"}}`, e.vpcID, gwUnknownUUID),
			golden: "error_network_not_found",
		},
		{
			name:   "subnet in another VPC",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "1"}}`, e.vpcID, e.subnet2),
			golden: "error_subnet_not_in_router",
		},
		{
			name:   "ip in use",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "ngport_ip_address": "192.168.0.20", "spec": "1"}}`, e.vpcID, e.subnetID),
			golden: "error_invalid_params",
		},
		{
			name:   "subnet full",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "1"}}`, fullVPC, fullSub),
			golden: "error_subnet_full",
		},
		{
			name:   "negative session_conf",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "1", "session_conf": {"tcp_session_expire_time": -1}}}`, e.vpcID, e.subnetID),
			golden: "error_invalid_params",
		},
		{
			name:   "invalid tag",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "1", "tags": ["*missing-key"]}}`, e.vpcID, e.subnetID),
			golden: "error_invalid_tag",
		},
		{
			name:   "too many tags",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "1", "tags": [%s]}}`, e.vpcID, e.subnetID, strings.Join(tooManyTags, ",")),
			golden: "error_too_many_tags",
		},
		{
			name:   "invalid enterprise_project_id",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "1", "enterprise_project_id": "bad-ep"}}`, e.vpcID, e.subnetID),
			golden: "error_invalid_enterprise_project",
		},
		{
			name:   "prepaid_options rejected",
			body:   fmt.Sprintf(`{"nat_gateway": {"name": "gw1", "router_id": %q, "internal_network_id": %q, "spec": "1", "prepaid_options": {"period_type": "month", "period_num": 1}}}`, e.vpcID, e.subnetID),
			golden: "error_prepaid_not_implemented",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, tc.golden, http.MethodPost, "/nat_gateways", tc.body)
		})
	}
}

func TestGatewayUpdateAndDeleteErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)
	ctx := t.Context()

	status, raw := e.call(t, http.MethodPost, "/nat_gateways", fmt.Sprintf(`{
		"nat_gateway": {
			"name": "gw-active",
			"router_id": %q,
			"internal_network_id": %q,
			"spec": "1"
		}
	}`, e.vpcID, e.subnetID))
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, raw)
	}
	id := gwDecodeInto[natGatewayEnvelope](t, raw).NatGateway.ID
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	// Update errors.
	e.expect(t, "error_bad_json", http.MethodPut, "/nat_gateways/"+id, `{`)
	e.expect(t, "error_invalid_params", http.MethodPut, "/nat_gateways/"+id, `{}`)
	e.expect(t, "error_invalid_params", http.MethodPut, "/nat_gateways/"+id, `{"nat_gateway": {"name": "bad name"}}`)
	e.expect(t, "error_invalid_description", http.MethodPut, "/nat_gateways/"+id, `{"nat_gateway": {"description": "<nope>"}}`)
	e.expect(t, "error_invalid_spec", http.MethodPut, "/nat_gateways/"+id, `{"nat_gateway": {"spec": "9"}}`)
	e.expect(t, "error_prepaid_not_implemented", http.MethodPut, "/nat_gateways/"+id, `{"nat_gateway": {"prepaid_options": {"is_auto_pay": true}}}`)

	// Seed 201 DNAT rules to verify NAT.0309 on update and NAT.0006 on delete.
	for i := range publicDnatRulesLimit + 1 {
		rid := fmt.Sprintf("55555555-5555-4555-8555-%012d", i)
		if err := e.svc.dnatRules(gwTestTenant).Create(ctx, rid, dnatRule{ID: rid, GatewayID: id}); err != nil {
			t.Fatalf("seed dnat %d: %v", i, err)
		}
	}
	e.expect(t, "error_dnat_limit", http.MethodPut, "/nat_gateways/"+id, `{"nat_gateway": {"spec": "2"}}`)
	e.expect(t, "error_rules_exist", http.MethodDelete, "/nat_gateways/"+id, "")
}

func TestGatewayListHTTPFiltersAndErrors(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)
	ctx := t.Context()

	status, raw := e.call(t, http.MethodPost, "/nat_gateways", fmt.Sprintf(`{
		"nat_gateway": {
			"name": "gw-http-1",
			"description": "first",
			"router_id": %q,
			"internal_network_id": %q,
			"spec": "2",
			"enterprise_project_id": %q
		}
	}`, e.vpcID, e.subnetID, gwCustomEP))
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, raw)
	}
	gw := gwDecodeInto[natGatewayEnvelope](t, raw).NatGateway
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	// Bad limit, bad marker, bad admin_state_up -> NAT.0002.
	e.expect(t, "error_invalid_params", http.MethodGet, "/nat_gateways?limit=0", "")
	e.expect(t, "error_invalid_params", http.MethodGet, "/nat_gateways?limit=2001", "")
	e.expect(t, "error_invalid_params", http.MethodGet, "/nat_gateways?limit=abc", "")
	e.expect(t, "error_invalid_params", http.MethodGet, "/nat_gateways?marker="+gwUnknownUUID, "")
	e.expect(t, "error_invalid_params", http.MethodGet, "/nat_gateways?admin_state_up=maybe", "")

	// Combined filters including repeatable status/spec, sort_key, sort_dir, page_reverse.
	q := url.Values{}
	q.Set("tenant_id", gwTestProject)
	q.Set("id", gw.ID)
	q.Set("enterprise_project_id", allGrantedEPs)
	q.Set("description", "first")
	q.Set("created_at", gw.CreatedAt)
	q.Set("name", "gw-http-1")
	q.Add("status", "INACTIVE")
	q.Add("status", "ACTIVE")
	q.Add("spec", "1")
	q.Add("spec", "2")
	q.Set("admin_state_up", "true")
	q.Set("internal_network_id", e.subnetID)
	q.Set("router_id", e.vpcID)
	q.Set("sort_key", "name")
	q.Set("sort_dir", "desc")
	q.Set("page_reverse", "true")
	status, out := e.call(t, http.MethodGet, "/nat_gateways?"+q.Encode(), "")
	if status != http.StatusOK {
		t.Fatalf("filtered list: %d %s", status, out)
	}
	listed := gwDecodeInto[listNatGatewaysResponse](t, out).NatGateways
	if len(listed) != 1 || listed[0].ID != gw.ID {
		t.Fatalf("filtered list = %+v, want [%s]", listed, gw.ID)
	}
}
