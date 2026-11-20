package nat

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSnatRulesHTTPLifecycleAndGolden(t *testing.T) {
	t.Parallel()
	e := newRulesEnv(t)

	e.expect(t, "snat", "list_snat_rules_empty", http.MethodGet, "/snat_rules", "")

	out := e.expect(t, "snat", "create_snat_rule", http.MethodPost, "/snat_rules", `{
		"snat_rule": {
			"nat_gateway_id": "`+rulesGW1ID+`",
			"network_id": "`+rulesSub1ID+`",
			"floating_ip_id": "`+rulesEIP1ID+`",
			"description": "my snat rule 01"
		}
	}`)
	id1 := rulesDecodeInto[snatRuleResponse](t, out).SnatRule.ID

	out2 := e.expect(t, "snat", "create_snat_rule_cidr", http.MethodPost, "/snat_rules", `{
		"snat_rule": {
			"nat_gateway_id": "`+rulesGW1ID+`",
			"cidr": "172.30.0.0/24",
			"source_type": 1,
			"floating_ip_id": "`+rulesEIP2ID+`",
			"description": "dc snat"
		}
	}`)
	id2 := rulesDecodeInto[snatRuleResponse](t, out2).SnatRule.ID

	e.settle(t)

	e.expect(t, "snat", "show_snat_rule", http.MethodGet, "/snat_rules/"+id1, "")
	e.expect(t, "snat", "list_snat_rules", http.MethodGet, "/snat_rules?id="+id1, "")

	e.expect(t, "snat", "update_snat_rule", http.MethodPut, "/snat_rules/"+id1, `{
		"snat_rule": {
			"nat_gateway_id": "`+rulesGW1ID+`",
			"public_ip_address": "198.51.100.1,198.51.100.2",
			"description": "my_snat_rule_update"
		}
	}`)

	e.expect(t, "snat", "delete_snat_rule", http.MethodDelete, "/nat_gateways/"+rulesGW1ID+"/snat_rules/"+id2, "")
	e.expect(t, "snat", "delete_snat_rule", http.MethodDelete, "/nat_gateways/"+rulesGW1ID+"/snat_rules/"+id1, "")

	e.expect(t, "snat", "error_nat_0209", http.MethodGet, "/snat_rules/"+id1, "")
	e.expect(t, "snat", "error_nat_0209", http.MethodPut, "/snat_rules/"+id1, `{"snat_rule": {"nat_gateway_id": "`+rulesGW1ID+`"}}`)
	e.expect(t, "snat", "error_nat_0209", http.MethodDelete, "/nat_gateways/"+rulesGW1ID+"/snat_rules/"+id1, "")
}

func TestSnatRulesHTTPErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newRulesEnvWithDelay(t, 0)

	// Seed one SNAT rule on rulesSub1ID and one DNAT any rule on rulesEIP3ID.
	st, out := e.call(t, http.MethodPost, "/snat_rules", `{
		"snat_rule": {
			"nat_gateway_id": "`+rulesGW1ID+`",
			"network_id": "`+rulesSub1ID+`",
			"floating_ip_id": "`+rulesEIP1ID+`"
		}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("seed snat: %d %s", st, out)
	}
	seedSnatID := rulesDecodeInto[snatRuleResponse](t, out).SnatRule.ID

	st, out = e.call(t, http.MethodPost, "/dnat_rules", `{
		"dnat_rule": {
			"nat_gateway_id": "`+rulesGW1ID+`",
			"port_id": "`+rulesPort1ID+`",
			"protocol": "any",
			"internal_service_port": 0,
			"external_service_port": 0,
			"floating_ip_id": "`+rulesEIP3ID+`"
		}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("seed any dnat: %d %s", st, out)
	}

	twentyOne := make([]string, 21)
	for i := range twentyOne {
		twentyOne[i] = fmt.Sprintf("10000000-0000-4000-8000-%012d", i+1)
	}

	createCases := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_nat_1010"},
		{"malformed json", `{"snat_rule": `, "error_nat_1010"},
		{"wrong type", `{"snat_rule": "bad"}`, "error_nat_0002"},
		{"missing snat_rule", `{}`, "error_nat_0002"},
		{"missing nat_gateway_id", `{"snat_rule": {"cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0002"},
		{"invalid source_type", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 5, "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0002"},
		{"subnet in other VPC", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "network_id": "` + rulesSubOtherID + `", "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0008"},
		{"invalid description", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIP2ID + `", "description": "<bad>"}}`, "error_nat_0014"},
		{"unknown network_id", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "network_id": "` + rulesUnknownID + `", "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0019"},
		{"unknown EIP", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesUnknownID + `"}}`, "error_nat_0026"},
		{"gateway not active", `{"snat_rule": {"nat_gateway_id": "` + rulesGWPending + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0103"},
		{"gateway not found", `{"snat_rule": {"nat_gateway_id": "` + rulesUnknownID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0105"},
		{"both network_id and cidr", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "network_id": "` + rulesSub2ID + `", "cidr": "10.0.2.0/25", "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0202"},
		{"invalid cidr", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "10.0.2.5/24", "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0203"},
		{"source_type 1 with network_id", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "network_id": "` + rulesSub2ID + `", "source_type": 1, "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0204"},
		{"cidr not in VPC subnet", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "192.168.1.0/24", "source_type": 0, "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0205"},
		{"cidr overlaps existing rule", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "10.0.1.0/25", "source_type": 0, "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0207"},
		{"network_id already has rule", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "network_id": "` + rulesSub1ID + `", "floating_ip_id": "` + rulesEIP2ID + `"}}`, "error_nat_0208"},
		{"invalid floating_ip_id uuid", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "bad-uuid"}}`, "error_nat_0210"},
		{"more than 20 EIPs", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + strings.Join(twentyOne, ",") + `"}}`, "error_nat_0211"},
		{"EIP bound to port", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIPBoundID + `"}}`, "error_nat_0402"},
		{"duplicate EIP in list", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIP2ID + `,` + rulesEIP2ID + `"}}`, "error_nat_0403"},
		{"EIP used by another gateway", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIPHeldID + `"}}`, "error_nat_0404"},
		{"EIP pending/occupied", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIPPendID + `"}}`, "error_nat_0405"},
		{"EIP used by DNAT any rule", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIP3ID + `"}}`, "error_nat_0409"},
		{"global_eip_id not implemented", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.16.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIP2ID + `", "global_eip_id": "geip-1"}}`, "error_not_implemented"},
	}

	for _, tc := range createCases {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "snat", tc.golden, http.MethodPost, "/snat_rules", tc.body)
		})
	}

	// Update error cases.
	e.expect(t, "snat", "error_nat_1010", http.MethodPut, "/snat_rules/"+seedSnatID, `{"snat_rule":`)
	e.expect(t, "snat", "error_nat_0002", http.MethodPut, "/snat_rules/"+seedSnatID, `{}`)
	e.expect(t, "snat", "error_nat_0002", http.MethodPut, "/snat_rules/"+seedSnatID, `{"snat_rule": {"nat_gateway_id": "`+rulesGW2ID+`"}}`)
	e.expect(t, "snat", "error_nat_0014", http.MethodPut, "/snat_rules/"+seedSnatID, `{"snat_rule": {"nat_gateway_id": "`+rulesGW1ID+`", "description": "<bad>"}}`)
	e.expect(t, "snat", "error_nat_0026", http.MethodPut, "/snat_rules/"+seedSnatID, `{"snat_rule": {"nat_gateway_id": "`+rulesGW1ID+`", "public_ip_address": "203.0.113.250"}}`)
	e.expect(t, "snat", "error_nat_0409", http.MethodPut, "/snat_rules/"+seedSnatID, `{"snat_rule": {"nat_gateway_id": "`+rulesGW1ID+`", "public_ip_address": "198.51.100.3"}}`)
	e.expect(t, "snat", "error_not_implemented", http.MethodPut, "/snat_rules/"+seedSnatID, `{"snat_rule": {"nat_gateway_id": "`+rulesGW1ID+`", "global_eip_id": "g1"}}`)

	// Delete with mismatched nat_gateway_id -> NAT.0209.
	e.expect(t, "snat", "error_nat_0209", http.MethodDelete, "/nat_gateways/"+rulesGW2ID+"/snat_rules/"+seedSnatID, "")

	// List error cases.
	e.expect(t, "snat", "error_nat_0002", http.MethodGet, "/snat_rules?limit=0", "")
	e.expect(t, "snat", "error_nat_0002", http.MethodGet, "/snat_rules?limit=2001", "")
	e.expect(t, "snat", "error_nat_0002", http.MethodGet, "/snat_rules?marker="+rulesUnknownID, "")
	e.expect(t, "snat", "error_nat_0002", http.MethodGet, "/snat_rules?admin_state_up=notbool", "")
	e.expect(t, "snat", "error_nat_0002", http.MethodGet, "/snat_rules?source_type=notint", "")
}

func TestSnatRulesListFiltersAndPagination(t *testing.T) {
	t.Parallel()
	e := newRulesEnvWithDelay(t, 0)

	bodies := []string{
		`{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "network_id": "` + rulesSub1ID + `", "floating_ip_id": "` + rulesEIP1ID + `,` + rulesEIP2ID + `", "description": "net-rule"}}`,
		`{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "cidr": "172.30.0.0/24", "source_type": 1, "floating_ip_id": "` + rulesEIP2ID + `", "description": "dc-rule"}}`,
		`{"snat_rule": {"nat_gateway_id": "` + rulesGW2ID + `", "network_id": "` + rulesSubOtherID + `", "floating_ip_id": "` + rulesEIP3ID + `", "description": "gw2-rule"}}`,
	}
	for _, b := range bodies {
		st, out := e.call(t, http.MethodPost, "/snat_rules", b)
		if st != http.StatusCreated {
			t.Fatalf("create: %d %s", st, out)
		}
	}
	if err := e.engine.WaitIdle(t.Context()); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	list := func(q string) []snatRuleResponseBody {
		t.Helper()
		st, out := e.call(t, http.MethodGet, "/snat_rules"+q, "")
		if st != http.StatusOK {
			t.Fatalf("list %s: %d %s", q, st, out)
		}
		return rulesDecodeInto[listSnatRulesResponse](t, out).SnatRules
	}

	all := list("")
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3", len(all))
	}
	if all[0].ID >= all[1].ID || all[1].ID >= all[2].ID {
		t.Fatalf("not sorted ascending: %q, %q, %q", all[0].ID, all[1].ID, all[2].ID)
	}

	// Filters: nat_gateway_id (repeatable), floating_ip_id (any one), floating_ip_address (joined), source_type, cidr, network_id, status, description, admin_state_up, created_at, global_eip_id.
	if got := list("?nat_gateway_id=" + rulesGW1ID); len(got) != 2 {
		t.Fatalf("nat_gateway_id=gw1 = %d, want 2", len(got))
	}
	if got := list("?nat_gateway_id=" + rulesGW1ID + "&nat_gateway_id=" + rulesGW2ID); len(got) != 3 {
		t.Fatalf("repeatable nat_gateway_id = %d, want 3", len(got))
	}
	if got := list("?floating_ip_id=" + rulesEIP2ID); len(got) != 2 {
		t.Fatalf("floating_ip_id=eip2 = %d, want 2 (matches multi-EIP rule too)", len(got))
	}
	if got := list("?floating_ip_address=198.51.100.1,198.51.100.2"); len(got) != 1 {
		t.Fatalf("floating_ip_address joined = %d, want 1", len(got))
	}
	if got := list("?source_type=1"); len(got) != 1 {
		t.Fatalf("source_type=1 = %d, want 1", len(got))
	}
	if got := list("?cidr=" + url.QueryEscape("172.30.0.0/24")); len(got) != 1 {
		t.Fatalf("cidr filter = %d, want 1", len(got))
	}
	if got := list("?network_id=" + rulesSub1ID); len(got) != 1 {
		t.Fatalf("network_id filter = %d, want 1", len(got))
	}
	if got := list("?description=gw2-rule"); len(got) != 1 {
		t.Fatalf("description filter = %d, want 1", len(got))
	}
	if got := list("?status=ACTIVE"); len(got) != 3 {
		t.Fatalf("status=ACTIVE = %d, want 3", len(got))
	}
	if got := list("?admin_state_up=true"); len(got) != 3 {
		t.Fatalf("admin_state_up=true = %d, want 3", len(got))
	}
	if got := list("?admin_state_up=false"); len(got) != 0 {
		t.Fatalf("admin_state_up=false = %d, want 0", len(got))
	}
	if got := list("?created_at=" + url.QueryEscape("2026-11-20 09:30:00.000000")); len(got) != 3 {
		t.Fatalf("created_at filter = %d, want 3", len(got))
	}
	if got := list("?global_eip_id=g1"); len(got) != 0 {
		t.Fatalf("global_eip_id filter = %d, want 0", len(got))
	}

	// Marker + limit pagination.
	p1 := list("?limit=2")
	if len(p1) != 2 || p1[0].ID != all[0].ID || p1[1].ID != all[1].ID {
		t.Fatalf("p1 = %+v", p1)
	}
	p2 := list("?limit=2&marker=" + p1[1].ID)
	if len(p2) != 1 || p2[0].ID != all[2].ID {
		t.Fatalf("p2 = %+v", p2)
	}
}

func TestDnatRulesHTTPLifecycleAndGolden(t *testing.T) {
	t.Parallel()
	e := newRulesEnv(t)

	e.expect(t, "dnat", "list_dnat_rules_empty", http.MethodGet, "/dnat_rules", "")

	out1 := e.expect(t, "dnat", "create_dnat_rule", http.MethodPost, "/dnat_rules", `{
		"dnat_rule": {
			"nat_gateway_id": "`+rulesGW1ID+`",
			"port_id": "`+rulesPort1ID+`",
			"internal_service_port": 80,
			"external_service_port": 8080,
			"protocol": "tcp",
			"floating_ip_id": "`+rulesEIP1ID+`",
			"description": "my dnat rule 01"
		}
	}`)
	id1 := rulesDecodeInto[dnatRuleResponse](t, out1).DnatRule.ID

	out2 := e.expect(t, "dnat", "create_dnat_rule_range", http.MethodPost, "/dnat_rules", `{
		"dnat_rule": {
			"nat_gateway_id": "`+rulesGW1ID+`",
			"port_id": "`+rulesPort1ID+`",
			"internal_service_port": 0,
			"external_service_port": 0,
			"internal_service_port_range": "8000-8010",
			"external_service_port_range": "9000-9010",
			"protocol": "UDP",
			"floating_ip_id": "`+rulesEIP1ID+`",
			"description": "range dnat"
		}
	}`)
	id2 := rulesDecodeInto[dnatRuleResponse](t, out2).DnatRule.ID

	out3 := e.expect(t, "dnat", "create_dnat_rule_any", http.MethodPost, "/dnat_rules", `{
		"dnat_rule": {
			"nat_gateway_id": "`+rulesGW1ID+`",
			"private_ip": "192.168.100.10",
			"internal_service_port": 0,
			"external_service_port": 0,
			"protocol": "any",
			"floating_ip_id": "`+rulesEIP2ID+`",
			"description": "any dnat"
		}
	}`)
	id3 := rulesDecodeInto[dnatRuleResponse](t, out3).DnatRule.ID

	outBatch := e.expect(t, "dnat", "batch_create_dnat_rules", http.MethodPost, "/dnat_rules/batch", `{
		"dnat_rules": [
			{
				"nat_gateway_id": "`+rulesGW1ID+`",
				"port_id": "`+rulesPort2ID+`",
				"internal_service_port": 443,
				"external_service_port": 8443,
				"protocol": "6",
				"floating_ip_id": "`+rulesEIP1ID+`",
				"description": "batch 1"
			},
			{
				"nat_gateway_id": "`+rulesGW1ID+`",
				"private_ip": "192.168.100.20",
				"internal_service_port": 0,
				"external_service_port": 0,
				"protocol": "0",
				"floating_ip_id": "`+rulesEIP3ID+`",
				"description": "batch 2"
			}
		]
	}`)
	batchRules := rulesDecodeInto[listDnatRulesResponse](t, outBatch).DnatRules

	e.settle(t)

	e.expect(t, "dnat", "show_dnat_rule", http.MethodGet, "/dnat_rules/"+id1, "")
	e.expect(t, "dnat", "list_dnat_rules", http.MethodGet, "/dnat_rules?id="+id1, "")

	e.expect(t, "dnat", "update_dnat_rule", http.MethodPut, "/dnat_rules/"+id1, `{
		"dnat_rule": {
			"nat_gateway_id": "`+rulesGW1ID+`",
			"internal_service_port": 808,
			"external_service_port": 8808,
			"description": "my dnat rule updated"
		}
	}`)

	for _, id := range []string{id1, id2, id3, batchRules[0].ID, batchRules[1].ID} {
		e.expect(t, "dnat", "delete_dnat_rule", http.MethodDelete, "/nat_gateways/"+rulesGW1ID+"/dnat_rules/"+id, "")
	}

	e.expect(t, "dnat", "error_nat_0319", http.MethodGet, "/dnat_rules/"+id1, "")
	e.expect(t, "dnat", "error_nat_0319", http.MethodPut, "/dnat_rules/"+id1, `{"dnat_rule": {"nat_gateway_id": "`+rulesGW1ID+`"}}`)
	e.expect(t, "dnat", "error_nat_0319", http.MethodDelete, "/nat_gateways/"+rulesGW1ID+"/dnat_rules/"+id1, "")
}

func TestDnatRulesHTTPErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newRulesEnvWithDelay(t, 0)

	eip4 := "e4444444-4444-4444-8444-444444444444"
	eip5 := "e5555555-5555-4555-8555-555555555555"
	e.eips.add(eip4, "198.51.100.4")
	e.eips.add(eip5, "198.51.100.5")

	// Seed:
	// - SNAT rule on EIP5
	// - DNAT tcp 80->8080 on EIP1 + port1
	// - DNAT any on EIP2 + port2
	// - DNAT any on EIP3 + private_ip 192.168.10.20
	for _, call := range []struct {
		path string
		body string
	}{
		{"/snat_rules", `{"snat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "network_id": "` + rulesSub1ID + `", "floating_ip_id": "` + eip5 + `"}}`},
		{"/dnat_rules", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort1ID + `", "protocol": "tcp", "internal_service_port": 80, "external_service_port": 8080, "floating_ip_id": "` + rulesEIP1ID + `"}}`},
		{"/dnat_rules", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort2ID + `", "protocol": "any", "internal_service_port": 0, "external_service_port": 0, "floating_ip_id": "` + rulesEIP2ID + `"}}`},
		{"/dnat_rules", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "192.168.10.20", "protocol": "any", "internal_service_port": 0, "external_service_port": 0, "floating_ip_id": "` + rulesEIP3ID + `"}}`},
	} {
		st, out := e.call(t, http.MethodPost, call.path, call.body)
		if st != http.StatusCreated {
			t.Fatalf("seed %s: %d %s", call.path, st, out)
		}
	}

	createCases := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_nat_1010"},
		{"malformed json", `{"dnat_rule": `, "error_nat_1010"},
		{"wrong type", `{"dnat_rule": {"internal_service_port": "bad"}}`, "error_nat_0002"},
		{"missing dnat_rule", `{}`, "error_nat_0002"},
		{"missing nat_gateway_id", `{"dnat_rule": {"port_id": "` + rulesPort1ID + `", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + rulesEIP1ID + `"}}`, "error_nat_0002"},
		{"invalid description", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort1ID + `", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + rulesEIP1ID + `", "description": "<bad>"}}`, "error_nat_0014"},
		{"unknown port_id", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesUnknownID + `", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + rulesEIP1ID + `"}}`, "error_nat_0023"},
		{"unknown EIP", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort1ID + `", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + rulesUnknownID + `"}}`, "error_nat_0026"},
		{"gateway not active", `{"dnat_rule": {"nat_gateway_id": "` + rulesGWPending + `", "port_id": "` + rulesPort1ID + `", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0103"},
		{"gateway not found", `{"dnat_rule": {"nat_gateway_id": "` + rulesUnknownID + `", "port_id": "` + rulesPort1ID + `", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0105"},
		{"invalid protocol", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort1ID + `", "protocol": "icmp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + rulesEIP1ID + `"}}`, "error_nat_0302"},
		{"invalid port", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort1ID + `", "protocol": "tcp", "internal_service_port": 70000, "external_service_port": 8081, "floating_ip_id": "` + rulesEIP1ID + `"}}`, "error_nat_0303"},
		{"internal port conflict NAT.0304", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort1ID + `", "protocol": "tcp", "internal_service_port": 80, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0304"},
		{"external port conflict NAT.0305", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "192.168.10.99", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8080, "floating_ip_id": "` + rulesEIP1ID + `"}}`, "error_nat_0305"},
		{"any port mismatch NAT.0306", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort1ID + `", "protocol": "any", "internal_service_port": 80, "external_service_port": 0, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0306"},
		{"port allport conflict NAT.0307", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort2ID + `", "protocol": "tcp", "internal_service_port": 80, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0307"},
		{"private_ip allport conflict NAT.0308", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "192.168.10.20", "protocol": "tcp", "internal_service_port": 80, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0308"},
		{"neither port_id nor private_ip NAT.0310", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "protocol": "tcp", "internal_service_port": 80, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0310"},
		{"invalid private_ip NAT.0311", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "999.999.1.1", "protocol": "tcp", "internal_service_port": 80, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0311"},
		{"port in other VPC NAT.0315", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPortOther + `", "protocol": "tcp", "internal_service_port": 80, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0315"},
		{"both port_id and private_ip NAT.0317", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "port_id": "` + rulesPort1ID + `", "private_ip": "10.0.1.10", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `"}}`, "error_nat_0317"},
		{"EIP bound to port NAT.0402", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "192.168.10.99", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + rulesEIPBoundID + `"}}`, "error_nat_0402"},
		{"EIP held by other gateway NAT.0404", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "192.168.10.99", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + rulesEIPHeldID + `"}}`, "error_nat_0404"},
		{"EIP pending/occupied NAT.0405", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "192.168.10.99", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + rulesEIPPendID + `"}}`, "error_nat_0405"},
		{"EIP DNAT allport conflict NAT.0408", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "192.168.10.99", "protocol": "any", "internal_service_port": 0, "external_service_port": 0, "floating_ip_id": "` + rulesEIP1ID + `"}}`, "error_nat_0408"},
		{"EIP SNAT + DNAT allport conflict NAT.0409", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "192.168.10.99", "protocol": "any", "internal_service_port": 0, "external_service_port": 0, "floating_ip_id": "` + eip5 + `"}}`, "error_nat_0409"},
		{"global_eip_id not implemented", `{"dnat_rule": {"nat_gateway_id": "` + rulesGW1ID + `", "private_ip": "192.168.10.99", "protocol": "tcp", "internal_service_port": 81, "external_service_port": 8081, "floating_ip_id": "` + eip4 + `", "global_eip_id": "geip-1"}}`, "error_not_implemented"},
	}

	for _, tc := range createCases {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "dnat", tc.golden, http.MethodPost, "/dnat_rules", tc.body)
		})
	}

	// Batch empty list -> NAT.0002, malformed -> NAT.1010.
	e.expect(t, "dnat", "error_nat_1010", http.MethodPost, "/dnat_rules/batch", `{"dnat_rules":`)
	e.expect(t, "dnat", "error_nat_0002", http.MethodPost, "/dnat_rules/batch", `{"dnat_rules": []}`)

	// List error cases.
	e.expect(t, "dnat", "error_nat_0002", http.MethodGet, "/dnat_rules?limit=0", "")
	e.expect(t, "dnat", "error_nat_0002", http.MethodGet, "/dnat_rules?marker="+rulesUnknownID, "")
	e.expect(t, "dnat", "error_nat_0002", http.MethodGet, "/dnat_rules?admin_state_up=bad", "")
	e.expect(t, "dnat", "error_nat_0002", http.MethodGet, "/dnat_rules?internal_service_port=bad", "")
	e.expect(t, "dnat", "error_nat_0002", http.MethodGet, "/dnat_rules?external_service_port=bad", "")
}

func TestDnatLimitGolden(t *testing.T) {
	t.Parallel()
	e := newRulesEnvWithDelay(t, 0)
	ctx := t.Context()

	for i := range publicDnatRulesLimit - 1 {
		p := i + 1
		r := dnatRule{
			ID: fmt.Sprintf("d2000000-0000-4000-8000-%012d", p), GatewayID: rulesGW1ID,
			PrivateIP: "192.168.20.1", Protocol: "tcp", InternalPort: p, ExternalPort: p,
			FloatingIPID: rulesEIP1ID, Status: StatusActive, CreatedAt: rulesTestEpoch,
		}
		if err := e.svc.dnatRules(rulesTestTenant).Create(ctx, r.ID, r); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	// 1 remaining slot: batch of 2 -> NAT.0314.
	e.expect(t, "dnat", "error_nat_0314", http.MethodPost, "/dnat_rules/batch", `{
		"dnat_rules": [
			{"nat_gateway_id": "`+rulesGW1ID+`", "private_ip": "192.168.20.1", "protocol": "tcp", "internal_service_port": 5001, "external_service_port": 5001, "floating_ip_id": "`+rulesEIP1ID+`"},
			{"nat_gateway_id": "`+rulesGW1ID+`", "private_ip": "192.168.20.1", "protocol": "tcp", "internal_service_port": 5002, "external_service_port": 5002, "floating_ip_id": "`+rulesEIP1ID+`"}
		]
	}`)

	// Fill the 200th slot, then single create -> NAT.0309.
	st, out := e.call(t, http.MethodPost, "/dnat_rules", `{
		"dnat_rule": {"nat_gateway_id": "`+rulesGW1ID+`", "private_ip": "192.168.20.1", "protocol": "tcp", "internal_service_port": 5001, "external_service_port": 5001, "floating_ip_id": "`+rulesEIP1ID+`"}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("200th create: %d %s", st, out)
	}
	e.expect(t, "dnat", "error_nat_0309", http.MethodPost, "/dnat_rules", `{
		"dnat_rule": {"nat_gateway_id": "`+rulesGW1ID+`", "private_ip": "192.168.20.1", "protocol": "tcp", "internal_service_port": 5002, "external_service_port": 5002, "floating_ip_id": "`+rulesEIP1ID+`"}
	}`)
}

func TestDnatRulesListFiltersAndPagination(t *testing.T) {
	t.Parallel()
	e := newRulesEnvWithDelay(t, 0)

	st, out := e.call(t, http.MethodPost, "/dnat_rules/batch", `{
		"dnat_rules": [
			{
				"nat_gateway_id": "`+rulesGW1ID+`",
				"port_id": "`+rulesPort1ID+`",
				"protocol": "tcp",
				"internal_service_port": 80,
				"external_service_port": 8080,
				"floating_ip_id": "`+rulesEIP1ID+`",
				"description": "tcp-rule"
			},
			{
				"nat_gateway_id": "`+rulesGW1ID+`",
				"port_id": "`+rulesPort1ID+`",
				"protocol": "udp",
				"internal_service_port": 53,
				"external_service_port": 5353,
				"floating_ip_id": "`+rulesEIP1ID+`",
				"description": "udp-rule"
			},
			{
				"nat_gateway_id": "`+rulesGW2ID+`",
				"private_ip": "192.168.88.8",
				"protocol": "any",
				"internal_service_port": 0,
				"external_service_port": 0,
				"floating_ip_id": "`+rulesEIP2ID+`",
				"description": "any-rule"
			}
		]
	}`)
	if st != http.StatusCreated {
		t.Fatalf("batch create: %d %s", st, out)
	}
	if err := e.engine.WaitIdle(t.Context()); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	list := func(q string) []dnatRuleResponseBody {
		t.Helper()
		st, out := e.call(t, http.MethodGet, "/dnat_rules"+q, "")
		if st != http.StatusOK {
			t.Fatalf("list %s: %d %s", q, st, out)
		}
		return rulesDecodeInto[listDnatRulesResponse](t, out).DnatRules
	}

	all := list("")
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3", len(all))
	}
	if all[0].ID >= all[1].ID || all[1].ID >= all[2].ID {
		t.Fatalf("not sorted ascending: %q, %q, %q", all[0].ID, all[1].ID, all[2].ID)
	}

	if got := list("?nat_gateway_id=" + rulesGW1ID); len(got) != 2 {
		t.Fatalf("nat_gateway_id=gw1 = %d, want 2", len(got))
	}
	if got := list("?protocol=TCP&protocol=17"); len(got) != 2 {
		t.Fatalf("repeatable protocol = %d, want 2", len(got))
	}
	if got := list("?status=ACTIVE&status=PENDING_CREATE"); len(got) != 3 {
		t.Fatalf("repeatable status = %d, want 3", len(got))
	}
	if got := list("?port_id=" + rulesPort1ID); len(got) != 2 {
		t.Fatalf("port_id = %d, want 2", len(got))
	}
	if got := list("?private_ip=192.168.88.8"); len(got) != 1 {
		t.Fatalf("private_ip = %d, want 1", len(got))
	}
	if got := list("?internal_service_port=80"); len(got) != 1 {
		t.Fatalf("internal_service_port=80 = %d, want 1", len(got))
	}
	if got := list("?external_service_port=5353"); len(got) != 1 {
		t.Fatalf("external_service_port=5353 = %d, want 1", len(got))
	}
	if got := list("?floating_ip_id=" + rulesEIP1ID); len(got) != 2 {
		t.Fatalf("floating_ip_id = %d, want 2", len(got))
	}
	if got := list("?floating_ip_address=198.51.100.2"); len(got) != 1 {
		t.Fatalf("floating_ip_address = %d, want 1", len(got))
	}
	if got := list("?description=any-rule"); len(got) != 1 {
		t.Fatalf("description = %d, want 1", len(got))
	}
	if got := list("?admin_state_up=true"); len(got) != 3 {
		t.Fatalf("admin_state_up=true = %d, want 3", len(got))
	}
	if got := list("?admin_state_up=false"); len(got) != 0 {
		t.Fatalf("admin_state_up=false = %d, want 0", len(got))
	}
	if got := list("?created_at=" + url.QueryEscape("2026-11-20 09:30:00.000000")); len(got) != 3 {
		t.Fatalf("created_at = %d, want 3", len(got))
	}
	if got := list("?global_eip_address=1.2.3.4"); len(got) != 0 {
		t.Fatalf("global_eip_address = %d, want 0", len(got))
	}

	// Marker + limit pagination.
	p1 := list("?limit=2")
	if len(p1) != 2 || p1[0].ID != all[0].ID || p1[1].ID != all[1].ID {
		t.Fatalf("p1 = %+v", p1)
	}
	p2 := list("?limit=2&marker=" + p1[1].ID)
	if len(p2) != 1 || p2[0].ID != all[2].ID {
		t.Fatalf("p2 = %+v", p2)
	}
}
