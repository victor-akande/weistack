package nat

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/services/vpc"
)

func TestTransitIPsHTTPLifecycleAndGolden(t *testing.T) {
	t.Parallel()
	e := newPREnv(t)

	e.expect(t, "transit_ips", "list_transit_ips_empty", http.MethodGet, "/transit-ips", "")

	out := e.expect(t, "transit_ips", "create_transit_ip", http.MethodPost, "/transit-ips", `{
		"transit_ip": {
			"virsubnet_id": "`+prTransitVirID+`",
			"ip_address": "172.16.1.68",
			"enterprise_project_id": "`+prCustomEP+`",
			"tags": [{"key": "key1", "value": "value1"}]
		}
	}`)
	id := prDecodeInto[transitIPEnvelope](t, out).TransitIP.ID

	e.expect(t, "transit_ips", "show_transit_ip", http.MethodGet, "/transit-ips/"+id, "")
	e.expect(t, "transit_ips", "list_transit_ips", http.MethodGet, "/transit-ips?transit_subnet_id="+prTransitSubID, "")

	e.expect(t, "transit_ips", "delete_transit_ip", http.MethodDelete, "/transit-ips/"+id, "")

	e.expect(t, "transit_ips", "error_nat_1002", http.MethodGet, "/transit-ips/"+id, "")
	e.expect(t, "transit_ips", "error_nat_1002", http.MethodDelete, "/transit-ips/"+id, "")
}

func TestTransitIPsHTTPErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newPREnv(t)

	// Seed one transit IP and use it in an SNAT rule for NAT.1403 and NAT.1409.
	st, out := e.call(t, http.MethodPost, "/transit-ips", `{
		"transit_ip": {
			"virsubnet_id": "`+prTransitVirID+`",
			"ip_address": "172.16.1.68"
		}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("seed transit ip: %d %s", st, out)
	}
	tiID := prDecodeInto[transitIPEnvelope](t, out).TransitIP.ID

	st, out = e.call(t, http.MethodPost, "/snat-rules", `{
		"snat_rule": {
			"gateway_id": "`+prGW1ID+`",
			"virsubnet_id": "`+prSub1ID+`",
			"transit_ip_ids": ["`+tiID+`"]
		}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("seed snat: %d %s", st, out)
	}

	e.net.fullSub[prTransitVir2ID] = true

	var tooManyTags []string
	for i := range maxTags + 1 {
		tooManyTags = append(tooManyTags, fmt.Sprintf(`{"key":"k%d","value":"v%d"}`, i, i))
	}

	cases := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_nat_1010"},
		{"malformed json", `{"transit_ip":`, "error_nat_1010"},
		{"wrong type", `{"transit_ip": "bad"}`, "error_nat_1010"},
		{"missing wrapper", `{}`, "error_nat_1010"},
		{"missing virsubnet_id", `{"transit_ip": {}}`, "error_nat_1010"},
		{"invalid enterprise_project_id", `{"transit_ip": {"virsubnet_id": "` + prTransitVirID + `", "enterprise_project_id": "bad"}}`, "error_vpc_0011"},
		{"invalid tag", `{"transit_ip": {"virsubnet_id": "` + prTransitVirID + `", "tags": [{"key": "", "value": "v"}]}}`, "error_nat_1015"},
		{"too many tags", `{"transit_ip": {"virsubnet_id": "` + prTransitVirID + `", "tags": [` + strings.Join(tooManyTags, ",") + `]}}`, "error_nat_1016"},
		{"unknown subnet", `{"transit_ip": {"virsubnet_id": "` + prUnknownID + `"}}`, "error_nat_1002"},
		{"non-transit subnet", `{"transit_ip": {"virsubnet_id": "` + prSub1ID + `"}}`, "error_nat_1101"},
		{"ip in use", `{"transit_ip": {"virsubnet_id": "` + prTransitVirID + `", "ip_address": "172.16.1.68"}}`, "error_nat_1403"},
		{"subnet full", `{"transit_ip": {"virsubnet_id": "` + prTransitVir2ID + `"}}`, "error_nat_1404"},
		{"invalid ip", `{"transit_ip": {"virsubnet_id": "` + prTransitVirID + `", "ip_address": "172.16.1.1"}}`, "error_nat_1405"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "transit_ips", tc.golden, http.MethodPost, "/transit-ips", tc.body)
		})
	}

	e.expect(t, "transit_ips", "error_nat_1409", http.MethodDelete, "/transit-ips/"+tiID, "")
	e.expect(t, "transit_ips", "error_nat_1010", http.MethodGet, "/transit-ips?limit=0", "")
	e.expect(t, "transit_ips", "error_nat_1010", http.MethodGet, "/transit-ips?marker="+prUnknownID, "")
}

func TestTransitIPsHTTPListFiltersAndPageInfo(t *testing.T) {
	t.Parallel()
	e := newPREnv(t)

	st, out1 := e.call(t, http.MethodPost, "/transit-ips", `{
		"transit_ip": {"virsubnet_id": "`+prTransitVirID+`", "ip_address": "172.16.1.10"}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("create ti1: %d %s", st, out1)
	}
	ti1 := prDecodeInto[transitIPEnvelope](t, out1).TransitIP

	st, out2 := e.call(t, http.MethodPost, "/transit-ips", `{
		"transit_ip": {"virsubnet_id": "`+prTransitVir2ID+`", "ip_address": "172.16.2.10", "enterprise_project_id": "`+prCustomEP+`"}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("create ti2: %d %s", st, out2)
	}
	ti2 := prDecodeInto[transitIPEnvelope](t, out2).TransitIP

	// Link ti1 to prGW1ID via an SNAT rule.
	st, outSnat := e.call(t, http.MethodPost, "/snat-rules", `{
		"snat_rule": {"gateway_id": "`+prGW1ID+`", "virsubnet_id": "`+prSub1ID+`", "transit_ip_ids": ["`+ti1.ID+`"]}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("seed snat: %d %s", st, outSnat)
	}

	list := func(q string) listTransitIPsResponse {
		t.Helper()
		st, out := e.call(t, http.MethodGet, "/transit-ips"+q, "")
		if st != http.StatusOK {
			t.Fatalf("list %s: %d %s", q, st, out)
		}
		return prDecodeInto[listTransitIPsResponse](t, out)
	}

	if got := list("?gateway_id=" + prGW1ID); len(got.TransitIPs) != 1 || got.TransitIPs[0].ID != ti1.ID {
		t.Fatalf("gateway_id filter = %+v", got)
	}
	if got := list("?transit_subnet_id=" + prTransitSub2ID); len(got.TransitIPs) != 1 || got.TransitIPs[0].ID != ti2.ID {
		t.Fatalf("transit_subnet_id filter = %+v", got)
	}
	if got := list("?virsubnet_id=" + prTransitVirID); len(got.TransitIPs) != 1 || got.TransitIPs[0].ID != ti1.ID {
		t.Fatalf("virsubnet_id filter = %+v", got)
	}
	if got := list("?ip_address=172.16.2.10"); len(got.TransitIPs) != 1 || got.TransitIPs[0].ID != ti2.ID {
		t.Fatalf("ip_address filter = %+v", got)
	}
	if got := list("?network_interface_id=" + ti1.NetworkInterfaceID); len(got.TransitIPs) != 1 || got.TransitIPs[0].ID != ti1.ID {
		t.Fatalf("network_interface_id filter = %+v", got)
	}
	if got := list("?enterprise_project_id=" + prCustomEP); len(got.TransitIPs) != 1 || got.TransitIPs[0].ID != ti2.ID {
		t.Fatalf("enterprise_project_id filter = %+v", got)
	}
	if got := list("?enterprise_project_id=" + allGrantedEPs); len(got.TransitIPs) != 2 {
		t.Fatalf("all_granted_eps filter = %d, want 2", len(got.TransitIPs))
	}
	if got := list("?project_id=" + prTestProject); len(got.TransitIPs) != 2 {
		t.Fatalf("project_id filter = %d, want 2", len(got.TransitIPs))
	}
	if got := list("?project_id=other"); len(got.TransitIPs) != 0 {
		t.Fatalf("other project_id filter = %d, want 0", len(got.TransitIPs))
	}

	// Pagination with next_marker and previous_marker.
	p1 := list("?limit=1")
	if p1.PageInfo.CurrentCount != 1 || p1.PageInfo.NextMarker == "" || p1.PageInfo.PreviousMarker == "" {
		t.Fatalf("p1 page_info = %+v", p1.PageInfo)
	}
	p2 := list("?limit=1&marker=" + p1.PageInfo.NextMarker)
	if p2.PageInfo.CurrentCount != 1 || p2.PageInfo.NextMarker != "" || p2.PageInfo.PreviousMarker == "" {
		t.Fatalf("p2 page_info = %+v", p2.PageInfo)
	}
}

func TestPrivateSnatHTTPLifecycleAndGolden(t *testing.T) {
	t.Parallel()
	e := newPREnv(t)

	_, out1 := e.call(t, http.MethodPost, "/transit-ips", `{"transit_ip": {"virsubnet_id": "`+prTransitVirID+`", "ip_address": "172.16.1.10"}}`)
	ti1ID := prDecodeInto[transitIPEnvelope](t, out1).TransitIP.ID
	_, out2 := e.call(t, http.MethodPost, "/transit-ips", `{"transit_ip": {"virsubnet_id": "`+prTransitVirID+`", "ip_address": "172.16.1.11"}}`)
	ti2ID := prDecodeInto[transitIPEnvelope](t, out2).TransitIP.ID

	e.expect(t, "private_snat", "list_private_snats_empty", http.MethodGet, "/snat-rules", "")

	res1 := e.expect(t, "private_snat", "create_private_snat_subnet", http.MethodPost, "/snat-rules", `{
		"snat_rule": {
			"gateway_id": "`+prGW1ID+`",
			"virsubnet_id": "`+prSub1ID+`",
			"transit_ip_ids": ["`+ti1ID+`"],
			"description": "my_snat_rule01"
		}
	}`)
	id1 := prDecodeInto[privateSnatEnvelope](t, res1).SnatRule.ID

	res2 := e.expect(t, "private_snat", "create_private_snat_cidr", http.MethodPost, "/snat-rules", `{
		"snat_rule": {
			"gateway_id": "`+prGW1ID+`",
			"cidr": "10.0.50.0/24",
			"transit_ip_ids": ["`+ti1ID+`"],
			"description": "my_snat_rule02"
		}
	}`)
	id2 := prDecodeInto[privateSnatEnvelope](t, res2).SnatRule.ID

	e.expect(t, "private_snat", "show_private_snat", http.MethodGet, "/snat-rules/"+id1, "")
	e.expect(t, "private_snat", "list_private_snats", http.MethodGet, "/snat-rules?id="+id1, "")

	e.expect(t, "private_snat", "update_private_snat", http.MethodPut, "/snat-rules/"+id1, `{
		"snat_rule": {
			"transit_ip_ids": ["`+ti2ID+`"],
			"description": "my_snat_rule_update"
		}
	}`)

	e.expect(t, "private_snat", "delete_private_snat", http.MethodDelete, "/snat-rules/"+id2, "")
	e.expect(t, "private_snat", "delete_private_snat", http.MethodDelete, "/snat-rules/"+id1, "")

	e.expect(t, "private_snat", "error_nat_1002", http.MethodGet, "/snat-rules/"+id1, "")
	e.expect(t, "private_snat", "error_nat_1002", http.MethodPut, "/snat-rules/"+id1, `{"snat_rule": {"description": "x"}}`)
	e.expect(t, "private_snat", "error_nat_1002", http.MethodDelete, "/snat-rules/"+id1, "")
}

func TestPrivateSnatHTTPErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newPREnv(t)

	sameVPCTransitVir := "77777777-7777-4777-8777-777777777702"
	e.net.mu.Lock()
	e.net.subnets[sameVPCTransitVir] = vpc.Subnet{ID: sameVPCTransitVir, VPCID: prVPC1ID, CIDR: "10.0.97.0/24", GatewayIP: "10.0.97.1"}
	e.net.mu.Unlock()
	_ = e.svc.transitSubnets(prTestTenant).Create(t.Context(), "ts-same-snat", transitSubnet{
		ID: "ts-same-snat", Name: "ts-same", SubnetID: sameVPCTransitVir, VPCID: prVPC1ID, CIDR: "10.0.97.0/24",
	})

	createTI := func(sub, ip string) string {
		st, out := e.call(t, http.MethodPost, "/transit-ips", fmt.Sprintf(`{"transit_ip":{"virsubnet_id":%q,"ip_address":%q}}`, sub, ip))
		if st != http.StatusCreated {
			t.Fatalf("seed ti: %d %s", st, out)
		}
		return prDecodeInto[transitIPEnvelope](t, out).TransitIP.ID
	}
	ti1 := createTI(prTransitVirID, "172.16.1.10")
	ti2 := createTI(prTransitVirID, "172.16.1.11")
	ti3 := createTI(prTransitVirID, "172.16.1.12")
	tiDNAT := createTI(prTransitVirID, "172.16.1.13")
	tiGW2 := createTI(prTransitVirID, "172.16.1.14")
	tiSame := createTI(sameVPCTransitVir, "10.0.97.10")

	// Seed SNAT on GW1 (sub1 + cidr 10.0.50.0/24), SNAT on GW2 (tiGW2), DNAT on GW1 (tiDNAT).
	st, out := e.call(t, http.MethodPost, "/snat-rules", `{"snat_rule": {"gateway_id": "`+prGW1ID+`", "virsubnet_id": "`+prSub1ID+`", "transit_ip_ids": ["`+ti1+`"]}}`)
	if st != http.StatusCreated {
		t.Fatalf("seed snat1: %d %s", st, out)
	}
	snat1ID := prDecodeInto[privateSnatEnvelope](t, out).SnatRule.ID

	st, out = e.call(t, http.MethodPost, "/snat-rules", `{"snat_rule": {"gateway_id": "`+prGW1ID+`", "cidr": "10.0.50.0/24", "transit_ip_ids": ["`+ti1+`"]}}`)
	if st != http.StatusCreated {
		t.Fatalf("seed snat2: %d %s", st, out)
	}
	st, out = e.call(t, http.MethodPost, "/snat-rules", `{"snat_rule": {"gateway_id": "`+prGW2ID+`", "virsubnet_id": "`+prSubOtherID+`", "transit_ip_ids": ["`+tiGW2+`"]}}`)
	if st != http.StatusCreated {
		t.Fatalf("seed snat gw2: %d %s", st, out)
	}
	st, out = e.call(t, http.MethodPost, "/dnat-rules", `{"dnat_rule": {"gateway_id": "`+prGW1ID+`", "transit_ip_id": "`+tiDNAT+`", "private_ip_address": "10.0.1.99"}}`)
	if st != http.StatusCreated {
		t.Fatalf("seed dnat: %d %s", st, out)
	}

	tooManyTransitIPs := make([]string, maxSnatEIPs+1)
	for i := range tooManyTransitIPs {
		tooManyTransitIPs[i] = fmt.Sprintf(`"10000000-0000-4000-8000-%012d"`, i+1)
	}

	cases := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_nat_1010"},
		{"malformed json", `{"snat_rule":`, "error_nat_1010"},
		{"missing snat_rule", `{}`, "error_nat_1010"},
		{"unknown gateway", `{"snat_rule": {"gateway_id": "` + prUnknownID + `", "cidr": "10.0.60.0/24", "transit_ip_ids": ["` + ti2 + `"]}}`, "error_nat_1002"},
		{"unknown transit ip", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "cidr": "10.0.60.0/24", "transit_ip_ids": ["` + prUnknownID + `"]}}`, "error_nat_1002"},
		{"subnet not in vpc", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "virsubnet_id": "` + prSubOtherID + `", "transit_ip_ids": ["` + ti2 + `"]}}`, "error_nat_1003"},
		{"transit ip in gateway vpc", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "cidr": "10.0.60.0/24", "transit_ip_ids": ["` + tiSame + `"]}}`, "error_nat_1303"},
		{"transit ip used by dnat", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "cidr": "10.0.60.0/24", "transit_ip_ids": ["` + tiDNAT + `"]}}`, "error_nat_1305"},
		{"transit ip used by other gw", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "cidr": "10.0.60.0/24", "transit_ip_ids": ["` + tiGW2 + `"]}}`, "error_nat_1406"},
		{"both cidr and virsubnet_id", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "cidr": "10.0.60.0/24", "virsubnet_id": "` + prSub2ID + `", "transit_ip_ids": ["` + ti2 + `"]}}`, "error_nat_1501"},
		{"invalid cidr", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "cidr": "10.0.60.5/24", "transit_ip_ids": ["` + ti2 + `"]}}`, "error_nat_1502"},
		{"duplicate subnet", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "virsubnet_id": "` + prSub1ID + `", "transit_ip_ids": ["` + ti2 + `"]}}`, "error_nat_1503"},
		{"duplicate cidr", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "cidr": "10.0.50.0/24", "transit_ip_ids": ["` + ti2 + `"]}}`, "error_nat_1505"},
		{"more than max transit ips", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "cidr": "10.0.60.0/24", "transit_ip_ids": [` + strings.Join(tooManyTransitIPs, ",") + `]}}`, "error_nat_1506"},
		{"non-uuid transit ip", `{"snat_rule": {"gateway_id": "` + prGW1ID + `", "cidr": "10.0.60.0/24", "transit_ip_ids": ["bad-uuid"]}}`, "error_nat_1507"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "private_snat", tc.golden, http.MethodPost, "/snat-rules", tc.body)
		})
	}

	// Update errors + list errors.
	e.expect(t, "private_snat", "error_nat_1010", http.MethodPut, "/snat-rules/"+snat1ID, `{"snat_rule": {"description": "<bad>"}}`)
	e.expect(t, "private_snat", "error_nat_1305", http.MethodPut, "/snat-rules/"+snat1ID, `{"snat_rule": {"transit_ip_ids": ["`+tiDNAT+`"]}}`)
	e.expect(t, "private_snat", "error_nat_1010", http.MethodGet, "/snat-rules?limit=0", "")
	e.expect(t, "private_snat", "error_nat_1010", http.MethodGet, "/snat-rules?marker="+prUnknownID, "")

	// Rule limit NAT.1207 (3 rules already on prGW1ID; fill remaining slots up to Small's rule_max).
	const seededOnGW1 = 3
	for i := range privateRuleMax("Small") - seededOnGW1 {
		st, out := e.call(t, http.MethodPost, "/snat-rules", fmt.Sprintf(`{"snat_rule":{"gateway_id":%q,"cidr":"10.0.%d.0/24","transit_ip_ids":[%q]}}`, prGW1ID, 100+i, ti3))
		if st != http.StatusCreated {
			t.Fatalf("fill %d: %d %s", i, st, out)
		}
	}
	e.expect(t, "private_snat", "error_nat_1207", http.MethodPost, "/snat-rules", `{"snat_rule":{"gateway_id":"`+prGW1ID+`","cidr":"10.0.200.0/24","transit_ip_ids":["`+ti3+`"]}}`)
}

func TestPrivateSnatHTTPListFilters(t *testing.T) {
	t.Parallel()
	e := newPREnv(t)

	_, out1 := e.call(t, http.MethodPost, "/transit-ips", `{"transit_ip":{"virsubnet_id":"`+prTransitVirID+`","ip_address":"172.16.1.10"}}`)
	ti1ID := prDecodeInto[transitIPEnvelope](t, out1).TransitIP.ID
	_, out2 := e.call(t, http.MethodPost, "/transit-ips", `{"transit_ip":{"virsubnet_id":"`+prTransitVirID+`","ip_address":"172.16.1.11"}}`)
	ti2ID := prDecodeInto[transitIPEnvelope](t, out2).TransitIP.ID

	_, _ = e.call(t, http.MethodPost, "/snat-rules", `{"snat_rule":{"gateway_id":"`+prGW1ID+`","virsubnet_id":"`+prSub1ID+`","transit_ip_ids":["`+ti1ID+`"],"description":"s1"}}`)
	_, _ = e.call(t, http.MethodPost, "/snat-rules", `{"snat_rule":{"gateway_id":"`+prGW2ID+`","cidr":"10.1.50.0/24","transit_ip_ids":["`+ti2ID+`"],"description":"s2"}}`)

	list := func(q string) listPrivateSnatsResponse {
		t.Helper()
		st, out := e.call(t, http.MethodGet, "/snat-rules"+q, "")
		if st != http.StatusOK {
			t.Fatalf("list %s: %d %s", q, st, out)
		}
		return prDecodeInto[listPrivateSnatsResponse](t, out)
	}

	if got := list("?gateway_id=" + prGW1ID); len(got.SnatRules) != 1 || got.SnatRules[0].VirsubnetID != prSub1ID {
		t.Fatalf("gateway_id = %+v", got)
	}
	if got := list("?cidr=" + url.QueryEscape("10.1.50.0/24")); len(got.SnatRules) != 1 {
		t.Fatalf("cidr = %+v", got)
	}
	if got := list("?virsubnet_id=" + prSub1ID); len(got.SnatRules) != 1 {
		t.Fatalf("virsubnet_id = %+v", got)
	}
	if got := list("?transit_ip_id=" + ti1ID); len(got.SnatRules) != 1 {
		t.Fatalf("transit_ip_id = %+v", got)
	}
	if got := list("?transit_ip_address=172.16.1.11"); len(got.SnatRules) != 1 {
		t.Fatalf("transit_ip_address = %+v", got)
	}
	if got := list("?enterprise_project_id=" + prCustomEP); len(got.SnatRules) != 1 || got.SnatRules[0].GatewayID != prGW2ID {
		t.Fatalf("enterprise_project_id = %+v", got)
	}
	if got := list("?description=s1"); len(got.SnatRules) != 1 {
		t.Fatalf("description = %+v", got)
	}
	if got := list("?limit=1"); got.PageInfo.CurrentCount != 1 || got.PageInfo.NextMarker == "" {
		t.Fatalf("pagination = %+v", got.PageInfo)
	}
}

func TestPrivateDnatHTTPLifecycleAndGolden(t *testing.T) {
	t.Parallel()
	e := newPREnv(t)

	_, out1 := e.call(t, http.MethodPost, "/transit-ips", `{"transit_ip": {"virsubnet_id": "`+prTransitVirID+`", "ip_address": "172.16.1.10"}}`)
	ti1ID := prDecodeInto[transitIPEnvelope](t, out1).TransitIP.ID
	_, out2 := e.call(t, http.MethodPost, "/transit-ips", `{"transit_ip": {"virsubnet_id": "`+prTransitVirID+`", "ip_address": "172.16.1.11"}}`)
	ti2ID := prDecodeInto[transitIPEnvelope](t, out2).TransitIP.ID

	e.expect(t, "private_dnat", "list_private_dnats_empty", http.MethodGet, "/dnat-rules", "")

	res1 := e.expect(t, "private_dnat", "create_private_dnat_compute", http.MethodPost, "/dnat-rules", `{
		"dnat_rule": {
			"description": "aa",
			"gateway_id": "`+prGW1ID+`",
			"transit_ip_id": "`+ti1ID+`",
			"network_interface_id": "`+prPort1ID+`"
		}
	}`)
	id1 := prDecodeInto[privateDnatEnvelope](t, res1).DnatRule.ID

	res2 := e.expect(t, "private_dnat", "create_private_dnat_customize", http.MethodPost, "/dnat-rules", `{
		"dnat_rule": {
			"description": "custom tcp",
			"gateway_id": "`+prGW1ID+`",
			"transit_ip_id": "`+ti2ID+`",
			"private_ip_address": "10.0.9.50",
			"protocol": "TCP",
			"internal_service_port": "80",
			"transit_service_port": "8080"
		}
	}`)
	id2 := prDecodeInto[privateDnatEnvelope](t, res2).DnatRule.ID

	e.expect(t, "private_dnat", "show_private_dnat", http.MethodGet, "/dnat-rules/"+id1, "")
	e.expect(t, "private_dnat", "list_private_dnats", http.MethodGet, "/dnat-rules?id="+id1, "")

	e.expect(t, "private_dnat", "update_private_dnat", http.MethodPut, "/dnat-rules/"+id1, `{
		"dnat_rule": {
			"description": "my dnat-rules 03"
		}
	}`)

	e.expect(t, "private_dnat", "delete_private_dnat", http.MethodDelete, "/dnat-rules/"+id2, "")
	e.expect(t, "private_dnat", "delete_private_dnat", http.MethodDelete, "/dnat-rules/"+id1, "")

	e.expect(t, "private_dnat", "error_nat_1002", http.MethodGet, "/dnat-rules/"+id1, "")
	e.expect(t, "private_dnat", "error_nat_1002", http.MethodPut, "/dnat-rules/"+id1, `{"dnat_rule": {"description": "x"}}`)
	e.expect(t, "private_dnat", "error_nat_1002", http.MethodDelete, "/dnat-rules/"+id1, "")
}

func TestPrivateDnatHTTPErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newPREnv(t)

	sameVPCTransitVir := "77777777-7777-4777-8777-777777777703"
	e.net.mu.Lock()
	e.net.subnets[sameVPCTransitVir] = vpc.Subnet{ID: sameVPCTransitVir, VPCID: prVPC1ID, CIDR: "10.0.96.0/24", GatewayIP: "10.0.96.1"}
	e.net.mu.Unlock()
	_ = e.svc.transitSubnets(prTestTenant).Create(t.Context(), "ts-same-dnat", transitSubnet{
		ID: "ts-same-dnat", Name: "ts-same", SubnetID: sameVPCTransitVir, VPCID: prVPC1ID, CIDR: "10.0.96.0/24",
	})

	createTI := func(sub, ip string) string {
		st, out := e.call(t, http.MethodPost, "/transit-ips", fmt.Sprintf(`{"transit_ip":{"virsubnet_id":%q,"ip_address":%q}}`, sub, ip))
		if st != http.StatusCreated {
			t.Fatalf("seed ti: %d %s", st, out)
		}
		return prDecodeInto[transitIPEnvelope](t, out).TransitIP.ID
	}
	ti1 := createTI(prTransitVirID, "172.16.1.10")
	ti2 := createTI(prTransitVirID, "172.16.1.11")
	tiFree := createTI(prTransitVirID, "172.16.1.12")
	tiSnat := createTI(prTransitVirID, "172.16.1.13")
	tiGW2 := createTI(prTransitVirID, "172.16.1.14")
	tiSame := createTI(sameVPCTransitVir, "10.0.96.10")

	// Seed SNAT on GW1 (tiSnat), SNAT on GW2 (tiGW2), DNAT tcp (ti1+port1), DNAT any (ti2+port2).
	_, _ = e.call(t, http.MethodPost, "/snat-rules", `{"snat_rule":{"gateway_id":"`+prGW1ID+`","cidr":"10.0.70.0/24","transit_ip_ids":["`+tiSnat+`"]}}`)
	_, _ = e.call(t, http.MethodPost, "/snat-rules", `{"snat_rule":{"gateway_id":"`+prGW2ID+`","cidr":"10.1.70.0/24","transit_ip_ids":["`+tiGW2+`"]}}`)
	_, _ = e.call(t, http.MethodPost, "/dnat-rules", `{"dnat_rule":{"gateway_id":"`+prGW1ID+`","transit_ip_id":"`+ti1+`","network_interface_id":"`+prPort1ID+`","protocol":"tcp","internal_service_port":"80","transit_service_port":"8080"}}`)
	_, _ = e.call(t, http.MethodPost, "/dnat-rules", `{"dnat_rule":{"gateway_id":"`+prGW1ID+`","transit_ip_id":"`+ti2+`","network_interface_id":"`+prPort2ID+`"}}`)

	cases := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_nat_1010"},
		{"malformed json", `{"dnat_rule":`, "error_nat_1010"},
		{"missing wrapper", `{}`, "error_nat_1010"},
		{"invalid protocol", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiFree + `","private_ip_address":"10.0.9.20","protocol":"icmp"}}`, "error_nat_1010"},
		{"invalid port", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiFree + `","private_ip_address":"10.0.9.20","protocol":"tcp","internal_service_port":"70000","transit_service_port":"80"}}`, "error_nat_1010"},
		{"unknown gateway", `{"dnat_rule":{"gateway_id":"` + prUnknownID + `","transit_ip_id":"` + tiFree + `","private_ip_address":"10.0.9.20"}}`, "error_nat_1002"},
		{"unknown transit ip", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + prUnknownID + `","private_ip_address":"10.0.9.20"}}`, "error_nat_1002"},
		{"unknown port", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiFree + `","network_interface_id":"` + prUnknownID + `"}}`, "error_nat_1009"},
		{"transit ip in gateway vpc", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiSame + `","private_ip_address":"10.0.9.20"}}`, "error_nat_1303"},
		{"port not in gateway vpc", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiFree + `","network_interface_id":"` + prPortOtherID + `"}}`, "error_nat_1304"},
		{"any port mismatch", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiFree + `","private_ip_address":"10.0.9.20","protocol":"any","internal_service_port":"80","transit_service_port":"0"}}`, "error_nat_1306"},
		{"internal conflict", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiFree + `","network_interface_id":"` + prPort1ID + `","protocol":"tcp","internal_service_port":"80","transit_service_port":"8081"}}`, "error_nat_1307"},
		{"transit ip used by snat", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiSnat + `","private_ip_address":"10.0.9.20"}}`, "error_nat_1308"},
		{"port allport conflict", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiFree + `","network_interface_id":"` + prPort1ID + `"}}`, "error_nat_1309"},
		{"transit conflict", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + ti1 + `","private_ip_address":"10.0.9.20","protocol":"tcp","internal_service_port":"81","transit_service_port":"8080"}}`, "error_nat_1310"},
		{"both nic and private ip", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiFree + `","network_interface_id":"` + prPort1ID + `","private_ip_address":"10.0.9.20"}}`, "error_nat_1311"},
		{"invalid private ip", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiFree + `","private_ip_address":"999.0.0.1"}}`, "error_nat_1405"},
		{"transit ip used by other gw", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + tiGW2 + `","private_ip_address":"10.0.9.20"}}`, "error_nat_1406"},
		{"transit ip allport conflict", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"` + ti1 + `","private_ip_address":"10.0.9.20"}}`, "error_nat_1410"},
		{"non-uuid transit_ip_id", `{"dnat_rule":{"gateway_id":"` + prGW1ID + `","transit_ip_id":"not-a-uuid","private_ip_address":"10.0.9.20"}}`, "error_nat_1507"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "private_dnat", tc.golden, http.MethodPost, "/dnat-rules", tc.body)
		})
	}

	e.expect(t, "private_dnat", "error_nat_1010", http.MethodGet, "/dnat-rules?limit=0", "")
	e.expect(t, "private_dnat", "error_nat_1010", http.MethodGet, "/dnat-rules?marker="+prUnknownID, "")

	// Fill remaining slots on prGW1ID (1 SNAT + 2 DNAT = 3) up to Small's rule_max -> NAT.1207.
	const seededOnGW1 = 3
	for i := range privateRuleMax("Small") - seededOnGW1 {
		port := 1000 + i
		st, out := e.call(t, http.MethodPost, "/dnat-rules", fmt.Sprintf(
			`{"dnat_rule":{"gateway_id":%q,"transit_ip_id":%q,"private_ip_address":"10.0.9.99","protocol":"tcp","internal_service_port":"%d","transit_service_port":"%d"}}`,
			prGW1ID, tiFree, port, port,
		))
		if st != http.StatusCreated {
			t.Fatalf("fill %d: %d %s", i, st, out)
		}
	}
	e.expect(t, "private_dnat", "error_nat_1207", http.MethodPost, "/dnat-rules",
		`{"dnat_rule":{"gateway_id":"`+prGW1ID+`","transit_ip_id":"`+tiFree+`","private_ip_address":"10.0.9.99","protocol":"tcp","internal_service_port":"2000","transit_service_port":"2000"}}`,
	)
}

func TestPrivateDnatHTTPListFilters(t *testing.T) {
	t.Parallel()
	e := newPREnv(t)

	_, out1 := e.call(t, http.MethodPost, "/transit-ips", `{"transit_ip":{"virsubnet_id":"`+prTransitVirID+`","ip_address":"172.16.1.10"}}`)
	ti1ID := prDecodeInto[transitIPEnvelope](t, out1).TransitIP.ID
	_, out2 := e.call(t, http.MethodPost, "/transit-ips", `{"transit_ip":{"virsubnet_id":"`+prTransitVirID+`","ip_address":"172.16.1.11"}}`)
	ti2ID := prDecodeInto[transitIPEnvelope](t, out2).TransitIP.ID

	_, _ = e.call(t, http.MethodPost, "/dnat-rules", `{"dnat_rule":{"gateway_id":"`+prGW1ID+`","transit_ip_id":"`+ti1ID+`","network_interface_id":"`+prPort1ID+`","protocol":"tcp","internal_service_port":"80","transit_service_port":"8080","description":"d1"}}`)
	_, _ = e.call(t, http.MethodPost, "/dnat-rules", `{"dnat_rule":{"gateway_id":"`+prGW2ID+`","transit_ip_id":"`+ti2ID+`","private_ip_address":"10.1.9.10","protocol":"udp","internal_service_port":"53","transit_service_port":"5353","description":"d2"}}`)

	list := func(q string) listPrivateDnatsResponse {
		t.Helper()
		st, out := e.call(t, http.MethodGet, "/dnat-rules"+q, "")
		if st != http.StatusOK {
			t.Fatalf("list %s: %d %s", q, st, out)
		}
		return prDecodeInto[listPrivateDnatsResponse](t, out)
	}

	if got := list("?protocol=6"); len(got.DnatRules) != 1 || got.DnatRules[0].Protocol != "tcp" {
		t.Fatalf("protocol=6 = %+v", got)
	}
	if got := list("?protocol=UDP"); len(got.DnatRules) != 1 || got.DnatRules[0].Protocol != "udp" {
		t.Fatalf("protocol=UDP = %+v", got)
	}
	if got := list("?type=COMPUTE"); len(got.DnatRules) != 1 {
		t.Fatalf("type=COMPUTE = %+v", got)
	}
	if got := list("?type=CUSTOMIZE"); len(got.DnatRules) != 1 {
		t.Fatalf("type=CUSTOMIZE = %+v", got)
	}
	if got := list("?network_interface_id=" + prPort1ID); len(got.DnatRules) != 1 {
		t.Fatalf("network_interface_id = %+v", got)
	}
	if got := list("?private_ip_address=10.1.9.10"); len(got.DnatRules) != 1 {
		t.Fatalf("private_ip_address = %+v", got)
	}
	if got := list("?internal_service_port=80"); len(got.DnatRules) != 1 {
		t.Fatalf("internal_service_port = %+v", got)
	}
	if got := list("?transit_service_port=5353"); len(got.DnatRules) != 1 {
		t.Fatalf("transit_service_port = %+v", got)
	}
	if got := list("?transit_ip_address=172.16.1.11"); len(got.DnatRules) != 1 {
		t.Fatalf("transit_ip_address = %+v", got)
	}
	if got := list("?enterprise_project_id=" + prCustomEP); len(got.DnatRules) != 1 {
		t.Fatalf("enterprise_project_id = %+v", got)
	}
	if got := list("?limit=1"); got.PageInfo.CurrentCount != 1 || got.PageInfo.NextMarker == "" {
		t.Fatalf("pagination = %+v", got.PageInfo)
	}
}
