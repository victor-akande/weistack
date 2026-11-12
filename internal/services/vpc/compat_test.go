package vpc

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestShowVPCv3(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")
	e.mustCreateSubnet(t, v.ID, "s", "192.168.1.0/24", "192.168.1.1")

	e.expect3(t, "show_vpc_v3", http.MethodGet, "/vpcs/"+v.ID, "")
	e.expect3(t, "error_vpc_v3_not_found", http.MethodGet, "/vpcs/"+testUnknownID, "")

	// A VPC still being created is PENDING in the v3 vocabulary.
	status, out := e.call(t, http.MethodPost, "/vpcs", `{"vpc": {"name": "new"}}`)
	if status != 200 {
		t.Fatal(string(out))
	}
	id := decodeInto[vpcResponse](t, out).VPC.ID
	_, out = e.call3(t, http.MethodGet, "/vpcs/"+id, "")
	if got := decodeInto[v3VPCResponse](t, out).VPC.Status; got != "PENDING" {
		t.Errorf("status of a VPC being created = %q, want PENDING", got)
	}
}

// v1 requests go to /v1/{project}/...; the env's call helper does that.
func TestSecurityGroupsThroughV1(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	// A group created with v3 and a rule with one port, read with v1.
	g := e.mustCreateSecGroup(t, "web")
	status, out := e.call3(t, http.MethodPost, "/security-group-rules", fmt.Sprintf(`{"security_group_rule": {
		"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "multiport": "22",
		"remote_ip_prefix": "0.0.0.0/0", "description": "ssh"}}`, g.ID))
	if status != http.StatusCreated {
		t.Fatal(string(out))
	}
	ruleID := decodeInto[securityGroupRuleResponse](t, out).SecurityGroupRule.ID

	e.expect(t, "show_security_group_v1", http.MethodGet, "/security-groups/"+g.ID, "")
	e.expect(t, "show_security_group_rule_v1", http.MethodGet, "/security-group-rules/"+ruleID, "")

	// A rule created with v1's port range reads back the same in v3.
	out = e.expect(t, "create_security_group_rule_v1", http.MethodPost, "/security-group-rules", fmt.Sprintf(`{"security_group_rule": {
		"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "port_range_min": 443, "port_range_max": 443,
		"remote_ip_prefix": "10.0.0.0/8", "description": "https"}}`, g.ID))
	v1ID := decodeInto[v1RuleResponse](t, out).SecurityGroupRule.ID
	_, out = e.call3(t, http.MethodGet, "/security-group-rules/"+v1ID, "")
	if r := decodeInto[securityGroupRuleResponse](t, out).SecurityGroupRule; r.Multiport == nil || *r.Multiport != "443" {
		t.Errorf("v3 view of a v1 rule: %+v", r)
	}
	status, out = e.call(t, http.MethodPost, "/security-group-rules", fmt.Sprintf(`{"security_group_rule": {
		"security_group_id": %q, "direction": "egress", "protocol": "udp", "port_range_min": 1000, "port_range_max": 2000}}`, g.ID))
	if status != 200 {
		t.Fatal(string(out))
	}
	if r := decodeInto[v1RuleResponse](t, out).SecurityGroupRule; *r.PortRangeMin != 1000 || *r.PortRangeMax != 2000 {
		t.Errorf("port range round trip: %+v", r)
	}

	// A v3 port list has no v1 equivalent: the range is reported open.
	status, out = e.call3(t, http.MethodPost, "/security-group-rules", fmt.Sprintf(`{"security_group_rule": {
		"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "multiport": "80,443"}}`, g.ID))
	if status != http.StatusCreated {
		t.Fatal(string(out))
	}
	listID := decodeInto[securityGroupRuleResponse](t, out).SecurityGroupRule.ID
	_, out = e.call(t, http.MethodGet, "/security-group-rules/"+listID, "")
	if r := decodeInto[v1RuleResponse](t, out).SecurityGroupRule; r.PortRangeMin != nil || r.PortRangeMax != nil {
		t.Errorf("a port list in v1: %+v", r)
	}

	// Listing with v1.
	_, out = e.call(t, http.MethodGet, "/security-group-rules?security_group_id="+g.ID, "")
	if n := len(decodeInto[v1RulesResponse](t, out).SecurityGroupRules); n != 8 {
		t.Errorf("%d rules listed, want 8 (4 default + 4)", n)
	}
	_, out = e.call(t, http.MethodGet, "/security-groups", "")
	var names []string
	for _, sg := range decodeInto[v1GroupsResponse](t, out).SecurityGroups {
		names = append(names, sg.Name)
	}
	if strings.Join(names, ",") != "default,web" {
		t.Errorf("v1 groups = %v", names)
	}
	_, out = e.call(t, http.MethodGet, "/security-groups?limit=1", "")
	if n := len(decodeInto[v1GroupsResponse](t, out).SecurityGroups); n != 1 {
		t.Errorf("limit=1 returned %d groups", n)
	}

	// Errors in the v1 vocabulary.
	e.expect(t, "error_vpc_0603", http.MethodGet, "/security-groups/"+testUnknownID, "")
	e.expect(t, "error_vpc_0603", http.MethodGet, "/security-group-rules/"+testUnknownID, "")
	e.expect(t, "error_vpc_0601", http.MethodPost, "/security-group-rules", `{"security_group_rule": {"security_group_id": "`+g.ID+`", "direction": "sideways"}}`)
	e.expect(t, "error_vpc_0601", http.MethodPost, "/security-group-rules", `{"security_group_rule": {"security_group_id": "`+g.ID+`", "direction": "ingress", "protocol": "tcp", "port_range_min": 1}}`)
	e.expect(t, "error_vpc_0601", http.MethodPost, "/security-group-rules", `{}`)
	e.expect(t, "error_vpc_0602", http.MethodPost, "/security-group-rules", fmt.Sprintf(`{"security_group_rule": {
		"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "port_range_min": 443, "port_range_max": 443,
		"remote_ip_prefix": "10.0.0.0/8", "description": "https"}}`, g.ID))
	e.expect(t, "error_vpc_0601", http.MethodGet, "/security-groups?limit=x", "")
	e.expect(t, "error_vpc_0601", http.MethodGet, "/security-group-rules?marker="+testUnknownID, "")

	// Deleting with v1: the rule, then the group, whose v3 view is gone too.
	if status, _ := e.call(t, http.MethodDelete, "/security-group-rules/"+ruleID, ""); status != http.StatusNoContent {
		t.Errorf("v1 rule delete: %d", status)
	}
	e.expect(t, "error_vpc_0603", http.MethodDelete, "/security-group-rules/"+ruleID, "")
	if status, _ := e.call(t, http.MethodDelete, "/security-groups/"+g.ID, ""); status != http.StatusNoContent {
		t.Errorf("v1 group delete: %d", status)
	}
	e.expect3(t, "error_secgroup_not_found", http.MethodGet, "/security-groups/"+g.ID, "")

	// The default group still cannot be deleted.
	_, out = e.call(t, http.MethodGet, "/security-groups", "")
	def := decodeInto[v1GroupsResponse](t, out).SecurityGroups[0]
	e.expect(t, "error_vpc_0602", http.MethodDelete, "/security-groups/"+def.ID, "")
}

func TestCreateSecurityGroupThroughV1(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")

	status, out := e.call(t, http.MethodPost, "/security-groups", `{"security_group": {"name": "legacy", "vpc_id": "`+v.ID+`"}}`)
	if status != http.StatusOK {
		t.Fatal(string(out))
	}
	g := decodeInto[v1GroupResponse](t, out).SecurityGroup
	if g.Name != "legacy" || g.VPCID != v.ID || len(g.Rules) != 4 {
		t.Errorf("v1 create = %+v", g)
	}
	e.expect(t, "error_vpc_0601", http.MethodPost, "/security-groups", `{"security_group": {"name": "x", "vpc_id": "`+testUnknownID+`"}}`)
	e.expect(t, "error_vpc_0601", http.MethodPost, "/security-groups", `{"security_group": {"name": "a/b"}}`)
	e.expect(t, "error_vpc_0601", http.MethodPost, "/security-groups", `{}`)
	e.expect(t, "error_vpc_0601", http.MethodPost, "/security-groups", `nope`)
}

func TestListVPCsV3(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	web := e.mustCreateVPC(t, "web", "192.168.0.0/16")
	e.mustCreateSubnet(t, web.ID, "a", "192.168.1.0/24", "192.168.1.1")
	e.mustCreateSubnet(t, web.ID, "b", "192.168.2.0/24", "192.168.2.1")
	db := e.mustCreateVPC(t, "db", "10.0.0.0/16")

	// The call KooCLI makes by default.
	e.expect3(t, "list_vpcs_v3", http.MethodGet, "/vpcs", "")

	names := func(query string) []string {
		t.Helper()
		status, out := e.call3(t, http.MethodGet, "/vpcs"+query, "")
		if status != http.StatusOK {
			t.Fatalf("GET /vpcs%s: %d %s", query, status, out)
		}
		var got []string
		for _, v := range decodeInto[listVPCsV3Response](t, out).VPCs {
			got = append(got, v.Name)
		}
		return got
	}
	for query, want := range map[string]string{
		"?id=" + db.ID:                             "db",
		"?id=" + db.ID + "&id=" + web.ID:           "web,db",
		"?name=web":                                "web",
		"?name=web&name=db":                        "web,db",
		"?cidr=10.0.0.0/16":                        "db",
		"?description=":                            "web,db",
		"?name=web&cidr=10.0.0.0/16":               "",
		"?name=nope":                               "",
		"?id=00000000-0000-4000-8000-000000000000": "",
	} {
		if got := strings.Join(names(query), ","); got != want {
			t.Errorf("GET /vpcs%s = %q, want %q", query, got, want)
		}
	}

	// Paging: a next marker only while more follow.
	_, out := e.call3(t, http.MethodGet, "/vpcs?limit=1", "")
	first := decodeInto[listVPCsV3Response](t, out)
	if len(first.VPCs) != 1 || first.PageInfo.NextMarker == nil || *first.PageInfo.NextMarker != web.ID || first.PageInfo.PreviousMarker != web.ID {
		t.Fatalf("first page = %s", out)
	}
	_, out = e.call3(t, http.MethodGet, "/vpcs?limit=1&marker="+*first.PageInfo.NextMarker, "")
	second := decodeInto[listVPCsV3Response](t, out)
	if len(second.VPCs) != 1 || second.VPCs[0].ID != db.ID || second.PageInfo.NextMarker != nil {
		t.Fatalf("second page = %s", out)
	}

	for _, query := range []string{"?limit=2001", "?limit=x", "?marker=00000000-0000-4000-8000-000000000000"} {
		status, out := e.call3(t, http.MethodGet, "/vpcs"+query, "")
		if status != http.StatusBadRequest || !strings.Contains(string(out), `"VPC.9902"`) {
			t.Errorf("GET /vpcs%s = %d %s, want 400 VPC.9902", query, status, out)
		}
	}

	// Another project sees nothing.
	status, out := e.send(t, http.MethodGet, "/v3/ffffffffffffffffffffffffffffffff/vpc/vpcs", nil)
	if list := decodeInto[listVPCsV3Response](t, out); status != http.StatusOK || len(list.VPCs) != 0 || list.VPCs == nil {
		t.Fatalf("another project: %d %s", status, out)
	}
}
