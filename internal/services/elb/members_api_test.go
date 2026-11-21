package elb

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestMemberHTTPLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newMemEnv(t)

	lb := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID, IPTargetEnable: true})
	p := e.seedPool(t, pool{LoadBalancerID: lb.ID, VPCID: e.vpc1.ID, Protocol: "HTTP", AdminStateUp: true})
	e.seedHealthMonitor(t, healthMonitor{PoolID: p.ID, Type: "HTTP", AdminStateUp: true})
	e.seedListener(t, listener{LoadBalancerID: lb.ID, Protocol: "HTTP", ProtocolPort: 80, DefaultPoolID: p.ID, AdminStateUp: true})

	// Boot an ECS server at 192.168.1.10 so the instance member reports ONLINE.
	_ = e.mustECSServer(t, "web-golden", e.vpc1.ID, e.subnet1.ID, "192.168.1.10")

	// Empty list.
	e.expect(t, "list_members_empty", http.MethodGet, "/pools/"+p.ID+"/members", "")

	// Create instance member (201).
	rawInst := e.expect(t, "create_instance_member", http.MethodPost, "/pools/"+p.ID+"/members", fmt.Sprintf(`{
		"member": {
			"name": "web-member-1",
			"address": "192.168.1.10",
			"protocol_port": 80,
			"subnet_cidr_id": %q,
			"weight": 10
		}
	}`, e.subnet1.NeutronSubnetID))
	instID := memDecodeInto[memberResponse](t, rawInst).Member.ID

	// Create IP member (201) — no server at 192.168.2.50 so operating_status is OFFLINE.
	rawIP := e.expect(t, "create_ip_member", http.MethodPost, "/pools/"+p.ID+"/members", fmt.Sprintf(`{
		"member": {
			"name": "ip-member-1",
			"address": "192.168.2.50",
			"protocol_port": 8080,
			"availability_zone": %q
		}
	}`, memTestRegion+"a"))
	ipID := memDecodeInto[memberResponse](t, rawIP).Member.ID

	// Show instance member (200).
	e.expect(t, "show_member", http.MethodGet, "/pools/"+p.ID+"/members/"+instID, "")

	// Update instance member (200).
	e.expect(t, "update_member", http.MethodPut, "/pools/"+p.ID+"/members/"+instID, `{
		"member": {
			"name": "web-member-1-updated",
			"weight": 50,
			"protocol_port": 8081
		}
	}`)

	// List members in pool (200) — filter by id so golden array order is deterministic.
	e.expect(t, "list_members", http.MethodGet, "/pools/"+p.ID+"/members?id="+instID, "")

	// List all members in project (200) — filter by id so golden array order is deterministic.
	e.expect(t, "list_all_members", http.MethodGet, "/members?id="+instID, "")

	// Delete IP member (204) and instance member (204).
	e.expect(t, "delete_member", http.MethodDelete, "/pools/"+p.ID+"/members/"+ipID, "")
	e.expect(t, "delete_member", http.MethodDelete, "/pools/"+p.ID+"/members/"+instID, "")

	// Deleted member returns ELB.8904 on show, update, delete.
	e.expect(t, "error_not_found", http.MethodGet, "/pools/"+p.ID+"/members/"+instID, "")
	e.expect(t, "error_not_found", http.MethodPut, "/pools/"+p.ID+"/members/"+instID, `{"member": {"name": "gone"}}`)
	e.expect(t, "error_not_found", http.MethodDelete, "/pools/"+p.ID+"/members/"+instID, "")
}

func TestMemberHTTPErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newMemEnv(t)

	lbNoIP := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID, IPTargetEnable: false})
	lbWithIP := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID, IPTargetEnable: true})

	pNoIP := e.seedPool(t, pool{LoadBalancerID: lbNoIP.ID, VPCID: e.vpc1.ID, Protocol: "HTTP", AdminStateUp: true})
	pBadProto := e.seedPool(t, pool{LoadBalancerID: lbWithIP.ID, VPCID: e.vpc1.ID, Protocol: "IP", AdminStateUp: true})

	// Seed one member so we can trigger ELB.8907 duplicate conflict.
	st, raw := e.call(t, http.MethodPost, "/pools/"+pNoIP.ID+"/members", fmt.Sprintf(`{
		"member": {
			"name": "seed",
			"address": "192.168.1.20",
			"protocol_port": 80,
			"subnet_cidr_id": %q
		}
	}`, e.subnet1.NeutronSubnetID))
	if st != http.StatusCreated {
		t.Fatalf("seed create: %d %s", st, raw)
	}
	seedID := memDecodeInto[memberResponse](t, raw).Member.ID

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		golden string
	}{
		{"malformed JSON", http.MethodPost, "/pools/" + pNoIP.ID + "/members", `{`, "error_invalid_input"},
		{"missing member wrapper", http.MethodPost, "/pools/" + pNoIP.ID + "/members", `{}`, "error_invalid_input"},
		{"invalid IPv4 address", http.MethodPost, "/pools/" + pNoIP.ID + "/members", fmt.Sprintf(`{"member": {"address": "999.0.0.1", "protocol_port": 80, "subnet_cidr_id": %q}}`, e.subnet1.NeutronSubnetID), "error_invalid_input"},
		{"IPv6 address", http.MethodPost, "/pools/" + pNoIP.ID + "/members", fmt.Sprintf(`{"member": {"address": "2001:db8::1", "protocol_port": 80, "subnet_cidr_id": %q}}`, e.subnet1.NeutronSubnetID), "error_invalid_input"},
		{"bad port", http.MethodPost, "/pools/" + pNoIP.ID + "/members", fmt.Sprintf(`{"member": {"address": "192.168.1.21", "protocol_port": 0, "subnet_cidr_id": %q}}`, e.subnet1.NeutronSubnetID), "error_invalid_input"},
		{"bad weight", http.MethodPost, "/pools/" + pNoIP.ID + "/members", fmt.Sprintf(`{"member": {"address": "192.168.1.21", "protocol_port": 80, "weight": 101, "subnet_cidr_id": %q}}`, e.subnet1.NeutronSubnetID), "error_invalid_input"},
		{"address outside subnet CIDR", http.MethodPost, "/pools/" + pNoIP.ID + "/members", fmt.Sprintf(`{"member": {"address": "192.168.2.21", "protocol_port": 80, "subnet_cidr_id": %q}}`, e.subnet1.NeutronSubnetID), "error_invalid_input"},
		{"subnet in another VPC", http.MethodPost, "/pools/" + pNoIP.ID + "/members", fmt.Sprintf(`{"member": {"address": "10.0.1.21", "protocol_port": 80, "subnet_cidr_id": %q}}`, e.subnet2.NeutronSubnetID), "error_invalid_input"},
		{"unknown pool on create", http.MethodPost, "/pools/" + memUnknownUUID + "/members", fmt.Sprintf(`{"member": {"address": "192.168.1.21", "protocol_port": 80, "subnet_cidr_id": %q}}`, e.subnet1.NeutronSubnetID), "error_not_found"},
		{"unknown subnet_cidr_id", http.MethodPost, "/pools/" + pNoIP.ID + "/members", fmt.Sprintf(`{"member": {"address": "192.168.1.21", "protocol_port": 80, "subnet_cidr_id": %q}}`, memUnknownUUID), "error_not_found"},
		{"unknown pool on list", http.MethodGet, "/pools/" + memUnknownUUID + "/members", "", "error_not_found"},
		{"duplicate address and port", http.MethodPost, "/pools/" + pNoIP.ID + "/members", fmt.Sprintf(`{"member": {"address": "192.168.1.20", "protocol_port": 80, "subnet_cidr_id": %q}}`, e.subnet1.NeutronSubnetID), "error_conflict"},
		{"IP member unsupported pool protocol", http.MethodPost, "/pools/" + pBadProto.ID + "/members", `{"member": {"address": "192.168.1.21", "protocol_port": 80}}`, "error_ip_member_protocol"},
		{"IP member when ip_target_enable is false", http.MethodPost, "/pools/" + pNoIP.ID + "/members", `{"member": {"address": "192.168.1.21", "protocol_port": 80}}`, "error_ip_target_disabled"},
		{"update malformed JSON", http.MethodPut, "/pools/" + pNoIP.ID + "/members/" + seedID, `{`, "error_invalid_input"},
		{"update missing member wrapper", http.MethodPut, "/pools/" + pNoIP.ID + "/members/" + seedID, `{}`, "error_invalid_input"},
		{"update invalid weight", http.MethodPut, "/pools/" + pNoIP.ID + "/members/" + seedID, `{"member": {"weight": 200}}`, "error_invalid_input"},
		{"list invalid limit", http.MethodGet, "/pools/" + pNoIP.ID + "/members?limit=0", "", "error_invalid_input"},
		{"list invalid marker", http.MethodGet, "/pools/" + pNoIP.ID + "/members?marker=" + memUnknownUUID, "", "error_invalid_input"},
		{"list invalid admin_state_up", http.MethodGet, "/pools/" + pNoIP.ID + "/members?admin_state_up=maybe", "", "error_invalid_input"},
		{"list invalid weight", http.MethodGet, "/pools/" + pNoIP.ID + "/members?weight=abc", "", "error_invalid_input"},
		{"list invalid protocol_port", http.MethodGet, "/pools/" + pNoIP.ID + "/members?protocol_port=abc", "", "error_invalid_input"},
		{"list all invalid limit", http.MethodGet, "/members?limit=2001", "", "error_invalid_input"},
		{"list all invalid page_reverse", http.MethodGet, "/members?page_reverse=nope", "", "error_invalid_input"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, tc.golden, tc.method, tc.path, tc.body)
		})
	}
}

func TestMemberHTTPListQueryFilters(t *testing.T) {
	t.Parallel()
	e := newMemEnv(t)

	lb := e.seedLB(t, loadBalancer{AdminStateUp: true, VPCID: e.vpc1.ID, IPTargetEnable: true, EnterpriseProjectID: memCustomEP})
	p := e.seedPool(t, pool{LoadBalancerID: lb.ID, VPCID: e.vpc1.ID, Protocol: "HTTP", AdminStateUp: true, EnterpriseProjectID: memCustomEP})

	st, raw := e.call(t, http.MethodPost, "/pools/"+p.ID+"/members", fmt.Sprintf(`{
		"member": {
			"name": "filter-target",
			"address": "192.168.1.44",
			"protocol_port": 8080,
			"weight": 15,
			"subnet_cidr_id": %q
		}
	}`, e.subnet1.NeutronSubnetID))
	if st != http.StatusCreated {
		t.Fatalf("create: %d %s", st, raw)
	}
	m := memDecodeInto[memberResponse](t, raw).Member

	q := url.Values{}
	q.Set("id", m.ID)
	q.Set("name", "filter-target")
	q.Add("weight", "10")
	q.Add("weight", "15")
	q.Set("admin_state_up", "true")
	q.Set("subnet_cidr_id", e.subnet1.NeutronSubnetID)
	q.Set("address", "192.168.1.44")
	q.Set("protocol_port", "8080")
	q.Set("operating_status", StatusNoMonitor)
	q.Set("enterprise_project_id", allGrantedEPs)
	q.Set("ip_version", "v4")
	q.Set("member_type", "instance")
	q.Set("page_reverse", "false")

	st, out := e.call(t, http.MethodGet, "/pools/"+p.ID+"/members?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("list members: %d %s", st, out)
	}
	resp := memDecodeInto[listMembersResponse](t, out)
	if len(resp.Members) != 1 || resp.Members[0].ID != m.ID {
		t.Fatalf("list members = %+v, want [%s]", resp.Members, m.ID)
	}

	qAll := url.Values{}
	qAll.Set("pool_id", p.ID)
	qAll.Set("loadbalancer_id", lb.ID)
	qAll.Set("address", "192.168.1.44")
	qAll.Set("enterprise_project_id", memCustomEP)
	st, out = e.call(t, http.MethodGet, "/members?"+qAll.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("list all members: %d %s", st, out)
	}
	allResp := memDecodeInto[listAllMembersResponse](t, out)
	if len(allResp.Members) != 1 || allResp.Members[0].ID != m.ID || allResp.Members[0].PoolID != p.ID || allResp.Members[0].LoadbalancerID != lb.ID {
		t.Fatalf("list all members = %+v, want member %s", allResp.Members, m.ID)
	}
}
