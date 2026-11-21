package elb

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestLoadBalancerLifecycleGolden(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)
	ctx := t.Context()

	// Empty list.
	e.expect(t, "loadbalancers", "list_loadbalancers_empty", http.MethodGet, "/loadbalancers", "")

	// Create load balancer.
	out := e.expect(t, "loadbalancers", "create_loadbalancer", http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {
			"name": "lb-golden",
			"description": "primary dedicated lb",
			"vip_subnet_cidr_id": %q,
			"l4_flavor_id": %q,
			"l7_flavor_id": %q,
			"availability_zone_list": ["ap-southeast-1a"],
			"tags": [{"key": "env", "value": "test"}]
		}
	}`, e.neutronSubnetID, e.l4SmallID, e.l7SmallID))
	lbID := lbDecodeInto[loadBalancerResponse](t, out).Loadbalancer.ID

	// Show & List.
	e.expect(t, "loadbalancers", "show_loadbalancer", http.MethodGet, "/loadbalancers/"+lbID, "")
	e.expect(t, "loadbalancers", "list_loadbalancers", http.MethodGet, "/loadbalancers", "")

	// Update.
	e.expect(t, "loadbalancers", "update_loadbalancer", http.MethodPut, "/loadbalancers/"+lbID, fmt.Sprintf(`{
		"loadbalancer": {
			"name": "lb-golden-updated",
			"description": "updated description",
			"l4_flavor_id": %q,
			"ip_target_enable": true
		}
	}`, e.l4MediumID))

	// Batch add & remove AZs.
	e.expect(t, "loadbalancers", "batch_add_azs", http.MethodPost, "/loadbalancers/"+lbID+"/availability-zone/batch-add", `{
		"availability_zone_list": ["ap-southeast-1b", "ap-southeast-1c"]
	}`)
	e.expect(t, "loadbalancers", "batch_remove_azs", http.MethodPost, "/loadbalancers/"+lbID+"/availability-zone/batch-remove", `{
		"availability_zone_list": ["ap-southeast-1b"]
	}`)

	// Seed a listener, pool, health monitor, member, L7 policy, and L7 rule to test ShowLoadBalancerStatus.
	pID := "10000000-0000-4000-8000-000000000010"
	lID := "20000000-0000-4000-8000-000000000010"
	hmID := "30000000-0000-4000-8000-000000000010"
	mID := "40000000-0000-4000-8000-000000000010"
	polID := "50000000-0000-4000-8000-000000000010"
	ruleID := "60000000-0000-4000-8000-000000000010"
	_ = e.svc.pools(lbTestTenant).Create(ctx, pID, pool{ID: pID, Name: "pool-1", LoadBalancerID: lbID, HealthMonitorID: hmID, AdminStateUp: true})
	_ = e.svc.listeners(lbTestTenant).Create(ctx, lID, listener{ID: lID, Name: "listener-1", LoadBalancerID: lbID, DefaultPoolID: pID, AdminStateUp: true})
	_ = e.svc.healthMonitors(lbTestTenant).Create(ctx, hmID, healthMonitor{ID: hmID, PoolID: pID, Name: "hm-1", Type: "TCP", AdminStateUp: true})
	_ = e.svc.members(lbTestTenant).Create(ctx, mID, member{ID: mID, PoolID: pID, Address: "192.168.0.50", ProtocolPort: 80, AdminStateUp: true})
	_ = e.svc.l7Policies(lbTestTenant).Create(ctx, polID, l7Policy{ID: polID, ListenerID: lID, Name: "policy-1", Action: "REDIRECT_TO_POOL", RedirectPoolID: pID})
	_ = e.svc.l7Rules(lbTestTenant).Create(ctx, ruleID, l7Rule{ID: ruleID, PolicyID: polID, Type: "PATH", CompareType: "STARTS_WITH", Value: "/v1"})

	e.expect(t, "loadbalancers", "show_loadbalancer_status", http.MethodGet, "/loadbalancers/"+lbID+"/statuses", "")

	// Standard delete refuses while listeners/pools exist (ELB.8907).
	e.expect(t, "loadbalancers", "error_conflict", http.MethodDelete, "/loadbalancers/"+lbID, "")

	// Force delete removes everything (204).
	e.expect(t, "loadbalancers", "delete_loadbalancer_force", http.MethodDelete, "/loadbalancers/"+lbID+"/force-elb", "")

	// Deleted LB returns ELB.8904.
	e.expect(t, "loadbalancers", "error_not_found", http.MethodGet, "/loadbalancers/"+lbID, "")
	e.expect(t, "loadbalancers", "error_not_found", http.MethodPut, "/loadbalancers/"+lbID, `{"loadbalancer":{"name":"x"}}`)
	e.expect(t, "loadbalancers", "error_not_found", http.MethodDelete, "/loadbalancers/"+lbID, "")
	e.expect(t, "loadbalancers", "error_not_found", http.MethodDelete, "/loadbalancers/"+lbID+"/force-elb", "")
	e.expect(t, "loadbalancers", "error_not_found", http.MethodGet, "/loadbalancers/"+lbID+"/statuses", "")
}

func TestLoadBalancerCreateWithEIPAndDeleteGolden(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)

	eipID, _ := e.createFreeEIP(t, "bw-golden-eip")
	out := e.expect(t, "loadbalancers", "create_loadbalancer_with_eip", http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {
			"name": "lb-with-eip",
			"vip_subnet_cidr_id": %q,
			"l4_flavor_id": %q,
			"availability_zone_list": ["ap-southeast-1a"],
			"publicip_ids": [%q]
		}
	}`, e.neutronSubnetID, e.l4SmallID, eipID))
	lbID := lbDecodeInto[loadBalancerResponse](t, out).Loadbalancer.ID

	e.expect(t, "loadbalancers", "delete_loadbalancer", http.MethodDelete, "/loadbalancers/"+lbID, "")
}

func TestLoadBalancerErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)

	// Seed one LB for update/conflict tests.
	st, raw := e.call(t, http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {
			"name": "seed-lb",
			"vip_subnet_cidr_id": %q,
			"vip_address": "192.168.0.40",
			"l4_flavor_id": %q,
			"l7_flavor_id": %q,
			"availability_zone_list": ["ap-southeast-1a"]
		}
	}`, e.neutronSubnetID, e.l4SmallID, e.l7SmallID))
	if st != http.StatusCreated {
		t.Fatalf("seed create: %d %s", st, raw)
	}
	lbID := lbDecodeInto[loadBalancerResponse](t, raw).Loadbalancer.ID

	// Fill a /29 subnet to trigger ELB.8934.
	_, tinySub := e.seedVPCSubnet(t, lbTestTenant, "vpc-tiny-http", "172.16.0.0/16", "sub-tiny-http", "172.16.1.0/29", "172.16.1.1")
	for i := range 3 {
		st, out := e.call(t, http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
			"loadbalancer": {
				"name": "tiny-%d",
				"vip_subnet_cidr_id": %q,
				"l4_flavor_id": %q,
				"availability_zone_list": ["ap-southeast-1a"]
			}
		}`, i, tinySub.NeutronSubnetID, e.l4SmallID))
		if st != http.StatusCreated {
			t.Fatalf("fill tiny %d: %d %s", i, st, out)
		}
	}

	// ELB.8902 invalid input cases.
	e.expect(t, "loadbalancers", "error_invalid_input", http.MethodPost, "/loadbalancers", ``)
	e.expect(t, "loadbalancers", "error_invalid_input", http.MethodPost, "/loadbalancers", `{`)
	e.expect(t, "loadbalancers", "error_invalid_input", http.MethodPost, "/loadbalancers", `{}`)
	e.expect(t, "loadbalancers", "error_invalid_input", http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {"vip_subnet_cidr_id": %q, "l4_flavor_id": %q}
	}`, e.neutronSubnetID, e.l4SmallID))
	e.expect(t, "loadbalancers", "error_invalid_input", http.MethodGet, "/loadbalancers?limit=0", "")
	e.expect(t, "loadbalancers", "error_invalid_input", http.MethodGet, "/loadbalancers?marker="+lbUnknownUUID, "")
	e.expect(t, "loadbalancers", "error_invalid_input", http.MethodPost, "/loadbalancers/"+lbID+"/availability-zone/batch-remove", `{"availability_zone_list":["ap-southeast-1a"]}`)

	// ELB.8904 not found.
	e.expect(t, "loadbalancers", "error_not_found", http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {"vip_subnet_cidr_id": %q, "l4_flavor_id": %q, "availability_zone_list": ["ap-southeast-1a"]}
	}`, lbUnknownUUID, e.l4SmallID))

	// ELB.8907 conflict (duplicate VIP address).
	e.expect(t, "loadbalancers", "error_conflict", http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {"vip_subnet_cidr_id": %q, "vip_address": "192.168.0.40", "l4_flavor_id": %q, "availability_zone_list": ["ap-southeast-1a"]}
	}`, e.neutronSubnetID, e.l4SmallID))

	// ELB.8934 subnet full.
	e.expect(t, "loadbalancers", "error_subnet_full", http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {"vip_subnet_cidr_id": %q, "l4_flavor_id": %q, "availability_zone_list": ["ap-southeast-1a"]}
	}`, tinySub.NeutronSubnetID, e.l4SmallID))

	// ELB.8959 flavor cross-type change.
	e.expect(t, "loadbalancers", "error_flavor_type_change", http.MethodPut, "/loadbalancers/"+lbID, fmt.Sprintf(`{
		"loadbalancer": {"l4_flavor_id": %q}
	}`, e.l7SmallID))

	// WeiStack.0501 out-of-scope features.
	for _, body := range []string{
		fmt.Sprintf(`{"loadbalancer": {"vip_subnet_cidr_id": %q, "l4_flavor_id": %q, "availability_zone_list": ["ap-southeast-1a"], "prepaid_options": {"period_type": "month"}}}`, e.neutronSubnetID, e.l4SmallID),
		fmt.Sprintf(`{"loadbalancer": {"vip_subnet_cidr_id": %q, "l4_flavor_id": %q, "availability_zone_list": ["ap-southeast-1a"], "ipv6_vip_virsubnet_id": %q}}`, e.neutronSubnetID, e.l4SmallID, e.subnetID),
		fmt.Sprintf(`{"loadbalancer": {"vip_subnet_cidr_id": %q, "l4_flavor_id": %q, "availability_zone_list": ["ap-southeast-1a"], "charge_mode": "lcu"}}`, e.neutronSubnetID, e.l4SmallID),
		fmt.Sprintf(`{"loadbalancer": {"vip_subnet_cidr_id": %q, "l4_flavor_id": %q, "availability_zone_list": ["ap-southeast-1a"], "log_group_id": "lg-1"}}`, e.neutronSubnetID, e.l4SmallID),
	} {
		e.expect(t, "loadbalancers", "error_not_implemented", http.MethodPost, "/loadbalancers", body)
	}
	e.expect(t, "loadbalancers", "error_not_implemented", http.MethodPut, "/loadbalancers/"+lbID, `{"loadbalancer": {"prepaid_options": {"auto_pay": true}}}`)
}

func TestLoadBalancerListHTTPFilters(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)

	eipID, eipAddr := e.createFreeEIP(t, "bw-filter")
	st, raw := e.call(t, http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {
			"name": "lb-filter-1",
			"description": "filter desc",
			"vip_subnet_cidr_id": %q,
			"l4_flavor_id": %q,
			"l7_flavor_id": %q,
			"availability_zone_list": ["ap-southeast-1a"],
			"enterprise_project_id": %q,
			"publicip_ids": [%q],
			"autoscaling": {"enable": true}
		}
	}`, e.neutronSubnetID, e.l4SmallID, e.l7SmallID, lbCustomEP, eipID))
	if st != http.StatusCreated {
		t.Fatalf("create: %d %s", st, raw)
	}
	lb := lbDecodeInto[loadBalancerResponse](t, raw).Loadbalancer

	q := url.Values{}
	q.Set("id", lb.ID)
	q.Set("name", "lb-filter-1")
	q.Set("description", "filter desc")
	q.Set("admin_state_up", "true")
	q.Set("provisioning_status", "ACTIVE")
	q.Set("operating_status", "ONLINE")
	q.Set("guaranteed", "true")
	q.Set("vpc_id", e.vpcID)
	q.Set("vip_port_id", lb.VIPPortID)
	q.Set("vip_address", lb.VIPAddress)
	q.Set("vip_subnet_cidr_id", e.neutronSubnetID)
	q.Add("eips", "eip_id="+eipID)
	q.Add("eips", "eip_address="+eipAddr)
	q.Add("publicips", "publicip_id="+eipID)
	q.Set("availability_zone_list", "ap-southeast-1a")
	q.Set("l4_flavor_id", e.l4SmallID)
	q.Set("l7_flavor_id", e.l7SmallID)
	q.Set("enterprise_project_id", allGrantedEPs)
	q.Set("ip_version", "4")
	q.Set("deletion_protection_enable", "false")
	q.Set("elb_virsubnet_type", "ipv4")
	q.Set("autoscaling", "enable=true")
	q.Set("protection_status", "nonProtection")

	st, out := e.call(t, http.MethodGet, "/loadbalancers?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("filtered list: %d %s", st, out)
	}
	resp := lbDecodeInto[listLoadBalancersResponse](t, out)
	if len(resp.Loadbalancers) != 1 || resp.Loadbalancers[0].ID != lb.ID {
		t.Fatalf("filtered list = %+v, want [%s]", resp.Loadbalancers, lb.ID)
	}
}

func TestFlavorsAndAvailabilityZonesGolden(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)

	// List all flavors: 4 seeded flavors in ascending ID order.
	st, raw := e.call(t, http.MethodGet, "/flavors", "")
	if st != http.StatusOK {
		t.Fatalf("list flavors: %d %s", st, raw)
	}
	all := lbDecodeInto[listFlavorsResponse](t, raw)
	if len(all.Flavors) != 4 || all.PageInfo.CurrentCount != 4 || all.PageInfo.NextMarker != nil {
		t.Fatalf("list all flavors = %+v", all)
	}

	// Golden filtered list (L4) and ShowFlavor (L7 small).
	e.expect(t, "flavors", "list_flavors_l4", http.MethodGet, "/flavors?type=L4", "")
	e.expect(t, "flavors", "show_flavor", http.MethodGet, "/flavors/"+e.l7SmallID, "")
	e.expect(t, "flavors", "error_flavor_not_found", http.MethodGet, "/flavors/"+lbUnknownUUID, "")
	e.expect(t, "flavors", "error_invalid_input", http.MethodGet, "/flavors?limit=0", "")
	e.expect(t, "flavors", "error_invalid_input", http.MethodGet, "/flavors?shared=maybe", "")

	// Pagination on flavors.
	st, raw = e.call(t, http.MethodGet, "/flavors?limit=2", "")
	if st != http.StatusOK {
		t.Fatalf("list flavors page 1: %d %s", st, raw)
	}
	p1 := lbDecodeInto[listFlavorsResponse](t, raw)
	if len(p1.Flavors) != 2 || p1.PageInfo.NextMarker == nil {
		t.Fatalf("flavors page 1 = %+v", p1)
	}
	st, raw = e.call(t, http.MethodGet, "/flavors?limit=2&marker="+*p1.PageInfo.NextMarker, "")
	if st != http.StatusOK {
		t.Fatalf("list flavors page 2: %d %s", st, raw)
	}
	p2 := lbDecodeInto[listFlavorsResponse](t, raw)
	if len(p2.Flavors) != 2 || p2.PageInfo.NextMarker != nil {
		t.Fatalf("flavors page 2 = %+v", p2)
	}

	// Availability zones.
	e.expect(t, "flavors", "list_availability_zones", http.MethodGet, "/availability-zones", "")
	e.expect(t, "loadbalancers", "error_not_found", http.MethodGet, "/availability-zones?loadbalancer_id="+lbUnknownUUID, "")

	st, raw = e.call(t, http.MethodGet, "/availability-zones?public_border_group=edge-1", "")
	if st != http.StatusOK {
		t.Fatalf("list AZ edge: %d %s", st, raw)
	}
	edgeResp := lbDecodeInto[listAvailabilityZonesResponse](t, raw)
	if len(edgeResp.AvailabilityZones) != 0 {
		t.Fatalf("expected empty AZ list for non-center public_border_group, got %+v", edgeResp.AvailabilityZones)
	}
}
