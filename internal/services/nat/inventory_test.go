package nat

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/inventory"
)

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newGWEnv(t)
	e.svc.eips = newFakePublicIPs()

	vpcB, subB := e.seedVPCSubnet(t, gwTestTenantB, "vpc-b", "172.16.0.0/16", "sub-b", "172.16.0.0/24", "172.16.0.1")

	callHTTP := func(method, path, body string) []byte {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rd)
		req.Host = gwTestHost
		rec := httptest.NewRecorder()
		e.handler.ServeHTTP(rec, req)
		res := rec.Result()
		defer res.Body.Close()
		out, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("reading %s %s: %v", method, path, err)
		}
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, out)
		}
		return out
	}

	gwOut := callHTTP(http.MethodPost, "/v2/"+gwTestProject+"/nat_gateways", fmt.Sprintf(
		`{"nat_gateway": {"name": "pub-gw", "router_id": %q, "internal_network_id": %q, "spec": "1", "enterprise_project_id": %q, "tags": ["env*dev"]}}`,
		e.vpcID, e.subnetID, gwCustomEP,
	))
	gw := gwDecodeInto[natGatewayEnvelope](t, gwOut).NatGateway
	e.settle(t)

	snatOut := callHTTP(http.MethodPost, "/v2/"+gwTestProject+"/snat_rules", fmt.Sprintf(
		`{"snat_rule": {"nat_gateway_id": %q, "network_id": %q, "floating_ip_id": %q}}`,
		gw.ID, e.subnetID, rulesEIP1ID,
	))
	snat := gwDecodeInto[snatRuleResponse](t, snatOut).SnatRule

	dnatOut := callHTTP(http.MethodPost, "/v2/"+gwTestProject+"/dnat_rules", fmt.Sprintf(
		`{"dnat_rule": {"nat_gateway_id": %q, "private_ip": "192.168.0.50", "protocol": "tcp", "internal_service_port": 80, "external_service_port": 8080, "floating_ip_id": %q}}`,
		gw.ID, rulesEIP2ID,
	))
	dnat := gwDecodeInto[dnatRuleResponse](t, dnatOut).DnatRule
	e.settle(t)

	pgwOut := callHTTP(http.MethodPost, "/v3/"+gwTestProject+"/private-nat/gateways", fmt.Sprintf(
		`{"gateway": {"name": "priv-gw", "downlink_vpcs": [{"virsubnet_id": %q}], "enterprise_project_id": %q, "tags": [{"key": "role", "value": "private"}]}}`,
		e.subnetID, gwCustomEP,
	))
	pgw := gwDecodeInto[privateNatEnvelope](t, pgwOut).Gateway

	tsOut := callHTTP(http.MethodPost, "/v3/"+gwTestProject+"/private-nat/transit-subnets", fmt.Sprintf(
		`{"transit_subnet": {"name": "tsub", "virsubnet_id": %q, "virsubnet_project_id": %q, "tags": [{"key": "tier", "value": "transit"}]}}`,
		e.subnet2, gwTestProject,
	))
	ts := gwDecodeInto[transitSubnetEnvelope](t, tsOut).TransitSubnet

	ti1Out := callHTTP(http.MethodPost, "/v3/"+gwTestProject+"/private-nat/transit-ips", fmt.Sprintf(
		`{"transit_ip": {"virsubnet_id": %q, "enterprise_project_id": %q, "tags": [{"key": "purpose", "value": "snat"}]}}`,
		e.subnet2, gwCustomEP,
	))
	ti1 := gwDecodeInto[transitIPEnvelope](t, ti1Out).TransitIP

	ti2Out := callHTTP(http.MethodPost, "/v3/"+gwTestProject+"/private-nat/transit-ips", fmt.Sprintf(
		`{"transit_ip": {"virsubnet_id": %q}}`,
		e.subnet2,
	))
	ti2 := gwDecodeInto[transitIPEnvelope](t, ti2Out).TransitIP

	psnatOut := callHTTP(http.MethodPost, "/v3/"+gwTestProject+"/private-nat/snat-rules", fmt.Sprintf(
		`{"snat_rule": {"gateway_id": %q, "virsubnet_id": %q, "transit_ip_ids": [%q]}}`,
		pgw.ID, e.subnetID, ti1.ID,
	))
	psnat := gwDecodeInto[privateSnatEnvelope](t, psnatOut).SnatRule

	pdnatOut := callHTTP(http.MethodPost, "/v3/"+gwTestProject+"/private-nat/dnat-rules", fmt.Sprintf(
		`{"dnat_rule": {"gateway_id": %q, "transit_ip_id": %q, "private_ip_address": "192.168.0.60", "protocol": "tcp", "internal_service_port": "80", "transit_service_port": "8080"}}`,
		pgw.ID, ti2.ID,
	))
	pdnat := gwDecodeInto[privateDnatEnvelope](t, pdnatOut).DnatRule

	// A gateway in a second project, still in PENDING_CREATE.
	pendingOut := callHTTP(http.MethodPost, "/v2/"+gwTestProjectB+"/nat_gateways", fmt.Sprintf(
		`{"nat_gateway": {"name": "pending-gw", "router_id": %q, "internal_network_id": %q, "spec": "1"}}`,
		vpcB, subB,
	))
	pendingGW := gwDecodeInto[natGatewayEnvelope](t, pendingOut).NatGateway

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := make(map[string]inventory.Resource)
	for _, r := range snap.Resources {
		got[r.Type.String()+"/"+r.ProjectID+"/"+r.ID] = r
	}
	at := func(typ inventory.Type, project, id string) inventory.Resource {
		t.Helper()
		r, ok := got[typ.String()+"/"+project+"/"+id]
		if !ok {
			t.Fatalf("%s %s is not reported; got %v", typ, id, snap.Resources)
		}
		return r
	}

	check := func(r inventory.Resource, wantName, wantProject, wantEP string, wantState inventory.State, wantTags map[string]string) {
		t.Helper()
		if r.Name != wantName || r.RegionID != gwTestRegion || r.ProjectID != wantProject || r.AccountID != "" ||
			r.EnterpriseProjectID != wantEP || !r.Created.Equal(gwTestEpoch) || !r.Updated.Equal(gwTestEpoch) ||
			r.State != wantState || !reflect.DeepEqual(r.Tags, wantTags) || len(r.Relations) != 0 {
			t.Errorf("%s %s = %+v", r.Type, r.ID, r)
		}
	}

	emptyTags := map[string]string{}
	check(at(inventory.NATGateways, gwTestProject, gw.ID), "pub-gw", gwTestProject, gwCustomEP, inventory.Succeeded, map[string]string{"env": "dev"})
	check(at(inventory.NATGateways, gwTestProjectB, pendingGW.ID), "pending-gw", gwTestProjectB, inventory.DefaultEnterpriseProject, inventory.Processing, emptyTags)
	check(at(inventory.NATSNATRules, gwTestProject, snat.ID), "", gwTestProject, inventory.DefaultEnterpriseProject, inventory.Succeeded, emptyTags)
	check(at(inventory.NATDNATRules, gwTestProject, dnat.ID), "", gwTestProject, inventory.DefaultEnterpriseProject, inventory.Succeeded, emptyTags)
	check(at(inventory.NATPrivateGateways, gwTestProject, pgw.ID), "priv-gw", gwTestProject, gwCustomEP, inventory.Succeeded, map[string]string{"role": "private"})
	check(at(inventory.NATPrivateSNATRules, gwTestProject, psnat.ID), "", gwTestProject, inventory.DefaultEnterpriseProject, inventory.Succeeded, emptyTags)
	check(at(inventory.NATPrivateDNATRules, gwTestProject, pdnat.ID), "", gwTestProject, inventory.DefaultEnterpriseProject, inventory.Succeeded, emptyTags)
	check(at(inventory.NATTransitSubnets, gwTestProject, ts.ID), "tsub", gwTestProject, inventory.DefaultEnterpriseProject, inventory.Succeeded, map[string]string{"tier": "transit"})
	check(at(inventory.NATTransitIPs, gwTestProject, ti1.ID), "", gwTestProject, gwCustomEP, inventory.Succeeded, map[string]string{"purpose": "snat"})
	check(at(inventory.NATTransitIPs, gwTestProject, ti2.ID), "", gwTestProject, inventory.DefaultEnterpriseProject, inventory.Succeeded, emptyTags)

	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.NATGateways:         len([]string{gw.ID, pendingGW.ID}),
		inventory.NATSNATRules:        1,
		inventory.NATDNATRules:        1,
		inventory.NATPrivateGateways:  1,
		inventory.NATPrivateSNATRules: 1,
		inventory.NATPrivateDNATRules: 1,
		inventory.NATTransitSubnets:   1,
		inventory.NATTransitIPs:       len([]string{ti1.ID, ti2.ID}),
	}
	if !reflect.DeepEqual(count, want) {
		t.Errorf("reported %v, want %v", count, want)
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	for status, want := range map[string]inventory.State{
		StatusPendingCreate: inventory.Processing,
		StatusActive:        inventory.Succeeded,
		StatusInactive:      inventory.Succeeded,
	} {
		if got := natState(status); got != want {
			t.Errorf("natState(%s) = %s, want %s", status, got, want)
		}
	}
}
