package elb

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
)

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)

	eipID, _ := e.createFreeEIP(t, "bw-inv")

	// 1. Load balancer in the primary project (with EIP and tags).
	st, out := e.call(t, http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {
			"name": "lb-web",
			"vip_subnet_cidr_id": %q,
			"l4_flavor_id": %q,
			"l7_flavor_id": %q,
			"availability_zone_list": [%q],
			"enterprise_project_id": %q,
			"publicip_ids": [%q],
			"tags": [{"key": "env", "value": "prod"}]
		}
	}`, e.neutronSubnetID, e.l4SmallID, e.l7SmallID, lbTestRegion+"a", lbCustomEP, eipID))
	if st != http.StatusCreated {
		t.Fatalf("creating load balancer: %d %s", st, out)
	}
	lb := lbDecodeInto[loadBalancerResponse](t, out).Loadbalancer

	// A load balancer in a second project.
	_, otherSub := e.seedVPCSubnet(t, lbTestTenantB, "vpc-b", "10.20.0.0/16", "sub-b", "10.20.0.0/24", "10.20.0.1")
	if err := e.engine.WaitIdle(t.Context()); err != nil {
		t.Fatalf("WaitIdle second VPC: %v", err)
	}
	st, out = e.callAs(t, lbTestProjectB, http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {
			"name": "lb-other",
			"vip_subnet_cidr_id": %q,
			"l4_flavor_id": %q,
			"availability_zone_list": [%q]
		}
	}`, otherSub.NeutronSubnetID, e.l4SmallID, lbTestRegion+"a"))
	if st != http.StatusCreated {
		t.Fatalf("creating second load balancer: %d %s", st, out)
	}
	otherLB := lbDecodeInto[loadBalancerResponse](t, out).Loadbalancer

	// 2. Pool attached to lb.
	st, out = e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {
			"name": "pool-http",
			"protocol": "HTTP",
			"lb_algorithm": "ROUND_ROBIN",
			"loadbalancer_id": %q,
			"enterprise_project_id": %q
		}
	}`, lb.ID, lbCustomEP))
	if st != http.StatusCreated {
		t.Fatalf("creating pool: %d %s", st, out)
	}
	pl := lbDecodeInto[poolEnvelope](t, out).Pool

	// 3. Listener on lb with default_pool_id set to pl and tags.
	st, out = e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "lsn-http",
			"protocol": "HTTP",
			"protocol_port": 80,
			"loadbalancer_id": %q,
			"default_pool_id": %q,
			"tags": [{"key": "tier", "value": "edge"}]
		}
	}`, lb.ID, pl.ID))
	if st != http.StatusCreated {
		t.Fatalf("creating listener: %d %s", st, out)
	}
	lsn := lbDecodeInto[listenerEnvelope](t, out).Listener

	// 4. Member in pl.
	st, out = e.call(t, http.MethodPost, "/pools/"+pl.ID+"/members", fmt.Sprintf(`{
		"member": {
			"name": "mem-1",
			"address": "192.168.0.50",
			"protocol_port": 8080,
			"subnet_cidr_id": %q
		}
	}`, e.neutronSubnetID))
	if st != http.StatusCreated {
		t.Fatalf("creating member: %d %s", st, out)
	}
	mem := lbDecodeInto[memberResponse](t, out).Member

	// 5. Health monitor on pl.
	st, out = e.call(t, http.MethodPost, "/healthmonitors", fmt.Sprintf(`{
		"healthmonitor": {
			"name": "hm-http",
			"pool_id": %q,
			"type": "HTTP",
			"delay": 5,
			"timeout": 3,
			"max_retries": 3
		}
	}`, pl.ID))
	if st != http.StatusCreated {
		t.Fatalf("creating health monitor: %d %s", st, out)
	}
	hm := lbDecodeInto[healthMonitorEnvelope](t, out).HealthMonitor

	// 6. L7 policy on lsn, plus an L7 rule (which must not be reported).
	st, out = e.call(t, http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "pol-api",
			"listener_id": %q,
			"action": "REDIRECT_TO_POOL",
			"redirect_pool_id": %q
		}
	}`, lsn.ID, pl.ID))
	if st != http.StatusCreated {
		t.Fatalf("creating L7 policy: %d %s", st, out)
	}
	pol := lbDecodeInto[l7PolicyEnvelope](t, out).L7Policy

	st, out = e.call(t, http.MethodPost, "/l7policies/"+pol.ID+"/rules", `{
		"rule": {
			"type": "PATH",
			"compare_type": "STARTS_WITH",
			"value": "/api"
		}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("creating L7 rule: %d %s", st, out)
	}
	l7r := lbDecodeInto[l7RuleEnvelope](t, out).Rule

	// 7. Server certificate with private key.
	cg := certGenECDSA(t, "app.example.com", []string{"app.example.com"}, false, lbTestEpoch.Add(24*time.Hour))
	certBody, err := json.Marshal(map[string]any{
		"certificate": map[string]any{
			"name":                  "cert-tls",
			"type":                  "server",
			"domain":                "app.example.com",
			"certificate":           cg.certPEM,
			"private_key":           cg.keySEC1PEM,
			"enterprise_project_id": lbCustomEP,
		},
	})
	if err != nil {
		t.Fatalf("marshalling certificate body: %v", err)
	}
	st, out = e.call(t, http.MethodPost, "/certificates", string(certBody))
	if st != http.StatusCreated {
		t.Fatalf("creating certificate: %d %s", st, out)
	}
	cert := lbDecodeInto[certEnvelope](t, out).Certificate

	// 8. IP group.
	st, out = e.call(t, http.MethodPost, "/ipgroups", fmt.Sprintf(`{
		"ipgroup": {
			"name": "ipg-allow",
			"ip_list": [{"ip": "10.0.0.1"}],
			"enterprise_project_id": %q
		}
	}`, lbCustomEP))
	if st != http.StatusCreated {
		t.Fatalf("creating IP group: %d %s", st, out)
	}
	ipg := lbDecodeInto[ipgEnvelope](t, out).IPGroup

	// 9. Security policy.
	st, out = e.call(t, http.MethodPost, "/security-policies", fmt.Sprintf(`{
		"security_policy": {
			"name": "sp-tls12",
			"protocols": ["TLSv1.2"],
			"ciphers": ["ECDHE-RSA-AES128-GCM-SHA256"],
			"enterprise_project_id": %q
		}
	}`, lbCustomEP))
	if st != http.StatusCreated {
		t.Fatalf("creating security policy: %d %s", st, out)
	}
	sp := lbDecodeInto[secpolEnvelope](t, out).SecurityPolicy

	// Confirm the load balancer does not emit EIP relations directly.
	var rawLB inventory.Resource
	if err := e.svc.ReportResources(t.Context(), func(r inventory.Resource) error {
		if r.Type == inventory.ELBLoadBalancers && r.ID == lb.ID {
			rawLB = r
		}
		return nil
	}); err != nil {
		t.Fatalf("ReportResources: %v", err)
	}
	if len(rawLB.Relations) != 0 {
		t.Errorf("load balancer raw relations = %v, want none (EIP reports load balancer EIPs)", rawLB.Relations)
	}

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := make(map[string]inventory.Resource)
	for _, r := range snap.Resources {
		if r.ID == l7r.ID {
			t.Errorf("L7 rule %s was reported as %+v", l7r.ID, r)
		}
		got[r.Type.String()+"/"+r.ProjectID+"/"+r.ID] = r
	}
	at := func(typ inventory.Type, project, id string) inventory.Resource {
		t.Helper()
		r, ok := got[typ.String()+"/"+project+"/"+id]
		if !ok {
			t.Fatalf("%s %s in %s is not reported; got %v", typ, id, project, snap.Resources)
		}
		return r
	}

	lbCreated, err := time.Parse(timeFormat, lb.CreatedAt)
	if err != nil {
		t.Fatalf("parsing load balancer CreatedAt: %v", err)
	}

	rLB := at(inventory.ELBLoadBalancers, lbTestProject, lb.ID)
	if rLB.Name != "lb-web" || rLB.RegionID != lbTestRegion || rLB.ProjectID != lbTestProject || rLB.AccountID != "" ||
		rLB.EnterpriseProjectID != lbCustomEP || !rLB.Created.Equal(lbCreated) || rLB.State != inventory.Succeeded ||
		!reflect.DeepEqual(rLB.Tags, map[string]string{"env": "prod"}) {
		t.Errorf("load balancer = %+v", rLB)
	}
	wantLBRels := []inventory.Ref{
		{Relation: inventory.Contains, Type: inventory.ELBListeners, ID: lsn.ID},
		{Relation: inventory.IsAttachedTo, Type: inventory.ELBPools, ID: pl.ID},
	}
	if !reflect.DeepEqual(rLB.Relations, wantLBRels) {
		t.Errorf("load balancer relations = %v, want %v", rLB.Relations, wantLBRels)
	}

	rOtherLB := at(inventory.ELBLoadBalancers, lbTestProjectB, otherLB.ID)
	if rOtherLB.Name != "lb-other" || rOtherLB.RegionID != lbTestRegion || rOtherLB.ProjectID != lbTestProjectB ||
		rOtherLB.AccountID != "" || rOtherLB.EnterpriseProjectID != defaultEnterpriseProjectID ||
		rOtherLB.Created.IsZero() || rOtherLB.State != inventory.Succeeded ||
		!reflect.DeepEqual(rOtherLB.Tags, map[string]string{}) || len(rOtherLB.Relations) != 0 {
		t.Errorf("second project load balancer = %+v", rOtherLB)
	}

	rLsn := at(inventory.ELBListeners, lbTestProject, lsn.ID)
	if rLsn.Name != "lsn-http" || rLsn.RegionID != lbTestRegion || rLsn.ProjectID != lbTestProject || rLsn.AccountID != "" ||
		rLsn.EnterpriseProjectID != lbCustomEP || rLsn.Created.IsZero() || rLsn.State != inventory.Succeeded ||
		!reflect.DeepEqual(rLsn.Tags, map[string]string{"tier": "edge"}) {
		t.Errorf("listener = %+v", rLsn)
	}
	wantLsnRels := []inventory.Ref{
		{Relation: inventory.Contains, Type: inventory.ELBL7Policies, ID: pol.ID},
		{Relation: inventory.IsAttachedTo, Type: inventory.ELBPools, ID: pl.ID},
		{Relation: inventory.IsContainedIn, Type: inventory.ELBLoadBalancers, ID: lb.ID},
	}
	if !reflect.DeepEqual(rLsn.Relations, wantLsnRels) {
		t.Errorf("listener relations = %v, want %v", rLsn.Relations, wantLsnRels)
	}

	rPool := at(inventory.ELBPools, lbTestProject, pl.ID)
	if rPool.Name != "pool-http" || rPool.RegionID != lbTestRegion || rPool.ProjectID != lbTestProject || rPool.AccountID != "" ||
		rPool.EnterpriseProjectID != lbCustomEP || rPool.Created.IsZero() || rPool.State != inventory.Succeeded ||
		!reflect.DeepEqual(rPool.Tags, map[string]string{}) {
		t.Errorf("pool = %+v", rPool)
	}
	wantPoolRels := []inventory.Ref{
		{Relation: inventory.Contains, Type: inventory.ELBMembers, ID: mem.ID},
		{Relation: inventory.IsAttachedTo, Type: inventory.ELBListeners, ID: lsn.ID},
		{Relation: inventory.IsAttachedTo, Type: inventory.ELBLoadBalancers, ID: lb.ID},
	}
	if !reflect.DeepEqual(rPool.Relations, wantPoolRels) {
		t.Errorf("pool relations = %v, want %v", rPool.Relations, wantPoolRels)
	}

	rMem := at(inventory.ELBMembers, lbTestProject, mem.ID)
	if rMem.Name != "mem-1" || rMem.RegionID != lbTestRegion || rMem.ProjectID != lbTestProject || rMem.AccountID != "" ||
		rMem.EnterpriseProjectID != defaultEnterpriseProjectID || rMem.Created.IsZero() || rMem.State != inventory.Succeeded ||
		!reflect.DeepEqual(rMem.Tags, map[string]string{}) {
		t.Errorf("member = %+v", rMem)
	}
	wantMemRels := []inventory.Ref{
		{Relation: inventory.IsContainedIn, Type: inventory.ELBPools, ID: pl.ID},
	}
	if !reflect.DeepEqual(rMem.Relations, wantMemRels) {
		t.Errorf("member relations = %v, want %v", rMem.Relations, wantMemRels)
	}

	rHM := at(inventory.ELBHealthMonitors, lbTestProject, hm.ID)
	if rHM.Name != "hm-http" || rHM.RegionID != lbTestRegion || rHM.ProjectID != lbTestProject || rHM.AccountID != "" ||
		rHM.EnterpriseProjectID != defaultEnterpriseProjectID || rHM.Created.IsZero() || rHM.State != inventory.Succeeded ||
		!reflect.DeepEqual(rHM.Tags, map[string]string{}) || len(rHM.Relations) != 0 {
		t.Errorf("health monitor = %+v", rHM)
	}

	rPol := at(inventory.ELBL7Policies, lbTestProject, pol.ID)
	if rPol.Name != "pol-api" || rPol.RegionID != lbTestRegion || rPol.ProjectID != lbTestProject || rPol.AccountID != "" ||
		rPol.EnterpriseProjectID != lbCustomEP || rPol.Created.IsZero() || rPol.State != inventory.Succeeded ||
		!reflect.DeepEqual(rPol.Tags, map[string]string{}) {
		t.Errorf("L7 policy = %+v", rPol)
	}
	wantPolRels := []inventory.Ref{
		{Relation: inventory.IsContainedIn, Type: inventory.ELBListeners, ID: lsn.ID},
	}
	if !reflect.DeepEqual(rPol.Relations, wantPolRels) {
		t.Errorf("L7 policy relations = %v, want %v", rPol.Relations, wantPolRels)
	}

	rCert := at(inventory.ELBCertificates, lbTestProject, cert.ID)
	if rCert.Name != "cert-tls" || rCert.RegionID != lbTestRegion || rCert.ProjectID != lbTestProject || rCert.AccountID != "" ||
		rCert.EnterpriseProjectID != lbCustomEP || rCert.Created.IsZero() || rCert.State != inventory.Succeeded ||
		!reflect.DeepEqual(rCert.Tags, map[string]string{}) || len(rCert.Relations) != 0 {
		t.Errorf("certificate = %+v", rCert)
	}

	rIPG := at(inventory.ELBIPGroups, lbTestProject, ipg.ID)
	if rIPG.Name != "ipg-allow" || rIPG.RegionID != lbTestRegion || rIPG.ProjectID != lbTestProject || rIPG.AccountID != "" ||
		rIPG.EnterpriseProjectID != lbCustomEP || rIPG.Created.IsZero() || rIPG.State != inventory.Succeeded ||
		!reflect.DeepEqual(rIPG.Tags, map[string]string{}) || len(rIPG.Relations) != 0 {
		t.Errorf("IP group = %+v", rIPG)
	}

	rSP := at(inventory.ELBSecurityPolicies, lbTestProject, sp.ID)
	if rSP.Name != "sp-tls12" || rSP.RegionID != lbTestRegion || rSP.ProjectID != lbTestProject || rSP.AccountID != "" ||
		rSP.EnterpriseProjectID != lbCustomEP || rSP.Created.IsZero() || rSP.State != inventory.Succeeded ||
		!reflect.DeepEqual(rSP.Tags, map[string]string{}) || len(rSP.Relations) != 0 {
		t.Errorf("security policy = %+v", rSP)
	}

	// Certificate private key material (plain or sealed) must never appear in the snapshot.
	storedCert, err := e.svc.certificates(lbTestTenant).Get(t.Context(), cert.ID)
	if err != nil {
		t.Fatalf("reading stored certificate: %v", err)
	}
	if len(storedCert.SealedPrivateKey) == 0 {
		t.Fatal("stored certificate has empty SealedPrivateKey")
	}
	dump := fmt.Sprintf("%+v", snap)
	for _, secret := range []string{
		"PRIVATE KEY",
		cg.keySEC1PEM,
		cg.keyPKCS8PEM,
		pemBodyLine(cg.keySEC1PEM),
		string(storedCert.SealedPrivateKey),
		hex.EncodeToString(storedCert.SealedPrivateKey),
		base64.StdEncoding.EncodeToString(storedCert.SealedPrivateKey),
	} {
		if secret != "" && strings.Contains(dump, secret) {
			t.Errorf("snapshot contains certificate secret material %q", secret)
		}
	}

	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.ELBLoadBalancers:    2,
		inventory.ELBListeners:        1,
		inventory.ELBPools:            1,
		inventory.ELBMembers:          1,
		inventory.ELBHealthMonitors:   1,
		inventory.ELBL7Policies:       1,
		inventory.ELBCertificates:     1,
		inventory.ELBIPGroups:         1,
		inventory.ELBSecurityPolicies: 1,
	}
	if !reflect.DeepEqual(count, want) {
		t.Errorf("reported %v, want %v", count, want)
	}
}

func TestReportResourcesUnboundOptionalRelations(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)

	// Load balancer with a listener that has no DefaultPoolID, plus an unbound IP pool.
	st, out := e.call(t, http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {
			"name": "lb-bare",
			"vip_subnet_cidr_id": %q,
			"l4_flavor_id": %q,
			"availability_zone_list": [%q]
		}
	}`, e.neutronSubnetID, e.l4SmallID, lbTestRegion+"a"))
	if st != http.StatusCreated {
		t.Fatalf("creating load balancer: %d %s", st, out)
	}
	lb := lbDecodeInto[loadBalancerResponse](t, out).Loadbalancer

	st, out = e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "lsn-no-pool",
			"protocol": "TCP",
			"protocol_port": 443,
			"loadbalancer_id": %q
		}
	}`, lb.ID))
	if st != http.StatusCreated {
		t.Fatalf("creating listener: %d %s", st, out)
	}
	lsn := lbDecodeInto[listenerEnvelope](t, out).Listener

	st, out = e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {
			"name": "pool-unbound",
			"protocol": "TCP",
			"lb_algorithm": "ROUND_ROBIN",
			"type": "ip",
			"vpc_id": %q
		}
	}`, e.vpcID))
	if st != http.StatusCreated {
		t.Fatalf("creating unbound pool: %d %s", st, out)
	}
	pl := lbDecodeInto[poolEnvelope](t, out).Pool

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := make(map[string]inventory.Resource)
	for _, r := range snap.Resources {
		byID[r.ID] = r
	}
	wantLsnRels := []inventory.Ref{{Relation: inventory.IsContainedIn, Type: inventory.ELBLoadBalancers, ID: lb.ID}}
	if got := byID[lsn.ID].Relations; !reflect.DeepEqual(got, wantLsnRels) {
		t.Errorf("listener without default pool relations = %v, want %v", got, wantLsnRels)
	}
	if got := byID[pl.ID].Relations; len(got) != 0 {
		t.Errorf("unbound pool relations = %v, want none", got)
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	e := newLBEnv(t)

	// Create resources across administrative and operating states (ACTIVE,
	// OFFLINE when admin_state_up is false, NO_MONITOR without a monitor):
	// ELB creates all resources active, so every resource reports Succeeded.
	st, out := e.call(t, http.MethodPost, "/loadbalancers", fmt.Sprintf(`{
		"loadbalancer": {
			"name": "lb-down",
			"admin_state_up": false,
			"vip_subnet_cidr_id": %q,
			"l4_flavor_id": %q,
			"availability_zone_list": [%q]
		}
	}`, e.neutronSubnetID, e.l4SmallID, lbTestRegion+"a"))
	if st != http.StatusCreated {
		t.Fatalf("creating load balancer: %d %s", st, out)
	}
	lb := lbDecodeInto[loadBalancerResponse](t, out).Loadbalancer
	if lb.ProvisioningStatus != StatusActive || lb.OperatingStatus != StatusOnline {
		t.Fatalf("load balancer statuses = %s/%s", lb.ProvisioningStatus, lb.OperatingStatus)
	}

	st, out = e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {
			"name": "pool-unmonitored",
			"protocol": "TCP",
			"lb_algorithm": "ROUND_ROBIN",
			"loadbalancer_id": %q
		}
	}`, lb.ID))
	if st != http.StatusCreated {
		t.Fatalf("creating pool: %d %s", st, out)
	}
	pl := lbDecodeInto[poolEnvelope](t, out).Pool

	// One member without a monitor (NO_MONITOR) and one administratively down (OFFLINE).
	st, out = e.call(t, http.MethodPost, "/pools/"+pl.ID+"/members", fmt.Sprintf(`{
		"member": {
			"name": "mem-nomon",
			"address": "192.168.0.60",
			"protocol_port": 80,
			"subnet_cidr_id": %q
		}
	}`, e.neutronSubnetID))
	if st != http.StatusCreated {
		t.Fatalf("creating unmonitored member: %d %s", st, out)
	}
	if got := lbDecodeInto[memberResponse](t, out).Member.OperatingStatus; got != StatusNoMonitor {
		t.Fatalf("member operating_status = %s, want %s", got, StatusNoMonitor)
	}

	st, out = e.call(t, http.MethodPost, "/pools/"+pl.ID+"/members", fmt.Sprintf(`{
		"member": {
			"name": "mem-offline",
			"address": "192.168.0.61",
			"protocol_port": 80,
			"admin_state_up": false,
			"subnet_cidr_id": %q
		}
	}`, e.neutronSubnetID))
	if st != http.StatusCreated {
		t.Fatalf("creating offline member: %d %s", st, out)
	}
	if got := lbDecodeInto[memberResponse](t, out).Member.OperatingStatus; got != StatusOffline {
		t.Fatalf("member operating_status = %s, want %s", got, StatusOffline)
	}

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(snap.Resources) == 0 {
		t.Fatal("expected reported resources")
	}
	for _, r := range snap.Resources {
		if r.State != inventory.Succeeded {
			t.Errorf("%s %s (%s) state = %s, want %s", r.Type, r.ID, r.Name, r.State, inventory.Succeeded)
		}
	}
}

func pemBodyLine(pemText string) string {
	for line := range strings.SplitSeq(pemText, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "-----") {
			return line
		}
	}
	return ""
}
