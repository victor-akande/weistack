package elb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

type quotaEnv struct {
	svc             *Service
	vpcSvc          *vpc.Service
	store           store.Store
	engine          *lifecycle.Engine
	handler         http.Handler
	vpcID           string
	neutronSubnetID string
	l4FlavorID      string
	l7FlavorID      string
}

func newQuotaEnv(t *testing.T, limits quota.Limits) *quotaEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(lbTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: 0, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(101)
	vlt, err := vault.New(make([]byte, vault.KeyLen))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	eipSvc, err := eip.New(eip.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Ports: vpcSvc, Now: clock.Now})
	if err != nil {
		t.Fatalf("eip.New: %v", err)
	}
	vpcSvc.Extend(eipSvc)

	svc, err := New(Deps{
		Quotas:  limits,
		Store:   st,
		IDs:     gen,
		Logger:  log,
		Vault:   vlt,
		VPC:     vpcSvc,
		EIPs:    eipSvc,
		Servers: lbStubServers{},
		Now:     clock.Now,
	})
	if err != nil {
		t.Fatalf("elb.New: %v", err)
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	srv, err := server.New(server.Options{
		Config:    cfg,
		ProjectID: lbTestProject,
		Logger:    log,
		Store:     st,
		Engine:    engine,
		IDs:       gen,
		Services:  []server.Service{vpcSvc, svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	e := &quotaEnv{
		svc:     svc,
		vpcSvc:  vpcSvc,
		store:   st,
		engine:  engine,
		handler: srv.Handler(),
	}

	for _, f := range seededFlavors(lbTestRegion, lbTestProject) {
		switch f.Name {
		case "L4_flavor.elb.s2.small":
			e.l4FlavorID = f.ID
		case "L7_flavor.elb.s1.small":
			e.l7FlavorID = f.ID
		}
	}

	cidr := "192.168.0.0/16"
	v, err := vpcSvc.CreateVPC(t.Context(), lbTestTenant, vpc.CreateVPCOption{
		Name: lbPtr("quota-vpc"),
		CIDR: &cidr,
	})
	if err != nil {
		t.Fatalf("CreateVPC: %v", err)
	}
	sn, err := vpcSvc.CreateSubnet(t.Context(), lbTestTenant, vpc.CreateSubnetOption{
		Name:      "quota-sub",
		CIDR:      "192.168.0.0/24",
		GatewayIP: "192.168.0.1",
		VPCID:     v.ID,
	})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := engine.WaitIdle(waitCtx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
	e.vpcID = v.ID
	e.neutronSubnetID = sn.NeutronSubnetID
	return e
}

func (e *quotaEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v3/"+lbTestProject+"/elb"+path, rd)
	r.Host = lbTestHost
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return res.StatusCode, out
}

func assertELBQuotaError(t *testing.T, status int, body []byte, wantStatus int, wantCode, wantMsg string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d; body: %s", status, wantStatus, body)
	}
	var got struct {
		ErrorCode string `json:"error_code"`
		ErrorMsg  string `json:"error_msg"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal error body %s: %v", body, err)
	}
	if got.ErrorCode != wantCode {
		t.Errorf("error_code = %q, want %q", got.ErrorCode, wantCode)
	}
	if got.ErrorMsg != wantMsg {
		t.Errorf("error_msg = %q, want %q", got.ErrorMsg, wantMsg)
	}
}

func (e *quotaEnv) mustCreateLB(t *testing.T, name string) string {
	t.Helper()
	body := fmt.Sprintf(`{"loadbalancer":{"name":%q,"vpc_id":%q,"vip_subnet_cidr_id":%q,"l4_flavor_id":%q,"l7_flavor_id":%q,"availability_zone_list":["ap-southeast-1a"]}}`,
		name, e.vpcID, e.neutronSubnetID, e.l4FlavorID, e.l7FlavorID)
	status, out := e.call(t, http.MethodPost, "/loadbalancers", body)
	if status != http.StatusCreated {
		t.Fatalf("create LB %s: status %d: %s", name, status, out)
	}
	var resp struct {
		LoadBalancer struct {
			ID string `json:"id"`
		} `json:"loadbalancer"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal LB: %v", err)
	}
	return resp.LoadBalancer.ID
}

func (e *quotaEnv) mustCreateListener(t *testing.T, lbID, name string, port int) string {
	t.Helper()
	body := fmt.Sprintf(`{"listener":{"loadbalancer_id":%q,"name":%q,"protocol":"HTTP","protocol_port":%d}}`, lbID, name, port)
	status, out := e.call(t, http.MethodPost, "/listeners", body)
	if status != http.StatusCreated {
		t.Fatalf("create listener %s: status %d: %s", name, status, out)
	}
	var resp struct {
		Listener struct {
			ID string `json:"id"`
		} `json:"listener"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal listener: %v", err)
	}
	return resp.Listener.ID
}

func (e *quotaEnv) mustCreatePool(t *testing.T, lbID, name string) string {
	t.Helper()
	body := fmt.Sprintf(`{"pool":{"loadbalancer_id":%q,"name":%q,"protocol":"HTTP","lb_algorithm":"ROUND_ROBIN"}}`, lbID, name)
	status, out := e.call(t, http.MethodPost, "/pools", body)
	if status != http.StatusCreated {
		t.Fatalf("create pool %s: status %d: %s", name, status, out)
	}
	var resp struct {
		Pool struct {
			ID string `json:"id"`
		} `json:"pool"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal pool: %v", err)
	}
	return resp.Pool.ID
}

func (e *quotaEnv) mustCreateMember(t *testing.T, poolID, addr string, port int) string {
	t.Helper()
	body := fmt.Sprintf(`{"member":{"address":%q,"protocol_port":%d,"subnet_cidr_id":%q}}`, addr, port, e.neutronSubnetID)
	status, out := e.call(t, http.MethodPost, "/pools/"+poolID+"/members", body)
	if status != http.StatusCreated {
		t.Fatalf("create member %s: status %d: %s", addr, status, out)
	}
	var resp struct {
		Member struct {
			ID string `json:"id"`
		} `json:"member"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal member: %v", err)
	}
	return resp.Member.ID
}

func (e *quotaEnv) mustCreateCert(t *testing.T, name string, cert certGenerated) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"certificate": map[string]any{
			"name":        name,
			"type":        "server",
			"certificate": cert.certPEM,
			"private_key": cert.keyPKCS1PEM,
		},
	})
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}
	status, out := e.call(t, http.MethodPost, "/certificates", string(payload))
	if status != http.StatusCreated {
		t.Fatalf("create cert %s: status %d: %s", name, status, out)
	}
	var resp struct {
		Certificate struct {
			ID string `json:"id"`
		} `json:"certificate"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal cert: %v", err)
	}
	return resp.Certificate.ID
}

func (e *quotaEnv) mustCreateL7Policy(t *testing.T, listenerID, name string) string {
	t.Helper()
	body := fmt.Sprintf(`{"l7policy":{"listener_id":%q,"name":%q,"action":"REDIRECT_TO_URL","redirect_url_config":{"status_code":"301","host":"example.com"}}}`, listenerID, name)
	status, out := e.call(t, http.MethodPost, "/l7policies", body)
	if status != http.StatusCreated {
		t.Fatalf("create l7policy %s: status %d: %s", name, status, out)
	}
	var resp struct {
		L7Policy struct {
			ID string `json:"id"`
		} `json:"l7policy"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal l7policy: %v", err)
	}
	return resp.L7Policy.ID
}

func TestQuotasEnforcedAndDeleteFrees(t *testing.T) {
	t.Run("loadbalancer", func(t *testing.T) {
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBLoadBalancer: 2}))
		id1 := e.mustCreateLB(t, "lb-1")
		_ = e.mustCreateLB(t, "lb-2")

		body := fmt.Sprintf(`{"loadbalancer":{"name":"lb-3","vpc_id":%q,"vip_subnet_cidr_id":%q,"l4_flavor_id":%q,"availability_zone_list":["ap-southeast-1a"]}}`,
			e.vpcID, e.neutronSubnetID, e.l4FlavorID)
		status, out := e.call(t, http.MethodPost, "/loadbalancers", body)
		assertELBQuotaError(t, status, out, http.StatusForbidden, "ELB.1091", "The number of load balancers exceeds the quota.")

		if st, delOut := e.call(t, http.MethodDelete, "/loadbalancers/"+id1, ""); st != http.StatusNoContent {
			t.Fatalf("delete LB: status %d: %s", st, delOut)
		}
		_ = e.mustCreateLB(t, "lb-3-ok")
	})

	t.Run("listener", func(t *testing.T) {
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBListener: 2}))
		lbID := e.mustCreateLB(t, "lb-1")
		id1 := e.mustCreateListener(t, lbID, "lsn-1", 80)
		_ = e.mustCreateListener(t, lbID, "lsn-2", 81)

		body := fmt.Sprintf(`{"listener":{"loadbalancer_id":%q,"name":"lsn-3","protocol":"HTTP","protocol_port":82}}`, lbID)
		status, out := e.call(t, http.MethodPost, "/listeners", body)
		assertELBQuotaError(t, status, out, http.StatusForbidden, "ELB.6091", "The number of listeners reaches the limit.")

		if st, delOut := e.call(t, http.MethodDelete, "/listeners/"+id1, ""); st != http.StatusNoContent {
			t.Fatalf("delete listener: status %d: %s", st, delOut)
		}
		_ = e.mustCreateListener(t, lbID, "lsn-3-ok", 82)
	})

	t.Run("member", func(t *testing.T) {
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBMember: 2}))
		lbID := e.mustCreateLB(t, "lb-1")
		pool1 := e.mustCreatePool(t, lbID, "pool-1")
		pool2 := e.mustCreatePool(t, lbID, "pool-2")
		m1 := e.mustCreateMember(t, pool1, "192.168.0.10", 80)
		_ = e.mustCreateMember(t, pool2, "192.168.0.11", 80)

		// Per-project limit applies across pools.
		body := fmt.Sprintf(`{"member":{"address":"192.168.0.12","protocol_port":80,"subnet_cidr_id":%q}}`, e.neutronSubnetID)
		status, out := e.call(t, http.MethodPost, "/pools/"+pool2+"/members", body)
		assertELBQuotaError(t, status, out, http.StatusForbidden, "ELB.2001", "Creating the member failed. The total number of members exceeds the upper limit.")

		if st, delOut := e.call(t, http.MethodDelete, "/pools/"+pool1+"/members/"+m1, ""); st != http.StatusNoContent {
			t.Fatalf("delete member: status %d: %s", st, delOut)
		}
		_ = e.mustCreateMember(t, pool2, "192.168.0.12", 80)
	})

	t.Run("certificate", func(t *testing.T) {
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBCertificate: 2}))
		cert := certGenRSA(t, "example.com", nil, nil, false, lbTestEpoch.Add(24*time.Hour))
		c1 := e.mustCreateCert(t, "cert-1", cert)
		_ = e.mustCreateCert(t, "cert-2", cert)

		payload, _ := json.Marshal(map[string]any{
			"certificate": map[string]any{
				"name":        "cert-3",
				"type":        "server",
				"certificate": cert.certPEM,
				"private_key": cert.keyPKCS1PEM,
			},
		})
		status, out := e.call(t, http.MethodPost, "/certificates", string(payload))
		assertELBQuotaError(t, status, out, http.StatusBadRequest, "ELB.5151", "The certificate quantity exceeds the quota.")

		if st, delOut := e.call(t, http.MethodDelete, "/certificates/"+c1, ""); st != http.StatusNoContent {
			t.Fatalf("delete cert: status %d: %s", st, delOut)
		}
		_ = e.mustCreateCert(t, "cert-3-ok", cert)
	})

	t.Run("pool", func(t *testing.T) {
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBPool: 2}))
		lbID := e.mustCreateLB(t, "lb-1")
		p1 := e.mustCreatePool(t, lbID, "pool-1")
		_ = e.mustCreatePool(t, lbID, "pool-2")

		body := fmt.Sprintf(`{"pool":{"loadbalancer_id":%q,"name":"pool-3","protocol":"HTTP","lb_algorithm":"ROUND_ROBIN"}}`, lbID)
		status, out := e.call(t, http.MethodPost, "/pools", body)
		assertELBQuotaError(t, status, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: pool")

		if st, delOut := e.call(t, http.MethodDelete, "/pools/"+p1, ""); st != http.StatusNoContent {
			t.Fatalf("delete pool: status %d: %s", st, delOut)
		}
		_ = e.mustCreatePool(t, lbID, "pool-3-ok")
	})

	t.Run("l7policy_then_l7policies_per_listener", func(t *testing.T) {
		// When both elb.l7policy and elb.l7policies_per_listener are reached, elb.l7policy wins.
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{
			quota.ELBL7Policy:              1,
			quota.ELBL7PoliciesPerListener: 1,
		}))
		lbID := e.mustCreateLB(t, "lb-1")
		lsn1 := e.mustCreateListener(t, lbID, "lsn-1", 80)
		pol1 := e.mustCreateL7Policy(t, lsn1, "pol-1")

		body := fmt.Sprintf(`{"l7policy":{"listener_id":%q,"name":"pol-2","action":"REDIRECT_TO_URL","redirect_url_config":{"status_code":"301","host":"example.com"}}}`, lsn1)
		status, out := e.call(t, http.MethodPost, "/l7policies", body)
		assertELBQuotaError(t, status, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: l7policy")

		if st, delOut := e.call(t, http.MethodDelete, "/l7policies/"+pol1, ""); st != http.StatusNoContent {
			t.Fatalf("delete l7policy: status %d: %s", st, delOut)
		}
		_ = e.mustCreateL7Policy(t, lsn1, "pol-2-ok")

		// With elb.l7policy higher, elb.l7policies_per_listener is enforced per listener.
		e2 := newQuotaEnv(t, quota.For(map[quota.Key]int{
			quota.ELBL7Policy:              5,
			quota.ELBL7PoliciesPerListener: 1,
		}))
		lb2 := e2.mustCreateLB(t, "lb-2")
		lsnA := e2.mustCreateListener(t, lb2, "lsn-a", 80)
		lsnB := e2.mustCreateListener(t, lb2, "lsn-b", 81)
		polA := e2.mustCreateL7Policy(t2OrT(t), lsnA, "pol-a")

		bodyA2 := fmt.Sprintf(`{"l7policy":{"listener_id":%q,"name":"pol-a2","action":"REDIRECT_TO_URL","redirect_url_config":{"status_code":"301","host":"example.com"}}}`, lsnA)
		status, out = e2.call(t, http.MethodPost, "/l7policies", bodyA2)
		assertELBQuotaError(t, status, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: l7policies_per_listener")

		// Another listener can still create its own L7 policy.
		_ = e2.mustCreateL7Policy(t, lsnB, "pol-b")

		// Deleting polA frees the slot on lsnA.
		if st, delOut := e2.call(t, http.MethodDelete, "/l7policies/"+polA, ""); st != http.StatusNoContent {
			t.Fatalf("delete l7policy: status %d: %s", st, delOut)
		}
		_ = e2.mustCreateL7Policy(t, lsnA, "pol-a2-ok")
	})
}

func t2OrT(t *testing.T) *testing.T { return t }

func TestQuotasUnlimited(t *testing.T) {
	e := newQuotaEnv(t, quota.For(map[quota.Key]int{
		quota.ELBLoadBalancer:          quota.Unlimited,
		quota.ELBListener:              quota.Unlimited,
		quota.ELBPool:                  quota.Unlimited,
		quota.ELBMember:                quota.Unlimited,
		quota.ELBCertificate:           quota.Unlimited,
		quota.ELBL7Policy:              quota.Unlimited,
		quota.ELBL7PoliciesPerListener: quota.Unlimited,
	}))

	lbID := e.mustCreateLB(t, "lb-1")
	_ = e.mustCreateLB(t, "lb-2")
	lsnID := e.mustCreateListener(t, lbID, "lsn-1", 80)
	_ = e.mustCreateListener(t, lbID, "lsn-2", 81)
	poolID := e.mustCreatePool(t, lbID, "pool-1")
	_ = e.mustCreatePool(t, lbID, "pool-2")
	_ = e.mustCreateMember(t, poolID, "192.168.0.10", 80)
	_ = e.mustCreateMember(t, poolID, "192.168.0.11", 80)
	cert := certGenRSA(t, "unlim.example.com", nil, nil, false, lbTestEpoch.Add(24*time.Hour))
	_ = e.mustCreateCert(t, "cert-1", cert)
	_ = e.mustCreateCert(t, "cert-2", cert)
	_ = e.mustCreateL7Policy(t, lsnID, "pol-1")
	_ = e.mustCreateL7Policy(t, lsnID, "pol-2")
}

func TestQuotasExistingDataOverLimit(t *testing.T) {
	e := newQuotaEnv(t, quota.For(map[quota.Key]int{
		quota.ELBLoadBalancer:          1,
		quota.ELBListener:              1,
		quota.ELBPool:                  1,
		quota.ELBMember:                1,
		quota.ELBCertificate:           1,
		quota.ELBL7Policy:              1,
		quota.ELBL7PoliciesPerListener: 1,
	}))
	ctx := t.Context()

	// Seed 2 of each resource directly in the store (above limit 1).
	lb1 := loadBalancer{ID: e.svc.ids.UUID(), Name: "seed-lb-1", L4FlavorID: e.l4FlavorID, L7FlavorID: e.l7FlavorID, VPCID: e.vpcID, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	lb2 := loadBalancer{ID: e.svc.ids.UUID(), Name: "seed-lb-2", L4FlavorID: e.l4FlavorID, L7FlavorID: e.l7FlavorID, VPCID: e.vpcID, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	for _, lb := range []loadBalancer{lb1, lb2} {
		if err := e.svc.loadBalancers(lbTestTenant).Create(ctx, lb.ID, lb); err != nil {
			t.Fatalf("seed LB: %v", err)
		}
	}

	lsn1 := listener{ID: e.svc.ids.UUID(), LoadBalancerID: lb1.ID, Name: "seed-lsn-1", Protocol: "HTTP", ProtocolPort: 80, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	lsn2 := listener{ID: e.svc.ids.UUID(), LoadBalancerID: lb1.ID, Name: "seed-lsn-2", Protocol: "HTTP", ProtocolPort: 81, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	for _, l := range []listener{lsn1, lsn2} {
		if err := e.svc.listeners(lbTestTenant).Create(ctx, l.ID, l); err != nil {
			t.Fatalf("seed listener: %v", err)
		}
	}

	p1 := pool{ID: e.svc.ids.UUID(), LoadBalancerID: lb1.ID, Name: "seed-pool-1", Protocol: "HTTP", LBAlgorithm: "ROUND_ROBIN", AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	p2 := pool{ID: e.svc.ids.UUID(), LoadBalancerID: lb1.ID, Name: "seed-pool-2", Protocol: "HTTP", LBAlgorithm: "ROUND_ROBIN", AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	for _, p := range []pool{p1, p2} {
		if err := e.svc.pools(lbTestTenant).Create(ctx, p.ID, p); err != nil {
			t.Fatalf("seed pool: %v", err)
		}
	}

	m1 := member{ID: e.svc.ids.UUID(), PoolID: p1.ID, Address: "192.168.0.10", ProtocolPort: 80, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	m2 := member{ID: e.svc.ids.UUID(), PoolID: p1.ID, Address: "192.168.0.11", ProtocolPort: 80, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	for _, m := range []member{m1, m2} {
		if err := e.svc.members(lbTestTenant).Create(ctx, m.ID, m); err != nil {
			t.Fatalf("seed member: %v", err)
		}
	}

	c1 := certificate{ID: e.svc.ids.UUID(), Name: "seed-cert-1", Type: certTypeServer, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	c2 := certificate{ID: e.svc.ids.UUID(), Name: "seed-cert-2", Type: certTypeServer, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	for _, c := range []certificate{c1, c2} {
		if err := e.svc.certificates(lbTestTenant).Create(ctx, c.ID, c); err != nil {
			t.Fatalf("seed cert: %v", err)
		}
	}

	pol1 := l7Policy{ID: e.svc.ids.UUID(), ListenerID: lsn1.ID, Name: "seed-pol-1", Action: l7ActionRedirectToURL, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	pol2 := l7Policy{ID: e.svc.ids.UUID(), ListenerID: lsn1.ID, Name: "seed-pol-2", Action: l7ActionRedirectToURL, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
	for _, pol := range []l7Policy{pol1, pol2} {
		if err := e.svc.l7Policies(lbTestTenant).Create(ctx, pol.ID, pol); err != nil {
			t.Fatalf("seed l7policy: %v", err)
		}
	}

	// Existing records are kept.
	if lbs, err := e.svc.loadBalancers(lbTestTenant).List(ctx, nil); err != nil || len(lbs) != 2 {
		t.Fatalf("loadbalancers len = %d, err = %v; want 2", len(lbs), err)
	}
	if lsns, err := e.svc.listeners(lbTestTenant).List(ctx, nil); err != nil || len(lsns) != 2 {
		t.Fatalf("listeners len = %d, err = %v; want 2", len(lsns), err)
	}
	if pools, err := e.svc.pools(lbTestTenant).List(ctx, nil); err != nil || len(pools) != 2 {
		t.Fatalf("pools len = %d, err = %v; want 2", len(pools), err)
	}
	if mems, err := e.svc.members(lbTestTenant).List(ctx, nil); err != nil || len(mems) != 2 {
		t.Fatalf("members len = %d, err = %v; want 2", len(mems), err)
	}
	if certs, err := e.svc.certificates(lbTestTenant).List(ctx, nil); err != nil || len(certs) != 2 {
		t.Fatalf("certificates len = %d, err = %v; want 2", len(certs), err)
	}
	if pols, err := e.svc.l7Policies(lbTestTenant).List(ctx, nil); err != nil || len(pols) != 2 {
		t.Fatalf("l7policies len = %d, err = %v; want 2", len(pols), err)
	}

	// One more create of each is refused.
	st, out := e.call(t, http.MethodPost, "/loadbalancers", fmt.Sprintf(`{"loadbalancer":{"name":"new-lb","vpc_id":%q,"vip_subnet_cidr_id":%q,"l4_flavor_id":%q,"availability_zone_list":["ap-southeast-1a"]}}`, e.vpcID, e.neutronSubnetID, e.l4FlavorID))
	assertELBQuotaError(t, st, out, http.StatusForbidden, "ELB.1091", "The number of load balancers exceeds the quota.")

	st, out = e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{"listener":{"loadbalancer_id":%q,"name":"new-lsn","protocol":"HTTP","protocol_port":82}}`, lb1.ID))
	assertELBQuotaError(t, st, out, http.StatusForbidden, "ELB.6091", "The number of listeners reaches the limit.")

	st, out = e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{"pool":{"loadbalancer_id":%q,"name":"new-pool","protocol":"HTTP","lb_algorithm":"ROUND_ROBIN"}}`, lb1.ID))
	assertELBQuotaError(t, st, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: pool")

	st, out = e.call(t, http.MethodPost, "/pools/"+p1.ID+"/members", fmt.Sprintf(`{"member":{"address":"192.168.0.12","protocol_port":80,"subnet_cidr_id":%q}}`, e.neutronSubnetID))
	assertELBQuotaError(t, st, out, http.StatusForbidden, "ELB.2001", "Creating the member failed. The total number of members exceeds the upper limit.")

	cert := certGenRSA(t, "over.example.com", nil, nil, false, lbTestEpoch.Add(24*time.Hour))
	certPayload, _ := json.Marshal(map[string]any{
		"certificate": map[string]any{
			"name":        "new-cert",
			"type":        "server",
			"certificate": cert.certPEM,
			"private_key": cert.keyPKCS1PEM,
		},
	})
	st, out = e.call(t, http.MethodPost, "/certificates", string(certPayload))
	assertELBQuotaError(t, st, out, http.StatusBadRequest, "ELB.5151", "The certificate quantity exceeds the quota.")

	st, out = e.call(t, http.MethodPost, "/l7policies", fmt.Sprintf(`{"l7policy":{"listener_id":%q,"name":"new-pol","action":"REDIRECT_TO_URL","redirect_url_config":{"status_code":"301","host":"example.com"}}}`, lsn1.ID))
	assertELBQuotaError(t, st, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: l7policy")
}

func TestQuotasLoadBalancerParallelCreate(t *testing.T) {
	e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBLoadBalancer: 10}))

	const total = 16
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		created  int
		rejected int
	)

	for i := range total {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"loadbalancer":{"name":"par-lb-%d","vpc_id":%q,"vip_subnet_cidr_id":%q,"l4_flavor_id":%q,"availability_zone_list":["ap-southeast-1a"]}}`,
				idx, e.vpcID, e.neutronSubnetID, e.l4FlavorID)
			st, out := e.call(t, http.MethodPost, "/loadbalancers", body)
			mu.Lock()
			defer mu.Unlock()
			switch st {
			case http.StatusCreated:
				created++
			case http.StatusForbidden:
				assertELBQuotaError(t, st, out, http.StatusForbidden, "ELB.1091", "The number of load balancers exceeds the quota.")
				rejected++
			default:
				t.Errorf("goroutine %d: unexpected status %d: %s", idx, st, out)
			}
		}(i)
	}
	wg.Wait()

	if created != 10 {
		t.Fatalf("created = %d, want 10 (rejected=%d)", created, rejected)
	}
	if rejected != 6 {
		t.Fatalf("rejected = %d, want 6", rejected)
	}
	lbs, err := e.svc.loadBalancers(lbTestTenant).List(t.Context(), nil)
	if err != nil {
		t.Fatalf("List loadbalancers: %v", err)
	}
	if len(lbs) != 10 {
		t.Fatalf("stored loadbalancers = %d, want 10", len(lbs))
	}
}
