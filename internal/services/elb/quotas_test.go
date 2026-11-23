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
		limit := 2
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBLoadBalancer: limit}))
		var firstID string
		for i := range limit {
			id := e.mustCreateLB(t, fmt.Sprintf("lb-%d", i+1))
			if i == 0 {
				firstID = id
			}
		}

		body := fmt.Sprintf(`{"loadbalancer":{"name":"lb-extra","vpc_id":%q,"vip_subnet_cidr_id":%q,"l4_flavor_id":%q,"availability_zone_list":["ap-southeast-1a"]}}`,
			e.vpcID, e.neutronSubnetID, e.l4FlavorID)
		status, out := e.call(t, http.MethodPost, "/loadbalancers", body)
		assertELBQuotaError(t, status, out, http.StatusForbidden, "ELB.1091", "The number of load balancers exceeds the quota.")

		if st, delOut := e.call(t, http.MethodDelete, "/loadbalancers/"+firstID, ""); st != http.StatusNoContent {
			t.Fatalf("delete LB: status %d: %s", st, delOut)
		}
		_ = e.mustCreateLB(t, "lb-extra-ok")
	})

	t.Run("listener", func(t *testing.T) {
		limit := 2
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBListener: limit}))
		lbID := e.mustCreateLB(t, "lb-1")
		var firstID string
		for i := range limit {
			id := e.mustCreateListener(t, lbID, fmt.Sprintf("lsn-%d", i+1), 80+i)
			if i == 0 {
				firstID = id
			}
		}

		body := fmt.Sprintf(`{"listener":{"loadbalancer_id":%q,"name":"lsn-extra","protocol":"HTTP","protocol_port":%d}}`, lbID, 80+limit)
		status, out := e.call(t, http.MethodPost, "/listeners", body)
		assertELBQuotaError(t, status, out, http.StatusForbidden, "ELB.6091", "The number of listeners reaches the limit.")

		if st, delOut := e.call(t, http.MethodDelete, "/listeners/"+firstID, ""); st != http.StatusNoContent {
			t.Fatalf("delete listener: status %d: %s", st, delOut)
		}
		_ = e.mustCreateListener(t, lbID, "lsn-extra-ok", 80+limit)
	})

	t.Run("member", func(t *testing.T) {
		limit := 2
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBMember: limit}))
		lbID := e.mustCreateLB(t, "lb-1")
		pool1 := e.mustCreatePool(t, lbID, "pool-1")
		pool2 := e.mustCreatePool(t, lbID, "pool-2")
		var firstID string
		for i := range limit {
			pool := pool1
			if i%2 == 1 {
				pool = pool2
			}
			id := e.mustCreateMember(t, pool, fmt.Sprintf("192.168.0.%d", 10+i), 80)
			if i == 0 {
				firstID = id
			}
		}

		// Per-project limit applies across pools.
		body := fmt.Sprintf(`{"member":{"address":"192.168.0.%d","protocol_port":80,"subnet_cidr_id":%q}}`, 10+limit, e.neutronSubnetID)
		status, out := e.call(t, http.MethodPost, "/pools/"+pool2+"/members", body)
		assertELBQuotaError(t, status, out, http.StatusForbidden, "ELB.2001", "Creating the member failed. The total number of members exceeds the upper limit.")

		if st, delOut := e.call(t, http.MethodDelete, "/pools/"+pool1+"/members/"+firstID, ""); st != http.StatusNoContent {
			t.Fatalf("delete member: status %d: %s", st, delOut)
		}
		_ = e.mustCreateMember(t, pool2, fmt.Sprintf("192.168.0.%d", 10+limit), 80)
	})

	t.Run("certificate", func(t *testing.T) {
		limit := 2
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBCertificate: limit}))
		cert := certGenRSA(t, "example.com", nil, nil, false, lbTestEpoch.Add(24*time.Hour))
		var firstID string
		for i := range limit {
			id := e.mustCreateCert(t, fmt.Sprintf("cert-%d", i+1), cert)
			if i == 0 {
				firstID = id
			}
		}

		payload, _ := json.Marshal(map[string]any{
			"certificate": map[string]any{
				"name":        "cert-extra",
				"type":        "server",
				"certificate": cert.certPEM,
				"private_key": cert.keyPKCS1PEM,
			},
		})
		status, out := e.call(t, http.MethodPost, "/certificates", string(payload))
		assertELBQuotaError(t, status, out, http.StatusBadRequest, "ELB.5151", "The certificate quantity exceeds the quota.")

		if st, delOut := e.call(t, http.MethodDelete, "/certificates/"+firstID, ""); st != http.StatusNoContent {
			t.Fatalf("delete cert: status %d: %s", st, delOut)
		}
		_ = e.mustCreateCert(t, "cert-extra-ok", cert)
	})

	t.Run("pool", func(t *testing.T) {
		limit := 2
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBPool: limit}))
		lbID := e.mustCreateLB(t, "lb-1")
		var firstID string
		for i := range limit {
			id := e.mustCreatePool(t, lbID, fmt.Sprintf("pool-%d", i+1))
			if i == 0 {
				firstID = id
			}
		}

		body := fmt.Sprintf(`{"pool":{"loadbalancer_id":%q,"name":"pool-extra","protocol":"HTTP","lb_algorithm":"ROUND_ROBIN"}}`, lbID)
		status, out := e.call(t, http.MethodPost, "/pools", body)
		assertELBQuotaError(t, status, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: pool")

		if st, delOut := e.call(t, http.MethodDelete, "/pools/"+firstID, ""); st != http.StatusNoContent {
			t.Fatalf("delete pool: status %d: %s", st, delOut)
		}
		_ = e.mustCreatePool(t, lbID, "pool-extra-ok")
	})

	t.Run("l7policy_then_l7policies_per_listener", func(t *testing.T) {
		// When both elb.l7policy and elb.l7policies_per_listener are reached, elb.l7policy wins.
		projLimit, perListenerLimit := 1, 1
		e := newQuotaEnv(t, quota.For(map[quota.Key]int{
			quota.ELBL7Policy:              projLimit,
			quota.ELBL7PoliciesPerListener: perListenerLimit,
		}))
		lbID := e.mustCreateLB(t, "lb-1")
		lsn1 := e.mustCreateListener(t, lbID, "lsn-1", 80)
		var firstPolID string
		for i := range projLimit {
			id := e.mustCreateL7Policy(t, lsn1, fmt.Sprintf("pol-%d", i+1))
			if i == 0 {
				firstPolID = id
			}
		}

		body := fmt.Sprintf(`{"l7policy":{"listener_id":%q,"name":"pol-extra","action":"REDIRECT_TO_URL","redirect_url_config":{"status_code":"301","host":"example.com"}}}`, lsn1)
		status, out := e.call(t, http.MethodPost, "/l7policies", body)
		assertELBQuotaError(t, status, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: l7policy")

		if st, delOut := e.call(t, http.MethodDelete, "/l7policies/"+firstPolID, ""); st != http.StatusNoContent {
			t.Fatalf("delete l7policy: status %d: %s", st, delOut)
		}
		_ = e.mustCreateL7Policy(t, lsn1, "pol-extra-ok")

		// With elb.l7policy higher, elb.l7policies_per_listener is enforced per listener.
		highProjLimit, perLsnLimit := 5, 1
		e2 := newQuotaEnv(t, quota.For(map[quota.Key]int{
			quota.ELBL7Policy:              highProjLimit,
			quota.ELBL7PoliciesPerListener: perLsnLimit,
		}))
		lb2 := e2.mustCreateLB(t, "lb-2")
		lsnA := e2.mustCreateListener(t, lb2, "lsn-a", 80)
		lsnB := e2.mustCreateListener(t, lb2, "lsn-b", 81)
		var firstPolA string
		for i := range perLsnLimit {
			id := e2.mustCreateL7Policy(t, lsnA, fmt.Sprintf("pol-a-%d", i+1))
			if i == 0 {
				firstPolA = id
			}
		}

		bodyA2 := fmt.Sprintf(`{"l7policy":{"listener_id":%q,"name":"pol-a-extra","action":"REDIRECT_TO_URL","redirect_url_config":{"status_code":"301","host":"example.com"}}}`, lsnA)
		status, out = e2.call(t, http.MethodPost, "/l7policies", bodyA2)
		assertELBQuotaError(t, status, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: l7policies_per_listener")

		// Another listener can still create its own L7 policy.
		_ = e2.mustCreateL7Policy(t, lsnB, "pol-b")

		// Deleting firstPolA frees the slot on lsnA.
		if st, delOut := e2.call(t, http.MethodDelete, "/l7policies/"+firstPolA, ""); st != http.StatusNoContent {
			t.Fatalf("delete l7policy: status %d: %s", st, delOut)
		}
		_ = e2.mustCreateL7Policy(t, lsnA, "pol-a-extra-ok")
	})
}

func TestQuotasUnlimited(t *testing.T) {
	creates := 2
	e := newQuotaEnv(t, quota.For(map[quota.Key]int{
		quota.ELBLoadBalancer:          quota.Unlimited,
		quota.ELBListener:              quota.Unlimited,
		quota.ELBPool:                  quota.Unlimited,
		quota.ELBMember:                quota.Unlimited,
		quota.ELBCertificate:           quota.Unlimited,
		quota.ELBL7Policy:              quota.Unlimited,
		quota.ELBL7PoliciesPerListener: quota.Unlimited,
	}))

	var lbID, lsnID, poolID string
	for i := range creates {
		id := e.mustCreateLB(t, fmt.Sprintf("lb-%d", i+1))
		if i == 0 {
			lbID = id
		}
	}
	for i := range creates {
		id := e.mustCreateListener(t, lbID, fmt.Sprintf("lsn-%d", i+1), 80+i)
		if i == 0 {
			lsnID = id
		}
	}
	for i := range creates {
		id := e.mustCreatePool(t, lbID, fmt.Sprintf("pool-%d", i+1))
		if i == 0 {
			poolID = id
		}
	}
	for i := range creates {
		_ = e.mustCreateMember(t, poolID, fmt.Sprintf("192.168.0.%d", 10+i), 80)
	}
	cert := certGenRSA(t, "unlim.example.com", nil, nil, false, lbTestEpoch.Add(24*time.Hour))
	for i := range creates {
		_ = e.mustCreateCert(t, fmt.Sprintf("cert-%d", i+1), cert)
	}
	for i := range creates {
		_ = e.mustCreateL7Policy(t, lsnID, fmt.Sprintf("pol-%d", i+1))
	}
}

func TestQuotasExistingDataOverLimit(t *testing.T) {
	limit, seeded := 1, 2
	e := newQuotaEnv(t, quota.For(map[quota.Key]int{
		quota.ELBLoadBalancer:          limit,
		quota.ELBListener:              limit,
		quota.ELBPool:                  limit,
		quota.ELBMember:                limit,
		quota.ELBCertificate:           limit,
		quota.ELBL7Policy:              limit,
		quota.ELBL7PoliciesPerListener: limit,
	}))
	ctx := t.Context()

	// Seed resources directly in the store above limit.
	var firstLBID, firstLsnID, firstPoolID string
	for i := range seeded {
		lb := loadBalancer{ID: e.svc.ids.UUID(), Name: fmt.Sprintf("seed-lb-%d", i+1), L4FlavorID: e.l4FlavorID, L7FlavorID: e.l7FlavorID, VPCID: e.vpcID, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
		if err := e.svc.loadBalancers(lbTestTenant).Create(ctx, lb.ID, lb); err != nil {
			t.Fatalf("seed LB: %v", err)
		}
		if i == 0 {
			firstLBID = lb.ID
		}
	}

	for i := range seeded {
		l := listener{ID: e.svc.ids.UUID(), LoadBalancerID: firstLBID, Name: fmt.Sprintf("seed-lsn-%d", i+1), Protocol: "HTTP", ProtocolPort: 80 + i, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
		if err := e.svc.listeners(lbTestTenant).Create(ctx, l.ID, l); err != nil {
			t.Fatalf("seed listener: %v", err)
		}
		if i == 0 {
			firstLsnID = l.ID
		}
	}

	for i := range seeded {
		p := pool{ID: e.svc.ids.UUID(), LoadBalancerID: firstLBID, Name: fmt.Sprintf("seed-pool-%d", i+1), Protocol: "HTTP", LBAlgorithm: "ROUND_ROBIN", AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
		if err := e.svc.pools(lbTestTenant).Create(ctx, p.ID, p); err != nil {
			t.Fatalf("seed pool: %v", err)
		}
		if i == 0 {
			firstPoolID = p.ID
		}
	}

	for i := range seeded {
		m := member{ID: e.svc.ids.UUID(), PoolID: firstPoolID, Address: fmt.Sprintf("192.168.0.%d", 10+i), ProtocolPort: 80, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
		if err := e.svc.members(lbTestTenant).Create(ctx, m.ID, m); err != nil {
			t.Fatalf("seed member: %v", err)
		}
	}

	for i := range seeded {
		c := certificate{ID: e.svc.ids.UUID(), Name: fmt.Sprintf("seed-cert-%d", i+1), Type: certTypeServer, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
		if err := e.svc.certificates(lbTestTenant).Create(ctx, c.ID, c); err != nil {
			t.Fatalf("seed cert: %v", err)
		}
	}

	for i := range seeded {
		pol := l7Policy{ID: e.svc.ids.UUID(), ListenerID: firstLsnID, Name: fmt.Sprintf("seed-pol-%d", i+1), Action: l7ActionRedirectToURL, AdminStateUp: true, CreatedAt: lbTestEpoch, UpdatedAt: lbTestEpoch}
		if err := e.svc.l7Policies(lbTestTenant).Create(ctx, pol.ID, pol); err != nil {
			t.Fatalf("seed l7policy: %v", err)
		}
	}

	// Existing records are kept.
	if lbs, err := e.svc.loadBalancers(lbTestTenant).List(ctx, nil); err != nil || len(lbs) != seeded {
		t.Fatalf("loadbalancers len = %d, err = %v; want %d", len(lbs), err, seeded)
	}
	if lsns, err := e.svc.listeners(lbTestTenant).List(ctx, nil); err != nil || len(lsns) != seeded {
		t.Fatalf("listeners len = %d, err = %v; want %d", len(lsns), err, seeded)
	}
	if pools, err := e.svc.pools(lbTestTenant).List(ctx, nil); err != nil || len(pools) != seeded {
		t.Fatalf("pools len = %d, err = %v; want %d", len(pools), err, seeded)
	}
	if mems, err := e.svc.members(lbTestTenant).List(ctx, nil); err != nil || len(mems) != seeded {
		t.Fatalf("members len = %d, err = %v; want %d", len(mems), err, seeded)
	}
	if certs, err := e.svc.certificates(lbTestTenant).List(ctx, nil); err != nil || len(certs) != seeded {
		t.Fatalf("certificates len = %d, err = %v; want %d", len(certs), err, seeded)
	}
	if pols, err := e.svc.l7Policies(lbTestTenant).List(ctx, nil); err != nil || len(pols) != seeded {
		t.Fatalf("l7policies len = %d, err = %v; want %d", len(pols), err, seeded)
	}

	// One more create of each is refused.
	st, out := e.call(t, http.MethodPost, "/loadbalancers", fmt.Sprintf(`{"loadbalancer":{"name":"new-lb","vpc_id":%q,"vip_subnet_cidr_id":%q,"l4_flavor_id":%q,"availability_zone_list":["ap-southeast-1a"]}}`, e.vpcID, e.neutronSubnetID, e.l4FlavorID))
	assertELBQuotaError(t, st, out, http.StatusForbidden, "ELB.1091", "The number of load balancers exceeds the quota.")

	st, out = e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{"listener":{"loadbalancer_id":%q,"name":"new-lsn","protocol":"HTTP","protocol_port":%d}}`, firstLBID, 80+seeded))
	assertELBQuotaError(t, st, out, http.StatusForbidden, "ELB.6091", "The number of listeners reaches the limit.")

	st, out = e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{"pool":{"loadbalancer_id":%q,"name":"new-pool","protocol":"HTTP","lb_algorithm":"ROUND_ROBIN"}}`, firstLBID))
	assertELBQuotaError(t, st, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: pool")

	st, out = e.call(t, http.MethodPost, "/pools/"+firstPoolID+"/members", fmt.Sprintf(`{"member":{"address":"192.168.0.%d","protocol_port":80,"subnet_cidr_id":%q}}`, 10+seeded, e.neutronSubnetID))
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

	st, out = e.call(t, http.MethodPost, "/l7policies", fmt.Sprintf(`{"l7policy":{"listener_id":%q,"name":"new-pol","action":"REDIRECT_TO_URL","redirect_url_config":{"status_code":"301","host":"example.com"}}}`, firstLsnID))
	assertELBQuotaError(t, st, out, http.StatusConflict, "ELB.8905", "Quota exceeded for resources: l7policy")
}

func TestQuotasLoadBalancerParallelCreate(t *testing.T) {
	limit, extra := 10, 6
	total := limit + extra
	e := newQuotaEnv(t, quota.For(map[quota.Key]int{quota.ELBLoadBalancer: limit}))

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

	if created != limit {
		t.Fatalf("created = %d, want %d (rejected=%d)", created, limit, rejected)
	}
	if rejected != extra {
		t.Fatalf("rejected = %d, want %d", rejected, extra)
	}
	lbs, err := e.svc.loadBalancers(lbTestTenant).List(t.Context(), nil)
	if err != nil {
		t.Fatalf("List loadbalancers: %v", err)
	}
	if len(lbs) != limit {
		t.Fatalf("stored loadbalancers = %d, want %d", len(lbs), limit)
	}
}
