package nat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

func newQuotaTestEnv(t *testing.T, limits quota.Limits) *gwEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(gwTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: 0, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(21)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	svc, err := New(Deps{
		Quotas: limits,
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		VPC:    vpcSvc,
		EIPs:   gwNoopEIPs{},
		Now:    clock.Now,
	})
	if err != nil {
		t.Fatalf("nat.New: %v", err)
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: gwTestProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	e := &gwEnv{
		svc:     svc,
		vpcSvc:  vpcSvc,
		store:   st,
		engine:  engine,
		clock:   clock,
		handler: srv.Handler(),
	}
	e.vpcID, e.subnetID = e.seedVPCSubnet(t, gwTestTenant, "vpc-q", "192.168.0.0/16", "sub-q", "192.168.0.0/24", "192.168.0.1")
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := e.engine.WaitIdle(waitCtx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
	return e
}

func (e *gwEnv) callV20(t *testing.T, path string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v2.0/"+gwTestProject+path, nil)
	r.Host = gwTestHost
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

func TestListNatGatewayQuotas(t *testing.T) {
	t.Parallel()

	t.Run("default_and_live_count", func(t *testing.T) {
		t.Parallel()
		e := newQuotaTestEnv(t, quota.Limits{})
		wantDefault := (quota.Limits{}).Get(quota.NATGateway)

		st, out := e.callV20(t, "/nat_gateways/quotas")
		if st != http.StatusOK {
			t.Fatalf("GET quotas: status %d: %s", st, out)
		}
		var resp listQuotasResponse
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		want := quotaResourceWire{Type: "nat_gateway", Used: 0, Quota: wantDefault, Min: 0}
		if len(resp.Quotas.Resources) != 1 || resp.Quotas.Resources[0] != want {
			t.Fatalf("resources = %+v, want [%+v]", resp.Quotas.Resources, want)
		}

		// Create 2 public NAT gateways and 1 private NAT gateway; only public ones count.
		for i := range 2 {
			body := fmt.Sprintf(`{"nat_gateway":{"name":"pub-%d","router_id":%q,"internal_network_id":%q,"spec":"1"}}`, i+1, e.vpcID, e.subnetID)
			cst, cout := e.call(t, http.MethodPost, "/nat_gateways", body)
			if cst != http.StatusCreated {
				t.Fatalf("create public gateway %d: %d %s", i+1, cst, cout)
			}
		}
		pgw := privateGateway{ID: e.svc.ids.UUID(), Name: "priv-1", Spec: "Small", CreatedAt: gwTestEpoch}
		if err := e.svc.privateGateways(gwTestTenant).Create(t.Context(), pgw.ID, pgw); err != nil {
			t.Fatalf("seed private gateway: %v", err)
		}

		st, out = e.callV20(t, "/nat_gateways/quotas?type=nat_gateway")
		if st != http.StatusOK {
			t.Fatalf("GET quotas?type=nat_gateway: status %d: %s", st, out)
		}
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		want.Used = 2
		if len(resp.Quotas.Resources) != 1 || resp.Quotas.Resources[0] != want {
			t.Fatalf("resources = %+v, want [%+v]", resp.Quotas.Resources, want)
		}

		// Other type filter returns empty array (not null).
		st, out = e.callV20(t, "/nat_gateways/quotas?type=other")
		if st != http.StatusOK {
			t.Fatalf("GET quotas?type=other: status %d: %s", st, out)
		}
		if !strings.Contains(string(out), `"resources":[]`) {
			t.Errorf("type=other response = %s, want empty resources array", out)
		}
	})

	t.Run("custom_limit_and_over_limit_not_refused", func(t *testing.T) {
		t.Parallel()
		limit, count := 1, 2
		e := newQuotaTestEnv(t, quota.For(map[quota.Key]int{quota.NATGateway: limit}))

		// NAT gateway creates are reported, not enforced (§3.4), so creating count > limit succeeds.
		for i := range count {
			body := fmt.Sprintf(`{"nat_gateway":{"name":"over-%d","router_id":%q,"internal_network_id":%q,"spec":"1"}}`, i+1, e.vpcID, e.subnetID)
			cst, cout := e.call(t, http.MethodPost, "/nat_gateways", body)
			if cst != http.StatusCreated {
				t.Fatalf("create gateway %d: %d %s", i+1, cst, cout)
			}
		}

		st, out := e.callV20(t, "/nat_gateways/quotas")
		if st != http.StatusOK {
			t.Fatalf("GET quotas: status %d: %s", st, out)
		}
		var resp listQuotasResponse
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		want := quotaResourceWire{Type: "nat_gateway", Used: count, Quota: limit, Min: 0}
		if len(resp.Quotas.Resources) != 1 || resp.Quotas.Resources[0] != want {
			t.Fatalf("resources = %+v, want [%+v]", resp.Quotas.Resources, want)
		}

		// VPCExtension reports nothing for NAT (§3.1).
		if qs, err := e.svc.VPCExtension().Quotas(t.Context(), gwTestTenant); err != nil || len(qs) != 0 {
			t.Errorf("VPCExtension().Quotas = %+v, %v; want empty, nil", qs, err)
		}
	})
}
