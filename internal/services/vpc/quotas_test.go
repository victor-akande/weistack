package vpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

func newEnvWithQuotas(t *testing.T, st store.Store, limits quota.Limits) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(testEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(7)
	svc, err := New(Deps{Quotas: limits, Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &env{svc: svc, store: st, engine: engine, clock: clock, handler: srv.Handler()}
}

func assertV1Error(t *testing.T, status int, body []byte, wantStatus int, wantCode, wantMsg string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d: %s", status, wantStatus, body)
	}
	var got struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding v1 error %s: %v", body, err)
	}
	if got.Code != wantCode || got.Message != wantMsg {
		t.Fatalf("got (%q, %q), want (%q, %q)", got.Code, got.Message, wantCode, wantMsg)
	}
}

func assertV3Error(t *testing.T, status int, body []byte, wantStatus int, wantCode, wantMsg string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d: %s", status, wantStatus, body)
	}
	var got struct {
		ErrorCode string `json:"error_code"`
		ErrorMsg  string `json:"error_msg"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding v3 error %s: %v", body, err)
	}
	if got.ErrorCode != wantCode || got.ErrorMsg != wantMsg {
		t.Fatalf("got (%q, %q), want (%q, %q)", got.ErrorCode, got.ErrorMsg, wantCode, wantMsg)
	}
}

func TestVPCQuotaEnforcedAndFreedOnDelete(t *testing.T) {
	t.Parallel()
	limit := 2
	e := newEnvWithQuotas(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.VPCVPC: limit}))

	var firstID string
	for i := range limit {
		v := e.mustCreateVPC(t, fmt.Sprintf("v%d", i+1), fmt.Sprintf("10.%d.0.0/16", i))
		if i == 0 {
			firstID = v.ID
		}
	}

	status, out := e.call(t, http.MethodPost, "/vpcs", fmt.Sprintf(`{"vpc": {"name": "v-extra", "cidr": "10.%d.0.0/16"}}`, limit))
	assertV1Error(t, status, out, http.StatusConflict, "VPC.0114", "Quota exceeded for resources: ['router'].")

	if status, out := e.call(t, http.MethodDelete, "/vpcs/"+firstID, ""); status != http.StatusNoContent {
		t.Fatalf("delete vpc: %d %s", status, out)
	}
	_ = e.mustCreateVPC(t, "v-extra", fmt.Sprintf("10.%d.0.0/16", limit))
}

func TestSubnetQuotaEnforcedAndFreedOnDelete(t *testing.T) {
	t.Parallel()
	limit := 2
	e := newEnvWithQuotas(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.VPCSubnet: limit}))
	v := e.mustCreateVPC(t, "v1", "10.0.0.0/16")

	var firstID string
	for i := range limit {
		s := e.mustCreateSubnet(t, v.ID, fmt.Sprintf("s%d", i+1), fmt.Sprintf("10.0.%d.0/24", i+1), fmt.Sprintf("10.0.%d.1", i+1))
		if i == 0 {
			firstID = s.ID
		}
	}

	status, out := e.call(t, http.MethodPost, "/subnets", fmt.Sprintf(
		`{"subnet": {"name": "s-extra", "cidr": "10.0.%d.0/24", "gateway_ip": "10.0.%d.1", "vpc_id": %q}}`, limit+1, limit+1, v.ID))
	assertV1Error(t, status, out, http.StatusConflict, "VPC.9905", "Quota exceeded for resources: ['subnet'].")

	if status, out := e.call(t, http.MethodDelete, "/vpcs/"+v.ID+"/subnets/"+firstID, ""); status != http.StatusNoContent {
		t.Fatalf("delete subnet: %d %s", status, out)
	}
	_ = e.mustCreateSubnet(t, v.ID, "s-extra", fmt.Sprintf("10.0.%d.0/24", limit+1), fmt.Sprintf("10.0.%d.1", limit+1))
}

func TestSecurityGroupQuotaV1AndV3(t *testing.T) {
	t.Parallel()
	// Allow the auto-created "default" group plus userGroups user groups.
	defaultGroups, userGroups := 1, 1
	limit := defaultGroups + userGroups
	e := newEnvWithQuotas(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.VPCSecurityGroup: limit}))

	var firstID string
	for i := range userGroups {
		g := e.mustCreateSecGroup(t, fmt.Sprintf("web-%d", i))
		if i == 0 {
			firstID = g.ID
		}
	}

	status, out := e.call3(t, http.MethodPost, "/security-groups", `{"security_group": {"name": "db"}}`)
	assertV3Error(t, status, out, http.StatusConflict, "VPC.9905", "Quota exceeded for resources: security_group.")

	status, out = e.call(t, http.MethodPost, "/security-groups", `{"security_group": {"name": "db"}}`)
	assertV1Error(t, status, out, http.StatusConflict, "VPC.0604", "Quota exceeded for resources: ['security_group'].")

	if status, out := e.call3(t, http.MethodDelete, "/security-groups/"+firstID, ""); status != http.StatusNoContent {
		t.Fatalf("delete security group: %d %s", status, out)
	}
	_ = e.mustCreateSecGroup(t, "db")
}

func TestSecurityGroupRuleQuotaV1AndV3(t *testing.T) {
	t.Parallel()
	// Creating "default" + "web" groups inserts 4+4 = 8 default rules; allow userRules more.
	defaultRules, userRules := 8, 1
	limit := defaultRules + userRules
	e := newEnvWithQuotas(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.VPCSecurityGroupRule: limit}))
	g := e.mustCreateSecGroup(t, "web")

	var firstRuleID string
	for i := range userRules {
		status, out := e.call3(t, http.MethodPost, "/security-group-rules", fmt.Sprintf(
			`{"security_group_rule": {"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "multiport": "%d"}}`, g.ID, 80+i))
		if status != http.StatusCreated {
			t.Fatalf("create rule %d: %d %s", i+1, status, out)
		}
		if i == 0 {
			firstRuleID = decodeInto[securityGroupRuleResponse](t, out).SecurityGroupRule.ID
		}
	}

	status, out := e.call3(t, http.MethodPost, "/security-group-rules", fmt.Sprintf(
		`{"security_group_rule": {"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "multiport": "443"}}`, g.ID))
	assertV3Error(t, status, out, http.StatusConflict, "VPC.9905", "Quota exceeded for resources: ['security_group_rule'].")

	status, out = e.call(t, http.MethodPost, "/security-group-rules", fmt.Sprintf(
		`{"security_group_rule": {"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "port_range_min": 443, "port_range_max": 443}}`, g.ID))
	assertV1Error(t, status, out, http.StatusConflict, "VPC.0602", "Quota exceeded for resources: ['security_group_rule'].")

	// A multi-item request (want > 1) that would cross the limit is refused before creating anything.
	batch := userRules + 1
	if err := checkQuota(t.Context(), e.svc.quotas, e.svc.secGroupRules(testTenant), quota.VPCSecurityGroupRule, batch, errSecGroupRuleQuotaExceeded); err == nil {
		t.Fatalf("expected checkQuota with want=%d to refuse", batch)
	}

	if status, out := e.call3(t, http.MethodDelete, "/security-group-rules/"+firstRuleID, ""); status != http.StatusNoContent {
		t.Fatalf("delete rule: %d %s", status, out)
	}
	status, out = e.call3(t, http.MethodPost, "/security-group-rules", fmt.Sprintf(
		`{"security_group_rule": {"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "multiport": "443"}}`, g.ID))
	if status != http.StatusCreated {
		t.Fatalf("create rule after delete: %d %s", status, out)
	}
}

func TestUnlimitedQuotaNeverRefuses(t *testing.T) {
	t.Parallel()
	creates := 5
	e := newEnvWithQuotas(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.VPCVPC: quota.Unlimited}))

	for i := range creates {
		_ = e.mustCreateVPC(t, fmt.Sprintf("v-%d", i), fmt.Sprintf("10.%d.0.0/16", i))
	}
}

func TestExistingDataOverLimitKeptAndNewRefused(t *testing.T) {
	t.Parallel()
	limit, seeded := 1, 3
	st := store.NewMemory()
	col := store.Of[VPC](st, store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindVPC})
	for i := range seeded {
		id := fmt.Sprintf("00000000-0000-0000-0000-00000000000%d", i+1)
		if err := col.Create(t.Context(), id, VPC{
			ID: id, Name: fmt.Sprintf("pre-%d", i), Status: VPCStatusOK, TenantID: testProject,
		}); err != nil {
			t.Fatalf("seed vpc: %v", err)
		}
	}

	e := newEnvWithQuotas(t, st, quota.For(map[quota.Key]int{quota.VPCVPC: limit}))

	vpcs, err := e.svc.ListVPCs(t.Context(), testTenant, ListVPCsFilter{})
	if err != nil || len(vpcs) != seeded {
		t.Fatalf("existing VPCs = %d (err %v), want %d", len(vpcs), err, seeded)
	}

	status, out := e.call(t, http.MethodPost, "/vpcs", `{"vpc": {"name": "new-one", "cidr": "10.9.0.0/16"}}`)
	assertV1Error(t, status, out, http.StatusConflict, "VPC.0114", "Quota exceeded for resources: ['router'].")
}

func TestParallelVPCCreatesRespectQuota(t *testing.T) {
	t.Parallel()
	limit, extra := 10, 6
	total := limit + extra
	e := newEnvWithQuotas(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.VPCVPC: limit}))

	var okCount, deniedCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(total)
	for i := range total {
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"vpc": {"name": "par-%d", "cidr": "10.%d.0.0/16"}}`, i, i)
			status, _ := e.call(t, http.MethodPost, "/vpcs", body)
			switch status {
			case http.StatusOK:
				okCount.Add(1)
			case http.StatusConflict:
				deniedCount.Add(1)
			default:
				t.Errorf("unexpected status %d", status)
			}
		}(i)
	}
	wg.Wait()
	e.settle(t)

	if okCount.Load() != int32(limit) || deniedCount.Load() != int32(extra) {
		t.Fatalf("ok=%d denied=%d, want %d and %d", okCount.Load(), deniedCount.Load(), limit, extra)
	}
	vpcs, err := e.svc.ListVPCs(t.Context(), testTenant, ListVPCsFilter{})
	if err != nil || len(vpcs) != limit {
		t.Fatalf("stored VPCs = %d (err %v), want %d", len(vpcs), err, limit)
	}
}
