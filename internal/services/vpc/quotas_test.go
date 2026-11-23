package vpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

func newEnvWithQuotas(t *testing.T, st store.Store, limits quota.Limits, exts ...Extension) *env {
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
	for _, ext := range exts {
		svc.Extend(ext)
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

type stubQuotaExt struct {
	items []QuotaResource
}

func (stubQuotaExt) RoutesV1(chi.Router)  {}
func (stubQuotaExt) RoutesV20(chi.Router) {}
func (stubQuotaExt) Routes(chi.Router)    {}
func (e stubQuotaExt) Quotas(_ context.Context, _ Tenant) ([]QuotaResource, error) {
	return e.items, nil
}

func TestShowQuotaV1DefaultsCountsAndTenantIsolation(t *testing.T) {
	t.Parallel()
	defaults := quota.Limits{}
	e := newEnvWithQuotas(t, store.NewMemory(), defaults)

	// Empty project reports zero used and the default limits in exact order.
	status, raw := e.call(t, http.MethodGet, "/quotas", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas: %d %s", status, raw)
	}
	got := decodeInto[v1QuotaResponse](t, raw).Quotas.Resources
	want := []QuotaResource{
		{Type: "vpc", Used: 0, Quota: defaults.Get(quota.VPCVPC), Min: 0},
		{Type: "subnet", Used: 0, Quota: defaults.Get(quota.VPCSubnet), Min: 0},
		{Type: "securityGroup", Used: 0, Quota: defaults.Get(quota.VPCSecurityGroup), Min: 0},
		{Type: "securityGroupRule", Used: 0, Quota: defaults.Get(quota.VPCSecurityGroupRule), Min: 0},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("initial quotas =\n%+v\nwant\n%+v", got, want)
	}

	// Create 2 VPCs, 3 subnets, 1 user security group (+ auto-created "default" group = 2 groups,
	// 8 default rules), and 2 user rules (= 10 rules total).
	v1 := e.mustCreateVPC(t, "v1", "10.0.0.0/16")
	_ = e.mustCreateVPC(t, "v2", "10.1.0.0/16")
	s1 := e.mustCreateSubnet(t, v1.ID, "s1", "10.0.1.0/24", "10.0.1.1")
	_ = e.mustCreateSubnet(t, v1.ID, "s2", "10.0.2.0/24", "10.0.2.1")
	_ = e.mustCreateSubnet(t, v1.ID, "s3", "10.0.3.0/24", "10.0.3.1")
	g := e.mustCreateSecGroup(t, "web")
	var firstRuleID string
	for i := range 2 {
		status, out := e.call3(t, http.MethodPost, "/security-group-rules", fmt.Sprintf(
			`{"security_group_rule": {"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "multiport": "%d"}}`, g.ID, 80+i))
		if status != http.StatusCreated {
			t.Fatalf("create rule %d: %d %s", i+1, status, out)
		}
		if i == 0 {
			firstRuleID = decodeInto[securityGroupRuleResponse](t, out).SecurityGroupRule.ID
		}
	}

	status, raw = e.call(t, http.MethodGet, "/quotas", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas after creates: %d %s", status, raw)
	}
	got = decodeInto[v1QuotaResponse](t, raw).Quotas.Resources
	want = []QuotaResource{
		{Type: "vpc", Used: 2, Quota: defaults.Get(quota.VPCVPC), Min: 0},
		{Type: "subnet", Used: 3, Quota: defaults.Get(quota.VPCSubnet), Min: 0},
		{Type: "securityGroup", Used: 2, Quota: defaults.Get(quota.VPCSecurityGroup), Min: 0},
		{Type: "securityGroupRule", Used: 10, Quota: defaults.Get(quota.VPCSecurityGroupRule), Min: 0},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("after creates =\n%+v\nwant\n%+v", got, want)
	}

	// Deleting a subnet and a rule decrements usage immediately.
	if status, out := e.call(t, http.MethodDelete, "/vpcs/"+v1.ID+"/subnets/"+s1.ID, ""); status != http.StatusNoContent {
		t.Fatalf("delete subnet: %d %s", status, out)
	}
	if status, out := e.call3(t, http.MethodDelete, "/security-group-rules/"+firstRuleID, ""); status != http.StatusNoContent {
		t.Fatalf("delete rule: %d %s", status, out)
	}

	status, raw = e.call(t, http.MethodGet, "/quotas", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas after deletes: %d %s", status, raw)
	}
	got = decodeInto[v1QuotaResponse](t, raw).Quotas.Resources
	want[1].Used = 2
	want[3].Used = 9
	if !slices.Equal(got, want) {
		t.Fatalf("after deletes =\n%+v\nwant\n%+v", got, want)
	}

	// Another project still reports 0 used for every resource.
	status, raw = e.callAs(t, "fedcba9876543210fedcba9876543210", http.MethodGet, "/quotas", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas other project: %d %s", status, raw)
	}
	for _, r := range decodeInto[v1QuotaResponse](t, raw).Quotas.Resources {
		if r.Used != 0 {
			t.Fatalf("other project %s used = %d, want 0", r.Type, r.Used)
		}
	}
}

func TestShowQuotaV1ExtensionsAndTypeFilter(t *testing.T) {
	t.Parallel()
	eipLimit, shareBWLimit, shareBWIPLimit := 12, 3, 7
	lbLimit, lsnLimit := 15, 25

	eipExt := stubQuotaExt{items: []QuotaResource{
		{Type: "publicIp", Used: 2, Quota: eipLimit, Min: 0},
		{Type: "shareBandwidth", Used: 1, Quota: shareBWLimit, Min: 0},
		{Type: "shareBandwidthIP", Used: 2, Quota: shareBWIPLimit, Min: 0},
	}}
	natExt := stubQuotaExt{}
	elbExt := stubQuotaExt{items: []QuotaResource{
		{Type: "loadbalancer", Used: 4, Quota: lbLimit, Min: 0},
		{Type: "listener", Used: 6, Quota: lsnLimit, Min: 0},
	}}

	// Without ELB registered, querying loadbalancer returns 400 VPC.1207.
	eNoELB := newEnvWithQuotas(t, store.NewMemory(), quota.Limits{}, eipExt, natExt)
	status, raw := eNoELB.call(t, http.MethodGet, "/quotas?type=loadbalancer", "")
	assertV1Error(t, status, raw, http.StatusBadRequest, "VPC.1207", "Invalid resource type.")

	// With EIP, NAT, and ELB extensions registered, all 9 items appear in exact order.
	defaults := quota.Limits{}
	e := newEnvWithQuotas(t, store.NewMemory(), defaults, eipExt, natExt, elbExt)

	status, raw = e.call(t, http.MethodGet, "/quotas", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas: %d %s", status, raw)
	}
	got := decodeInto[v1QuotaResponse](t, raw).Quotas.Resources
	want := []QuotaResource{
		{Type: "vpc", Used: 0, Quota: defaults.Get(quota.VPCVPC), Min: 0},
		{Type: "subnet", Used: 0, Quota: defaults.Get(quota.VPCSubnet), Min: 0},
		{Type: "securityGroup", Used: 0, Quota: defaults.Get(quota.VPCSecurityGroup), Min: 0},
		{Type: "securityGroupRule", Used: 0, Quota: defaults.Get(quota.VPCSecurityGroupRule), Min: 0},
		{Type: "publicIp", Used: 2, Quota: eipLimit, Min: 0},
		{Type: "shareBandwidth", Used: 1, Quota: shareBWLimit, Min: 0},
		{Type: "shareBandwidthIP", Used: 2, Quota: shareBWIPLimit, Min: 0},
		{Type: "loadbalancer", Used: 4, Quota: lbLimit, Min: 0},
		{Type: "listener", Used: 6, Quota: lsnLimit, Min: 0},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("all quotas =\n%+v\nwant\n%+v", got, want)
	}

	// Filtering by any reported type returns just that entry.
	for _, wantItem := range want {
		status, raw := e.call(t, http.MethodGet, "/quotas?type="+wantItem.Type, "")
		if status != http.StatusOK {
			t.Fatalf("GET /quotas?type=%s: %d %s", wantItem.Type, status, raw)
		}
		filtered := decodeInto[v1QuotaResponse](t, raw).Quotas.Resources
		if len(filtered) != 1 || filtered[0] != wantItem {
			t.Fatalf("type=%s: got %+v, want [%+v]", wantItem.Type, filtered, wantItem)
		}
	}

	// Unknown type returns 400 VPC.1207.
	status, raw = e.call(t, http.MethodGet, "/quotas?type=vpn", "")
	assertV1Error(t, status, raw, http.StatusBadRequest, "VPC.1207", "Invalid resource type.")
}

func TestShowQuotaV1OverLimitAndUnlimited(t *testing.T) {
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

	limits := quota.For(map[quota.Key]int{
		quota.VPCVPC:    limit,
		quota.VPCSubnet: quota.Unlimited,
	})
	e := newEnvWithQuotas(t, st, limits)

	status, raw := e.call(t, http.MethodGet, "/quotas?type=vpc", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas?type=vpc: %d %s", status, raw)
	}
	gotVPC := decodeInto[v1QuotaResponse](t, raw).Quotas.Resources
	wantVPC := QuotaResource{Type: "vpc", Used: seeded, Quota: limit, Min: 0}
	if len(gotVPC) != 1 || gotVPC[0] != wantVPC {
		t.Fatalf("over-limit vpc = %+v, want [%+v]", gotVPC, wantVPC)
	}

	status, raw = e.call(t, http.MethodGet, "/quotas?type=subnet", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas?type=subnet: %d %s", status, raw)
	}
	gotSubnet := decodeInto[v1QuotaResponse](t, raw).Quotas.Resources
	wantSubnet := QuotaResource{Type: "subnet", Used: 0, Quota: quota.Unlimited, Min: 0}
	if len(gotSubnet) != 1 || gotSubnet[0] != wantSubnet {
		t.Fatalf("unlimited subnet = %+v, want [%+v]", gotSubnet, wantSubnet)
	}
}

func TestShowQuotaV3(t *testing.T) {
	t.Parallel()

	defaults := quota.Limits{}
	vpcLimit, sgLimit, ruleLimit := 0, 12, 345
	custom := quota.For(map[quota.Key]int{
		quota.VPCVPC:               vpcLimit,
		quota.VPCSubnet:            quota.Unlimited,
		quota.VPCSecurityGroup:     sgLimit,
		quota.VPCSecurityGroupRule: ruleLimit,
	})

	for _, tc := range []struct {
		name   string
		limits quota.Limits
		want   map[string]int
	}{
		{
			name:   "defaults",
			limits: defaults,
			want: map[string]int{
				"vpc":                 defaults.Get(quota.VPCVPC),
				"virsubnet":           defaults.Get(quota.VPCSubnet),
				"security_group":      defaults.Get(quota.VPCSecurityGroup),
				"security_group_rule": defaults.Get(quota.VPCSecurityGroupRule),
			},
		},
		{
			name:   "custom including zero and unlimited",
			limits: custom,
			want: map[string]int{
				"vpc":                 vpcLimit,
				"virsubnet":           quota.Unlimited,
				"security_group":      sgLimit,
				"security_group_rule": ruleLimit,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnvWithQuotas(t, store.NewMemory(), tc.limits)
			status, raw := e.call3(t, http.MethodGet, "/quotas", "")
			if status != http.StatusOK {
				t.Fatalf("GET /v3/.../vpc/quotas: %d %s", status, raw)
			}

			var body struct {
				RequestID string         `json:"request_id"`
				Quota     map[string]int `json:"quota"`
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("decode v3 quota response %s: %v", raw, err)
			}
			if body.RequestID == "" {
				t.Fatalf("missing request_id in %s", raw)
			}
			if len(body.Quota) != len(tc.want) {
				t.Fatalf("quota keys = %v, want %v", body.Quota, tc.want)
			}
			for k, wantVal := range tc.want {
				gotVal, ok := body.Quota[k]
				if !ok || gotVal != wantVal {
					t.Fatalf("quota[%q] = %d (present=%v), want %d", k, gotVal, ok, wantVal)
				}
			}
		})
	}
}
