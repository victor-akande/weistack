package nat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/faults"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

type pgwEnv struct {
	svc      *Service
	vpcSvc   *vpc.Service
	store    store.Store
	engine   *lifecycle.Engine
	clock    *lifecycle.FakeClock
	handler  http.Handler
	vpcID    string
	subnetID string
	vpc2ID   string
	subnet2  string
}

func newPGWEnv(t *testing.T) *pgwEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(gwTestEpoch)
	reg := faults.New(clock.Now)
	engine := lifecycle.New(lifecycle.Options{Delay: 0, Clock: clock, Logger: log, Faults: reg})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(23)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	svc, err := New(Deps{
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

	e := &pgwEnv{
		svc:     svc,
		vpcSvc:  vpcSvc,
		store:   st,
		engine:  engine,
		clock:   clock,
		handler: srv.Handler(),
	}
	e.vpcID, e.subnetID = e.seedVPCSubnet(t, gwTestTenant, "pgw-vpc-1", "192.168.0.0/16", "pgw-sub-1", "192.168.0.0/24", "192.168.0.1")
	e.vpc2ID, e.subnet2 = e.seedVPCSubnet(t, gwTestTenant, "pgw-vpc-2", "10.0.0.0/16", "pgw-sub-2", "10.0.0.0/24", "10.0.0.1")
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle seed: %v", err)
	}
	return e
}

func (e *pgwEnv) seedVPCSubnet(t *testing.T, tenant Tenant, vpcName, vpcCIDR, subName, subCIDR, gwIP string) (string, string) {
	t.Helper()
	ctx := t.Context()
	v, err := e.vpcSvc.CreateVPC(ctx, tenant, vpc.CreateVPCOption{
		Name: gwPtr(vpcName),
		CIDR: gwPtr(vpcCIDR),
	})
	if err != nil {
		t.Fatalf("CreateVPC %s: %v", vpcName, err)
	}
	sn, err := e.vpcSvc.CreateSubnet(ctx, tenant, vpc.CreateSubnetOption{
		Name:      subName,
		CIDR:      subCIDR,
		GatewayIP: gwIP,
		VPCID:     v.ID,
	})
	if err != nil {
		t.Fatalf("CreateSubnet %s: %v", subName, err)
	}
	return v.ID, sn.ID
}

func (e *pgwEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v3/"+gwTestProject+"/private-nat"+path, rd)
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

func (e *pgwEnv) expect(t *testing.T, dir, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", dir, goldenName+".json"), status, out)
	return out
}

func TestPrivateGatewayCreateSuccessAndDefaults(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)
	ctx := t.Context()

	g1, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:         "pgw-default",
		DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: e.subnetID}},
	})
	if err != nil {
		t.Fatalf("createPrivateGateway default: %v", err)
	}
	if g1.Spec != "Small" || g1.EnterpriseProjectID != defaultEnterpriseProjectID {
		t.Fatalf("defaults = (%q, %q), want (Small, 0)", g1.Spec, g1.EnterpriseProjectID)
	}
	if g1.VPCID != e.vpcID || g1.SubnetID != e.subnetID || g1.NgportIP != "192.168.0.2" {
		t.Fatalf("network = %+v", g1)
	}
	if !g1.CreatedAt.Equal(gwTestEpoch) || !g1.UpdatedAt.Equal(gwTestEpoch) {
		t.Fatalf("timestamps = (%v, %v), want %v", g1.CreatedAt, g1.UpdatedAt, gwTestEpoch)
	}

	g2, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:                "pgw-custom",
		Description:         "custom gateway",
		Spec:                gwPtr("Extra-xlarge"),
		DownlinkVPCs:        []downlinkVPCInput{{VirsubnetID: e.subnet2, NgportIPAddress: "10.0.0.44"}},
		EnterpriseProjectID: gwCustomEP,
		Tags:                []tag{{Key: "env", Value: "prod"}, {Key: "env", Value: "staging"}, {Key: "team", Value: ""}},
	})
	if err != nil {
		t.Fatalf("createPrivateGateway custom: %v", err)
	}
	if g2.Spec != "Extra-xlarge" || g2.NgportIP != "10.0.0.44" || g2.EnterpriseProjectID != gwCustomEP {
		t.Fatalf("custom = %+v", g2)
	}
	if len(g2.Tags) != 2 || g2.Tags[0] != (tag{Key: "env", Value: "staging"}) || g2.Tags[1] != (tag{Key: "team", Value: ""}) {
		t.Fatalf("tags = %+v", g2.Tags)
	}
}

func TestPrivateGatewayCreateRollsBackIPOnStoreFailure(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)
	ctx := t.Context()

	boom := errors.New("disk full")
	failingStore := &gwFailCreateStore{Store: e.store, failKind: kindPrivateGateway, err: boom}
	svc, err := New(Deps{
		Store:  failingStore,
		Engine: e.engine,
		IDs:    ids.NewSeeded(99),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		VPC:    e.vpcSvc,
		EIPs:   gwNoopEIPs{},
		Now:    e.clock.Now,
	})
	if err != nil {
		t.Fatalf("nat.New: %v", err)
	}

	_, err = svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:         "pgw-fail",
		DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: e.subnetID, NgportIPAddress: "192.168.0.77"}},
	})
	if !errors.Is(err, boom) {
		t.Fatalf("createPrivateGateway err = %v, want %v", err, boom)
	}

	sn, err := e.vpcSvc.GetSubnet(ctx, gwTestTenant, e.subnetID)
	if err != nil {
		t.Fatalf("GetSubnet: %v", err)
	}
	if sn.AvailableIPAddressCount != 251 {
		t.Fatalf("available IPs after rollback = %d, want 251", sn.AvailableIPAddressCount)
	}
	g, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:         "pgw-after-rollback",
		DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: e.subnetID, NgportIPAddress: "192.168.0.77"}},
	})
	if err != nil || g.NgportIP != "192.168.0.77" {
		t.Fatalf("re-allocate after rollback = %+v, %v", g, err)
	}
}

func TestPrivateGatewayCreateValidation(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)
	ctx := t.Context()

	// Seed one gateway on 192.168.0.10 to test NAT.1403.
	if _, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:         "pgw-occupied",
		DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: e.subnetID, NgportIPAddress: "192.168.0.10"}},
	}); err != nil {
		t.Fatalf("seed gateway: %v", err)
	}

	// Fill a /29 subnet (3 usable IPs) to test NAT.1404.
	_, fullSub := e.seedVPCSubnet(t, gwTestTenant, "pgw-vpc-full", "172.16.0.0/16", "pgw-sub-full", "172.16.0.0/29", "172.16.0.1")
	for i := range 3 {
		if _, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
			Name:         fmt.Sprintf("pgw-full-%d", i),
			DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: fullSub}},
		}); err != nil {
			t.Fatalf("fill subnet %d: %v", i, err)
		}
	}

	tooManyTags := make([]tag, maxTags+1)
	for i := range tooManyTags {
		tooManyTags[i] = tag{Key: fmt.Sprintf("k%d", i), Value: fmt.Sprintf("v%d", i)}
	}

	base := func() createPrivateGatewayInput {
		return createPrivateGatewayInput{
			Name:         "valid-pgw",
			DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: e.subnetID}},
		}
	}

	tests := []struct {
		name       string
		mutate     func(*createPrivateGatewayInput)
		wantCode   string
		wantStatus int
	}{
		{
			name:       "empty name",
			mutate:     func(in *createPrivateGatewayInput) { in.Name = "" },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "name with space",
			mutate:     func(in *createPrivateGatewayInput) { in.Name = "bad name" },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "name > 64 chars",
			mutate:     func(in *createPrivateGatewayInput) { in.Name = strings.Repeat("a", 65) },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "description > 255 runes",
			mutate:     func(in *createPrivateGatewayInput) { in.Description = strings.Repeat("x", 256) },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "description contains <",
			mutate:     func(in *createPrivateGatewayInput) { in.Description = "bad <desc" },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "description contains >",
			mutate:     func(in *createPrivateGatewayInput) { in.Description = "bad desc>" },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid empty spec",
			mutate:     func(in *createPrivateGatewayInput) { in.Spec = gwPtr("") },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid unknown spec",
			mutate:     func(in *createPrivateGatewayInput) { in.Spec = gwPtr("Huge") },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid enterprise_project_id",
			mutate:     func(in *createPrivateGatewayInput) { in.EnterpriseProjectID = "not-a-uuid" },
			wantCode:   "VPC.0011",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "tag empty key",
			mutate:     func(in *createPrivateGatewayInput) { in.Tags = []tag{{Key: "", Value: "v"}} },
			wantCode:   "NAT.1015",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "tag key > 128 runes",
			mutate:     func(in *createPrivateGatewayInput) { in.Tags = []tag{{Key: strings.Repeat("k", 129), Value: "v"}} },
			wantCode:   "NAT.1015",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "tag value > 255 runes",
			mutate:     func(in *createPrivateGatewayInput) { in.Tags = []tag{{Key: "k", Value: strings.Repeat("v", 256)}} },
			wantCode:   "NAT.1015",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "more than max tags",
			mutate:     func(in *createPrivateGatewayInput) { in.Tags = tooManyTags },
			wantCode:   "NAT.1016",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "no downlink_vpcs",
			mutate:     func(in *createPrivateGatewayInput) { in.DownlinkVPCs = nil },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "more than one downlink_vpc",
			mutate: func(in *createPrivateGatewayInput) {
				in.DownlinkVPCs = []downlinkVPCInput{{VirsubnetID: e.subnetID}, {VirsubnetID: e.subnet2}}
			},
			wantCode:   "NAT.1201",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty virsubnet_id",
			mutate:     func(in *createPrivateGatewayInput) { in.DownlinkVPCs = []downlinkVPCInput{{VirsubnetID: ""}} },
			wantCode:   "NAT.1010",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "unknown virsubnet_id",
			mutate: func(in *createPrivateGatewayInput) {
				in.DownlinkVPCs = []downlinkVPCInput{{VirsubnetID: gwUnknownUUID}}
			},
			wantCode:   "NAT.1002",
			wantStatus: http.StatusNotFound,
		},
		{
			name: "ngport_ip_address malformed",
			mutate: func(in *createPrivateGatewayInput) {
				in.DownlinkVPCs = []downlinkVPCInput{{VirsubnetID: e.subnetID, NgportIPAddress: "not-an-ip"}}
			},
			wantCode:   "NAT.1405",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "ngport_ip_address gateway ip",
			mutate: func(in *createPrivateGatewayInput) {
				in.DownlinkVPCs = []downlinkVPCInput{{VirsubnetID: e.subnetID, NgportIPAddress: "192.168.0.1"}}
			},
			wantCode:   "NAT.1405",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "ngport_ip_address outside subnet",
			mutate: func(in *createPrivateGatewayInput) {
				in.DownlinkVPCs = []downlinkVPCInput{{VirsubnetID: e.subnetID, NgportIPAddress: "10.0.0.5"}}
			},
			wantCode:   "NAT.1405",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "ngport_ip_address already in use",
			mutate: func(in *createPrivateGatewayInput) {
				in.DownlinkVPCs = []downlinkVPCInput{{VirsubnetID: e.subnetID, NgportIPAddress: "192.168.0.10"}}
			},
			wantCode:   "NAT.1403",
			wantStatus: http.StatusConflict,
		},
		{
			name:       "subnet full",
			mutate:     func(in *createPrivateGatewayInput) { in.DownlinkVPCs = []downlinkVPCInput{{VirsubnetID: fullSub}} },
			wantCode:   "NAT.1404",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.mutate(&in)
			_, err := e.svc.createPrivateGateway(ctx, gwTestTenant, in)
			if gwCodeOf(err) != tc.wantCode || gwStatusOf(err) != tc.wantStatus {
				t.Fatalf("createPrivateGateway err = (%d, %q, %v), want (%d, %q)",
					gwStatusOf(err), gwCodeOf(err), err, tc.wantStatus, tc.wantCode)
			}
		})
	}
}

func TestPrivateGatewayUpdateRules(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)
	ctx := t.Context()

	g, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:         "pgw-upd",
		Description:  "initial",
		Spec:         gwPtr("Medium"),
		DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: e.subnetID}},
	})
	if err != nil {
		t.Fatalf("createPrivateGateway: %v", err)
	}

	e.clock.Advance(time.Minute)

	// Partial update preserves untouched fields and updates UpdatedAt.
	got, err := e.svc.updatePrivateGateway(ctx, gwTestTenant, g.ID, updatePrivateGatewayInput{
		Name: gwPtr("pgw-upd-2"),
	})
	if err != nil {
		t.Fatalf("updatePrivateGateway partial: %v", err)
	}
	if got.Name != "pgw-upd-2" || got.Description != "initial" || got.Spec != "Medium" {
		t.Fatalf("partial update = %+v", got)
	}
	if !got.UpdatedAt.Equal(gwTestEpoch.Add(time.Minute)) {
		t.Fatalf("updated_at = %v, want %v", got.UpdatedAt, gwTestEpoch.Add(time.Minute))
	}

	// Clearing description and changing spec succeeds.
	got, err = e.svc.updatePrivateGateway(ctx, gwTestTenant, g.ID, updatePrivateGatewayInput{
		Description: gwPtr(""),
		Spec:        gwPtr("Large"),
	})
	if err != nil {
		t.Fatalf("updatePrivateGateway clear desc + spec: %v", err)
	}
	if got.Description != "" || got.Spec != "Large" {
		t.Fatalf("after clear desc = %+v", got)
	}

	// Validation & error cases.
	tests := []struct {
		name     string
		id       string
		in       updatePrivateGatewayInput
		wantCode string
	}{
		{"not found", gwUnknownUUID, updatePrivateGatewayInput{Name: gwPtr("ok")}, "NAT.1002"},
		{"bad name", g.ID, updatePrivateGatewayInput{Name: gwPtr("bad name")}, "NAT.1010"},
		{"empty name", g.ID, updatePrivateGatewayInput{Name: gwPtr("")}, "NAT.1010"},
		{"bad desc", g.ID, updatePrivateGatewayInput{Description: gwPtr("<bad>")}, "NAT.1010"},
		{"bad spec", g.ID, updatePrivateGatewayInput{Spec: gwPtr("Giant")}, "NAT.1010"},
		{"same spec", g.ID, updatePrivateGatewayInput{Spec: gwPtr("Large")}, "NAT.1206"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.svc.updatePrivateGateway(ctx, gwTestTenant, tc.id, tc.in); gwCodeOf(err) != tc.wantCode {
				t.Fatalf("updatePrivateGateway err = %v, want %s", err, tc.wantCode)
			}
		})
	}

	// Seed rules exceeding Small's rule_max (within Medium's), split across SNAT and DNAT.
	smallMax := privateRuleMax("Small")
	mediumMax := privateRuleMax("Medium")
	snatCount := smallMax/2 + 1
	dnatCount := smallMax + 1 - snatCount
	for i := range snatCount {
		rid := fmt.Sprintf("11111111-1111-4111-8111-%012d", i)
		if err := e.svc.privateSnats(gwTestTenant).Create(ctx, rid, privateSnat{ID: rid, GatewayID: g.ID}); err != nil {
			t.Fatalf("seed private snat %d: %v", i, err)
		}
	}
	for i := range dnatCount {
		rid := fmt.Sprintf("22222222-2222-4222-8222-%012d", i)
		if err := e.svc.privateDnats(gwTestTenant).Create(ctx, rid, privateDnat{ID: rid, GatewayID: g.ID}); err != nil {
			t.Fatalf("seed private dnat %d: %v", i, err)
		}
	}
	if _, err := e.svc.updatePrivateGateway(ctx, gwTestTenant, g.ID, updatePrivateGatewayInput{Spec: gwPtr("Small")}); gwCodeOf(err) != "NAT.1207" {
		t.Fatalf("downgrade below rule count err = %v, want NAT.1207", err)
	}
	if _, err := e.svc.updatePrivateGateway(ctx, gwTestTenant, g.ID, updatePrivateGatewayInput{Spec: gwPtr("Medium")}); err != nil {
		t.Fatalf("downgrade to Medium (rule_max %d >= %d) failed: %v", mediumMax, snatCount+dnatCount, err)
	}
}

func TestPrivateGatewayDeleteRules(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)
	ctx := t.Context()

	if err := e.svc.deletePrivateGateway(ctx, gwTestTenant, gwUnknownUUID); gwCodeOf(err) != "NAT.1002" {
		t.Fatalf("delete unknown err = %v, want NAT.1002", err)
	}

	g, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:         "pgw-del",
		DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: e.subnetID}},
	})
	if err != nil {
		t.Fatalf("createPrivateGateway: %v", err)
	}

	// Private SNAT rule present -> NAT.1202.
	snatID := "33333333-3333-4333-8333-333333333333"
	if err := e.svc.privateSnats(gwTestTenant).Create(ctx, snatID, privateSnat{ID: snatID, GatewayID: g.ID}); err != nil {
		t.Fatalf("seed private snat: %v", err)
	}
	if err := e.svc.deletePrivateGateway(ctx, gwTestTenant, g.ID); gwCodeOf(err) != "NAT.1202" {
		t.Fatalf("delete with snat err = %v, want NAT.1202", err)
	}
	if err := e.svc.privateSnats(gwTestTenant).Delete(ctx, snatID); err != nil {
		t.Fatalf("delete snat: %v", err)
	}

	// Private DNAT rule present -> NAT.1202.
	dnatID := "44444444-4444-4444-8444-444444444444"
	if err := e.svc.privateDnats(gwTestTenant).Create(ctx, dnatID, privateDnat{ID: dnatID, GatewayID: g.ID}); err != nil {
		t.Fatalf("seed private dnat: %v", err)
	}
	if err := e.svc.deletePrivateGateway(ctx, gwTestTenant, g.ID); gwCodeOf(err) != "NAT.1202" {
		t.Fatalf("delete with dnat err = %v, want NAT.1202", err)
	}
	if err := e.svc.privateDnats(gwTestTenant).Delete(ctx, dnatID); err != nil {
		t.Fatalf("delete dnat: %v", err)
	}

	// Now delete succeeds and releases its IP.
	if err := e.svc.deletePrivateGateway(ctx, gwTestTenant, g.ID); err != nil {
		t.Fatalf("deletePrivateGateway: %v", err)
	}
	if _, err := e.svc.getPrivateGateway(ctx, gwTestTenant, g.ID); gwCodeOf(err) != "NAT.1002" {
		t.Fatalf("get after delete err = %v, want NAT.1002", err)
	}
	sn, err := e.vpcSvc.GetSubnet(ctx, gwTestTenant, e.subnetID)
	if err != nil {
		t.Fatalf("GetSubnet: %v", err)
	}
	if sn.AvailableIPAddressCount != 251 {
		t.Fatalf("available IPs after delete = %d, want 251", sn.AvailableIPAddressCount)
	}
}

func TestPrivateGatewayListFiltersAndPagination(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)
	ctx := t.Context()

	g1, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:                "pgw-alpha",
		Description:         "desc-alpha",
		Spec:                gwPtr("Small"),
		DownlinkVPCs:        []downlinkVPCInput{{VirsubnetID: e.subnetID}},
		EnterpriseProjectID: defaultEnterpriseProjectID,
	})
	if err != nil {
		t.Fatalf("create g1: %v", err)
	}
	g2, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:                "pgw-beta",
		Description:         "desc-beta",
		Spec:                gwPtr("Medium"),
		DownlinkVPCs:        []downlinkVPCInput{{VirsubnetID: e.subnet2}},
		EnterpriseProjectID: gwCustomEP,
	})
	if err != nil {
		t.Fatalf("create g2: %v", err)
	}
	g3, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:                "pgw-gamma",
		Description:         "desc-gamma",
		Spec:                gwPtr("Large"),
		DownlinkVPCs:        []downlinkVPCInput{{VirsubnetID: e.subnetID}},
		EnterpriseProjectID: gwCustomEP,
	})
	if err != nil {
		t.Fatalf("create g3: %v", err)
	}

	// Project B isolation.
	_, subB := e.seedVPCSubnet(t, gwTestTenantB, "pgw-vpc-b", "192.168.0.0/16", "pgw-sub-b", "192.168.0.0/24", "192.168.0.1")
	if _, err := e.svc.createPrivateGateway(ctx, gwTestTenantB, createPrivateGatewayInput{
		Name:         "pgw-other-project",
		DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: subB}},
	}); err != nil {
		t.Fatalf("create project B pgw: %v", err)
	}

	allPage := pagination.Marker{Limit: listLimits.Default}
	all, info, err := e.svc.listPrivateGateways(ctx, gwTestTenant, listPrivateGatewaysFilter{Page: allPage})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 || info.CurrentCount != 3 || info.NextMarker != "" || info.PreviousMarker != all[0].ID {
		t.Fatalf("list all = (%d, %+v)", len(all), info)
	}
	if all[0].ID >= all[1].ID || all[1].ID >= all[2].ID {
		t.Fatalf("IDs not sorted ascending: %s, %s, %s", all[0].ID, all[1].ID, all[2].ID)
	}

	p1, info1, err := e.svc.listPrivateGateways(ctx, gwTestTenant, listPrivateGatewaysFilter{Page: pagination.Marker{Limit: 2}})
	if err != nil || len(p1) != 2 || info1.CurrentCount != 2 || info1.NextMarker != p1[1].ID || info1.PreviousMarker != p1[0].ID {
		t.Fatalf("page 1 = (%+v, %+v, %v)", p1, info1, err)
	}
	p2, info2, err := e.svc.listPrivateGateways(ctx, gwTestTenant, listPrivateGatewaysFilter{Page: pagination.Marker{ID: info1.NextMarker, Limit: 2}})
	if err != nil || len(p2) != 1 || p2[0].ID != all[2].ID || info2.CurrentCount != 1 || info2.NextMarker != "" || info2.PreviousMarker != all[2].ID {
		t.Fatalf("page 2 = (%+v, %+v, %v)", p2, info2, err)
	}
	if _, _, err := e.svc.listPrivateGateways(ctx, gwTestTenant, listPrivateGatewaysFilter{Page: pagination.Marker{ID: gwUnknownUUID, Limit: 10}}); gwCodeOf(err) != "NAT.1010" {
		t.Fatalf("unknown marker err = %v, want NAT.1010", err)
	}

	tests := []struct {
		name    string
		filter  listPrivateGatewaysFilter
		wantIDs []string
	}{
		{"id multi", listPrivateGatewaysFilter{IDs: []string{g1.ID, g3.ID}, Page: allPage}, []string{g1.ID, g3.ID}},
		{"project_id matches", listPrivateGatewaysFilter{ProjectIDs: []string{gwTestProject}, Page: allPage}, []string{g1.ID, g2.ID, g3.ID}},
		{"project_id mismatch", listPrivateGatewaysFilter{ProjectIDs: []string{gwTestProjectB}, Page: allPage}, nil},
		{"name", listPrivateGatewaysFilter{Names: []string{"pgw-beta"}, Page: allPage}, []string{g2.ID}},
		{"description", listPrivateGatewaysFilter{Descriptions: []string{"desc-gamma"}, Page: allPage}, []string{g3.ID}},
		{"spec multi", listPrivateGatewaysFilter{Specs: []string{"Small", "Large"}, Page: allPage}, []string{g1.ID, g3.ID}},
		{"status ACTIVE", listPrivateGatewaysFilter{Statuses: []string{StatusActive}, Page: allPage}, []string{g1.ID, g2.ID, g3.ID}},
		{"status INACTIVE", listPrivateGatewaysFilter{Statuses: []string{StatusInactive}, Page: allPage}, nil},
		{"vpc_id", listPrivateGatewaysFilter{VPCIDs: []string{e.vpc2ID}, Page: allPage}, []string{g2.ID}},
		{"virsubnet_id", listPrivateGatewaysFilter{VirsubnetIDs: []string{e.subnetID}, Page: allPage}, []string{g1.ID, g3.ID}},
		{"ep 0", listPrivateGatewaysFilter{EnterpriseProjectIDs: []string{"0"}, Page: allPage}, []string{g1.ID}},
		{"ep custom", listPrivateGatewaysFilter{EnterpriseProjectIDs: []string{gwCustomEP}, Page: allPage}, []string{g2.ID, g3.ID}},
		{"ep all_granted_eps", listPrivateGatewaysFilter{EnterpriseProjectIDs: []string{allGrantedEPs}, Page: allPage}, []string{g1.ID, g2.ID, g3.ID}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := e.svc.listPrivateGateways(ctx, gwTestTenant, tc.filter)
			if err != nil {
				t.Fatalf("listPrivateGateways: %v", err)
			}
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("got %d gateways, want %d", len(got), len(tc.wantIDs))
			}
			gotSet := map[string]bool{}
			for _, g := range got {
				gotSet[g.ID] = true
			}
			for _, id := range tc.wantIDs {
				if !gotSet[id] {
					t.Fatalf("missing expected gateway %s", id)
				}
			}
		})
	}
}

func TestTransitSubnetLifecycleAndValidation(t *testing.T) {
	t.Parallel()
	e := newPGWEnv(t)
	ctx := t.Context()

	// Seed a private gateway on e.subnet2 so CreateTransitSubnet on e.subnet2 returns NAT.1101.
	if _, err := e.svc.createPrivateGateway(ctx, gwTestTenant, createPrivateGatewayInput{
		Name:         "pgw-on-sub2",
		DownlinkVPCs: []downlinkVPCInput{{VirsubnetID: e.subnet2}},
	}); err != nil {
		t.Fatalf("seed gateway: %v", err)
	}

	ts, ipCount, err := e.svc.createTransitSubnet(ctx, gwTestTenant, createTransitSubnetInput{
		Name:               "ts-1",
		Description:        "transit subnet 1",
		VirsubnetID:        e.subnetID,
		VirsubnetProjectID: gwTestProject,
		Tags:               []tag{{Key: "k1", Value: "v1"}},
	})
	if err != nil {
		t.Fatalf("createTransitSubnet: %v", err)
	}
	if ts.VPCID != e.vpcID || ts.CIDR != "192.168.0.0/24" || ipCount != 0 {
		t.Fatalf("created transit subnet = %+v, ipCount=%d", ts, ipCount)
	}

	// Dynamic ip_count reflects transitIPs in the same virsubnet_id.
	tiID := "66666666-6666-4666-8666-666666666666"
	if err := e.svc.transitIPs(gwTestTenant).Create(ctx, tiID, transitIP{ID: tiID, SubnetID: e.subnetID, Address: "192.168.0.50"}); err != nil {
		t.Fatalf("seed transit ip: %v", err)
	}
	got, gotCount, err := e.svc.getTransitSubnet(ctx, gwTestTenant, ts.ID)
	if err != nil || got.ID != ts.ID || gotCount != 1 {
		t.Fatalf("getTransitSubnet = (%+v, %d, %v)", got, gotCount, err)
	}

	// Update name and description.
	e.clock.Advance(time.Minute)
	upd, updCount, err := e.svc.updateTransitSubnet(ctx, gwTestTenant, ts.ID, updateTransitSubnetInput{
		Name:        gwPtr("ts-1-renamed"),
		Description: gwPtr(""),
	})
	if err != nil || upd.Name != "ts-1-renamed" || upd.Description != "" || updCount != 1 || !upd.UpdatedAt.Equal(gwTestEpoch.Add(time.Minute)) {
		t.Fatalf("updateTransitSubnet = (%+v, %d, %v)", upd, updCount, err)
	}

	// Delete while transit IP exists -> NAT.1202.
	if err := e.svc.deleteTransitSubnet(ctx, gwTestTenant, ts.ID); gwCodeOf(err) != "NAT.1202" {
		t.Fatalf("delete with transit ip err = %v, want NAT.1202", err)
	}
	if err := e.svc.transitIPs(gwTestTenant).Delete(ctx, tiID); err != nil {
		t.Fatalf("delete transit ip: %v", err)
	}
	if err := e.svc.deleteTransitSubnet(ctx, gwTestTenant, ts.ID); err != nil {
		t.Fatalf("deleteTransitSubnet: %v", err)
	}
	if _, _, err := e.svc.getTransitSubnet(ctx, gwTestTenant, ts.ID); gwCodeOf(err) != "NAT.1002" {
		t.Fatalf("get after delete err = %v, want NAT.1002", err)
	}

	// Validation error cases.
	_, sub3 := e.seedVPCSubnet(t, gwTestTenant, "pgw-vpc-3", "172.16.0.0/16", "pgw-sub-3", "172.16.0.0/24", "172.16.0.1")
	if _, _, err := e.svc.createTransitSubnet(ctx, gwTestTenant, createTransitSubnetInput{
		Name:               "ts-existing",
		VirsubnetID:        sub3,
		VirsubnetProjectID: gwTestProject,
	}); err != nil {
		t.Fatalf("seed ts3: %v", err)
	}

	tooManyTags := make([]tag, maxTags+1)
	for i := range tooManyTags {
		tooManyTags[i] = tag{Key: fmt.Sprintf("k%d", i), Value: "v"}
	}
	createTests := []struct {
		name     string
		in       createTransitSubnetInput
		wantCode string
	}{
		{"bad name", createTransitSubnetInput{Name: "bad name", VirsubnetID: e.subnetID, VirsubnetProjectID: gwTestProject}, "NAT.1010"},
		{"bad desc", createTransitSubnetInput{Name: "ok", Description: "<x>", VirsubnetID: e.subnetID, VirsubnetProjectID: gwTestProject}, "NAT.1010"},
		{"missing virsubnet_id", createTransitSubnetInput{Name: "ok", VirsubnetProjectID: gwTestProject}, "NAT.1010"},
		{"missing virsubnet_project_id", createTransitSubnetInput{Name: "ok", VirsubnetID: e.subnetID}, "NAT.1010"},
		{"mismatched virsubnet_project_id", createTransitSubnetInput{Name: "ok", VirsubnetID: e.subnetID, VirsubnetProjectID: gwTestProjectB}, "NAT.1010"},
		{"invalid tag", createTransitSubnetInput{Name: "ok", VirsubnetID: e.subnetID, VirsubnetProjectID: gwTestProject, Tags: []tag{{Key: ""}}}, "NAT.1015"},
		{"too many tags", createTransitSubnetInput{Name: "ok", VirsubnetID: e.subnetID, VirsubnetProjectID: gwTestProject, Tags: tooManyTags}, "NAT.1016"},
		{"unknown virsubnet_id", createTransitSubnetInput{Name: "ok", VirsubnetID: gwUnknownUUID, VirsubnetProjectID: gwTestProject}, "NAT.1002"},
		{"already transit subnet", createTransitSubnetInput{Name: "ok", VirsubnetID: sub3, VirsubnetProjectID: gwTestProject}, "NAT.1101"},
		{"subnet used by private gateway", createTransitSubnetInput{Name: "ok", VirsubnetID: e.subnet2, VirsubnetProjectID: gwTestProject}, "NAT.1101"},
	}
	for _, tc := range createTests {
		t.Run("create_"+tc.name, func(t *testing.T) {
			if _, _, err := e.svc.createTransitSubnet(ctx, gwTestTenant, tc.in); gwCodeOf(err) != tc.wantCode {
				t.Fatalf("createTransitSubnet err = %v, want %s", err, tc.wantCode)
			}
		})
	}

	if _, _, err := e.svc.updateTransitSubnet(ctx, gwTestTenant, gwUnknownUUID, updateTransitSubnetInput{Name: gwPtr("ok")}); gwCodeOf(err) != "NAT.1002" {
		t.Fatalf("update unknown err = %v, want NAT.1002", err)
	}
	if err := e.svc.deleteTransitSubnet(ctx, gwTestTenant, gwUnknownUUID); gwCodeOf(err) != "NAT.1002" {
		t.Fatalf("delete unknown err = %v, want NAT.1002", err)
	}
}
