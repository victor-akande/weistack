package nat

import (
	"context"
	"encoding/json"
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

	"github.com/victor-akande/weistack/internal/core/apierr"
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

const (
	gwTestProject  = "0123456789abcdef0123456789abcdef"
	gwTestProjectB = "fedcba9876543210fedcba9876543210"
	gwTestRegion   = "ap-southeast-1"
	gwTestHost     = "nat." + gwTestRegion + ".myhuaweicloud.com"
	gwTestDelay    = 2 * time.Second
	gwUnknownUUID  = "00000000-0000-4000-8000-000000000000"
	gwCustomEP     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

var (
	gwTestTenant  = Tenant{Region: gwTestRegion, ProjectID: gwTestProject}
	gwTestTenantB = Tenant{Region: gwTestRegion, ProjectID: gwTestProjectB}
	gwTestEpoch   = time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
)

// gwNoopEIPs satisfies PublicIPs for gateway tests that do not exercise EIPs.
type gwNoopEIPs struct{}

func (gwNoopEIPs) HoldForNAT(_ context.Context, _ vpc.Tenant, _, _ string) (string, error) {
	return "", errors.New("unexpected HoldForNAT")
}

func (gwNoopEIPs) ReleaseFromNAT(_ context.Context, _ vpc.Tenant, _, _ string) error {
	return nil
}

func (gwNoopEIPs) PublicIPByAddress(_ context.Context, _ vpc.Tenant, _ string) (string, bool, error) {
	return "", false, nil
}

func (gwNoopEIPs) PublicIPAddress(_ context.Context, _ vpc.Tenant, _ string) (string, bool, error) {
	return "", false, nil
}

type gwEnv struct {
	svc      *Service
	vpcSvc   *vpc.Service
	store    store.Store
	engine   *lifecycle.Engine
	clock    *lifecycle.FakeClock
	faults   *faults.Registry
	handler  http.Handler
	vpcID    string
	subnetID string
	vpc2ID   string
	subnet2  string
}

func newGWEnv(t *testing.T) *gwEnv {
	t.Helper()
	return newGWEnvWithDelay(t, gwTestDelay)
}

func newGWEnvWithDelay(t *testing.T, delay time.Duration) *gwEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(gwTestEpoch)
	reg := faults.New(clock.Now)
	engine := lifecycle.New(lifecycle.Options{Delay: delay, Clock: clock, Logger: log, Faults: reg})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(11)
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

	e := &gwEnv{
		svc:     svc,
		vpcSvc:  vpcSvc,
		store:   st,
		engine:  engine,
		clock:   clock,
		faults:  reg,
		handler: srv.Handler(),
	}

	// Seed two VPCs and one subnet in each so tests have real VPC/subnet IDs.
	e.vpcID, e.subnetID = e.seedVPCSubnet(t, gwTestTenant, "vpc-1", "192.168.0.0/16", "sub-1", "192.168.0.0/24", "192.168.0.1")
	e.vpc2ID, e.subnet2 = e.seedVPCSubnet(t, gwTestTenant, "vpc-2", "10.0.0.0/16", "sub-2", "10.0.0.0/24", "10.0.0.1")
	if delay > 0 {
		e.clock.Advance(delay)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := e.engine.WaitIdle(waitCtx); err != nil {
		t.Fatalf("WaitIdle seed: %v", err)
	}
	// Reset fake clock to epoch after seeding VPCs/subnets so gateway created_at is deterministic.
	clock2 := lifecycle.NewFakeClock(gwTestEpoch)
	svc.now = clock2.Now
	return e
}

func (e *gwEnv) seedVPCSubnet(t *testing.T, tenant Tenant, vpcName, vpcCIDR, subName, subCIDR, gwIP string) (string, string) {
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

func (e *gwEnv) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(gwTestDelay)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

func (e *gwEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callAs(t, gwTestProject, method, path, body)
}

func (e *gwEnv) callAs(t *testing.T, project, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v2/"+project+path, rd)
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

func (e *gwEnv) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "gateways", goldenName+".json"), status, out)
	return out
}

func gwPtr[T any](v T) *T { return &v }

func gwDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func gwCodeOf(err error) string {
	if err == nil {
		return ""
	}
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return err.Error()
}

func gwStatusOf(err error) int {
	if err == nil {
		return 0
	}
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func TestGatewayLifecycleZeroDelay(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)
	ctx := t.Context()

	g, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:              "gw-zero",
		RouterID:          e.vpcID,
		InternalNetworkID: e.subnetID,
		Spec:              "1",
		Description:       "zero delay test",
	})
	if err != nil {
		t.Fatalf("createGateway: %v", err)
	}
	if g.Status != StatusPendingCreate {
		t.Fatalf("initial status = %q, want PENDING_CREATE", g.Status)
	}
	if g.EnterpriseProjectID != defaultEnterpriseProjectID {
		t.Fatalf("default ep = %q, want 0", g.EnterpriseProjectID)
	}
	if g.Session != defaultSessionConf {
		t.Fatalf("default session = %+v, want %+v", g.Session, defaultSessionConf)
	}
	if g.NgportIP != "192.168.0.2" {
		t.Fatalf("ngport_ip = %q, want 192.168.0.2", g.NgportIP)
	}

	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	got, err := e.svc.getGateway(ctx, gwTestTenant, g.ID)
	if err != nil {
		t.Fatalf("getGateway: %v", err)
	}
	if got.Status != StatusActive {
		t.Fatalf("settled status = %q, want ACTIVE", got.Status)
	}
}

func TestGatewayLifecycleFaultInactive(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)
	ctx := t.Context()

	if _, err := e.faults.Add(faults.Rule{
		Type:       faults.TypeLifecycle,
		Transition: taskGatewayCreate,
		Times:      1,
	}); err != nil {
		t.Fatalf("faults.Add: %v", err)
	}

	g, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:              "gw-fault",
		RouterID:          e.vpcID,
		InternalNetworkID: e.subnetID,
		Spec:              "2",
	})
	if err != nil {
		t.Fatalf("createGateway: %v", err)
	}
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	got, err := e.svc.getGateway(ctx, gwTestTenant, g.ID)
	if err != nil {
		t.Fatalf("getGateway: %v", err)
	}
	if got.Status != StatusInactive {
		t.Fatalf("status after fault = %q, want INACTIVE", got.Status)
	}

	// Updating an INACTIVE gateway is refused with NAT.0103.
	if _, err := e.svc.updateGateway(ctx, gwTestTenant, g.ID, updateGatewayInput{Name: gwPtr("renamed")}); gwCodeOf(err) != "NAT.0103" {
		t.Fatalf("update INACTIVE err = %v, want NAT.0103", err)
	}

	// Deleting an INACTIVE gateway succeeds and releases its IP.
	if err := e.svc.deleteGateway(ctx, gwTestTenant, g.ID); err != nil {
		t.Fatalf("delete INACTIVE: %v", err)
	}
	sn, err := e.vpcSvc.GetSubnet(ctx, gwTestTenant, e.subnetID)
	if err != nil {
		t.Fatalf("GetSubnet: %v", err)
	}
	if sn.AvailableIPAddressCount != 251 {
		t.Fatalf("available IPs after delete = %d, want 251", sn.AvailableIPAddressCount)
	}
}

func TestGatewayResumePendingCreate(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)
	ctx := t.Context()

	stuck := gateway{
		ID:                  "11111111-1111-4111-8111-111111111111",
		Name:                "gw-resumed",
		Spec:                "1",
		Status:              StatusPendingCreate,
		RouterID:            e.vpcID,
		InternalNetworkID:   e.subnetID,
		NgportIP:            "192.168.0.50",
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Session:             defaultSessionConf,
		CreatedAt:           gwTestEpoch,
	}
	if err := e.svc.gateways(gwTestTenant).Create(ctx, stuck.ID, stuck); err != nil {
		t.Fatalf("seed gateway: %v", err)
	}
	if err := e.svc.Resume(ctx); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
	got, err := e.svc.getGateway(ctx, gwTestTenant, stuck.ID)
	if err != nil {
		t.Fatalf("getGateway: %v", err)
	}
	if got.Status != StatusActive {
		t.Fatalf("resumed status = %q, want ACTIVE", got.Status)
	}
}

// gwFailCreateStore wraps a store.Store and fails Create for one kind.
type gwFailCreateStore struct {
	store.Store
	failKind string
	err      error
}

func (s *gwFailCreateStore) Create(ctx context.Context, scope store.Scope, id string, data []byte) (store.Record, error) {
	if scope.Kind == s.failKind {
		return store.Record{}, s.err
	}
	return s.Store.Create(ctx, scope, id, data)
}

func TestGatewayCreateRollsBackIPOnStoreFailure(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)
	ctx := t.Context()

	boom := errors.New("disk full")
	failingStore := &gwFailCreateStore{Store: e.store, failKind: kindGateway, err: boom}
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

	_, err = svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:              "gw-fail",
		RouterID:          e.vpcID,
		InternalNetworkID: e.subnetID,
		NgportIPAddress:   "192.168.0.77",
		Spec:              "1",
	})
	if !errors.Is(err, boom) {
		t.Fatalf("createGateway err = %v, want %v", err, boom)
	}

	// The IP must have been released back to the subnet.
	sn, err := e.vpcSvc.GetSubnet(ctx, gwTestTenant, e.subnetID)
	if err != nil {
		t.Fatalf("GetSubnet: %v", err)
	}
	if sn.AvailableIPAddressCount != 251 {
		t.Fatalf("available IPs after rollback = %d, want 251", sn.AvailableIPAddressCount)
	}
	// Re-allocating the exact same IP must succeed.
	g, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:              "gw-after-rollback",
		RouterID:          e.vpcID,
		InternalNetworkID: e.subnetID,
		NgportIPAddress:   "192.168.0.77",
		Spec:              "1",
	})
	if err != nil || g.NgportIP != "192.168.0.77" {
		t.Fatalf("create after rollback = %+v, %v", g, err)
	}
}

func TestGatewayCreateValidation(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)
	ctx := t.Context()

	// Seed one gateway occupying 192.168.0.10 to test ErrIPInUse.
	if _, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:              "gw-occupied",
		RouterID:          e.vpcID,
		InternalNetworkID: e.subnetID,
		NgportIPAddress:   "192.168.0.10",
		Spec:              "1",
	}); err != nil {
		t.Fatalf("seed gateway: %v", err)
	}

	// Seed a tiny /29 subnet (3 usable IPs: .2, .3, .4) and fill it to test NAT.1404.
	fullVPC, fullSub := e.seedVPCSubnet(t, gwTestTenant, "vpc-full", "172.16.0.0/16", "sub-full", "172.16.0.0/29", "172.16.0.1")
	for i := range 3 {
		if _, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
			Name:              fmt.Sprintf("gw-full-%d", i),
			RouterID:          fullVPC,
			InternalNetworkID: fullSub,
			Spec:              "1",
		}); err != nil {
			t.Fatalf("fill subnet %d: %v", i, err)
		}
	}

	tooManyTags := make([]string, maxTags+1)
	for i := range tooManyTags {
		tooManyTags[i] = fmt.Sprintf("k%d*v%d", i, i)
	}

	base := func() createGatewayInput {
		return createGatewayInput{
			Name:              "valid-gw",
			RouterID:          e.vpcID,
			InternalNetworkID: e.subnetID,
			Spec:              "1",
		}
	}

	tests := []struct {
		name       string
		mutate     func(*createGatewayInput)
		wantCode   string
		wantStatus int
	}{
		{
			name:       "prepaid_options not implemented",
			mutate:     func(in *createGatewayInput) { in.PrepaidOptions = true },
			wantCode:   apierr.CodeNotImplemented,
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "empty name",
			mutate:     func(in *createGatewayInput) { in.Name = "" },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "name with space",
			mutate:     func(in *createGatewayInput) { in.Name = "bad name" },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "name > 64 chars",
			mutate:     func(in *createGatewayInput) { in.Name = strings.Repeat("a", 65) },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing router_id",
			mutate:     func(in *createGatewayInput) { in.RouterID = "" },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing internal_network_id",
			mutate:     func(in *createGatewayInput) { in.InternalNetworkID = "" },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing spec",
			mutate:     func(in *createGatewayInput) { in.Spec = "" },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid spec 0",
			mutate:     func(in *createGatewayInput) { in.Spec = "0" },
			wantCode:   "NAT.0016",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid spec 6",
			mutate:     func(in *createGatewayInput) { in.Spec = "6" },
			wantCode:   "NAT.0016",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "description > 255 runes",
			mutate:     func(in *createGatewayInput) { in.Description = strings.Repeat("x", 256) },
			wantCode:   "NAT.0014",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "description contains angle bracket <",
			mutate:     func(in *createGatewayInput) { in.Description = "bad <desc" },
			wantCode:   "NAT.0014",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "description contains angle bracket >",
			mutate:     func(in *createGatewayInput) { in.Description = "bad desc>" },
			wantCode:   "NAT.0014",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid enterprise_project_id",
			mutate:     func(in *createGatewayInput) { in.EnterpriseProjectID = "not-a-uuid" },
			wantCode:   "VPC.0011",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "negative tcp session timeout",
			mutate: func(in *createGatewayInput) {
				in.SessionConf = &sessionConfInput{TCPSessionExpireTime: gwPtr(-1)}
			},
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "negative udp session timeout",
			mutate: func(in *createGatewayInput) {
				in.SessionConf = &sessionConfInput{UDPSessionExpireTime: gwPtr(-5)}
			},
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "negative icmp session timeout",
			mutate: func(in *createGatewayInput) {
				in.SessionConf = &sessionConfInput{ICMPSessionExpireTime: gwPtr(-1)}
			},
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "negative tcp time_wait timeout",
			mutate: func(in *createGatewayInput) {
				in.SessionConf = &sessionConfInput{TCPTimeWaitTime: gwPtr(-1)}
			},
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "tag empty string",
			mutate:     func(in *createGatewayInput) { in.Tags = []string{""} },
			wantCode:   "NAT.1015",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "tag empty key",
			mutate:     func(in *createGatewayInput) { in.Tags = []string{"*val"} },
			wantCode:   "NAT.1015",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "tag key > 128 runes",
			mutate:     func(in *createGatewayInput) { in.Tags = []string{strings.Repeat("k", 129) + "*v"} },
			wantCode:   "NAT.1015",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "tag value > 255 runes",
			mutate:     func(in *createGatewayInput) { in.Tags = []string{"k*" + strings.Repeat("v", 256)} },
			wantCode:   "NAT.1015",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "more than max tags",
			mutate:     func(in *createGatewayInput) { in.Tags = tooManyTags },
			wantCode:   "NAT.1016",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown router_id uuid",
			mutate:     func(in *createGatewayInput) { in.RouterID = gwUnknownUUID },
			wantCode:   "NAT.0004",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "invalid router_id non-uuid",
			mutate:     func(in *createGatewayInput) { in.RouterID = "not-a-uuid" },
			wantCode:   "NAT.0004",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "unknown internal_network_id",
			mutate:     func(in *createGatewayInput) { in.InternalNetworkID = gwUnknownUUID },
			wantCode:   "NAT.0005",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "subnet belongs to another VPC",
			mutate:     func(in *createGatewayInput) { in.InternalNetworkID = e.subnet2 },
			wantCode:   "NAT.0008",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "ngport_ip_address malformed",
			mutate:     func(in *createGatewayInput) { in.NgportIPAddress = "not-an-ip" },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "ngport_ip_address gateway ip unusable",
			mutate:     func(in *createGatewayInput) { in.NgportIPAddress = "192.168.0.1" },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "ngport_ip_address outside subnet",
			mutate:     func(in *createGatewayInput) { in.NgportIPAddress = "10.0.0.5" },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "ngport_ip_address already in use",
			mutate:     func(in *createGatewayInput) { in.NgportIPAddress = "192.168.0.10" },
			wantCode:   "NAT.0002",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "subnet full",
			mutate: func(in *createGatewayInput) {
				in.RouterID = fullVPC
				in.InternalNetworkID = fullSub
			},
			wantCode:   "NAT.1404",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.mutate(&in)
			_, err := e.svc.createGateway(ctx, gwTestTenant, in)
			if gwCodeOf(err) != tc.wantCode || gwStatusOf(err) != tc.wantStatus {
				t.Fatalf("createGateway err = (%d, %q, %v), want (%d, %q)",
					gwStatusOf(err), gwCodeOf(err), err, tc.wantStatus, tc.wantCode)
			}
		})
	}
}

func TestGatewayCreateOptionalFieldsAndTags(t *testing.T) {
	t.Parallel()
	e := newGWEnvWithDelay(t, 0)
	ctx := t.Context()

	g, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:                "gw-opts_5",
		RouterID:            e.vpcID,
		InternalNetworkID:   e.subnetID,
		NgportIPAddress:     "192.168.0.42",
		Description:         "with options",
		Spec:                "5",
		EnterpriseProjectID: gwCustomEP,
		SessionConf: &sessionConfInput{
			TCPSessionExpireTime: gwPtr(1800),
			TCPTimeWaitTime:      gwPtr(0),
		},
		Tags: []string{"env*prod", "expr*a*b", "empty*", "env*staging"},
	})
	if err != nil {
		t.Fatalf("createGateway: %v", err)
	}
	if g.NgportIP != "192.168.0.42" {
		t.Fatalf("ngport_ip = %q, want 192.168.0.42", g.NgportIP)
	}
	if g.EnterpriseProjectID != gwCustomEP {
		t.Fatalf("ep = %q, want %q", g.EnterpriseProjectID, gwCustomEP)
	}
	wantSess := sessionConf{
		TCPSessionExpireTime:  1800,
		UDPSessionExpireTime:  300,
		ICMPSessionExpireTime: 10,
		TCPTimeWaitTime:       0,
	}
	if g.Session != wantSess {
		t.Fatalf("session = %+v, want %+v", g.Session, wantSess)
	}
	wantTags := []tag{
		{Key: "env", Value: "staging"},
		{Key: "expr", Value: "a*b"},
		{Key: "empty", Value: ""},
	}
	if len(g.Tags) != len(wantTags) {
		t.Fatalf("tags = %+v, want %+v", g.Tags, wantTags)
	}
	for i := range wantTags {
		if g.Tags[i] != wantTags[i] {
			t.Fatalf("tag[%d] = %+v, want %+v", i, g.Tags[i], wantTags[i])
		}
	}
}

func TestGatewayUpdateRules(t *testing.T) {
	t.Parallel()
	e := newGWEnv(t)
	ctx := t.Context()

	g, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:              "gw-upd",
		RouterID:          e.vpcID,
		InternalNetworkID: e.subnetID,
		Description:       "initial",
		Spec:              "1",
	})
	if err != nil {
		t.Fatalf("createGateway: %v", err)
	}

	// Still PENDING_CREATE -> NAT.0103.
	if _, err := e.svc.updateGateway(ctx, gwTestTenant, g.ID, updateGatewayInput{Name: gwPtr("new")}); gwCodeOf(err) != "NAT.0103" {
		t.Fatalf("update pending err = %v, want NAT.0103", err)
	}

	e.settle(t)

	// Partial update preserves untouched fields.
	got, err := e.svc.updateGateway(ctx, gwTestTenant, g.ID, updateGatewayInput{
		Name: gwPtr("gw-upd-2"),
		SessionConf: &sessionConfInput{
			UDPSessionExpireTime: gwPtr(600),
		},
	})
	if err != nil {
		t.Fatalf("updateGateway partial: %v", err)
	}
	if got.Name != "gw-upd-2" || got.Description != "initial" || got.Spec != "1" {
		t.Fatalf("partial update fields = %+v", got)
	}
	if got.Session.TCPSessionExpireTime != 900 || got.Session.UDPSessionExpireTime != 600 ||
		got.Session.ICMPSessionExpireTime != 10 || got.Session.TCPTimeWaitTime != 5 {
		t.Fatalf("partial session = %+v", got.Session)
	}

	// Clearing description to "" is allowed.
	got, err = e.svc.updateGateway(ctx, gwTestTenant, g.ID, updateGatewayInput{
		Description: gwPtr(""),
		Spec:        gwPtr("4"),
	})
	if err != nil {
		t.Fatalf("updateGateway clear desc: %v", err)
	}
	if got.Description != "" || got.Spec != "4" {
		t.Fatalf("after clear desc = %+v", got)
	}

	// Validation & error cases.
	tests := []struct {
		name     string
		id       string
		in       updateGatewayInput
		wantCode string
	}{
		{"not found", gwUnknownUUID, updateGatewayInput{Name: gwPtr("ok")}, "NAT.0105"},
		{"prepaid", g.ID, updateGatewayInput{PrepaidOptions: true}, apierr.CodeNotImplemented},
		{"bad name", g.ID, updateGatewayInput{Name: gwPtr("bad name")}, "NAT.0002"},
		{"empty name", g.ID, updateGatewayInput{Name: gwPtr("")}, "NAT.0002"},
		{"bad desc", g.ID, updateGatewayInput{Description: gwPtr("<bad>")}, "NAT.0014"},
		{"bad spec", g.ID, updateGatewayInput{Spec: gwPtr("9")}, "NAT.0016"},
		{"neg session", g.ID, updateGatewayInput{SessionConf: &sessionConfInput{ICMPSessionExpireTime: gwPtr(-1)}}, "NAT.0002"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.svc.updateGateway(ctx, gwTestTenant, tc.id, tc.in); gwCodeOf(err) != tc.wantCode {
				t.Fatalf("updateGateway err = %v, want %s", err, tc.wantCode)
			}
		})
	}

	// DNAT rule count exceeding spec limit -> NAT.0309.
	for i := range publicDnatRulesLimit + 1 {
		id := fmt.Sprintf("22222222-2222-4222-8222-%012d", i)
		if err := e.svc.dnatRules(gwTestTenant).Create(ctx, id, dnatRule{ID: id, GatewayID: g.ID}); err != nil {
			t.Fatalf("seed dnat %d: %v", i, err)
		}
	}
	if _, err := e.svc.updateGateway(ctx, gwTestTenant, g.ID, updateGatewayInput{Spec: gwPtr("2")}); gwCodeOf(err) != "NAT.0309" {
		t.Fatalf("update over dnat limit err = %v, want NAT.0309", err)
	}
}

func TestGatewayDeleteRules(t *testing.T) {
	t.Parallel()
	e := newGWEnv(t)
	ctx := t.Context()

	// Not found -> NAT.0105.
	if err := e.svc.deleteGateway(ctx, gwTestTenant, gwUnknownUUID); gwCodeOf(err) != "NAT.0105" {
		t.Fatalf("delete unknown err = %v, want NAT.0105", err)
	}

	g, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:              "gw-del",
		RouterID:          e.vpcID,
		InternalNetworkID: e.subnetID,
		Spec:              "1",
	})
	if err != nil {
		t.Fatalf("createGateway: %v", err)
	}

	// PENDING_CREATE -> NAT.0103.
	if err := e.svc.deleteGateway(ctx, gwTestTenant, g.ID); gwCodeOf(err) != "NAT.0103" {
		t.Fatalf("delete pending err = %v, want NAT.0103", err)
	}

	e.settle(t)

	// SNAT rule present -> NAT.0006.
	snatID := "33333333-3333-4333-8333-333333333333"
	if err := e.svc.snatRules(gwTestTenant).Create(ctx, snatID, snatRule{ID: snatID, GatewayID: g.ID}); err != nil {
		t.Fatalf("seed snat: %v", err)
	}
	if err := e.svc.deleteGateway(ctx, gwTestTenant, g.ID); gwCodeOf(err) != "NAT.0006" {
		t.Fatalf("delete with snat err = %v, want NAT.0006", err)
	}
	if err := e.svc.snatRules(gwTestTenant).Delete(ctx, snatID); err != nil {
		t.Fatalf("delete snat: %v", err)
	}

	// DNAT rule present -> NAT.0006.
	dnatID := "44444444-4444-4444-8444-444444444444"
	if err := e.svc.dnatRules(gwTestTenant).Create(ctx, dnatID, dnatRule{ID: dnatID, GatewayID: g.ID}); err != nil {
		t.Fatalf("seed dnat: %v", err)
	}
	if err := e.svc.deleteGateway(ctx, gwTestTenant, g.ID); gwCodeOf(err) != "NAT.0006" {
		t.Fatalf("delete with dnat err = %v, want NAT.0006", err)
	}
	if err := e.svc.dnatRules(gwTestTenant).Delete(ctx, dnatID); err != nil {
		t.Fatalf("delete dnat: %v", err)
	}

	// Now delete succeeds and releases its IP.
	if err := e.svc.deleteGateway(ctx, gwTestTenant, g.ID); err != nil {
		t.Fatalf("deleteGateway: %v", err)
	}
	if _, err := e.svc.getGateway(ctx, gwTestTenant, g.ID); gwCodeOf(err) != "NAT.0105" {
		t.Fatalf("get after delete err = %v, want NAT.0105", err)
	}
	sn, err := e.vpcSvc.GetSubnet(ctx, gwTestTenant, e.subnetID)
	if err != nil {
		t.Fatalf("GetSubnet: %v", err)
	}
	if sn.AvailableIPAddressCount != 251 {
		t.Fatalf("available IPs after delete = %d, want 251", sn.AvailableIPAddressCount)
	}
}

func TestGatewayListFiltersAndPagination(t *testing.T) {
	t.Parallel()
	e := newGWEnv(t)
	ctx := t.Context()

	// Create 3 gateways with distinct attributes and timestamps.
	t1 := gwTestEpoch
	t2 := gwTestEpoch.Add(time.Minute)
	t3 := gwTestEpoch.Add(2 * time.Minute)

	e.svc.now = func() time.Time { return t1 }
	g1, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:                "gw-alpha",
		Description:         "desc-alpha",
		RouterID:            e.vpcID,
		InternalNetworkID:   e.subnetID,
		Spec:                "1",
		EnterpriseProjectID: defaultEnterpriseProjectID,
	})
	if err != nil {
		t.Fatalf("create g1: %v", err)
	}
	e.settle(t) // g1 becomes ACTIVE

	e.svc.now = func() time.Time { return t2 }
	g2, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:                "gw-beta",
		Description:         "desc-beta",
		RouterID:            e.vpc2ID,
		InternalNetworkID:   e.subnet2,
		Spec:                "2",
		EnterpriseProjectID: gwCustomEP,
	})
	if err != nil {
		t.Fatalf("create g2: %v", err)
	}
	e.settle(t) // g2 becomes ACTIVE

	// g3 stays PENDING_CREATE.
	e.svc.now = func() time.Time { return t3 }
	g3, err := e.svc.createGateway(ctx, gwTestTenant, createGatewayInput{
		Name:                "gw-gamma",
		Description:         "desc-gamma",
		RouterID:            e.vpcID,
		InternalNetworkID:   e.subnetID,
		Spec:                "3",
		EnterpriseProjectID: gwCustomEP,
	})
	if err != nil {
		t.Fatalf("create g3: %v", err)
	}

	// Another project must be isolated.
	vpcB, subB := e.seedVPCSubnet(t, gwTestTenantB, "vpc-b", "192.168.0.0/16", "sub-b", "192.168.0.0/24", "192.168.0.1")
	if _, err := e.svc.createGateway(ctx, gwTestTenantB, createGatewayInput{
		Name:              "gw-other-project",
		RouterID:          vpcB,
		InternalNetworkID: subB,
		Spec:              "1",
	}); err != nil {
		t.Fatalf("create project B gw: %v", err)
	}

	allPage := pagination.Marker{Limit: listLimits.Default}

	// Ascending ID order.
	all, err := e.svc.listGateways(ctx, gwTestTenant, listGatewaysFilter{Page: allPage})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3", len(all))
	}
	if all[0].ID >= all[1].ID || all[1].ID >= all[2].ID {
		t.Fatalf("IDs not sorted ascending: %s, %s, %s", all[0].ID, all[1].ID, all[2].ID)
	}

	// Pagination with limit & marker.
	p1, err := e.svc.listGateways(ctx, gwTestTenant, listGatewaysFilter{Page: pagination.Marker{Limit: 2}})
	if err != nil || len(p1) != 2 || p1[0].ID != all[0].ID || p1[1].ID != all[1].ID {
		t.Fatalf("page 1 = %+v, %v", p1, err)
	}
	p2, err := e.svc.listGateways(ctx, gwTestTenant, listGatewaysFilter{Page: pagination.Marker{ID: p1[1].ID, Limit: 2}})
	if err != nil || len(p2) != 1 || p2[0].ID != all[2].ID {
		t.Fatalf("page 2 = %+v, %v", p2, err)
	}
	if _, err := e.svc.listGateways(ctx, gwTestTenant, listGatewaysFilter{Page: pagination.Marker{ID: gwUnknownUUID, Limit: 10}}); gwCodeOf(err) != "NAT.0002" {
		t.Fatalf("unknown marker err = %v, want NAT.0002", err)
	}

	// Table of filters.
	tests := []struct {
		name    string
		filter  listGatewaysFilter
		wantIDs []string
	}{
		{"tenant_id matches", listGatewaysFilter{TenantID: gwTestProject, Page: allPage}, []string{g1.ID, g2.ID, g3.ID}},
		{"tenant_id mismatch", listGatewaysFilter{TenantID: gwTestProjectB, Page: allPage}, nil},
		{"id", listGatewaysFilter{ID: g2.ID, Page: allPage}, []string{g2.ID}},
		{"ep 0", listGatewaysFilter{EnterpriseProjectID: "0", Page: allPage}, []string{g1.ID}},
		{"ep custom", listGatewaysFilter{EnterpriseProjectID: gwCustomEP, Page: allPage}, []string{g2.ID, g3.ID}},
		{"ep all_granted_eps", listGatewaysFilter{EnterpriseProjectID: allGrantedEPs, Page: allPage}, []string{g1.ID, g2.ID, g3.ID}},
		{"description", listGatewaysFilter{Description: "desc-beta", Page: allPage}, []string{g2.ID}},
		{"created_at public format", listGatewaysFilter{CreatedAt: t1.UTC().Format(publicTimeFormat), Page: allPage}, []string{g1.ID}},
		{"created_at sdk ISO format", listGatewaysFilter{CreatedAt: t2.UTC().Format("2006-01-02T15:04:05Z"), Page: allPage}, []string{g2.ID}},
		{"name", listGatewaysFilter{Name: "gw-gamma", Page: allPage}, []string{g3.ID}},
		{"status single", listGatewaysFilter{Statuses: []string{StatusPendingCreate}, Page: allPage}, []string{g3.ID}},
		{"status multi", listGatewaysFilter{Statuses: []string{StatusActive, StatusPendingCreate}, Page: allPage}, []string{g1.ID, g2.ID, g3.ID}},
		{"spec single", listGatewaysFilter{Specs: []string{"2"}, Page: allPage}, []string{g2.ID}},
		{"spec multi", listGatewaysFilter{Specs: []string{"1", "3"}, Page: allPage}, []string{g1.ID, g3.ID}},
		{"admin_state_up true", listGatewaysFilter{AdminStateUp: gwPtr(true), Page: allPage}, []string{g1.ID, g2.ID, g3.ID}},
		{"admin_state_up false", listGatewaysFilter{AdminStateUp: gwPtr(false), Page: allPage}, nil},
		{"router_id", listGatewaysFilter{RouterID: e.vpc2ID, Page: allPage}, []string{g2.ID}},
		{"internal_network_id", listGatewaysFilter{InternalNetworkID: e.subnetID, Page: allPage}, []string{g1.ID, g3.ID}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.svc.listGateways(ctx, gwTestTenant, tc.filter)
			if err != nil {
				t.Fatalf("listGateways: %v", err)
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
					t.Fatalf("missing expected gateway %s in %+v", id, got)
				}
			}
		})
	}
}
