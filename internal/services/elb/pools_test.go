package elb

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
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/faults"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	poolTestProject     = "0123456789abcdef0123456789abcdef"
	poolTestRegion      = "ap-southeast-1"
	poolTestHost        = "elb." + poolTestRegion + ".myhuaweicloud.com"
	poolTestUnknownUUID = "00000000-0000-4000-8000-000000000000"
	poolTestCustomEP    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

var (
	poolTestTenant = Tenant{Region: poolTestRegion, ProjectID: poolTestProject}
	poolTestEpoch  = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
)

type poolNoopEIPs struct{}

func (poolNoopEIPs) BindToELB(context.Context, vpc.Tenant, string, string, string, string) (string, error) {
	return "", errors.New("unexpected BindToELB")
}

func (poolNoopEIPs) CreateForELB(context.Context, vpc.Tenant, string, string, string, eip.ServerIP) (string, string, error) {
	return "", "", errors.New("unexpected CreateForELB")
}

func (poolNoopEIPs) UnbindFromELB(context.Context, vpc.Tenant, string, string) error {
	return nil
}

func (poolNoopEIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type poolNoopServers struct{}

func (poolNoopServers) ServerAt(context.Context, vpc.Tenant, string, string, string) (string, bool, error) {
	return "", false, nil
}

type poolTestEnv struct {
	svc     *Service
	vpcSvc  *vpc.Service
	store   store.Store
	clock   *lifecycle.FakeClock
	handler http.Handler
	vpcID   string
	vpc2ID  string
	lbID    string
	lb2ID   string
}

func newPoolTestEnv(t *testing.T) *poolTestEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(poolTestEpoch)
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

	gen := ids.NewSeeded(42)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	vkey := make([]byte, vault.KeyLen)
	vlt, err := vault.New(vkey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	svc, err := New(Deps{
		Store:   st,
		IDs:     gen,
		Logger:  log,
		Vault:   vlt,
		VPC:     vpcSvc,
		EIPs:    poolNoopEIPs{},
		Servers: poolNoopServers{},
		Now:     clock.Now,
	})
	if err != nil {
		t.Fatalf("elb.New: %v", err)
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: poolTestProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	vpcName1, cidr1 := "vpc-1", "10.0.0.0/16"
	v1, err := vpcSvc.CreateVPC(ctx, poolTestTenant, vpc.CreateVPCOption{Name: &vpcName1, CIDR: &cidr1})
	if err != nil {
		t.Fatalf("CreateVPC 1: %v", err)
	}
	vpcName2, cidr2 := "vpc-2", "10.1.0.0/16"
	v2, err := vpcSvc.CreateVPC(ctx, poolTestTenant, vpc.CreateVPCOption{Name: &vpcName2, CIDR: &cidr2})
	if err != nil {
		t.Fatalf("CreateVPC 2: %v", err)
	}
	if err := engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	e := &poolTestEnv{
		svc:     svc,
		vpcSvc:  vpcSvc,
		store:   st,
		clock:   clock,
		handler: srv.Handler(),
		vpcID:   v1.ID,
		vpc2ID:  v2.ID,
	}
	e.lbID = e.seedLB(t, "lb-1", v1.ID)
	e.lb2ID = e.seedLB(t, "lb-2", v2.ID)
	return e
}

func (e *poolTestEnv) seedLB(t *testing.T, name, vpcID string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	lb := loadBalancer{
		ID:                  id,
		Name:                name,
		AdminStateUp:        true,
		Provider:            "vlb",
		VPCID:               vpcID,
		EnterpriseProjectID: defaultEnterpriseProjectID,
		CreatedAt:           e.svc.nowUTC(),
		UpdatedAt:           e.svc.nowUTC(),
	}
	if err := e.svc.loadBalancers(poolTestTenant).Create(t.Context(), id, lb); err != nil {
		t.Fatalf("seedLB: %v", err)
	}
	return id
}

func (e *poolTestEnv) seedListener(t *testing.T, lbID, proto string, port int) string {
	t.Helper()
	id := e.svc.ids.UUID()
	l := listener{
		ID:                  id,
		LoadBalancerID:      lbID,
		Name:                "lsn-" + proto,
		Protocol:            proto,
		ProtocolPort:        port,
		AdminStateUp:        true,
		EnterpriseProjectID: defaultEnterpriseProjectID,
		CreatedAt:           e.svc.nowUTC(),
		UpdatedAt:           e.svc.nowUTC(),
	}
	if err := e.svc.listeners(poolTestTenant).Create(t.Context(), id, l); err != nil {
		t.Fatalf("seedListener: %v", err)
	}
	return id
}

func (e *poolTestEnv) seedMember(t *testing.T, poolID, addr string, port int) string {
	t.Helper()
	id := e.svc.ids.UUID()
	m := member{
		ID:           id,
		PoolID:       poolID,
		Name:         "mem-" + addr,
		Address:      addr,
		ProtocolPort: port,
		MemberType:   "ip",
		Weight:       1,
		AdminStateUp: true,
		CreatedAt:    e.svc.nowUTC(),
		UpdatedAt:    e.svc.nowUTC(),
	}
	if err := e.svc.members(poolTestTenant).Create(t.Context(), id, m); err != nil {
		t.Fatalf("seedMember: %v", err)
	}
	return id
}

func (e *poolTestEnv) seedL7Policy(t *testing.T, lsnID, redirectPoolID string, extraPools []redirectPoolsConfig) string {
	t.Helper()
	id := e.svc.ids.UUID()
	pol := l7Policy{
		ID:                  id,
		ListenerID:          lsnID,
		Name:                "pol-1",
		Action:              "REDIRECT_TO_POOL",
		AdminStateUp:        true,
		RedirectPoolID:      redirectPoolID,
		RedirectPoolsConfig: extraPools,
		EnterpriseProjectID: defaultEnterpriseProjectID,
		CreatedAt:           e.svc.nowUTC(),
		UpdatedAt:           e.svc.nowUTC(),
	}
	if err := e.svc.l7Policies(poolTestTenant).Create(t.Context(), id, pol); err != nil {
		t.Fatalf("seedL7Policy: %v", err)
	}
	return id
}

func (e *poolTestEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	full := "/v3/" + poolTestProject + "/elb" + path
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, full, rdr)
	req.Host = poolTestHost
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *poolTestEnv) expect(t *testing.T, dir, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", dir, goldenName+".json"), status, out)
	return out
}

func poolDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %T: %v\nbody: %s", out, err, raw)
	}
	return out
}

func poolAssertAPIError(t *testing.T, err error, wantStatus int, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got nil error, want %d %s", wantStatus, wantCode)
	}
	var apiErr *apierr.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("got non-apierr %T: %v", err, err)
	}
	if apiErr.Status != wantStatus || apiErr.Code != wantCode {
		t.Fatalf("got %d %s (%s), want %d %s", apiErr.Status, apiErr.Code, apiErr.Message, wantStatus, wantCode)
	}
}

func poolStrPtr(s string) *string { return &s }
func poolBoolPtr(b bool) *bool    { return &b }

func TestPoolListenerProtocolPairing(t *testing.T) {
	t.Parallel()
	listenerProtos := []string{"UDP", "TCP", "HTTP", "HTTPS", "TLS", "QUIC"}
	poolProtos := []string{"TCP", "UDP", "HTTP", "HTTPS", "QUIC", "GRPC", "TLS"}

	allowed := map[string]map[string]bool{
		"UDP":   {"UDP": true, "QUIC": true},
		"TCP":   {"TCP": true},
		"HTTP":  {"HTTP": true},
		"HTTPS": {"HTTP": true, "HTTPS": true, "GRPC": true},
		"TLS":   {"TCP": true, "TLS": true},
		"QUIC":  {"UDP": true, "QUIC": true},
	}

	e := newPoolTestEnv(t)
	port := 8000
	for _, lp := range listenerProtos {
		for _, pp := range poolProtos {
			wantOK := allowed[lp][pp]
			t.Run(lp+"_to_"+pp, func(t *testing.T) {
				port++
				lsnID := e.seedListener(t, e.lbID, lp, port)
				d, err := e.svc.createPool(t.Context(), poolTestTenant, createPoolInput{
					Name:        "p-" + lp + "-" + pp,
					Protocol:    pp,
					LBAlgorithm: "ROUND_ROBIN",
					ListenerID:  lsnID,
				})
				if wantOK {
					if err != nil {
						t.Fatalf("expected %s->%s allowed, got error: %v", lp, pp, err)
					}
					if len(d.ListenerIDs) != 1 || d.ListenerIDs[0] != lsnID {
						t.Fatalf("listeners = %v, want [%s]", d.ListenerIDs, lsnID)
					}
					if d.Pool.LoadBalancerID != e.lbID {
						t.Fatalf("loadbalancer_id = %q, want %q", d.Pool.LoadBalancerID, e.lbID)
					}
					lsn, err := e.svc.listeners(poolTestTenant).Get(t.Context(), lsnID)
					if err != nil {
						t.Fatalf("get listener: %v", err)
					}
					if lsn.DefaultPoolID != d.Pool.ID {
						t.Fatalf("listener.DefaultPoolID = %q, want %q", lsn.DefaultPoolID, d.Pool.ID)
					}
				} else {
					poolAssertAPIError(t, err, http.StatusBadRequest, "ELB.8902")
				}
			})
		}
	}
}

func TestPoolPlacementAndAlgorithms(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)
	ctx := t.Context()

	lsn1 := e.seedListener(t, e.lbID, "HTTP", 80)
	lsnBusy := e.seedListener(t, e.lbID, "TCP", 81)

	// Bind lsnBusy first.
	if _, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
		Protocol:    "TCP",
		LBAlgorithm: "ROUND_ROBIN",
		ListenerID:  lsnBusy,
	}); err != nil {
		t.Fatalf("bind lsnBusy: %v", err)
	}

	tests := []struct {
		name       string
		in         createPoolInput
		wantStatus int
		wantCode   string
	}{
		{
			name: "listener with matching loadbalancer",
			in: createPoolInput{
				Protocol:       "HTTP",
				LBAlgorithm:    "ROUND_ROBIN",
				ListenerID:     lsn1,
				LoadBalancerID: e.lbID,
			},
		},
		{
			name: "listener already has default pool",
			in: createPoolInput{
				Protocol:    "TCP",
				LBAlgorithm: "ROUND_ROBIN",
				ListenerID:  lsnBusy,
			},
			wantStatus: http.StatusConflict,
			wantCode:   "ELB.8907",
		},
		{
			name: "listener and mismatched loadbalancer",
			in: createPoolInput{
				Protocol:       "HTTP",
				LBAlgorithm:    "ROUND_ROBIN",
				ListenerID:     e.seedListener(t, e.lbID, "HTTP", 82),
				LoadBalancerID: e.lb2ID,
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name: "loadbalancer only",
			in: createPoolInput{
				Protocol:       "HTTPS",
				LBAlgorithm:    "LEAST_CONNECTIONS",
				LoadBalancerID: e.lbID,
			},
		},
		{
			name: "type ip with vpc_id (unbound)",
			in: createPoolInput{
				Protocol:    "TCP",
				LBAlgorithm: "SOURCE_IP",
				Type:        "ip",
				VPCID:       e.vpcID,
			},
		},
		{
			name: "type ip without vpc_id (unbound)",
			in: createPoolInput{
				Protocol:    "TCP",
				LBAlgorithm: "SOURCE_IP",
				Type:        "ip",
			},
		},
		{
			name: "type instance with vpc_id (unbound)",
			in: createPoolInput{
				Protocol:    "TCP",
				LBAlgorithm: "ROUND_ROBIN",
				Type:        "instance",
				VPCID:       e.vpcID,
			},
		},
		{
			name: "type instance without vpc_id",
			in: createPoolInput{
				Protocol:    "TCP",
				LBAlgorithm: "ROUND_ROBIN",
				Type:        "instance",
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name: "no placement fields at all",
			in: createPoolInput{
				Protocol:    "TCP",
				LBAlgorithm: "ROUND_ROBIN",
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name: "unknown listener",
			in: createPoolInput{
				Protocol:    "TCP",
				LBAlgorithm: "ROUND_ROBIN",
				ListenerID:  poolTestUnknownUUID,
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "ELB.8904",
		},
		{
			name: "unknown loadbalancer",
			in: createPoolInput{
				Protocol:       "TCP",
				LBAlgorithm:    "ROUND_ROBIN",
				LoadBalancerID: poolTestUnknownUUID,
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "ELB.8904",
		},
		{
			name: "unknown vpc",
			in: createPoolInput{
				Protocol:    "TCP",
				LBAlgorithm: "ROUND_ROBIN",
				Type:        "ip",
				VPCID:       poolTestUnknownUUID,
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "ELB.8904",
		},
		{
			name: "vpc does not match loadbalancer vpc",
			in: createPoolInput{
				Protocol:       "TCP",
				LBAlgorithm:    "ROUND_ROBIN",
				LoadBalancerID: e.lbID,
				VPCID:          e.vpc2ID,
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name: "QUIC_CID on QUIC pool allowed",
			in: createPoolInput{
				Protocol:       "QUIC",
				LBAlgorithm:    "QUIC_CID",
				LoadBalancerID: e.lbID,
			},
		},
		{
			name: "QUIC_CID on TCP pool rejected",
			in: createPoolInput{
				Protocol:       "TCP",
				LBAlgorithm:    "QUIC_CID",
				LoadBalancerID: e.lbID,
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name: "unknown lb_algorithm rejected",
			in: createPoolInput{
				Protocol:       "TCP",
				LBAlgorithm:    "RANDOM",
				LoadBalancerID: e.lbID,
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name: "invalid protocol IP rejected",
			in: createPoolInput{
				Protocol:       "IP",
				LBAlgorithm:    "ROUND_ROBIN",
				LoadBalancerID: e.lbID,
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name: "invalid pool type rejected",
			in: createPoolInput{
				Protocol:       "TCP",
				LBAlgorithm:    "ROUND_ROBIN",
				LoadBalancerID: e.lbID,
				Type:           "container",
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
		{
			name: "ip_version v6 returns WeiStack.0501",
			in: createPoolInput{
				Protocol:       "TCP",
				LBAlgorithm:    "ROUND_ROBIN",
				LoadBalancerID: e.lbID,
				IPVersion:      "v6",
			},
			wantStatus: http.StatusNotImplemented,
			wantCode:   "WeiStack.0501",
		},
		{
			name: "ip_version dualstack accepted",
			in: createPoolInput{
				Protocol:       "TCP",
				LBAlgorithm:    "ROUND_ROBIN",
				LoadBalancerID: e.lbID,
				IPVersion:      "dualstack",
			},
		},
		{
			name: "ip_version bogus rejected",
			in: createPoolInput{
				Protocol:       "TCP",
				LBAlgorithm:    "ROUND_ROBIN",
				LoadBalancerID: e.lbID,
				IPVersion:      "v9",
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "ELB.8902",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.svc.createPool(ctx, poolTestTenant, tc.in)
			if tc.wantCode != "" {
				poolAssertAPIError(t, err, tc.wantStatus, tc.wantCode)
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPoolSessionPersistenceValidation(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)
	ctx := t.Context()

	tooLongCookie := strings.Repeat("a", 1025)

	tests := []struct {
		name        string
		proto       string
		sp          *sessionPersistence
		wantErr     bool
		wantTimeout *int
	}{
		{
			name:        "TCP SOURCE_IP default timeout 1",
			proto:       "TCP",
			sp:          &sessionPersistence{Type: "SOURCE_IP"},
			wantTimeout: intPtr(1),
		},
		{
			name:        "TCP SOURCE_IP max timeout 60",
			proto:       "TCP",
			sp:          &sessionPersistence{Type: "SOURCE_IP", PersistenceTimeout: intPtr(60)},
			wantTimeout: intPtr(60),
		},
		{
			name:    "TCP SOURCE_IP timeout 61 rejected",
			proto:   "TCP",
			sp:      &sessionPersistence{Type: "SOURCE_IP", PersistenceTimeout: intPtr(61)},
			wantErr: true,
		},
		{
			name:    "UDP SOURCE_IP timeout 0 rejected",
			proto:   "UDP",
			sp:      &sessionPersistence{Type: "SOURCE_IP", PersistenceTimeout: intPtr(0)},
			wantErr: true,
		},
		{
			name:        "HTTP HTTP_COOKIE default timeout 1440",
			proto:       "HTTP",
			sp:          &sessionPersistence{Type: "HTTP_COOKIE"},
			wantTimeout: intPtr(1440),
		},
		{
			name:        "HTTPS HTTP_COOKIE timeout 1440",
			proto:       "HTTPS",
			sp:          &sessionPersistence{Type: "HTTP_COOKIE", PersistenceTimeout: intPtr(1440)},
			wantTimeout: intPtr(1440),
		},
		{
			name:    "HTTP HTTP_COOKIE timeout 1441 rejected",
			proto:   "HTTP",
			sp:      &sessionPersistence{Type: "HTTP_COOKIE", PersistenceTimeout: intPtr(1441)},
			wantErr: true,
		},
		{
			name:    "SOURCE_IP with cookie_name rejected",
			proto:   "TCP",
			sp:      &sessionPersistence{Type: "SOURCE_IP", CookieName: poolStrPtr("SID")},
			wantErr: true,
		},
		{
			name:    "HTTP_COOKIE with cookie_name rejected",
			proto:   "HTTP",
			sp:      &sessionPersistence{Type: "HTTP_COOKIE", CookieName: poolStrPtr("SID")},
			wantErr: true,
		},
		{
			name:  "APP_COOKIE with cookie_name ok",
			proto: "HTTP",
			sp:    &sessionPersistence{Type: "APP_COOKIE", CookieName: poolStrPtr("JSESSIONID")},
		},
		{
			name:    "APP_COOKIE missing cookie_name rejected",
			proto:   "HTTP",
			sp:      &sessionPersistence{Type: "APP_COOKIE"},
			wantErr: true,
		},
		{
			name:    "APP_COOKIE empty cookie_name rejected",
			proto:   "HTTP",
			sp:      &sessionPersistence{Type: "APP_COOKIE", CookieName: poolStrPtr("")},
			wantErr: true,
		},
		{
			name:    "APP_COOKIE cookie_name too long rejected",
			proto:   "HTTP",
			sp:      &sessionPersistence{Type: "APP_COOKIE", CookieName: &tooLongCookie},
			wantErr: true,
		},
		{
			name:    "unknown type rejected",
			proto:   "HTTP",
			sp:      &sessionPersistence{Type: "MAGIC_COOKIE"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
				Protocol:           tc.proto,
				LBAlgorithm:        "ROUND_ROBIN",
				LoadBalancerID:     e.lbID,
				SessionPersistence: tc.sp,
			})
			if tc.wantErr {
				poolAssertAPIError(t, err, http.StatusBadRequest, "ELB.8902")
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantTimeout != nil {
				if d.Pool.SessionPersistence == nil || d.Pool.SessionPersistence.PersistenceTimeout == nil {
					t.Fatalf("expected persistence_timeout %d, got nil", *tc.wantTimeout)
				}
				if *d.Pool.SessionPersistence.PersistenceTimeout != *tc.wantTimeout {
					t.Fatalf("persistence_timeout = %d, want %d", *d.Pool.SessionPersistence.PersistenceTimeout, *tc.wantTimeout)
				}
			}
		})
	}
}

func TestPoolDeleteRefusedWhileInUseAndCascadeDelete(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)
	ctx := t.Context()

	// Case 1: pool with a member cannot be deleted.
	pMem, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
		Protocol: "HTTP", LBAlgorithm: "ROUND_ROBIN", LoadBalancerID: e.lbID,
	})
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	e.seedMember(t, pMem.Pool.ID, "10.0.0.10", 80)
	poolAssertAPIError(t, e.svc.deletePool(ctx, poolTestTenant, pMem.Pool.ID), http.StatusConflict, "ELB.8907")

	// Case 2: pool with a health monitor cannot be deleted.
	pHM, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
		Protocol: "HTTP", LBAlgorithm: "ROUND_ROBIN", LoadBalancerID: e.lbID,
	})
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	if _, err := e.svc.createHealthMonitor(ctx, poolTestTenant, createHealthMonitorInput{
		PoolID: pHM.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3,
	}); err != nil {
		t.Fatalf("create hm: %v", err)
	}
	poolAssertAPIError(t, e.svc.deletePool(ctx, poolTestTenant, pHM.Pool.ID), http.StatusConflict, "ELB.8907")

	// Case 3: pool bound to a listener cannot be deleted.
	lsnID := e.seedListener(t, e.lbID, "HTTP", 8080)
	pLsn, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
		Protocol: "HTTP", LBAlgorithm: "ROUND_ROBIN", ListenerID: lsnID,
	})
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	poolAssertAPIError(t, e.svc.deletePool(ctx, poolTestTenant, pLsn.Pool.ID), http.StatusConflict, "ELB.8907")

	// Case 4: pool referenced by L7 policy RedirectPoolID or RedirectPoolsConfig cannot be deleted.
	pPol1, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
		Protocol: "HTTP", LBAlgorithm: "ROUND_ROBIN", LoadBalancerID: e.lbID,
	})
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	pPol2, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
		Protocol: "HTTP", LBAlgorithm: "ROUND_ROBIN", LoadBalancerID: e.lbID,
	})
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	polID := e.seedL7Policy(t, lsnID, pPol1.Pool.ID, []redirectPoolsConfig{{PoolID: pPol2.Pool.ID, Weight: 1}})
	poolAssertAPIError(t, e.svc.deletePool(ctx, poolTestTenant, pPol1.Pool.ID), http.StatusConflict, "ELB.8907")
	poolAssertAPIError(t, e.svc.deletePool(ctx, poolTestTenant, pPol2.Pool.ID), http.StatusConflict, "ELB.8907")

	// Cascade delete on a pool that has members, health monitor, listener, and L7 policies.
	lsnCascade := e.seedListener(t, e.lbID, "HTTP", 8081)
	pCas, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
		Name:                           "cascade-pool",
		Protocol:                       "HTTP",
		LBAlgorithm:                    "ROUND_ROBIN",
		ListenerID:                     lsnCascade,
		MemberDeletionProtectionEnable: poolBoolPtr(true),
	})
	if err != nil {
		t.Fatalf("create cascade pool: %v", err)
	}
	mem1 := e.seedMember(t, pCas.Pool.ID, "10.0.0.21", 80)
	mem2 := e.seedMember(t, pCas.Pool.ID, "10.0.0.22", 80)
	hmCas, err := e.svc.createHealthMonitor(ctx, poolTestTenant, createHealthMonitorInput{
		PoolID: pCas.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3,
	})
	if err != nil {
		t.Fatalf("create cascade hm: %v", err)
	}
	polCas := e.seedL7Policy(t, lsnCascade, pCas.Pool.ID, []redirectPoolsConfig{
		{PoolID: pCas.Pool.ID, Weight: 1},
		{PoolID: pPol1.Pool.ID, Weight: 2},
	})

	// Member deletion protection blocks cascade delete while members exist.
	poolAssertAPIError(t, e.svc.deletePoolCascade(ctx, poolTestTenant, pCas.Pool.ID), http.StatusConflict, "ELB.8907")

	// Disable member deletion protection, then cascade delete succeeds.
	if _, err := e.svc.updatePool(ctx, poolTestTenant, pCas.Pool.ID, updatePoolInput{
		MemberDeletionProtectionEnable: poolBoolPtr(false),
	}); err != nil {
		t.Fatalf("disable protection: %v", err)
	}
	if err := e.svc.deletePoolCascade(ctx, poolTestTenant, pCas.Pool.ID); err != nil {
		t.Fatalf("deletePoolCascade: %v", err)
	}

	// Verify pool, members, and health monitor are gone.
	poolAssertAPIError(t, func() error { _, err := e.svc.getPool(ctx, poolTestTenant, pCas.Pool.ID); return err }(), http.StatusNotFound, "ELB.8904")
	poolAssertAPIError(t, func() error { _, err := e.svc.getHealthMonitor(ctx, poolTestTenant, hmCas.ID); return err }(), http.StatusNotFound, "ELB.8904")
	for _, mid := range []string{mem1, mem2} {
		if _, err := e.svc.members(poolTestTenant).Get(ctx, mid); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("member %s still exists after cascade delete (err=%v)", mid, err)
		}
	}

	// Verify listener remains with DefaultPoolID cleared.
	lsnAfter, err := e.svc.listeners(poolTestTenant).Get(ctx, lsnCascade)
	if err != nil {
		t.Fatalf("listener should remain after cascade delete: %v", err)
	}
	if lsnAfter.DefaultPoolID != "" {
		t.Fatalf("listener.DefaultPoolID = %q, want empty", lsnAfter.DefaultPoolID)
	}

	// Verify L7 policy remains with pool unbound and other pools preserved.
	polAfter, err := e.svc.l7Policies(poolTestTenant).Get(ctx, polCas)
	if err != nil {
		t.Fatalf("policy should remain after cascade delete: %v", err)
	}
	if polAfter.RedirectPoolID != "" {
		t.Fatalf("pol.RedirectPoolID = %q, want empty", polAfter.RedirectPoolID)
	}
	if len(polAfter.RedirectPoolsConfig) != 1 || polAfter.RedirectPoolsConfig[0].PoolID != pPol1.Pool.ID {
		t.Fatalf("pol.RedirectPoolsConfig = %+v, want only %s", polAfter.RedirectPoolsConfig, pPol1.Pool.ID)
	}
	_ = polID
}

func TestHealthMonitorValidation(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)
	ctx := t.Context()

	// Pool protocol vs health monitor type matrix.
	poolProtos := []string{"UDP", "QUIC", "TCP", "HTTP", "HTTPS", "GRPC", "TLS"}
	hmTypes := []string{"TCP", "UDP_CONNECT", "HTTP", "HTTPS", "GRPC", "TLS"}
	allowed := map[string]map[string]bool{
		"UDP":   {"UDP_CONNECT": true},
		"QUIC":  {"UDP_CONNECT": true},
		"TCP":   {"TCP": true, "HTTP": true, "HTTPS": true},
		"HTTP":  {"TCP": true, "HTTP": true, "HTTPS": true, "GRPC": true, "TLS": true},
		"HTTPS": {"TCP": true, "HTTP": true, "HTTPS": true, "GRPC": true, "TLS": true},
		"GRPC":  {"TCP": true, "HTTP": true, "HTTPS": true, "GRPC": true, "TLS": true},
		"TLS":   {"TCP": true, "HTTP": true, "HTTPS": true, "GRPC": true, "TLS": true},
	}

	for _, pp := range poolProtos {
		for _, ht := range hmTypes {
			wantOK := allowed[pp][ht]
			t.Run("proto_"+pp+"_hm_"+ht, func(t *testing.T) {
				p, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
					Protocol: pp, LBAlgorithm: "ROUND_ROBIN", LoadBalancerID: e.lbID,
				})
				if err != nil {
					t.Fatalf("create pool: %v", err)
				}
				hm, err := e.svc.createHealthMonitor(ctx, poolTestTenant, createHealthMonitorInput{
					PoolID: p.Pool.ID, Type: ht, Delay: 5, Timeout: 3, MaxRetries: 3,
				})
				if wantOK {
					if err != nil {
						t.Fatalf("expected pool %s + hm %s allowed, got: %v", pp, ht, err)
					}
					if hm.MaxRetriesDown != 3 {
						t.Fatalf("default max_retries_down = %d, want 3", hm.MaxRetriesDown)
					}
					gotPool, err := e.svc.getPool(ctx, poolTestTenant, p.Pool.ID)
					if err != nil {
						t.Fatalf("getPool: %v", err)
					}
					if gotPool.Pool.HealthMonitorID != hm.ID {
						t.Fatalf("pool.HealthMonitorID = %q, want %q", gotPool.Pool.HealthMonitorID, hm.ID)
					}
				} else {
					poolAssertAPIError(t, err, http.StatusBadRequest, "ELB.8902")
				}
			})
		}
	}

	// Field bounds and HTTP-only fields validation.
	httpPool, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
		Protocol: "HTTP", LBAlgorithm: "ROUND_ROBIN", LoadBalancerID: e.lbID,
	})
	if err != nil {
		t.Fatalf("create http pool: %v", err)
	}
	anyPortPool, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
		Protocol: "TCP", LBAlgorithm: "ROUND_ROBIN", LoadBalancerID: e.lbID, AnyPortEnable: poolBoolPtr(true),
	})
	if err != nil {
		t.Fatalf("create any-port pool: %v", err)
	}

	fieldTests := []struct {
		name       string
		in         createHealthMonitorInput
		wantStatus int
		wantCode   string
	}{
		{
			name:       "missing pool_id",
			in:         createHealthMonitorInput{Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "unknown pool_id",
			in:         createHealthMonitorInput{PoolID: poolTestUnknownUUID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3},
			wantStatus: http.StatusNotFound, wantCode: "ELB.8904",
		},
		{
			name:       "unknown type",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "ICMP", Delay: 5, Timeout: 3, MaxRetries: 3},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "delay 0",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 0, Timeout: 3, MaxRetries: 3},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "delay 51",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 51, Timeout: 3, MaxRetries: 3},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "timeout 0",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 0, MaxRetries: 3},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "max_retries 0",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 0},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "max_retries 11",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 11},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "max_retries_down 0",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3, MaxRetriesDown: intPtr(0)},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "max_retries_down 11",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3, MaxRetriesDown: intPtr(11)},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "monitor_port 0",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3, MonitorPort: intPtr(0)},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "monitor_port 65536",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3, MonitorPort: intPtr(65536)},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "any_port_enable pool requires monitor_port",
			in:         createHealthMonitorInput{PoolID: anyPortPool.Pool.ID, Type: "TCP", Delay: 5, Timeout: 3, MaxRetries: 3},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "TCP rejects http_method",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "TCP", Delay: 5, Timeout: 3, MaxRetries: 3, HTTPMethod: poolStrPtr("GET")},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "TCP rejects url_path",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "TCP", Delay: 5, Timeout: 3, MaxRetries: 3, URLPath: poolStrPtr("/")},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "TCP rejects expected_codes",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "TCP", Delay: 5, Timeout: 3, MaxRetries: 3, ExpectedCodes: poolStrPtr("200")},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "TCP rejects domain_name",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "TCP", Delay: 5, Timeout: 3, MaxRetries: 3, DomainName: poolStrPtr("a.com")},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "TLS rejects url_path",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "TLS", Delay: 5, Timeout: 3, MaxRetries: 3, URLPath: poolStrPtr("/health")},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "HTTP invalid http_method",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3, HTTPMethod: poolStrPtr("DELETE")},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "HTTP url_path without leading slash",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3, URLPath: poolStrPtr("health")},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "HTTP invalid expected_codes",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3, ExpectedCodes: poolStrPtr("300-200")},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "HTTP invalid domain_name starting with dash",
			in:         createHealthMonitorInput{PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 5, Timeout: 3, MaxRetries: 3, DomainName: poolStrPtr("-bad.com")},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
	}

	for _, tc := range fieldTests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.svc.createHealthMonitor(ctx, poolTestTenant, tc.in)
			poolAssertAPIError(t, err, tc.wantStatus, tc.wantCode)
		})
	}

	// Duplicate monitor on same pool -> ELB.8907; after delete, creating a new monitor succeeds.
	hm1, err := e.svc.createHealthMonitor(ctx, poolTestTenant, createHealthMonitorInput{
		PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 10, Timeout: 5, MaxRetries: 3,
		ExpectedCodes: poolStrPtr("200,202,204-206"), DomainName: poolStrPtr("api.example.com"),
	})
	if err != nil {
		t.Fatalf("create hm1: %v", err)
	}
	_, dupErr := e.svc.createHealthMonitor(ctx, poolTestTenant, createHealthMonitorInput{
		PoolID: httpPool.Pool.ID, Type: "HTTP", Delay: 10, Timeout: 5, MaxRetries: 3,
	})
	poolAssertAPIError(t, dupErr, http.StatusConflict, "ELB.8907")

	// Update type from HTTP to TCP clears HTTP-only fields.
	updated, err := e.svc.updateHealthMonitor(ctx, poolTestTenant, hm1.ID, updateHealthMonitorInput{
		Type: poolStrPtr("TCP"),
	})
	if err != nil {
		t.Fatalf("update hm type to TCP: %v", err)
	}
	if updated.Type != "TCP" || updated.HTTPMethod != "" || updated.URLPath != "" || updated.ExpectedCodes != "" || updated.DomainName != "" {
		t.Fatalf("expected HTTP fields cleared after switch to TCP, got %+v", updated)
	}

	if err := e.svc.deleteHealthMonitor(ctx, poolTestTenant, hm1.ID); err != nil {
		t.Fatalf("delete hm1: %v", err)
	}
	gotPool, err := e.svc.getPool(ctx, poolTestTenant, httpPool.Pool.ID)
	if err != nil {
		t.Fatalf("getPool: %v", err)
	}
	if gotPool.Pool.HealthMonitorID != "" {
		t.Fatalf("pool.HealthMonitorID = %q after delete, want empty", gotPool.Pool.HealthMonitorID)
	}
	if _, err := e.svc.createHealthMonitor(ctx, poolTestTenant, createHealthMonitorInput{
		PoolID: httpPool.Pool.ID, Type: "GRPC", Delay: 5, Timeout: 3, MaxRetries: 3,
	}); err != nil {
		t.Fatalf("re-create hm after delete: %v", err)
	}
}

func TestPoolAndHealthMonitorPaginationAndConcurrency(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)
	ctx := t.Context()

	// Create 5 pools and verify ascending ID order and marker pagination (forward + reverse).
	for i := range 5 {
		ep := defaultEnterpriseProjectID
		if i%2 == 1 {
			ep = poolTestCustomEP
		}
		if _, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
			Name:                fmt.Sprintf("pool-%d", i),
			Protocol:            "HTTP",
			LBAlgorithm:         "ROUND_ROBIN",
			LoadBalancerID:      e.lbID,
			EnterpriseProjectID: &ep,
		}); err != nil {
			t.Fatalf("create pool %d: %v", i, err)
		}
	}

	all, piAll, err := e.svc.listPools(ctx, poolTestTenant, listPoolsFilter{
		EnterpriseProjectIDs: []string{allGrantedEPs},
		Page:                 pagination.Marker{Limit: 2000},
	})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 5 || piAll.CurrentCount != 5 || piAll.NextMarker != nil {
		t.Fatalf("all=%d pi=%+v", len(all), piAll)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Pool.ID >= all[i].Pool.ID {
			t.Fatalf("pools not sorted ascending: %s >= %s", all[i-1].Pool.ID, all[i].Pool.ID)
		}
	}

	// Page 1 (limit 2).
	p1, pi1, err := e.svc.listPools(ctx, poolTestTenant, listPoolsFilter{Page: pagination.Marker{Limit: 2}})
	if err != nil || len(p1) != 2 || pi1.NextMarker == nil || *pi1.NextMarker != p1[1].Pool.ID {
		t.Fatalf("page 1: len=%d pi=%+v err=%v", len(p1), pi1, err)
	}
	// Page 2 (marker = p1[1].ID, limit 2).
	p2, pi2, err := e.svc.listPools(ctx, poolTestTenant, listPoolsFilter{Page: pagination.Marker{ID: *pi1.NextMarker, Limit: 2}})
	if err != nil || len(p2) != 2 || pi2.NextMarker == nil || p2[0].Pool.ID != all[2].Pool.ID {
		t.Fatalf("page 2: len=%d pi=%+v err=%v", len(p2), pi2, err)
	}
	// Reverse from p2[0].ID -> should return p1.
	prev, _, err := e.svc.listPools(ctx, poolTestTenant, listPoolsFilter{
		Page:        pagination.Marker{ID: pi2.PreviousMarker, Limit: 2},
		PageReverse: true,
	})
	if err != nil || len(prev) != 2 || prev[0].Pool.ID != p1[0].Pool.ID || prev[1].Pool.ID != p1[1].Pool.ID {
		t.Fatalf("reverse page: got %+v, want %s,%s (err=%v)", prev, p1[0].Pool.ID, p1[1].Pool.ID, err)
	}

	// Concurrency: 8 goroutines racing to create a default pool on one listener; exactly 1 wins.
	raceLsn := e.seedListener(t, e.lbID, "HTTP", 9090)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, conflicts := 0, 0
	for i := range 8 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := e.svc.createPool(ctx, poolTestTenant, createPoolInput{
				Name:        fmt.Sprintf("race-pool-%d", idx),
				Protocol:    "HTTP",
				LBAlgorithm: "ROUND_ROBIN",
				ListenerID:  raceLsn,
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
			} else {
				var apiErr *apierr.Error
				if errors.As(err, &apiErr) && apiErr.Code == "ELB.8907" {
					conflicts++
				} else {
					t.Errorf("unexpected race err: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 || conflicts != 7 {
		t.Fatalf("listener pool race: wins=%d conflicts=%d, want 1 and 7", wins, conflicts)
	}

	// Concurrency: 8 goroutines racing to create a health monitor on one pool; exactly 1 wins.
	racePool := all[0].Pool.ID
	wins, conflicts = 0, 0
	for i := range 8 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := e.svc.createHealthMonitor(ctx, poolTestTenant, createHealthMonitorInput{
				PoolID:     racePool,
				Name:       fmt.Sprintf("race-hm-%d", idx),
				Type:       "HTTP",
				Delay:      5,
				Timeout:    3,
				MaxRetries: 3,
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
			} else {
				var apiErr *apierr.Error
				if errors.As(err, &apiErr) && apiErr.Code == "ELB.8907" {
					conflicts++
				} else {
					t.Errorf("unexpected hm race err: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 || conflicts != 7 {
		t.Fatalf("hm race: wins=%d conflicts=%d, want 1 and 7", wins, conflicts)
	}
}
