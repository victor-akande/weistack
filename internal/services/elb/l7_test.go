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
	l7TestProject     = "0123456789abcdef0123456789abcdef"
	l7TestRegion      = "ap-southeast-1"
	l7TestHost        = "elb." + l7TestRegion + ".myhuaweicloud.com"
	l7TestUnknownUUID = "00000000-0000-4000-8000-000000000000"
	l7TestCustomEP    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

var (
	l7TestTenant = Tenant{Region: l7TestRegion, ProjectID: l7TestProject}
	l7TestEpoch  = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
)

type l7NoopEIPs struct{}

func (l7NoopEIPs) BindToELB(context.Context, vpc.Tenant, string, string, string, string) (string, error) {
	return "", errors.New("unexpected BindToELB")
}

func (l7NoopEIPs) CreateForELB(context.Context, vpc.Tenant, string, string, string, eip.ServerIP) (string, string, error) {
	return "", "", errors.New("unexpected CreateForELB")
}

func (l7NoopEIPs) UnbindFromELB(context.Context, vpc.Tenant, string, string) error {
	return nil
}

func (l7NoopEIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type l7NoopServers struct{}

func (l7NoopServers) ServerAt(context.Context, vpc.Tenant, string, string, string) (string, bool, error) {
	return "", false, nil
}

type l7TestEnv struct {
	svc        *Service
	store      store.Store
	clock      *lifecycle.FakeClock
	handler    http.Handler
	vpc1ID     string
	vpc2ID     string
	lb1ID      string
	lb2ID      string
	httpLsnID  string
	enhLsnID   string
	httpsLsnID string
	tcpLsnID   string
	lb2HttpsID string
	httpPoolID string
	grpcPoolID string
	tcpPoolID  string
	lb2PoolID  string
}

func l7NewTestEnv(t *testing.T) *l7TestEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(l7TestEpoch)
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

	gen := ids.NewSeeded(77)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	vlt, err := vault.New(make([]byte, vault.KeyLen))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	svc, err := New(Deps{
		Store:   st,
		IDs:     gen,
		Logger:  log,
		Vault:   vlt,
		VPC:     vpcSvc,
		EIPs:    l7NoopEIPs{},
		Servers: l7NoopServers{},
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
		Config: cfg, ProjectID: l7TestProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	name1, cidr1 := "l7-vpc-1", "10.10.0.0/16"
	v1, err := vpcSvc.CreateVPC(ctx, l7TestTenant, vpc.CreateVPCOption{Name: &name1, CIDR: &cidr1})
	if err != nil {
		t.Fatalf("CreateVPC 1: %v", err)
	}
	name2, cidr2 := "l7-vpc-2", "10.20.0.0/16"
	v2, err := vpcSvc.CreateVPC(ctx, l7TestTenant, vpc.CreateVPCOption{Name: &name2, CIDR: &cidr2})
	if err != nil {
		t.Fatalf("CreateVPC 2: %v", err)
	}
	if err := engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	e := &l7TestEnv{
		svc:     svc,
		store:   st,
		clock:   clock,
		handler: srv.Handler(),
		vpc1ID:  v1.ID,
		vpc2ID:  v2.ID,
	}
	e.lb1ID = e.seedLB(t, "lb-1", v1.ID, defaultEnterpriseProjectID)
	e.lb2ID = e.seedLB(t, "lb-2", v2.ID, l7TestCustomEP)
	e.httpLsnID = e.seedListener(t, e.lb1ID, "HTTP", 80, false, defaultEnterpriseProjectID)
	e.enhLsnID = e.seedListener(t, e.lb1ID, "HTTP", 8080, true, defaultEnterpriseProjectID)
	e.httpsLsnID = e.seedListener(t, e.lb1ID, "HTTPS", 443, true, defaultEnterpriseProjectID)
	e.tcpLsnID = e.seedListener(t, e.lb1ID, "TCP", 9000, false, defaultEnterpriseProjectID)
	e.lb2HttpsID = e.seedListener(t, e.lb2ID, "HTTPS", 443, true, l7TestCustomEP)

	e.httpPoolID = e.seedPool(t, e.lb1ID, v1.ID, "HTTP")
	e.grpcPoolID = e.seedPool(t, e.lb1ID, v1.ID, "GRPC")
	e.tcpPoolID = e.seedPool(t, e.lb1ID, v1.ID, "TCP")
	e.lb2PoolID = e.seedPool(t, e.lb2ID, v2.ID, "HTTP")
	return e
}

func (e *l7TestEnv) seedLB(t *testing.T, name, vpcID, ep string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	lb := loadBalancer{
		ID:                  id,
		Name:                name,
		AdminStateUp:        true,
		Provider:            "vlb",
		VPCID:               vpcID,
		EnterpriseProjectID: ep,
		CreatedAt:           e.svc.nowUTC(),
		UpdatedAt:           e.svc.nowUTC(),
	}
	if err := e.svc.loadBalancers(l7TestTenant).Create(t.Context(), id, lb); err != nil {
		t.Fatalf("seedLB: %v", err)
	}
	return id
}

func (e *l7TestEnv) seedListener(t *testing.T, lbID, proto string, port int, enhance bool, ep string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	l := listener{
		ID:                    id,
		LoadBalancerID:        lbID,
		Name:                  fmt.Sprintf("lsn-%s-%d", proto, port),
		Protocol:              proto,
		ProtocolPort:          port,
		AdminStateUp:          true,
		EnhanceL7PolicyEnable: enhance,
		EnterpriseProjectID:   ep,
		CreatedAt:             e.svc.nowUTC(),
		UpdatedAt:             e.svc.nowUTC(),
	}
	if err := e.svc.listeners(l7TestTenant).Create(t.Context(), id, l); err != nil {
		t.Fatalf("seedListener: %v", err)
	}
	return id
}

func (e *l7TestEnv) seedPool(t *testing.T, lbID, vpcID, proto string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	p := pool{
		ID:                  id,
		Name:                "pool-" + proto,
		Protocol:            proto,
		LBAlgorithm:         "ROUND_ROBIN",
		AdminStateUp:        true,
		LoadBalancerID:      lbID,
		VPCID:               vpcID,
		EnterpriseProjectID: defaultEnterpriseProjectID,
		CreatedAt:           e.svc.nowUTC(),
		UpdatedAt:           e.svc.nowUTC(),
	}
	if err := e.svc.pools(l7TestTenant).Create(t.Context(), id, p); err != nil {
		t.Fatalf("seedPool: %v", err)
	}
	return id
}

func (e *l7TestEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	full := "/v3/" + l7TestProject + "/elb" + path
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, full, rdr)
	req.Host = l7TestHost
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *l7TestEnv) expect(t *testing.T, dir, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", dir, goldenName+".json"), status, out)
	return out
}

func l7DecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %T: %v\nbody: %s", out, err, raw)
	}
	return out
}

func l7AssertAPIError(t *testing.T, err error, wantStatus int, wantCode string) {
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

func l7StrPtr(s string) *string { return &s }
func l7IntPtr(n int) *int       { return &n }
func l7BoolPtr(b bool) *bool    { return &b }

func TestL7PolicyActions(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)
	ctx := t.Context()

	httpsPoolID := e.seedPool(t, e.lb1ID, e.vpc1ID, "HTTPS")
	unboundSameVPCPool := e.seedPool(t, "", e.vpc1ID, "HTTP")
	unboundOtherVPCPool := e.seedPool(t, "", e.vpc2ID, "HTTP")
	udpPoolID := e.seedPool(t, e.lb1ID, e.vpc1ID, "UDP")
	tlsPoolID := e.seedPool(t, e.lb1ID, e.vpc1ID, "TLS")
	quicPoolID := e.seedPool(t, e.lb1ID, e.vpc1ID, "QUIC")
	extraPool1 := e.seedPool(t, e.lb1ID, e.vpc1ID, "HTTP")
	extraPool2 := e.seedPool(t, e.lb1ID, e.vpc1ID, "HTTP")
	extraPool3 := e.seedPool(t, e.lb1ID, e.vpc1ID, "HTTP")
	extraPool4 := e.seedPool(t, e.lb1ID, e.vpc1ID, "HTTP")

	tests := []struct {
		name       string
		in         l7CreatePolicyInput
		wantStatus int
		wantCode   string
	}{
		// REDIRECT_TO_POOL valid cases
		{
			name: "redirect_to_pool HTTP pool on HTTP listener",
			in:   l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: e.httpPoolID, Position: l7IntPtr(1)},
		},
		{
			name: "redirect_to_pool HTTPS pool on HTTPS listener",
			in:   l7CreatePolicyInput{ListenerID: e.httpsLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: httpsPoolID},
		},
		{
			name: "redirect_to_pool GRPC pool",
			in:   l7CreatePolicyInput{ListenerID: e.httpsLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: e.grpcPoolID},
		},
		{
			name: "redirect_to_pool unbound pool in same VPC",
			in:   l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: unboundSameVPCPool},
		},
		{
			name: "redirect_to_pool via redirect_pools_config",
			in: l7CreatePolicyInput{
				ListenerID: e.enhLsnID,
				Action:     l7ActionRedirectToPool,
				RedirectPoolsConfig: []l7RedirectPoolConfigInput{
					{PoolID: e.httpPoolID, Weight: l7IntPtr(80)},
					{PoolID: httpsPoolID, Weight: l7IntPtr(20)},
				},
			},
		},
		// REDIRECT_TO_POOL error cases
		{
			name:       "redirect_to_pool missing pool",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_pool unknown pool",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: l7TestUnknownUUID},
			wantStatus: http.StatusNotFound, wantCode: "ELB.8904",
		},
		{
			name:       "redirect_to_pool pool on different LB",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: e.lb2PoolID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_pool unbound pool in different VPC",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: unboundOtherVPCPool},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_pool TCP pool rejected",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: e.tcpPoolID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_pool UDP pool rejected",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: udpPoolID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_pool TLS pool rejected",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: tlsPoolID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_pool QUIC pool rejected",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: quicPoolID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "redirect_to_pool duplicate pool in redirect_pools_config",
			in: l7CreatePolicyInput{
				ListenerID: e.enhLsnID,
				Action:     l7ActionRedirectToPool,
				RedirectPoolsConfig: []l7RedirectPoolConfigInput{
					{PoolID: e.httpPoolID, Weight: l7IntPtr(50)},
					{PoolID: e.httpPoolID, Weight: l7IntPtr(50)},
				},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "redirect_to_pool >5 pools in redirect_pools_config",
			in: l7CreatePolicyInput{
				ListenerID: e.enhLsnID,
				Action:     l7ActionRedirectToPool,
				RedirectPoolsConfig: []l7RedirectPoolConfigInput{
					{PoolID: e.httpPoolID},
					{PoolID: httpsPoolID},
					{PoolID: extraPool1},
					{PoolID: extraPool2},
					{PoolID: extraPool3},
					{PoolID: extraPool4},
				},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "redirect_to_pool weight out of range",
			in: l7CreatePolicyInput{
				ListenerID: e.enhLsnID,
				Action:     l7ActionRedirectToPool,
				RedirectPoolsConfig: []l7RedirectPoolConfigInput{
					{PoolID: e.httpPoolID, Weight: l7IntPtr(101)},
				},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_pool rejects redirect_listener_id",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: e.httpPoolID, RedirectListenerID: e.httpsLsnID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},

		// REDIRECT_TO_LISTENER cases
		{
			name: "redirect_to_listener HTTP -> HTTPS same LB",
			in:   l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToListener, RedirectListenerID: e.httpsLsnID},
		},
		{
			name:       "redirect_to_listener from HTTPS listener rejected",
			in:         l7CreatePolicyInput{ListenerID: e.httpsLsnID, Action: l7ActionRedirectToListener, RedirectListenerID: e.httpsLsnID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_listener unknown target listener",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToListener, RedirectListenerID: l7TestUnknownUUID},
			wantStatus: http.StatusNotFound, wantCode: "ELB.8904",
		},
		{
			name:       "redirect_to_listener target listener on different LB",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToListener, RedirectListenerID: e.lb2HttpsID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_listener target listener not HTTPS",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToListener, RedirectListenerID: e.enhLsnID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "redirect_to_listener rejects redirect_pool_id",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToListener, RedirectListenerID: e.httpsLsnID, RedirectPoolID: e.httpPoolID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "redirect_to_listener rejects inline rules",
			in: l7CreatePolicyInput{
				ListenerID:         e.httpLsnID,
				Action:             l7ActionRedirectToListener,
				RedirectListenerID: e.httpsLsnID,
				Rules:              []l7CreateRuleInput{{Type: l7RuleTypePath, CompareType: l7CompareEqualTo, Value: "/a"}},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},

		// REDIRECT_TO_URL cases
		{
			name: "redirect_to_url defaults with status 301",
			in: l7CreatePolicyInput{
				ListenerID:        e.httpLsnID,
				Action:            l7ActionRedirectToURL,
				RedirectURLConfig: &l7RedirectURLConfigInput{StatusCode: l7StrPtr("301")},
			},
		},
		{
			name: "redirect_to_url full explicit config",
			in: l7CreatePolicyInput{
				ListenerID: e.httpsLsnID,
				Action:     l7ActionRedirectToURL,
				RedirectURLConfig: &l7RedirectURLConfigInput{
					Protocol:   l7StrPtr("HTTPS"),
					Host:       l7StrPtr("www.example.com"),
					Port:       l7StrPtr("8443"),
					Path:       l7StrPtr("/v2/login"),
					Query:      l7StrPtr("${query}&src=elb"),
					StatusCode: l7StrPtr("308"),
				},
			},
		},
		{
			name:       "redirect_to_url missing config",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToURL},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "redirect_to_url invalid protocol",
			in: l7CreatePolicyInput{
				ListenerID:        e.httpLsnID,
				Action:            l7ActionRedirectToURL,
				RedirectURLConfig: &l7RedirectURLConfigInput{Protocol: l7StrPtr("FTP"), StatusCode: l7StrPtr("301")},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "redirect_to_url invalid status_code",
			in: l7CreatePolicyInput{
				ListenerID:        e.httpLsnID,
				Action:            l7ActionRedirectToURL,
				RedirectURLConfig: &l7RedirectURLConfigInput{StatusCode: l7StrPtr("200")},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "redirect_to_url invalid host",
			in: l7CreatePolicyInput{
				ListenerID:        e.httpLsnID,
				Action:            l7ActionRedirectToURL,
				RedirectURLConfig: &l7RedirectURLConfigInput{Host: l7StrPtr("-bad.com"), StatusCode: l7StrPtr("302")},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "redirect_to_url invalid port",
			in: l7CreatePolicyInput{
				ListenerID:        e.httpLsnID,
				Action:            l7ActionRedirectToURL,
				RedirectURLConfig: &l7RedirectURLConfigInput{Port: l7StrPtr("70000"), StatusCode: l7StrPtr("302")},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "redirect_to_url invalid path without leading slash",
			in: l7CreatePolicyInput{
				ListenerID:        e.httpLsnID,
				Action:            l7ActionRedirectToURL,
				RedirectURLConfig: &l7RedirectURLConfigInput{Path: l7StrPtr("no-slash"), StatusCode: l7StrPtr("302")},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},

		// FIXED_RESPONSE cases
		{
			name: "fixed_response minimal with default content_type",
			in: l7CreatePolicyInput{
				ListenerID:          e.httpLsnID,
				Action:              l7ActionFixedResponse,
				FixedResponseConfig: &l7FixedResponseConfigInput{StatusCode: l7StrPtr("200")},
			},
		},
		{
			name: "fixed_response json 503",
			in: l7CreatePolicyInput{
				ListenerID: e.httpsLsnID,
				Action:     l7ActionFixedResponse,
				FixedResponseConfig: &l7FixedResponseConfigInput{
					StatusCode:  l7StrPtr("503"),
					ContentType: l7StrPtr("application/json"),
					MessageBody: l7StrPtr(`{"status":"maintenance"}`),
				},
			},
		},
		{
			name:       "fixed_response missing config",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionFixedResponse},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "fixed_response invalid status_code 302",
			in: l7CreatePolicyInput{
				ListenerID:          e.httpLsnID,
				Action:              l7ActionFixedResponse,
				FixedResponseConfig: &l7FixedResponseConfigInput{StatusCode: l7StrPtr("302")},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "fixed_response invalid content_type",
			in: l7CreatePolicyInput{
				ListenerID:          e.httpLsnID,
				Action:              l7ActionFixedResponse,
				FixedResponseConfig: &l7FixedResponseConfigInput{StatusCode: l7StrPtr("200"), ContentType: l7StrPtr("application/xml")},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "fixed_response message_body too long",
			in: l7CreatePolicyInput{
				ListenerID:          e.httpLsnID,
				Action:              l7ActionFixedResponse,
				FixedResponseConfig: &l7FixedResponseConfigInput{StatusCode: l7StrPtr("200"), MessageBody: l7StrPtr(strings.Repeat("a", 1025))},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},

		// General policy errors
		{
			name:       "unknown action",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: "DROP"},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "unknown listener",
			in:         l7CreatePolicyInput{ListenerID: l7TestUnknownUUID, Action: l7ActionRedirectToPool, RedirectPoolID: e.httpPoolID},
			wantStatus: http.StatusNotFound, wantCode: "ELB.8904",
		},
		{
			name:       "TCP listener rejected",
			in:         l7CreatePolicyInput{ListenerID: e.tcpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: e.httpPoolID},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "admin_state_up false rejected",
			in:         l7CreatePolicyInput{ListenerID: e.httpLsnID, Action: l7ActionRedirectToPool, RedirectPoolID: e.httpPoolID, AdminStateUp: l7BoolPtr(false)},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, tc.in)
			if tc.wantCode != "" {
				l7AssertAPIError(t, err, tc.wantStatus, tc.wantCode)
				return
			}
			if err != nil {
				t.Fatalf("l7CreatePolicy: unexpected error: %v", err)
			}
			if got.Policy.Position != l7DefaultPosition {
				t.Fatalf("position = %d, want %d", got.Policy.Position, l7DefaultPosition)
			}
			if !got.Policy.AdminStateUp {
				t.Fatalf("admin_state_up = false, want true")
			}
		})
	}
}

func TestL7PolicyPriorityRules(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)
	ctx := t.Context()

	// Priority rejected when enhance_l7policy_enable is false.
	_, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.httpLsnID,
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Priority:       l7IntPtr(1),
	})
	l7AssertAPIError(t, err, http.StatusBadRequest, "ELB.8902")

	// Negative priority rejected.
	_, err = e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Priority:       l7IntPtr(-1),
	})
	l7AssertAPIError(t, err, http.StatusBadRequest, "ELB.8902")

	// Priority 0 and 10 accepted on enhanced listener.
	p0, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Priority:       l7IntPtr(0),
	})
	if err != nil {
		t.Fatalf("create priority 0: %v", err)
	}
	if p0.Policy.Priority == nil || *p0.Policy.Priority != 0 {
		t.Fatalf("priority = %v, want 0", p0.Policy.Priority)
	}

	p10, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Priority:       l7IntPtr(10),
	})
	if err != nil {
		t.Fatalf("create priority 10: %v", err)
	}

	// Duplicate priority on same listener -> ELB.8907.
	_, err = e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Priority:       l7IntPtr(10),
	})
	l7AssertAPIError(t, err, http.StatusConflict, "ELB.8907")

	// Same priority on a different enhanced listener is allowed.
	if _, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.httpsLsnID,
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Priority:       l7IntPtr(10),
	}); err != nil {
		t.Fatalf("same priority on different listener: %v", err)
	}

	// Update p10 to p0's priority -> ELB.8907.
	_, err = e.svc.l7UpdatePolicy(ctx, l7TestTenant, p10.Policy.ID, l7UpdatePolicyInput{Priority: l7IntPtr(0)})
	l7AssertAPIError(t, err, http.StatusConflict, "ELB.8907")

	// Update p10 to its own priority -> OK.
	if _, err := e.svc.l7UpdatePolicy(ctx, l7TestTenant, p10.Policy.ID, l7UpdatePolicyInput{Priority: l7IntPtr(10)}); err != nil {
		t.Fatalf("update same priority: %v", err)
	}

	// Update policy on non-enhanced listener with priority -> ELB.8902.
	plainPol, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.httpLsnID,
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
	})
	if err != nil {
		t.Fatalf("create plain policy: %v", err)
	}
	_, err = e.svc.l7UpdatePolicy(ctx, l7TestTenant, plainPol.Policy.ID, l7UpdatePolicyInput{Priority: l7IntPtr(5)})
	l7AssertAPIError(t, err, http.StatusBadRequest, "ELB.8902")
}

func TestL7InlineRulesAndCascadeDelete(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)
	ctx := t.Context()

	// Duplicate type in inline rules must fail with ELB.8907 and store nothing.
	_, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Name:           "atomic-dup",
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Rules: []l7CreateRuleInput{
			{Type: l7RuleTypePath, CompareType: l7CompareEqualTo, Value: "/a"},
			{Type: l7RuleTypePath, CompareType: l7CompareStartsWith, Value: "/b"},
		},
	})
	l7AssertAPIError(t, err, http.StatusConflict, "ELB.8907")

	// Invalid second inline rule must fail with ELB.8902 and store nothing.
	_, err = e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Name:           "atomic-bad",
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Rules: []l7CreateRuleInput{
			{Type: l7RuleTypeHostName, CompareType: l7CompareEqualTo, Value: "app.example.com"},
			{Type: l7RuleTypePath, CompareType: l7CompareEqualTo, Value: "no-leading-slash"},
		},
	})
	l7AssertAPIError(t, err, http.StatusBadRequest, "ELB.8902")

	// Verify store has 0 policies and 0 rules after failed atomic creates.
	pols, err := e.svc.l7Policies(l7TestTenant).List(ctx, nil)
	if err != nil || len(pols) != 0 {
		t.Fatalf("policies after failed creates = %d (err=%v), want 0", len(pols), err)
	}
	rules, err := e.svc.l7Rules(l7TestTenant).List(ctx, nil)
	if err != nil || len(rules) != 0 {
		t.Fatalf("rules after failed creates = %d (err=%v), want 0", len(rules), err)
	}

	// Create policy with 2 valid inline rules.
	d1, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Name:           "with-inline",
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Rules: []l7CreateRuleInput{
			{Type: l7RuleTypeHostName, CompareType: l7CompareEqualTo, Value: "*.example.com"},
			{Type: l7RuleTypePath, CompareType: l7CompareStartsWith, Value: "/api"},
		},
	})
	if err != nil {
		t.Fatalf("create with inline rules: %v", err)
	}
	if len(d1.RuleIDs) != 2 {
		t.Fatalf("inline RuleIDs = %d, want 2", len(d1.RuleIDs))
	}

	// Create a second policy with 1 rule to verify cascade delete only removes target policy's rules.
	d2, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Name:           "survivor",
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
		Rules: []l7CreateRuleInput{
			{Type: l7RuleTypeMethod, CompareType: l7CompareEqualTo, Value: "GET"},
		},
	})
	if err != nil {
		t.Fatalf("create survivor: %v", err)
	}

	// Delete policy 1 -> deletes policy 1 and both of its rules.
	if err := e.svc.l7DeletePolicy(ctx, l7TestTenant, d1.Policy.ID); err != nil {
		t.Fatalf("l7DeletePolicy: %v", err)
	}
	for _, rID := range d1.RuleIDs {
		if _, err := e.svc.l7Rules(l7TestTenant).Get(ctx, rID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("rule %s still exists after policy delete: %v", rID, err)
		}
	}
	// Survivor policy and its rule remain intact.
	if _, err := e.svc.l7GetRule(ctx, l7TestTenant, d2.Policy.ID, d2.RuleIDs[0]); err != nil {
		t.Fatalf("survivor rule missing: %v", err)
	}
}

func TestL7RuleTypeCompareMatrix(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)
	ctx := t.Context()

	validSamples := map[string]struct {
		key   string
		value string
	}{
		l7RuleTypeHostName:    {value: "api.example.com"},
		l7RuleTypePath:        {value: "/v1/items"},
		l7RuleTypeMethod:      {value: "POST"},
		l7RuleTypeHeader:      {key: "X-Custom-Hdr", value: "v1*"},
		l7RuleTypeQueryString: {key: "env", value: "canary?"},
		l7RuleTypeSourceIP:    {value: "192.168.1.0/24"},
	}

	allTypes := []string{
		l7RuleTypeHostName, l7RuleTypePath, l7RuleTypeMethod,
		l7RuleTypeHeader, l7RuleTypeQueryString, l7RuleTypeSourceIP,
	}
	allCompares := []string{l7CompareEqualTo, l7CompareStartsWith, l7CompareRegex}

	for _, typ := range allTypes {
		for _, cmp := range allCompares {
			wantOK := cmp == l7CompareEqualTo || typ == l7RuleTypePath
			t.Run(typ+"_"+cmp, func(t *testing.T) {
				pol, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
					ListenerID:     e.enhLsnID,
					Action:         l7ActionRedirectToPool,
					RedirectPoolID: e.httpPoolID,
				})
				if err != nil {
					t.Fatalf("seed policy: %v", err)
				}
				sample := validSamples[typ]
				got, err := e.svc.l7CreateRule(ctx, l7TestTenant, pol.Policy.ID, l7CreateRuleInput{
					Type:        typ,
					CompareType: cmp,
					Key:         sample.key,
					Value:       sample.value,
				})
				if !wantOK {
					l7AssertAPIError(t, err, http.StatusBadRequest, "ELB.8902")
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got.Type != typ || got.CompareType != cmp || got.Invert {
					t.Fatalf("got rule = %+v", got)
				}
			})
		}
	}
}

func TestL7RuleValueKeyAndConditionsValidation(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)
	ctx := t.Context()

	tests := []struct {
		name       string
		in         l7CreateRuleInput
		wantStatus int
		wantCode   string
	}{
		// HOST_NAME
		{"host wildcard valid", l7CreateRuleInput{Type: l7RuleTypeHostName, CompareType: l7CompareEqualTo, Value: "*.example.com"}, 0, ""},
		{"host mid wildcard invalid", l7CreateRuleInput{Type: l7RuleTypeHostName, CompareType: l7CompareEqualTo, Value: "a.*.example.com"}, http.StatusBadRequest, "ELB.8902"},
		{"host no dot after star invalid", l7CreateRuleInput{Type: l7RuleTypeHostName, CompareType: l7CompareEqualTo, Value: "*example.com"}, http.StatusBadRequest, "ELB.8902"},
		{"host leading dash invalid", l7CreateRuleInput{Type: l7RuleTypeHostName, CompareType: l7CompareEqualTo, Value: "-bad.com"}, http.StatusBadRequest, "ELB.8902"},
		{"host forbids key", l7CreateRuleInput{Type: l7RuleTypeHostName, CompareType: l7CompareEqualTo, Key: "k", Value: "example.com"}, http.StatusBadRequest, "ELB.8902"},

		// PATH
		{"path regex valid", l7CreateRuleInput{Type: l7RuleTypePath, CompareType: l7CompareRegex, Value: "^/api/v[0-9]+/.*$"}, 0, ""},
		{"path regex invalid", l7CreateRuleInput{Type: l7RuleTypePath, CompareType: l7CompareRegex, Value: "[unclosed"}, http.StatusBadRequest, "ELB.8902"},
		{"path equal missing slash", l7CreateRuleInput{Type: l7RuleTypePath, CompareType: l7CompareEqualTo, Value: "api/v1"}, http.StatusBadRequest, "ELB.8902"},
		{"path equal space invalid", l7CreateRuleInput{Type: l7RuleTypePath, CompareType: l7CompareEqualTo, Value: "/api v1"}, http.StatusBadRequest, "ELB.8902"},
		{"path forbids key", l7CreateRuleInput{Type: l7RuleTypePath, CompareType: l7CompareEqualTo, Key: "k", Value: "/ok"}, http.StatusBadRequest, "ELB.8902"},

		// METHOD
		{"method valid PATCH", l7CreateRuleInput{Type: l7RuleTypeMethod, CompareType: l7CompareEqualTo, Value: "PATCH"}, 0, ""},
		{"method invalid lowercase", l7CreateRuleInput{Type: l7RuleTypeMethod, CompareType: l7CompareEqualTo, Value: "get"}, http.StatusBadRequest, "ELB.8902"},
		{"method invalid CONNECT", l7CreateRuleInput{Type: l7RuleTypeMethod, CompareType: l7CompareEqualTo, Value: "CONNECT"}, http.StatusBadRequest, "ELB.8902"},
		{"method forbids key", l7CreateRuleInput{Type: l7RuleTypeMethod, CompareType: l7CompareEqualTo, Key: "m", Value: "GET"}, http.StatusBadRequest, "ELB.8902"},

		// SOURCE_IP
		{"source_ip ipv4 cidr valid", l7CreateRuleInput{Type: l7RuleTypeSourceIP, CompareType: l7CompareEqualTo, Value: "10.0.0.1/32"}, 0, ""},
		{"source_ip ipv6 cidr valid", l7CreateRuleInput{Type: l7RuleTypeSourceIP, CompareType: l7CompareEqualTo, Value: "2049::49/64"}, 0, ""},
		{"source_ip bare ip invalid", l7CreateRuleInput{Type: l7RuleTypeSourceIP, CompareType: l7CompareEqualTo, Value: "10.0.0.1"}, http.StatusBadRequest, "ELB.8902"},
		{"source_ip forbids key", l7CreateRuleInput{Type: l7RuleTypeSourceIP, CompareType: l7CompareEqualTo, Key: "ip", Value: "10.0.0.0/8"}, http.StatusBadRequest, "ELB.8902"},

		// HEADER
		{"header valid", l7CreateRuleInput{Type: l7RuleTypeHeader, CompareType: l7CompareEqualTo, Key: "X-Env_1", Value: "prod-*?"}, 0, ""},
		{"header missing key", l7CreateRuleInput{Type: l7RuleTypeHeader, CompareType: l7CompareEqualTo, Value: "prod"}, http.StatusBadRequest, "ELB.8902"},
		{"header key invalid char", l7CreateRuleInput{Type: l7RuleTypeHeader, CompareType: l7CompareEqualTo, Key: "X.Env", Value: "prod"}, http.StatusBadRequest, "ELB.8902"},
		{"header value space invalid", l7CreateRuleInput{Type: l7RuleTypeHeader, CompareType: l7CompareEqualTo, Key: "X-Env", Value: "a b"}, http.StatusBadRequest, "ELB.8902"},
		{"header value quote invalid", l7CreateRuleInput{Type: l7RuleTypeHeader, CompareType: l7CompareEqualTo, Key: "X-Env", Value: `a"b`}, http.StatusBadRequest, "ELB.8902"},

		// QUERY_STRING
		{"query valid", l7CreateRuleInput{Type: l7RuleTypeQueryString, CompareType: l7CompareEqualTo, Key: "ver", Value: "v1.*"}, 0, ""},
		{"query missing key", l7CreateRuleInput{Type: l7RuleTypeQueryString, CompareType: l7CompareEqualTo, Value: "v1"}, http.StatusBadRequest, "ELB.8902"},
		{"query key forbidden amp", l7CreateRuleInput{Type: l7RuleTypeQueryString, CompareType: l7CompareEqualTo, Key: "a&b", Value: "1"}, http.StatusBadRequest, "ELB.8902"},
		{"query value forbidden hash", l7CreateRuleInput{Type: l7RuleTypeQueryString, CompareType: l7CompareEqualTo, Key: "a", Value: "1#2"}, http.StatusBadRequest, "ELB.8902"},

		// Conditions
		{
			name: "conditions header multi-value valid",
			in: l7CreateRuleInput{
				Type:        l7RuleTypeHeader,
				CompareType: l7CompareEqualTo,
				Conditions: []ruleCondition{
					{Key: "X-Tier", Value: "gold"},
					{Key: "X-Tier", Value: "silver"},
				},
			},
		},
		{
			name: "conditions mismatched keys invalid",
			in: l7CreateRuleInput{
				Type:        l7RuleTypeHeader,
				CompareType: l7CompareEqualTo,
				Conditions: []ruleCondition{
					{Key: "X-Tier", Value: "gold"},
					{Key: "X-Other", Value: "silver"},
				},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "conditions duplicate values invalid",
			in: l7CreateRuleInput{
				Type:        l7RuleTypeHostName,
				CompareType: l7CompareEqualTo,
				Conditions: []ruleCondition{
					{Key: "", Value: "a.example.com"},
					{Key: "", Value: "a.example.com"},
				},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name: "conditions non-empty key on PATH invalid",
			in: l7CreateRuleInput{
				Type:        l7RuleTypePath,
				CompareType: l7CompareStartsWith,
				Conditions:  []ruleCondition{{Key: "bad", Value: "/v1"}},
			},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "unknown rule type",
			in:         l7CreateRuleInput{Type: "COOKIE", CompareType: l7CompareEqualTo, Value: "sid=1"},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
		{
			name:       "unknown compare_type",
			in:         l7CreateRuleInput{Type: l7RuleTypePath, CompareType: "CONTAINS", Value: "/a"},
			wantStatus: http.StatusBadRequest, wantCode: "ELB.8902",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
				ListenerID:     e.enhLsnID,
				Action:         l7ActionRedirectToPool,
				RedirectPoolID: e.httpPoolID,
			})
			if err != nil {
				t.Fatalf("seed policy: %v", err)
			}
			_, err = e.svc.l7CreateRule(ctx, l7TestTenant, pol.Policy.ID, tc.in)
			if tc.wantCode != "" {
				l7AssertAPIError(t, err, tc.wantStatus, tc.wantCode)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestL7RuleDuplicateTypeConflictAndUpdate(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)
	ctx := t.Context()

	pol, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
	})
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	r1, err := e.svc.l7CreateRule(ctx, l7TestTenant, pol.Policy.ID, l7CreateRuleInput{
		Type:        l7RuleTypePath,
		CompareType: l7CompareEqualTo,
		Value:       "/v1",
	})
	if err != nil {
		t.Fatalf("create PATH rule: %v", err)
	}

	// Second rule of the same type -> ELB.8907.
	_, err = e.svc.l7CreateRule(ctx, l7TestTenant, pol.Policy.ID, l7CreateRuleInput{
		Type:        l7RuleTypePath,
		CompareType: l7CompareStartsWith,
		Value:       "/v2",
	})
	l7AssertAPIError(t, err, http.StatusConflict, "ELB.8907")

	// Update compare_type and value.
	updated, err := e.svc.l7UpdateRule(ctx, l7TestTenant, pol.Policy.ID, r1.ID, l7UpdateRuleInput{
		CompareType: l7StrPtr(l7CompareStartsWith),
		Value:       l7StrPtr("/v2"),
	})
	if err != nil {
		t.Fatalf("update PATH rule: %v", err)
	}
	if updated.CompareType != l7CompareStartsWith || updated.Value != "/v2" {
		t.Fatalf("updated = %+v", updated)
	}

	// Updating rule via another policy's ID -> ELB.8904.
	pol2, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
	})
	if err != nil {
		t.Fatalf("seed policy 2: %v", err)
	}
	_, err = e.svc.l7GetRule(ctx, l7TestTenant, pol2.Policy.ID, r1.ID)
	l7AssertAPIError(t, err, http.StatusNotFound, "ELB.8904")
	_, err = e.svc.l7UpdateRule(ctx, l7TestTenant, pol2.Policy.ID, r1.ID, l7UpdateRuleInput{Value: l7StrPtr("/v3")})
	l7AssertAPIError(t, err, http.StatusNotFound, "ELB.8904")
	err = e.svc.l7DeleteRule(ctx, l7TestTenant, pol2.Policy.ID, r1.ID)
	l7AssertAPIError(t, err, http.StatusNotFound, "ELB.8904")

	// Creating a rule on a REDIRECT_TO_LISTENER policy -> ELB.8902.
	redirPol, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:         e.httpLsnID,
		Action:             l7ActionRedirectToListener,
		RedirectListenerID: e.httpsLsnID,
	})
	if err != nil {
		t.Fatalf("seed redirect policy: %v", err)
	}
	_, err = e.svc.l7CreateRule(ctx, l7TestTenant, redirPol.Policy.ID, l7CreateRuleInput{
		Type:        l7RuleTypePath,
		CompareType: l7CompareEqualTo,
		Value:       "/x",
	})
	l7AssertAPIError(t, err, http.StatusBadRequest, "ELB.8902")
}

func TestL7ListPagination(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)
	ctx := t.Context()

	var polIDs []string
	for i := range 3 {
		d, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
			ListenerID:     e.enhLsnID,
			Name:           fmt.Sprintf("p-%d", i),
			Action:         l7ActionRedirectToPool,
			RedirectPoolID: e.httpPoolID,
		})
		if err != nil {
			t.Fatalf("create policy %d: %v", i, err)
		}
		polIDs = append(polIDs, d.Policy.ID)
	}

	page1, pi1, err := e.svc.l7ListPolicies(ctx, l7TestTenant, l7ListPoliciesFilter{
		Page: pagination.Marker{Limit: 2},
	})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 || pi1.CurrentCount != 2 || pi1.NextMarker == nil {
		t.Fatalf("page1 = %d, pi = %+v", len(page1), pi1)
	}

	page2, pi2, err := e.svc.l7ListPolicies(ctx, l7TestTenant, l7ListPoliciesFilter{
		Page: pagination.Marker{Limit: 2, ID: *pi1.NextMarker},
	})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 1 || pi2.CurrentCount != 1 || pi2.NextMarker != nil {
		t.Fatalf("page2 = %d, pi = %+v", len(page2), pi2)
	}

	// Reverse pagination from page2's previous_marker returns page1.
	rev, piRev, err := e.svc.l7ListPolicies(ctx, l7TestTenant, l7ListPoliciesFilter{
		Page:        pagination.Marker{Limit: 2, ID: pi2.PreviousMarker},
		PageReverse: true,
	})
	if err != nil {
		t.Fatalf("reverse page: %v", err)
	}
	if len(rev) != 2 || rev[0].Policy.ID != page1[0].Policy.ID || rev[1].Policy.ID != page1[1].Policy.ID || piRev.CurrentCount != 2 {
		t.Fatalf("rev = %+v (pi=%+v), want same as page1", rev, piRev)
	}
	if len(polIDs) != 3 {
		t.Fatalf("unexpected polIDs len")
	}
}

func TestL7ConcurrencyRace(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)
	ctx := t.Context()

	const workers = 8

	// 1. 8 goroutines racing to claim priority=42 on the same enhanced listener.
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		polWins   int
		polConf   int
		otherErrs []error
	)
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			_, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
				ListenerID:     e.enhLsnID,
				Name:           fmt.Sprintf("race-%d", idx),
				Action:         l7ActionRedirectToPool,
				RedirectPoolID: e.httpPoolID,
				Priority:       l7IntPtr(42),
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				polWins++
				return
			}
			var apiErr *apierr.Error
			if errors.As(err, &apiErr) && apiErr.Code == "ELB.8907" {
				polConf++
				return
			}
			otherErrs = append(otherErrs, err)
		}(i)
	}
	wg.Wait()
	if polWins != 1 || polConf != workers-1 || len(otherErrs) != 0 {
		t.Fatalf("priority race: wins=%d conflicts=%d other=%v", polWins, polConf, otherErrs)
	}

	// 2. 8 goroutines racing to add a PATH rule on the same policy.
	targetPol, err := e.svc.l7CreatePolicy(ctx, l7TestTenant, l7CreatePolicyInput{
		ListenerID:     e.enhLsnID,
		Name:           "rule-race-target",
		Action:         l7ActionRedirectToPool,
		RedirectPoolID: e.httpPoolID,
	})
	if err != nil {
		t.Fatalf("seed rule race policy: %v", err)
	}

	var (
		ruleWins  int
		ruleConf  int
		ruleOther []error
	)
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			_, err := e.svc.l7CreateRule(ctx, l7TestTenant, targetPol.Policy.ID, l7CreateRuleInput{
				Type:        l7RuleTypePath,
				CompareType: l7CompareEqualTo,
				Value:       fmt.Sprintf("/p/%d", idx),
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ruleWins++
				return
			}
			var apiErr *apierr.Error
			if errors.As(err, &apiErr) && apiErr.Code == "ELB.8907" {
				ruleConf++
				return
			}
			ruleOther = append(ruleOther, err)
		}(i)
	}
	wg.Wait()
	if ruleWins != 1 || ruleConf != workers-1 || len(ruleOther) != 0 {
		t.Fatalf("rule type race: wins=%d conflicts=%d other=%v", ruleWins, ruleConf, ruleOther)
	}
}
