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
	lsnTestProject  = "0123456789abcdef0123456789abcdef"
	lsnTestProjectB = "fedcba9876543210fedcba9876543210"
	lsnTestRegion   = "ap-southeast-1"
	lsnTestHost     = "elb." + lsnTestRegion + ".myhuaweicloud.com"
	lsnUnknownUUID  = "00000000-0000-4000-8000-000000000000"
	lsnCustomEP     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

var (
	lsnTestTenant  = Tenant{Region: lsnTestRegion, ProjectID: lsnTestProject}
	lsnTestTenantB = Tenant{Region: lsnTestRegion, ProjectID: lsnTestProjectB}
	lsnTestEpoch   = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
)

type lsnStubNetwork struct{}

func (lsnStubNetwork) GetVPC(context.Context, vpc.Tenant, string) (vpc.VPC, error) {
	return vpc.VPC{}, errors.New("unexpected GetVPC")
}
func (lsnStubNetwork) GetSubnet(context.Context, vpc.Tenant, string) (vpc.Subnet, error) {
	return vpc.Subnet{}, errors.New("unexpected GetSubnet")
}
func (lsnStubNetwork) ListSubnets(context.Context, vpc.Tenant, vpc.ListSubnetsFilter) ([]vpc.Subnet, error) {
	return nil, nil
}
func (lsnStubNetwork) AllocateIP(context.Context, vpc.Tenant, string, string, string) (string, error) {
	return "", errors.New("unexpected AllocateIP")
}
func (lsnStubNetwork) ReleaseIP(context.Context, vpc.Tenant, string, string) error {
	return nil
}

type lsnStubPublicIPs struct{}

func (lsnStubPublicIPs) BindToELB(context.Context, vpc.Tenant, string, string, string, string) (string, error) {
	return "", errors.New("unexpected BindToELB")
}
func (lsnStubPublicIPs) CreateForELB(context.Context, vpc.Tenant, string, string, string, eip.ServerIP) (string, string, error) {
	return "", "", errors.New("unexpected CreateForELB")
}
func (lsnStubPublicIPs) UnbindFromELB(context.Context, vpc.Tenant, string, string) error {
	return nil
}
func (lsnStubPublicIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type lsnStubServers struct{}

func (lsnStubServers) ServerAt(context.Context, vpc.Tenant, string, string, string) (string, bool, error) {
	return "", false, nil
}

type lsnEnv struct {
	svc     *Service
	store   store.Store
	clock   *lifecycle.FakeClock
	handler http.Handler

	lbBothID string
	lbL4ID   string
	lbL7ID   string
	lbOther  string

	serverCertID string
	serverCert2  string
	clientCertID string
	secPolID     string
	ipGroupID    string
	ipGroup2ID   string
}

func newLsnEnv(t *testing.T) *lsnEnv {
	t.Helper()
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(lsnTestEpoch)
	gen := ids.NewSeeded(22)

	vltKey := make([]byte, vault.KeyLen)
	for i := range vltKey {
		vltKey[i] = byte(i + 1)
	}
	vlt, err := vault.New(vltKey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	svc, err := New(Deps{
		Store:   st,
		IDs:     gen,
		Logger:  log,
		Vault:   vlt,
		VPC:     lsnStubNetwork{},
		EIPs:    lsnStubPublicIPs{},
		Servers: lsnStubServers{},
		Now:     clock.Now,
	})
	if err != nil {
		t.Fatalf("elb.New: %v", err)
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	engine := lifecycle.New(lifecycle.Options{Clock: clock, Logger: log})
	srv, err := server.New(server.Options{
		Config:    cfg,
		ProjectID: lsnTestProject,
		Logger:    log,
		Store:     st,
		Engine:    engine,
		IDs:       gen,
		Services:  []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	e := &lsnEnv{
		svc:     svc,
		store:   st,
		clock:   clock,
		handler: srv.Handler(),
	}

	e.lbBothID = e.seedLB(t, lsnTestTenant, "lb-both", "l4-flv", "l7-flv", defaultEnterpriseProjectID)
	e.lbL4ID = e.seedLB(t, lsnTestTenant, "lb-l4", "l4-flv", "", defaultEnterpriseProjectID)
	e.lbL7ID = e.seedLB(t, lsnTestTenant, "lb-l7", "", "l7-flv", lsnCustomEP)
	e.lbOther = e.seedLB(t, lsnTestTenant, "lb-other", "l4-flv", "l7-flv", defaultEnterpriseProjectID)

	e.serverCertID = e.seedCert(t, lsnTestTenant, "srv-cert-1", "server")
	e.serverCert2 = e.seedCert(t, lsnTestTenant, "srv-cert-2", "server")
	e.clientCertID = e.seedCert(t, lsnTestTenant, "ca-cert-1", "client")
	e.secPolID = e.seedSecPolicy(t, lsnTestTenant, "custom-sp-1")
	e.ipGroupID = e.seedIPGroup(t, lsnTestTenant, "ipg-1")
	e.ipGroup2ID = e.seedIPGroup(t, lsnTestTenant, "ipg-2")
	return e
}

func (e *lsnEnv) seedLB(t *testing.T, tenant Tenant, name, l4Flavor, l7Flavor, ep string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	lb := loadBalancer{
		ID:                  id,
		Name:                name,
		AdminStateUp:        true,
		L4FlavorID:          l4Flavor,
		L7FlavorID:          l7Flavor,
		EnterpriseProjectID: ep,
		CreatedAt:           lsnTestEpoch,
		UpdatedAt:           lsnTestEpoch,
	}
	if err := e.svc.loadBalancers(tenant).Create(t.Context(), id, lb); err != nil {
		t.Fatalf("seedLB %s: %v", name, err)
	}
	return id
}

func (e *lsnEnv) seedPool(t *testing.T, tenant Tenant, lbID, proto string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	p := pool{
		ID:             id,
		Name:           "pool-" + proto,
		Protocol:       proto,
		LBAlgorithm:    "ROUND_ROBIN",
		AdminStateUp:   true,
		LoadBalancerID: lbID,
		CreatedAt:      lsnTestEpoch,
		UpdatedAt:      lsnTestEpoch,
	}
	if err := e.svc.pools(tenant).Create(t.Context(), id, p); err != nil {
		t.Fatalf("seedPool %s: %v", proto, err)
	}
	return id
}

func (e *lsnEnv) seedCert(t *testing.T, tenant Tenant, name, certType string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	c := certificate{
		ID:           id,
		Name:         name,
		Type:         certType,
		AdminStateUp: true,
		CreatedAt:    lsnTestEpoch,
		UpdatedAt:    lsnTestEpoch,
	}
	if err := e.svc.certificates(tenant).Create(t.Context(), id, c); err != nil {
		t.Fatalf("seedCert %s: %v", name, err)
	}
	return id
}

func (e *lsnEnv) seedSecPolicy(t *testing.T, tenant Tenant, name string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	sp := securityPolicy{
		ID:        id,
		Name:      name,
		Protocols: []string{"TLSv1.2"},
		Ciphers:   []string{"ECDHE-RSA-AES128-GCM-SHA256"},
		CreatedAt: lsnTestEpoch,
		UpdatedAt: lsnTestEpoch,
	}
	if err := e.svc.securityPolicies(tenant).Create(t.Context(), id, sp); err != nil {
		t.Fatalf("seedSecPolicy %s: %v", name, err)
	}
	return id
}

func (e *lsnEnv) seedIPGroup(t *testing.T, tenant Tenant, name string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	g := ipGroup{
		ID:        id,
		Name:      name,
		IPList:    []ipInfo{{IP: "10.0.0.1"}},
		CreatedAt: lsnTestEpoch,
		UpdatedAt: lsnTestEpoch,
	}
	if err := e.svc.ipGroups(tenant).Create(t.Context(), id, g); err != nil {
		t.Fatalf("seedIPGroup %s: %v", name, err)
	}
	return id
}

func (e *lsnEnv) seedL7PolicyWithRule(t *testing.T, tenant Tenant, listenerID, redirectListenerID string) (string, string) {
	t.Helper()
	polID := e.svc.ids.UUID()
	pol := l7Policy{
		ID:                 polID,
		ListenerID:         listenerID,
		RedirectListenerID: redirectListenerID,
		Name:               "pol-1",
		Action:             "REDIRECT_TO_POOL",
		AdminStateUp:       true,
		CreatedAt:          lsnTestEpoch,
		UpdatedAt:          lsnTestEpoch,
	}
	if err := e.svc.l7Policies(tenant).Create(t.Context(), polID, pol); err != nil {
		t.Fatalf("seedL7Policy: %v", err)
	}
	ruleID := e.svc.ids.UUID()
	r := l7Rule{
		ID:           ruleID,
		PolicyID:     polID,
		Type:         "PATH",
		CompareType:  "EQUAL_TO",
		Value:        "/api",
		AdminStateUp: true,
		CreatedAt:    lsnTestEpoch,
		UpdatedAt:    lsnTestEpoch,
	}
	if err := e.svc.l7Rules(tenant).Create(t.Context(), ruleID, r); err != nil {
		t.Fatalf("seedL7Rule: %v", err)
	}
	return polID, ruleID
}

func (e *lsnEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callAs(t, lsnTestProject, method, path, body)
}

func (e *lsnEnv) callAs(t *testing.T, project, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v3/"+project+"/elb"+path, rd)
	r.Host = lsnTestHost
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

func (e *lsnEnv) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "listeners", goldenName+".json"), status, out)
	return out
}

func lsnPtr[T any](v T) *T { return &v }

func lsnDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func lsnCodeOf(err error) string {
	if err == nil {
		return ""
	}
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return err.Error()
}

func TestListenerProtocolAndFlavorValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		lbKind    string // "both", "l4", "l7"
		protocol  string
		wantProto string
		wantCode  string
		needCert  bool
	}{
		{"TCP on L4", "l4", "TCP", "TCP", "", false},
		{"UDP on L4", "l4", "UDP", "UDP", "", false},
		{"TLS on L4", "l4", "TLS", "TLS", "", true},
		{"QUIC on L4", "l4", "QUIC", "QUIC", "", true},
		{"HTTP on L4 rejected", "l4", "HTTP", "", "ELB.8902", false},
		{"HTTPS on L4 rejected", "l4", "HTTPS", "", "ELB.8902", true},
		{"HTTP on L7", "l7", "HTTP", "HTTP", "", false},
		{"HTTPS on L7", "l7", "HTTPS", "HTTPS", "", true},
		{"TERMINATED_HTTPS stored as HTTPS", "l7", "TERMINATED_HTTPS", "HTTPS", "", true},
		{"TCP on L7 rejected", "l7", "TCP", "", "ELB.8902", false},
		{"UDP on L7 rejected", "l7", "UDP", "", "ELB.8902", false},
		{"TLS on L7 rejected", "l7", "TLS", "", "ELB.8902", true},
		{"QUIC on L7 rejected", "l7", "QUIC", "", "ELB.8902", true},
		{"IP rejected", "both", "IP", "", "ELB.8902", false},
		{"unknown protocol rejected", "both", "SCTP", "", "ELB.8902", false},
		{"empty protocol rejected", "both", "", "", "ELB.8902", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newLsnEnv(t)
			lbID := e.lbBothID
			switch tc.lbKind {
			case "l4":
				lbID = e.lbL4ID
			case "l7":
				lbID = e.lbL7ID
			}
			in := createListenerInput{
				LoadBalancerID:  lbID,
				Protocol:        tc.protocol,
				ProtocolPort:    lsnPtr(8080),
				PortRangesValid: true,
			}
			if tc.needCert {
				in.DefaultTLSContainerRef = e.serverCertID
			}
			got, err := e.svc.createListener(t.Context(), lsnTestTenant, in)
			if tc.wantCode != "" {
				if code := lsnCodeOf(err); code != tc.wantCode {
					t.Fatalf("err = %v (code %q), want %q", err, code, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Protocol != tc.wantProto {
				t.Fatalf("protocol = %q, want %q", got.Protocol, tc.wantProto)
			}
		})
	}
}

func TestListenerPoolProtocolPairing(t *testing.T) {
	t.Parallel()

	listenerProtos := []string{"TCP", "UDP", "HTTP", "HTTPS", "TLS", "QUIC"}
	poolProtos := []string{"TCP", "UDP", "HTTP", "HTTPS", "QUIC", "GRPC", "TLS"}

	allowed := map[string]map[string]bool{
		"UDP":   {"UDP": true, "QUIC": true},
		"TCP":   {"TCP": true},
		"HTTP":  {"HTTP": true},
		"HTTPS": {"HTTP": true, "HTTPS": true, "GRPC": true},
		"TLS":   {"TCP": true, "TLS": true},
		"QUIC":  {"UDP": true, "QUIC": true},
	}

	for _, lp := range listenerProtos {
		for _, pp := range poolProtos {
			wantOK := allowed[lp][pp]
			t.Run(lp+"_to_"+pp, func(t *testing.T) {
				t.Parallel()
				e := newLsnEnv(t)
				poolID := e.seedPool(t, lsnTestTenant, e.lbBothID, pp)
				in := createListenerInput{
					LoadBalancerID:  e.lbBothID,
					Protocol:        lp,
					ProtocolPort:    lsnPtr(443),
					PortRangesValid: true,
					DefaultPoolID:   poolID,
				}
				if isTLSListenerProtocol(lp) {
					in.DefaultTLSContainerRef = e.serverCertID
				}
				got, err := e.svc.createListener(t.Context(), lsnTestTenant, in)
				if wantOK {
					if err != nil {
						t.Fatalf("expected allowed pairing %s->%s, got err: %v", lp, pp, err)
					}
					if got.DefaultPoolID != poolID {
						t.Fatalf("default_pool_id = %q, want %q", got.DefaultPoolID, poolID)
					}
				} else {
					if code := lsnCodeOf(err); code != "ELB.8902" {
						t.Fatalf("expected ELB.8902 for %s->%s, got %v", lp, pp, err)
					}
				}
			})
		}
	}
}

func TestListenerPoolOwnershipAndConflict(t *testing.T) {
	t.Parallel()
	e := newLsnEnv(t)
	ctx := t.Context()

	poolOtherLB := e.seedPool(t, lsnTestTenant, e.lbOther, "HTTP")
	poolSameLB := e.seedPool(t, lsnTestTenant, e.lbBothID, "HTTP")

	// Unknown pool -> ELB.8904.
	if _, err := e.svc.createListener(ctx, lsnTestTenant, createListenerInput{
		LoadBalancerID:  e.lbBothID,
		Protocol:        "HTTP",
		ProtocolPort:    lsnPtr(80),
		PortRangesValid: true,
		DefaultPoolID:   lsnUnknownUUID,
	}); lsnCodeOf(err) != "ELB.8904" {
		t.Fatalf("unknown pool: got %v, want ELB.8904", err)
	}

	// Pool on different LB -> ELB.8902.
	if _, err := e.svc.createListener(ctx, lsnTestTenant, createListenerInput{
		LoadBalancerID:  e.lbBothID,
		Protocol:        "HTTP",
		ProtocolPort:    lsnPtr(80),
		PortRangesValid: true,
		DefaultPoolID:   poolOtherLB,
	}); lsnCodeOf(err) != "ELB.8902" {
		t.Fatalf("other LB pool: got %v, want ELB.8902", err)
	}

	// First listener claims poolSameLB -> ok.
	l1, err := e.svc.createListener(ctx, lsnTestTenant, createListenerInput{
		LoadBalancerID:  e.lbBothID,
		Protocol:        "HTTP",
		ProtocolPort:    lsnPtr(80),
		PortRangesValid: true,
		DefaultPoolID:   poolSameLB,
	})
	if err != nil {
		t.Fatalf("l1 create: %v", err)
	}

	// Second listener trying to claim same pool -> ELB.8907.
	if _, err := e.svc.createListener(ctx, lsnTestTenant, createListenerInput{
		LoadBalancerID:  e.lbBothID,
		Protocol:        "HTTP",
		ProtocolPort:    lsnPtr(81),
		PortRangesValid: true,
		DefaultPoolID:   poolSameLB,
	}); lsnCodeOf(err) != "ELB.8907" {
		t.Fatalf("duplicate default_pool_id: got %v, want ELB.8907", err)
	}

	// Re-saving same pool on l1 via update -> ok.
	if _, err := e.svc.updateListener(ctx, lsnTestTenant, l1.ID, updateListenerInput{
		DefaultPoolIDSet: true,
		DefaultPoolID:    poolSameLB,
	}); err != nil {
		t.Fatalf("re-save same pool on l1: %v", err)
	}
}

func TestListenerPortConflictsPerFamily(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		firstProto string
		firstPort  *int
		firstRange []portRange
		nextProto  string
		nextPort   *int
		nextRange  []portRange
		sameLB     bool
		wantCode   string
	}{
		{"TCP vs HTTP same port conflicts", "TCP", lsnPtr(80), nil, "HTTP", lsnPtr(80), nil, true, "ELB.8907"},
		{"HTTP vs HTTPS same port conflicts", "HTTP", lsnPtr(443), nil, "HTTPS", lsnPtr(443), nil, true, "ELB.8907"},
		{"HTTPS vs TLS same port conflicts", "HTTPS", lsnPtr(8443), nil, "TLS", lsnPtr(8443), nil, true, "ELB.8907"},
		{"UDP vs QUIC same port conflicts", "UDP", lsnPtr(443), nil, "QUIC", lsnPtr(443), nil, true, "ELB.8907"},
		{"TCP vs UDP same port allowed", "TCP", lsnPtr(53), nil, "UDP", lsnPtr(53), nil, true, ""},
		{"HTTPS vs QUIC same port allowed", "HTTPS", lsnPtr(443), nil, "QUIC", lsnPtr(443), nil, true, ""},
		{"same port on different LB allowed", "TCP", lsnPtr(80), nil, "TCP", lsnPtr(80), nil, false, ""},
		{"TCP port range conflicts with HTTP single port", "TCP", nil, []portRange{{1000, 2000}}, "HTTP", lsnPtr(1500), nil, true, "ELB.8907"},
		{"TCP port range conflicts with overlapping TLS range", "TCP", nil, []portRange{{1000, 2000}}, "TLS", nil, []portRange{{2000, 3000}}, true, "ELB.8907"},
		{"TCP port range does not conflict with adjacent range", "TCP", nil, []portRange{{1000, 2000}}, "TLS", nil, []portRange{{2001, 3000}}, true, ""},
		{"TCP port range does not conflict with UDP same range", "TCP", nil, []portRange{{1000, 2000}}, "UDP", nil, []portRange{{1000, 2000}}, true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newLsnEnv(t)
			ctx := t.Context()

			in1 := createListenerInput{
				LoadBalancerID:  e.lbBothID,
				Protocol:        tc.firstProto,
				ProtocolPort:    tc.firstPort,
				PortRanges:      tc.firstRange,
				PortRangesValid: true,
			}
			if isTLSListenerProtocol(tc.firstProto) {
				in1.DefaultTLSContainerRef = e.serverCertID
			}
			if _, err := e.svc.createListener(ctx, lsnTestTenant, in1); err != nil {
				t.Fatalf("first create: %v", err)
			}

			lb2 := e.lbOther
			if tc.sameLB {
				lb2 = e.lbBothID
			}
			in2 := createListenerInput{
				LoadBalancerID:  lb2,
				Protocol:        tc.nextProto,
				ProtocolPort:    tc.nextPort,
				PortRanges:      tc.nextRange,
				PortRangesValid: true,
			}
			if isTLSListenerProtocol(tc.nextProto) {
				in2.DefaultTLSContainerRef = e.serverCertID
			}
			_, err := e.svc.createListener(ctx, lsnTestTenant, in2)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("second create: unexpected err %v", err)
				}
				return
			}
			if code := lsnCodeOf(err); code != tc.wantCode {
				t.Fatalf("second create: got %v (code %q), want %q", err, code, tc.wantCode)
			}
		})
	}
}

func TestListenerTLSAndSecurityPolicyValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		modify   func(e *lsnEnv, in *createListenerInput)
		wantCode string
	}{
		{
			name: "HTTPS missing default_tls_container_ref",
			modify: func(_ *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTPS"
			},
			wantCode: "ELB.8902",
		},
		{
			name: "HTTPS unknown cert",
			modify: func(_ *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTPS"
				in.DefaultTLSContainerRef = lsnUnknownUUID
			},
			wantCode: "ELB.8904",
		},
		{
			name: "HTTPS client cert as server cert rejected",
			modify: func(e *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTPS"
				in.DefaultTLSContainerRef = e.clientCertID
			},
			wantCode: "ELB.8902",
		},
		{
			name: "HTTPS server cert as client CA rejected",
			modify: func(e *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTPS"
				in.DefaultTLSContainerRef = e.serverCertID
				in.ClientCATLSContainerRef = e.serverCert2
			},
			wantCode: "ELB.8902",
		},
		{
			name: "HTTPS client cert in SNI refs rejected",
			modify: func(e *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTPS"
				in.DefaultTLSContainerRef = e.serverCertID
				in.SNIContainerRefs = []string{e.clientCertID}
			},
			wantCode: "ELB.8902",
		},
		{
			name: "HTTPS both tls_ciphers_policy and security_policy_id rejected",
			modify: func(e *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTPS"
				in.DefaultTLSContainerRef = e.serverCertID
				in.TLSCiphersPolicy = "tls-1-2"
				in.SecurityPolicyID = e.secPolID
			},
			wantCode: "ELB.8902",
		},
		{
			name: "HTTPS invalid system policy rejected",
			modify: func(e *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTPS"
				in.DefaultTLSContainerRef = e.serverCertID
				in.TLSCiphersPolicy = "not-a-policy"
			},
			wantCode: "ELB.8902",
		},
		{
			name: "HTTPS unknown custom security policy",
			modify: func(e *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTPS"
				in.DefaultTLSContainerRef = e.serverCertID
				in.SecurityPolicyID = lsnUnknownUUID
			},
			wantCode: "ELB.8904",
		},
		{
			name: "HTTP with default_tls_container_ref rejected",
			modify: func(e *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTP"
				in.DefaultTLSContainerRef = e.serverCertID
			},
			wantCode: "ELB.8902",
		},
		{
			name: "TCP with tls_ciphers_policy rejected",
			modify: func(_ *lsnEnv, in *createListenerInput) {
				in.Protocol = "TCP"
				in.TLSCiphersPolicy = "tls-1-2"
			},
			wantCode: "ELB.8902",
		},
		{
			name: "UDP with security_policy_id rejected",
			modify: func(e *lsnEnv, in *createListenerInput) {
				in.Protocol = "UDP"
				in.SecurityPolicyID = e.secPolID
			},
			wantCode: "ELB.8902",
		},
		{
			name: "HTTPS valid with custom security policy, SNI, and client CA",
			modify: func(e *lsnEnv, in *createListenerInput) {
				in.Protocol = "HTTPS"
				in.DefaultTLSContainerRef = e.serverCertID
				in.SNIContainerRefs = []string{e.serverCert2}
				in.ClientCATLSContainerRef = e.clientCertID
				in.SecurityPolicyID = e.secPolID
			},
			wantCode: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newLsnEnv(t)
			in := createListenerInput{
				LoadBalancerID:  e.lbBothID,
				ProtocolPort:    lsnPtr(443),
				PortRangesValid: true,
			}
			tc.modify(e, &in)
			got, err := e.svc.createListener(t.Context(), lsnTestTenant, in)
			if tc.wantCode != "" {
				if code := lsnCodeOf(err); code != tc.wantCode {
					t.Fatalf("got err %v (code %q), want %q", err, code, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got.SecurityPolicyID != e.secPolID || got.TLSCiphersPolicy != "" {
				t.Fatalf("policy mismatch: sp=%q ciphers=%q", got.SecurityPolicyID, got.TLSCiphersPolicy)
			}
		})
	}
}

func TestListenerDeleteRefusedAndForceDelete(t *testing.T) {
	t.Parallel()
	e := newLsnEnv(t)
	ctx := t.Context()

	poolID := e.seedPool(t, lsnTestTenant, e.lbBothID, "HTTP")
	l, err := e.svc.createListener(ctx, lsnTestTenant, createListenerInput{
		LoadBalancerID:  e.lbBothID,
		Name:            "http-80",
		Protocol:        "HTTP",
		ProtocolPort:    lsnPtr(80),
		PortRangesValid: true,
		DefaultPoolID:   poolID,
	})
	if err != nil {
		t.Fatalf("createListener: %v", err)
	}

	// Refused while default_pool_id is set.
	if err := e.svc.deleteListener(ctx, lsnTestTenant, l.ID); lsnCodeOf(err) != "ELB.8907" {
		t.Fatalf("delete with pool: got %v, want ELB.8907", err)
	}

	// Also attach an L7 policy with a rule.
	polID, ruleID := e.seedL7PolicyWithRule(t, lsnTestTenant, l.ID, "")

	// Unbind pool: delete still refused because of L7 policy.
	if _, err := e.svc.updateListener(ctx, lsnTestTenant, l.ID, updateListenerInput{
		DefaultPoolIDSet: true,
		DefaultPoolID:    "",
	}); err != nil {
		t.Fatalf("unbind pool: %v", err)
	}
	if err := e.svc.deleteListener(ctx, lsnTestTenant, l.ID); lsnCodeOf(err) != "ELB.8907" {
		t.Fatalf("delete with l7policy: got %v, want ELB.8907", err)
	}

	// Rebind pool, then force delete: deletes policy + rule + listener, leaves pool intact.
	if _, err := e.svc.updateListener(ctx, lsnTestTenant, l.ID, updateListenerInput{
		DefaultPoolIDSet: true,
		DefaultPoolID:    poolID,
	}); err != nil {
		t.Fatalf("rebind pool: %v", err)
	}
	if err := e.svc.deleteListenerForce(ctx, lsnTestTenant, l.ID); err != nil {
		t.Fatalf("deleteListenerForce: %v", err)
	}

	if _, err := e.svc.listeners(lsnTestTenant).Get(ctx, l.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("listener still exists: %v", err)
	}
	if _, err := e.svc.l7Policies(lsnTestTenant).Get(ctx, polID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("l7Policy still exists: %v", err)
	}
	if _, err := e.svc.l7Rules(lsnTestTenant).Get(ctx, ruleID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("l7Rule still exists: %v", err)
	}
	if _, err := e.svc.pools(lsnTestTenant).Get(ctx, poolID); err != nil {
		t.Fatalf("pool should remain after force delete: %v", err)
	}
}

func TestListenerConcurrentPortCreation(t *testing.T) {
	t.Parallel()
	e := newLsnEnv(t)
	ctx := t.Context()

	// 8 goroutines racing to create listeners on one LB across 2 overlapping ports (§7).
	const workers = 8
	ports := []int{8080, 8081}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		winsByP   = make(map[int]int)
		conflicts = 0
		otherErrs []error
	)

	start := make(chan struct{})
	for i := range workers {
		port := ports[i%len(ports)]
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			<-start
			proto := "TCP"
			if idx%2 == 1 {
				proto = "HTTP"
			}
			_, err := e.svc.createListener(ctx, lsnTestTenant, createListenerInput{
				LoadBalancerID:  e.lbBothID,
				Name:            fmt.Sprintf("race-%d", idx),
				Protocol:        proto,
				ProtocolPort:    lsnPtr(p),
				PortRangesValid: true,
			})
			mu.Lock()
			defer mu.Unlock()
			switch lsnCodeOf(err) {
			case "":
				winsByP[p]++
			case "ELB.8907":
				conflicts++
			default:
				otherErrs = append(otherErrs, err)
			}
		}(i, port)
	}
	close(start)
	wg.Wait()

	if len(otherErrs) > 0 {
		t.Fatalf("unexpected errors: %v", otherErrs)
	}
	for _, p := range ports {
		if winsByP[p] != 1 {
			t.Fatalf("port %d: wins = %d, want exactly 1", p, winsByP[p])
		}
	}
	if conflicts != workers-len(ports) {
		t.Fatalf("conflicts = %d, want %d", conflicts, workers-len(ports))
	}
}

func TestListenerListPaginationAndTenantIsolation(t *testing.T) {
	t.Parallel()
	e := newLsnEnv(t)
	ctx := t.Context()

	lbB := e.seedLB(t, lsnTestTenantB, "lb-b", "l4-flv", "l7-flv", defaultEnterpriseProjectID)
	if _, err := e.svc.createListener(ctx, lsnTestTenantB, createListenerInput{
		LoadBalancerID:  lbB,
		Name:            "tenant-b-lsn",
		Protocol:        "TCP",
		ProtocolPort:    lsnPtr(80),
		PortRangesValid: true,
	}); err != nil {
		t.Fatalf("tenant B create: %v", err)
	}

	var createdIDs []string
	for p := 8001; p <= 8005; p++ {
		l, err := e.svc.createListener(ctx, lsnTestTenant, createListenerInput{
			LoadBalancerID:  e.lbBothID,
			Name:            fmt.Sprintf("lsn-%d", p),
			Protocol:        "TCP",
			ProtocolPort:    lsnPtr(p),
			PortRangesValid: true,
		})
		if err != nil {
			t.Fatalf("create %d: %v", p, err)
		}
		createdIDs = append(createdIDs, l.ID)
	}

	// Page through 2 at a time and verify ascending ID order + complete coverage.
	var seen []string
	marker := ""
	for {
		page, pi, err := e.svc.listListeners(ctx, lsnTestTenant, listListenersFilter{
			Page: pagination.Marker{ID: marker, Limit: 2},
		})
		if err != nil {
			t.Fatalf("list page marker=%q: %v", marker, err)
		}
		for _, l := range page {
			seen = append(seen, l.ID)
		}
		if pi.NextMarker == nil {
			break
		}
		marker = *pi.NextMarker
	}
	if len(seen) != len(createdIDs) {
		t.Fatalf("paginated count = %d, want %d", len(seen), len(createdIDs))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("not sorted ascending: %v", seen)
		}
	}

	// Tenant A cannot view tenant B's listener.
	if _, err := e.svc.getListener(ctx, lsnTestTenantB, createdIDs[0]); lsnCodeOf(err) != "ELB.8904" {
		t.Fatalf("cross-tenant get: got %v, want ELB.8904", err)
	}
}
