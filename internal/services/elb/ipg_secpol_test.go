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
	"slices"
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
	ipgspTestProject  = "0123456789abcdef0123456789abcdef"
	ipgspTestProjectB = "fedcba9876543210fedcba9876543210"
	ipgspTestRegion   = "ap-southeast-1"
	ipgspTestHost     = "elb." + ipgspTestRegion + ".myhuaweicloud.com"
	ipgspUnknownUUID  = "00000000-0000-4000-8000-000000000000"
	ipgspCustomEP     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

var (
	ipgspTestTenant  = Tenant{Region: ipgspTestRegion, ProjectID: ipgspTestProject}
	ipgspTestTenantB = Tenant{Region: ipgspTestRegion, ProjectID: ipgspTestProjectB}
	ipgspTestEpoch   = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
)

type ipgspStubNetwork struct{}

func (ipgspStubNetwork) GetVPC(context.Context, vpc.Tenant, string) (vpc.VPC, error) {
	return vpc.VPC{}, errors.New("unexpected GetVPC")
}
func (ipgspStubNetwork) GetSubnet(context.Context, vpc.Tenant, string) (vpc.Subnet, error) {
	return vpc.Subnet{}, errors.New("unexpected GetSubnet")
}
func (ipgspStubNetwork) ListSubnets(context.Context, vpc.Tenant, vpc.ListSubnetsFilter) ([]vpc.Subnet, error) {
	return nil, nil
}
func (ipgspStubNetwork) AllocateIP(context.Context, vpc.Tenant, string, string, string) (string, error) {
	return "", errors.New("unexpected AllocateIP")
}
func (ipgspStubNetwork) ReleaseIP(context.Context, vpc.Tenant, string, string) error {
	return nil
}

type ipgspStubPublicIPs struct{}

func (ipgspStubPublicIPs) BindToELB(context.Context, vpc.Tenant, string, string, string, string) (string, error) {
	return "", errors.New("unexpected BindToELB")
}
func (ipgspStubPublicIPs) CreateForELB(context.Context, vpc.Tenant, string, string, string, eip.ServerIP) (string, string, error) {
	return "", "", errors.New("unexpected CreateForELB")
}
func (ipgspStubPublicIPs) UnbindFromELB(context.Context, vpc.Tenant, string, string) error {
	return nil
}
func (ipgspStubPublicIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type ipgspStubServers struct{}

func (ipgspStubServers) ServerAt(context.Context, vpc.Tenant, string, string, string) (string, bool, error) {
	return "", false, nil
}

type ipgspEnv struct {
	svc     *Service
	store   store.Store
	clock   *lifecycle.FakeClock
	handler http.Handler

	lbID         string
	serverCertID string
}

func newIPGSPEnv(t *testing.T) *ipgspEnv {
	t.Helper()
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(ipgspTestEpoch)
	gen := ids.NewSeeded(77)

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
		VPC:     ipgspStubNetwork{},
		EIPs:    ipgspStubPublicIPs{},
		Servers: ipgspStubServers{},
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
		ProjectID: ipgspTestProject,
		Logger:    log,
		Store:     st,
		Engine:    engine,
		IDs:       gen,
		Services:  []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	e := &ipgspEnv{
		svc:     svc,
		store:   st,
		clock:   clock,
		handler: srv.Handler(),
	}
	e.lbID = e.seedLB(t, ipgspTestTenant, "lb-main")
	e.serverCertID = e.seedServerCert(t, ipgspTestTenant, "srv-cert-1")
	return e
}

func (e *ipgspEnv) seedLB(t *testing.T, tenant Tenant, name string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	lb := loadBalancer{
		ID:                  id,
		Name:                name,
		AdminStateUp:        true,
		L4FlavorID:          "l4-flv",
		L7FlavorID:          "l7-flv",
		EnterpriseProjectID: defaultEnterpriseProjectID,
		CreatedAt:           ipgspTestEpoch,
		UpdatedAt:           ipgspTestEpoch,
	}
	if err := e.svc.loadBalancers(tenant).Create(t.Context(), id, lb); err != nil {
		t.Fatalf("seedLB %s: %v", name, err)
	}
	return id
}

func (e *ipgspEnv) seedServerCert(t *testing.T, tenant Tenant, name string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	c := certificate{
		ID:           id,
		Name:         name,
		Type:         "server",
		AdminStateUp: true,
		CreatedAt:    ipgspTestEpoch,
		UpdatedAt:    ipgspTestEpoch,
	}
	if err := e.svc.certificates(tenant).Create(t.Context(), id, c); err != nil {
		t.Fatalf("seedServerCert %s: %v", name, err)
	}
	return id
}

func (e *ipgspEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callAs(t, ipgspTestProject, method, path, body)
}

func (e *ipgspEnv) callAs(t *testing.T, project, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v3/"+project+"/elb"+path, rd)
	r.Host = ipgspTestHost
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

func (e *ipgspEnv) expect(t *testing.T, dir, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", dir, goldenName+".json"), status, out)
	return out
}

func ipgspPtr[T any](v T) *T { return &v }

func ipgspDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func ipgspCodeOf(err error) string {
	if err == nil {
		return ""
	}
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return err.Error()
}

func TestIPGroupIPValidationAndCanonicalization(t *testing.T) {
	t.Parallel()

	longStr := strings.Repeat("a", 256)
	tests := []struct {
		name     string
		in       ipgCreateInput
		wantIPs  []string
		wantCode string
	}{
		{
			name: "valid single IPv4 and canonical CIDRs",
			in: ipgCreateInput{
				Name:      "valid-group",
				IPListSet: true,
				IPList: []ipInfo{
					{IP: "192.168.1.123", Description: "host"},
					{IP: "192.168.3.0/24", Description: "subnet"},
					{IP: "0.0.0.0/0", Description: "all"},
					{IP: "10.1.2.3/32", Description: "single cidr"},
				},
			},
			wantIPs: []string{"192.168.1.123", "192.168.3.0/24", "0.0.0.0/0", "10.1.2.3/32"},
		},
		{
			name: "empty ip_list allowed",
			in: ipgCreateInput{
				Name:      "empty-group",
				IPListSet: true,
				IPList:    []ipInfo{},
			},
			wantIPs: []string{},
		},
		{
			name: "missing ip_list rejected",
			in: ipgCreateInput{
				Name:      "no-list",
				IPListSet: false,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "non-canonical CIDR with host bits set rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "192.168.3.1/24"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "non-canonical /0 CIDR rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "10.0.0.1/0"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "IPv6 address rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "2001:db8::1"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "IPv6 CIDR rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "2001:db8::/32"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "IPv4-mapped IPv6 rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "::ffff:192.168.1.1"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "IP range rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "192.168.1.1-192.168.1.10"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid IP string rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "not-an-ip"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "empty IP string rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: ""}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "CIDR prefix out of range rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "10.0.0.0/33"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "leading zero IP rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "10.0.0.01"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "duplicate IPv4 address rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "10.0.0.1"}, {IP: "10.0.0.1"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "duplicate CIDR rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "10.0.0.0/24"}, {IP: "10.0.0.0/24"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "duplicate IPv4 and /32 CIDR rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "10.0.0.1"}, {IP: "10.0.0.1/32"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "entry description too long rejected",
			in: ipgCreateInput{
				IPListSet: true,
				IPList:    []ipInfo{{IP: "10.0.0.1", Description: longStr}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "group name too long rejected",
			in: ipgCreateInput{
				Name:      longStr,
				IPListSet: true,
				IPList:    []ipInfo{{IP: "10.0.0.1"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "group description too long rejected",
			in: ipgCreateInput{
				Description: longStr,
				IPListSet:   true,
				IPList:      []ipInfo{{IP: "10.0.0.1"}},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "empty enterprise_project_id rejected",
			in: ipgCreateInput{
				IPListSet:           true,
				IPList:              []ipInfo{{IP: "10.0.0.1"}},
				EnterpriseProjectID: ipgspPtr(""),
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid enterprise_project_id rejected",
			in: ipgCreateInput{
				IPListSet:           true,
				IPList:              []ipInfo{{IP: "10.0.0.1"}},
				EnterpriseProjectID: ipgspPtr("not-a-uuid"),
			},
			wantCode: "ELB.8902",
		},
		{
			name: "valid UUID enterprise_project_id accepted",
			in: ipgCreateInput{
				IPListSet:           true,
				IPList:              []ipInfo{{IP: "10.0.0.1"}},
				EnterpriseProjectID: ipgspPtr(ipgspCustomEP),
			},
			wantIPs: []string{"10.0.0.1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newIPGSPEnv(t)
			got, err := e.svc.createIPGroup(t.Context(), ipgspTestTenant, tc.in)
			if tc.wantCode != "" {
				if code := ipgspCodeOf(err); code != tc.wantCode {
					t.Fatalf("createIPGroup() err = %v (code %q), want %q", err, code, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("createIPGroup() unexpected error: %v", err)
			}
			gotIPs := make([]string, len(got.Group.IPList))
			for i, entry := range got.Group.IPList {
				gotIPs[i] = entry.IP
			}
			if !slices.Equal(gotIPs, tc.wantIPs) {
				t.Fatalf("IPList = %v, want %v", gotIPs, tc.wantIPs)
			}
		})
	}
}

func TestIPGroupUpdatePaginationAndIsolation(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	g1, err := e.svc.createIPGroup(t.Context(), ipgspTestTenant, ipgCreateInput{
		Name:        "g1",
		Description: "first",
		IPListSet:   true,
		IPList:      []ipInfo{{IP: "10.0.0.1", Description: "a"}},
	})
	if err != nil {
		t.Fatalf("create g1: %v", err)
	}
	e.clock.Advance(5 * time.Second)

	// Name-only update preserves description and ip_list, advances updated_at.
	u1, err := e.svc.updateIPGroup(t.Context(), ipgspTestTenant, g1.Group.ID, ipgUpdateInput{
		Name: ipgspPtr("g1-renamed"),
	})
	if err != nil {
		t.Fatalf("update g1 name: %v", err)
	}
	if u1.Group.Name != "g1-renamed" || u1.Group.Description != "first" || len(u1.Group.IPList) != 1 || u1.Group.IPList[0].IP != "10.0.0.1" {
		t.Fatalf("unexpected after name update: %+v", u1.Group)
	}
	if !u1.Group.UpdatedAt.After(u1.Group.CreatedAt) {
		t.Fatalf("expected UpdatedAt > CreatedAt: %+v", u1.Group)
	}

	// Replace ip_list with empty slice clears entries.
	empty := []ipInfo{}
	u2, err := e.svc.updateIPGroup(t.Context(), ipgspTestTenant, g1.Group.ID, ipgUpdateInput{
		IPList: &empty,
	})
	if err != nil {
		t.Fatalf("clear ip_list: %v", err)
	}
	if len(u2.Group.IPList) != 0 {
		t.Fatalf("expected empty IPList, got %+v", u2.Group.IPList)
	}

	// Invalid ip_list update fails with ELB.8902.
	bad := []ipInfo{{IP: "192.168.1.5/24"}}
	if _, err := e.svc.updateIPGroup(t.Context(), ipgspTestTenant, g1.Group.ID, ipgUpdateInput{IPList: &bad}); ipgspCodeOf(err) != "ELB.8902" {
		t.Fatalf("bad update err = %v, want ELB.8902", err)
	}

	// Cross-tenant isolation.
	if _, err := e.svc.getIPGroup(t.Context(), ipgspTestTenantB, g1.Group.ID); ipgspCodeOf(err) != "ELB.8904" {
		t.Fatalf("cross-tenant get err = %v, want ELB.8904", err)
	}
	if err := e.svc.deleteIPGroup(t.Context(), ipgspTestTenantB, g1.Group.ID); ipgspCodeOf(err) != "ELB.8904" {
		t.Fatalf("cross-tenant delete err = %v, want ELB.8904", err)
	}

	// Seed two more groups and check ascending ID order + marker/limit pagination.
	g2, err := e.svc.createIPGroup(t.Context(), ipgspTestTenant, ipgCreateInput{
		Name:                "g2",
		IPListSet:           true,
		IPList:              []ipInfo{{IP: "10.0.1.0/24"}},
		EnterpriseProjectID: ipgspPtr(ipgspCustomEP),
	})
	if err != nil {
		t.Fatalf("create g2: %v", err)
	}
	g3, err := e.svc.createIPGroup(t.Context(), ipgspTestTenant, ipgCreateInput{
		Name:      "g3",
		IPListSet: true,
		IPList:    []ipInfo{{IP: "10.0.2.0/24"}},
	})
	if err != nil {
		t.Fatalf("create g3: %v", err)
	}

	wantOrder := []string{g1.Group.ID, g2.Group.ID, g3.Group.ID}
	slices.Sort(wantOrder)

	page1, pi1, err := e.svc.listIPGroups(t.Context(), ipgspTestTenant, ipgListFilter{
		Page: pagination.Marker{Limit: 2},
	})
	if err != nil {
		t.Fatalf("list page 1: %v", err)
	}
	if len(page1) != 2 || pi1.CurrentCount != 2 || pi1.NextMarker == nil || *pi1.NextMarker != wantOrder[1] || pi1.PreviousMarker != wantOrder[0] {
		t.Fatalf("unexpected page 1: items=%+v pi=%+v", page1, pi1)
	}

	page2, pi2, err := e.svc.listIPGroups(t.Context(), ipgspTestTenant, ipgListFilter{
		Page: pagination.Marker{ID: *pi1.NextMarker, Limit: 2},
	})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(page2) != 1 || page2[0].Group.ID != wantOrder[2] || pi2.NextMarker != nil || pi2.CurrentCount != 1 {
		t.Fatalf("unexpected page 2: items=%+v pi=%+v", page2, pi2)
	}
}

func TestSecurityPolicyProtocolAndCipherValidation(t *testing.T) {
	t.Parallel()

	longStr := strings.Repeat("x", 256)
	tests := []struct {
		name     string
		in       secpolCreateInput
		wantCode string
	}{
		{
			name: "all valid protocols and mixed TLS 1.2 + 1.3 ciphers",
			in: secpolCreateInput{
				Name:      "modern-and-compat",
				Protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
				Ciphers: []string{
					"ECDHE-RSA-AES128-GCM-SHA256",
					"TLS_AES_128_GCM_SHA256",
					"TLS_CHACHA20_POLY1305_SHA256",
					"TLS_AES_128_CCM_8_SHA256",
				},
			},
		},
		{
			name: "valid UUID enterprise_project_id",
			in: secpolCreateInput{
				Name:                "ep-policy",
				Protocols:           []string{"TLSv1.2"},
				Ciphers:             []string{"AES128-SHA"},
				EnterpriseProjectID: ipgspPtr(ipgspCustomEP),
			},
		},
		{
			name: "empty protocols rejected",
			in: secpolCreateInput{
				Protocols: []string{},
				Ciphers:   []string{"AES128-SHA"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "nil protocols rejected",
			in: secpolCreateInput{
				Ciphers: []string{"AES128-SHA"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid protocol rejected",
			in: secpolCreateInput{
				Protocols: []string{"SSLv3"},
				Ciphers:   []string{"AES128-SHA"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "duplicate protocol rejected",
			in: secpolCreateInput{
				Protocols: []string{"TLSv1.2", "TLSv1.2"},
				Ciphers:   []string{"AES128-SHA"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "empty ciphers rejected",
			in: secpolCreateInput{
				Protocols: []string{"TLSv1.2"},
				Ciphers:   []string{},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "nil ciphers rejected",
			in: secpolCreateInput{
				Protocols: []string{"TLSv1.2"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "unknown cipher rejected",
			in: secpolCreateInput{
				Protocols: []string{"TLSv1.2"},
				Ciphers:   []string{"NOT-A-REAL-CIPHER"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "duplicate cipher rejected",
			in: secpolCreateInput{
				Protocols: []string{"TLSv1.2"},
				Ciphers:   []string{"AES128-SHA", "AES128-SHA"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "name too long rejected",
			in: secpolCreateInput{
				Name:      longStr,
				Protocols: []string{"TLSv1.2"},
				Ciphers:   []string{"AES128-SHA"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "description too long rejected",
			in: secpolCreateInput{
				Description: longStr,
				Protocols:   []string{"TLSv1.2"},
				Ciphers:     []string{"AES128-SHA"},
			},
			wantCode: "ELB.8902",
		},
		{
			name: "empty enterprise_project_id rejected",
			in: secpolCreateInput{
				Protocols:           []string{"TLSv1.2"},
				Ciphers:             []string{"AES128-SHA"},
				EnterpriseProjectID: ipgspPtr(""),
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid enterprise_project_id rejected",
			in: secpolCreateInput{
				Protocols:           []string{"TLSv1.2"},
				Ciphers:             []string{"AES128-SHA"},
				EnterpriseProjectID: ipgspPtr("bad-ep"),
			},
			wantCode: "ELB.8902",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newIPGSPEnv(t)
			got, err := e.svc.createSecurityPolicy(t.Context(), ipgspTestTenant, tc.in)
			if tc.wantCode != "" {
				if code := ipgspCodeOf(err); code != tc.wantCode {
					t.Fatalf("createSecurityPolicy() err = %v (code %q), want %q", err, code, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("createSecurityPolicy() unexpected error: %v", err)
			}
			if !slices.Equal(got.Policy.Protocols, tc.in.Protocols) || !slices.Equal(got.Policy.Ciphers, tc.in.Ciphers) {
				t.Fatalf("got protocols=%v ciphers=%v", got.Policy.Protocols, got.Policy.Ciphers)
			}
		})
	}
}

func TestSecurityPolicyUpdatePaginationAndIsolation(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	sp1, err := e.svc.createSecurityPolicy(t.Context(), ipgspTestTenant, secpolCreateInput{
		Name:        "sp-1",
		Description: "desc-1",
		Protocols:   []string{"TLSv1.2"},
		Ciphers:     []string{"ECDHE-RSA-AES128-GCM-SHA256"},
	})
	if err != nil {
		t.Fatalf("create sp1: %v", err)
	}
	e.clock.Advance(5 * time.Second)

	// Partial update preserves protocols and ciphers.
	u1, err := e.svc.updateSecurityPolicy(t.Context(), ipgspTestTenant, sp1.Policy.ID, secpolUpdateInput{
		Name: ipgspPtr("sp-1-updated"),
	})
	if err != nil {
		t.Fatalf("update sp1: %v", err)
	}
	if u1.Policy.Name != "sp-1-updated" || u1.Policy.Description != "desc-1" || !slices.Equal(u1.Policy.Protocols, []string{"TLSv1.2"}) {
		t.Fatalf("unexpected after partial update: %+v", u1.Policy)
	}
	if !u1.Policy.UpdatedAt.After(u1.Policy.CreatedAt) {
		t.Fatalf("expected UpdatedAt > CreatedAt")
	}

	// Reject empty protocols / ciphers on update.
	empty := []string{}
	if _, err := e.svc.updateSecurityPolicy(t.Context(), ipgspTestTenant, sp1.Policy.ID, secpolUpdateInput{Protocols: &empty}); ipgspCodeOf(err) != "ELB.8902" {
		t.Fatalf("empty protocols update err = %v, want ELB.8902", err)
	}
	if _, err := e.svc.updateSecurityPolicy(t.Context(), ipgspTestTenant, sp1.Policy.ID, secpolUpdateInput{Ciphers: &empty}); ipgspCodeOf(err) != "ELB.8902" {
		t.Fatalf("empty ciphers update err = %v, want ELB.8902", err)
	}

	// Cross-tenant isolation.
	if _, err := e.svc.getSecurityPolicy(t.Context(), ipgspTestTenantB, sp1.Policy.ID); ipgspCodeOf(err) != "ELB.8904" {
		t.Fatalf("cross-tenant get err = %v, want ELB.8904", err)
	}
	if err := e.svc.deleteSecurityPolicy(t.Context(), ipgspTestTenantB, sp1.Policy.ID); ipgspCodeOf(err) != "ELB.8904" {
		t.Fatalf("cross-tenant delete err = %v, want ELB.8904", err)
	}

	sp2, err := e.svc.createSecurityPolicy(t.Context(), ipgspTestTenant, secpolCreateInput{
		Name:                "sp-2",
		Protocols:           []string{"TLSv1.2", "TLSv1.3"},
		Ciphers:             []string{"AES128-SHA", "TLS_AES_128_GCM_SHA256"},
		EnterpriseProjectID: ipgspPtr(ipgspCustomEP),
	})
	if err != nil {
		t.Fatalf("create sp2: %v", err)
	}
	sp3, err := e.svc.createSecurityPolicy(t.Context(), ipgspTestTenant, secpolCreateInput{
		Name:      "sp-3",
		Protocols: []string{"TLSv1.3"},
		Ciphers:   []string{"TLS_AES_256_GCM_SHA384"},
	})
	if err != nil {
		t.Fatalf("create sp3: %v", err)
	}

	wantOrder := []string{sp1.Policy.ID, sp2.Policy.ID, sp3.Policy.ID}
	slices.Sort(wantOrder)

	p1, pi1, err := e.svc.listSecurityPolicies(t.Context(), ipgspTestTenant, secpolListFilter{
		Page: pagination.Marker{Limit: 2},
	})
	if err != nil {
		t.Fatalf("list page 1: %v", err)
	}
	if len(p1) != 2 || pi1.NextMarker == nil || *pi1.NextMarker != wantOrder[1] {
		t.Fatalf("unexpected page 1: %+v %+v", p1, pi1)
	}
	p2, pi2, err := e.svc.listSecurityPolicies(t.Context(), ipgspTestTenant, secpolListFilter{
		Page: pagination.Marker{ID: *pi1.NextMarker, Limit: 2},
	})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(p2) != 1 || p2[0].Policy.ID != wantOrder[2] || pi2.NextMarker != nil {
		t.Fatalf("unexpected page 2: %+v %+v", p2, pi2)
	}
}

func TestListenerIPGroupBindingAndDeleteGuard(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	ipg1, err := e.svc.createIPGroup(t.Context(), ipgspTestTenant, ipgCreateInput{
		Name:      "ipg-1",
		IPListSet: true,
		IPList:    []ipInfo{{IP: "10.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("create ipg1: %v", err)
	}
	ipg2, err := e.svc.createIPGroup(t.Context(), ipgspTestTenant, ipgCreateInput{
		Name:      "ipg-2",
		IPListSet: true,
		IPList:    []ipInfo{{IP: "10.0.1.0/24"}},
	})
	if err != nil {
		t.Fatalf("create ipg2: %v", err)
	}

	// Attaching an unknown IP group to a listener returns ELB.8904.
	if _, err := e.svc.createListener(t.Context(), ipgspTestTenant, createListenerInput{
		LoadBalancerID:  e.lbID,
		Protocol:        "HTTP",
		ProtocolPort:    ipgspPtr(8000),
		PortRangesValid: true,
		IPGroup: &listenerIPGroupInput{
			IPGroupID: ipgspPtr(ipgspUnknownUUID),
			Type:      ipgspPtr("white"),
		},
	}); ipgspCodeOf(err) != "ELB.8904" {
		t.Fatalf("create listener with unknown ipgroup err = %v, want ELB.8904", err)
	}

	// Listener 1 uses ipg1.
	l1, err := e.svc.createListener(t.Context(), ipgspTestTenant, createListenerInput{
		LoadBalancerID:  e.lbID,
		Name:            "http-1",
		Protocol:        "HTTP",
		ProtocolPort:    ipgspPtr(8081),
		PortRangesValid: true,
		IPGroup: &listenerIPGroupInput{
			IPGroupID:     ipgspPtr(ipg1.Group.ID),
			EnableIPGroup: ipgspPtr(true),
			Type:          ipgspPtr("white"),
		},
	})
	if err != nil {
		t.Fatalf("create l1: %v", err)
	}

	// Listener 2 uses comma-separated ipg1,ipg2.
	combined := ipg1.Group.ID + "," + ipg2.Group.ID
	l2, err := e.svc.createListener(t.Context(), ipgspTestTenant, createListenerInput{
		LoadBalancerID:  e.lbID,
		Name:            "http-2",
		Protocol:        "HTTP",
		ProtocolPort:    ipgspPtr(8082),
		PortRangesValid: true,
		IPGroup: &listenerIPGroupInput{
			IPGroupID:     ipgspPtr(combined),
			EnableIPGroup: ipgspPtr(true),
			Type:          ipgspPtr("black"),
		},
	})
	if err != nil {
		t.Fatalf("create l2: %v", err)
	}

	wantBoth := []string{l1.ID, l2.ID}
	slices.Sort(wantBoth)

	// Show IP group lists associated listeners in ascending ID order.
	got1, err := e.svc.getIPGroup(t.Context(), ipgspTestTenant, ipg1.Group.ID)
	if err != nil {
		t.Fatalf("get ipg1: %v", err)
	}
	if !slices.Equal(got1.ListenerIDs, wantBoth) {
		t.Fatalf("ipg1 listeners = %v, want %v", got1.ListenerIDs, wantBoth)
	}
	got2, err := e.svc.getIPGroup(t.Context(), ipgspTestTenant, ipg2.Group.ID)
	if err != nil {
		t.Fatalf("get ipg2: %v", err)
	}
	if !slices.Equal(got2.ListenerIDs, []string{l2.ID}) {
		t.Fatalf("ipg2 listeners = %v, want [%s]", got2.ListenerIDs, l2.ID)
	}

	// List IP groups also returns listener refs for every group.
	listed, _, err := e.svc.listIPGroups(t.Context(), ipgspTestTenant, ipgListFilter{})
	if err != nil {
		t.Fatalf("list ipgroups: %v", err)
	}
	byID := make(map[string][]string, len(listed))
	for _, item := range listed {
		byID[item.Group.ID] = item.ListenerIDs
	}
	if !slices.Equal(byID[ipg1.Group.ID], wantBoth) || !slices.Equal(byID[ipg2.Group.ID], []string{l2.ID}) {
		t.Fatalf("listed listeners mismatch: %+v", byID)
	}

	// Deleting either IP group while associated fails with ELB.8907.
	if err := e.svc.deleteIPGroup(t.Context(), ipgspTestTenant, ipg1.Group.ID); ipgspCodeOf(err) != "ELB.8907" {
		t.Fatalf("delete ipg1 while bound err = %v, want ELB.8907", err)
	}
	if err := e.svc.deleteIPGroup(t.Context(), ipgspTestTenant, ipg2.Group.ID); ipgspCodeOf(err) != "ELB.8907" {
		t.Fatalf("delete ipg2 while bound err = %v, want ELB.8907", err)
	}

	// Update l2 to only use ipg1 -> ipg2 is now free and deletable.
	if _, err := e.svc.updateListener(t.Context(), ipgspTestTenant, l2.ID, updateListenerInput{
		IPGroupSet: true,
		IPGroup: &listenerIPGroupInput{
			IPGroupID: ipgspPtr(ipg1.Group.ID),
		},
	}); err != nil {
		t.Fatalf("update l2 ipgroup: %v", err)
	}
	if err := e.svc.deleteIPGroup(t.Context(), ipgspTestTenant, ipg2.Group.ID); err != nil {
		t.Fatalf("delete detached ipg2: %v", err)
	}
	// ipg1 still bound to l1 and l2 -> ELB.8907.
	if err := e.svc.deleteIPGroup(t.Context(), ipgspTestTenant, ipg1.Group.ID); ipgspCodeOf(err) != "ELB.8907" {
		t.Fatalf("delete ipg1 still bound err = %v, want ELB.8907", err)
	}

	// Clear ipgroup on l1 and delete l2 -> ipg1 is free and deletable.
	if _, err := e.svc.updateListener(t.Context(), ipgspTestTenant, l1.ID, updateListenerInput{
		IPGroupSet: true,
		IPGroup:    nil,
	}); err != nil {
		t.Fatalf("clear l1 ipgroup: %v", err)
	}
	if err := e.svc.deleteListener(t.Context(), ipgspTestTenant, l2.ID); err != nil {
		t.Fatalf("delete l2: %v", err)
	}
	if err := e.svc.deleteIPGroup(t.Context(), ipgspTestTenant, ipg1.Group.ID); err != nil {
		t.Fatalf("delete detached ipg1: %v", err)
	}
}

func TestListenerSecurityPolicyBindingAndDeleteGuard(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	sp1, err := e.svc.createSecurityPolicy(t.Context(), ipgspTestTenant, secpolCreateInput{
		Name:      "sp-1",
		Protocols: []string{"TLSv1.2", "TLSv1.3"},
		Ciphers:   []string{"ECDHE-RSA-AES128-GCM-SHA256", "TLS_AES_128_GCM_SHA256"},
	})
	if err != nil {
		t.Fatalf("create sp1: %v", err)
	}
	sp2, err := e.svc.createSecurityPolicy(t.Context(), ipgspTestTenant, secpolCreateInput{
		Name:      "sp-2",
		Protocols: []string{"TLSv1.3"},
		Ciphers:   []string{"TLS_AES_256_GCM_SHA384"},
	})
	if err != nil {
		t.Fatalf("create sp2: %v", err)
	}

	// Non-TLS listener rejects security_policy_id with ELB.8902.
	if _, err := e.svc.createListener(t.Context(), ipgspTestTenant, createListenerInput{
		LoadBalancerID:   e.lbID,
		Protocol:         "HTTP",
		ProtocolPort:     ipgspPtr(80),
		PortRangesValid:  true,
		SecurityPolicyID: sp1.Policy.ID,
	}); ipgspCodeOf(err) != "ELB.8902" {
		t.Fatalf("HTTP listener with security_policy_id err = %v, want ELB.8902", err)
	}

	// HTTPS listener with unknown security_policy_id returns ELB.8904.
	if _, err := e.svc.createListener(t.Context(), ipgspTestTenant, createListenerInput{
		LoadBalancerID:         e.lbID,
		Protocol:               "HTTPS",
		ProtocolPort:           ipgspPtr(443),
		PortRangesValid:        true,
		DefaultTLSContainerRef: e.serverCertID,
		SecurityPolicyID:       ipgspUnknownUUID,
	}); ipgspCodeOf(err) != "ELB.8904" {
		t.Fatalf("HTTPS listener with unknown security_policy_id err = %v, want ELB.8904", err)
	}

	// Bind two HTTPS listeners to sp1.
	l1, err := e.svc.createListener(t.Context(), ipgspTestTenant, createListenerInput{
		LoadBalancerID:         e.lbID,
		Name:                   "https-1",
		Protocol:               "HTTPS",
		ProtocolPort:           ipgspPtr(443),
		PortRangesValid:        true,
		DefaultTLSContainerRef: e.serverCertID,
		SecurityPolicyID:       sp1.Policy.ID,
	})
	if err != nil {
		t.Fatalf("create https l1: %v", err)
	}
	l2, err := e.svc.createListener(t.Context(), ipgspTestTenant, createListenerInput{
		LoadBalancerID:         e.lbID,
		Name:                   "https-2",
		Protocol:               "HTTPS",
		ProtocolPort:           ipgspPtr(8443),
		PortRangesValid:        true,
		DefaultTLSContainerRef: e.serverCertID,
		SecurityPolicyID:       sp1.Policy.ID,
	})
	if err != nil {
		t.Fatalf("create https l2: %v", err)
	}

	wantBoth := []string{l1.ID, l2.ID}
	slices.Sort(wantBoth)

	got1, err := e.svc.getSecurityPolicy(t.Context(), ipgspTestTenant, sp1.Policy.ID)
	if err != nil {
		t.Fatalf("get sp1: %v", err)
	}
	if !slices.Equal(got1.ListenerIDs, wantBoth) {
		t.Fatalf("sp1 listeners = %v, want %v", got1.ListenerIDs, wantBoth)
	}

	// Delete refused while used (ELB.8907).
	if err := e.svc.deleteSecurityPolicy(t.Context(), ipgspTestTenant, sp1.Policy.ID); ipgspCodeOf(err) != "ELB.8907" {
		t.Fatalf("delete sp1 while in use err = %v, want ELB.8907", err)
	}

	// Move l1 to sp2.
	if _, err := e.svc.updateListener(t.Context(), ipgspTestTenant, l1.ID, updateListenerInput{
		SecurityPolicyIDSet: true,
		SecurityPolicyID:    sp2.Policy.ID,
	}); err != nil {
		t.Fatalf("move l1 to sp2: %v", err)
	}

	got1, err = e.svc.getSecurityPolicy(t.Context(), ipgspTestTenant, sp1.Policy.ID)
	if err != nil {
		t.Fatalf("get sp1 after move: %v", err)
	}
	got2, err := e.svc.getSecurityPolicy(t.Context(), ipgspTestTenant, sp2.Policy.ID)
	if err != nil {
		t.Fatalf("get sp2 after move: %v", err)
	}
	if !slices.Equal(got1.ListenerIDs, []string{l2.ID}) || !slices.Equal(got2.ListenerIDs, []string{l1.ID}) {
		t.Fatalf("after move: sp1=%v sp2=%v", got1.ListenerIDs, got2.ListenerIDs)
	}
	if err := e.svc.deleteSecurityPolicy(t.Context(), ipgspTestTenant, sp2.Policy.ID); ipgspCodeOf(err) != "ELB.8907" {
		t.Fatalf("delete sp2 while in use err = %v, want ELB.8907", err)
	}

	// Switch l1 back to system policy -> sp2 can now be deleted.
	if _, err := e.svc.updateListener(t.Context(), ipgspTestTenant, l1.ID, updateListenerInput{
		TLSCiphersPolicySet: true,
		TLSCiphersPolicy:    "tls-1-2-strict",
	}); err != nil {
		t.Fatalf("switch l1 to system policy: %v", err)
	}
	if err := e.svc.deleteSecurityPolicy(t.Context(), ipgspTestTenant, sp2.Policy.ID); err != nil {
		t.Fatalf("delete sp2 after detach: %v", err)
	}

	// Delete l2 -> sp1 can now be deleted.
	if err := e.svc.deleteListener(t.Context(), ipgspTestTenant, l2.ID); err != nil {
		t.Fatalf("delete l2: %v", err)
	}
	if err := e.svc.deleteSecurityPolicy(t.Context(), ipgspTestTenant, sp1.Policy.ID); err != nil {
		t.Fatalf("delete sp1 after listener deleted: %v", err)
	}
}

func TestIPGroupAndSecurityPolicyConcurrency(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	// Concurrently create, update, list IP groups and security policies under -race.
	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers*4)

	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ipg, err := e.svc.createIPGroup(t.Context(), ipgspTestTenant, ipgCreateInput{
				Name:      fmt.Sprintf("conc-ipg-%d", idx),
				IPListSet: true,
				IPList:    []ipInfo{{IP: fmt.Sprintf("10.0.%d.1", idx)}},
			})
			if err != nil {
				errCh <- fmt.Errorf("createIPGroup %d: %w", idx, err)
				return
			}
			if _, err := e.svc.updateIPGroup(t.Context(), ipgspTestTenant, ipg.Group.ID, ipgUpdateInput{
				Description: ipgspPtr(fmt.Sprintf("desc-%d", idx)),
			}); err != nil {
				errCh <- fmt.Errorf("updateIPGroup %d: %w", idx, err)
				return
			}
			if _, _, err := e.svc.listIPGroups(t.Context(), ipgspTestTenant, ipgListFilter{}); err != nil {
				errCh <- fmt.Errorf("listIPGroups %d: %w", idx, err)
				return
			}

			sp, err := e.svc.createSecurityPolicy(t.Context(), ipgspTestTenant, secpolCreateInput{
				Name:      fmt.Sprintf("conc-sp-%d", idx),
				Protocols: []string{"TLSv1.2"},
				Ciphers:   []string{"ECDHE-RSA-AES128-GCM-SHA256"},
			})
			if err != nil {
				errCh <- fmt.Errorf("createSecurityPolicy %d: %w", idx, err)
				return
			}
			if _, err := e.svc.updateSecurityPolicy(t.Context(), ipgspTestTenant, sp.Policy.ID, secpolUpdateInput{
				Description: ipgspPtr(fmt.Sprintf("sp-desc-%d", idx)),
			}); err != nil {
				errCh <- fmt.Errorf("updateSecurityPolicy %d: %w", idx, err)
				return
			}
			if _, _, err := e.svc.listSecurityPolicies(t.Context(), ipgspTestTenant, secpolListFilter{}); err != nil {
				errCh <- fmt.Errorf("listSecurityPolicies %d: %w", idx, err)
				return
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	// Race binding a listener against deleting an IP group and a security policy.
	// Serialization via s.mu ensures we never end up with a dangling listener reference.
	for i := range 10 {
		ipg, err := e.svc.createIPGroup(t.Context(), ipgspTestTenant, ipgCreateInput{
			Name:      fmt.Sprintf("race-ipg-%d", i),
			IPListSet: true,
			IPList:    []ipInfo{{IP: "192.0.2.1"}},
		})
		if err != nil {
			t.Fatalf("create race ipg: %v", err)
		}
		sp, err := e.svc.createSecurityPolicy(t.Context(), ipgspTestTenant, secpolCreateInput{
			Name:      fmt.Sprintf("race-sp-%d", i),
			Protocols: []string{"TLSv1.2"},
			Ciphers:   []string{"AES128-SHA"},
		})
		if err != nil {
			t.Fatalf("create race sp: %v", err)
		}

		start := make(chan struct{})
		var bindErr, delIPGErr, delSPErr error
		var raceWG sync.WaitGroup
		raceWG.Add(3)
		go func(port int) {
			defer raceWG.Done()
			<-start
			_, bindErr = e.svc.createListener(t.Context(), ipgspTestTenant, createListenerInput{
				LoadBalancerID:         e.lbID,
				Protocol:               "HTTPS",
				ProtocolPort:           ipgspPtr(port),
				PortRangesValid:        true,
				DefaultTLSContainerRef: e.serverCertID,
				SecurityPolicyID:       sp.Policy.ID,
				IPGroup: &listenerIPGroupInput{
					IPGroupID: ipgspPtr(ipg.Group.ID),
					Type:      ipgspPtr("white"),
				},
			})
		}(10000 + i)
		go func() {
			defer raceWG.Done()
			<-start
			delIPGErr = e.svc.deleteIPGroup(t.Context(), ipgspTestTenant, ipg.Group.ID)
		}()
		go func() {
			defer raceWG.Done()
			<-start
			delSPErr = e.svc.deleteSecurityPolicy(t.Context(), ipgspTestTenant, sp.Policy.ID)
		}()
		close(start)
		raceWG.Wait()

		if bindErr == nil {
			// Listener succeeded: neither resource may have been deleted.
			if ipgspCodeOf(delIPGErr) != "ELB.8907" {
				t.Fatalf("iter %d: listener bound but deleteIPGroup err = %v, want ELB.8907", i, delIPGErr)
			}
			if ipgspCodeOf(delSPErr) != "ELB.8907" {
				t.Fatalf("iter %d: listener bound but deleteSecurityPolicy err = %v, want ELB.8907", i, delSPErr)
			}
		} else if ipgspCodeOf(bindErr) != "ELB.8904" {
			t.Fatalf("iter %d: unexpected bindErr = %v", i, bindErr)
		}
	}
}
