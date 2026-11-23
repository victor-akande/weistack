package elb

import (
	"context"
	"encoding/json"
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

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	tagTestProject   = "0123456789abcdef0123456789abcdef"
	tagTestProjectB  = "fedcba9876543210fedcba9876543210"
	tagTestRegion    = "ap-southeast-1"
	tagTestHost      = "elb." + tagTestRegion + ".myhuaweicloud.com"
	tagTestUnknownID = "00000000-0000-4000-8000-000000000000"
)

var (
	tagTestTenant  = Tenant{Region: tagTestRegion, ProjectID: tagTestProject}
	tagTestTenantB = Tenant{Region: tagTestRegion, ProjectID: tagTestProjectB}
	tagTestEpoch   = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
)

type tagStubVPC struct{}

func (tagStubVPC) GetVPC(context.Context, vpc.Tenant, string) (vpc.VPC, error) {
	return vpc.VPC{}, nil
}
func (tagStubVPC) GetSubnet(context.Context, vpc.Tenant, string) (vpc.Subnet, error) {
	return vpc.Subnet{}, nil
}
func (tagStubVPC) ListSubnets(context.Context, vpc.Tenant, vpc.ListSubnetsFilter) ([]vpc.Subnet, error) {
	return nil, nil
}
func (tagStubVPC) AllocateIP(context.Context, vpc.Tenant, string, string, string) (string, error) {
	return "", nil
}
func (tagStubVPC) ReleaseIP(context.Context, vpc.Tenant, string, string) error {
	return nil
}

type tagStubEIPs struct{}

func (tagStubEIPs) BindToELB(context.Context, vpc.Tenant, string, string, string, string) (string, error) {
	return "", nil
}
func (tagStubEIPs) CreateForELB(context.Context, vpc.Tenant, string, string, string, eip.ServerIP) (string, string, error) {
	return "", "", nil
}
func (tagStubEIPs) UnbindFromELB(context.Context, vpc.Tenant, string, string) error {
	return nil
}
func (tagStubEIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type tagStubServers struct{}

func (tagStubServers) ServerAt(context.Context, vpc.Tenant, string, string, string) (string, bool, error) {
	return "", false, nil
}

type tagEnv struct {
	svc     *Service
	store   store.Store
	clock   *lifecycle.FakeClock
	ids     *ids.Generator
	handler http.Handler
}

func newTagEnv(t *testing.T) *tagEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(tagTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: 0, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(29)
	vlt, err := vault.New(make([]byte, vault.KeyLen))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	elbSvc, err := New(Deps{
		Store:   st,
		IDs:     gen,
		Logger:  log,
		Vault:   vlt,
		VPC:     tagStubVPC{},
		EIPs:    tagStubEIPs{},
		Servers: tagStubServers{},
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
		ProjectID: tagTestProject,
		Logger:    log,
		Store:     st,
		Engine:    engine,
		IDs:       gen,
		Services:  []server.Service{elbSvc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &tagEnv{
		svc:     elbSvc,
		store:   st,
		clock:   clock,
		ids:     gen,
		handler: srv.Handler(),
	}
}

func (e *tagEnv) seedLoadBalancer(t *testing.T, tenant Tenant, name string, tags []tag) loadBalancer {
	t.Helper()
	now := e.svc.nowUTC()
	lb := loadBalancer{
		ID:                   e.ids.UUID(),
		Name:                 name,
		AdminStateUp:         true,
		Provider:             lbDefaultProvider,
		VPCID:                e.ids.UUID(),
		AvailabilityZoneList: []string{"ap-southeast-1a"},
		Guaranteed:           true,
		EnterpriseProjectID:  defaultEnterpriseProjectID,
		Tags:                 tags,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := e.svc.loadBalancers(tenant).Create(t.Context(), lb.ID, lb); err != nil {
		t.Fatalf("seedLoadBalancer: %v", err)
	}
	return lb
}

func (e *tagEnv) seedListener(t *testing.T, tenant Tenant, lbID, name string, port int, tags []tag) listener {
	t.Helper()
	now := e.svc.nowUTC()
	lsn := listener{
		ID:                  e.ids.UUID(),
		LoadBalancerID:      lbID,
		Name:                name,
		Protocol:            "HTTP",
		ProtocolPort:        port,
		AdminStateUp:        true,
		ConnectionLimit:     -1,
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Tags:                tags,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := e.svc.listeners(tenant).Create(t.Context(), lsn.ID, lsn); err != nil {
		t.Fatalf("seedListener: %v", err)
	}
	return lsn
}

func (e *tagEnv) call(t *testing.T, prefix, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, prefix+"/"+tagTestProject+path, rd)
	r.Host = tagTestHost
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if res.Header.Get("X-Request-Id") == "" {
		t.Errorf("%s %s%s: response has no X-Request-Id", method, prefix, path)
	}
	return res.StatusCode, out
}

func (e *tagEnv) expect(t *testing.T, prefix, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, prefix, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "tags", goldenName+".json"), status, out)
	return out
}

func tagDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func TestTagLoadBalancerGoldenLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("v2.0", func(t *testing.T) {
		t.Parallel()
		e := newTagEnv(t)

		// Empty project tags list and empty filter result.
		e.expect(t, "/v2.0", "list_tags_empty", http.MethodGet, "/loadbalancers/tags", "")
		e.expect(t, "/v2.0", "list_loadbalancers_by_tags_filter_empty", http.MethodPost, "/loadbalancers/resource_instances/action",
			`{"action": "filter"}`)

		lb1 := e.seedLoadBalancer(t, tagTestTenant, "lb-tag-1", nil)
		lb2 := e.seedLoadBalancer(t, tagTestTenant, "lb-tag-2", nil)

		// Empty tags on a fresh load balancer.
		e.expect(t, "/v2.0", "show_tags_empty", http.MethodGet, "/loadbalancers/"+lb1.ID+"/tags", "")

		// Single tag create and show.
		e.expect(t, "/v2.0", "create_tag", http.MethodPost, "/loadbalancers/"+lb1.ID+"/tags",
			`{"tag": {"key": "key1", "value": "value1"}}`)
		e.expect(t, "/v2.0", "create_tag", http.MethodPost, "/loadbalancers/"+lb1.ID+"/tags",
			`{"tag": {"key": "key2", "value": "value2"}}`)
		e.expect(t, "/v2.0", "show_tags", http.MethodGet, "/loadbalancers/"+lb1.ID+"/tags", "")
		// Same tags visible through /v3 prefix.
		e.expect(t, "/v3", "show_tags", http.MethodGet, "/loadbalancers/"+lb1.ID+"/tags", "")

		// Single tag delete.
		e.expect(t, "/v2.0", "delete_tag", http.MethodDelete, "/loadbalancers/"+lb1.ID+"/tags/key2", "")

		// Batch create tags on lb1 and lb2.
		e.expect(t, "/v2.0", "change_tags_create", http.MethodPost, "/loadbalancers/"+lb1.ID+"/tags/action",
			`{"action": "create", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}]}`)
		e.expect(t, "/v2.0", "change_tags_create", http.MethodPost, "/loadbalancers/"+lb2.ID+"/tags/action",
			`{"action": "create", "tags": [{"key": "key1", "value": "value2"}, {"key": "key2", "value": "value2"}]}`)

		// List all project tags (both /v2.0 and /v3).
		e.expect(t, "/v2.0", "list_tags", http.MethodGet, "/loadbalancers/tags", "")
		e.expect(t, "/v3", "list_tags", http.MethodGet, "/loadbalancers/tags", "")

		// List load balancers by tag: filter and count.
		e.expect(t, "/v2.0", "list_loadbalancers_by_tags_filter", http.MethodPost, "/loadbalancers/resource_instances/action", `{
			"offset": "0",
			"limit": "100",
			"action": "filter",
			"matches": [{"key": "resource_name", "value": "TAG-1"}],
			"tags": [
				{"key": "key1", "values": ["value1"]},
				{"key": "key2", "values": ["value1", "value2"]}
			]
		}`)
		e.expect(t, "/v2.0", "list_loadbalancers_by_tags_count", http.MethodPost, "/loadbalancers/resource_instances/action", `{
			"action": "count",
			"matches": [{"key": "resource_name", "value": "TAG-1"}],
			"tags": [
				{"key": "key1", "values": ["value1"]},
				{"key": "key2", "values": ["value1", "value2"]}
			]
		}`)

		// Verify tags are reflected on ShowLoadBalancer.
		st, out := e.call(t, "/v3", http.MethodGet, "/elb/loadbalancers/"+lb1.ID, "")
		if st != http.StatusOK {
			t.Fatalf("show loadbalancer: %d %s", st, out)
		}
		lbResp := tagDecodeInto[loadBalancerResponse](t, out)
		if len(lbResp.Loadbalancer.Tags) != 2 {
			t.Fatalf("loadbalancer tags = %+v, want 2 tags", lbResp.Loadbalancer.Tags)
		}

		// Batch delete tags on lb1, including a missing key (must succeed with 204).
		e.expect(t, "/v2.0", "change_tags_delete", http.MethodPost, "/loadbalancers/"+lb1.ID+"/tags/action",
			`{"action": "delete", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}, {"key": "missing", "value": "x"}]}`)
		e.expect(t, "/v2.0", "show_tags_empty", http.MethodGet, "/loadbalancers/"+lb1.ID+"/tags", "")
	})

	t.Run("v3", func(t *testing.T) {
		t.Parallel()
		e := newTagEnv(t)

		e.expect(t, "/v3", "list_tags_empty", http.MethodGet, "/loadbalancers/tags", "")
		lb1 := e.seedLoadBalancer(t, tagTestTenant, "lb-v3-1", nil)
		lb2 := e.seedLoadBalancer(t, tagTestTenant, "lb-v3-2", nil)

		e.expect(t, "/v3", "show_tags_empty", http.MethodGet, "/loadbalancers/"+lb1.ID+"/tags", "")

		// Batch create via /v3.
		e.expect(t, "/v3", "change_tags_create", http.MethodPost, "/loadbalancers/"+lb1.ID+"/tags/action",
			`{"action": "create", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value2"}]}`)
		e.expect(t, "/v3", "show_tags", http.MethodGet, "/loadbalancers/"+lb1.ID+"/tags", "")
		// Visible via /v2.0 too.
		e.expect(t, "/v2.0", "show_tags", http.MethodGet, "/loadbalancers/"+lb1.ID+"/tags", "")

		e.expect(t, "/v3", "change_tags_create", http.MethodPost, "/loadbalancers/"+lb2.ID+"/tags/action",
			`{"action": "create", "tags": [{"key": "key1", "value": "value2"}, {"key": "key2", "value": "value1"}]}`)
		e.expect(t, "/v3", "list_tags", http.MethodGet, "/loadbalancers/tags", "")

		// Batch delete via /v3, ignoring missing key.
		e.expect(t, "/v3", "change_tags_delete", http.MethodPost, "/loadbalancers/"+lb1.ID+"/tags/action",
			`{"action": "delete", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value2"}, {"key": "absent", "value": ""}]}`)
		e.expect(t, "/v3", "show_tags_empty", http.MethodGet, "/loadbalancers/"+lb1.ID+"/tags", "")
	})
}

func TestTagListenerGoldenLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("v2.0", func(t *testing.T) {
		t.Parallel()
		e := newTagEnv(t)

		e.expect(t, "/v2.0", "list_tags_empty", http.MethodGet, "/listeners/tags", "")
		e.expect(t, "/v2.0", "list_listeners_by_tags_filter_empty", http.MethodPost, "/listeners/resource_instances/action",
			`{"action": "filter"}`)

		lb := e.seedLoadBalancer(t, tagTestTenant, "lb-parent", nil)
		l1 := e.seedListener(t, tagTestTenant, lb.ID, "lsn-tag-1", 80, nil)
		l2 := e.seedListener(t, tagTestTenant, lb.ID, "lsn-tag-2", 8080, nil)

		e.expect(t, "/v2.0", "show_tags_empty", http.MethodGet, "/listeners/"+l1.ID+"/tags", "")

		// Single create & show.
		e.expect(t, "/v2.0", "create_tag", http.MethodPost, "/listeners/"+l1.ID+"/tags",
			`{"tag": {"key": "key1", "value": "value1"}}`)
		e.expect(t, "/v2.0", "create_tag", http.MethodPost, "/listeners/"+l1.ID+"/tags",
			`{"tag": {"key": "key2", "value": "value2"}}`)
		e.expect(t, "/v2.0", "show_tags", http.MethodGet, "/listeners/"+l1.ID+"/tags", "")
		e.expect(t, "/v3", "show_tags", http.MethodGet, "/listeners/"+l1.ID+"/tags", "")

		// Single delete.
		e.expect(t, "/v2.0", "delete_tag", http.MethodDelete, "/listeners/"+l1.ID+"/tags/key2", "")

		// Batch create.
		e.expect(t, "/v2.0", "change_tags_create", http.MethodPost, "/listeners/"+l1.ID+"/tags/action",
			`{"action": "create", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}]}`)
		e.expect(t, "/v2.0", "change_tags_create", http.MethodPost, "/listeners/"+l2.ID+"/tags/action",
			`{"action": "create", "tags": [{"key": "key1", "value": "value2"}, {"key": "key2", "value": "value2"}]}`)

		// List project tags.
		e.expect(t, "/v2.0", "list_tags", http.MethodGet, "/listeners/tags", "")
		e.expect(t, "/v3", "list_tags", http.MethodGet, "/listeners/tags", "")

		// Filter and count.
		e.expect(t, "/v2.0", "list_listeners_by_tags_filter", http.MethodPost, "/listeners/resource_instances/action", `{
			"offset": "0",
			"limit": "100",
			"action": "filter",
			"matches": [{"key": "resource_name", "value": "TAG-1"}],
			"tags": [
				{"key": "key1", "values": ["value1"]},
				{"key": "key2", "values": ["value1", "value2"]}
			]
		}`)
		e.expect(t, "/v2.0", "list_listeners_by_tags_count", http.MethodPost, "/listeners/resource_instances/action", `{
			"action": "count",
			"matches": [{"key": "resource_name", "value": "TAG-1"}],
			"tags": [
				{"key": "key1", "values": ["value1"]},
				{"key": "key2", "values": ["value1", "value2"]}
			]
		}`)

		// Verify tags are reflected on ShowListener.
		st, out := e.call(t, "/v3", http.MethodGet, "/elb/listeners/"+l1.ID, "")
		if st != http.StatusOK {
			t.Fatalf("show listener: %d %s", st, out)
		}
		lsnResp := tagDecodeInto[listenerEnvelope](t, out)
		if len(lsnResp.Listener.Tags) != 2 {
			t.Fatalf("listener tags = %+v, want 2 tags", lsnResp.Listener.Tags)
		}

		// Batch delete including missing key.
		e.expect(t, "/v2.0", "change_tags_delete", http.MethodPost, "/listeners/"+l1.ID+"/tags/action",
			`{"action": "delete", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}, {"key": "missing", "value": "x"}]}`)
		e.expect(t, "/v2.0", "show_tags_empty", http.MethodGet, "/listeners/"+l1.ID+"/tags", "")
	})

	t.Run("v3", func(t *testing.T) {
		t.Parallel()
		e := newTagEnv(t)

		e.expect(t, "/v3", "list_tags_empty", http.MethodGet, "/listeners/tags", "")
		lb := e.seedLoadBalancer(t, tagTestTenant, "lb-parent", nil)
		l1 := e.seedListener(t, tagTestTenant, lb.ID, "lsn-v3-1", 80, nil)
		l2 := e.seedListener(t, tagTestTenant, lb.ID, "lsn-v3-2", 8080, nil)

		e.expect(t, "/v3", "show_tags_empty", http.MethodGet, "/listeners/"+l1.ID+"/tags", "")
		e.expect(t, "/v3", "change_tags_create", http.MethodPost, "/listeners/"+l1.ID+"/tags/action",
			`{"action": "create", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value2"}]}`)
		e.expect(t, "/v3", "show_tags", http.MethodGet, "/listeners/"+l1.ID+"/tags", "")
		e.expect(t, "/v2.0", "show_tags", http.MethodGet, "/listeners/"+l1.ID+"/tags", "")

		e.expect(t, "/v3", "change_tags_create", http.MethodPost, "/listeners/"+l2.ID+"/tags/action",
			`{"action": "create", "tags": [{"key": "key1", "value": "value2"}, {"key": "key2", "value": "value1"}]}`)
		e.expect(t, "/v3", "list_tags", http.MethodGet, "/listeners/tags", "")

		e.expect(t, "/v3", "change_tags_delete", http.MethodPost, "/listeners/"+l1.ID+"/tags/action",
			`{"action": "delete", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value2"}, {"key": "absent", "value": ""}]}`)
		e.expect(t, "/v3", "show_tags_empty", http.MethodGet, "/listeners/"+l1.ID+"/tags", "")
	})
}

func TestTagGoldenErrors(t *testing.T) {
	t.Parallel()

	resources := []struct {
		name     string
		segment  string
		seedFunc func(e *tagEnv, t *testing.T, tags []tag) string
	}{
		{
			name:    "loadbalancers",
			segment: "/loadbalancers",
			seedFunc: func(e *tagEnv, t *testing.T, tags []tag) string {
				return e.seedLoadBalancer(t, tagTestTenant, "lb-err", tags).ID
			},
		},
		{
			name:    "listeners",
			segment: "/listeners",
			seedFunc: func(e *tagEnv, t *testing.T, tags []tag) string {
				lb := e.seedLoadBalancer(t, tagTestTenant, "lb-for-lsn-err", nil)
				return e.seedListener(t, tagTestTenant, lb.ID, "lsn-err", 80, tags).ID
			},
		},
	}

	for _, res := range resources {
		t.Run(res.name, func(t *testing.T) {
			t.Parallel()
			e := newTagEnv(t)
			id := res.seedFunc(e, t, nil)

			var fullTags []tag
			for i := range maxTags {
				fullTags = append(fullTags, tag{Key: fmt.Sprintf("k%02d", i), Value: "v"})
			}
			fullID := res.seedFunc(e, t, fullTags)

			// Shared /v2.0 and /v3 error cases.
			for _, prefix := range []string{"/v2.0", "/v3"} {
				t.Run(strings.TrimPrefix(prefix, "/"), func(t *testing.T) {
					// Unknown resource -> ELB.8904.
					e.expect(t, prefix, "error_not_found", http.MethodGet, res.segment+"/"+tagTestUnknownID+"/tags", "")
					e.expect(t, prefix, "error_not_found", http.MethodPost, res.segment+"/"+tagTestUnknownID+"/tags/action",
						`{"action": "create", "tags": [{"key": "k1", "value": "v1"}]}`)
					e.expect(t, prefix, "error_not_found", http.MethodPost, res.segment+"/"+tagTestUnknownID+"/tags/action",
						`{"action": "delete", "tags": [{"key": "k1", "value": ""}]}`)

					// Invalid batch inputs -> ELB.8902.
					invalidBatch := []struct {
						name string
						body string
					}{
						{"empty body", ``},
						{"malformed json", `{"action":`},
						{"missing action", `{"tags": [{"key": "k", "value": "v"}]}`},
						{"unknown action", `{"action": "update", "tags": [{"key": "k", "value": "v"}]}`},
						{"empty tags create", `{"action": "create", "tags": []}`},
						{"empty tags delete", `{"action": "delete", "tags": []}`},
						{"empty key create", `{"action": "create", "tags": [{"key": "", "value": "v"}]}`},
						{"key over max", `{"action": "create", "tags": [{"key": "` + strings.Repeat("k", tagMaxFilterKeyLen+1) + `", "value": "v"}]}`},
						{"invalid key char dot", `{"action": "create", "tags": [{"key": "a.b", "value": "v"}]}`},
						{"invalid key char star", `{"action": "create", "tags": [{"key": "a*b", "value": "v"}]}`},
						{"invalid key char space", `{"action": "create", "tags": [{"key": "a b", "value": "v"}]}`},
						{"value over max", `{"action": "create", "tags": [{"key": "k", "value": "` + strings.Repeat("v", tagMaxFilterValueLen+1) + `"}]}`},
						{"invalid value char slash", `{"action": "create", "tags": [{"key": "k", "value": "a/b"}]}`},
						{"invalid value char eq", `{"action": "create", "tags": [{"key": "k", "value": "a=b"}]}`},
						{"duplicate key create", `{"action": "create", "tags": [{"key": "dup", "value": "v1"}, {"key": "dup", "value": "v2"}]}`},
						{"empty key delete", `{"action": "delete", "tags": [{"key": ""}]}`},
						{"invalid key delete", `{"action": "delete", "tags": [{"key": "bad*key"}]}`},
					}
					for _, tc := range invalidBatch {
						t.Run("batch_"+tc.name, func(t *testing.T) {
							e.expect(t, prefix, "error_invalid_input", http.MethodPost, res.segment+"/"+id+"/tags/action", tc.body)
						})
					}

					// Overflow past maxTags -> ELB.8902.
					e.expect(t, prefix, "error_invalid_input", http.MethodPost, res.segment+"/"+fullID+"/tags/action",
						fmt.Sprintf(`{"action": "create", "tags": [{"key": "k00", "value": "updated"}, {"key": "k%d", "value": "overflow"}]}`, maxTags))
				})
			}

			// v2.0-only endpoints: single create, single delete, resource_instances/action.
			t.Run("v2.0_only", func(t *testing.T) {
				// Unknown resource -> ELB.8904.
				e.expect(t, "/v2.0", "error_not_found", http.MethodPost, res.segment+"/"+tagTestUnknownID+"/tags",
					`{"tag": {"key": "k1", "value": "v1"}}`)
				e.expect(t, "/v2.0", "error_not_found", http.MethodDelete, res.segment+"/"+tagTestUnknownID+"/tags/k1", "")

				// Deleting a missing key on single DELETE -> ELB.8902.
				e.expect(t, "/v2.0", "error_invalid_input", http.MethodDelete, res.segment+"/"+id+"/tags/missing", "")

				// Overflow on single create -> ELB.8902.
				e.expect(t, "/v2.0", "error_invalid_input", http.MethodPost, res.segment+"/"+fullID+"/tags",
					fmt.Sprintf(`{"tag": {"key": "k%d", "value": "v"}}`, maxTags))

				// Single create invalid inputs -> ELB.8902.
				invalidSingle := []struct {
					name string
					body string
				}{
					{"empty body", ``},
					{"malformed json", `{"tag":`},
					{"missing tag", `{}`},
					{"empty key", `{"tag": {"key": "", "value": "v"}}`},
					{"key over max", `{"tag": {"key": "` + strings.Repeat("k", tagMaxFilterKeyLen+1) + `", "value": "v"}}`},
					{"invalid key char", `{"tag": {"key": "bad/key", "value": "v"}}`},
					{"value over max", `{"tag": {"key": "k", "value": "` + strings.Repeat("v", tagMaxFilterValueLen+1) + `"}}`},
					{"invalid value char", `{"tag": {"key": "k", "value": "bad*val"}}`},
				}
				for _, tc := range invalidSingle {
					t.Run("single_"+tc.name, func(t *testing.T) {
						e.expect(t, "/v2.0", "error_invalid_input", http.MethodPost, res.segment+"/"+id+"/tags", tc.body)
					})
				}

				// resource_instances/action invalid inputs -> ELB.8902.
				tooManyKeys := make([]tagFilter, 0, tagMaxFilterKeys+1)
				for i := range tagMaxFilterKeys + 1 {
					tooManyKeys = append(tooManyKeys, tagFilter{Key: fmt.Sprintf("k%d", i), Values: []string{"v"}})
				}
				tooManyKeysBody, err := json.Marshal(tagListByTagsRequest{Action: "filter", Tags: tooManyKeys})
				if err != nil {
					t.Fatal(err)
				}
				tooManyVals := make([]string, 0, tagMaxFilterValues+1)
				for i := range tagMaxFilterValues + 1 {
					tooManyVals = append(tooManyVals, fmt.Sprintf("v%d", i))
				}
				tooManyValsBody, err := json.Marshal(tagListByTagsRequest{
					Action: "filter",
					Tags:   []tagFilter{{Key: "k", Values: tooManyVals}},
				})
				if err != nil {
					t.Fatal(err)
				}

				invalidQuery := []struct {
					name string
					body string
				}{
					{"empty body", ``},
					{"malformed json", `{"action":`},
					{"missing action", `{}`},
					{"unknown action", `{"action": "list"}`},
					{"limit zero", `{"action": "filter", "limit": 0}`},
					{"limit negative", `{"action": "filter", "limit": -1}`},
					{"limit over max", fmt.Sprintf(`{"action": "filter", "limit": %d}`, tagMaxFilterPage+1)},
					{"limit bad string", `{"action": "filter", "limit": "abc"}`},
					{"limit float", `{"action": "filter", "limit": 1.5}`},
					{"limit bool", `{"action": "filter", "limit": true}`},
					{"offset negative", `{"action": "filter", "offset": -1}`},
					{"offset negative string", `{"action": "filter", "offset": "-5"}`},
					{"offset bad string", `{"action": "filter", "offset": "abc"}`},
					{"offset float", `{"action": "filter", "offset": 2.5}`},
					{"filter empty key", `{"action": "filter", "tags": [{"key": "", "values": ["v"]}]}`},
					{"filter space key", `{"action": "filter", "tags": [{"key": "   ", "values": ["v"]}]}`},
					{"filter key over max", `{"action": "filter", "tags": [{"key": "` + strings.Repeat("k", tagMaxFilterKeyLen+1) + `", "values": ["v"]}]}`},
					{"filter duplicate key", `{"action": "filter", "tags": [{"key": "k", "values": ["v1"]}, {"key": "k", "values": ["v2"]}]}`},
					{"filter value over max", `{"action": "filter", "tags": [{"key": "k", "values": ["` + strings.Repeat("v", tagMaxFilterValueLen+1) + `"]}]}`},
					{"filter duplicate value", `{"action": "filter", "tags": [{"key": "k", "values": ["v1", "v1"]}]}`},
					{"filter too many keys", string(tooManyKeysBody)},
					{"filter too many values", string(tooManyValsBody)},
					{"tags_any invalid", `{"action": "filter", "tags_any": [{"key": "", "values": ["v"]}]}`},
					{"not_tags invalid", `{"action": "filter", "not_tags": [{"key": "", "values": ["v"]}]}`},
					{"not_tags_any invalid", `{"action": "filter", "not_tags_any": [{"key": "", "values": ["v"]}]}`},
					{"unsupported match key", `{"action": "filter", "matches": [{"key": "description", "value": "x"}]}`},
					{"match value over max", `{"action": "filter", "matches": [{"key": "resource_name", "value": "` + strings.Repeat("a", tagMaxMatchValueLen+1) + `"}]}`},
				}
				for _, tc := range invalidQuery {
					t.Run("query_"+tc.name, func(t *testing.T) {
						e.expect(t, "/v2.0", "error_invalid_input", http.MethodPost, res.segment+"/resource_instances/action", tc.body)
					})
				}
			})
		})
	}
}

func TestTagOverwriteBoundariesAndMaxTags(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{"loadbalancers", "listeners"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			e := newTagEnv(t)

			var id string
			if kind == "loadbalancers" {
				id = e.seedLoadBalancer(t, tagTestTenant, "lb-bounds", nil).ID
			} else {
				lb := e.seedLoadBalancer(t, tagTestTenant, "lb-for-bounds", nil)
				id = e.seedListener(t, tagTestTenant, lb.ID, "lsn-bounds", 80, nil).ID
			}
			base := "/" + kind + "/" + id

			// Max length key (128 chars in [A-Za-z0-9_-]) and max length value (255 chars in [A-Za-z0-9_.-]).
			maxKey := "K_" + strings.Repeat("a", 125) + "-"
			maxVal := "v1.0_" + strings.Repeat("b", 249) + "-"

			st, out := e.call(t, "/v2.0", http.MethodPost, base+"/tags",
				fmt.Sprintf(`{"tag": {"key": %q, "value": %q}}`, maxKey, maxVal))
			if st != http.StatusNoContent {
				t.Fatalf("create max key/val: %d %s", st, out)
			}
			st, out = e.call(t, "/v2.0", http.MethodPost, base+"/tags",
				`{"tag": {"key": "empty-val", "value": ""}}`)
			if st != http.StatusNoContent {
				t.Fatalf("create empty value: %d %s", st, out)
			}

			// Overwrite existing key via single create and via /v3 batch create.
			st, out = e.call(t, "/v2.0", http.MethodPost, base+"/tags",
				fmt.Sprintf(`{"tag": {"key": %q, "value": "updated.1"}}`, maxKey))
			if st != http.StatusNoContent {
				t.Fatalf("overwrite tag: %d %s", st, out)
			}
			st, out = e.call(t, "/v3", http.MethodPost, base+"/tags/action",
				`{"action": "create", "tags": [{"key": "empty-val", "value": "now-set"}, {"key": "k3", "value": "v3"}]}`)
			if st != http.StatusNoContent {
				t.Fatalf("batch overwrite: %d %s", st, out)
			}

			// Fill remaining slots to reach exact limit of maxTags (3 tags already present).
			var batch []tag
			for i := 4; i <= maxTags; i++ {
				batch = append(batch, tag{Key: fmt.Sprintf("k%d", i), Value: fmt.Sprintf("v%d", i)})
			}
			body, err := json.Marshal(tagChangeRequest{Action: "create", Tags: batch})
			if err != nil {
				t.Fatal(err)
			}
			st, out = e.call(t, "/v3", http.MethodPost, base+"/tags/action", string(body))
			if st != http.StatusNoContent {
				t.Fatalf("fill to %d tags: %d %s", maxTags, st, out)
			}

			// Overwriting an existing key when at maxTags succeeds.
			st, out = e.call(t, "/v2.0", http.MethodPost, base+"/tags",
				`{"tag": {"key": "k3", "value": "v3-updated"}}`)
			if st != http.StatusNoContent {
				t.Fatalf("overwrite at %d tags: %d %s", maxTags, st, out)
			}

			// Batch create with 1 existing key + 1 new key at maxTags fails atomically with ELB.8902.
			e.expect(t, "/v3", "error_invalid_input", http.MethodPost, base+"/tags/action",
				fmt.Sprintf(`{"action": "create", "tags": [{"key": "k3", "value": "should-not-apply"}, {"key": "k%d", "value": "overflow"}]}`, maxTags+1))

			// Verify k3 was NOT mutated by the rejected batch create and count is still maxTags.
			st, out = e.call(t, "/v3", http.MethodGet, base+"/tags", "")
			if st != http.StatusOK {
				t.Fatalf("show tags: %d %s", st, out)
			}
			got := tagDecodeInto[tagShowResponse](t, out).Tags
			if len(got) != maxTags {
				t.Fatalf("len(tags) = %d, want %d", len(got), maxTags)
			}
			if got[0].Key != maxKey || got[0].Value != "updated.1" || got[1].Key != "empty-val" || got[1].Value != "now-set" || got[2].Key != "k3" || got[2].Value != "v3-updated" {
				t.Fatalf("unexpected first 3 tags: %+v", got[:3])
			}
		})
	}
}

func TestTagListByTagsFilteringMatchesAndPaging(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{"loadbalancers", "listeners"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			e := newTagEnv(t)

			var id1, id2, id3 string
			if kind == "loadbalancers" {
				id1 = e.seedLoadBalancer(t, tagTestTenant, "Prod-Res-Alpha", []tag{
					{Key: "env", Value: "prod"},
					{Key: "team", Value: "core-platform"},
				}).ID
				id2 = e.seedLoadBalancer(t, tagTestTenant, "Staging-Res-Beta", []tag{
					{Key: "env", Value: "staging"},
					{Key: "team", Value: "core-platform"},
				}).ID
				id3 = e.seedLoadBalancer(t, tagTestTenant, "prod-res-gamma", []tag{
					{Key: "env", Value: "prod"},
					{Key: "team", Value: "edge-net"},
				}).ID
				// Different project must never leak.
				e.seedLoadBalancer(t, tagTestTenantB, "Prod-Res-Other", []tag{
					{Key: "env", Value: "prod"},
					{Key: "team", Value: "core-platform"},
				})
			} else {
				lb := e.seedLoadBalancer(t, tagTestTenant, "lb-host", nil)
				id1 = e.seedListener(t, tagTestTenant, lb.ID, "Prod-Res-Alpha", 80, []tag{
					{Key: "env", Value: "prod"},
					{Key: "team", Value: "core-platform"},
				}).ID
				id2 = e.seedListener(t, tagTestTenant, lb.ID, "Staging-Res-Beta", 81, []tag{
					{Key: "env", Value: "staging"},
					{Key: "team", Value: "core-platform"},
				}).ID
				id3 = e.seedListener(t, tagTestTenant, lb.ID, "prod-res-gamma", 82, []tag{
					{Key: "env", Value: "prod"},
					{Key: "team", Value: "edge-net"},
				}).ID
				lbB := e.seedLoadBalancer(t, tagTestTenantB, "lb-host-b", nil)
				e.seedListener(t, tagTestTenantB, lbB.ID, "Prod-Res-Other", 80, []tag{
					{Key: "env", Value: "prod"},
					{Key: "team", Value: "core-platform"},
				})
			}

			path := "/" + kind + "/resource_instances/action"

			// Empty values matches any value for that key.
			st, out := e.call(t, "/v2.0", http.MethodPost, path,
				`{"action": "filter", "tags": [{"key": "team", "values": []}]}`)
			if st != http.StatusOK {
				t.Fatalf("filter any value: %d %s", st, out)
			}
			res := tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if res.TotalCount != 3 || len(res.Resources) != 3 {
				t.Fatalf("filter any value: total=%d len=%d, want 3", res.TotalCount, len(res.Resources))
			}

			// Pagination with integer limit and offset.
			st, out = e.call(t, "/v2.0", http.MethodPost, path,
				`{"action": "filter", "limit": 1, "offset": 1, "tags": [{"key": "team", "values": []}]}`)
			if st != http.StatusOK {
				t.Fatalf("filter paged: %d %s", st, out)
			}
			paged := tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if paged.TotalCount != 3 || len(paged.Resources) != 1 || paged.Resources[0].ResourceID != res.Resources[1].ResourceID {
				t.Fatalf("filter paged = %+v, want second item %s", paged, res.Resources[1].ResourceID)
			}

			// Offset beyond total_count returns empty resources slice and full total_count.
			st, out = e.call(t, "/v2.0", http.MethodPost, path,
				`{"action": "filter", "limit": "10", "offset": "5", "tags": [{"key": "team", "values": []}]}`)
			if st != http.StatusOK {
				t.Fatalf("filter high offset: %d %s", st, out)
			}
			hi := tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if hi.TotalCount != 3 || len(hi.Resources) != 0 {
				t.Fatalf("filter high offset = %+v, want total=3 len=0", hi)
			}

			// matches on resource_name: case-insensitive fuzzy substring match.
			st, out = e.call(t, "/v2.0", http.MethodPost, path,
				`{"action": "filter", "matches": [{"key": "resource_name", "value": "PROD-RES"}]}`)
			if st != http.StatusOK {
				t.Fatalf("matches fuzzy: %d %s", st, out)
			}
			res = tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if res.TotalCount != 2 || !tagContainsIDs(res.Resources, id1, id3) {
				t.Fatalf("matches fuzzy = %+v, want [%s, %s]", res, id1, id3)
			}

			// matches on resource_name with empty string uses exact match.
			st, out = e.call(t, "/v2.0", http.MethodPost, path,
				`{"action": "filter", "matches": [{"key": "resource_name", "value": ""}]}`)
			if st != http.StatusOK {
				t.Fatalf("matches empty exact: %d %s", st, out)
			}
			res = tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if res.TotalCount != 0 || len(res.Resources) != 0 {
				t.Fatalf("matches empty exact = %+v, want 0", res)
			}

			// matches on resource_id uses exact match.
			st, out = e.call(t, "/v2.0", http.MethodPost, path,
				fmt.Sprintf(`{"action": "filter", "matches": [{"key": "resource_id", "value": %q}]}`, id2))
			if st != http.StatusOK {
				t.Fatalf("matches resource_id: %d %s", st, out)
			}
			res = tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if res.TotalCount != 1 || res.Resources[0].ResourceID != id2 {
				t.Fatalf("matches resource_id = %+v, want [%s]", res, id2)
			}

			// Star-prefixed tag value performs fuzzy substring match.
			st, out = e.call(t, "/v2.0", http.MethodPost, path,
				`{"action": "filter", "tags": [{"key": "team", "values": ["*platform"]}]}`)
			if st != http.StatusOK {
				t.Fatalf("star prefix filter: %d %s", st, out)
			}
			res = tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if res.TotalCount != 2 || !tagContainsIDs(res.Resources, id1, id2) {
				t.Fatalf("star prefix filter = %+v, want [%s, %s]", res, id1, id2)
			}

			// tags_any (OR across keys).
			st, out = e.call(t, "/v2.0", http.MethodPost, path, `{
				"action": "filter",
				"tags_any": [{"key": "env", "values": ["staging"]}, {"key": "team", "values": ["edge-net"]}]
			}`)
			if st != http.StatusOK {
				t.Fatalf("tags_any: %d %s", st, out)
			}
			res = tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if res.TotalCount != 2 || !tagContainsIDs(res.Resources, id2, id3) {
				t.Fatalf("tags_any = %+v, want [%s, %s]", res, id2, id3)
			}

			// not_tags (exclude resources matching ALL).
			st, out = e.call(t, "/v2.0", http.MethodPost, path, `{
				"action": "filter",
				"not_tags": [{"key": "env", "values": ["prod"]}, {"key": "team", "values": ["core-platform"]}]
			}`)
			if st != http.StatusOK {
				t.Fatalf("not_tags: %d %s", st, out)
			}
			res = tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if res.TotalCount != 2 || !tagContainsIDs(res.Resources, id2, id3) {
				t.Fatalf("not_tags = %+v, want [%s, %s]", res, id2, id3)
			}

			// not_tags_any (exclude resources matching ANY).
			st, out = e.call(t, "/v2.0", http.MethodPost, path, `{
				"action": "filter",
				"not_tags_any": [{"key": "env", "values": ["staging"]}, {"key": "team", "values": ["edge-net"]}]
			}`)
			if st != http.StatusOK {
				t.Fatalf("not_tags_any: %d %s", st, out)
			}
			res = tagDecodeInto[tagListByTagsFilterResponse](t, out)
			if res.TotalCount != 1 || res.Resources[0].ResourceID != id1 {
				t.Fatalf("not_tags_any = %+v, want [%s]", res, id1)
			}

			// action=count returns only total_count and ignores limit/offset.
			st, out = e.call(t, "/v2.0", http.MethodPost, path,
				`{"action": "count", "limit": "bad", "offset": "-99", "tags": [{"key": "env", "values": ["prod"]}]}`)
			if st != http.StatusOK {
				t.Fatalf("count: %d %s", st, out)
			}
			var rawMap map[string]any
			if err := json.Unmarshal(out, &rawMap); err != nil {
				t.Fatal(err)
			}
			if _, hasResources := rawMap["resources"]; hasResources {
				t.Fatalf("count response must not include resources: %s", out)
			}
			if rawMap["total_count"] != float64(2) {
				t.Fatalf("count total_count = %v, want 2", rawMap["total_count"])
			}
		})
	}
}

func tagContainsIDs(items []tagResourceItem, want ...string) bool {
	if len(items) != len(want) {
		return false
	}
	got := make(map[string]struct{}, len(items))
	for _, it := range items {
		got[it.ResourceID] = struct{}{}
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			return false
		}
	}
	return true
}

func TestTagConcurrentWrites(t *testing.T) {
	t.Parallel()
	e := newTagEnv(t)
	lb := e.seedLoadBalancer(t, tagTestTenant, "lb-concurrent", nil)
	lsn := e.seedListener(t, tagTestTenant, lb.ID, "lsn-concurrent", 80, nil)

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers * 2)
	for i := range workers {
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", i)
			if err := e.svc.tagCreateLoadBalancer(t.Context(), tagTestTenant, lb.ID, tag{Key: key, Value: "v1"}); err != nil {
				t.Errorf("lb create %s: %v", key, err)
				return
			}
			if err := e.svc.tagChangeLoadBalancer(t.Context(), tagTestTenant, lb.ID, "create", []tag{{Key: key, Value: "v2"}}); err != nil {
				t.Errorf("lb batch overwrite %s: %v", key, err)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", i)
			if err := e.svc.tagCreateListener(t.Context(), tagTestTenant, lsn.ID, tag{Key: key, Value: "v1"}); err != nil {
				t.Errorf("lsn create %s: %v", key, err)
				return
			}
			if err := e.svc.tagChangeListener(t.Context(), tagTestTenant, lsn.ID, "create", []tag{{Key: key, Value: "v2"}}); err != nil {
				t.Errorf("lsn batch overwrite %s: %v", key, err)
			}
		}(i)
	}
	wg.Wait()

	lbTags, err := e.svc.tagShowLoadBalancer(t.Context(), tagTestTenant, lb.ID)
	if err != nil {
		t.Fatalf("tagShowLoadBalancer: %v", err)
	}
	if len(lbTags) != workers {
		t.Fatalf("lb len(tags) = %d, want %d", len(lbTags), workers)
	}
	for _, tg := range lbTags {
		if tg.Value != "v2" {
			t.Errorf("lb tag %s = %q, want v2", tg.Key, tg.Value)
		}
	}

	lsnTags, err := e.svc.tagShowListener(t.Context(), tagTestTenant, lsn.ID)
	if err != nil {
		t.Fatalf("tagShowListener: %v", err)
	}
	if len(lsnTags) != workers {
		t.Fatalf("lsn len(tags) = %d, want %d", len(lsnTags), workers)
	}
	for _, tg := range lsnTags {
		if tg.Value != "v2" {
			t.Errorf("lsn tag %s = %q, want v2", tg.Key, tg.Value)
		}
	}
}
