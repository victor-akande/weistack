package nat

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
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

type privateTagStubVPC struct{}

func (privateTagStubVPC) GetVPC(context.Context, vpc.Tenant, string) (vpc.VPC, error) {
	return vpc.VPC{}, nil
}
func (privateTagStubVPC) GetSubnet(context.Context, vpc.Tenant, string) (vpc.Subnet, error) {
	return vpc.Subnet{}, nil
}
func (privateTagStubVPC) ListSubnets(context.Context, vpc.Tenant, vpc.ListSubnetsFilter) ([]vpc.Subnet, error) {
	return nil, nil
}
func (privateTagStubVPC) Port(context.Context, vpc.Tenant, string) (vpc.Port, bool, error) {
	return vpc.Port{}, false, nil
}
func (privateTagStubVPC) AllocateIP(context.Context, vpc.Tenant, string, string, string) (string, error) {
	return "", nil
}
func (privateTagStubVPC) ReleaseIP(context.Context, vpc.Tenant, string, string) error {
	return nil
}

type privateTagStubEIPs struct{}

func (privateTagStubEIPs) HoldForNAT(context.Context, vpc.Tenant, string, string) (string, error) {
	return "", nil
}
func (privateTagStubEIPs) ReleaseFromNAT(context.Context, vpc.Tenant, string, string) error {
	return nil
}
func (privateTagStubEIPs) PublicIPByAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}
func (privateTagStubEIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type privateTagEnv struct {
	svc     *Service
	clock   *lifecycle.FakeClock
	ids     *ids.Generator
	handler http.Handler
}

func newPrivateTagEnv(t *testing.T) *privateTagEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(tagTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: tagTestDelay, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(16)
	natSvc, err := New(Deps{
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		VPC:    privateTagStubVPC{},
		EIPs:   privateTagStubEIPs{},
		Now:    clock.Now,
	})
	if err != nil {
		t.Fatalf("nat.New: %v", err)
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
		Services:  []server.Service{natSvc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &privateTagEnv{
		svc:     natSvc,
		clock:   clock,
		ids:     gen,
		handler: srv.Handler(),
	}
}

func (e *privateTagEnv) seedPrivateGateway(t *testing.T, tenant Tenant, name string, tags []tag) privateGateway {
	t.Helper()
	now := e.svc.nowUTC()
	gw := privateGateway{
		ID:                  e.ids.UUID(),
		Name:                name,
		Spec:                "Small",
		VPCID:               e.ids.UUID(),
		SubnetID:            e.ids.UUID(),
		NgportIP:            "10.0.0.10",
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Tags:                tags,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := e.svc.privateGateways(tenant).Create(t.Context(), gw.ID, gw); err != nil {
		t.Fatalf("seedPrivateGateway: %v", err)
	}
	return gw
}

func (e *privateTagEnv) seedTransitIP(t *testing.T, tenant Tenant, addr string, tags []tag) transitIP {
	t.Helper()
	now := e.svc.nowUTC()
	ip := transitIP{
		ID:                  e.ids.UUID(),
		SubnetID:            e.ids.UUID(),
		Address:             addr,
		NetworkInterfaceID:  e.ids.UUID(),
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Tags:                tags,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := e.svc.transitIPs(tenant).Create(t.Context(), ip.ID, ip); err != nil {
		t.Fatalf("seedTransitIP: %v", err)
	}
	return ip
}

func (e *privateTagEnv) seedTransitSubnet(t *testing.T, tenant Tenant, name string, tags []tag) transitSubnet {
	t.Helper()
	now := e.svc.nowUTC()
	ts := transitSubnet{
		ID:        e.ids.UUID(),
		Name:      name,
		SubnetID:  e.ids.UUID(),
		VPCID:     e.ids.UUID(),
		CIDR:      "10.1.0.0/24",
		Tags:      tags,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := e.svc.transitSubnets(tenant).Create(t.Context(), ts.ID, ts); err != nil {
		t.Fatalf("seedTransitSubnet: %v", err)
	}
	return ts
}

func (e *privateTagEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v3/"+tagTestProject+path, rd)
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
		t.Errorf("%s %s: response has no X-Request-Id", method, path)
	}
	return res.StatusCode, out
}

func (e *privateTagEnv) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "private_tags", goldenName+".json"), status, out)
	return out
}

func privateTagDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

type privateTagTarget struct {
	name           string
	basePath       string
	notFoundGolden string
	filterNamed    bool
	seed           func(e *privateTagEnv, t *testing.T, tenant Tenant, name string, tags []tag) string
	updatedAt      func(e *privateTagEnv, t *testing.T, tenant Tenant, id string) time.Time
	createTag      func(e *privateTagEnv, ctx context.Context, tenant Tenant, id string, tg tag) error
	showTags       func(e *privateTagEnv, ctx context.Context, tenant Tenant, id string) ([]tag, error)
	deleteTag      func(e *privateTagEnv, ctx context.Context, tenant Tenant, id, key string) error
	batchTags      func(e *privateTagEnv, ctx context.Context, tenant Tenant, id, action string, tags []tag) error
}

var privateTagTargets = []privateTagTarget{
	{
		name:           "private-nat-gateways",
		basePath:       "/private-nat-gateways",
		notFoundGolden: "error_nat_1002_gateway",
		filterNamed:    true,
		seed: func(e *privateTagEnv, t *testing.T, tenant Tenant, name string, tags []tag) string {
			return e.seedPrivateGateway(t, tenant, name, tags).ID
		},
		updatedAt: func(e *privateTagEnv, t *testing.T, tenant Tenant, id string) time.Time {
			rec, err := e.svc.privateGateways(tenant).Get(t.Context(), id)
			if err != nil {
				t.Fatalf("Get privateGateway %s: %v", id, err)
			}
			return rec.UpdatedAt
		},
		createTag: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id string, tg tag) error {
			return createPrivateResourceTag(ctx, e.svc, tenant, privateGatewayTagResource, id, tg)
		},
		showTags: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id string) ([]tag, error) {
			return showPrivateResourceTags(ctx, e.svc, tenant, privateGatewayTagResource, id)
		},
		deleteTag: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id, key string) error {
			return deletePrivateResourceTag(ctx, e.svc, tenant, privateGatewayTagResource, id, key)
		},
		batchTags: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id, action string, tags []tag) error {
			return batchPrivateResourceTags(ctx, e.svc, tenant, privateGatewayTagResource, id, action, tags)
		},
	},
	{
		name:           "transit-ips",
		basePath:       "/transit-ips",
		notFoundGolden: "error_nat_1002_transit_ip",
		filterNamed:    false,
		seed: func(e *privateTagEnv, t *testing.T, tenant Tenant, _ string, tags []tag) string {
			return e.seedTransitIP(t, tenant, "10.2.0.10", tags).ID
		},
		updatedAt: func(e *privateTagEnv, t *testing.T, tenant Tenant, id string) time.Time {
			rec, err := e.svc.transitIPs(tenant).Get(t.Context(), id)
			if err != nil {
				t.Fatalf("Get transitIP %s: %v", id, err)
			}
			return rec.UpdatedAt
		},
		createTag: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id string, tg tag) error {
			return createPrivateResourceTag(ctx, e.svc, tenant, transitIPTagResource, id, tg)
		},
		showTags: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id string) ([]tag, error) {
			return showPrivateResourceTags(ctx, e.svc, tenant, transitIPTagResource, id)
		},
		deleteTag: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id, key string) error {
			return deletePrivateResourceTag(ctx, e.svc, tenant, transitIPTagResource, id, key)
		},
		batchTags: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id, action string, tags []tag) error {
			return batchPrivateResourceTags(ctx, e.svc, tenant, transitIPTagResource, id, action, tags)
		},
	},
	{
		name:           "transit-subnets",
		basePath:       "/transit-subnets",
		notFoundGolden: "error_nat_1002_transit_subnet",
		filterNamed:    true,
		seed: func(e *privateTagEnv, t *testing.T, tenant Tenant, name string, tags []tag) string {
			return e.seedTransitSubnet(t, tenant, name, tags).ID
		},
		updatedAt: func(e *privateTagEnv, t *testing.T, tenant Tenant, id string) time.Time {
			rec, err := e.svc.transitSubnets(tenant).Get(t.Context(), id)
			if err != nil {
				t.Fatalf("Get transitSubnet %s: %v", id, err)
			}
			return rec.UpdatedAt
		},
		createTag: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id string, tg tag) error {
			return createPrivateResourceTag(ctx, e.svc, tenant, transitSubnetTagResource, id, tg)
		},
		showTags: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id string) ([]tag, error) {
			return showPrivateResourceTags(ctx, e.svc, tenant, transitSubnetTagResource, id)
		},
		deleteTag: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id, key string) error {
			return deletePrivateResourceTag(ctx, e.svc, tenant, transitSubnetTagResource, id, key)
		},
		batchTags: func(e *privateTagEnv, ctx context.Context, tenant Tenant, id, action string, tags []tag) error {
			return batchPrivateResourceTags(ctx, e.svc, tenant, transitSubnetTagResource, id, action, tags)
		},
	},
}

func TestPrivateTagGoldenLifecycle(t *testing.T) {
	t.Parallel()
	for _, target := range privateTagTargets {
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			e := newPrivateTagEnv(t)

			// Empty project tags list and empty filter result.
			e.expect(t, "list_private_tags_empty", http.MethodGet, target.basePath+"/tags", "")
			e.expect(t, "list_private_by_tag_filter_empty", http.MethodPost, target.basePath+"/resource_instances/action",
				`{"action": "filter"}`)

			id1 := target.seed(e, t, tagTestTenant, "res-1", nil)
			id2 := target.seed(e, t, tagTestTenant, "res-2", nil)

			// Empty tags on a fresh resource.
			e.expect(t, "show_private_tags_empty", http.MethodGet, target.basePath+"/"+id1+"/tags", "")

			// Single tag create and show.
			e.expect(t, "create_private_tag", http.MethodPost, target.basePath+"/"+id1+"/tags",
				`{"tag": {"key": "key1", "value": "value1"}}`)
			e.expect(t, "create_private_tag", http.MethodPost, target.basePath+"/"+id1+"/tags",
				`{"tag": {"key": "key2", "value": "value2"}}`)
			e.expect(t, "show_private_tags", http.MethodGet, target.basePath+"/"+id1+"/tags", "")

			// Single tag delete.
			e.expect(t, "delete_private_tag", http.MethodDelete, target.basePath+"/"+id1+"/tags/key2", "")

			// Batch create tags on both resources.
			e.expect(t, "batch_create_private_tags", http.MethodPost, target.basePath+"/"+id1+"/tags/action",
				`{"action": "create", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}]}`)
			e.expect(t, "batch_create_private_tags", http.MethodPost, target.basePath+"/"+id2+"/tags/action",
				`{"action": "create", "tags": [{"key": "key1", "value": "value2"}, {"key": "key2", "value": "value2"}]}`)

			// List all project tags.
			e.expect(t, "list_private_tags", http.MethodGet, target.basePath+"/tags", "")

			// List resources by tag: filter and count.
			filterBody := `{
				"offset": "0",
				"limit": "100",
				"action": "filter",
				"tags": [
					{"key": "key1", "values": ["value1"]},
					{"key": "key2", "values": ["value1", "value2"]}
				]
			}`
			countBody := `{
				"action": "count",
				"tags": [
					{"key": "key1", "values": ["value1"]},
					{"key": "key2", "values": ["value1", "value2"]}
				]
			}`
			if target.filterNamed {
				filterBody = `{
					"offset": "0",
					"limit": "100",
					"action": "filter",
					"matches": [{"key": "resource_name", "value": "RES-1"}],
					"tags": [
						{"key": "key1", "values": ["value1"]},
						{"key": "key2", "values": ["value1", "value2"]}
					]
				}`
				countBody = `{
					"action": "count",
					"matches": [{"key": "resource_name", "value": "RES-1"}],
					"tags": [
						{"key": "key1", "values": ["value1"]},
						{"key": "key2", "values": ["value1", "value2"]}
					]
				}`
				e.expect(t, "list_private_by_tag_filter_named", http.MethodPost, target.basePath+"/resource_instances/action", filterBody)
			} else {
				e.expect(t, "list_transit_ips_by_tag_filter", http.MethodPost, target.basePath+"/resource_instances/action", filterBody)
			}
			e.expect(t, "list_private_by_tag_count", http.MethodPost, target.basePath+"/resource_instances/action", countBody)

			// Batch delete tags on id1, including a missing key (must succeed with 204).
			e.expect(t, "batch_delete_private_tags", http.MethodPost, target.basePath+"/"+id1+"/tags/action",
				`{"action": "delete", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}, {"key": "missing", "value": "x"}]}`)
			e.expect(t, "show_private_tags_empty", http.MethodGet, target.basePath+"/"+id1+"/tags", "")
		})
	}
}

func TestPrivateTagGoldenErrors(t *testing.T) {
	t.Parallel()
	for _, target := range privateTagTargets {
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			e := newPrivateTagEnv(t)
			id := target.seed(e, t, tagTestTenant, "priv-err", nil)

			// Unknown resource (NAT.1002, 404) on every per-resource route.
			e.expect(t, target.notFoundGolden, http.MethodGet, target.basePath+"/"+tagTestUnknownID+"/tags", "")
			e.expect(t, target.notFoundGolden, http.MethodPost, target.basePath+"/"+tagTestUnknownID+"/tags",
				`{"tag": {"key": "k1", "value": "v1"}}`)
			e.expect(t, target.notFoundGolden, http.MethodDelete, target.basePath+"/"+tagTestUnknownID+"/tags/k1", "")
			e.expect(t, target.notFoundGolden, http.MethodPost, target.basePath+"/"+tagTestUnknownID+"/tags/action",
				`{"action": "create", "tags": [{"key": "k1", "value": "v1"}]}`)
			e.expect(t, target.notFoundGolden, http.MethodPost, target.basePath+"/"+tagTestUnknownID+"/tags/action",
				`{"action": "delete", "tags": [{"key": "k1"}]}`)

			// Deleting a key the resource lacks on single DELETE -> NAT.1010 (400).
			e.expect(t, "error_nat_1010", http.MethodDelete, target.basePath+"/"+id+"/tags/missing", "")

			// Malformed / empty JSON -> NAT.1010 (400).
			badJSON := []struct {
				name string
				path string
				body string
			}{
				{"create empty", target.basePath + "/" + id + "/tags", ``},
				{"create malformed", target.basePath + "/" + id + "/tags", `{"tag":`},
				{"batch empty", target.basePath + "/" + id + "/tags/action", ``},
				{"batch malformed", target.basePath + "/" + id + "/tags/action", `{"action":`},
				{"list_by_tag empty", target.basePath + "/resource_instances/action", ``},
				{"list_by_tag malformed", target.basePath + "/resource_instances/action", `{"action":`},
			}
			for _, tc := range badJSON {
				t.Run("json_"+tc.name, func(t *testing.T) {
					e.expect(t, "error_nat_1010", http.MethodPost, tc.path, tc.body)
				})
			}

			// Invalid tags -> NAT.1015 (400).
			invalidTags := []struct {
				name string
				path string
				body string
			}{
				{"create nil tag", target.basePath + "/" + id + "/tags", `{}`},
				{"create empty key", target.basePath + "/" + id + "/tags", `{"tag": {"key": "", "value": "v"}}`},
				{"create key over 128", target.basePath + "/" + id + "/tags", `{"tag": {"key": "` + strings.Repeat("k", 129) + `", "value": "v"}}`},
				{"create value over 255", target.basePath + "/" + id + "/tags", `{"tag": {"key": "k", "value": "` + strings.Repeat("v", 256) + `"}}`},
				{"batch create empty tags", target.basePath + "/" + id + "/tags/action", `{"action": "create", "tags": []}`},
				{"batch delete empty tags", target.basePath + "/" + id + "/tags/action", `{"action": "delete", "tags": []}`},
				{"batch create empty key", target.basePath + "/" + id + "/tags/action", `{"action": "create", "tags": [{"key": "", "value": "v"}]}`},
				{"batch create key over 128", target.basePath + "/" + id + "/tags/action", `{"action": "create", "tags": [{"key": "` + strings.Repeat("k", 129) + `", "value": "v"}]}`},
				{"batch create value over 255", target.basePath + "/" + id + "/tags/action", `{"action": "create", "tags": [{"key": "k", "value": "` + strings.Repeat("v", 256) + `"}]}`},
				{"batch create duplicate key", target.basePath + "/" + id + "/tags/action", `{"action": "create", "tags": [{"key": "dup", "value": "v1"}, {"key": "dup", "value": "v2"}]}`},
				{"batch delete empty key", target.basePath + "/" + id + "/tags/action", `{"action": "delete", "tags": [{"key": ""}]}`},
				{"batch delete key over 128", target.basePath + "/" + id + "/tags/action", `{"action": "delete", "tags": [{"key": "` + strings.Repeat("k", 129) + `"}]}`},
				{"filter empty key", target.basePath + "/resource_instances/action", `{"action": "filter", "tags": [{"key": "", "values": ["v"]}]}`},
				{"filter space-only key", target.basePath + "/resource_instances/action", `{"action": "filter", "tags": [{"key": "   ", "values": ["v"]}]}`},
				{"filter key over 128", target.basePath + "/resource_instances/action", `{"action": "filter", "tags": [{"key": "` + strings.Repeat("k", 129) + `", "values": ["v"]}]}`},
				{"filter duplicate key", target.basePath + "/resource_instances/action", `{"action": "filter", "tags": [{"key": "k", "values": ["v1"]}, {"key": "k", "values": ["v2"]}]}`},
				{"filter value over 255", target.basePath + "/resource_instances/action", `{"action": "filter", "tags": [{"key": "k", "values": ["` + strings.Repeat("v", 256) + `"]}]}`},
				{"filter duplicate value", target.basePath + "/resource_instances/action", `{"action": "filter", "tags": [{"key": "k", "values": ["v1", "v1"]}]}`},
			}
			for _, tc := range invalidTags {
				t.Run("tag_"+tc.name, func(t *testing.T) {
					e.expect(t, "error_nat_1015", http.MethodPost, tc.path, tc.body)
				})
			}

			// Invalid parameters -> NAT.1010 (400).
			invalidParams := []struct {
				name string
				path string
				body string
			}{
				{"batch missing action", target.basePath + "/" + id + "/tags/action", `{"tags": [{"key": "k", "value": "v"}]}`},
				{"batch unknown action", target.basePath + "/" + id + "/tags/action", `{"action": "update", "tags": [{"key": "k", "value": "v"}]}`},
				{"list missing action", target.basePath + "/resource_instances/action", `{}`},
				{"list unknown action", target.basePath + "/resource_instances/action", `{"action": "list"}`},
				{"limit zero", target.basePath + "/resource_instances/action", `{"action": "filter", "limit": 0}`},
				{"limit negative", target.basePath + "/resource_instances/action", `{"action": "filter", "limit": -1}`},
				{"limit over 1000", target.basePath + "/resource_instances/action", `{"action": "filter", "limit": 1001}`},
				{"limit bad string", target.basePath + "/resource_instances/action", `{"action": "filter", "limit": "abc"}`},
				{"limit float", target.basePath + "/resource_instances/action", `{"action": "filter", "limit": 1.5}`},
				{"limit bool", target.basePath + "/resource_instances/action", `{"action": "filter", "limit": true}`},
				{"offset negative", target.basePath + "/resource_instances/action", `{"action": "filter", "offset": -1}`},
				{"offset negative string", target.basePath + "/resource_instances/action", `{"action": "filter", "offset": "-5"}`},
				{"offset bad string", target.basePath + "/resource_instances/action", `{"action": "filter", "offset": "abc"}`},
				{"offset float", target.basePath + "/resource_instances/action", `{"action": "filter", "offset": 2.5}`},
				{"unsupported match key", target.basePath + "/resource_instances/action", `{"action": "filter", "matches": [{"key": "resource_id", "value": "x"}]}`},
				{"match value over 255", target.basePath + "/resource_instances/action", `{"action": "filter", "matches": [{"key": "resource_name", "value": "` + strings.Repeat("a", 256) + `"}]}`},
			}
			for _, tc := range invalidParams {
				t.Run("param_"+tc.name, func(t *testing.T) {
					e.expect(t, "error_nat_1010", http.MethodPost, tc.path, tc.body)
				})
			}

			// More than 20 tags -> NAT.1016 (400).
			var fullTags []tag
			for i := range maxTags {
				fullTags = append(fullTags, tag{Key: fmt.Sprintf("k%02d", i), Value: "v"})
			}
			fullID := target.seed(e, t, tagTestTenant, "priv-full", fullTags)
			e.expect(t, "error_nat_1016", http.MethodPost, target.basePath+"/"+fullID+"/tags",
				`{"tag": {"key": "k20", "value": "v"}}`)
			e.expect(t, "error_nat_1016", http.MethodPost, target.basePath+"/"+fullID+"/tags/action",
				`{"action": "create", "tags": [{"key": "k00", "value": "updated"}, {"key": "k20", "value": "overflow"}]}`)
		})
	}
}

func TestPrivateTagOverwriteBoundariesUpdatedAtAndMaxTags(t *testing.T) {
	t.Parallel()
	for _, target := range privateTagTargets {
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			e := newPrivateTagEnv(t)
			id := target.seed(e, t, tagTestTenant, "priv-bounds", nil)
			initialUpdated := target.updatedAt(e, t, tagTestTenant, id)

			maxKey := strings.Repeat("é", 128)
			maxVal := strings.Repeat("中", 255)

			// Advance clock before create and verify UpdatedAt updates.
			e.clock.Advance(5 * time.Second)
			status, out := e.call(t, http.MethodPost, target.basePath+"/"+id+"/tags",
				`{"tag": {"key": "`+maxKey+`", "value": "`+maxVal+`"}}`)
			if status != http.StatusNoContent {
				t.Fatalf("create max key/val: %d %s", status, out)
			}
			afterCreate := target.updatedAt(e, t, tagTestTenant, id)
			if !afterCreate.After(initialUpdated) {
				t.Fatalf("UpdatedAt after create = %v, want > %v", afterCreate, initialUpdated)
			}

			status, out = e.call(t, http.MethodPost, target.basePath+"/"+id+"/tags",
				`{"tag": {"key": "empty-val", "value": ""}}`)
			if status != http.StatusNoContent {
				t.Fatalf("create empty value: %d %s", status, out)
			}

			// Overwrite existing key via single create and batch create.
			e.clock.Advance(5 * time.Second)
			status, out = e.call(t, http.MethodPost, target.basePath+"/"+id+"/tags",
				`{"tag": {"key": "`+maxKey+`", "value": "updated"}}`)
			if status != http.StatusNoContent {
				t.Fatalf("overwrite tag: %d %s", status, out)
			}
			afterOverwrite := target.updatedAt(e, t, tagTestTenant, id)
			if !afterOverwrite.After(afterCreate) {
				t.Fatalf("UpdatedAt after overwrite = %v, want > %v", afterOverwrite, afterCreate)
			}

			e.clock.Advance(5 * time.Second)
			status, out = e.call(t, http.MethodPost, target.basePath+"/"+id+"/tags/action",
				`{"action": "create", "tags": [{"key": "empty-val", "value": "now-set"}, {"key": "k3", "value": "v3"}]}`)
			if status != http.StatusNoContent {
				t.Fatalf("batch overwrite: %d %s", status, out)
			}
			afterBatch := target.updatedAt(e, t, tagTestTenant, id)
			if !afterBatch.After(afterOverwrite) {
				t.Fatalf("UpdatedAt after batch = %v, want > %v", afterBatch, afterOverwrite)
			}

			// Add 17 more tags to reach exact limit of 20.
			var batch []tag
			for i := 4; i <= maxTags; i++ {
				batch = append(batch, tag{Key: fmt.Sprintf("k%d", i), Value: fmt.Sprintf("v%d", i)})
			}
			body, err := json.Marshal(batchNatGatewayTagsRequest{Action: "create", Tags: batch})
			if err != nil {
				t.Fatal(err)
			}
			status, out = e.call(t, http.MethodPost, target.basePath+"/"+id+"/tags/action", string(body))
			if status != http.StatusNoContent {
				t.Fatalf("fill to 20 tags: %d %s", status, out)
			}

			// Overwriting an existing key when at 20 tags must still succeed.
			status, out = e.call(t, http.MethodPost, target.basePath+"/"+id+"/tags",
				`{"tag": {"key": "k3", "value": "v3-updated"}}`)
			if status != http.StatusNoContent {
				t.Fatalf("overwrite at 20 tags: %d %s", status, out)
			}

			// Failed batch create (NAT.1016) must NOT mutate tags or advance UpdatedAt.
			beforeFail := target.updatedAt(e, t, tagTestTenant, id)
			e.clock.Advance(5 * time.Second)
			e.expect(t, "error_nat_1016", http.MethodPost, target.basePath+"/"+id+"/tags/action",
				`{"action": "create", "tags": [{"key": "k3", "value": "should-not-apply"}, {"key": "k21", "value": "overflow"}]}`)
			if gotUpdated := target.updatedAt(e, t, tagTestTenant, id); !gotUpdated.Equal(beforeFail) {
				t.Fatalf("UpdatedAt changed on failed batch: got %v, want %v", gotUpdated, beforeFail)
			}

			// Verify k3 was NOT mutated and count is still 20.
			status, out = e.call(t, http.MethodGet, target.basePath+"/"+id+"/tags", "")
			if status != http.StatusOK {
				t.Fatalf("show tags: %d %s", status, out)
			}
			got := privateTagDecodeInto[showPrivateTagsResponse](t, out).Tags
			if len(got) != maxTags {
				t.Fatalf("len(tags) = %d, want %d", len(got), maxTags)
			}
			if got[0].Key != maxKey || got[0].Value != "updated" || got[1].Key != "empty-val" || got[1].Value != "now-set" || got[2].Key != "k3" || got[2].Value != "v3-updated" {
				t.Fatalf("unexpected first 3 tags: %+v", got[:3])
			}

			// Single delete and batch delete advance UpdatedAt.
			e.clock.Advance(5 * time.Second)
			status, out = e.call(t, http.MethodDelete, target.basePath+"/"+id+"/tags/k20", "")
			if status != http.StatusNoContent {
				t.Fatalf("delete k20: %d %s", status, out)
			}
			afterDel := target.updatedAt(e, t, tagTestTenant, id)
			if !afterDel.After(beforeFail) {
				t.Fatalf("UpdatedAt after single delete = %v, want > %v", afterDel, beforeFail)
			}

			e.clock.Advance(5 * time.Second)
			status, out = e.call(t, http.MethodPost, target.basePath+"/"+id+"/tags/action",
				`{"action": "delete", "tags": [{"key": "k19"}]}`)
			if status != http.StatusNoContent {
				t.Fatalf("batch delete k19: %d %s", status, out)
			}
			afterBatchDel := target.updatedAt(e, t, tagTestTenant, id)
			if !afterBatchDel.After(afterDel) {
				t.Fatalf("UpdatedAt after batch delete = %v, want > %v", afterBatchDel, afterDel)
			}
		})
	}
}

func TestPrivateTagListByTagFilteringMatchesAndPaging(t *testing.T) {
	t.Parallel()
	for _, target := range privateTagTargets {
		if !target.filterNamed {
			continue
		}
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			e := newPrivateTagEnv(t)

			id1 := target.seed(e, t, tagTestTenant, "Prod-Resource-Alpha", []tag{
				{Key: "env", Value: "prod"},
				{Key: "team", Value: "core-platform"},
			})
			id2 := target.seed(e, t, tagTestTenant, "Staging-Resource-Beta", []tag{
				{Key: "env", Value: "staging"},
				{Key: "team", Value: "core-platform"},
			})
			id3 := target.seed(e, t, tagTestTenant, "prod-resource-gamma", []tag{
				{Key: "env", Value: "prod"},
				{Key: "team", Value: "edge-net"},
			})
			// Another project's resource must never leak into tag queries.
			otherTenant := Tenant{Region: tagTestRegion, ProjectID: "ffffffffffffffffffffffffffffffff"}
			target.seed(e, t, otherTenant, "Prod-Resource-Other", []tag{
				{Key: "env", Value: "prod"},
				{Key: "team", Value: "core-platform"},
			})

			// Empty values matches any value for that key.
			status, out := e.call(t, http.MethodPost, target.basePath+"/resource_instances/action",
				`{"action": "filter", "tags": [{"key": "team", "values": []}]}`)
			if status != http.StatusOK {
				t.Fatalf("filter any value: %d %s", status, out)
			}
			res := privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
			if res.RequestID == "" || res.TotalCount != 3 || len(res.Resources) != 3 {
				t.Fatalf("filter any value = %+v, want 3 with request_id", res)
			}

			// Pagination with integer limit and offset.
			status, out = e.call(t, http.MethodPost, target.basePath+"/resource_instances/action",
				`{"action": "filter", "limit": 1, "offset": 1, "tags": [{"key": "team", "values": []}]}`)
			if status != http.StatusOK {
				t.Fatalf("filter paged: %d %s", status, out)
			}
			res = privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
			if res.TotalCount != 3 || len(res.Resources) != 1 || res.Resources[0].ResourceID != id2 || res.Resources[0].ResourceName != "Staging-Resource-Beta" {
				t.Fatalf("filter paged = %+v, want id2 (%s)", res, id2)
			}

			// Offset beyond total_count returns empty resources slice and full total_count.
			status, out = e.call(t, http.MethodPost, target.basePath+"/resource_instances/action",
				`{"action": "filter", "limit": "10", "offset": "5", "tags": [{"key": "team", "values": []}]}`)
			if status != http.StatusOK {
				t.Fatalf("filter high offset: %d %s", status, out)
			}
			res = privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
			if res.TotalCount != 3 || len(res.Resources) != 0 {
				t.Fatalf("filter high offset = %+v, want total=3 len=0", res)
			}

			// matches on resource_name: case-insensitive fuzzy substring match.
			status, out = e.call(t, http.MethodPost, target.basePath+"/resource_instances/action",
				`{"action": "filter", "matches": [{"key": "resource_name", "value": "PROD-RESOURCE"}]}`)
			if status != http.StatusOK {
				t.Fatalf("matches fuzzy: %d %s", status, out)
			}
			res = privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
			if res.TotalCount != 2 || len(res.Resources) != 2 || res.Resources[0].ResourceID != id1 || res.Resources[1].ResourceID != id3 {
				t.Fatalf("matches fuzzy = %+v, want [id1, id3]", res)
			}

			// matches on resource_name with empty string uses exact match (none match since all have names).
			status, out = e.call(t, http.MethodPost, target.basePath+"/resource_instances/action",
				`{"action": "filter", "matches": [{"key": "resource_name", "value": ""}]}`)
			if status != http.StatusOK {
				t.Fatalf("matches empty exact: %d %s", status, out)
			}
			res = privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
			if res.TotalCount != 0 || len(res.Resources) != 0 {
				t.Fatalf("matches empty exact = %+v, want 0", res)
			}

			// Star-prefixed tag value does fuzzy substring match.
			status, out = e.call(t, http.MethodPost, target.basePath+"/resource_instances/action",
				`{"action": "filter", "tags": [{"key": "team", "values": ["*platform"]}]}`)
			if status != http.StatusOK {
				t.Fatalf("star prefix filter: %d %s", status, out)
			}
			res = privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
			if res.TotalCount != 2 || res.Resources[0].ResourceID != id1 || res.Resources[1].ResourceID != id2 {
				t.Fatalf("star prefix filter = %+v, want [id1, id2]", res)
			}

			// tags_any, not_tags, not_tags_any.
			status, out = e.call(t, http.MethodPost, target.basePath+"/resource_instances/action", `{
				"action": "filter",
				"tags_any": [{"key": "env", "values": ["staging"]}, {"key": "team", "values": ["edge-net"]}]
			}`)
			if status != http.StatusOK {
				t.Fatalf("tags_any: %d %s", status, out)
			}
			res = privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
			if res.TotalCount != 2 || res.Resources[0].ResourceID != id2 || res.Resources[1].ResourceID != id3 {
				t.Fatalf("tags_any = %+v, want [id2, id3]", res)
			}

			status, out = e.call(t, http.MethodPost, target.basePath+"/resource_instances/action", `{
				"action": "filter",
				"not_tags": [{"key": "env", "values": ["prod"]}, {"key": "team", "values": ["core-platform"]}]
			}`)
			if status != http.StatusOK {
				t.Fatalf("not_tags: %d %s", status, out)
			}
			res = privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
			if res.TotalCount != 2 || res.Resources[0].ResourceID != id2 || res.Resources[1].ResourceID != id3 {
				t.Fatalf("not_tags = %+v, want [id2, id3]", res)
			}

			status, out = e.call(t, http.MethodPost, target.basePath+"/resource_instances/action", `{
				"action": "filter",
				"not_tags_any": [{"key": "env", "values": ["staging"]}, {"key": "team", "values": ["edge-net"]}]
			}`)
			if status != http.StatusOK {
				t.Fatalf("not_tags_any: %d %s", status, out)
			}
			res = privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
			if res.TotalCount != 1 || res.Resources[0].ResourceID != id1 {
				t.Fatalf("not_tags_any = %+v, want [id1]", res)
			}

			// action=count returns request_id and total_count only, ignoring limit/offset.
			status, out = e.call(t, http.MethodPost, target.basePath+"/resource_instances/action",
				`{"action": "count", "limit": "bad", "offset": "-99", "tags": [{"key": "env", "values": ["prod"]}]}`)
			if status != http.StatusOK {
				t.Fatalf("count: %d %s", status, out)
			}
			var rawMap map[string]any
			if err := json.Unmarshal(out, &rawMap); err != nil {
				t.Fatal(err)
			}
			if _, hasResources := rawMap["resources"]; hasResources {
				t.Fatalf("count response must not include resources: %s", out)
			}
			if rawMap["request_id"] == "" || rawMap["total_count"] != float64(2) {
				t.Fatalf("count = %v, want request_id and total_count=2", rawMap)
			}
		})
	}
}

func TestTransitIPTagEmptyResourceNameMatches(t *testing.T) {
	t.Parallel()
	e := newPrivateTagEnv(t)
	ip := e.seedTransitIP(t, tagTestTenant, "10.2.0.10", []tag{{Key: "env", Value: "prod"}})

	// Transit IPs have no name, so resource_name is "" and non-empty match excludes them.
	status, out := e.call(t, http.MethodPost, "/transit-ips/resource_instances/action",
		`{"action": "filter", "matches": [{"key": "resource_name", "value": "10.2.0.10"}]}`)
	if status != http.StatusOK {
		t.Fatalf("non-empty match: %d %s", status, out)
	}
	res := privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
	if res.TotalCount != 0 || len(res.Resources) != 0 {
		t.Fatalf("non-empty match = %+v, want 0", res)
	}

	// Empty resource_name exact match includes transit IPs with resource_name="".
	status, out = e.call(t, http.MethodPost, "/transit-ips/resource_instances/action",
		`{"action": "filter", "matches": [{"key": "resource_name", "value": ""}]}`)
	if status != http.StatusOK {
		t.Fatalf("empty match: %d %s", status, out)
	}
	res = privateTagDecodeInto[listPrivateByTagsFilterResponse](t, out)
	if res.TotalCount != 1 || len(res.Resources) != 1 || res.Resources[0].ResourceID != ip.ID || res.Resources[0].ResourceName != "" {
		t.Fatalf("empty match = %+v, want [ip] with empty resource_name", res)
	}
}

func TestPrivateTagConcurrentWrites(t *testing.T) {
	t.Parallel()
	for _, target := range privateTagTargets {
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			e := newPrivateTagEnv(t)
			id := target.seed(e, t, tagTestTenant, "priv-concurrent", nil)

			const workers = 10
			var wg sync.WaitGroup
			wg.Add(workers)
			for i := range workers {
				go func(i int) {
					defer wg.Done()
					key := fmt.Sprintf("k%d", i)
					if err := target.createTag(e, t.Context(), tagTestTenant, id, tag{Key: key, Value: "v1"}); err != nil {
						t.Errorf("create %s: %v", key, err)
						return
					}
					if err := target.createTag(e, t.Context(), tagTestTenant, id, tag{Key: key, Value: "v2"}); err != nil {
						t.Errorf("overwrite %s: %v", key, err)
					}
				}(i)
			}
			wg.Wait()

			tags, err := target.showTags(e, t.Context(), tagTestTenant, id)
			if err != nil {
				t.Fatalf("showTags: %v", err)
			}
			if len(tags) != workers {
				t.Fatalf("len(tags) = %d, want %d", len(tags), workers)
			}
			for _, tg := range tags {
				if tg.Value != "v2" {
					t.Errorf("tag %s = %q, want v2", tg.Key, tg.Value)
				}
			}
		})
	}
}
