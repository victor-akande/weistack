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

const (
	tagTestProject   = "0123456789abcdef0123456789abcdef"
	tagTestRegion    = "ap-southeast-1"
	tagTestHost      = "nat." + tagTestRegion + ".myhuaweicloud.com"
	tagTestDelay     = 2 * time.Second
	tagTestUnknownID = "00000000-0000-4000-8000-000000000000"
)

var (
	tagTestTenant = Tenant{Region: tagTestRegion, ProjectID: tagTestProject}
	tagTestEpoch  = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
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
func (tagStubVPC) Port(context.Context, vpc.Tenant, string) (vpc.Port, bool, error) {
	return vpc.Port{}, false, nil
}
func (tagStubVPC) AllocateIP(context.Context, vpc.Tenant, string, string, string) (string, error) {
	return "", nil
}
func (tagStubVPC) ReleaseIP(context.Context, vpc.Tenant, string, string) error {
	return nil
}

type tagStubEIPs struct{}

func (tagStubEIPs) HoldForNAT(context.Context, vpc.Tenant, string, string) (string, error) {
	return "", nil
}
func (tagStubEIPs) ReleaseFromNAT(context.Context, vpc.Tenant, string, string) error {
	return nil
}
func (tagStubEIPs) PublicIPByAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}
func (tagStubEIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type tagEnv struct {
	svc     *Service
	store   store.Store
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	ids     *ids.Generator
	handler http.Handler
}

func newTagEnv(t *testing.T) *tagEnv {
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
		VPC:    tagStubVPC{},
		EIPs:   tagStubEIPs{},
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
	return &tagEnv{
		svc:     natSvc,
		store:   st,
		engine:  engine,
		clock:   clock,
		ids:     gen,
		handler: srv.Handler(),
	}
}

func (e *tagEnv) seedGateway(t *testing.T, tenant Tenant, name string, tags []tag) gateway {
	t.Helper()
	gw := gateway{
		ID:                  e.ids.UUID(),
		Name:                name,
		Spec:                "1",
		Status:              StatusActive,
		RouterID:            e.ids.UUID(),
		InternalNetworkID:   e.ids.UUID(),
		NgportIP:            "192.168.0.10",
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Session:             defaultSessionConf,
		Tags:                tags,
		CreatedAt:           e.svc.nowUTC(),
	}
	if err := e.svc.gateways(tenant).Create(t.Context(), gw.ID, gw); err != nil {
		t.Fatalf("seedGateway: %v", err)
	}
	return gw
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

func TestNatGatewayTagGoldenLifecycle(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"/v3", "/v2.0"} {
		t.Run(strings.TrimPrefix(prefix, "/"), func(t *testing.T) {
			t.Parallel()
			e := newTagEnv(t)

			// Empty project tags list and empty filter result.
			e.expect(t, prefix, "list_nat_gateway_tags_empty", http.MethodGet, "/nat_gateways/tags", "")
			e.expect(t, prefix, "list_nat_gateways_by_tag_filter_empty", http.MethodPost, "/nat_gateways/resource_instances/action",
				`{"action": "filter"}`)

			gw1 := e.seedGateway(t, tagTestTenant, "nat-gw-1", nil)
			gw2 := e.seedGateway(t, tagTestTenant, "nat-gw-2", nil)

			// Empty tags on a fresh gateway.
			e.expect(t, prefix, "show_nat_gateway_tags_empty", http.MethodGet, "/nat_gateways/"+gw1.ID+"/tags", "")

			// Single tag create and show.
			e.expect(t, prefix, "create_nat_gateway_tag", http.MethodPost, "/nat_gateways/"+gw1.ID+"/tags",
				`{"tag": {"key": "key1", "value": "value1"}}`)
			e.expect(t, prefix, "create_nat_gateway_tag", http.MethodPost, "/nat_gateways/"+gw1.ID+"/tags",
				`{"tag": {"key": "key2", "value": "value2"}}`)
			e.expect(t, prefix, "show_nat_gateway_tags", http.MethodGet, "/nat_gateways/"+gw1.ID+"/tags", "")

			// Single tag delete.
			e.expect(t, prefix, "delete_nat_gateway_tag", http.MethodDelete, "/nat_gateways/"+gw1.ID+"/tags/key2", "")

			// Batch create tags on gw1 and gw2.
			e.expect(t, prefix, "batch_create_nat_gateway_tags", http.MethodPost, "/nat_gateways/"+gw1.ID+"/tags/action",
				`{"action": "create", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}]}`)
			e.expect(t, prefix, "batch_create_nat_gateway_tags", http.MethodPost, "/nat_gateways/"+gw2.ID+"/tags/action",
				`{"action": "create", "tags": [{"key": "key1", "value": "value2"}, {"key": "key2", "value": "value2"}]}`)

			// List all project tags.
			e.expect(t, prefix, "list_nat_gateway_tags", http.MethodGet, "/nat_gateways/tags", "")

			// List gateways by tag: filter and count.
			e.expect(t, prefix, "list_nat_gateways_by_tag_filter", http.MethodPost, "/nat_gateways/resource_instances/action", `{
				"offset": "0",
				"limit": "100",
				"action": "filter",
				"matches": [{"key": "resource_name", "value": "GW-1"}],
				"tags": [
					{"key": "key1", "values": ["value1"]},
					{"key": "key2", "values": ["value1", "value2"]}
				]
			}`)
			e.expect(t, prefix, "list_nat_gateways_by_tag_count", http.MethodPost, "/nat_gateways/resource_instances/action", `{
				"action": "count",
				"matches": [{"key": "resource_name", "value": "GW-1"}],
				"tags": [
					{"key": "key1", "values": ["value1"]},
					{"key": "key2", "values": ["value1", "value2"]}
				]
			}`)

			// Batch delete tags on gw1, including a missing key (must succeed with 204).
			e.expect(t, prefix, "batch_delete_nat_gateway_tags", http.MethodPost, "/nat_gateways/"+gw1.ID+"/tags/action",
				`{"action": "delete", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}, {"key": "missing", "value": "x"}]}`)
			e.expect(t, prefix, "show_nat_gateway_tags_empty", http.MethodGet, "/nat_gateways/"+gw1.ID+"/tags", "")
		})
	}
}

func TestNatGatewayTagGoldenErrors(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"/v3", "/v2.0"} {
		t.Run(strings.TrimPrefix(prefix, "/"), func(t *testing.T) {
			t.Parallel()
			e := newTagEnv(t)
			gw := e.seedGateway(t, tagTestTenant, "nat-err", nil)

			// Unknown gateway (NAT.0105, 404) on every per-gateway route.
			e.expect(t, prefix, "error_nat_0105", http.MethodGet, "/nat_gateways/"+tagTestUnknownID+"/tags", "")
			e.expect(t, prefix, "error_nat_0105", http.MethodPost, "/nat_gateways/"+tagTestUnknownID+"/tags",
				`{"tag": {"key": "k1", "value": "v1"}}`)
			e.expect(t, prefix, "error_nat_0105", http.MethodDelete, "/nat_gateways/"+tagTestUnknownID+"/tags/k1", "")
			e.expect(t, prefix, "error_nat_0105", http.MethodPost, "/nat_gateways/"+tagTestUnknownID+"/tags/action",
				`{"action": "create", "tags": [{"key": "k1", "value": "v1"}]}`)
			e.expect(t, prefix, "error_nat_0105", http.MethodPost, "/nat_gateways/"+tagTestUnknownID+"/tags/action",
				`{"action": "delete", "tags": [{"key": "k1"}]}`)

			// Deleting a key the gateway lacks on single DELETE -> NAT.0002 (400).
			e.expect(t, prefix, "error_nat_0002", http.MethodDelete, "/nat_gateways/"+gw.ID+"/tags/missing", "")

			// Malformed / empty JSON -> NAT.1010 (400).
			badJSON := []struct {
				name string
				path string
				body string
			}{
				{"create empty", "/nat_gateways/" + gw.ID + "/tags", ``},
				{"create malformed", "/nat_gateways/" + gw.ID + "/tags", `{"tag":`},
				{"batch empty", "/nat_gateways/" + gw.ID + "/tags/action", ``},
				{"batch malformed", "/nat_gateways/" + gw.ID + "/tags/action", `{"action":`},
				{"list_by_tag empty", "/nat_gateways/resource_instances/action", ``},
				{"list_by_tag malformed", "/nat_gateways/resource_instances/action", `{"action":`},
			}
			for _, tc := range badJSON {
				t.Run("json_"+tc.name, func(t *testing.T) {
					e.expect(t, prefix, "error_nat_1010", http.MethodPost, tc.path, tc.body)
				})
			}

			// Invalid tags -> NAT.1015 (400).
			invalidTags := []struct {
				name string
				path string
				body string
			}{
				{"create nil tag", "/nat_gateways/" + gw.ID + "/tags", `{}`},
				{"create empty key", "/nat_gateways/" + gw.ID + "/tags", `{"tag": {"key": "", "value": "v"}}`},
				{"create key over max", "/nat_gateways/" + gw.ID + "/tags", `{"tag": {"key": "` + strings.Repeat("k", maxTagFilterKeyLen+1) + `", "value": "v"}}`},
				{"create value over max", "/nat_gateways/" + gw.ID + "/tags", `{"tag": {"key": "k", "value": "` + strings.Repeat("v", maxTagFilterValueLen+1) + `"}}`},
				{"batch create empty tags", "/nat_gateways/" + gw.ID + "/tags/action", `{"action": "create", "tags": []}`},
				{"batch delete empty tags", "/nat_gateways/" + gw.ID + "/tags/action", `{"action": "delete", "tags": []}`},
				{"batch create empty key", "/nat_gateways/" + gw.ID + "/tags/action", `{"action": "create", "tags": [{"key": "", "value": "v"}]}`},
				{"batch create key over max", "/nat_gateways/" + gw.ID + "/tags/action", `{"action": "create", "tags": [{"key": "` + strings.Repeat("k", maxTagFilterKeyLen+1) + `", "value": "v"}]}`},
				{"batch create value over max", "/nat_gateways/" + gw.ID + "/tags/action", `{"action": "create", "tags": [{"key": "k", "value": "` + strings.Repeat("v", maxTagFilterValueLen+1) + `"}]}`},
				{"batch create duplicate key", "/nat_gateways/" + gw.ID + "/tags/action", `{"action": "create", "tags": [{"key": "dup", "value": "v1"}, {"key": "dup", "value": "v2"}]}`},
				{"batch delete empty key", "/nat_gateways/" + gw.ID + "/tags/action", `{"action": "delete", "tags": [{"key": ""}]}`},
				{"batch delete key over max", "/nat_gateways/" + gw.ID + "/tags/action", `{"action": "delete", "tags": [{"key": "` + strings.Repeat("k", maxTagFilterKeyLen+1) + `"}]}`},
				{"filter empty key", "/nat_gateways/resource_instances/action", `{"action": "filter", "tags": [{"key": "", "values": ["v"]}]}`},
				{"filter space-only key", "/nat_gateways/resource_instances/action", `{"action": "filter", "tags": [{"key": "   ", "values": ["v"]}]}`},
				{"filter key over max", "/nat_gateways/resource_instances/action", `{"action": "filter", "tags": [{"key": "` + strings.Repeat("k", maxTagFilterKeyLen+1) + `", "values": ["v"]}]}`},
				{"filter duplicate key", "/nat_gateways/resource_instances/action", `{"action": "filter", "tags": [{"key": "k", "values": ["v1"]}, {"key": "k", "values": ["v2"]}]}`},
				{"filter value over max", "/nat_gateways/resource_instances/action", `{"action": "filter", "tags": [{"key": "k", "values": ["` + strings.Repeat("v", maxTagFilterValueLen+1) + `"]}]}`},
				{"filter duplicate value", "/nat_gateways/resource_instances/action", `{"action": "filter", "tags": [{"key": "k", "values": ["v1", "v1"]}]}`},
			}
			for _, tc := range invalidTags {
				t.Run("tag_"+tc.name, func(t *testing.T) {
					e.expect(t, prefix, "error_nat_1015", http.MethodPost, tc.path, tc.body)
				})
			}

			// Invalid parameters -> NAT.0002 (400).
			invalidParams := []struct {
				name string
				path string
				body string
			}{
				{"batch missing action", "/nat_gateways/" + gw.ID + "/tags/action", `{"tags": [{"key": "k", "value": "v"}]}`},
				{"batch unknown action", "/nat_gateways/" + gw.ID + "/tags/action", `{"action": "update", "tags": [{"key": "k", "value": "v"}]}`},
				{"list missing action", "/nat_gateways/resource_instances/action", `{}`},
				{"list unknown action", "/nat_gateways/resource_instances/action", `{"action": "list"}`},
				{"limit zero", "/nat_gateways/resource_instances/action", `{"action": "filter", "limit": 0}`},
				{"limit negative", "/nat_gateways/resource_instances/action", `{"action": "filter", "limit": -1}`},
				{"limit over max", "/nat_gateways/resource_instances/action", fmt.Sprintf(`{"action": "filter", "limit": %d}`, maxTagFilterPage+1)},
				{"limit bad string", "/nat_gateways/resource_instances/action", `{"action": "filter", "limit": "abc"}`},
				{"limit float", "/nat_gateways/resource_instances/action", `{"action": "filter", "limit": 1.5}`},
				{"limit bool", "/nat_gateways/resource_instances/action", `{"action": "filter", "limit": true}`},
				{"offset negative", "/nat_gateways/resource_instances/action", `{"action": "filter", "offset": -1}`},
				{"offset negative string", "/nat_gateways/resource_instances/action", `{"action": "filter", "offset": "-5"}`},
				{"offset bad string", "/nat_gateways/resource_instances/action", `{"action": "filter", "offset": "abc"}`},
				{"offset float", "/nat_gateways/resource_instances/action", `{"action": "filter", "offset": 2.5}`},
				{"unsupported match key", "/nat_gateways/resource_instances/action", `{"action": "filter", "matches": [{"key": "resource_id", "value": "x"}]}`},
				{"match value over max", "/nat_gateways/resource_instances/action", `{"action": "filter", "matches": [{"key": "resource_name", "value": "` + strings.Repeat("a", maxMatchValueLen+1) + `"}]}`},
			}
			for _, tc := range invalidParams {
				t.Run("param_"+tc.name, func(t *testing.T) {
					e.expect(t, prefix, "error_nat_0002", http.MethodPost, tc.path, tc.body)
				})
			}

			// More than maxTags -> NAT.1016 (400).
			var fullTags []tag
			for i := range maxTags {
				fullTags = append(fullTags, tag{Key: fmt.Sprintf("k%02d", i), Value: "v"})
			}
			gwFull := e.seedGateway(t, tagTestTenant, "nat-full", fullTags)
			e.expect(t, prefix, "error_nat_1016", http.MethodPost, "/nat_gateways/"+gwFull.ID+"/tags",
				fmt.Sprintf(`{"tag": {"key": "k%d", "value": "v"}}`, maxTags))
			e.expect(t, prefix, "error_nat_1016", http.MethodPost, "/nat_gateways/"+gwFull.ID+"/tags/action",
				fmt.Sprintf(`{"action": "create", "tags": [{"key": "k00", "value": "updated"}, {"key": "k%d", "value": "overflow"}]}`, maxTags))
		})
	}
}

func TestTagOverwriteBoundariesAndMaxTags(t *testing.T) {
	t.Parallel()
	e := newTagEnv(t)
	gw := e.seedGateway(t, tagTestTenant, "nat-bounds", nil)

	// Boundary Unicode lengths (maxTagFilterKeyLen runes, maxTagFilterValueLen runes) and empty value.
	maxKey := strings.Repeat("é", maxTagFilterKeyLen)
	maxVal := strings.Repeat("中", maxTagFilterValueLen)

	status, out := e.call(t, "/v3", http.MethodPost, "/nat_gateways/"+gw.ID+"/tags",
		`{"tag": {"key": "`+maxKey+`", "value": "`+maxVal+`"}}`)
	if status != http.StatusNoContent {
		t.Fatalf("create max key/val: %d %s", status, out)
	}
	status, out = e.call(t, "/v2.0", http.MethodPost, "/nat_gateways/"+gw.ID+"/tags",
		`{"tag": {"key": "empty-val", "value": ""}}`)
	if status != http.StatusNoContent {
		t.Fatalf("create empty value: %d %s", status, out)
	}

	// Overwrite existing key via single create and batch create.
	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/"+gw.ID+"/tags",
		`{"tag": {"key": "`+maxKey+`", "value": "updated"}}`)
	if status != http.StatusNoContent {
		t.Fatalf("overwrite tag: %d %s", status, out)
	}
	status, out = e.call(t, "/v2.0", http.MethodPost, "/nat_gateways/"+gw.ID+"/tags/action",
		`{"action": "create", "tags": [{"key": "empty-val", "value": "now-set"}, {"key": "k3", "value": "v3"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("batch overwrite: %d %s", status, out)
	}

	// Fill remaining slots to reach exact limit of maxTags (3 tags already present).
	var batch []tag
	for i := 4; i <= maxTags; i++ {
		batch = append(batch, tag{Key: fmt.Sprintf("k%d", i), Value: fmt.Sprintf("v%d", i)})
	}
	body, err := json.Marshal(batchNatGatewayTagsRequest{Action: "create", Tags: batch})
	if err != nil {
		t.Fatal(err)
	}
	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/"+gw.ID+"/tags/action", string(body))
	if status != http.StatusNoContent {
		t.Fatalf("fill to %d tags: %d %s", maxTags, status, out)
	}

	// Overwriting an existing key when at maxTags must still succeed.
	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/"+gw.ID+"/tags",
		`{"tag": {"key": "k3", "value": "v3-updated"}}`)
	if status != http.StatusNoContent {
		t.Fatalf("overwrite at %d tags: %d %s", maxTags, status, out)
	}

	// Batch create with 1 existing key + 1 new key at maxTags must fail atomically with NAT.1016.
	e.expect(t, "/v3", "error_nat_1016", http.MethodPost, "/nat_gateways/"+gw.ID+"/tags/action",
		fmt.Sprintf(`{"action": "create", "tags": [{"key": "k3", "value": "should-not-apply"}, {"key": "k%d", "value": "overflow"}]}`, maxTags+1))

	// Verify k3 was NOT mutated by the rejected batch create and count is still maxTags.
	status, out = e.call(t, "/v2.0", http.MethodGet, "/nat_gateways/"+gw.ID+"/tags", "")
	if status != http.StatusOK {
		t.Fatalf("show tags: %d %s", status, out)
	}
	got := tagDecodeInto[showNatGatewayTagsResponse](t, out).Tags
	if len(got) != maxTags {
		t.Fatalf("len(tags) = %d, want %d", len(got), maxTags)
	}
	if got[0].Key != maxKey || got[0].Value != "updated" || got[1].Key != "empty-val" || got[1].Value != "now-set" || got[2].Key != "k3" || got[2].Value != "v3-updated" {
		t.Fatalf("unexpected first 3 tags: %+v", got[:3])
	}
}

func TestTagListByTagFilteringMatchesAndPaging(t *testing.T) {
	t.Parallel()
	e := newTagEnv(t)

	g1 := e.seedGateway(t, tagTestTenant, "Prod-Gateway-Alpha", []tag{
		{Key: "env", Value: "prod"},
		{Key: "team", Value: "core-platform"},
	})
	g2 := e.seedGateway(t, tagTestTenant, "Staging-Gateway-Beta", []tag{
		{Key: "env", Value: "staging"},
		{Key: "team", Value: "core-platform"},
	})
	g3 := e.seedGateway(t, tagTestTenant, "prod-gateway-gamma", []tag{
		{Key: "env", Value: "prod"},
		{Key: "team", Value: "edge-net"},
	})
	// Another project's gateway must never leak into tag queries.
	otherTenant := Tenant{Region: tagTestRegion, ProjectID: "ffffffffffffffffffffffffffffffff"}
	e.seedGateway(t, otherTenant, "Prod-Gateway-Other", []tag{
		{Key: "env", Value: "prod"},
		{Key: "team", Value: "core-platform"},
	})

	// Empty values matches any value for that key.
	status, out := e.call(t, "/v3", http.MethodPost, "/nat_gateways/resource_instances/action",
		`{"action": "filter", "tags": [{"key": "team", "values": []}]}`)
	if status != http.StatusOK {
		t.Fatalf("filter any value: %d %s", status, out)
	}
	res := tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if res.TotalCount != 3 || len(res.Resources) != 3 {
		t.Fatalf("filter any value: total=%d len=%d, want 3", res.TotalCount, len(res.Resources))
	}

	// Pagination with integer limit and offset.
	status, out = e.call(t, "/v2.0", http.MethodPost, "/nat_gateways/resource_instances/action",
		`{"action": "filter", "limit": 1, "offset": 1, "tags": [{"key": "team", "values": []}]}`)
	if status != http.StatusOK {
		t.Fatalf("filter paged: %d %s", status, out)
	}
	res = tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if res.TotalCount != 3 || len(res.Resources) != 1 || res.Resources[0].ResourceID != g2.ID || res.Resources[0].ResourceName != "Staging-Gateway-Beta" {
		t.Fatalf("filter paged = %+v, want g2 (%s)", res, g2.ID)
	}

	// Offset beyond total_count returns empty resources slice and full total_count.
	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/resource_instances/action",
		`{"action": "filter", "limit": "10", "offset": "5", "tags": [{"key": "team", "values": []}]}`)
	if status != http.StatusOK {
		t.Fatalf("filter high offset: %d %s", status, out)
	}
	res = tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if res.TotalCount != 3 || len(res.Resources) != 0 {
		t.Fatalf("filter high offset = %+v, want total=3 len=0", res)
	}

	// matches on resource_name: case-insensitive fuzzy substring match.
	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/resource_instances/action",
		`{"action": "filter", "matches": [{"key": "resource_name", "value": "PROD-GATEWAY"}]}`)
	if status != http.StatusOK {
		t.Fatalf("matches fuzzy: %d %s", status, out)
	}
	res = tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if res.TotalCount != 2 || len(res.Resources) != 2 || res.Resources[0].ResourceID != g1.ID || res.Resources[1].ResourceID != g3.ID {
		t.Fatalf("matches fuzzy = %+v, want [g1, g3]", res)
	}

	// matches on resource_name with empty string uses exact match (none match since all have names).
	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/resource_instances/action",
		`{"action": "filter", "matches": [{"key": "resource_name", "value": ""}]}`)
	if status != http.StatusOK {
		t.Fatalf("matches empty exact: %d %s", status, out)
	}
	res = tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if res.TotalCount != 0 || len(res.Resources) != 0 {
		t.Fatalf("matches empty exact = %+v, want 0", res)
	}

	// Star-prefixed tag value does fuzzy substring match.
	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/resource_instances/action",
		`{"action": "filter", "tags": [{"key": "team", "values": ["*platform"]}]}`)
	if status != http.StatusOK {
		t.Fatalf("star prefix filter: %d %s", status, out)
	}
	res = tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if res.TotalCount != 2 || res.Resources[0].ResourceID != g1.ID || res.Resources[1].ResourceID != g2.ID {
		t.Fatalf("star prefix filter = %+v, want [g1, g2]", res)
	}

	// tags_any (OR across keys) and not_tags (exclude matching all) and not_tags_any (exclude matching any).
	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/resource_instances/action", `{
		"action": "filter",
		"tags_any": [{"key": "env", "values": ["staging"]}, {"key": "team", "values": ["edge-net"]}]
	}`)
	if status != http.StatusOK {
		t.Fatalf("tags_any: %d %s", status, out)
	}
	res = tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if res.TotalCount != 2 || res.Resources[0].ResourceID != g2.ID || res.Resources[1].ResourceID != g3.ID {
		t.Fatalf("tags_any = %+v, want [g2, g3]", res)
	}

	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/resource_instances/action", `{
		"action": "filter",
		"not_tags": [{"key": "env", "values": ["prod"]}, {"key": "team", "values": ["core-platform"]}]
	}`)
	if status != http.StatusOK {
		t.Fatalf("not_tags: %d %s", status, out)
	}
	res = tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if res.TotalCount != 2 || res.Resources[0].ResourceID != g2.ID || res.Resources[1].ResourceID != g3.ID {
		t.Fatalf("not_tags = %+v, want [g2, g3]", res)
	}

	status, out = e.call(t, "/v3", http.MethodPost, "/nat_gateways/resource_instances/action", `{
		"action": "filter",
		"not_tags_any": [{"key": "env", "values": ["staging"]}, {"key": "team", "values": ["edge-net"]}]
	}`)
	if status != http.StatusOK {
		t.Fatalf("not_tags_any: %d %s", status, out)
	}
	res = tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if res.TotalCount != 1 || res.Resources[0].ResourceID != g1.ID {
		t.Fatalf("not_tags_any = %+v, want [g1]", res)
	}

	// action=count returns only total_count and ignores limit/offset.
	status, out = e.call(t, "/v2.0", http.MethodPost, "/nat_gateways/resource_instances/action",
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
	if rawMap["total_count"] != float64(2) {
		t.Fatalf("count total_count = %v, want 2", rawMap["total_count"])
	}
}

func TestTagConcurrentWrites(t *testing.T) {
	t.Parallel()
	e := newTagEnv(t)
	gw := e.seedGateway(t, tagTestTenant, "nat-concurrent", nil)

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", i)
			if err := e.svc.createNatGatewayTag(t.Context(), tagTestTenant, gw.ID, tag{Key: key, Value: "v1"}); err != nil {
				t.Errorf("create %s: %v", key, err)
				return
			}
			if err := e.svc.createNatGatewayTag(t.Context(), tagTestTenant, gw.ID, tag{Key: key, Value: "v2"}); err != nil {
				t.Errorf("overwrite %s: %v", key, err)
			}
		}(i)
	}
	wg.Wait()

	tags, err := e.svc.showNatGatewayTags(t.Context(), tagTestTenant, gw.ID)
	if err != nil {
		t.Fatalf("showNatGatewayTags: %v", err)
	}
	if len(tags) != workers {
		t.Fatalf("len(tags) = %d, want %d", len(tags), workers)
	}
	for _, tg := range tags {
		if tg.Value != "v2" {
			t.Errorf("tag %s = %q, want v2", tg.Key, tg.Value)
		}
	}
}

func TestNatGatewayTagsViaVPCHost(t *testing.T) {
	t.Parallel()
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

	gen := ids.NewSeeded(42)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	natSvc, err := New(Deps{
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		VPC:    vpcSvc,
		EIPs:   tagStubEIPs{},
		Now:    clock.Now,
	})
	if err != nil {
		t.Fatalf("nat.New: %v", err)
	}
	vpcSvc.Extend(natSvc.VPCExtension())

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
		Services:  []server.Service{vpcSvc, natSvc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	handler := srv.Handler()

	gw := gateway{
		ID:                  gen.UUID(),
		Name:                "nat-via-vpc",
		Spec:                "1",
		Status:              StatusActive,
		RouterID:            gen.UUID(),
		InternalNetworkID:   gen.UUID(),
		NgportIP:            "192.168.0.10",
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Session:             defaultSessionConf,
		CreatedAt:           natSvc.nowUTC(),
	}
	if err := natSvc.gateways(tagTestTenant).Create(t.Context(), gw.ID, gw); err != nil {
		t.Fatalf("seed gateway: %v", err)
	}

	vpcHost := "vpc." + tagTestRegion + ".myhuaweicloud.com"
	callHost := func(host, method, path, body string) (int, []byte) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		r := httptest.NewRequest(method, path, rd)
		r.Host = host
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		res := w.Result()
		defer res.Body.Close()
		out, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("reading response: %v", err)
		}
		return res.StatusCode, out
	}

	// Batch create tags through the VPC host (as Terraform's NetworkingV2Client does).
	status, out := callHost(vpcHost, http.MethodPost, "/v2.0/"+tagTestProject+"/nat_gateways/"+gw.ID+"/tags/action",
		`{"action": "create", "tags": [{"key": "env", "value": "test"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("vpc host batch create tags: %d %s", status, out)
	}

	// Single create tag through the VPC host.
	status, out = callHost(vpcHost, http.MethodPost, "/v2.0/"+tagTestProject+"/nat_gateways/"+gw.ID+"/tags",
		`{"tag": {"key": "owner", "value": "team"}}`)
	if status != http.StatusNoContent {
		t.Fatalf("vpc host create tag: %d %s", status, out)
	}

	// Show tags through the VPC host.
	status, out = callHost(vpcHost, http.MethodGet, "/v2.0/"+tagTestProject+"/nat_gateways/"+gw.ID+"/tags", "")
	if status != http.StatusOK {
		t.Fatalf("vpc host show tags: %d %s", status, out)
	}
	showRes := tagDecodeInto[showNatGatewayTagsResponse](t, out)
	if len(showRes.Tags) != 2 {
		t.Fatalf("vpc host show tags = %+v, want 2 tags", showRes.Tags)
	}

	// List project tags and filter by tag through the VPC host.
	status, out = callHost(vpcHost, http.MethodGet, "/v2.0/"+tagTestProject+"/nat_gateways/tags", "")
	if status != http.StatusOK {
		t.Fatalf("vpc host list project tags: %d %s", status, out)
	}
	status, out = callHost(vpcHost, http.MethodPost, "/v2.0/"+tagTestProject+"/nat_gateways/resource_instances/action",
		`{"action": "filter", "tags": [{"key": "env", "values": ["test"]}]}`)
	if status != http.StatusOK {
		t.Fatalf("vpc host filter by tag: %d %s", status, out)
	}
	filterRes := tagDecodeInto[listNatGatewaysByTagResponse](t, out)
	if filterRes.TotalCount != 1 || filterRes.Resources[0].ResourceID != gw.ID {
		t.Fatalf("vpc host filter = %+v, want gateway %s", filterRes, gw.ID)
	}

	// Delete a tag through the VPC host.
	status, out = callHost(vpcHost, http.MethodDelete, "/v2.0/"+tagTestProject+"/nat_gateways/"+gw.ID+"/tags/owner", "")
	if status != http.StatusNoContent {
		t.Fatalf("vpc host delete tag: %d %s", status, out)
	}

	// Verify the NAT host sees the exact remaining tag on both /v3 and /v2.0.
	for _, prefix := range []string{"/v3", "/v2.0"} {
		status, out = callHost(tagTestHost, http.MethodGet, prefix+"/"+tagTestProject+"/nat_gateways/"+gw.ID+"/tags", "")
		if status != http.StatusOK {
			t.Fatalf("nat host %s show tags: %d %s", prefix, status, out)
		}
		got := tagDecodeInto[showNatGatewayTagsResponse](t, out)
		if len(got.Tags) != 1 || got.Tags[0].Key != "env" || got.Tags[0].Value != "test" {
			t.Fatalf("nat host %s show tags = %+v, want [{env test}]", prefix, got.Tags)
		}
	}

	// Non-tag NAT routes must not be mounted on the VPC host.
	status, _ = callHost(vpcHost, http.MethodGet, "/v2/"+tagTestProject+"/nat_gateways", "")
	if status != http.StatusNotImplemented {
		t.Fatalf("vpc host GET /v2/.../nat_gateways = %d, want 501", status)
	}
}
