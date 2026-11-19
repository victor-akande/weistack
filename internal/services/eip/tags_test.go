package eip

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	tagTestProject   = "0123456789abcdef0123456789abcdef"
	tagTestRegion    = "ap-southeast-1"
	tagTestHost      = "vpc." + tagTestRegion + ".myhuaweicloud.com"
	tagTestDelay     = 2 * time.Second
	tagTestUnknownID = "00000000-0000-4000-8000-000000000000"
)

var (
	tagTestTenant = Tenant{Region: tagTestRegion, ProjectID: tagTestProject}
	tagTestEpoch  = time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC)
)

type tagEnv struct {
	svc     *Service
	vpcSvc  *vpc.Service
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

	gen := ids.NewSeeded(15)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	eipSvc, err := New(Deps{
		Store:         st,
		Engine:        engine,
		IDs:           gen,
		Logger:        log,
		Ports:         vpcSvc,
		MaxPerProject: DefaultMaxPerProject,
		Now:           clock.Now,
	})
	if err != nil {
		t.Fatalf("eip.New: %v", err)
	}
	vpcSvc.Extend(eipSvc)

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
		Services:  []server.Service{vpcSvc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &tagEnv{
		svc:     eipSvc,
		vpcSvc:  vpcSvc,
		store:   st,
		engine:  engine,
		clock:   clock,
		ids:     gen,
		handler: srv.Handler(),
	}
}

func (e *tagEnv) seedPublicIP(t *testing.T, tenant Tenant, alias, addr string, tags []tag) publicIP {
	t.Helper()
	now := e.svc.nowUTC()
	pip := publicIP{
		ID:                  e.ids.UUID(),
		Alias:               alias,
		Type:                "5_bgp",
		Address:             addr,
		Status:              StatusDown,
		BandwidthID:         e.ids.UUID(),
		EnterpriseProjectID: defaultEnterpriseProjectID,
		Tags:                tags,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := e.svc.publicips(tenant).Create(t.Context(), pip.ID, pip); err != nil {
		t.Fatalf("seedPublicIP: %v", err)
	}
	return pip
}

func (e *tagEnv) callV20(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callV20As(t, tagTestProject, method, path, body)
}

func (e *tagEnv) callV20As(t *testing.T, project, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v2.0/"+project+path, rd)
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

func (e *tagEnv) expectV20(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.callV20(t, method, path, body)
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

func TestTagsGoldenLifecycle(t *testing.T) {
	t.Parallel()
	e := newTagEnv(t)

	// Empty project tags list and empty filter result.
	e.expectV20(t, "list_publicip_tags_empty", http.MethodGet, "/publicips/tags", "")
	e.expectV20(t, "list_publicips_by_tags_filter_empty", http.MethodPost, "/publicips/resource_instances/action",
		`{"action": "filter"}`)

	pip1 := e.seedPublicIP(t, tagTestTenant, "resource1", "192.0.2.1", nil)
	pip2 := e.seedPublicIP(t, tagTestTenant, "resource2", "192.0.2.2", nil)

	// Empty tags on a fresh EIP.
	e.expectV20(t, "show_publicip_tags_empty", http.MethodGet, "/publicips/"+pip1.ID+"/tags", "")

	// Single tag create and show.
	e.expectV20(t, "create_publicip_tag", http.MethodPost, "/publicips/"+pip1.ID+"/tags",
		`{"tag": {"key": "key1", "value": "value1"}}`)
	e.expectV20(t, "create_publicip_tag", http.MethodPost, "/publicips/"+pip1.ID+"/tags",
		`{"tag": {"key": "key2", "value": "value3"}}`)
	e.expectV20(t, "show_publicip_tags", http.MethodGet, "/publicips/"+pip1.ID+"/tags", "")

	// Delete a single tag, plus deleting a non-existent key is a 204 no-op.
	e.expectV20(t, "delete_publicip_tag", http.MethodDelete, "/publicips/"+pip1.ID+"/tags/key2", "")
	e.expectV20(t, "delete_publicip_tag", http.MethodDelete, "/publicips/"+pip1.ID+"/tags/nonexistent", "")

	// Batch create tags on pip1 and pip2.
	e.expectV20(t, "batch_create_publicip_tags", http.MethodPost, "/publicips/"+pip1.ID+"/tags/action",
		`{"action": "create", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}]}`)
	e.expectV20(t, "batch_create_publicip_tags", http.MethodPost, "/publicips/"+pip2.ID+"/tags/action",
		`{"action": "create", "tags": [{"key": "key1", "value": "value2"}, {"key": "key2", "value": "value2"}]}`)

	// List all project tags (matches eip_apitag_0006).
	e.expectV20(t, "list_publicip_tags", http.MethodGet, "/publicips/tags", "")

	// List EIPs by tags: filter and count (matches eip_apitag_0005).
	e.expectV20(t, "list_publicips_by_tags_filter", http.MethodPost, "/publicips/resource_instances/action", `{
		"offset": "0",
		"limit": "100",
		"action": "filter",
		"matches": [{"key": "resource_name", "value": "ignored"}],
		"tags": [
			{"key": "key1", "values": ["value1"]},
			{"key": "key2", "values": ["value1", "value2"]}
		]
	}`)
	e.expectV20(t, "list_publicips_by_tags_count", http.MethodPost, "/publicips/resource_instances/action", `{
		"action": "count",
		"tags": [
			{"key": "key1", "values": ["value1"]},
			{"key": "key2", "values": ["value1", "value2"]}
		]
	}`)

	// Batch delete tags on pip1 (including a key it does not have).
	e.expectV20(t, "batch_delete_publicip_tags", http.MethodPost, "/publicips/"+pip1.ID+"/tags/action",
		`{"action": "delete", "tags": [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value1"}, {"key": "missing", "value": "x"}]}`)
	e.expectV20(t, "show_publicip_tags_empty", http.MethodGet, "/publicips/"+pip1.ID+"/tags", "")
}

func TestTagsGoldenErrors(t *testing.T) {
	t.Parallel()
	e := newTagEnv(t)
	pip := e.seedPublicIP(t, tagTestTenant, "eip-err", "192.0.2.10", nil)

	// Not found (VPC.0504) on every per-EIP tag route.
	e.expectV20(t, "error_vpc_0504", http.MethodPost, "/publicips/"+tagTestUnknownID+"/tags",
		`{"tag": {"key": "k1", "value": "v1"}}`)
	e.expectV20(t, "error_vpc_0504", http.MethodGet, "/publicips/"+tagTestUnknownID+"/tags", "")
	e.expectV20(t, "error_vpc_0504", http.MethodDelete, "/publicips/"+tagTestUnknownID+"/tags/k1", "")
	e.expectV20(t, "error_vpc_0504", http.MethodPost, "/publicips/"+tagTestUnknownID+"/tags/action",
		`{"action": "create", "tags": [{"key": "k1", "value": "v1"}]}`)
	e.expectV20(t, "error_vpc_0504", http.MethodPost, "/publicips/"+tagTestUnknownID+"/tags/action",
		`{"action": "delete", "tags": [{"key": "k1"}]}`)

	// CreatePublicipTag invalid requests (VPC.0501).
	createBad := []struct {
		name string
		body string
	}{
		{"empty body", ``},
		{"malformed json", `{"tag":`},
		{"missing tag object", `{}`},
		{"empty key", `{"tag": {"key": "", "value": "v"}}`},
		{"key over 36 chars", `{"tag": {"key": "` + strings.Repeat("k", 37) + `", "value": "v"}}`},
		{"value over 43 chars", `{"tag": {"key": "k", "value": "` + strings.Repeat("v", 44) + `"}}`},
	}
	for _, tc := range createBad {
		t.Run("create_"+tc.name, func(t *testing.T) {
			e.expectV20(t, "error_vpc_0501", http.MethodPost, "/publicips/"+pip.ID+"/tags", tc.body)
		})
	}

	// BatchCreatePublicipTags / BatchDeletePublicipTags invalid requests (VPC.0501).
	batchBad := []struct {
		name string
		body string
	}{
		{"empty body", ``},
		{"malformed json", `{"action":`},
		{"missing action", `{"tags": [{"key": "k", "value": "v"}]}`},
		{"unknown action", `{"action": "update", "tags": [{"key": "k", "value": "v"}]}`},
		{"empty tags on create", `{"action": "create", "tags": []}`},
		{"empty tags on delete", `{"action": "delete", "tags": []}`},
		{"empty key on create", `{"action": "create", "tags": [{"key": "", "value": "v"}]}`},
		{"overlong key on create", `{"action": "create", "tags": [{"key": "` + strings.Repeat("k", 37) + `", "value": "v"}]}`},
		{"overlong value on create", `{"action": "create", "tags": [{"key": "k", "value": "` + strings.Repeat("v", 44) + `"}]}`},
		{"empty key on delete", `{"action": "delete", "tags": [{"key": ""}]}`},
		{"overlong key on delete", `{"action": "delete", "tags": [{"key": "` + strings.Repeat("k", 37) + `"}]}`},
	}
	for _, tc := range batchBad {
		t.Run("batch_"+tc.name, func(t *testing.T) {
			e.expectV20(t, "error_vpc_0501", http.MethodPost, "/publicips/"+pip.ID+"/tags/action", tc.body)
		})
	}

	// ListPublicipsByTags invalid requests (VPC.0501).
	filterBad := []struct {
		name string
		body string
	}{
		{"empty body", ``},
		{"malformed json", `{"action":`},
		{"missing action", `{}`},
		{"unknown action", `{"action": "list"}`},
		{"limit zero", `{"action": "filter", "limit": 0}`},
		{"limit negative", `{"action": "filter", "limit": -1}`},
		{"limit over 1000", `{"action": "filter", "limit": 1001}`},
		{"limit bad string", `{"action": "filter", "limit": "abc"}`},
		{"limit float", `{"action": "filter", "limit": 1.5}`},
		{"limit bool", `{"action": "filter", "limit": true}`},
		{"offset negative", `{"action": "filter", "offset": -1}`},
		{"offset negative string", `{"action": "filter", "offset": "-5"}`},
		{"offset bad string", `{"action": "filter", "offset": "abc"}`},
		{"offset float", `{"action": "filter", "offset": 2.5}`},
		{"empty filter tag key", `{"action": "filter", "tags": [{"key": "", "values": ["v"]}]}`},
		{"duplicate filter tag key", `{"action": "filter", "tags": [{"key": "k", "values": ["v1"]}, {"key": "k", "values": ["v2"]}]}`},
		{"duplicate filter tag value", `{"action": "filter", "tags": [{"key": "k", "values": ["v1", "v1"]}]}`},
	}
	for _, tc := range filterBad {
		t.Run("filter_"+tc.name, func(t *testing.T) {
			e.expectV20(t, "error_vpc_0501", http.MethodPost, "/publicips/resource_instances/action", tc.body)
		})
	}
}

func TestTagOverwriteAndBoundaryLengths(t *testing.T) {
	t.Parallel()
	e := newTagEnv(t)
	pip := e.seedPublicIP(t, tagTestTenant, "eip-bounds", "192.0.2.20", nil)

	maxKey := strings.Repeat("k", 36)
	maxVal := strings.Repeat("v", 43)

	// Boundary lengths (key=36, value=43) and empty value (value="") are valid.
	status, out := e.callV20(t, http.MethodPost, "/publicips/"+pip.ID+"/tags",
		`{"tag": {"key": "`+maxKey+`", "value": "`+maxVal+`"}}`)
	if status != http.StatusNoContent {
		t.Fatalf("create max key/val: %d %s", status, out)
	}
	status, out = e.callV20(t, http.MethodPost, "/publicips/"+pip.ID+"/tags",
		`{"tag": {"key": "empty-val", "value": ""}}`)
	if status != http.StatusNoContent {
		t.Fatalf("create empty value: %d %s", status, out)
	}

	// Overwriting an existing key replaces its value in place.
	status, out = e.callV20(t, http.MethodPost, "/publicips/"+pip.ID+"/tags",
		`{"tag": {"key": "`+maxKey+`", "value": "updated"}}`)
	if status != http.StatusNoContent {
		t.Fatalf("overwrite tag: %d %s", status, out)
	}

	// Batch overwrite also updates existing key and appends new key.
	status, out = e.callV20(t, http.MethodPost, "/publicips/"+pip.ID+"/tags/action",
		`{"action": "create", "tags": [{"key": "empty-val", "value": "now-set"}, {"key": "k3", "value": "v3"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("batch overwrite: %d %s", status, out)
	}

	status, out = e.callV20(t, http.MethodGet, "/publicips/"+pip.ID+"/tags", "")
	if status != http.StatusOK {
		t.Fatalf("show tags: %d %s", status, out)
	}
	got := tagDecodeInto[showPublicIPTagsResponse](t, out).Tags
	want := []tag{
		{Key: maxKey, Value: "updated"},
		{Key: "empty-val", Value: "now-set"},
		{Key: "k3", Value: "v3"},
	}
	if len(got) != len(want) {
		t.Fatalf("tags = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tags[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestListPublicIPsByTagsFilteringAndPaging(t *testing.T) {
	t.Parallel()
	e := newTagEnv(t)

	p1 := e.seedPublicIP(t, tagTestTenant, "eip-1", "192.0.2.31", []tag{
		{Key: "env", Value: "prod"},
		{Key: "team", Value: "core"},
	})
	p2 := e.seedPublicIP(t, tagTestTenant, "eip-2", "192.0.2.32", []tag{
		{Key: "env", Value: "staging"},
		{Key: "team", Value: "core"},
	})
	p3 := e.seedPublicIP(t, tagTestTenant, "eip-3", "192.0.2.33", []tag{
		{Key: "env", Value: "prod"},
		{Key: "team", Value: "edge"},
	})
	// Another project's EIP must never leak into tag queries.
	otherTenant := Tenant{Region: tagTestRegion, ProjectID: "ffffffffffffffffffffffffffffffff"}
	e.seedPublicIP(t, otherTenant, "eip-other", "192.0.2.34", []tag{
		{Key: "env", Value: "prod"},
		{Key: "team", Value: "core"},
	})

	// Empty values array matches any value for that key.
	status, out := e.callV20(t, http.MethodPost, "/publicips/resource_instances/action",
		`{"action": "filter", "tags": [{"key": "team", "values": []}]}`)
	if status != http.StatusOK {
		t.Fatalf("filter any value: %d %s", status, out)
	}
	res := tagDecodeInto[listPublicIPsByTagsResponse](t, out)
	if res.TotalCount != 3 || len(res.Resources) != 3 {
		t.Fatalf("filter any value: total=%d len=%d, want 3", res.TotalCount, len(res.Resources))
	}

	// Pagination with integer limit and offset: total_count remains 3 while page has 1 item.
	status, out = e.callV20(t, http.MethodPost, "/publicips/resource_instances/action",
		`{"action": "filter", "limit": 1, "offset": 1, "tags": [{"key": "team", "values": []}]}`)
	if status != http.StatusOK {
		t.Fatalf("filter paged: %d %s", status, out)
	}
	res = tagDecodeInto[listPublicIPsByTagsResponse](t, out)
	if res.TotalCount != 3 || len(res.Resources) != 1 || res.Resources[0].ResourceID != p2.ID || res.Resources[0].ResourceName != "eip-2" {
		t.Fatalf("filter paged = %+v, want p2 (%s)", res, p2.ID)
	}

	// Offset beyond total_count returns empty resources array and total_count.
	status, out = e.callV20(t, http.MethodPost, "/publicips/resource_instances/action",
		`{"action": "filter", "limit": 10, "offset": 5, "tags": [{"key": "team", "values": []}]}`)
	if status != http.StatusOK {
		t.Fatalf("filter high offset: %d %s", status, out)
	}
	res = tagDecodeInto[listPublicIPsByTagsResponse](t, out)
	if res.TotalCount != 3 || len(res.Resources) != 0 {
		t.Fatalf("filter high offset = %+v, want total=3, len=0", res)
	}

	// Multiple keys (AND) and multiple values (OR).
	status, out = e.callV20(t, http.MethodPost, "/publicips/resource_instances/action", `{
		"action": "filter",
		"tags": [
			{"key": "env", "values": ["prod"]},
			{"key": "team", "values": ["core", "edge"]}
		]
	}`)
	if status != http.StatusOK {
		t.Fatalf("filter AND/OR: %d %s", status, out)
	}
	res = tagDecodeInto[listPublicIPsByTagsResponse](t, out)
	if res.TotalCount != 2 || len(res.Resources) != 2 ||
		res.Resources[0].ResourceID != p1.ID || res.Resources[1].ResourceID != p3.ID {
		t.Fatalf("filter AND/OR = %+v, want [%s, %s]", res, p1.ID, p3.ID)
	}
}

type tagNoGrants struct{}

func (tagNoGrants) Grants(context.Context, identity.Principal, authz.Scope) (authz.Grants, error) {
	return authz.Grants{}, nil
}

func TestBatchTagsDeferredAuthz(t *testing.T) {
	t.Parallel()
	e := newTagEnv(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	acct, err := identity.NewAccount()
	if err != nil {
		t.Fatal(err)
	}
	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	vlt, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	e.vpcSvc.Routes(r)

	for _, body := range []string{
		`{}`,
		`{"action": "create", "tags": [{"key": "k", "value": "v"}]}`,
		`{"action": "delete", "tags": [{"key": "k"}]}`,
	} {
		gate := authz.NewGate(authz.GateOptions{
			Principal: identity.Principal{AccountID: acct.ID, UserID: "u1", UserName: "nobody"},
			Account:   acct.ID,
			Provider:  tagNoGrants{},
			Sealer:    vlt,
			Log:       log,
		})
		req := httptest.NewRequest(http.MethodPost, "/v2.0/"+tagTestProject+"/publicips/p1/tags/action", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		info := &reqctx.Info{RequestID: "r", Service: "vpc", Region: tagTestRegion}
		ctx := reqctx.With(req.Context(), info)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(authz.WithGate(ctx, gate)))
		if !gate.Consulted() {
			t.Errorf("body %s: gate was not consulted", body)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("body %s: status = %d, want 403", body, w.Code)
		}
		if strings.Contains(body, `"delete"`) && info.Operation() != "BatchDeletePublicipTags" {
			t.Errorf("delete action operation = %q, want BatchDeletePublicipTags", info.Operation())
		}
	}
}
