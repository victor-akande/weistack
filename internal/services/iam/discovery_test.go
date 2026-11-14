package iam

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
)

const (
	testRegion  = "ap-southeast-1"
	testProject = "0123456789abcdef0123456789abcdef"
)

var testAccount = identity.Account{ID: "fedcba9876543210fedcba9876543210", Name: identity.AccountName}

type env struct {
	svc     *Service
	handler http.Handler
}

func newEnv(t *testing.T) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	dir := identity.NewDirectory(testAccount, identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "s"})
	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	vlt, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Deps{Store: st, Logger: log, Directory: dir, IDs: ids.NewSeeded(1), Vault: vlt, DefaultRegion: testRegion, DefaultProjectID: testProject})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Resume(t.Context()); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: st, Engine: lifecycle.New(lifecycle.Options{}),
		IDs: ids.New(), Services: []server.Service{svc}, Directory: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, handler: srv.Handler()}
}

// get sends a request to the region-less IAM host the SDKs use.
func (e *env) get(t *testing.T, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = "iam.myhuaweicloud.com"
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s: %v: %s", path, err, w.Body)
	}
	return w, out
}

func names(t *testing.T, out map[string]any) []string {
	t.Helper()
	var got []string
	for _, p := range out["projects"].([]any) {
		got = append(got, p.(map[string]any)["name"].(string))
	}
	return got
}

func TestListAuthDomains(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w, out := e.get(t, "/v3/auth/domains")
	domains := out["domains"].([]any)
	d := domains[0].(map[string]any)
	if w.Code != http.StatusOK || len(domains) != 1 || d["id"] != testAccount.ID || d["name"] != "weistack" || d["enabled"] != true ||
		!strings.HasPrefix(d["links"].(map[string]any)["self"].(string), "https://iam.myhuaweicloud.com/v3/domains/") {
		t.Fatalf("domains = %d %v", w.Code, out)
	}
	if w.Header().Get("X-IAM-Trace-Id") == "" {
		t.Fatal("no X-IAM-Trace-Id header")
	}
}

func TestProjectDiscovery(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	// The SDK's lookup: exactly one project, the configured one, for the
	// default region.
	_, out := e.get(t, "/v3/projects?name="+testRegion)
	projects := out["projects"].([]any)
	p := projects[0].(map[string]any)
	if len(projects) != 1 || p["id"] != testProject || p["domain_id"] != testAccount.ID || p["parent_id"] != testAccount.ID ||
		p["enabled"] != true || p["is_domain"] != false {
		t.Fatalf("default region's project = %v", out)
	}

	// Terraform's lookup adds the domain ID. Another region's project
	// exists too, with an ID that stays the same.
	_, out = e.get(t, "/v3/projects?domain_id="+testAccount.ID+"&name=cn-north-4")
	other := out["projects"].([]any)[0].(map[string]any)
	want := testAccount.ProjectID("cn-north-4", testRegion, testProject)
	if other["id"] != want || other["name"] != "cn-north-4" {
		t.Fatalf("cn-north-4's project = %v, want id %s", out, want)
	}

	// Once seen, a project is listed and can be shown by ID.
	_, out = e.get(t, "/v3/projects")
	if got := strings.Join(names(t, out), ","); !strings.Contains(got, testRegion) || !strings.Contains(got, "cn-north-4") {
		t.Fatalf("all projects = %s", got)
	}
	w, shown := e.get(t, "/v3/projects/"+want)
	if w.Code != http.StatusOK || shown["project"].(map[string]any)["name"] != "cn-north-4" {
		t.Fatalf("show = %d %v", w.Code, shown)
	}
	_, auth := e.get(t, "/v3/auth/projects")
	if len(names(t, auth)) != 2 {
		t.Fatalf("auth projects = %v", auth)
	}

	for query, want := range map[string]int{
		"?name=not%20a%20region":        0,
		"?domain_id=someoneelse":        0,
		"?enabled=false":                0,
		"?is_domain=true":               0,
		"?parent_id=" + testAccount.ID:  2,
		"?page=1&per_page=1":            1,
		"?page=2&per_page=1":            1,
		"?page=3&per_page=1":            0,
		"?enabled=true&is_domain=false": 2,
	} {
		if _, out := e.get(t, "/v3/projects"+query); len(names(t, out)) != want {
			t.Errorf("GET /v3/projects%s: %d projects, want %d", query, len(names(t, out)), want)
		}
	}
}

func TestDiscoveryErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w, out := e.get(t, "/v3/projects/ffffffffffffffffffffffffffffffff")
	if w.Code != http.StatusNotFound || out["error_code"] != "IAM.0004" || out["error_msg"] != "Could not find project: ffffffffffffffffffffffffffffffff." {
		t.Fatalf("missing project = %d %v", w.Code, out)
	}
	for query, key := range map[string]string{
		"?page=0&per_page=1": "page", "?page=1&per_page=x": "per_page", "?page=1": "per_page", "?enabled=maybe": "enabled",
	} {
		w, out := e.get(t, "/v3/projects"+query)
		if w.Code != http.StatusBadRequest || out["error_code"] != "IAM.0007" || out["error_msg"] != "Request parameter "+key+" is invalid." {
			t.Errorf("GET /v3/projects%s = %d %v", query, w.Code, out)
		}
	}
}

func TestNewChecksDeps(t *testing.T) {
	t.Parallel()
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New accepted no dependencies")
	}
}
