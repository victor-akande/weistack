package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/vault"
)

// fakeProvider grants fixed policies and records the scopes asked for.
type fakeProvider struct {
	grants Grants
	err    error
	scopes []Scope
}

func (f *fakeProvider) Grants(_ context.Context, _ identity.Principal, s Scope) (Grants, error) {
	f.scopes = append(f.scopes, s)
	return f.grants, f.err
}

func mustPolicy(t *testing.T, doc string) []policy.Source {
	t.Helper()
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return []policy.Source{{Name: "test-policy", Policy: p}}
}

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// router builds a VPC-like service: one route per kind of declaration.
func router(o ServiceOptions) http.Handler {
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	r := chi.NewRouter()
	r.Use(Service(o))
	r.With(Action("vpc:vpcs:list")).Get("/v1/{project_id}/vpcs", ok)
	r.With(Action("vpc:vpcs:get", Param("vpc", "vpc_id"))).Get("/v1/{project_id}/vpcs/{vpc_id}", ok)
	r.With(Public()).Get("/v1/{project_id}/public", ok)
	r.With(Defer()).Post("/v1/{project_id}/vpcs/action", func(w http.ResponseWriter, r *http.Request) {
		if err := Check(r, "vpc:vpcs:delete", Resource{Type: "vpc", Path: "v9"}); err != nil {
			apierr.Write(w, r, o.Style, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/v1/{project_id}/undeclared", ok)
	return r
}

func serve(h http.Handler, g *Gate, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	ctx := reqctx.With(req.Context(), &reqctx.Info{RequestID: "rid", Service: "vpc", Region: "ap-southeast-1"})
	if g != nil {
		ctx = WithGate(ctx, g)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req.WithContext(ctx))
	return w
}

func TestNoGateAllowsEverything(t *testing.T) {
	t.Parallel()
	h := router(ServiceOptions{Name: "vpc", Style: apierr.StyleFlat})
	for _, p := range []string{"/v1/p/vpcs", "/v1/p/vpcs/v1", "/v1/p/undeclared"} {
		if w := serve(h, nil, http.MethodGet, p); w.Code != http.StatusOK {
			t.Errorf("GET %s = %d", p, w.Code)
		}
	}
	if w := serve(h, nil, http.MethodPost, "/v1/p/vpcs/action"); w.Code != http.StatusOK {
		t.Errorf("Check without a gate = %d", w.Code)
	}
}

func TestGateAllowsAndDenies(t *testing.T) {
	t.Parallel()
	v := testVault(t)
	prov := &fakeProvider{grants: Grants{
		Sources: mustPolicy(t, `{"Version":"5.0","Statement":[
			{"Effect":"Allow","Action":["vpc:vpcs:list"]},
			{"Effect":"Allow","Action":["vpc:vpcs:get"],"Resource":["vpc:ap-southeast-1:acct:vpc:v1"]},
			{"Sid":"noDelete","Effect":"Deny","Action":["vpc:vpcs:delete"]}]}`),
		Keys: map[string][]string{"g:username": {"alice"}},
	}}
	h := router(ServiceOptions{Name: "vpc", Style: apierr.StyleFlatRequestID})
	gate := func() *Gate {
		return NewGate(GateOptions{
			Principal: identity.Principal{UserID: "u1", UserName: "alice", AccountID: "acct"},
			Account:   "acct", Provider: prov, Sealer: v, Now: time.Now(), SourceIP: "10.0.0.1",
		})
	}

	if w := serve(h, gate(), http.MethodGet, "/v1/proj/vpcs"); w.Code != http.StatusOK {
		t.Errorf("list = %d %s", w.Code, w.Body)
	}
	if got := prov.scopes[0]; got != (Scope{Service: "vpc", Region: "ap-southeast-1", ProjectID: "proj"}) {
		t.Errorf("scope = %+v", got)
	}
	if w := serve(h, gate(), http.MethodGet, "/v1/proj/vpcs/v1"); w.Code != http.StatusOK {
		t.Errorf("get v1 = %d %s", w.Code, w.Body)
	}

	w := serve(h, gate(), http.MethodGet, "/v1/proj/vpcs/v2")
	if w.Code != http.StatusForbidden {
		t.Fatalf("get v2 = %d", w.Code)
	}
	var body struct {
		RequestID string `json:"request_id"`
		Code      string `json:"error_code"`
		Msg       string `json:"error_msg"`
		Encoded   string `json:"encoded_authorization_message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "WeiStack.0403" || body.Msg != "Policy doesn't allow vpc:vpcs:get to be performed." || body.RequestID != "rid" {
		t.Errorf("denial = %+v", body)
	}
	plain, ok := Decode(v, body.Encoded)
	if !ok {
		t.Fatal("the message does not decode")
	}
	for _, want := range []string{`"user_name":"alice"`, `"action":"vpc:vpcs:get"`, `"vpc:ap-southeast-1:acct:vpc:v2"`, `"failure":"implicit deny by identity-based policy"`} {
		if !strings.Contains(plain, want) {
			t.Errorf("decoded %s lacks %s", plain, want)
		}
	}

	// A handler's own check, denied explicitly.
	w = serve(h, gate(), http.MethodPost, "/v1/proj/vpcs/action")
	if w.Code != http.StatusForbidden {
		t.Fatalf("action = %d", w.Code)
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	plain, _ = Decode(v, body.Encoded)
	if !strings.Contains(plain, `"failure":"explicit deny by identity-based policy"`) || !strings.Contains(plain, `"statement":"noDelete"`) {
		t.Errorf("decoded %s", plain)
	}

	// Messages from elsewhere do not decode.
	if _, ok := Decode(v, "bm90IHNlYWxlZA=="); ok {
		t.Error("a foreign message decoded")
	}
	if _, ok := Decode(v, "%%%"); ok {
		t.Error("bad base64 decoded")
	}
}

func TestConsulted(t *testing.T) {
	t.Parallel()
	h := router(ServiceOptions{Name: "vpc"})
	for path, want := range map[string]bool{"/v1/p/vpcs": true, "/v1/p/public": true, "/v1/p/undeclared": false} {
		g := NewGate(GateOptions{Principal: identity.Principal{Admin: true}})
		serve(h, g, http.MethodGet, path)
		if g.Consulted() != want {
			t.Errorf("%s consulted = %v", path, g.Consulted())
		}
	}
}

func TestAllPowerfulAndAdmin(t *testing.T) {
	t.Parallel()
	h := router(ServiceOptions{Name: "vpc"})
	all := NewGate(GateOptions{Principal: identity.Principal{UserID: "root"}, Provider: &fakeProvider{grants: Grants{All: true}}})
	if w := serve(h, all, http.MethodGet, "/v1/p/vpcs/x"); w.Code != http.StatusOK {
		t.Errorf("all-powerful = %d", w.Code)
	}
	prov := &fakeProvider{}
	admin := NewGate(GateOptions{Principal: identity.Principal{Admin: true}, Provider: prov})
	if w := serve(h, admin, http.MethodGet, "/v1/p/vpcs/x"); w.Code != http.StatusOK || len(prov.scopes) != 0 {
		t.Errorf("admin = %d, provider asked %d times", w.Code, len(prov.scopes))
	}
}

func TestProviderError(t *testing.T) {
	t.Parallel()
	h := router(ServiceOptions{Name: "vpc"})
	g := NewGate(GateOptions{Principal: identity.Principal{UserID: "u"}, Provider: &fakeProvider{err: errors.New("store down")}})
	if w := serve(h, g, http.MethodGet, "/v1/p/vpcs"); w.Code != http.StatusInternalServerError {
		t.Errorf("provider failure = %d", w.Code)
	}
}

func TestGlobalServiceURNs(t *testing.T) {
	t.Parallel()
	var seen []string
	deny := func(d *Denial) *apierr.Error {
		seen = d.Resources
		return apierr.New(http.StatusForbidden, "AccessDenied", "Access Denied")
	}
	r := chi.NewRouter()
	r.Use(Service(ServiceOptions{Name: "obs", Global: true, NoAccount: true, Style: apierr.StyleXML, Deny: deny}))
	r.Get("/{bucket}", func(w http.ResponseWriter, r *http.Request) {
		if err := Check(r, "obs:bucket:listBucket", Resource{Type: "bucket", Path: chi.URLParam(r, "bucket")}); err != nil {
			apierr.Write(w, r, apierr.StyleXML, err)
		}
	})
	prov := &fakeProvider{}
	g := NewGate(GateOptions{Principal: identity.Principal{UserID: "u"}, Account: "acct", Provider: prov})
	w := serve(r, g, http.MethodGet, "/photos")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") {
		t.Fatalf("OBS denial = %d %s", w.Code, w.Body)
	}
	if len(seen) != 1 || seen[0] != "obs:::bucket:photos" {
		t.Errorf("URN = %v", seen)
	}
	if prov.scopes[0] != (Scope{Service: "obs", Region: "ap-southeast-1", Global: true}) {
		t.Errorf("scope = %+v", prov.scopes[0])
	}
}

func TestActionPanicsOnUnknownName(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	Action("vpc:vpcs:fly")
}

func TestSelfOrAndIsCaller(t *testing.T) {
	t.Parallel()
	r := chi.NewRouter()
	r.Use(Service(ServiceOptions{Name: "iam", Global: true}))
	r.With(SelfOr("user_id", "iam:users:get")).Get("/users/{user_id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	g := func() *Gate {
		return NewGate(GateOptions{Principal: identity.Principal{UserID: "me"}, Provider: &fakeProvider{}})
	}
	self := g()
	if w := serve(r, self, http.MethodGet, "/users/me"); w.Code != http.StatusOK || !self.Consulted() {
		t.Errorf("self = %d, consulted %v", w.Code, self.Consulted())
	}
	if w := serve(r, g(), http.MethodGet, "/users/other"); w.Code != http.StatusForbidden {
		t.Errorf("other = %d", w.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if IsCaller(req, "me") {
		t.Error("IsCaller without a gate")
	}
	req = req.WithContext(WithGate(req.Context(), g()))
	if !IsCaller(req, "me") || IsCaller(req, "") || IsCaller(req, "other") {
		t.Error("IsCaller")
	}
	if res, ok := Fixed("user", "*")(req); !ok || res.Type != "user" || res.Path != "*" {
		t.Errorf("Fixed = %+v", res)
	}
}

func TestAnotherAccountsProject(t *testing.T) {
	t.Parallel()
	v := testVault(t)
	h := router(ServiceOptions{Name: "vpc", Deny: Forbidden})
	owners := map[string]string{"pa": "acct-a", "pb": "acct-b"}
	owner := func(projectID, region string) (string, bool) {
		if region != "ap-southeast-1" {
			t.Errorf("ProjectOwner asked about region %q", region)
		}
		a, ok := owners[projectID]
		return a, ok
	}
	for _, c := range []struct {
		name      string
		principal identity.Principal
		path      string
		want      int
	}{
		{"own project", identity.Principal{AccountID: "acct-a", UserID: "root"}, "/v1/pa/vpcs", http.StatusOK},
		{"another account's", identity.Principal{AccountID: "acct-a", UserID: "root"}, "/v1/pb/vpcs", http.StatusForbidden},
		{"the administrator, another account's", identity.Principal{AccountID: "acct-a", Admin: true}, "/v1/pb/vpcs", http.StatusForbidden},
		{"a project no account has", identity.Principal{AccountID: "acct-a", UserID: "root"}, "/v1/pz/vpcs", http.StatusOK},
	} {
		g := NewGate(GateOptions{
			Principal: c.principal, Provider: &fakeProvider{grants: Grants{All: true}}, Sealer: v, ProjectOwner: owner,
		})
		w := serve(h, g, http.MethodGet, c.path)
		if w.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, w.Code, w.Body, c.want)
			continue
		}
		if c.want != http.StatusForbidden {
			continue
		}
		var body struct {
			Encoded string `json:"encoded_authorization_message"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		plain, ok := Decode(v, body.Encoded)
		if !ok || !strings.Contains(plain, "the project belongs to another account") {
			t.Errorf("%s: decoded %q, %v", c.name, plain, ok)
		}
	}
}

// TestSessionPolicies: temporary credentials do what both their
// principal and their session policies allow, even an all-powerful
// principal's.
func TestSessionPolicies(t *testing.T) {
	t.Parallel()
	h := router(ServiceOptions{Name: "vpc"})
	listOnly := mustPolicy(t, `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:vpcs:list"]}]}`)
	for _, c := range []struct {
		name   string
		grants Grants
		admin  bool
		list   int
		get    int
	}{
		{"all-powerful", Grants{All: true, Session: listOnly}, false, http.StatusOK, http.StatusForbidden},
		{"administrator", Grants{All: true, Session: listOnly}, true, http.StatusOK, http.StatusForbidden},
		{"limited", Grants{Sources: mustPolicy(t, `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:vpcs:get"]}]}`), Session: listOnly}, false, http.StatusForbidden, http.StatusForbidden},
	} {
		p := identity.Principal{UserID: "u", Admin: c.admin, Temporary: true, Session: &identity.Session{Policy: "x"}}
		g := func() *Gate {
			return NewGate(GateOptions{Principal: p, Provider: &fakeProvider{grants: c.grants}, Sealer: testVault(t)})
		}
		if w := serve(h, g(), http.MethodGet, "/v1/p/vpcs"); w.Code != c.list {
			t.Errorf("%s: list = %d, want %d", c.name, w.Code, c.list)
		}
		if w := serve(h, g(), http.MethodGet, "/v1/p/vpcs/x"); w.Code != c.get {
			t.Errorf("%s: get = %d, want %d", c.name, w.Code, c.get)
		}
	}
}

// TestURIResourcesAndRefuse: classic {"uri": [...]} resources, and
// denials for reasons only the handler knows.
func TestURIResourcesAndRefuse(t *testing.T) {
	t.Parallel()
	r := chi.NewRouter()
	r.Use(Service(ServiceOptions{Name: "iam", Global: true}))
	r.With(Defer()).Post("/assume/{agency}", func(w http.ResponseWriter, r *http.Request) {
		res := Resource{URIs: []string{"/iam/agencies/" + chi.URLParam(r, "agency")}}
		err := Check(r, "iam:tokens:assume", res)
		if err == nil && chi.URLParam(r, "agency") == "untrusted" {
			err = Refuse(r, "iam:tokens:assume", "not trusted", res)
		}
		if err != nil {
			apierr.Write(w, r, apierr.StyleFlat, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	prov := &fakeProvider{grants: Grants{Sources: mustPolicy(t, `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["iam:tokens:assume"],"Resource":{"uri":["/iam/agencies/ops","/iam/agencies/untrusted"]}}]}`)}}
	g := func() *Gate {
		return NewGate(GateOptions{Principal: identity.Principal{UserID: "u"}, Provider: prov, Sealer: testVault(t)})
	}
	for agency, want := range map[string]int{"ops": http.StatusOK, "other": http.StatusForbidden, "untrusted": http.StatusForbidden} {
		if w := serve(r, g(), http.MethodPost, "/assume/"+agency); w.Code != want {
			t.Errorf("assume %s = %d, want %d", agency, w.Code, want)
		}
	}
	if w := serve(r, nil, http.MethodPost, "/assume/untrusted"); w.Code != http.StatusOK {
		t.Errorf("Refuse without a gate = %d", w.Code)
	}
}
