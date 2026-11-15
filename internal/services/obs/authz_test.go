package obs

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// policyProvider grants one document.
type policyProvider struct{ sources []policy.Source }

func (p policyProvider) Grants(context.Context, identity.Principal, authz.Scope) (authz.Grants, error) {
	return authz.Grants{Sources: p.sources}, nil
}

// authzEnv serves OBS's routes to a caller holding doc.
func authzEnv(t *testing.T, doc string) func(method, path, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	var sources []policy.Source
	if doc != "" {
		p, err := policy.Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		sources = []policy.Source{{Name: "test", Policy: p}}
	}
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	svc, err := New(Deps{Store: st, IDs: ids.NewSeeded(3), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	svc.Routes(router)
	return func(method, path, body string, headers ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Host = testHost
		for i := 0; i+1 < len(headers); i += 2 {
			r.Header.Set(headers[i], headers[i+1])
		}
		g := authz.NewGate(authz.GateOptions{Principal: identity.Principal{UserID: "u1", UserName: "dev"}, Provider: policyProvider{sources}})
		ctx := reqctx.With(r.Context(), &reqctx.Info{RequestID: "r", Service: "obs", Region: testRegion})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r.WithContext(authz.WithGate(ctx, g)))
		return w
	}
}

func TestAuthorizationDeniesEveryOperation(t *testing.T) {
	t.Parallel()
	call := authzEnv(t, "")
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodPut, "/b"},
		{http.MethodHead, "/b"},
		{http.MethodDelete, "/b"},
		{http.MethodGet, "/b"},
		{http.MethodGet, "/b?location"},
		{http.MethodGet, "/b?uploads"},
		{http.MethodGet, "/b?acl"},
		{http.MethodGet, "/b?storageClass"},
		{http.MethodPut, "/b/k"},
		{http.MethodGet, "/b/k"},
		{http.MethodHead, "/b/k"},
		{http.MethodDelete, "/b/k"},
		{http.MethodPost, "/b/k?uploads"},
		{http.MethodPut, "/b/k?uploadId=u&partNumber=1"},
		{http.MethodPost, "/b/k?uploadId=u"},
		{http.MethodDelete, "/b/k?uploadId=u"},
		{http.MethodGet, "/b/k?uploadId=u"},
	} {
		w := call(c.method, c.path, "")
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d %s", c.method, c.path, w.Code, w.Body)
			continue
		}
		if c.method != http.MethodHead && !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") {
			t.Errorf("%s %s body = %s", c.method, c.path, w.Body)
		}
	}
	// Every operation in the table names a catalogued action.
	for op, a := range opActions {
		if err := checkCatalogued(a.action); err != nil {
			t.Errorf("%s: %v", op, err)
		}
	}
	for sub, a := range configActions {
		if err := checkCatalogued(a); err != nil {
			t.Errorf("%s: %v", sub, err)
		}
	}
}

func checkCatalogued(action string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	authz.Action(action)
	return nil
}

func TestAuthorizationObjects(t *testing.T) {
	t.Parallel()
	call := authzEnv(t, `{"Version":"1.1","Statement":[
		{"Effect":"Allow","Action":["obs:bucket:*"],"Resource":["obs:*:*:bucket:bkt"]},
		{"Effect":"Allow","Action":["obs:object:putObject","obs:object:getObject","obs:object:deleteObject"],"Resource":["obs:*:*:object:bkt/allowed*"]}]}`)

	if w := call(http.MethodPut, "/bkt", ""); w.Code != http.StatusOK {
		t.Fatalf("create bucket = %d %s", w.Code, w.Body)
	}
	if w := call(http.MethodPut, "/cbk", ""); w.Code != http.StatusForbidden {
		t.Errorf("create another bucket = %d", w.Code)
	}
	if w := call(http.MethodPut, "/bkt/allowed1", "data"); w.Code != http.StatusOK {
		t.Fatalf("put allowed = %d %s", w.Code, w.Body)
	}
	if w := call(http.MethodPut, "/bkt/other", "data"); w.Code != http.StatusForbidden {
		t.Errorf("put other = %d", w.Code)
	}

	// Copying reads the source: it must be allowed too.
	if w := call(http.MethodPut, "/bkt/allowed2", "", "x-obs-copy-source", "/bkt/other"); w.Code != http.StatusForbidden {
		t.Errorf("copy from an unreadable source = %d %s", w.Code, w.Body)
	}
	if w := call(http.MethodPut, "/bkt/allowed2", "", "x-obs-copy-source", "/bkt/allowed1"); w.Code != http.StatusOK {
		t.Errorf("copy = %d %s", w.Code, w.Body)
	}

	// A batch delete refuses only the keys the caller may not delete.
	body := `<Delete><Object><Key>allowed1</Key></Object><Object><Key>other</Key></Object></Delete>`
	w := call(http.MethodPost, "/bkt?delete", body)
	if w.Code != http.StatusOK {
		t.Fatalf("batch delete = %d %s", w.Code, w.Body)
	}
	out := w.Body.String()
	if !strings.Contains(out, "<Deleted><Key>allowed1</Key>") || !strings.Contains(out, "<Key>other</Key><Code>AccessDenied</Code>") {
		t.Errorf("batch delete result = %s", out)
	}
}
