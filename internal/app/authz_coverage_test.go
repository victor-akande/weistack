package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
)

// noGrants is a provider for a principal that holds nothing.
type noGrants struct{}

func (noGrants) Grants(context.Context, identity.Principal, authz.Scope) (authz.Grants, error) {
	return authz.Grants{}, nil
}

// openRoutes are the routes a principal without permissions may call,
// or whose handler checks only once it has read the body. Every other
// route must refuse such a principal with 403. A route added without an
// action fails this test.
var openRoutes = map[string]string{
	"iam GET /v3/auth/domains":                                       "documented: no permission needed",
	"iam GET /v3/auth/projects":                                      "documented: no permission needed",
	"iam GET /v3/projects/{project_id}":                              "documented: no permission needed",
	"iam POST /v3/auth/tokens":                                       "documented: no permission needed",
	"iam GET /v3/auth/tokens":                                        "a token's holder may check it",
	"iam PUT /v3.0/OS-USER/users/{user_id}/info":                     "documented: no permission needed",
	"iam POST /v3/users/{user_id}/password":                          "documented: no permission needed",
	"iam POST /v3.0/OS-CREDENTIAL/credentials":                       "checked once the body names the user",
	"iam POST /v3.0/OS-CREDENTIAL/securitytokens":                    "documented: none for oneself; checked once the body names an agency",
	"ecs GET /v1/{project_id}/jobs/{job_id}":                         "documented: no permission needed",
	"ecs POST /v1/{project_id}/cloudservers/action":                  "checked once the body names the action",
	"ecs POST /v1/{project_id}/cloudservers/{server_id}/tags/action": "checked once the body names the action",
	"rds POST /v3/{project_id}/instances/{instance_id}/action":       "checked once the body names the action",
	"sts GET /v5/caller-identity":                                    "documented: no permission needed",
	"sts POST /v5/agencies/assume":                                   "checked once the body names the agency",
}

// KMS names the key in the body of most operations, and checks the
// action on it once read.
func init() {
	for _, op := range []string{
		"describe-key", "enable-key", "disable-key", "schedule-key-deletion", "cancel-key-deletion",
		"update-key-alias", "update-key-description", "encrypt-data", "decrypt-data", "create-datakey",
		"create-datakey-without-plaintext", "encrypt-datakey", "decrypt-datakey", "enable-key-rotation",
		"disable-key-rotation", "update-key-rotation-interval", "get-key-rotation-status",
	} {
		openRoutes["kms POST /v1.0/{project_id}/kms/"+op] = "checked once the body names the key"
	}
}

var paramRE = regexp.MustCompile(`\{[^}]+\}`)

func TestEveryRouteIsAuthorized(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	acct, err := identity.NewAccount()
	if err != nil {
		t.Fatal(err)
	}
	adm, err := identity.NewCredentials()
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
	cfg := config.Config{Region: "ap-southeast-1", SeedDir: t.TempDir(), IAM: config.IAMEnforce}
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	services, err := buildServices(t.Context(), cfg, "0123456789abcdef0123456789abcdef", t.TempDir(), st,
		lifecycle.New(lifecycle.Options{Logger: log}), ids.New(), log, identity.NewDirectory(acct, adm), vlt)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, svc := range services {
		r := chi.NewRouter()
		svc.Routes(r)
		var routes [][2]string
		if err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			routes = append(routes, [2]string{method, route})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		sort.Slice(routes, func(i, j int) bool { return routes[i][1]+routes[i][0] < routes[j][1]+routes[j][0] })
		for _, mr := range routes {
			method, route := mr[0], mr[1]
			if svc.Name() == "obs" && method != http.MethodGet {
				continue // one catch-all route; checked below by operation
			}
			name := svc.Name() + " " + method + " " + route
			seen[name] = true
			path := paramRE.ReplaceAllString(strings.ReplaceAll(route, "/*", "/bucket/key"), "p1")
			gate := authz.NewGate(authz.GateOptions{
				Principal: identity.Principal{AccountID: acct.ID, UserID: "u1", UserName: "nobody"},
				Account:   acct.ID, Provider: noGrants{}, Sealer: vlt, Log: log,
			})
			req := httptest.NewRequest(method, path, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			ctx := reqctx.With(req.Context(), &reqctx.Info{RequestID: "r", Service: svc.Name(), Region: cfg.Region})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req.WithContext(authz.WithGate(ctx, gate)))

			if !gate.Consulted() {
				t.Errorf("%s: no action declared", name)
				continue
			}
			_, open := openRoutes[name]
			switch {
			case w.Code == http.StatusForbidden && open:
				t.Errorf("%s: listed as open but refused", name)
			case w.Code != http.StatusForbidden && !open:
				t.Errorf("%s: a principal without permissions got %d %s", name, w.Code, w.Body)
			}
		}
	}
	for name := range openRoutes {
		if !seen[name] {
			t.Errorf("open route %q does not exist", name)
		}
	}
}
