package kps

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

type staticGrants struct {
	doc string
}

func (g staticGrants) Grants(context.Context, identity.Principal, authz.Scope) (authz.Grants, error) {
	p, err := policydoc.Parse([]byte(g.doc))
	if err != nil {
		return authz.Grants{}, err
	}
	return authz.Grants{
		Sources: []policydoc.Source{{Name: "kps-list-only", Policy: p}},
	}, nil
}

func TestEnforcePermissions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	r := chi.NewRouter()
	e.kms.Routes(r)

	acct := e.dir.Account()
	listOnly := staticGrants{doc: `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["kps:SSHKeyPair:list"]}]}`}

	do := func(method, path, body string) (int, []byte) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, strings.ReplaceAll(path, "{project}", testProject), rd)
		req.Header.Set("Content-Type", "application/json")
		gate := authz.NewGate(authz.GateOptions{
			Principal: identity.Principal{AccountID: acct.ID, UserID: "u-list-only", UserName: "reader"},
			Account:   acct.ID,
			Provider:  listOnly,
			Sealer:    e.vault,
			Log:       e.svc.log,
		})
		ctx := reqctx.With(req.Context(), &reqctx.Info{RequestID: "req-authz", Service: "kms", Region: testRegion})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(authz.WithGate(ctx, gate)))
		return w.Code, w.Body.Bytes()
	}

	// Listing is allowed.
	status, out := do(http.MethodGet, "/v3/{project}/keypairs", "")
	if status != http.StatusOK {
		t.Fatalf("list with kps:SSHKeyPair:list = %d %s, want 200", status, out)
	}

	// Creating is denied with 403 KPS.9003 and an encoded authorization message.
	status, out = do(http.MethodPost, "/v3/{project}/keypairs", `{"keypair":{"name":"denied-kp"}}`)
	if status != http.StatusForbidden {
		t.Fatalf("create without permission = %d %s, want 403", status, out)
	}
	var errBody struct {
		Code string `json:"error_code"`
		Msg  string `json:"error_msg"`
		Enc  string `json:"encoded_authorization_message"`
	}
	if err := json.Unmarshal(out, &errBody); err != nil {
		t.Fatalf("unmarshal denial %s: %v", out, err)
	}
	if errBody.Code != "KPS.9003" || errBody.Enc == "" {
		t.Errorf("denial = %+v, want KPS.9003 with encoded_authorization_message", errBody)
	}
}
