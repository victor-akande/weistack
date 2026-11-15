package iam

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
)

// as returns the header of a request signed (in form only) with ak.
func as(ak string) []string {
	return []string{"Authorization", "SDK-HMAC-SHA256 Access=" + ak + ", SignedHeaders=host, Signature=abc"}
}

func userNames(out map[string]any) []string {
	var got []string
	for _, u := range list(out["users"]) {
		got = append(got, obj(u)["name"].(string))
	}
	return got
}

func TestAddedAccounts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	partner, root, err := e.svc.NewAccount(ctx, "partner", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !root.Valid() || partner.Name != "partner" || !partner.Valid() || partner.ID == testAccount.ID {
		t.Fatalf("NewAccount = %+v, %+v", partner, root)
	}
	b := as(root.AccessKey)

	// Discovery answers in the caller's account.
	w, out := e.do(t, http.MethodGet, "/v3/auth/domains", "", b...)
	if d := obj(list(out["domains"])[0]); w.Code != http.StatusOK || d["id"] != partner.ID || d["name"] != "partner" {
		t.Fatalf("domains as partner = %d %v", w.Code, out)
	}
	wantProject := partner.DerivedProjectID(testRegion)
	_, out = e.do(t, http.MethodGet, "/v3/projects?name="+testRegion, "", b...)
	if p := list(out["projects"]); len(p) != 1 || obj(p[0])["id"] != wantProject || obj(p[0])["domain_id"] != partner.ID {
		t.Fatalf("partner's project = %v, want %s", out, wantProject)
	}
	if owner, ok := e.svc.ProjectOwner(wantProject, testRegion); !ok || owner != partner.ID {
		t.Errorf("ProjectOwner(partner's) = %s, %v", owner, ok)
	}
	if owner, ok := e.svc.ProjectOwner(testProject, testRegion); !ok || owner != testAccount.ID {
		t.Errorf("ProjectOwner(primary's) = %s, %v", owner, ok)
	}

	// Each account has its own users: the same name in both, each listing
	// only its own (and its root user).
	e.want(t, http.StatusCreated, http.MethodPost, "/v3/users", `{"user":{"name":"dana","password":"`+pwFirst+`"}}`)
	w, out = e.do(t, http.MethodPost, "/v3/users", `{"user":{"name":"dana","password":"`+pwFirst+`","domain_id":"`+partner.ID+`"}}`, b...)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating dana in partner = %d %v", w.Code, out)
	}
	danaB := obj(out["user"])["id"].(string)
	e.want(t, http.StatusCreated, http.MethodPost, "/v3/users", `{"user":{"name":"only-primary"}}`)
	_, out = e.do(t, http.MethodGet, "/v3/users", "", b...)
	if got := userNames(out); !slices.Equal(got, []string{"partner", "dana"}) {
		t.Errorf("partner's users = %v", got)
	}
	if got := userNames(e.want(t, http.StatusOK, http.MethodGet, "/v3/users", "")); slices.Contains(got, "partner") || !slices.Contains(got, "only-primary") {
		t.Errorf("primary's users = %v", got)
	}
	// Another account's domain_id is refused, as a field naming an
	// account that is not the caller's.
	if w, _ := e.do(t, http.MethodPost, "/v3/users", `{"user":{"name":"x","domain_id":"`+testAccount.ID+`"}}`, b...); w.Code != http.StatusBadRequest {
		t.Errorf("creating in the primary account as partner = %d", w.Code)
	}

	// A password login names its account; the token acts in it.
	w, out = e.do(t, http.MethodPost, "/v3/auth/tokens", `{"auth":{"identity":{"methods":["password"],"password":{"user":
		{"name":"dana","password":"`+pwFirst+`","domain":{"name":"Partner"}}}},"scope":{"project":{"name":"`+testRegion+`"}}}}`)
	tok := w.Header().Get("X-Subject-Token")
	if w.Code != http.StatusCreated || obj(obj(out["token"])["user"])["id"] != danaB || obj(obj(out["token"])["project"])["id"] != wantProject ||
		obj(obj(obj(out["token"])["user"])["domain"])["id"] != partner.ID {
		t.Fatalf("partner login = %d %v", w.Code, out)
	}
	p, err := e.svc.CheckToken(ctx, tok)
	if err != nil || p.AccountID != partner.ID || p.UserID != danaB {
		t.Errorf("CheckToken = %+v, %v", p, err)
	}
	if w, _ := e.do(t, http.MethodGet, "/v3/auth/tokens", "", "X-Subject-Token", tok); w.Code != http.StatusOK {
		t.Errorf("validating partner's token = %d", w.Code)
	}

	// The root user holds everything in its own account only: grants
	// are computed in the principal's account.
	g, err := e.svc.Grants(ctx, identity.Principal{AccountID: partner.ID, UserID: partner.RootUserID()}, authz.Scope{Service: "vpc", ProjectID: wantProject})
	if err != nil || !g.All {
		t.Errorf("partner's root grants = %+v, %v", g, err)
	}
	g, err = e.svc.Grants(ctx, identity.Principal{AccountID: partner.ID, UserID: danaB}, authz.Scope{Service: "vpc", ProjectID: wantProject})
	if err != nil || g.All || len(g.Sources) != 0 || !slices.Equal(g.Keys["g:domainname"], []string{"partner"}) {
		t.Errorf("dana's grants = %+v, %v", g, err)
	}
}

func TestAddedAccountErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	if _, _, err := e.svc.NewAccount(ctx, "partner", nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		root *identity.Credentials
		code int
	}{
		{"PARTNER", nil, http.StatusConflict},
		{"Weistack", nil, http.StatusConflict},
		{"9lives", nil, http.StatusBadRequest},
		{"", nil, http.StatusBadRequest},
		{"other", &identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "secretsecret"}, http.StatusConflict},
		{"other", &identity.Credentials{AccessKey: "SHORT", SecretKey: "secretsecret"}, http.StatusBadRequest},
	} {
		_, _, err := e.svc.NewAccount(ctx, c.name, c.root)
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) || apiErr.Status != c.code {
			t.Errorf("NewAccount(%q) = %v, want %d", c.name, err, c.code)
		}
	}
	if got := e.svc.Accounts(); len(got) != 2 {
		t.Errorf("failed additions left accounts: %v", got)
	}
}

func TestAddedAccountsPersistAndReset(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	partner, root, err := e.svc.NewAccount(ctx, "partner", &identity.Credentials{AccessKey: "PARTNERKEY0000000000", SecretKey: "partnersecret0000000"})
	if err != nil {
		t.Fatal(err)
	}
	if root.AccessKey != "PARTNERKEY0000000000" {
		t.Fatalf("the given keys were not kept: %+v", root)
	}
	if w, out := e.do(t, http.MethodPost, "/v3/users", `{"user":{"name":"kept"}}`, as(root.AccessKey)...); w.Code != http.StatusCreated {
		t.Fatalf("creating a user in partner = %d %v", w.Code, out)
	}

	// A restart over the same store finds the account, its root key and
	// its users again.
	dir := identity.NewDirectory(testAccount, identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "s"})
	again, err := New(Deps{
		Store: e.svc.store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Directory: dir, IDs: ids.NewSeeded(2),
		Vault: e.svc.vault, DefaultRegion: testRegion, DefaultProjectID: testProject,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if a, ok := dir.AccountByName("partner"); !ok || a != partner {
		t.Fatalf("after a restart, partner = %+v, %v", a, ok)
	}
	if secret, ok := dir.Secret(root.AccessKey); !ok || secret != root.SecretKey {
		t.Error("after a restart, partner's root key is not known")
	}
	users, err := again.users(withAccount(ctx, partner)).List(ctx, nil)
	if err != nil || len(users) != 2 {
		t.Errorf("after a restart, partner's users = %v, %v", users, err)
	}

	// A reset returns to the start: the primary account alone.
	if err := e.svc.store.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.svc.Accounts(); len(got) != 1 || got[0] != testAccount {
		t.Errorf("after a reset, accounts = %v", got)
	}
}

func TestAccountsAdminAPI(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w, out := e.do(t, http.MethodPost, "/_weistack/accounts", `{"name":"partner"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /_weistack/accounts = %d %v", w.Code, out)
	}
	acct, creds := obj(out["account"]), obj(out["credentials"])
	if acct["name"] != "partner" || acct["primary"] != false || len(creds["access_key"].(string)) != identity.AccessKeyLen || len(creds["secret_key"].(string)) != identity.SecretKeyLen {
		t.Fatalf("added = %v", out)
	}
	if want := (identity.Account{ID: acct["id"].(string)}).DerivedProjectID(testRegion); acct["project_id"] != want {
		t.Errorf("the added account's project_id = %v", acct["project_id"])
	}
	// The new keys work at once.
	if got := e.signedBy(t, creds["access_key"].(string), "/v3/auth/domains"); obj(list(got["domains"])[0])["name"] != "partner" {
		t.Errorf("domains with the new key = %v", got)
	}

	// Keys given are kept.
	w, out = e.do(t, http.MethodPost, "/_weistack/accounts", `{"name":"ci","access_key":"CIKEY000000000000000","secret_key":"cisecret00000000"}`)
	if w.Code != http.StatusCreated || obj(out["credentials"])["access_key"] != "CIKEY000000000000000" {
		t.Fatalf("POST with keys = %d %v", w.Code, out)
	}

	// The list shows every account, the primary first, and no secrets.
	w, out = e.do(t, http.MethodGet, "/_weistack/accounts", "")
	all := list(out["accounts"])
	if w.Code != http.StatusOK || len(all) != 3 || obj(all[0])["id"] != testAccount.ID || obj(all[0])["primary"] != true ||
		obj(all[0])["project_id"] != testProject || obj(all[1])["name"] != "ci" || obj(all[2])["name"] != "partner" {
		t.Fatalf("GET /_weistack/accounts = %d %v", w.Code, out)
	}
	if body := w.Body.String(); strings.Contains(body, "secret") || strings.Contains(body, "CIKEY") {
		t.Errorf("the list shows keys: %s", body)
	}

	for _, c := range []struct {
		body, code string
		status     int
	}{
		{`{"name":"partner"}`, "WeiStack.0409", http.StatusConflict},
		{`{"name":"x","access_key":"CIKEY000000000000000","secret_key":"another0000000"}`, "WeiStack.0409", http.StatusConflict},
		{`{"name":"y","access_key":"ONLYTHEACCESSKEY0000"}`, "WeiStack.0400", http.StatusBadRequest},
		{`{"name":"has/slash"}`, "WeiStack.0400", http.StatusBadRequest},
		{`{"name":"z","extra":1}`, "WeiStack.0400", http.StatusBadRequest},
		{`not json`, "WeiStack.0400", http.StatusBadRequest},
	} {
		w, out := e.do(t, http.MethodPost, "/_weistack/accounts", c.body)
		if w.Code != c.status || out["error_code"] != c.code {
			t.Errorf("POST %s = %d %v, want %d %s", c.body, w.Code, out, c.status, c.code)
		}
	}
}
