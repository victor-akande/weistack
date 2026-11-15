package iam

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/actions"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
)

const securityTokens = "/v3.0/OS-CREDENTIAL/securitytokens"

// temporary asks for temporary credentials, signed with ak.
func (e *env) temporary(t *testing.T, ak, identityBody string) (ak2, token string) {
	t.Helper()
	w, out := e.do(t, http.MethodPost, securityTokens, `{"auth":{"identity":`+identityBody+`}}`, as(ak)...)
	if w.Code != http.StatusCreated {
		t.Fatalf("securitytokens %s = %d %v", identityBody, w.Code, out)
	}
	c := obj(out["credential"])
	if _, err := time.Parse(keystoneTime, c["expires_at"].(string)); err != nil || c["secret"] == "" {
		t.Fatalf("credential = %v (%v)", c, err)
	}
	return c["access"].(string), c["securitytoken"].(string)
}

// allowsAs evaluates an action for p in a scope, as authz would,
// session policies included.
func (e *env) allowsAs(t *testing.T, p identity.Principal, sc authz.Scope, action string) bool {
	t.Helper()
	g, err := e.svc.Grants(t.Context(), p, sc)
	if err != nil {
		t.Fatal(err)
	}
	a := actions.MustLookup(action)
	req := policydoc.Request{Action: a.Name, Aliases: a.Aliases, Keys: g.Keys}
	if !g.All && !policydoc.Evaluate(req, g.Sources).Allowed {
		return false
	}
	return len(g.Session) == 0 || policydoc.Evaluate(req, g.Session).Allowed
}

func TestTemporaryCredentialsForOneself(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := time.Now()
	e.svc.now = func() time.Time { return now }
	partner, root, err := e.svc.NewAccount(t.Context(), "partner", nil)
	if err != nil {
		t.Fatal(err)
	}

	ak, token := e.temporary(t, root.AccessKey, `{"methods":["token"],"token":{"duration_seconds":1800}}`)
	p, secret, ok := e.svc.Temporary(t.Context(), ak, token)
	if !ok || secret == "" || !p.Temporary || p.AccountID != partner.ID || p.UserID != partner.RootUserID() || p.Session != nil {
		t.Fatalf("Temporary = %+v, %v", p, ok)
	}
	// The access key's own secret, and nobody else's.
	if _, _, ok := e.svc.Temporary(t.Context(), root.AccessKey, token); ok {
		t.Error("a security token resolved another access key")
	}
	tampered := []byte(token)
	tampered[len(tampered)/2] ^= 1
	if _, _, ok := e.svc.Temporary(t.Context(), ak, string(tampered)); ok {
		t.Error("a tampered security token resolved")
	}
	// Requests made with them act as their user.
	w, out := e.do(t, http.MethodGet, "/v3/auth/domains", "", append(as(ak), "X-Security-Token", token)...)
	if d := obj(list(out["domains"])[0]); w.Code != http.StatusOK || d["id"] != partner.ID {
		t.Errorf("domains with temporary credentials = %d %v", w.Code, out)
	}
	// They expire.
	now = now.Add(1801 * time.Second)
	if _, _, ok := e.svc.Temporary(t.Context(), ak, token); ok {
		t.Error("expired credentials resolved")
	}

	// A classic policy limits them on OBS only.
	ak, token = e.temporary(t, root.AccessKey, `{"methods":["token"],"policy":{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["obs:object:getObject"]}]}}`)
	p, _, ok = e.svc.Temporary(t.Context(), ak, token)
	if !ok || p.Session == nil || p.Session.OBSPolicy == "" {
		t.Fatalf("Temporary with a policy = %+v, %v", p, ok)
	}
	if !e.allowsAs(t, p, globalScope, "obs:object:getObject") || e.allowsAs(t, p, globalScope, "obs:object:putObject") {
		t.Error("the session policy does not limit OBS")
	}
	if !e.allowsAs(t, p, projectScope, "vpc:vpcs:create") {
		t.Error("the session policy limits a service other than OBS")
	}

	for _, body := range []string{
		`{"methods":["token"],"token":{"duration_seconds":899}}`,
		`{"methods":["token"],"token":{"duration_seconds":86401}}`,
		`{"methods":["password"]}`,
		`{"methods":["token"],"policy":{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["*"]}]}}`,
	} {
		w, out := e.do(t, http.MethodPost, securityTokens, `{"auth":{"identity":`+body+`}}`, as(root.AccessKey)...)
		if w.Code != http.StatusBadRequest || out["error_code"] != "IAM.0073" {
			t.Errorf("%s = %d %v", body, w.Code, out)
		}
	}
}

func TestAssumingAgencies(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	partner, root, err := e.svc.NewAccount(t.Context(), "partner", nil)
	if err != nil {
		t.Fatal(err)
	}
	a := e.newClassicAgency(t, `{"name":"ops","domain_id":"`+testAccount.ID+`","trust_domain_name":"partner"}`)
	id := a["id"].(string)
	role := e.roleID(t, "VPC ReadOnlyAccess")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3.0/OS-AGENCY/projects/"+testProject+"/agencies/"+id+"/roles/"+role, "")

	// The partner assumes the agency, in the account that made it.
	ak, token := e.temporary(t, root.AccessKey,
		`{"methods":["assume_role"],"assume_role":{"agency_name":"ops","domain_name":"`+testAccount.Name+`","session_user":{"name":"alice"}}}`)
	p, _, ok := e.svc.Temporary(t.Context(), ak, token)
	if !ok || p.AccountID != testAccount.ID || p.AgencyID != id || p.AgencyName != "ops" || p.SessionName != "alice" || p.UserID != "" {
		t.Fatalf("Temporary = %+v, %v", p, ok)
	}
	if got := p.URN(testAccount); got != "sts::"+testAccount.ID+":assumed-agency:ops/alice" {
		t.Errorf("URN = %s", got)
	}
	// It may do what the agency was granted, and no more.
	if !e.allowsAs(t, p, projectScope, "vpc:vpcs:list") || e.allowsAs(t, p, projectScope, "vpc:vpcs:create") {
		t.Error("the agency's grants do not apply")
	}

	// Trust: the agency trusts the partner, not its own account.
	if !e.svc.Trusts(t.Context(), testAccount.ID, id, identity.Principal{AccountID: partner.ID, UserID: partner.RootUserID()}) {
		t.Error("the agency does not trust the partner")
	}
	if e.svc.Trusts(t.Context(), testAccount.ID, id, identity.Principal{AccountID: testAccount.ID, UserID: testAccount.RootUserID()}) {
		t.Error("the agency trusts its own account")
	}
	trust := strings.ReplaceAll(`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["sts:agencies:assume"],"Principal":{"IAM":["iam::PARTNER:user:dev"]}}]}`, "PARTNER", partner.ID)
	v5 := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v5/agencies", `{"agency_name":"ci","trust_policy":`+docJSON(trust)+`}`)["agency"])
	v5ID := v5["agency_id"].(string)
	if !e.svc.Trusts(t.Context(), testAccount.ID, v5ID, identity.Principal{AccountID: partner.ID, UserID: "u", UserName: "dev"}) ||
		e.svc.Trusts(t.Context(), testAccount.ID, v5ID, identity.Principal{AccountID: partner.ID, UserID: "u", UserName: "ops"}) {
		t.Error("a trust policy naming a user")
	}
	if got, longest, ok := e.svc.FindAgency(t.Context(), testAccount.ID, "ci"); !ok || got != v5ID || longest != time.Hour {
		t.Errorf("FindAgency = %s, %v, %v", got, longest, ok)
	}

	for _, name := range []string{"bob", strings.Repeat("a", 65), "1alice", "al ice"} {
		w, out := e.do(t, http.MethodPost, securityTokens,
			`{"auth":{"identity":{"methods":["assume_role"],"assume_role":{"agency_name":"ops","domain_id":"`+testAccount.ID+`","session_user":{"name":"`+name+`"}}}}}`, as(root.AccessKey)...)
		if w.Code != http.StatusBadRequest || out["error_code"] != "IAM.0073" {
			t.Errorf("session_user %q = %d %v", name, w.Code, out)
		}
	}

	// Unknown agencies, and credentials of a deleted one.
	w, out := e.do(t, http.MethodPost, securityTokens,
		`{"auth":{"identity":{"methods":["assume_role"],"assume_role":{"agency_name":"nobody","domain_id":"`+testAccount.ID+`"}}}}`, as(root.AccessKey)...)
	if w.Code != http.StatusForbidden || out["error_code"] != "IAM.0002" {
		t.Errorf("an unknown agency = %d %v", w.Code, out)
	}
	e.want(t, http.StatusNoContent, http.MethodDelete, "/v3.0/OS-AGENCY/agencies/"+id, "")
	if _, _, ok := e.svc.Temporary(t.Context(), ak, token); ok {
		t.Error("a deleted agency's credentials resolved")
	}
}

func TestSessionPolicies(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	pol := e.newPolicy(t, "reader", "")
	p := identity.Principal{AccountID: testAccount.ID, UserID: testAccount.RootUserID(), Temporary: true,
		Session: &identity.Session{Policy: `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:*:list*"]}]}`}}
	if !e.allowsAs(t, p, projectScope, "vpc:vpcs:list") || e.allowsAs(t, p, projectScope, "vpc:vpcs:create") {
		t.Error("an inline session policy does not limit the root user")
	}
	p.Session = &identity.Session{PolicyIDs: []string{pol["policy_id"].(string)}}
	if !e.svc.SessionPolicies(t.Context(), testAccount.ID, p.Session.PolicyIDs) || e.svc.SessionPolicies(t.Context(), testAccount.ID, []string{"nope"}) {
		t.Error("SessionPolicies")
	}
	g, err := e.svc.Grants(t.Context(), p, projectScope)
	if err != nil || len(g.Session) != 1 {
		t.Errorf("Grants with policy_ids = %+v, %v", g, err)
	}
}
