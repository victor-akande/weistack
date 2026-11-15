package sts

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// fakeAgencies has one agency, "ops", which trusts one account.
type fakeAgencies struct {
	trusted string
	issued  identity.Principal
	dur     time.Duration
}

func (f *fakeAgencies) FindAgency(_ context.Context, _, name string) (string, time.Duration, bool) {
	return "agency-1", 2 * time.Hour, name == "ops"
}

func (f *fakeAgencies) Trusts(_ context.Context, _, _ string, caller identity.Principal) bool {
	return caller.AccountID == f.trusted
}

func (f *fakeAgencies) AgencyPrincipal(_ context.Context, acct, id, session string) (identity.Principal, bool) {
	return identity.Principal{AccountID: acct, AgencyID: id, AgencyName: "ops", SessionName: session}, true
}

func (f *fakeAgencies) SessionPolicies(_ context.Context, _ string, ids []string) bool {
	return len(ids) == 0 || ids[0] != "missing"
}

func (f *fakeAgencies) IssueTemporary(_ context.Context, p identity.Principal, d time.Duration) (identity.TemporaryCredentials, error) {
	f.issued, f.dur = p, d
	return identity.TemporaryCredentials{AccessKey: "TEMPAK", SecretKey: "tempsk", SecurityToken: "tok", ExpiresAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}, nil
}

func TestAssumeAgency(t *testing.T) {
	t.Parallel()
	acct := identity.Account{ID: "fedcba9876543210fedcba9876543210", Name: identity.AccountName}
	partner := "0123456789abcdef0123456789abcdef"
	dir := identity.NewDirectory(acct, identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "s"})
	agencies := &fakeAgencies{trusted: partner}
	v := testVault(t)
	svc, err := New(slog.New(slog.DiscardHandler), dir, v, agencies)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	svc.Routes(router)
	urn := "iam::" + acct.ID + ":agency:ops"
	call := func(p identity.Principal, enforce bool, body string) (int, map[string]any) {
		r := httptest.NewRequest(http.MethodPost, "/v5/agencies/assume", strings.NewReader(body))
		ctx := reqctx.With(r.Context(), &reqctx.Info{RequestID: "r", Service: "sts", Region: "ap-southeast-1"})
		ctx = auth.WithIdentity(ctx, auth.Identity{Known: true, Principal: p, Temporary: p.Temporary})
		if enforce {
			// The caller may assume any agency; trust is the question.
			ctx = authz.WithGate(ctx, authz.NewGate(authz.GateOptions{Principal: p, Account: p.AccountID, Sealer: v,
				Provider: allGrants{}}))
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r.WithContext(ctx))
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	caller := identity.Principal{AccountID: partner, UserID: "u", UserName: "dev"}

	code, out := call(caller, true, `{"agency_urn":"`+urn+`","agency_session_name":"s1","duration_seconds":7200,"policy_ids":["p1"]}`)
	if code != http.StatusOK {
		t.Fatalf("assume = %d %v", code, out)
	}
	ag, creds := out["assumed_agency"].(map[string]any), out["credentials"].(map[string]any)
	if ag["urn"] != "sts::"+acct.ID+":assumed-agency:ops/s1" || ag["id"] != "agency-1:s1" ||
		creds["access_key_id"] != "TEMPAK" || creds["security_token"] != "tok" || creds["expiration"] != "2026-01-02T03:04:05.000Z" {
		t.Errorf("response = %v", out)
	}
	if agencies.dur != 2*time.Hour || agencies.issued.Session == nil || agencies.issued.Session.PolicyIDs[0] != "p1" {
		t.Errorf("issued %+v for %v", agencies.issued, agencies.dur)
	}

	// The default duration is an hour; chained sessions are limited to one.
	if code, _ = call(caller, true, `{"agency_urn":"`+urn+`","agency_session_name":"s1"}`); code != http.StatusOK || agencies.dur != time.Hour {
		t.Errorf("default duration = %d, %v", code, agencies.dur)
	}
	chained := caller
	chained.Temporary = true
	for _, c := range []struct {
		p       identity.Principal
		enforce bool
		body    string
		status  int
		code    string
	}{
		{caller, true, `{"agency_urn":"` + urn + `","agency_session_name":"s1","duration_seconds":7201}`, 400, "STS5.1102"},
		{chained, true, `{"agency_urn":"` + urn + `","agency_session_name":"s1","duration_seconds":3601}`, 400, "STS5.1102"},
		{caller, true, `{"agency_urn":"` + urn + `","agency_session_name":"s1","duration_seconds":899}`, 400, "WeiStack.0400"},
		{caller, true, `{"agency_urn":"` + urn + `","agency_session_name":"s1","policy_ids":["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21"]}`, 400, "STS5.1905"},
		{caller, true, `{"agency_urn":"` + urn + `","agency_session_name":"s1","policy_ids":["missing"]}`, 400, "WeiStack.0400"},
		{caller, true, `{"agency_urn":"` + urn + `","agency_session_name":"s1","policy":"{\"Version\":\"1.1\",\"Statement\":[]}"}`, 400, "WeiStack.0400"},
		{caller, true, `{"agency_urn":"iam::x:agency:ops","agency_session_name":"s1"}`, 400, "WeiStack.0400"},
		{caller, true, `{"agency_urn":"` + urn + `","agency_session_name":"a"}`, 400, "WeiStack.0400"},
		{caller, true, `{"agency_urn":"iam::` + acct.ID + `:agency:nobody","agency_session_name":"s1"}`, 403, "STS5.1001"},
		{caller, false, `{"agency_urn":"iam::` + acct.ID + `:agency:nobody","agency_session_name":"s1"}`, 403, "STS5.1001"},
		// Trust is checked under enforce only.
		{identity.Principal{AccountID: acct.ID, UserID: "x"}, true, `{"agency_urn":"` + urn + `","agency_session_name":"s1"}`, 403, "STS5.1001"},
		{identity.Principal{AccountID: acct.ID, UserID: "x"}, false, `{"agency_urn":"` + urn + `","agency_session_name":"s1"}`, 200, ""},
	} {
		code, out := call(c.p, c.enforce, c.body)
		if code != c.status || c.code != "" && out["error_code"] != c.code {
			t.Errorf("%s = %d %v, want %d %s", c.body, code, out, c.status, c.code)
		}
		if c.code == "STS5.1001" && c.enforce && out["encoded_authorization_message"] == "" {
			t.Errorf("%s: no encoded message", c.body)
		}
	}
}

type allGrants struct{}

func (allGrants) Grants(context.Context, identity.Principal, authz.Scope) (authz.Grants, error) {
	return authz.Grants{All: true}, nil
}

func TestCallerIdentityOfAnAssumedAgency(t *testing.T) {
	t.Parallel()
	acct := identity.Account{ID: "fedcba9876543210fedcba9876543210", Name: identity.AccountName}
	dir := identity.NewDirectory(acct, identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "s"})
	svc, err := New(slog.New(slog.DiscardHandler), dir, testVault(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/v5/caller-identity", nil)
	p := identity.Principal{AccountID: acct.ID, AgencyID: "a1", AgencyName: "ops", SessionName: "s1", Temporary: true}
	r = r.WithContext(auth.WithIdentity(r.Context(), auth.Identity{Known: true, Principal: p}))
	w := httptest.NewRecorder()
	svc.handleCallerIdentity(w, r)
	var out callerIdentity
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil ||
		out != (callerIdentity{AccountID: acct.ID, PrincipalURN: "sts::" + acct.ID + ":assumed-agency:ops/s1", PrincipalID: "a1:s1"}) {
		t.Errorf("caller identity = %+v (%v)", out, err)
	}
}
