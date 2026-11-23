package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
)

func newEnvWithQuotas(t *testing.T, limits quota.Limits) *env {
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
	svc, err := New(Deps{
		Quotas:           limits,
		Store:            st,
		Logger:           log,
		Directory:        dir,
		IDs:              ids.NewSeeded(1),
		Vault:            vlt,
		DefaultRegion:    testRegion,
		DefaultProjectID: testProject,
	})
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
		IDs: ids.New(), Services: []server.Service{svc}, Directory: dir, Accounts: svc, Temporary: svc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, handler: srv.Handler()}
}

func decodeQuotaResponse(t *testing.T, body []byte) quotaResponse {
	t.Helper()
	var resp quotaResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal quotaResponse: %v: %s", err, body)
	}
	return resp
}

func TestShowDomainQuota(t *testing.T) {
	t.Parallel()

	t.Run("defaults_and_live_counts_and_filter", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		defaults := quota.Limits{}

		// Initial state: root user is not counted; built-in admin group counts as 1; 0 agencies.
		w, _ := e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/domains/"+testAccount.ID, "")
		if w.Code != http.StatusOK {
			t.Fatalf("GET domain quota = %d %s", w.Code, w.Body)
		}
		got := decodeQuotaResponse(t, w.Body.Bytes())
		want := []quotaResource{
			{Type: "user", Used: 0, Quota: defaults.Get(quota.IAMUser), Min: 50, Max: 1000},
			{Type: "group", Used: 1, Quota: defaults.Get(quota.IAMGroup), Min: 10, Max: 300},
			{Type: "agency", Used: 0, Quota: defaults.Get(quota.IAMAgency), Min: 10, Max: 300},
		}
		if len(got.Quotas.Resources) != len(want) {
			t.Fatalf("resources = %+v, want %+v", got.Quotas.Resources, want)
		}
		for i := range want {
			if got.Quotas.Resources[i] != want[i] {
				t.Errorf("resources[%d] = %+v, want %+v", i, got.Quotas.Resources[i], want[i])
			}
		}

		// Create 2 users, 1 group, 1 classic agency, 1 v5 agency.
		e.want(t, http.StatusCreated, http.MethodPost, "/v3/users", `{"user":{"name":"alice"}}`)
		e.want(t, http.StatusCreated, http.MethodPost, "/v5/users", `{"name":"bob","enabled":true}`)
		e.want(t, http.StatusCreated, http.MethodPost, "/v3/groups", `{"group":{"name":"devs"}}`)
		e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-AGENCY/agencies",
			`{"agency":{"name":"ag-classic","domain_id":"`+testAccount.ID+`","trust_domain_name":"op_svc_ecs"}}`)
		e.want(t, http.StatusCreated, http.MethodPost, "/v5/agencies",
			`{"agency_name":"ag-v5","trust_policy":"`+trustPartner+`"}`)

		w, _ = e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/domains/"+testAccount.ID, "")
		if w.Code != http.StatusOK {
			t.Fatalf("GET domain quota = %d %s", w.Code, w.Body)
		}
		got = decodeQuotaResponse(t, w.Body.Bytes())
		want[0].Used = 2
		want[1].Used = 2 // admin + devs
		want[2].Used = 2 // classic + v5
		for i := range want {
			if got.Quotas.Resources[i] != want[i] {
				t.Errorf("after creates resources[%d] = %+v, want %+v", i, got.Quotas.Resources[i], want[i])
			}
		}

		// Filter by type.
		for i, typ := range []string{"user", "group", "agency"} {
			w, _ = e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/domains/"+testAccount.ID+"?type="+typ, "")
			if w.Code != http.StatusOK {
				t.Fatalf("type=%s: status %d %s", typ, w.Code, w.Body)
			}
			filtered := decodeQuotaResponse(t, w.Body.Bytes())
			if len(filtered.Quotas.Resources) != 1 || filtered.Quotas.Resources[0] != want[i] {
				t.Errorf("type=%s: got %+v, want [%+v]", typ, filtered.Quotas.Resources, want[i])
			}
		}

		// Documented-but-unemulated type returns empty array.
		w, _ = e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/domains/"+testAccount.ID+"?type=idp", "")
		if w.Code != http.StatusOK {
			t.Fatalf("type=idp: status %d %s", w.Code, w.Body)
		}
		if gotEmpty := decodeQuotaResponse(t, w.Body.Bytes()); gotEmpty.Quotas.Resources == nil || len(gotEmpty.Quotas.Resources) != 0 {
			t.Errorf("type=idp: got %+v, want empty non-nil slice", gotEmpty.Quotas.Resources)
		}

		// Invalid type returns 400 IAM.0007.
		e.wantErr(t, http.StatusBadRequest, "IAM.0007", http.MethodGet, "/v3.0/OS-QUOTA/domains/"+testAccount.ID+"?type=bogus", "")
	})

	t.Run("custom_limits_and_existing_data_over_limit", func(t *testing.T) {
		t.Parallel()
		userLim, groupLim, agencyLim := 1, 1, 1
		seededUsers, seededGroups, seededAgencies := 2, 2, 2
		e := newEnvWithQuotas(t, quota.For(map[quota.Key]int{
			quota.IAMUser:   userLim,
			quota.IAMGroup:  groupLim,
			quota.IAMAgency: agencyLim,
		}))
		ctx := t.Context()

		// Seed users directly in store above limit; existing records stay and quota reports used > quota.
		for i := range seededUsers {
			u := user{ID: e.svc.ids.Hex32(), Name: fmt.Sprintf("seed-u-%d", i+1), Enabled: true, AccessMode: "default"}
			if err := e.svc.users(ctx).Create(ctx, u.ID, u); err != nil {
				t.Fatalf("seed user: %v", err)
			}
		}
		// One more user create is refused.
		e.wantErr(t, http.StatusBadRequest, "1115", http.MethodPost, "/v3/users", `{"user":{"name":"extra"}}`)

		// Groups and agencies are reported, not enforced (§3.8).
		for i := range seededGroups {
			e.want(t, http.StatusCreated, http.MethodPost, "/v3/groups", fmt.Sprintf(`{"group":{"name":"g-%d"}}`, i+1))
		}
		for i := range seededAgencies {
			e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-AGENCY/agencies",
				fmt.Sprintf(`{"agency":{"name":"ag-%d","domain_id":%q,"trust_domain_name":"op_svc_ecs"}}`, i+1, testAccount.ID))
		}

		w, _ := e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/domains/"+testAccount.ID, "")
		if w.Code != http.StatusOK {
			t.Fatalf("GET domain quota = %d %s", w.Code, w.Body)
		}
		got := decodeQuotaResponse(t, w.Body.Bytes())
		want := []quotaResource{
			{Type: "user", Used: seededUsers, Quota: userLim, Min: 50, Max: 1000},
			{Type: "group", Used: 1 + seededGroups, Quota: groupLim, Min: 10, Max: 300},
			{Type: "agency", Used: seededAgencies, Quota: agencyLim, Min: 10, Max: 300},
		}
		if len(got.Quotas.Resources) != len(want) {
			t.Fatalf("resources = %+v, want %+v", got.Quotas.Resources, want)
		}
		for i := range want {
			if got.Quotas.Resources[i] != want[i] {
				t.Errorf("resources[%d] = %+v, want %+v", i, got.Quotas.Resources[i], want[i])
			}
		}
	})

	t.Run("cross_account_403_and_unknown_404", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		partner, partnerCreds, err := e.svc.NewAccount(t.Context(), "partner", nil)
		if err != nil {
			t.Fatal(err)
		}

		// Primary calling partner's domain -> 403 IAM.0002.
		e.wantErr(t, http.StatusForbidden, "IAM.0002", http.MethodGet, "/v3.0/OS-QUOTA/domains/"+partner.ID, "")

		// Partner calling primary's domain -> 403 IAM.0002.
		w, out := e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/domains/"+testAccount.ID, "", as(partnerCreds.AccessKey)...)
		if w.Code != http.StatusForbidden || out["error_code"] != "IAM.0002" {
			t.Errorf("partner reading primary domain = %d %v, want 403 IAM.0002", w.Code, out)
		}

		// Partner calling its own domain -> 200 OK.
		w, _ = e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/domains/"+partner.ID, "", as(partnerCreds.AccessKey)...)
		if w.Code != http.StatusOK {
			t.Fatalf("partner reading own domain = %d %s", w.Code, w.Body)
		}

		// Unknown domain ID -> 404 IAM.0004.
		e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v3.0/OS-QUOTA/domains/p1", "")
	})
}

func TestShowProjectQuota(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	partner, partnerCreds, err := e.svc.NewAccount(t.Context(), "partner", nil)
	if err != nil {
		t.Fatal(err)
	}
	partnerProject := partner.DerivedProjectID(testRegion)

	// Default: 1 project in the primary account.
	w, _ := e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/projects/"+testProject, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET project quota = %d %s", w.Code, w.Body)
	}
	got := decodeQuotaResponse(t, w.Body.Bytes())
	want := quotaResource{Type: "project", Used: 1, Quota: 10, Min: 0, Max: 50}
	if len(got.Quotas.Resources) != 1 || got.Quotas.Resources[0] != want {
		t.Fatalf("resources = %+v, want [%+v]", got.Quotas.Resources, want)
	}

	// Discovering another region adds a project and increments used.
	e.want(t, http.StatusOK, http.MethodGet, "/v3/projects?name=cn-north-4", "")
	w, _ = e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/projects/"+testProject, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET project quota after second region = %d %s", w.Code, w.Body)
	}
	got = decodeQuotaResponse(t, w.Body.Bytes())
	want.Used = 2
	if len(got.Quotas.Resources) != 1 || got.Quotas.Resources[0] != want {
		t.Fatalf("resources = %+v, want [%+v]", got.Quotas.Resources, want)
	}

	// Primary calling partner's project -> 403 IAM.0002.
	e.wantErr(t, http.StatusForbidden, "IAM.0002", http.MethodGet, "/v3.0/OS-QUOTA/projects/"+partnerProject, "")

	// Partner calling primary's project -> 403 IAM.0002.
	w, out := e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/projects/"+testProject, "", as(partnerCreds.AccessKey)...)
	if w.Code != http.StatusForbidden || out["error_code"] != "IAM.0002" {
		t.Errorf("partner reading primary project = %d %v, want 403 IAM.0002", w.Code, out)
	}

	// Partner calling its own project -> 200 OK with used=1 (primary's second region doesn't leak).
	w, _ = e.do(t, http.MethodGet, "/v3.0/OS-QUOTA/projects/"+partnerProject, "", as(partnerCreds.AccessKey)...)
	if w.Code != http.StatusOK {
		t.Fatalf("partner reading own project = %d %s", w.Code, w.Body)
	}
	gotPartner := decodeQuotaResponse(t, w.Body.Bytes())
	wantPartner := quotaResource{Type: "project", Used: 1, Quota: 10, Min: 0, Max: 50}
	if len(gotPartner.Quotas.Resources) != 1 || gotPartner.Quotas.Resources[0] != wantPartner {
		t.Fatalf("partner resources = %+v, want [%+v]", gotPartner.Quotas.Resources, wantPartner)
	}

	// Unknown project ID -> 404 IAM.0004.
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v3.0/OS-QUOTA/projects/p1", "")
}
