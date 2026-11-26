package iam

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
)

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()

	// Add a second account and create a user in it.
	partner, partnerRoot, err := e.svc.NewAccount(ctx, "partner", nil)
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	w, partnerOut := e.do(t, http.MethodPost, "/v3/users",
		fmt.Sprintf(`{"user":{"name":"dana","domain_id":%q}}`, partner.ID), as(partnerRoot.AccessKey)...)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating user in partner account: %d %v", w.Code, partnerOut)
	}
	danaID := obj(partnerOut["user"])["id"].(string)

	// Create a user with a password, an access key and a login token in the primary account.
	aliceOut := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-USER/users",
		fmt.Sprintf(`{"user":{"name":"alice","domain_id":%q,"password":%q}}`, testAccount.ID, pwFirst))["user"])
	aliceID := aliceOut["id"].(string)

	cred := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-CREDENTIAL/credentials",
		fmt.Sprintf(`{"credential":{"user_id":%q,"description":"ci"}}`, aliceID))["credential"])
	ak, sk := cred["access"].(string), cred["secret"].(string)

	loginRec, loginOut := e.do(t, http.MethodPost, "/v3/auth/tokens",
		fmt.Sprintf(`{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"alice","password":%q,"domain":{"name":%q}}}}}}`,
			pwFirst, testAccount.Name))
	if loginRec.Code != http.StatusCreated {
		t.Fatalf("creating token: %d %v", loginRec.Code, loginOut)
	}
	tok := loginRec.Header().Get("X-Subject-Token")

	// Create a group containing alice.
	devsID := e.newGroup(t, "devs")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3/groups/"+devsID+"/users/"+aliceID, "")

	// Create a classic agency, plus a deleted service-linked agency (which leaves a deletion task).
	agencyObj := e.newClassicAgency(t, fmt.Sprintf(`{"name":"ops-agency","domain_id":%q,"trust_domain_name":"partner"}`, testAccount.ID))
	agencyID := agencyObj["id"].(string)
	linked := obj(e.want(t, http.StatusCreated, http.MethodPut, "/v5/service-linked-agencies",
		`{"service_principal":"service.RDS"}`)["agency"])
	e.want(t, http.StatusOK, http.MethodDelete, "/v5/service-linked-agencies/"+linked["agency_id"].(string), "")

	// Create two classic custom roles; grant the first to alice, devs (in two scopes) and ops-agency,
	// and also grant a system role to prove system roles are not reported.
	customRoleObj := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-ROLE/roles",
		`{"role":{"display_name":"BucketReader","type":"AX","description":"d","policy":`+customPolicy+`}}`)["role"])
	roleID := customRoleObj["id"].(string)
	roleName := customRoleObj["name"].(string)
	unusedRoleID := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-ROLE/roles",
		`{"role":{"display_name":"UnusedRole","type":"XA","description":"d","policy":`+customPolicy+`}}`)["role"])["id"].(string)

	e.want(t, http.StatusNoContent, http.MethodPut, "/v3.0/OS-PERMISSION/enterprise-projects/"+defaultEP+"/users/"+aliceID+"/roles/"+roleID, "")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3/domains/"+testAccount.ID+"/groups/"+devsID+"/roles/"+roleID, "")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3.0/OS-PERMISSION/enterprise-projects/"+defaultEP+"/groups/"+devsID+"/roles/"+roleID, "")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3.0/OS-AGENCY/domains/"+testAccount.ID+"/agencies/"+agencyID+"/roles/"+roleID, "")

	sysRoleID := roleByName(t, "secu_admin")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3/domains/"+testAccount.ID+"/groups/"+devsID+"/roles/"+sysRoleID, "")

	// Create two IAM 5.0 policies; attach the first to alice, devs and ops-agency.
	policyID := e.newPolicy(t, "readers", "team/")["policy_id"].(string)
	unusedPolicyID := e.newPolicy(t, "unused-policy", "")["policy_id"].(string)
	e.want(t, http.StatusOK, http.MethodPost, "/v5/policies/"+policyID+"/attach-user", fmt.Sprintf(`{"user_id":%q}`, aliceID))
	e.want(t, http.StatusOK, http.MethodPost, "/v5/policies/"+policyID+"/attach-group", fmt.Sprintf(`{"group_id":%q}`, devsID))
	e.want(t, http.StatusOK, http.MethodPost, "/v5/policies/"+policyID+"/attach-agency", fmt.Sprintf(`{"agency_id":%q}`, agencyID))

	primaryID := e.svc.dir.Account().ID
	primaryAdminGroup := e.svc.adminGroupID(withAccount(ctx, testAccount))
	partnerAdminGroup := e.svc.adminGroupID(withAccount(ctx, partner))

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(ctx)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := make(map[string]inventory.Resource, len(snap.Resources))
	for _, r := range snap.Resources {
		if r.RegionID != inventory.GlobalRegion || r.ProjectID != "" ||
			r.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
			r.State != inventory.Succeeded || r.Created.IsZero() || r.Updated.IsZero() || len(r.Tags) != 0 {
			t.Errorf("common fields of %s %s = %+v", r.Type, r.ID, r)
		}
		got[r.Type.String()+"/"+r.ID] = r
	}
	at := func(typ inventory.Type, id string) inventory.Resource {
		t.Helper()
		r, ok := got[typ.String()+"/"+id]
		if !ok {
			t.Fatalf("%s %s is not reported; got %v", typ, id, snap.Resources)
		}
		return r
	}

	alice := at(inventory.IAMUsers, aliceID)
	wantAliceRels := []inventory.Ref{
		{Relation: inventory.IsAssociatedWith, Type: inventory.IAMPolicies, ID: policyID},
		{Relation: inventory.IsAssociatedWith, Type: inventory.IAMRoles, ID: roleID},
		{Relation: inventory.IsContainedIn, Type: inventory.IAMGroups, ID: devsID},
	}
	if alice.Name != "alice" || alice.AccountID != primaryID || !reflect.DeepEqual(alice.Relations, wantAliceRels) {
		t.Errorf("alice = %+v, want relations %+v", alice, wantAliceRels)
	}
	if root := at(inventory.IAMUsers, testAccount.RootUserID()); root.Name != testAccount.Name || root.AccountID != primaryID || len(root.Relations) != 0 {
		t.Errorf("primary root user = %+v", root)
	}
	if dana := at(inventory.IAMUsers, danaID); dana.Name != "dana" || dana.AccountID != partner.ID || len(dana.Relations) != 0 {
		t.Errorf("partner user = %+v", dana)
	}
	if pRoot := at(inventory.IAMUsers, partner.RootUserID()); pRoot.Name != partner.Name || pRoot.AccountID != partner.ID || len(pRoot.Relations) != 0 {
		t.Errorf("partner root user = %+v", pRoot)
	}

	devs := at(inventory.IAMGroups, devsID)
	wantDevsRels := []inventory.Ref{
		{Relation: inventory.Contains, Type: inventory.IAMUsers, ID: aliceID},
		{Relation: inventory.IsAssociatedWith, Type: inventory.IAMPolicies, ID: policyID},
		{Relation: inventory.IsAssociatedWith, Type: inventory.IAMRoles, ID: roleID},
	}
	if devs.Name != "devs" || devs.AccountID != primaryID || !reflect.DeepEqual(devs.Relations, wantDevsRels) {
		t.Errorf("devs group = %+v, want relations %+v", devs, wantDevsRels)
	}
	if adm := at(inventory.IAMGroups, primaryAdminGroup); adm.Name != adminGroupName || adm.AccountID != primaryID || len(adm.Relations) != 0 {
		t.Errorf("primary admin group = %+v", adm)
	}
	if pAdm := at(inventory.IAMGroups, partnerAdminGroup); pAdm.Name != adminGroupName || pAdm.AccountID != partner.ID || len(pAdm.Relations) != 0 {
		t.Errorf("partner admin group = %+v", pAdm)
	}

	wantSubjectRels := []inventory.Ref{
		{Relation: inventory.IsAssociatedWith, Type: inventory.IAMAgencies, ID: agencyID},
		{Relation: inventory.IsAssociatedWith, Type: inventory.IAMGroups, ID: devsID},
		{Relation: inventory.IsAssociatedWith, Type: inventory.IAMUsers, ID: aliceID},
	}
	if cr := at(inventory.IAMRoles, roleID); cr.Name != roleName || cr.AccountID != primaryID || !reflect.DeepEqual(cr.Relations, wantSubjectRels) {
		t.Errorf("custom role = %+v, want relations %+v", cr, wantSubjectRels)
	}
	if unused := at(inventory.IAMRoles, unusedRoleID); unused.AccountID != primaryID || len(unused.Relations) != 0 {
		t.Errorf("unused custom role = %+v", unused)
	}

	if pol := at(inventory.IAMPolicies, policyID); pol.Name != "readers" || pol.AccountID != primaryID || !reflect.DeepEqual(pol.Relations, wantSubjectRels) {
		t.Errorf("policy = %+v, want relations %+v", pol, wantSubjectRels)
	}
	if unused := at(inventory.IAMPolicies, unusedPolicyID); unused.Name != "unused-policy" || unused.AccountID != primaryID || len(unused.Relations) != 0 {
		t.Errorf("unused policy = %+v", unused)
	}

	ag := at(inventory.IAMAgencies, agencyID)
	wantAgencyRels := []inventory.Ref{
		{Relation: inventory.IsAssociatedWith, Type: inventory.IAMPolicies, ID: policyID},
		{Relation: inventory.IsAssociatedWith, Type: inventory.IAMRoles, ID: roleID},
	}
	if ag.Name != "ops-agency" || ag.AccountID != primaryID || !reflect.DeepEqual(ag.Relations, wantAgencyRels) {
		t.Errorf("agency = %+v, want relations %+v", ag, wantAgencyRels)
	}

	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.IAMUsers:    4,
		inventory.IAMGroups:   3,
		inventory.IAMRoles:    2,
		inventory.IAMPolicies: 2,
		inventory.IAMAgencies: 1,
	}
	if !reflect.DeepEqual(count, want) {
		t.Errorf("reported counts = %v, want %v", count, want)
	}

	rendered := fmt.Sprintf("%+v", snap)
	for label, secret := range map[string]string{
		"password":           pwFirst,
		"access key":         ak,
		"secret key":         sk,
		"auth token":         tok,
		"partner access key": partnerRoot.AccessKey,
		"partner secret key": partnerRoot.SecretKey,
	} {
		if secret == "" {
			t.Fatalf("empty fixture %s", label)
		}
		if strings.Contains(rendered, secret) {
			t.Errorf("snapshot contains %s", label)
		}
	}
}

func TestReportResourcesInvalidSubject(t *testing.T) {
	t.Parallel()

	t.Run("assignment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		ctx := t.Context()
		roleID := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-ROLE/roles",
			`{"role":{"display_name":"Reader","type":"AX","description":"d","policy":`+customPolicy+`}}`)["role"])["id"].(string)
		corrupt := assignment{
			ID:        "corrupt-assignment",
			Subject:   "robot",
			SubjectID: "subject-1",
			RoleID:    roleID,
			Scope:     scopeDomain,
			ScopeID:   testAccount.ID,
			CreatedAt: time.Now().UTC(),
		}
		if err := e.svc.assignments(ctx).Create(ctx, corrupt.ID, corrupt); err != nil {
			t.Fatalf("creating corrupt assignment: %v", err)
		}
		if _, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(ctx); err == nil {
			t.Fatal("Collect succeeded with unknown assignment subject, want error")
		}
	})

	t.Run("policy_attachment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		ctx := t.Context()
		policyID := e.newPolicy(t, "readers", "")["policy_id"].(string)
		corrupt := policyAttachment{
			ID:         "corrupt-attachment",
			PolicyID:   policyID,
			Subject:    "robot",
			SubjectID:  "subject-1",
			AttachedAt: time.Now().UTC(),
		}
		if err := e.svc.policyAttachments(ctx).Create(ctx, corrupt.ID, corrupt); err != nil {
			t.Fatalf("creating corrupt policy attachment: %v", err)
		}
		if _, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(ctx); err == nil {
			t.Fatal("Collect succeeded with unknown policy attachment subject, want error")
		}
	})
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	// Include a disabled user and an agency with a finite duration: every IAM
	// resource still reports provisioning state Succeeded.
	e.want(t, http.StatusCreated, http.MethodPost, "/v5/users", `{"name":"disabled-user","enabled":false}`)
	e.newGroup(t, "ops")
	e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-ROLE/roles",
		`{"role":{"display_name":"Viewer","type":"XA","description":"d","policy":`+customPolicy+`}}`)
	e.newPolicy(t, "viewer", "")
	e.newClassicAgency(t, fmt.Sprintf(`{"name":"expiring","domain_id":%q,"trust_domain_name":"op_svc_ecs","duration":"ONEDAY"}`, testAccount.ID))

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	seen := make(map[inventory.Type]bool)
	for _, r := range snap.Resources {
		seen[r.Type] = true
		if r.State != inventory.Succeeded {
			t.Errorf("%s %s state = %s, want %s", r.Type, r.ID, r.State, inventory.Succeeded)
		}
	}
	for _, typ := range []inventory.Type{
		inventory.IAMUsers,
		inventory.IAMGroups,
		inventory.IAMRoles,
		inventory.IAMPolicies,
		inventory.IAMAgencies,
	} {
		if !seen[typ] {
			t.Errorf("type %s was not tested", typ)
		}
	}
}
