package iam

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func (e *env) newClassicAgency(t *testing.T, body string) map[string]any {
	t.Helper()
	return obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-AGENCY/agencies", `{"agency":`+body+`}`)["agency"])
}

func TestClassicAgencies(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	partner, _, err := e.svc.NewAccount(t.Context(), "partner", nil)
	if err != nil {
		t.Fatal(err)
	}
	dom := `"domain_id":"` + testAccount.ID + `"`

	// A delegated account by name, valid forever by default.
	a := e.newClassicAgency(t, `{"name":"ops",`+dom+`,"trust_domain_name":"partner","description":"for partner"}`)
	if a["duration"] != "FOREVER" || a["expire_time"] != nil || a["trust_domain_id"] != partner.ID || a["domain_id"] != testAccount.ID ||
		a["description"] != "for partner" || len(a["id"].(string)) != 32 {
		t.Fatalf("created = %v", a)
	}
	if _, err := time.Parse(classicAgencyTime, a["create_time"].(string)); err != nil {
		t.Errorf("create_time %v: %v", a["create_time"], err)
	}
	id := a["id"].(string)

	// Durations: ONEDAY, days as a number or a string; answered in hours.
	for body, hours := range map[string]string{`"ONEDAY"`: "24", `20`: "480", `"2"`: "48"} {
		got := e.newClassicAgency(t, `{"name":"d`+strings.Trim(body, `"`)+`",`+dom+`,"trust_domain_id":"`+partner.ID+`","duration":`+body+`}`)
		if got["duration"] != hours || got["expire_time"] == nil {
			t.Errorf("duration %s = %v", body, got)
		}
	}
	// A cloud service.
	svc := e.newClassicAgency(t, `{"name":"evs-kms",`+dom+`,"trust_domain_name":"op_svc_evs"}`)
	if svc["trust_domain_id"] != nil {
		t.Errorf("a service agency's trust_domain_id = %v", svc["trust_domain_id"])
	}

	for _, c := range []struct {
		body, code string
		status     int
	}{
		{`{"name":"x",` + dom + `}`, "IAM.0072", http.StatusBadRequest},
		{`{"name":"x",` + dom + `,"trust_domain_name":"nobody"}`, "IAM.0004", http.StatusNotFound},
		{`{"name":"x",` + dom + `,"trust_domain_id":"00000000000000000000000000000000"}`, "IAM.0004", http.StatusNotFound},
		{`{"name":"x",` + dom + `,"trust_domain_name":"partner","duration":"WEEK"}`, "IAM.0073", http.StatusBadRequest},
		{`{"name":"x",` + dom + `,"trust_domain_name":"partner","duration":0}`, "IAM.0073", http.StatusBadRequest},
		{`{"name":"x","domain_id":"` + partner.ID + `","trust_domain_name":"partner"}`, "IAM.0073", http.StatusBadRequest},
		{`{"name":"has space",` + dom + `,"trust_domain_name":"partner"}`, "IAM.0073", http.StatusBadRequest},
		{`{"name":"` + strings.Repeat("n", 65) + `",` + dom + `,"trust_domain_name":"partner"}`, "IAM.0073", http.StatusBadRequest},
		{`{"name":"OPS",` + dom + `,"trust_domain_name":"partner"}`, "IAM.0005", http.StatusConflict},
	} {
		e.wantErr(t, c.status, c.code, http.MethodPost, "/v3.0/OS-AGENCY/agencies", `{"agency":`+c.body+`}`)
	}

	// Show and list add the delegated account's name and the URN.
	shown := obj(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-AGENCY/agencies/"+id, "")["agency"])
	if shown["trust_domain_name"] != "partner" || shown["agency_urn"] != "iam::"+testAccount.ID+":agency:ops" {
		t.Errorf("shown = %v", shown)
	}
	listed := list(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-AGENCY/agencies?domain_id="+testAccount.ID+"&trust_domain_id="+partner.ID+"&name=ops", "")["agencies"])
	if len(listed) != 1 || obj(listed[0])["id"] != id {
		t.Errorf("listed = %v", listed)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-AGENCY/agencies?domain_id="+testAccount.ID, "")["agencies"]); len(got) != 5 {
		t.Errorf("all agencies = %d", len(got))
	}
	e.wantErr(t, http.StatusBadRequest, "IAM.0007", http.MethodGet, "/v3.0/OS-AGENCY/agencies", "")

	// Update.
	up := obj(e.want(t, http.StatusOK, http.MethodPut, "/v3.0/OS-AGENCY/agencies/"+id, `{"agency":{"description":"new","duration":"ONEDAY"}}`)["agency"])
	if up["description"] != "new" || up["duration"] != "24" || up["expire_time"] == nil {
		t.Errorf("updated = %v", up)
	}

	// Grants, as for a group, on the domain, a project, all projects and
	// the default enterprise project.
	role := e.roleID(t, "VPC ReadOnlyAccess")
	obsRole := e.roleID(t, "OBS ReadOnlyAccess")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3.0/OS-AGENCY/projects/"+testProject+"/agencies/"+id+"/roles/"+role, "")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3.0/OS-AGENCY/domains/"+testAccount.ID+"/agencies/"+id+"/roles/"+obsRole, "")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3.0/OS-INHERIT/domains/"+testAccount.ID+"/agencies/"+id+"/roles/"+role+"/inherited_to_projects", "")
	ep := "/v3.0/OS-PERMISSION/subjects/agency/scopes/enterprise-project/role-assignments"
	e.want(t, http.StatusNoContent, http.MethodPut, ep, `{"role_assignments":[{"agency_id":"`+id+`","enterprise_project_id":"0","role_id":"`+role+`"}]}`)
	if w, _ := e.do(t, http.MethodHead, "/v3.0/OS-AGENCY/projects/"+testProject+"/agencies/"+id+"/roles/"+role, ""); w.Code != http.StatusNoContent {
		t.Errorf("check on the project = %d", w.Code)
	}
	if roles := list(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-AGENCY/domains/"+testAccount.ID+"/agencies/"+id+"/roles", "")["roles"]); len(roles) != 1 || obj(roles[0])["id"] != obsRole {
		t.Errorf("roles on the domain = %v", roles)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-PERMISSION/role-assignments?subject.agency_id="+id, "")["role_assignments"]); len(got) != 4 {
		t.Errorf("the agency's role assignments = %v", got)
	}
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, ep, `{"role_assignments":[{"agency_id":"`+id+`","enterprise_project_id":"9","role_id":"`+role+`"}]}`)
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, "/v3.0/OS-AGENCY/projects/"+testProject+"/agencies/nope/roles/"+role, "")
	e.want(t, http.StatusNoContent, http.MethodDelete, ep, `{"role_assignments":[{"agency_id":"`+id+`","enterprise_project_id":"0","role_id":"`+role+`"}]}`)

	// Deleting the agency removes its grants.
	e.want(t, http.StatusNoContent, http.MethodDelete, "/v3.0/OS-AGENCY/agencies/"+id, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v3.0/OS-AGENCY/agencies/"+id, "")
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-PERMISSION/role-assignments?subject.agency_id="+id, "")["role_assignments"]); len(got) != 0 {
		t.Errorf("a deleted agency's grants remain: %v", got)
	}
}

// roleID returns the ID of the system role with that display name.
func (e *env) roleID(t *testing.T, display string) string {
	t.Helper()
	roles := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/roles?display_name="+strings.ReplaceAll(display, " ", "%20"), "")["roles"])
	if len(roles) != 1 {
		t.Fatalf("role %q: %v", display, roles)
	}
	return obj(roles[0])["id"].(string)
}

const trustPartner = `{\"Version\":\"5.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"sts:agencies:assume\"],\"Principal\":{\"IAM\":[\"123456789012\"]}}]}`

func TestTrustAgencies(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v5/agencies",
		`{"agency_name":"deployer","path":"ci/","trust_policy":"`+trustPartner+`","max_session_duration":7200,"description":"CI"}`)["agency"])
	id := a["agency_id"].(string)
	if a["urn"] != "iam::"+testAccount.ID+":agency:ci/deployer" || a["max_session_duration"] != float64(7200) || a["path"] != "ci/" ||
		!strings.Contains(a["trust_policy"].(string), "123456789012") || a["description"] != "CI" {
		t.Fatalf("created = %v", a)
	}
	if _, err := time.Parse(v5Time, a["created_at"].(string)); err != nil {
		t.Errorf("created_at %v: %v", a["created_at"], err)
	}

	for _, c := range []struct {
		body, code string
		status     int
	}{
		{`{"agency_name":"bad name","trust_policy":"` + trustPartner + `"}`, "PAP5.0029", http.StatusBadRequest},
		{`{"agency_name":"x","path":"/abs","trust_policy":"` + trustPartner + `"}`, "PAP5.0030", http.StatusBadRequest},
		{`{"agency_name":"x"}`, "PAP5.0257", http.StatusBadRequest},
		{`{"agency_name":"x","trust_policy":"{\"Version\":\"5.0\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"sts:agencies:assume\"]}]}"}`, "PAP5.0011", http.StatusBadRequest},
		{`{"agency_name":"x","trust_policy":"` + trustPartner + `","max_session_duration":60}`, "PAP5.0257", http.StatusBadRequest},
		{`{"agency_name":"Deployer","trust_policy":"` + trustPartner + `"}`, "PAP5.0031", http.StatusConflict},
	} {
		e.wantErr(t, c.status, c.code, http.MethodPost, "/v5/agencies", c.body)
	}

	got := obj(e.want(t, http.StatusOK, http.MethodGet, "/v5/agencies/"+id, "")["agency"])
	if tags, ok := got["tags"].([]any); !ok || len(tags) != 0 {
		t.Errorf("tags = %v", got["tags"])
	}
	upd := obj(e.want(t, http.StatusOK, http.MethodPut, "/v5/agencies/"+id, `{"max_session_duration":3600,"description":"d"}`)["agency"])
	if upd["max_session_duration"] != float64(3600) || upd["description"] != "d" {
		t.Errorf("updated = %v", upd)
	}
	newTrust := strings.ReplaceAll(trustPartner, "123456789012", "210987654321")
	e.want(t, http.StatusOK, http.MethodPut, "/v5/agencies/"+id+"/trust-policy", `{"trust_policy":"`+newTrust+`"}`)
	if got := obj(e.want(t, http.StatusOK, http.MethodGet, "/v5/agencies/"+id, "")["agency"]); !strings.Contains(got["trust_policy"].(string), "210987654321") {
		t.Errorf("trust policy not replaced: %v", got["trust_policy"])
	}
	e.wantErr(t, http.StatusNotFound, "PAP5.0012", http.MethodGet, "/v5/agencies/nope", "")

	// IAM 5.0 lists classic agencies too, but their trust is not a policy.
	classic := e.newClassicAgency(t, `{"name":"old","domain_id":"`+testAccount.ID+`","trust_domain_name":"op_svc_ecs"}`)
	all := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/agencies", "")["agencies"])
	if len(all) != 2 {
		t.Errorf("v5 list = %v", all)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/agencies?path_prefix=ci/", "")["agencies"]); len(got) != 1 {
		t.Errorf("path_prefix = %v", got)
	}
	e.wantErr(t, http.StatusBadRequest, "PAP5.0038", http.MethodPut, "/v5/agencies/"+classic["id"].(string)+"/trust-policy", `{"trust_policy":"`+trustPartner+`"}`)

	// Identity policies attach to agencies of both generations.
	pid := e.newPolicy(t, "agency-policy", "")["policy_id"].(string)
	for _, aid := range []string{id, classic["id"].(string)} {
		e.want(t, http.StatusOK, http.MethodPost, "/v5/policies/"+pid+"/attach-agency", `{"agency_id":"`+aid+`"}`)
	}
	e.wantErr(t, http.StatusConflict, "PAP5.0026", http.MethodPost, "/v5/policies/"+pid+"/attach-agency", `{"agency_id":"`+id+`"}`)
	e.wantErr(t, http.StatusNotFound, "PAP5.0012", http.MethodPost, "/v5/policies/"+pid+"/attach-agency", `{"agency_id":"nope"}`)
	held := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/agencies/"+id+"/attached-policies", "")["attached_policies"])
	if len(held) != 1 || obj(held[0])["policy_id"] != pid {
		t.Errorf("attached = %v", held)
	}
	ents := e.want(t, http.StatusOK, http.MethodGet, "/v5/policies/"+pid+"/attached-entities?entity_type=agency", "")
	if got := list(ents["policy_agencies"]); len(got) != 2 {
		t.Errorf("attached entities = %v", ents)
	}
	e.want(t, http.StatusOK, http.MethodPost, "/v5/policies/"+pid+"/detach-agency", `{"agency_id":"`+classic["id"].(string)+`"}`)

	// Deleting an agency detaches its policies.
	e.want(t, http.StatusNoContent, http.MethodDelete, "/v5/agencies/"+id, "")
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/policies/"+pid+"/attached-entities", "")["policy_agencies"]); len(got) != 0 {
		t.Errorf("a deleted agency's attachments remain: %v", got)
	}
}

func TestServiceLinkedAgencies(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := obj(e.want(t, http.StatusCreated, http.MethodPut, "/v5/service-linked-agencies", `{"service_principal":"service.RDS","description":"rds"}`)["agency"])
	if a["agency_name"] != "ServiceLinkedAgencyForRDS" || a["path"] != "service-linked-agency/service.RDS/" ||
		!strings.Contains(a["trust_policy"].(string), `"Service":["service.RDS"]`) {
		t.Fatalf("created = %v", a)
	}
	e.wantErr(t, http.StatusConflict, "PAP5.0031", http.MethodPut, "/v5/service-linked-agencies", `{"service_principal":"service.RDS"}`)
	e.wantErr(t, http.StatusNotFound, "PAP5.0023", http.MethodPut, "/v5/service-linked-agencies", `{"service_principal":"rds"}`)

	trust := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v5/agencies", `{"agency_name":"plain","trust_policy":"`+trustPartner+`"}`)["agency"])
	e.wantErr(t, http.StatusNotFound, "PAP5.0022", http.MethodDelete, "/v5/service-linked-agencies/"+trust["agency_id"].(string), "")

	task := e.want(t, http.StatusOK, http.MethodDelete, "/v5/service-linked-agencies/"+a["agency_id"].(string), "")["deletion_task_id"].(string)
	if got := e.want(t, http.StatusOK, http.MethodGet, "/v5/service-linked-agencies/deletion-task/"+task, ""); got["status"] != "succeeded" {
		t.Errorf("deletion status = %v", got)
	}
	e.wantErr(t, http.StatusNotFound, "PAP5.0015", http.MethodGet, "/v5/service-linked-agencies/deletion-task/nope", "")
	e.wantErr(t, http.StatusNotFound, "PAP5.0012", http.MethodGet, "/v5/agencies/"+a["agency_id"].(string), "")
}
