package iam

import (
	"net/http"
	"strings"
	"testing"
)

// roleByName returns a system role's ID.
func roleByName(t *testing.T, name string) string {
	t.Helper()
	for _, ro := range catalogue {
		if ro.Name == name {
			return ro.ID
		}
	}
	t.Fatalf("no system role %s", name)
	return ""
}

func (e *env) newGroup(t *testing.T, name string) string {
	t.Helper()
	return obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3/groups", `{"group":{"name":"`+name+`"}}`)["group"])["id"].(string)
}

const customPolicy = `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["obs:bucket:GetBucketAcl"],` +
	`"Condition":{"StringStartWith":{"g:ProjectName":["ap-southeast-1"]}},"Resource":["obs:*:*:bucket:*"]}]}`

func TestSystemRoles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	out := e.want(t, http.StatusOK, http.MethodGet, "/v3/roles", "")
	if n := len(list(out["roles"])); n != len(systemRoles) || out["total_number"] != float64(len(systemRoles)) {
		t.Fatalf("%d roles, total %v", n, out["total_number"])
	}

	// The lookup Terraform's identity_role makes, by display name.
	got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/roles?display_name=ECS+FullAccess&page=1&per_page=300", "")["roles"])
	ecs := obj(got[0])
	if len(got) != 1 || ecs["name"] != "system_all_3" || ecs["type"] != "XA" || ecs["flag"] != "fine_grained" ||
		ecs["domain_id"] != nil || ecs["catalog"] != "ECS" || obj(ecs["policy"])["Version"] != "1.1" {
		t.Fatalf("ECS FullAccess = %v", got)
	}
	// It pages until a page is empty.
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/roles?display_name=ECS+FullAccess&page=2&per_page=300", "")["roles"]); len(got) != 0 {
		t.Fatalf("page 2 = %v", got)
	}
	// A display name filters as a substring; a name matches exactly.
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/roles?display_name=Administrator", "")["roles"]); len(got) < 5 {
		t.Fatalf("administrators = %d", len(got))
	}
	te := obj(list(e.want(t, http.StatusOK, http.MethodGet, "/v3/roles?name=te_admin", "")["roles"])[0])
	if te["display_name"] != "Tenant Administrator" || te["type"] != "AA" || te["flag"] != nil || obj(te["policy"])["Version"] != "1.0" {
		t.Fatalf("te_admin = %v", te)
	}

	for query, ok := range map[string]func(map[string]any) bool{
		"type=domain":            func(r map[string]any) bool { return r["type"] != "XA" },
		"type=project":           func(r map[string]any) bool { return r["type"] != "AX" },
		"permission_type=role":   func(r map[string]any) bool { return r["flag"] == nil },
		"permission_type=policy": func(r map[string]any) bool { return r["flag"] == "fine_grained" },
		"catalog=OBS":            func(r map[string]any) bool { return r["catalog"] == "OBS" },
	} {
		got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/roles?"+query, "")["roles"])
		if len(got) == 0 {
			t.Errorf("%s: none", query)
		}
		for _, r := range got {
			if !ok(obj(r)) {
				t.Errorf("%s: %v", query, r)
			}
		}
	}

	id := roleByName(t, "secu_admin")
	if got := obj(e.want(t, http.StatusOK, http.MethodGet, "/v3/roles/"+id, "")["role"]); got["display_name"] != "Security Administrator" {
		t.Fatalf("show = %v", got)
	}
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v3/roles/nope", "")
	e.wantErr(t, http.StatusBadRequest, "IAM.0007", http.MethodGet, "/v3/roles?page=1&per_page=501", "")
	e.wantErr(t, http.StatusBadRequest, "IAM.0007", http.MethodGet, "/v3/roles?type=nope", "")
	e.wantErr(t, http.StatusBadRequest, "IAM.0007", http.MethodGet, "/v3/roles?permission_type=nope", "")
}

func TestCustomRoles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	body := func(display, typ, policy string) string {
		return `{"role":{"display_name":"` + display + `","type":"` + typ + `","description":"d","description_cn":"c","policy":` + policy + `}}`
	}

	c := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-ROLE/roles", body("IAMCloudServicePolicy", "AX", customPolicy))["role"])
	id := c["id"].(string)
	if c["name"] != "custom_"+testAccount.ID+"_0" || c["catalog"] != "CUSTOMED" || c["domain_id"] != testAccount.ID ||
		c["description_cn"] != "c" || c["flag"] != nil || c["created_time"] == "" ||
		obj(list(obj(c["policy"])["Statement"])[0])["Condition"] == nil {
		t.Fatalf("created = %v", c)
	}
	second := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-ROLE/roles", body("Second", "XA", customPolicy))["role"])
	if second["name"] != "custom_"+testAccount.ID+"_1" {
		t.Fatalf("second = %v", second)
	}

	// Listed as custom policies, and by /v3/roles with the account's ID;
	// never among the system roles.
	if out := e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-ROLE/roles?page=1&per_page=1", ""); len(list(out["roles"])) != 1 || out["total_number"] != float64(2) {
		t.Fatalf("listed = %v", out)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/roles?domain_id="+testAccount.ID, "")["roles"]); len(got) != 2 {
		t.Fatalf("by domain = %v", got)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/roles?display_name=Second", "")["roles"]); len(got) != 0 {
		t.Fatalf("a custom policy among system roles: %v", got)
	}

	shown := obj(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-ROLE/roles/"+id, "")["role"])
	if shown["references"] != float64(0) {
		t.Fatalf("shown = %v", shown)
	}
	updated := obj(e.want(t, http.StatusOK, http.MethodPatch, "/v3.0/OS-ROLE/roles/"+id,
		`{"role":{"display_name":"Renamed","type":"AX","description":"new","policy":`+customPolicy+`}}`)["role"])
	if updated["display_name"] != "Renamed" || updated["description"] != "new" || updated["name"] != c["name"] {
		t.Fatalf("updated = %v", updated)
	}

	for name, tc := range map[string]struct{ code, body string }{
		"no role":         {"IAM.0072", `{}`},
		"blank name":      {"IAM.1001", body(" ", "AX", customPolicy)},
		"long name":       {"IAM.1002", body(strings.Repeat("n", 129), "AX", customPolicy)},
		"name characters": {"IAM.1003", body("a<b", "AX", customPolicy)},
		"no type":         {"IAM.1004", `{"role":{"display_name":"x","description":"d","policy":` + customPolicy + `}}`},
		"type AA":         {"IAM.1009", body("x", "AA", customPolicy)},
		"no policy":       {"IAM.0072", `{"role":{"display_name":"x","type":"AX","description":"d"}}`},
		"policy string":   {"IAM.1020", body("x", "AX", `"text"`)},
		"version":         {"IAM.1024", body("x", "AX", `{"Version":"1.0","Statement":[{"Effect":"Allow","Action":["a:b:c"]}]}`)},
		"statement":       {"IAM.1027", body("x", "AX", `{"Version":"1.1","Statement":{}}`)},
		"no statements":   {"IAM.1028", body("x", "AX", `{"Version":"1.1","Statement":[]}`)},
		"effect":          {"IAM.1029", body("x", "AX", `{"Version":"1.1","Statement":[{"Effect":"Maybe","Action":["a:b:c"]}]}`)},
		"action":          {"IAM.1030", body("x", "AX", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":"a:b:c"}]}`)},
		"both":            {"IAM.1031", body("x", "AX", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["a:b:c"],"NotAction":["a:b:d"]}]}`)},
		"action urn":      {"IAM.1035", body("x", "AX", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["not an action"]}]}`)},
		"resources":       {"IAM.1037", body("x", "AX", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Resource":[]}]}`)},
		"size": {"IAM.1021", body("x", "AX", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Resource":["`+
			strings.Repeat("r", 6200)+`"]}]}`)},
	} {
		w, out := e.do(t, http.MethodPost, "/v3.0/OS-ROLE/roles", tc.body)
		if w.Code != http.StatusBadRequest || out["error_code"] != tc.code {
			t.Errorf("%s: %d %v, want %s", name, w.Code, out, tc.code)
		}
	}

	// Deleting answers 200 with a message, as documented.
	if out := e.want(t, http.StatusOK, http.MethodDelete, "/v3.0/OS-ROLE/roles/"+id, ""); out["message"] != "Delete success" {
		t.Fatalf("delete = %v", out)
	}
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v3.0/OS-ROLE/roles/"+id, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPatch, "/v3.0/OS-ROLE/roles/"+id, `{"role":{}}`)
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodDelete, "/v3.0/OS-ROLE/roles/"+id, "")
}

func TestGroupRoleAssignments(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	g := e.newGroup(t, "admins")
	secu, ecs, te := roleByName(t, "secu_admin"), roleByName(t, "system_all_3"), roleByName(t, "te_admin")
	domain := "/v3/domains/" + testAccount.ID + "/groups/" + g + "/roles"
	project := "/v3/projects/" + testProject + "/groups/" + g + "/roles"
	inherited := "/v3/OS-INHERIT/domains/" + testAccount.ID + "/groups/" + g + "/roles"

	for _, path := range []string{domain + "/" + secu, project + "/" + ecs, inherited + "/" + te + "/inherited_to_projects"} {
		e.want(t, http.StatusNotFound, http.MethodHead, path, "")
		e.want(t, http.StatusNoContent, http.MethodPut, path, "")
		e.want(t, http.StatusNoContent, http.MethodPut, path, "") // again: still one
		e.want(t, http.StatusNoContent, http.MethodHead, path, "")
	}
	for path, want := range map[string]string{domain: "secu_admin", project: "system_all_3", inherited + "/inherited_to_projects": "te_admin"} {
		got := list(e.want(t, http.StatusOK, http.MethodGet, path, "")["roles"])
		if len(got) != 1 || obj(got[0])["name"] != want {
			t.Errorf("GET %s = %v", path, got)
		}
	}

	// Unknown scopes, groups and roles.
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, "/v3/domains/other/groups/"+g+"/roles/"+secu, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, "/v3/projects/other/groups/"+g+"/roles/"+ecs, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, "/v3/domains/"+testAccount.ID+"/groups/nope/roles/"+secu, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, domain+"/nope", "")

	// The records, filtered.
	records := func(query string) int {
		t.Helper()
		out := e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-PERMISSION/role-assignments?"+query, "")
		return len(list(out["role_assignments"]))
	}
	for query, want := range map[string]int{
		"domain_id=" + testAccount.ID:              3,
		"subject.group_id=" + g:                    3,
		"scope=domain":                             1,
		"scope=domain&is_inherited=true":           1,
		"scope.project_id=" + testProject:          1,
		"role_id=" + ecs:                           1,
		"subject=user":                             0,
		"domain_id=other":                          0,
		"page=1&per_page=2":                        2,
		"scope=enterprise_project":                 0,
		"subject.group_id=" + g + "&scope=project": 1,
	} {
		if got := records(query); got != want {
			t.Errorf("records?%s = %d, want %d", query, got, want)
		}
	}
	rec := obj(list(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-PERMISSION/role-assignments?scope=domain&is_inherited=true", "")["role_assignments"])[0])
	if obj(rec["group"])["id"] != g || obj(rec["role"])["id"] != te || rec["is_inherited"] != true ||
		obj(obj(rec["scope"])["domain"])["id"] != testAccount.ID {
		t.Fatalf("inherited record = %v", rec)
	}
	e.wantErr(t, http.StatusBadRequest, "IAM.0007", http.MethodGet, "/v3.0/OS-PERMISSION/role-assignments?page=1&per_page=51", "")

	// A member's token carries the group's roles in its scope, and the
	// member sees the projects the group has roles in.
	uid := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3/users", `{"user":{"name":"gina","password":"`+pwFirst+`"}}`)["user"])["id"].(string)
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3/groups/"+g+"/users/"+uid, "")
	login := func(scope string) []string {
		t.Helper()
		w, out := e.do(t, http.MethodPost, "/v3/auth/tokens", `{"auth":{"identity":{"methods":["password"],"password":{"user":
			{"name":"gina","password":"`+pwFirst+`","domain":{"name":"weistack"}}}},"scope":`+scope+`}}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("login = %d %v", w.Code, out)
		}
		var names []string
		for _, ro := range list(obj(out["token"])["roles"]) {
			names = append(names, obj(ro)["name"].(string))
		}
		return names
	}
	if got := strings.Join(login(`{"project":{"id":"`+testProject+`"}}`), ","); got != "system_all_3,te_admin" && got != "te_admin,system_all_3" {
		t.Errorf("project token roles = %s", got)
	}
	if got := strings.Join(login(`{"domain":{"id":"`+testAccount.ID+`"}}`), ","); got != "secu_admin" {
		t.Errorf("domain token roles = %s", got)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/users/"+uid+"/projects", "")["projects"]); len(got) != 1 {
		t.Errorf("projects = %v", got)
	}
	if n := records("subject.user_id=" + uid); n != 3 {
		t.Errorf("a user's records with their groups' = %d", n)
	}
	if n := records("subject.user_id=" + uid + "&include_group=false"); n != 0 {
		t.Errorf("a user's own records = %d", n)
	}

	// Revoking, then deleting the group, removes the records.
	e.want(t, http.StatusNoContent, http.MethodDelete, project+"/"+ecs, "")
	e.want(t, http.StatusNotFound, http.MethodHead, project+"/"+ecs, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodDelete, project+"/"+ecs, "")
	e.want(t, http.StatusNoContent, http.MethodDelete, "/v3/groups/"+g, "")
	if n := records(""); n != 0 {
		t.Fatalf("records after deleting the group = %d", n)
	}
}

func TestEnterpriseProjectAssignments(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	g := e.newGroup(t, "ops")
	uid := e.newUser(t, "hank")
	custom := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-ROLE/roles",
		`{"role":{"display_name":"Viewer","type":"XA","description":"d","policy":`+customPolicy+`}}`)["role"])["id"].(string)
	const ep = "/v3.0/OS-PERMISSION/enterprise-projects/0"

	e.want(t, http.StatusNoContent, http.MethodPut, ep+"/groups/"+g+"/roles/"+custom, "")
	e.want(t, http.StatusNoContent, http.MethodPut, ep+"/users/"+uid+"/roles/"+custom, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, "/v3.0/OS-PERMISSION/enterprise-projects/1/users/"+uid+"/roles/"+custom, "")

	if got := list(e.want(t, http.StatusOK, http.MethodGet, ep+"/users/"+uid+"/roles", "")["roles"]); len(got) != 1 || obj(got[0])["id"] != custom {
		t.Fatalf("user's EP roles = %v", got)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, ep+"/groups/"+g+"/roles", "")["roles"]); len(got) != 1 {
		t.Fatalf("group's EP roles = %v", got)
	}
	users := list(e.want(t, http.StatusOK, http.MethodGet, ep+"/users", "")["users"])
	if len(users) != 1 || obj(users[0])["name"] != "hank" || obj(users[0])["policy_num"] != float64(1) {
		t.Fatalf("EP users = %v", users)
	}
	groups := list(e.want(t, http.StatusOK, http.MethodGet, ep+"/groups", "")["groups"])
	if len(groups) != 1 || obj(groups[0])["name"] != "ops" || obj(groups[0])["domainId"] != testAccount.ID {
		t.Fatalf("EP groups = %v", groups)
	}
	for _, path := range []string{"/v3.0/OS-PERMISSION/users/" + uid + "/enterprise-projects", "/v3.0/OS-PERMISSION/groups/" + g + "/enterprise-projects"} {
		got := list(e.want(t, http.StatusOK, http.MethodGet, path, "")["enterprise-projects"])
		if len(got) != 1 || obj(got[0])["projectId"] != "0" {
			t.Errorf("GET %s = %v", path, got)
		}
	}
	if refs := obj(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-ROLE/roles/"+custom, "")["role"])["references"]; refs != float64(2) {
		t.Fatalf("references = %v", refs)
	}

	e.want(t, http.StatusNoContent, http.MethodDelete, ep+"/users/"+uid+"/roles/"+custom, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodDelete, ep+"/users/"+uid+"/roles/"+custom, "")

	// Deleting the custom policy removes its assignments.
	e.want(t, http.StatusOK, http.MethodDelete, "/v3.0/OS-ROLE/roles/"+custom, "")
	if got := list(e.want(t, http.StatusOK, http.MethodGet, ep+"/groups", "")["groups"]); len(got) != 0 {
		t.Fatalf("EP groups after the policy's delete = %v", got)
	}
}
