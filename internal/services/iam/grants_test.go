package iam

import (
	"net/http"
	"testing"

	"github.com/victor-akande/weistack/internal/core/actions"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
)

// allows evaluates an action for a user in a scope, as authz would.
func (e *env) allows(t *testing.T, userID string, sc authz.Scope, action string) bool {
	t.Helper()
	g, err := e.svc.Grants(t.Context(), identity.Principal{UserID: userID}, sc)
	if err != nil {
		t.Fatal(err)
	}
	if g.All {
		return true
	}
	a := actions.MustLookup(action)
	return policydoc.Evaluate(policydoc.Request{Action: a.Name, Aliases: a.Aliases, Keys: g.Keys}, g.Sources).Allowed
}

var (
	projectScope = authz.Scope{Service: "vpc", Region: testRegion, ProjectID: testProject}
	globalScope  = authz.Scope{Service: "obs", Global: true}
)

func TestGrantsByScope(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := e.newUser(t, "alice")
	gid := e.newGroup(t, "readers")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3/groups/"+gid+"/users/"+uid, "")

	if e.allows(t, uid, projectScope, "vpc:vpcs:list") {
		t.Fatal("a user with no grants may list VPCs")
	}

	// A project grant covers that project only.
	vpcRO := roleByName(t, "system_all_5")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3/projects/"+testProject+"/groups/"+gid+"/roles/"+vpcRO, "")
	if !e.allows(t, uid, projectScope, "vpc:vpcs:list") {
		t.Error("VPC ReadOnlyAccess in the project does not allow listing VPCs")
	}
	if e.allows(t, uid, projectScope, "vpc:vpcs:create") {
		t.Error("VPC ReadOnlyAccess allows creating VPCs")
	}
	other := authz.Scope{Service: "vpc", Region: "eu-west-101", ProjectID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if e.allows(t, uid, other, "vpc:vpcs:list") {
		t.Error("a project grant applies to another project")
	}
	// Without a project in the path, the region's project is used.
	if !e.allows(t, uid, authz.Scope{Service: "vpc", Region: testRegion}, "vpc:vpcs:list") {
		t.Error("the region's project was not used")
	}

	// A domain grant covers global services, not projects.
	obsRO := roleByName(t, "system_all_64")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3/domains/"+testAccount.ID+"/groups/"+gid+"/roles/"+obsRO, "")
	if !e.allows(t, uid, globalScope, "obs:bucket:listAllMyBuckets") {
		t.Error("a domain grant does not cover OBS")
	}
	ecsRO := roleByName(t, "system_all_8")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3/domains/"+testAccount.ID+"/groups/"+gid+"/roles/"+ecsRO, "")
	if e.allows(t, uid, authz.Scope{Service: "ecs", Region: testRegion, ProjectID: testProject}, "ecs:cloudServers:listServersDetails") {
		t.Error("a domain grant covers a project")
	}

	// An all-projects grant covers every project.
	e.want(t, http.StatusNoContent, http.MethodPut,
		"/v3/OS-INHERIT/domains/"+testAccount.ID+"/groups/"+gid+"/roles/"+ecsRO+"/inherited_to_projects", "")
	if !e.allows(t, uid, authz.Scope{Service: "ecs", Region: "eu-west-101", ProjectID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "ecs:cloudServers:listServersDetails") {
		t.Error("an all-projects grant does not cover another project")
	}
}

func TestGrantsEnterpriseProject(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := e.newUser(t, "bob")
	evsFull := roleByName(t, "system_all_6")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3.0/OS-PERMISSION/enterprise-projects/0/users/"+uid+"/roles/"+evsFull, "")
	if !e.allows(t, uid, authz.Scope{Service: "evs", Region: testRegion, ProjectID: testProject}, "evs:volumes:list") {
		t.Error("a grant in the default enterprise project does not apply")
	}
	secAdmin := roleByName(t, "secu_admin")
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3.0/OS-PERMISSION/enterprise-projects/0/users/"+uid+"/roles/"+secAdmin, "")
	if e.allows(t, uid, authz.Scope{Service: "iam", Global: true}, "iam:users:list") {
		t.Error("an enterprise project grant applies to IAM, which has no enterprise projects")
	}
}

func TestGrantsV5AndCache(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := e.newUser(t, "carol")
	doc := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:vpcs:*"]},{"Effect":"Deny","Action":["vpc:vpcs:delete"]}]}`
	p := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v5/policies",
		`{"policy_name":"vpc-no-delete","policy_document":`+docJSON(doc)+`}`)["policy"])
	pid := p["policy_id"].(string)

	if e.allows(t, uid, projectScope, "vpc:vpcs:create") {
		t.Fatal("allowed before the policy was attached")
	}
	e.want(t, http.StatusOK, http.MethodPost, "/v5/policies/"+pid+"/attach-user", `{"user_id":"`+uid+`"}`)
	if !e.allows(t, uid, projectScope, "vpc:vpcs:create") {
		t.Error("an attached policy does not apply (or a stale cache answered)")
	}
	if e.allows(t, uid, projectScope, "vpc:vpcs:delete") {
		t.Error("the policy's Deny did not apply")
	}
	e.want(t, http.StatusOK, http.MethodPost, "/v5/policies/"+pid+"/detach-user", `{"user_id":"`+uid+`"}`)
	if e.allows(t, uid, projectScope, "vpc:vpcs:create") {
		t.Error("a detached policy still applies")
	}
}

func TestGrantsAllPowerful(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, p := range []identity.Principal{{Admin: true}, {UserID: testAccount.RootUserID()}} {
		g, err := e.svc.Grants(t.Context(), p, projectScope)
		if err != nil || !g.All {
			t.Errorf("Grants(%+v) = %+v, %v", p, g, err)
		}
	}
	uid := e.newUser(t, "dave")
	if e.allows(t, uid, projectScope, "vpc:vpcs:create") {
		t.Fatal("a new user may create VPCs")
	}
	adminID := e.svc.adminGroupID()
	e.want(t, http.StatusNoContent, http.MethodPut, "/v3/groups/"+adminID+"/users/"+uid, "")
	if !e.allows(t, uid, projectScope, "vpc:vpcs:create") || !e.allows(t, uid, authz.Scope{Service: "iam", Global: true}, "iam:users:create") {
		t.Error("a member of the admin group is not all-powerful")
	}
	// An unknown user holds nothing.
	if e.allows(t, "nobody", projectScope, "vpc:vpcs:list") {
		t.Error("an unknown user may list VPCs")
	}
}

func TestGrantsKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := e.newUser(t, "erin")
	g, err := e.svc.Grants(t.Context(), identity.Principal{UserID: uid}, projectScope)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"g:userid": uid, "g:username": "erin", "g:domainid": testAccount.ID, "g:domainname": testAccount.Name,
		"g:projectid": testProject, "g:projectname": testRegion,
	} {
		if v := g.Keys[k]; len(v) != 1 || v[0] != want {
			t.Errorf("%s = %v, want %s", k, v, want)
		}
	}
}
