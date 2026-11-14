package sdk

import (
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	epsv1 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eps/v1"
	eps "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eps/v1/model"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
)

// TestIAMRolesAndAssignments looks up a system role and creates a custom
// policy, grants both to a group in every scope and to a user in the
// default enterprise project, all through the SDK's own models, then
// reads the records back.
func TestIAMRolesAndAssignments(t *testing.T) {
	t.Parallel()
	c, _ := iamClients(t, "AKIAMROLES0000000000")
	domains, err := c.KeystoneListAuthDomains(&iam.KeystoneListAuthDomainsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	account := (*domains.Domains)[0].Id
	projects, err := c.KeystoneListProjects(&iam.KeystoneListProjectsRequest{Name: ptr(region)})
	if err != nil || len(*projects.Projects) != 1 {
		t.Fatalf("KeystoneListProjects = %+v, %v", projects, err)
	}
	project := (*projects.Projects)[0].Id

	// A system role, by display name, as Terraform finds one.
	perms, err := c.KeystoneListPermissions(&iam.KeystoneListPermissionsRequest{DisplayName: ptr("ECS FullAccess")})
	if err != nil || len(*perms.Roles) != 1 || (*perms.Roles)[0].Name != "system_all_3" {
		t.Fatalf("KeystoneListPermissions = %+v, %v", perms, err)
	}
	ecsFull := (*perms.Roles)[0].Id

	// A custom policy.
	resources := []string{"obs:*:*:bucket:*"}
	created, err := c.CreateCloudServiceCustomPolicy(&iam.CreateCloudServiceCustomPolicyRequest{
		Body: &iam.CreateCloudServiceCustomPolicyRequestBody{Role: &iam.ServicePolicyRoleOption{
			DisplayName: "sdk-bucket-acl", Type: "AX", Description: "sdk",
			Policy: &iam.ServicePolicy{Version: "1.1", Statement: []iam.ServiceStatement{{
				Action: []string{"obs:bucket:GetBucketAcl"}, Effect: iam.GetServiceStatementEffectEnum().ALLOW, Resource: &resources,
			}}},
		}},
	})
	if err != nil || created.Role == nil || created.Role.Catalog != "CUSTOMED" {
		t.Fatalf("CreateCloudServiceCustomPolicy = %+v, %v", created, err)
	}
	custom := created.Role.Id
	defer func() {
		if _, err := c.DeleteCustomPolicy(&iam.DeleteCustomPolicyRequest{RoleId: custom}); err != nil {
			t.Errorf("DeleteCustomPolicy: %v", err)
		}
	}()

	g, err := c.KeystoneCreateGroup(&iam.KeystoneCreateGroupRequest{Body: &iam.KeystoneCreateGroupRequestBody{
		Group: &iam.KeystoneCreateGroupOption{Name: "sdk-role-holders"},
	}})
	if err != nil {
		t.Fatalf("KeystoneCreateGroup: %v", err)
	}
	group := g.Group.Id
	defer func() {
		if _, err := c.KeystoneDeleteGroup(&iam.KeystoneDeleteGroupRequest{GroupId: group}); err != nil {
			t.Errorf("KeystoneDeleteGroup: %v", err)
		}
	}()

	if _, err := c.KeystoneAssociateGroupWithProjectPermission(&iam.KeystoneAssociateGroupWithProjectPermissionRequest{
		ProjectId: project, GroupId: group, RoleId: ecsFull,
	}); err != nil {
		t.Fatalf("KeystoneAssociateGroupWithProjectPermission: %v", err)
	}
	if _, err := c.KeystoneCheckProjectPermissionForGroup(&iam.KeystoneCheckProjectPermissionForGroupRequest{
		ProjectId: project, GroupId: group, RoleId: ecsFull,
	}); err != nil {
		t.Fatalf("KeystoneCheckProjectPermissionForGroup: %v", err)
	}
	if _, err := c.KeystoneAssociateGroupWithDomainPermission(&iam.KeystoneAssociateGroupWithDomainPermissionRequest{
		DomainId: account, GroupId: group, RoleId: custom,
	}); err != nil {
		t.Fatalf("KeystoneAssociateGroupWithDomainPermission: %v", err)
	}
	if _, err := c.UpdateDomainGroupInheritRole(&iam.UpdateDomainGroupInheritRoleRequest{
		DomainId: account, GroupId: group, RoleId: ecsFull,
	}); err != nil {
		t.Fatalf("UpdateDomainGroupInheritRole: %v", err)
	}
	listed, err := c.KeystoneListDomainPermissionsForGroup(&iam.KeystoneListDomainPermissionsForGroupRequest{DomainId: account, GroupId: group})
	if err != nil || len(*listed.Roles) != 1 || (*listed.Roles)[0].Id != custom {
		t.Fatalf("KeystoneListDomainPermissionsForGroup = %+v, %v", listed, err)
	}

	// A user, in the default enterprise project.
	u, err := c.KeystoneCreateUser(&iam.KeystoneCreateUserRequest{Body: &iam.KeystoneCreateUserRequestBody{
		User: &iam.KeystoneCreateUserOption{Name: "sdk-ep-user", DomainId: &account},
	}})
	if err != nil {
		t.Fatalf("KeystoneCreateUser: %v", err)
	}
	user := u.User.Id
	defer func() {
		if _, err := c.KeystoneDeleteUser(&iam.KeystoneDeleteUserRequest{UserId: user}); err != nil {
			t.Errorf("KeystoneDeleteUser: %v", err)
		}
	}()
	if _, err := c.AssociateRoleToUserOnEnterpriseProject(&iam.AssociateRoleToUserOnEnterpriseProjectRequest{
		EnterpriseProjectId: "0", UserId: user, RoleId: custom,
	}); err != nil {
		t.Fatalf("AssociateRoleToUserOnEnterpriseProject: %v", err)
	}
	epRoles, err := c.ListRolesForUserOnEnterpriseProject(&iam.ListRolesForUserOnEnterpriseProjectRequest{EnterpriseProjectId: "0", UserId: user})
	if err != nil || len(*epRoles.Roles) != 1 {
		t.Fatalf("ListRolesForUserOnEnterpriseProject = %+v, %v", epRoles, err)
	}

	records, err := c.ShowDomainRoleAssignments(&iam.ShowDomainRoleAssignmentsRequest{DomainId: account, SubjectGroupId: &group})
	if err != nil || records.TotalNum == nil || *records.TotalNum != 3 {
		t.Fatalf("ShowDomainRoleAssignments = %+v, %v", records, err)
	}

	// The default enterprise project, through EPS.
	creds, err := global.NewCredentialsBuilder().WithAk("AKIAMROLES0000000000").WithSk("weistack-does-not-verify-signatures").SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	hc, err := epsv1.EpsClientBuilder().
		WithEndpoints([]string{"https://eps.myhuaweicloud.com"}).WithCredential(creds).WithHttpConfig(proxyConfig(t)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	eprojects, err := epsv1.NewEpsClient(hc).ListEnterpriseProject(&eps.ListEnterpriseProjectRequest{})
	if err != nil || len(*eprojects.EnterpriseProjects) != 1 || (*eprojects.EnterpriseProjects)[0].Id != "0" {
		t.Fatalf("ListEnterpriseProject = %+v, %v", eprojects, err)
	}
}
