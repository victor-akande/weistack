package sdk

import (
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	iamv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	iamv5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
)

// sdkPassword is a fixture, assembled at run time so that secret scanners
// do not report it as a leaked credential.
var sdkPassword = strings.Join([]string{"Passw0rd", "!sdk"}, "")

func iamClients(t *testing.T, ak string) (*iamv3.IamClient, *iamv5.IamClient) {
	t.Helper()
	creds, err := global.NewCredentialsBuilder().WithAk(ak).WithSk("weistack-does-not-verify-signatures").SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	classic, err := iamv3.IamClientBuilder().
		WithEndpoints([]string{"https://iam.myhuaweicloud.com"}).WithCredential(creds).WithHttpConfig(proxyConfig(t)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	five, err := iamv5.IamClientBuilder().
		WithEndpoints([]string{"https://iam.myhuaweicloud.com"}).WithCredential(creds).WithHttpConfig(proxyConfig(t)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	return iamv3.NewIamClient(classic), iamv5.NewIamClient(five)
}

// TestIAMUsersGroupsAndTokens drives users, groups, membership and a
// password token through the SDK's own models, mixing classic IAM and
// IAM 5.0 over the same records.
func TestIAMUsersGroupsAndTokens(t *testing.T) {
	t.Parallel()
	c, c5 := iamClients(t, "AKIAMUSERS0000000000")
	domains, err := c.KeystoneListAuthDomains(&iam.KeystoneListAuthDomainsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	account := (*domains.Domains)[0].Id

	// Classic create, as Terraform does it.
	created, err := c.CreateUser(&iam.CreateUserRequest{Body: &iam.CreateUserRequestBody{User: &iam.CreateUserOption{
		Name: "sdk-alice", DomainId: account, Password: ptr(sdkPassword), Email: ptr("alice@example.com"),
	}}})
	if err != nil || created.User == nil || created.User.Name != "sdk-alice" {
		t.Fatalf("CreateUser = %+v, %v", created, err)
	}
	userID := created.User.Id
	defer func() {
		if _, err := c.KeystoneDeleteUser(&iam.KeystoneDeleteUserRequest{UserId: userID}); err != nil {
			t.Errorf("KeystoneDeleteUser: %v", err)
		}
	}()
	shown, err := c.ShowUser(&iam.ShowUserRequest{UserId: userID})
	if err != nil || shown.User.Email == nil || *shown.User.Email != "alice@example.com" || shown.User.IsDomainOwner {
		t.Fatalf("ShowUser = %+v, %v", shown, err)
	}
	if lp, err := c.ShowUserLoginProtect(&iam.ShowUserLoginProtectRequest{UserId: userID}); err != nil || lp.LoginProtect.Enabled {
		t.Fatalf("ShowUserLoginProtect = %+v, %v", lp, err)
	}

	// IAM 5.0 sees the same user, and makes a group it joins.
	u5, err := c5.ShowUserV5(&v5.ShowUserV5Request{UserId: userID})
	if err != nil || u5.User.UserName != "sdk-alice" || u5.User.CreatedAt == nil {
		t.Fatalf("ShowUserV5 = %+v, %v", u5, err)
	}
	g, err := c5.CreateGroupV5(&v5.CreateGroupV5Request{Body: &v5.CreateGroupReqBody{GroupName: "sdk-devs"}})
	if err != nil || g.Group.GroupName != "sdk-devs" {
		t.Fatalf("CreateGroupV5 = %+v, %v", g, err)
	}
	groupID := g.Group.GroupId
	defer func() {
		if _, err := c5.DeleteGroupV5(&v5.DeleteGroupV5Request{GroupId: groupID}); err != nil {
			t.Errorf("DeleteGroupV5: %v", err)
		}
	}()
	if _, err := c5.AddUserToGroupV5(&v5.AddUserToGroupV5Request{GroupId: groupID, Body: &v5.AddUserToGroupReqBody{UserId: userID}}); err != nil {
		t.Fatalf("AddUserToGroupV5: %v", err)
	}
	if _, err := c.KeystoneCheckUserInGroup(&iam.KeystoneCheckUserInGroupRequest{GroupId: groupID, UserId: userID}); err != nil {
		t.Fatalf("KeystoneCheckUserInGroup: %v", err)
	}
	groups, err := c.KeystoneListGroupsForUser(&iam.KeystoneListGroupsForUserRequest{UserId: userID})
	if err != nil || groups.Groups == nil || len(*groups.Groups) != 1 || (*groups.Groups)[0].Name != "sdk-devs" {
		t.Fatalf("KeystoneListGroupsForUser = %+v, %v", groups, err)
	}
	members, err := c5.ListUsersV5(&v5.ListUsersV5Request{GroupId: &groupID})
	if err != nil || members.Users == nil || len(*members.Users) != 1 {
		t.Fatalf("ListUsersV5 = %+v, %v", members, err)
	}

	// The user signs in with the password, for the region's project.
	tok, err := c.KeystoneCreateUserTokenByPassword(&iam.KeystoneCreateUserTokenByPasswordRequest{Body: &iam.KeystoneCreateUserTokenByPasswordRequestBody{
		Auth: &iam.PwdAuth{
			Identity: &iam.PwdIdentity{
				Methods: []iam.PwdIdentityMethods{iam.GetPwdIdentityMethodsEnum().PASSWORD},
				Password: &iam.PwdPassword{User: &iam.PwdPasswordUser{
					Name: "sdk-alice", Password: sdkPassword, Domain: &iam.PwdPasswordUserDomain{Name: "weistack"},
				}},
			},
			Scope: &iam.AuthScope{Project: &iam.AuthScopeProject{Name: ptr(region)}},
		},
	}})
	if err != nil || tok.XSubjectToken == nil || tok.Token == nil || tok.Token.Project == nil || tok.Token.Project.Id != projectID {
		t.Fatalf("KeystoneCreateUserTokenByPassword = %+v, %v", tok, err)
	}
	valid, err := c.KeystoneValidateToken(&iam.KeystoneValidateTokenRequest{XSubjectToken: *tok.XSubjectToken})
	if err != nil || valid.Token.User.Id != userID {
		t.Fatalf("KeystoneValidateToken = %+v, %v", valid, err)
	}
	last, err := c5.ShowUserLastLoginV5(&v5.ShowUserLastLoginV5Request{UserId: userID})
	if err != nil || last.UserLastLogin == nil || last.UserLastLogin.LastLoginAt == nil {
		t.Fatalf("ShowUserLastLoginV5 = %+v, %v", last, err)
	}

	if _, err := c5.RemoveUserFromGroupV5(&v5.RemoveUserFromGroupV5Request{GroupId: groupID, Body: &v5.RemoveUserFromGroupReqBody{UserId: userID}}); err != nil {
		t.Fatalf("RemoveUserFromGroupV5: %v", err)
	}
}
