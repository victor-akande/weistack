package sdk

import (
	"testing"

	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
)

// TestIAMPoliciesV5 creates an identity policy with a second version,
// attaches it to a user and a group, and takes it apart again, all
// through the SDK's IAM 5.0 models.
func TestIAMPoliciesV5(t *testing.T) {
	t.Parallel()
	_, c5 := iamClients(t, "AKIAMPOLICIES0000000")
	const doc = `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["obs:*:get*","obs:*:list*"]}]}`

	created, err := c5.CreatePolicyV5(&v5.CreatePolicyV5Request{Body: &v5.CreatePolicyReqBody{
		PolicyName: "sdk-obs-readers", Path: ptr("sdk/"), PolicyDocument: doc, Description: ptr("sdk"),
	}})
	if err != nil || created.Policy == nil || created.Policy.DefaultVersionId != "v1" || created.Policy.CreatedAt == nil ||
		created.Policy.PolicyType.Value() != "custom" {
		t.Fatalf("CreatePolicyV5 = %+v, %v", created, err)
	}
	pid := created.Policy.PolicyId

	v2, err := c5.CreatePolicyVersionV5(&v5.CreatePolicyVersionV5Request{PolicyId: pid, Body: &v5.CreatePolicyVersionReqBody{
		PolicyDocument: `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["obs:*:*"]}]}`, SetAsDefault: ptr(true),
	}})
	if err != nil || v2.PolicyVersion.VersionId != "v2" || !v2.PolicyVersion.IsDefault {
		t.Fatalf("CreatePolicyVersionV5 = %+v, %v", v2, err)
	}
	versions, err := c5.ListPolicyVersionsV5(&v5.ListPolicyVersionsV5Request{PolicyId: pid})
	if err != nil || len(*versions.Versions) != 2 || (*versions.Versions)[0].VersionId != "v2" {
		t.Fatalf("ListPolicyVersionsV5 = %+v, %v", versions, err)
	}
	if _, err := c5.SetDefaultPolicyVersionV5(&v5.SetDefaultPolicyVersionV5Request{PolicyId: pid, VersionId: "v1"}); err != nil {
		t.Fatalf("SetDefaultPolicyVersionV5: %v", err)
	}
	if _, err := c5.DeletePolicyVersionV5(&v5.DeletePolicyVersionV5Request{PolicyId: pid, VersionId: "v2"}); err != nil {
		t.Fatalf("DeletePolicyVersionV5: %v", err)
	}

	u, err := c5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-policy-holder", Enabled: true}})
	if err != nil {
		t.Fatalf("CreateUserV5: %v", err)
	}
	uid := u.User.UserId
	g, err := c5.CreateGroupV5(&v5.CreateGroupV5Request{Body: &v5.CreateGroupReqBody{GroupName: "sdk-policy-group"}})
	if err != nil {
		t.Fatalf("CreateGroupV5: %v", err)
	}
	gid := g.Group.GroupId
	defer func() {
		if _, err := c5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: uid}); err != nil {
			t.Errorf("DeleteUserV5: %v", err)
		}
		if _, err := c5.DeleteGroupV5(&v5.DeleteGroupV5Request{GroupId: gid}); err != nil {
			t.Errorf("DeleteGroupV5: %v", err)
		}
	}()

	if _, err := c5.AttachUserPolicyV5(&v5.AttachUserPolicyV5Request{PolicyId: pid, Body: &v5.AttachUserPolicyReqBody{UserId: uid}}); err != nil {
		t.Fatalf("AttachUserPolicyV5: %v", err)
	}
	if _, err := c5.AttachGroupPolicyV5(&v5.AttachGroupPolicyV5Request{PolicyId: pid, Body: &v5.AttachGroupPolicyReqBody{GroupId: gid}}); err != nil {
		t.Fatalf("AttachGroupPolicyV5: %v", err)
	}
	held, err := c5.ListAttachedUserPoliciesV5(&v5.ListAttachedUserPoliciesV5Request{UserId: uid})
	if err != nil || len(*held.AttachedPolicies) != 1 || (*held.AttachedPolicies)[0].PolicyId != pid || (*held.AttachedPolicies)[0].AttachedAt == nil {
		t.Fatalf("ListAttachedUserPoliciesV5 = %+v, %v", held, err)
	}
	entities, err := c5.ListEntitiesForPolicyV5(&v5.ListEntitiesForPolicyV5Request{PolicyId: pid})
	if err != nil || len(*entities.PolicyUsers) != 1 || len(*entities.PolicyGroups) != 1 {
		t.Fatalf("ListEntitiesForPolicyV5 = %+v, %v", entities, err)
	}
	if _, err := c5.DeletePolicyV5(&v5.DeletePolicyV5Request{PolicyId: pid}); err == nil {
		t.Fatal("an attached policy was deleted")
	}

	if _, err := c5.DetachUserPolicyV5(&v5.DetachUserPolicyV5Request{PolicyId: pid, Body: &v5.DetachUserPolicyReqBody{UserId: uid}}); err != nil {
		t.Fatalf("DetachUserPolicyV5: %v", err)
	}
	if _, err := c5.DetachGroupPolicyV5(&v5.DetachGroupPolicyV5Request{PolicyId: pid, Body: &v5.DetachGroupPolicyReqBody{GroupId: gid}}); err != nil {
		t.Fatalf("DetachGroupPolicyV5: %v", err)
	}
	if _, err := c5.DeletePolicyV5(&v5.DeletePolicyV5Request{PolicyId: pid}); err != nil {
		t.Fatalf("DeletePolicyV5: %v", err)
	}
}
