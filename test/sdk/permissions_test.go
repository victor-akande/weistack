package sdk

import (
	"errors"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	kmsmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
	stsv1 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1"
	sts "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/model"
	stsregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/region"
	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

// stsAs builds an STS client that signs with ak and sk.
func stsAs(t *testing.T, ak, sk string) *stsv1.StsClient {
	t.Helper()
	creds, err := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithProjectId(projectID).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := stsregion.SafeValueOf(region)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := stsv1.StsClientBuilder().
		WithRegion(reg).WithCredential(creds).WithHttpConfig(proxyConfig(t)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	return stsv1.NewStsClient(hc)
}

// denialOf returns the encoded authorization message of a denial the
// SDK decoded, after checking its status and code.
func denialOf(t *testing.T, err error, code string) string {
	t.Helper()
	wantError(t, err, 403, code)
	var byPtr *sdkerr.ServiceResponseError
	var byValue sdkerr.ServiceResponseError
	switch {
	case errors.As(err, &byPtr):
		byValue = *byPtr
	case errors.As(err, &byValue):
	}
	if byValue.EncodedAuthorizationMessage == "" {
		t.Fatalf("the denial has no encoded_authorization_message: %v", err)
	}
	return byValue.EncodedAuthorizationMessage
}

// TestPermissions runs only with WEISTACK_SDK_IAM=enforce: an IAM user's
// own key is allowed what its group's and its own policies allow, and
// refused the rest with each service's error, which the SDK decodes.
func TestPermissions(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()
	admin, admin5 := iamClientsAs(t, adminAK, adminSK)

	// A user with a key, in a group with VPC ReadOnlyAccess in the
	// project.
	u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-limited", Enabled: true}})
	if err != nil {
		t.Fatalf("CreateUserV5: %v", err)
	}
	uid := u.User.UserId
	defer func() {
		if _, err := admin5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: uid}); err != nil {
			t.Errorf("DeleteUserV5: %v", err)
		}
	}()
	key, err := admin.CreatePermanentAccessKey(&iam.CreatePermanentAccessKeyRequest{Body: &iam.CreatePermanentAccessKeyRequestBody{
		Credential: &iam.CreateCredentialOption{UserId: uid},
	}})
	if err != nil {
		t.Fatalf("CreatePermanentAccessKey: %v", err)
	}
	ak, sk := key.Credential.Access, key.Credential.Secret

	g, err := admin.KeystoneCreateGroup(&iam.KeystoneCreateGroupRequest{Body: &iam.KeystoneCreateGroupRequestBody{
		Group: &iam.KeystoneCreateGroupOption{Name: "sdk-vpc-readers"},
	}})
	if err != nil {
		t.Fatalf("KeystoneCreateGroup: %v", err)
	}
	gid := g.Group.Id
	defer func() {
		if _, err := admin.KeystoneDeleteGroup(&iam.KeystoneDeleteGroupRequest{GroupId: gid}); err != nil {
			t.Errorf("KeystoneDeleteGroup: %v", err)
		}
	}()
	if _, err := admin.KeystoneAddUserToGroup(&iam.KeystoneAddUserToGroupRequest{GroupId: gid, UserId: uid}); err != nil {
		t.Fatalf("KeystoneAddUserToGroup: %v", err)
	}
	perms, err := admin.KeystoneListPermissions(&iam.KeystoneListPermissionsRequest{DisplayName: ptr("VPC ReadOnlyAccess")})
	if err != nil || perms.Roles == nil || len(*perms.Roles) != 1 {
		t.Fatalf("KeystoneListPermissions = %+v, %v", perms, err)
	}
	if _, err := admin.KeystoneAssociateGroupWithProjectPermission(&iam.KeystoneAssociateGroupWithProjectPermissionRequest{
		ProjectId: projectID, GroupId: gid, RoleId: (*perms.Roles)[0].Id,
	}); err != nil {
		t.Fatalf("KeystoneAssociateGroupWithProjectPermission: %v", err)
	}

	// Reading is allowed; creating is not.
	user := vpcAs(t, ak, sk)
	if _, err := user.ListVpcs(&vpc.ListVpcsRequest{}); err != nil {
		t.Fatalf("ListVpcs with VPC ReadOnlyAccess: %v", err)
	}
	_, err = user.CreateVpc(&vpc.CreateVpcRequest{Body: &vpc.CreateVpcRequestBody{Vpc: &vpc.CreateVpcOption{Name: ptr("sdk-denied")}}})
	encoded := denialOf(t, err, "WeiStack.0403")

	// KMS refuses with its own code; a key resource is named.
	_, err = kmsAs(t, ak, sk).CreateKey(&kmsmodel.CreateKeyRequest{Body: &kmsmodel.CreateKeyRequestBody{KeyAlias: "sdk-denied"}})
	denialOf(t, err, "KMS.0306")
	_, err = kmsAs(t, ak, sk).ListKeyDetail(&kmsmodel.ListKeyDetailRequest{Body: &kmsmodel.OperateKeyRequestBody{KeyId: "00000000-0000-0000-0000-000000000000"}})
	denialOf(t, err, "KMS.0306")

	// STS decodes the denial, for whoever may decode.
	decoded, err := stsAs(t, adminAK, adminSK).DecodeAuthorizationMessage(&sts.DecodeAuthorizationMessageRequest{
		Body: &sts.DecodeAuthorizationMessageReq{EncodedMessage: encoded},
	})
	if err != nil || decoded.DecodedMessage == nil {
		t.Fatalf("DecodeAuthorizationMessage = %+v, %v", decoded, err)
	}
	for _, want := range []string{`"action":"vpc:vpcs:create"`, `"user_name":"sdk-limited"`, `"failure":"implicit deny by identity-based policy"`} {
		if !strings.Contains(*decoded.DecodedMessage, want) {
			t.Errorf("decoded %s lacks %s", *decoded.DecodedMessage, want)
		}
	}
	// The user may not decode it: that needs sts::decodeAuthorizationMessage.
	_, err = stsAs(t, ak, sk).DecodeAuthorizationMessage(&sts.DecodeAuthorizationMessageRequest{
		Body: &sts.DecodeAuthorizationMessageReq{EncodedMessage: encoded},
	})
	denialOf(t, err, "STS5.1001")

	// An IAM 5.0 policy's Deny overrides the group's Allow.
	doc := `{"Version":"5.0","Statement":[{"Effect":"Deny","Action":["vpc:vpcs:list"]}]}`
	p, err := admin5.CreatePolicyV5(&v5.CreatePolicyV5Request{Body: &v5.CreatePolicyReqBody{PolicyName: "sdk-no-vpc-list", PolicyDocument: doc}})
	if err != nil {
		t.Fatalf("CreatePolicyV5: %v", err)
	}
	pid := p.Policy.PolicyId
	if _, err := admin5.AttachUserPolicyV5(&v5.AttachUserPolicyV5Request{PolicyId: pid, Body: &v5.AttachUserPolicyReqBody{UserId: uid}}); err != nil {
		t.Fatalf("AttachUserPolicyV5: %v", err)
	}
	_, err = user.ListVpcs(&vpc.ListVpcsRequest{})
	denialOf(t, err, "WeiStack.0403")
	if _, err := admin5.DetachUserPolicyV5(&v5.DetachUserPolicyV5Request{PolicyId: pid, Body: &v5.DetachUserPolicyReqBody{UserId: uid}}); err != nil {
		t.Fatalf("DetachUserPolicyV5: %v", err)
	}
	if _, err := admin5.DeletePolicyV5(&v5.DeletePolicyV5Request{PolicyId: pid}); err != nil {
		t.Fatalf("DeletePolicyV5: %v", err)
	}
	if _, err := user.ListVpcs(&vpc.ListVpcsRequest{}); err != nil {
		t.Fatalf("ListVpcs once the Deny is detached: %v", err)
	}

	// IAM refuses with its own documented codes, but lets the user read
	// itself and manage its own keys.
	mine, mine5 := iamClientsAs(t, ak, sk)
	_, err = mine.KeystoneListUsers(&iam.KeystoneListUsersRequest{})
	denialOf(t, err, "IAM.0003")
	_, err = mine5.ListUsersV5(&v5.ListUsersV5Request{})
	denialOf(t, err, "PAP5.0001")
	if _, err := mine.KeystoneShowUser(&iam.KeystoneShowUserRequest{UserId: uid}); err != nil {
		t.Errorf("KeystoneShowUser of oneself: %v", err)
	}
	if _, err := mine.ListPermanentAccessKeys(&iam.ListPermanentAccessKeysRequest{UserId: &uid}); err != nil {
		t.Errorf("ListPermanentAccessKeys of one's own: %v", err)
	}

	// OBS refuses with AccessDenied.
	_, err = newOBSWithKey(t, emulatorAddr, ak, sk, obs.SignatureObs, false).ListBuckets(nil)
	wantOBSError(t, err, 403, "AccessDenied")
}
