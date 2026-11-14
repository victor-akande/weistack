package sdk

import (
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	stsv1 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1"
	sts "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/model"
	stsregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/region"
)

// callerAs asks STS who the holder of an access key is.
func callerAs(t *testing.T, ak, sk string) *sts.GetCallerIdentityResponse {
	t.Helper()
	creds, err := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	hc, err := stsv1.StsClientBuilder().
		WithRegion(stsregion.ValueOf(region)).WithCredential(creds).WithHttpConfig(proxyConfig(t)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	who, err := stsv1.NewStsClient(hc).GetCallerIdentity(&sts.GetCallerIdentityRequest{})
	if err != nil {
		t.Fatalf("GetCallerIdentity: %v", err)
	}
	return who
}

// TestIAMAccessKeys creates keys through both API generations with the
// SDK's own models, then signs requests with one: the emulator knows it
// as its user's.
func TestIAMAccessKeys(t *testing.T) {
	t.Parallel()
	c, c5 := iamClients(t, "AKIAMKEYS00000000000")
	u, err := c5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-keyholder", Enabled: true}})
	if err != nil {
		t.Fatalf("CreateUserV5: %v", err)
	}
	userID := u.User.UserId
	defer func() {
		if _, err := c5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: userID}); err != nil {
			t.Errorf("DeleteUserV5: %v", err)
		}
	}()

	// Classic.
	created, err := c.CreatePermanentAccessKey(&iam.CreatePermanentAccessKeyRequest{Body: &iam.CreatePermanentAccessKeyRequestBody{
		Credential: &iam.CreateCredentialOption{UserId: userID, Description: ptr("sdk")},
	}})
	if err != nil || created.Credential == nil || len(created.Credential.Access) != 20 || len(created.Credential.Secret) != 40 {
		t.Fatalf("CreatePermanentAccessKey = %+v, %v", created, err)
	}
	ak, sk := created.Credential.Access, created.Credential.Secret
	shown, err := c.ShowPermanentAccessKey(&iam.ShowPermanentAccessKeyRequest{AccessKey: ak})
	if err != nil || shown.Credential.UserId != userID || shown.Credential.Status != "active" || shown.Credential.Description != "sdk" {
		t.Fatalf("ShowPermanentAccessKey = %+v, %v", shown, err)
	}

	// The key acts as its user.
	who := callerAs(t, ak, sk)
	if who.PrincipalId == nil || *who.PrincipalId != userID || who.PrincipalUrn == nil || *who.PrincipalUrn != "iam::"+*who.AccountId+":user:sdk-keyholder" {
		t.Fatalf("GetCallerIdentity = %+v", who)
	}

	// IAM 5.0 sees it, and can make the second.
	listed, err := c5.ListAccessKeysV5(&v5.ListAccessKeysV5Request{UserId: userID})
	if err != nil || len(*listed.AccessKeys) != 1 || (*listed.AccessKeys)[0].AccessKeyId != ak {
		t.Fatalf("ListAccessKeysV5 = %+v, %v", listed, err)
	}
	second, err := c5.CreateAccessKeyV5(&v5.CreateAccessKeyV5Request{UserId: userID})
	if err != nil || second.AccessKey.SecretAccessKey == "" || second.AccessKey.CreatedAt == nil {
		t.Fatalf("CreateAccessKeyV5 = %+v, %v", second, err)
	}
	if _, err := c5.CreateAccessKeyV5(&v5.CreateAccessKeyV5Request{UserId: userID}); err == nil {
		t.Fatal("a third key was created")
	}
	owners, err := c5.ListUsersV5(&v5.ListUsersV5Request{AccessKeyId: &second.AccessKey.AccessKeyId})
	if err != nil || len(*owners.Users) != 1 || (*owners.Users)[0].UserId != userID {
		t.Fatalf("ListUsersV5(access_key_id) = %+v, %v", owners, err)
	}
	used, err := c5.ShowAccessKeyLastUsedV5(&v5.ShowAccessKeyLastUsedV5Request{UserId: userID, AccessKeyId: ak})
	if err != nil || used.AccessKeyLastUsed == nil || used.AccessKeyLastUsed.LastUsedAt == nil {
		t.Fatalf("ShowAccessKeyLastUsedV5 = %+v, %v", used, err)
	}

	// Deactivated through one API, it shows through the other.
	inactive := v5.GetAccessKeyStatusEnum().INACTIVE
	if _, err := c5.UpdateAccessKeyV5(&v5.UpdateAccessKeyV5Request{
		UserId: userID, AccessKeyId: ak, Body: &v5.UpdateAccessKeyReqBody{Status: &inactive},
	}); err != nil {
		t.Fatalf("UpdateAccessKeyV5: %v", err)
	}
	if shown, err := c.ShowPermanentAccessKey(&iam.ShowPermanentAccessKeyRequest{AccessKey: ak}); err != nil || shown.Credential.Status != "inactive" {
		t.Fatalf("ShowPermanentAccessKey after deactivation = %+v, %v", shown, err)
	}
	active := iam.GetUpdateCredentialOptionStatusEnum().ACTIVE
	if _, err := c.UpdatePermanentAccessKey(&iam.UpdatePermanentAccessKeyRequest{
		AccessKey: ak, Body: &iam.UpdatePermanentAccessKeyRequestBody{Credential: &iam.UpdateCredentialOption{Status: &active}},
	}); err != nil {
		t.Fatalf("UpdatePermanentAccessKey: %v", err)
	}

	if _, err := c.DeletePermanentAccessKey(&iam.DeletePermanentAccessKeyRequest{AccessKey: ak}); err != nil {
		t.Fatalf("DeletePermanentAccessKey: %v", err)
	}
	if _, err := c5.DeleteAccessKeyV5(&v5.DeleteAccessKeyV5Request{UserId: userID, AccessKeyId: second.AccessKey.AccessKeyId}); err != nil {
		t.Fatalf("DeleteAccessKeyV5: %v", err)
	}
	keys, err := c.ListPermanentAccessKeys(&iam.ListPermanentAccessKeysRequest{UserId: &userID})
	if err != nil || len(*keys.Credentials) != 0 {
		t.Fatalf("ListPermanentAccessKeys = %+v, %v", keys, err)
	}
}
