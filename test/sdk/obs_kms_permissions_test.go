package sdk

import (
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	kms "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
)

// TestOBSSSEKMSWithRegionalKMSGrant: SSE-KMS needs KMS permission as well
// as OBS's, and the KMS permission is the one granted where KMS's own
// grants apply, in the region's project. A user with OBS Administrator for
// the account is refused an SSE-KMS upload until its group also holds KMS
// Administrator in the project, and may then write and read the object.
func TestOBSSSEKMSWithRegionalKMSGrant(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()
	admin, admin5 := iamClientsAs(t, adminAK, adminSK)
	suffix := strings.ToLower(rand.Text()[:6])

	domains, err := admin.KeystoneListAuthDomains(&iam.KeystoneListAuthDomainsRequest{})
	if err != nil || domains.Domains == nil || len(*domains.Domains) == 0 {
		t.Fatalf("KeystoneListAuthDomains = %+v, %v", domains, err)
	}
	account := (*domains.Domains)[0].Id

	u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-sse-" + suffix, Enabled: true}})
	if err != nil {
		t.Fatalf("CreateUserV5: %v", err)
	}
	uid := u.User.UserId
	t.Cleanup(func() { _, _ = admin5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: uid}) })
	key, err := admin.CreatePermanentAccessKey(&iam.CreatePermanentAccessKeyRequest{Body: &iam.CreatePermanentAccessKeyRequestBody{
		Credential: &iam.CreateCredentialOption{UserId: uid},
	}})
	if err != nil {
		t.Fatalf("CreatePermanentAccessKey: %v", err)
	}
	ak, sk := key.Credential.Access, key.Credential.Secret

	g, err := admin.KeystoneCreateGroup(&iam.KeystoneCreateGroupRequest{Body: &iam.KeystoneCreateGroupRequestBody{
		Group: &iam.KeystoneCreateGroupOption{Name: "sdk-sse-" + suffix},
	}})
	if err != nil {
		t.Fatalf("KeystoneCreateGroup: %v", err)
	}
	gid := g.Group.Id
	t.Cleanup(func() { _, _ = admin.KeystoneDeleteGroup(&iam.KeystoneDeleteGroupRequest{GroupId: gid}) })
	if _, err := admin.KeystoneAddUserToGroup(&iam.KeystoneAddUserToGroupRequest{GroupId: gid, UserId: uid}); err != nil {
		t.Fatalf("KeystoneAddUserToGroup: %v", err)
	}
	role := func(name string) string {
		t.Helper()
		perms, err := admin.KeystoneListPermissions(&iam.KeystoneListPermissionsRequest{DisplayName: ptr(name)})
		if err != nil || perms.Roles == nil || len(*perms.Roles) != 1 {
			t.Fatalf("KeystoneListPermissions(%s) = %+v, %v", name, perms, err)
		}
		return (*perms.Roles)[0].Id
	}
	// OBS is a global service: granted for the account.
	if _, err := admin.KeystoneAssociateGroupWithDomainPermission(&iam.KeystoneAssociateGroupWithDomainPermissionRequest{
		DomainId: account, GroupId: gid, RoleId: role("OBS Administrator"),
	}); err != nil {
		t.Fatalf("KeystoneAssociateGroupWithDomainPermission: %v", err)
	}

	keys := kmsAs(t, adminAK, adminSK)
	k, err := keys.CreateKey(&kms.CreateKeyRequest{Body: &kms.CreateKeyRequestBody{KeyAlias: "sdk-sse-" + suffix}})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyID := *k.KeyInfo.KeyId
	t.Cleanup(func() {
		_, _ = keys.DeleteKey(&kms.DeleteKeyRequest{Body: &kms.ScheduleKeyDeletionRequestBody{KeyId: keyID, PendingDays: "7"}})
	})

	c := newOBSWithKey(t, emulatorAddr, ak, sk, obs.SignatureObs, false)
	bucket := "sdk-sse-" + suffix
	if _, err := c.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
		t.Fatalf("CreateBucket with OBS Administrator: %v", err)
	}
	t.Cleanup(func() {
		_, _ = c.DeleteObject(&obs.DeleteObjectInput{Bucket: bucket, Key: "secret"})
		_, _ = c.DeleteBucket(bucket)
	})
	put := func() error {
		in := &obs.PutObjectInput{Body: strings.NewReader("encrypted at rest")}
		in.Bucket, in.Key = bucket, "secret"
		in.SseHeader = obs.SseKmsHeader{Encryption: obs.DEFAULT_SSE_KMS_ENCRYPTION_OBS, Key: keyID}
		_, err := c.PutObject(in)
		return err
	}

	// OBS's permission alone does not let the user use the key.
	wantOBSError(t, put(), 403, "AccessDenied")

	// KMS Administrator in the region's project does, as a direct call to
	// KMS would be allowed.
	if _, err := admin.KeystoneAssociateGroupWithProjectPermission(&iam.KeystoneAssociateGroupWithProjectPermissionRequest{
		ProjectId: projectID, GroupId: gid, RoleId: role("KMS Administrator"),
	}); err != nil {
		t.Fatalf("KeystoneAssociateGroupWithProjectPermission: %v", err)
	}
	if err := put(); err != nil {
		t.Fatalf("PutObject(SSE-KMS) with KMS Administrator in the project: %v", err)
	}
	got, err := c.GetObject(&obs.GetObjectInput{GetObjectMetadataInput: obs.GetObjectMetadataInput{Bucket: bucket, Key: "secret"}})
	if err != nil {
		t.Fatalf("GetObject(SSE-KMS): %v", err)
	}
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()
	if string(body) != "encrypted at rest" {
		t.Errorf("GetObject = %q", body)
	}
}
