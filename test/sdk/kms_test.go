package sdk

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	kmsv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2"
	kms "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
	kmsregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/region"
)

// kmsAs builds a KMS client that signs with ak and sk in the project.
func kmsAs(t *testing.T, ak, sk string) *kmsv2.KmsClient {
	t.Helper()
	return kmsIn(t, ak, sk, projectID)
}

// kmsIn builds a KMS client that signs with ak and sk in project.
func kmsIn(t *testing.T, ak, sk, project string) *kmsv2.KmsClient {
	t.Helper()
	creds, err := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithProjectId(project).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	hc, err := kmsv2.KmsClientBuilder().
		WithRegion(kmsregion.ValueOf(region)).WithCredential(creds).WithHttpConfig(proxyConfig(t)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	return kmsv2.NewKmsClient(hc)
}

// TestKMS drives a key's life through the SDK's own models: creating,
// encrypting and decrypting, data keys, rotation, tags, disabling and
// scheduled deletion.
func TestKMS(t *testing.T) {
	t.Parallel()
	c := kmsAs(t, signingAK("AKKMS000000000000000"), signingSK())
	alias := "sdk-kms-" + strings.ToLower(rand.Text()[:6])
	created, err := c.CreateKey(&kms.CreateKeyRequest{Body: &kms.CreateKeyRequestBody{
		KeyAlias: alias, KeyDescription: ptr("for the SDK suite"),
	}})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	id := *created.KeyInfo.KeyId
	t.Cleanup(func() {
		_, _ = c.DeleteKey(&kms.DeleteKeyRequest{Body: &kms.ScheduleKeyDeletionRequestBody{KeyId: id, PendingDays: "7"}})
	})
	shown, err := c.ListKeyDetail(&kms.ListKeyDetailRequest{Body: &kms.OperateKeyRequestBody{KeyId: id}})
	if err != nil || *shown.KeyInfo.KeyAlias != alias || *shown.KeyInfo.KeyState != "2" || shown.KeyInfo.KeySpec.Value() != "AES_256" {
		t.Fatalf("ListKeyDetail = %+v, %v", shown, err)
	}

	// Encryption, without the key ID on the way back.
	enc, err := c.EncryptData(&kms.EncryptDataRequest{Body: &kms.EncryptDataRequestBody{KeyId: id, PlainText: "hello world"}})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	dec, err := c.DecryptData(&kms.DecryptDataRequest{Body: &kms.DecryptDataRequestBody{CipherText: *enc.CipherText}})
	if err != nil || *dec.PlainText != "hello world" || *dec.KeyId != id {
		t.Fatalf("DecryptData = %+v, %v", dec, err)
	}

	// A data key, and its ciphertext decrypted again.
	dk, err := c.CreateDatakey(&kms.CreateDatakeyRequest{Body: &kms.CreateDatakeyRequestBody{KeyId: id, DatakeyLength: ptr("256")}})
	if err != nil {
		t.Fatalf("CreateDatakey: %v", err)
	}
	back, err := c.DecryptDatakey(&kms.DecryptDatakeyRequest{Body: &kms.DecryptDatakeyRequestBody{
		KeyId: id, CipherText: *dk.CipherText, DatakeyCipherLength: "32",
	}})
	if err != nil || *back.DataKey != *dk.PlainText {
		t.Fatalf("DecryptDatakey = %+v, %v", back, err)
	}

	// Rotation and tags.
	if _, err := c.EnableKeyRotation(&kms.EnableKeyRotationRequest{Body: &kms.OperateKeyRequestBody{KeyId: id}}); err != nil {
		t.Fatalf("EnableKeyRotation: %v", err)
	}
	rot, err := c.ShowKeyRotationStatus(&kms.ShowKeyRotationStatusRequest{Body: &kms.OperateKeyRequestBody{KeyId: id}})
	if err != nil || !*rot.KeyRotationEnabled || *rot.RotationInterval != 365 {
		t.Fatalf("ShowKeyRotationStatus = %+v, %v", rot, err)
	}
	if _, err := c.CreateKmsTag(&kms.CreateKmsTagRequest{KeyId: id, Body: &kms.CreateKmsTagRequestBody{
		Tag: &kms.TagItem{Key: "env", Value: ptr("test")},
	}}); err != nil {
		t.Fatalf("CreateKmsTag: %v", err)
	}
	tags, err := c.ShowKmsTags(&kms.ShowKmsTagsRequest{KeyId: id})
	if err != nil || len(*tags.Tags) != 1 || (*tags.Tags)[0].Key != "env" {
		t.Fatalf("ShowKmsTags = %+v, %v", tags, err)
	}

	// Disabled keys refuse to encrypt, with KMS's error.
	if _, err := c.DisableKey(&kms.DisableKeyRequest{Body: &kms.OperateKeyRequestBody{KeyId: id}}); err != nil {
		t.Fatalf("DisableKey: %v", err)
	}
	_, err = c.EncryptData(&kms.EncryptDataRequest{Body: &kms.EncryptDataRequestBody{KeyId: id, PlainText: "x"}})
	wantError(t, err, 400, "KMS.0209")

	listed, err := c.ListKeys(&kms.ListKeysRequest{Body: &kms.ListKeysRequestBody{KeyState: ptr("3")}})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	found := false
	for _, k := range *listed.Keys {
		found = found || k == id
	}
	if !found {
		t.Errorf("ListKeys(disabled) = %v, lacks %s", *listed.Keys, id)
	}
	del, err := c.DeleteKey(&kms.DeleteKeyRequest{Body: &kms.ScheduleKeyDeletionRequestBody{KeyId: id, PendingDays: "7"}})
	if err != nil || *del.KeyState != "4" {
		t.Fatalf("DeleteKey = %+v, %v", del, err)
	}
	_, err = c.ListKeyDetail(&kms.ListKeyDetailRequest{Body: &kms.OperateKeyRequestBody{KeyId: "00000000-0000-0000-0000-000000000000"}})
	wantError(t, err, 404, "KMS.0207")
}

// TestKMSSigningAndMACs signs and verifies with an EC key, reads its
// public key, and makes and checks an HMAC, through the SDK's models.
func TestKMSSigningAndMACs(t *testing.T) {
	t.Parallel()
	c := kmsAs(t, signingAK("AKKMSSIGN00000000000"), signingSK())
	suffix := strings.ToLower(rand.Text()[:6])
	spec := kms.GetCreateKeyRequestBodyKeySpecEnum()
	ec, err := c.CreateKey(&kms.CreateKeyRequest{Body: &kms.CreateKeyRequestBody{KeyAlias: "sdk-ec-" + suffix, KeySpec: &spec.EC_P256}})
	if err != nil {
		t.Fatalf("CreateKey(EC_P256): %v", err)
	}
	id := *ec.KeyInfo.KeyId
	digest := sha256.Sum256([]byte("release"))
	msg := base64.StdEncoding.EncodeToString(digest[:])
	signed, err := c.Sign(&kms.SignRequest{Body: &kms.SignRequestBody{
		KeyId: id, Message: msg, SigningAlgorithm: kms.GetSignRequestBodySigningAlgorithmEnum().ECDSA_SHA_256,
	}})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	valid, err := c.ValidateSignature(&kms.ValidateSignatureRequest{Body: &kms.VerifyRequestBody{
		KeyId: id, Message: msg, Signature: *signed.Signature, SigningAlgorithm: kms.GetVerifyRequestBodySigningAlgorithmEnum().ECDSA_SHA_256,
	}})
	if err != nil || *valid.SignatureValid != "true" {
		t.Fatalf("ValidateSignature = %+v, %v", valid, err)
	}
	pub, err := c.ShowPublicKey(&kms.ShowPublicKeyRequest{Body: &kms.OperateKeyRequestBody{KeyId: id}})
	if err != nil {
		t.Fatalf("ShowPublicKey: %v", err)
	}
	block, _ := pem.Decode([]byte(*pub.PublicKey))
	if block == nil {
		t.Fatalf("public key %q", *pub.PublicKey)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	// The signature verifies outside KMS, with the public key alone.
	sig, _ := base64.StdEncoding.DecodeString(*signed.Signature)
	if !ecdsa.VerifyASN1(key.(*ecdsa.PublicKey), digest[:], sig) {
		t.Error("the signature does not verify with the public key")
	}

	mk, err := c.CreateKey(&kms.CreateKeyRequest{Body: &kms.CreateKeyRequestBody{KeyAlias: "sdk-mac-" + suffix, KeySpec: &spec.HMAC_256}})
	if err != nil {
		t.Fatalf("CreateKey(HMAC_256): %v", err)
	}
	mac, err := c.GenerateMac(&kms.GenerateMacRequest{Body: &kms.GenerateMacRequestBody{
		KeyId: *mk.KeyInfo.KeyId, MacAlgorithm: kms.GetGenerateMacRequestBodyMacAlgorithmEnum().HMAC_SHA_256, Message: msg,
	}})
	if err != nil {
		t.Fatalf("GenerateMac: %v", err)
	}
	checked, err := c.VerifyMac(&kms.VerifyMacRequest{Body: &kms.VerifyMacRequestBody{
		KeyId: *mk.KeyInfo.KeyId, MacAlgorithm: kms.GetVerifyMacRequestBodyMacAlgorithmEnum().HMAC_SHA_256, Message: msg, Mac: *mac.Mac,
	}})
	if err != nil || !*checked.MacValid {
		t.Fatalf("VerifyMac = %+v, %v", checked, err)
	}
	for _, k := range []string{id, *mk.KeyInfo.KeyId} {
		if _, err := c.DeleteKey(&kms.DeleteKeyRequest{Body: &kms.ScheduleKeyDeletionRequestBody{KeyId: k, PendingDays: "7"}}); err != nil {
			t.Errorf("DeleteKey: %v", err)
		}
	}
}

// TestKMSGrants: an IAM user with no permissions, and another account,
// use a key through grants alone; revoking ends it. With credentials
// enforced, what was not granted is refused.
func TestKMSGrants(t *testing.T) {
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	admin := kmsAs(t, signingAK("AKKMSGRANTS000000000"), signingSK())
	_, admin5 := iamClients(t, "AKKMSGRANTS000000000")
	u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-grantee-" + suffix, Enabled: true}})
	if err != nil {
		t.Fatalf("CreateUserV5: %v", err)
	}
	uid := u.User.UserId
	t.Cleanup(func() { _, _ = admin5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: uid}) })
	ak, err := admin5.CreateAccessKeyV5(&v5.CreateAccessKeyV5Request{UserId: uid})
	if err != nil {
		t.Fatalf("CreateAccessKeyV5: %v", err)
	}
	user := kmsAs(t, ak.AccessKey.AccessKeyId, ak.AccessKey.SecretAccessKey)
	partner := addAccount(t, "sdk-kms-partner-"+suffix)
	other := kmsIn(t, partner.AK, partner.SK, partner.ProjectID)

	k, err := admin.CreateKey(&kms.CreateKeyRequest{Body: &kms.CreateKeyRequestBody{KeyAlias: "sdk-granted-" + suffix}})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	id := *k.KeyInfo.KeyId
	t.Cleanup(func() {
		_, _ = admin.DeleteKey(&kms.DeleteKeyRequest{Body: &kms.ScheduleKeyDeletionRequestBody{KeyId: id, PendingDays: "7"}})
	})
	typ := kms.GetCreateGrantRequestBodyGranteePrincipalTypeEnum()
	for _, g := range []kms.CreateGrantRequestBody{
		{KeyId: id, GranteePrincipal: uid, Operations: []string{"encrypt-data"}},
		{KeyId: id, GranteePrincipal: partner.ID, GranteePrincipalType: &typ.DOMAIN, Operations: []string{"decrypt-data"}},
	} {
		if _, err := admin.CreateGrant(&kms.CreateGrantRequest{Body: &g}); err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}
	}

	// The user encrypts; the partner, in its own project, decrypts.
	enc, err := user.EncryptData(&kms.EncryptDataRequest{Body: &kms.EncryptDataRequestBody{KeyId: id, PlainText: "granted"}})
	if err != nil {
		t.Fatalf("EncryptData as the grantee: %v", err)
	}
	dec, err := other.DecryptData(&kms.DecryptDataRequest{Body: &kms.DecryptDataRequestBody{CipherText: *enc.CipherText}})
	if err != nil || *dec.PlainText != "granted" {
		t.Fatalf("DecryptData as the other account = %+v, %v", dec, err)
	}
	if enforcing {
		_, err = user.ListKeyDetail(&kms.ListKeyDetailRequest{Body: &kms.OperateKeyRequestBody{KeyId: id}})
		denialOf(t, err, "KMS.0306")
	}

	grants, err := admin.ListGrants(&kms.ListGrantsRequest{Body: &kms.ListGrantsRequestBody{KeyId: id}})
	if err != nil || *grants.Total != 2 {
		t.Fatalf("ListGrants = %+v, %v", grants, err)
	}
	for _, g := range *grants.Grants {
		if _, err := admin.CancelGrant(&kms.CancelGrantRequest{Body: &kms.RevokeGrantRequestBody{KeyId: id, GrantId: *g.GrantId}}); err != nil {
			t.Fatalf("CancelGrant: %v", err)
		}
	}
	_, err = other.DecryptData(&kms.DecryptDataRequest{Body: &kms.DecryptDataRequestBody{CipherText: *enc.CipherText}})
	wantError(t, err, 404, "KMS.0207")
}
