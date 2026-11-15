package sdk

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	kmsv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2"
	kms "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
	kmsregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/region"
)

// kmsAs builds a KMS client that signs with ak and sk in the project.
func kmsAs(t *testing.T, ak, sk string) *kmsv2.KmsClient {
	t.Helper()
	creds, err := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithProjectId(projectID).SafeBuild()
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
