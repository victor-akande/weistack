package sdk

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/def"
	csmsv1 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/csms/v1"
	csms "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/csms/v1/model"
	csmsregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/csms/v1/region"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	kms "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
	sts "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/model"
)

// csmsAs builds a CSMS client that signs with ak and sk in the project, using
// Huawei Cloud's real regional endpoint through the emulator proxy.
func csmsAs(t *testing.T, ak, sk string) *csmsv1.CsmsClient {
	t.Helper()
	return csmsIn(t, ak, sk, projectID)
}

// csmsIn builds a CSMS client that signs with ak and sk in project.
func csmsIn(t *testing.T, ak, sk, project string) *csmsv1.CsmsClient {
	t.Helper()
	creds, err := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithProjectId(project).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := csmsregion.SafeValueOf(region)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := csmsv1.CsmsClientBuilder().
		WithRegion(reg).
		WithCredential(creds).
		WithHttpConfig(proxyConfig(t)).
		SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	return csmsv1.NewCsmsClient(hc)
}

type showSecretWireResponse struct {
	csms.ShowSecretResponse
	Secret struct {
		LastUsedTime *int64 `json:"last_used_time,omitempty"`
	} `json:"secret"`
}

// showSecretLastUsedTime fetches GET /v1/{project_id}/secrets/{secret_name}
// through the official SDK client transport to inspect last_used_time, which
// CSMS sends on the wire even though model.Secret omits the field.
func showSecretLastUsedTime(t *testing.T, c *csmsv1.CsmsClient, secretName string) *int64 {
	t.Helper()
	reqDef := def.NewHttpRequestDefBuilder().
		WithMethod(http.MethodGet).
		WithPath("/v1/{project_id}/secrets/{secret_name}").
		WithResponse(new(showSecretWireResponse)).
		WithContentType("application/json").
		WithRequestField(def.NewFieldDef().
			WithName("SecretName").
			WithJsonTag("secret_name").
			WithLocationType(def.Path)).
		Build()
	resp, err := c.HcClient.Sync(&csms.ShowSecretRequest{SecretName: secretName}, reqDef)
	if err != nil {
		t.Fatalf("ShowSecret(%s) wire check: %v", secretName, err)
	}
	return resp.(*showSecretWireResponse).Secret.LastUsedTime
}

// TestCSMSSecretsVersionsAndStages exercises secret CRUD, pagination, KMS key
// integration (both csms/default and explicit KMS keys, including CSMS.0401 on
// disabled keys), secret versions (string and binary values, custom stages,
// expiration updates, latest alias, last_used_time), and stage lifecycle
// (SYSCURRENT/SYSPREVIOUS transitions, custom stage moves, CSMS.0105) through
// the official csms/v1 client.
func TestCSMSSecretsVersionsAndStages(t *testing.T) {
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	ak := signingAK("AKCSMSCRUD0000000000")
	sk := signingSK()
	c := csmsAs(t, ak, sk)
	kmsClient := kmsAs(t, ak, sk)

	cleanupSecret := func(name string) {
		t.Cleanup(func() {
			_, _ = c.DeleteSecret(&csms.DeleteSecretRequest{SecretName: name})
		})
	}

	makeKMSKey := func(label string) string {
		t.Helper()
		km, err := kmsClient.CreateKey(&kms.CreateKeyRequest{Body: &kms.CreateKeyRequestBody{
			KeyAlias: "sdk-csms-" + label + "-" + suffix,
		}})
		if err != nil {
			t.Fatalf("CreateKey(%s): %v", label, err)
		}
		keyID := *km.KeyInfo.KeyId
		t.Cleanup(func() {
			_, _ = kmsClient.EnableKey(&kms.EnableKeyRequest{Body: &kms.OperateKeyRequestBody{KeyId: keyID}})
			_, _ = kmsClient.DeleteKey(&kms.DeleteKeyRequest{Body: &kms.ScheduleKeyDeletionRequestBody{
				KeyId: keyID, PendingDays: "7",
			}})
		})
		return keyID
	}

	kmsKey1 := makeKMSKey("k1")
	kmsKey2 := makeKMSKey("k2")

	// 1. CreateSecret with default csms/default KMS key and SecretString.
	defName := "sdk-csms-def-" + suffix
	cleanupSecret(defName)
	defVal := "default-key-initial-value-" + suffix
	defCreated, err := c.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
		Name:         defName,
		SecretString: ptr(defVal),
		Description:  ptr("uses csms/default"),
	}})
	if err != nil || defCreated.Secret == nil {
		t.Fatalf("CreateSecret(default): %+v, %v", defCreated, err)
	}
	if defCreated.Secret.Id == nil || *defCreated.Secret.Id == "" ||
		defCreated.Secret.Name == nil || *defCreated.Secret.Name != defName ||
		defCreated.Secret.State == nil || *defCreated.Secret.State != "ENABLED" ||
		defCreated.Secret.KmsKeyId == nil || *defCreated.Secret.KmsKeyId == "" ||
		defCreated.Secret.SecretType == nil || defCreated.Secret.SecretType.Value() != "COMMON" ||
		defCreated.Secret.EnterpriseProjectId == nil || *defCreated.Secret.EnterpriseProjectId != "0" ||
		defCreated.Secret.AutoRotation == nil || *defCreated.Secret.AutoRotation ||
		defCreated.Secret.ScheduledDeleteTime != nil {
		t.Fatalf("CreateSecret(default) secret = %+v", defCreated.Secret)
	}
	defaultKMSKeyID := *defCreated.Secret.KmsKeyId
	defKeyDetail, err := kmsClient.ListKeyDetail(&kms.ListKeyDetailRequest{Body: &kms.OperateKeyRequestBody{KeyId: defaultKMSKeyID}})
	if err != nil || defKeyDetail.KeyInfo == nil || defKeyDetail.KeyInfo.KeyAlias == nil || *defKeyDetail.KeyInfo.KeyAlias != "csms/default" {
		t.Fatalf("ListKeyDetail(csms/default %s) = %+v, %v", defaultKMSKeyID, defKeyDetail, err)
	}

	// Duplicate secret name -> 409 CSMS.0101.
	_, err = c.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
		Name:         defName,
		SecretString: ptr("duplicate"),
	}})
	wantError(t, err, 409, "CSMS.0101")

	// Unknown KMS key ID -> 400 CSMS.0002.
	_, err = c.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
		Name:         "sdk-csms-badkey-" + suffix,
		KmsKeyId:     ptr("00000000-0000-0000-0000-000000000099"),
		SecretString: ptr("bad-key"),
	}})
	wantError(t, err, 400, "CSMS.0002")

	// Missing secret -> 404 CSMS.0005.
	_, err = c.ShowSecret(&csms.ShowSecretRequest{SecretName: "no-such-secret-" + suffix})
	wantError(t, err, 404, "CSMS.0005")

	// 2. CreateSecret with explicit KMS key and SecretBinary.
	kmsName := "sdk-csms-kms-" + suffix
	cleanupSecret(kmsName)
	v1Raw := []byte{0x00, 0xde, 0xad, 0xbe, 0xef, 0xff, 0x42}
	v1B64 := base64.StdEncoding.EncodeToString(v1Raw)
	secTypeCommon := csms.GetCreateSecretRequestBodySecretTypeEnum().COMMON
	kmsCreated, err := c.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
		Name:         kmsName,
		KmsKeyId:     ptr(kmsKey1),
		Description:  ptr("initial kms description"),
		SecretBinary: ptr(v1B64),
		SecretType:   &secTypeCommon,
	}})
	if err != nil || kmsCreated.Secret == nil {
		t.Fatalf("CreateSecret(kms): %+v, %v", kmsCreated, err)
	}
	if kmsCreated.Secret.KmsKeyId == nil || *kmsCreated.Secret.KmsKeyId != kmsKey1 ||
		kmsCreated.Secret.Description == nil || *kmsCreated.Secret.Description != "initial kms description" {
		t.Fatalf("CreateSecret(kms) = %+v", kmsCreated.Secret)
	}

	// Create a third secret so pagination exercises multiple pages, then delete it.
	extraName := "sdk-csms-extra-" + suffix
	cleanupSecret(extraName)
	if _, err := c.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
		Name:         extraName,
		SecretString: ptr("ephemeral-secret"),
	}}); err != nil {
		t.Fatalf("CreateSecret(extra): %v", err)
	}

	// 3. ListSecrets in the shared project, plus Limit & Marker pagination in
	// an isolated account project so concurrent tests deleting secrets cannot
	// remove NextMarker mid-walk.
	allShared, err := c.ListSecrets(&csms.ListSecretsRequest{})
	if err != nil || allShared.Secrets == nil {
		t.Fatalf("ListSecrets(shared): %+v, %v", allShared, err)
	}
	sharedFound := make(map[string]bool, len(*allShared.Secrets))
	for _, sec := range *allShared.Secrets {
		if sec.Name != nil {
			sharedFound[*sec.Name] = true
		}
	}
	for _, name := range []string{defName, kmsName, extraName} {
		if !sharedFound[name] {
			t.Fatalf("ListSecrets(shared) missing %q", name)
		}
	}

	pageAcct := addAccount(t, "sdk-csms-page-"+suffix)
	pageCSMS := csmsIn(t, pageAcct.AK, pageAcct.SK, pageAcct.ProjectID)
	wantNames := []string{
		"sdk-csms-p1-" + suffix,
		"sdk-csms-p2-" + suffix,
		"sdk-csms-p3-" + suffix,
	}
	for _, name := range wantNames {
		t.Cleanup(func() {
			_, _ = pageCSMS.DeleteSecret(&csms.DeleteSecretRequest{SecretName: name})
		})
		if _, err := pageCSMS.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
			Name:         name,
			SecretString: ptr("page-secret-" + name),
		}}); err != nil {
			t.Fatalf("CreateSecret(%s): %v", name, err)
		}
	}
	seenOrder := make([]string, 0, len(wantNames))
	pageSize := 2
	maxPages := 100
	var marker *string
	pages := 0
	for {
		pages++
		if pages > maxPages {
			t.Fatal("ListSecrets pagination did not terminate")
		}
		res, err := pageCSMS.ListSecrets(&csms.ListSecretsRequest{
			Limit:  ptr(strconv.Itoa(pageSize)),
			Marker: marker,
		})
		if err != nil || res.Secrets == nil || res.PageInfo == nil || res.PageInfo.CurrentCount == nil {
			t.Fatalf("ListSecrets(page %d): %+v, %v", pages, res, err)
		}
		if int(*res.PageInfo.CurrentCount) != len(*res.Secrets) || len(*res.Secrets) > pageSize {
			t.Fatalf("ListSecrets(page %d) count=%d len=%d", pages, *res.PageInfo.CurrentCount, len(*res.Secrets))
		}
		for _, sec := range *res.Secrets {
			if sec.Name != nil {
				seenOrder = append(seenOrder, *sec.Name)
			}
		}
		if res.PageInfo.NextMarker == nil || *res.PageInfo.NextMarker == "" {
			break
		}
		marker = res.PageInfo.NextMarker
	}
	if pages != 2 {
		t.Errorf("expected 2 pages with limit=%d and 3 secrets, got %d", pageSize, pages)
	}
	if !slices.Equal(seenOrder, wantNames) {
		t.Fatalf("paginated ListSecrets order = %v, want %v", seenOrder, wantNames)
	}

	// 4. ShowSecret & UpdateSecret (Description, KmsKeyId, EventSubscriptions) & DeleteSecret.
	shown, err := c.ShowSecret(&csms.ShowSecretRequest{SecretName: kmsName})
	if err != nil || shown.Secret == nil || shown.Secret.Name == nil || *shown.Secret.Name != kmsName {
		t.Fatalf("ShowSecret(%s): %+v, %v", kmsName, shown, err)
	}
	if beforeRead := showSecretLastUsedTime(t, c, kmsName); beforeRead != nil {
		t.Fatalf("expected nil last_used_time before reading secret value, got %d", *beforeRead)
	}

	eventSub := "sdk-evt-" + suffix
	updated, err := c.UpdateSecret(&csms.UpdateSecretRequest{
		SecretName: kmsName,
		Body: &csms.UpdateSecretRequestBody{
			Description:        ptr("updated kms description"),
			KmsKeyId:           ptr(kmsKey2),
			EventSubscriptions: &[]string{eventSub},
		},
	})
	if err != nil || updated.Secret == nil {
		t.Fatalf("UpdateSecret: %+v, %v", updated, err)
	}
	if updated.Secret.Description == nil || *updated.Secret.Description != "updated kms description" ||
		updated.Secret.KmsKeyId == nil || *updated.Secret.KmsKeyId != kmsKey2 ||
		updated.Secret.EventSubscriptions == nil || !slices.Equal(*updated.Secret.EventSubscriptions, []string{eventSub}) {
		t.Fatalf("UpdateSecret = %+v", updated.Secret)
	}

	delResp, err := c.DeleteSecret(&csms.DeleteSecretRequest{SecretName: extraName})
	if err != nil {
		t.Fatalf("DeleteSecret(%s): %v", extraName, err)
	}
	if delResp.HttpStatusCode != http.StatusNoContent {
		t.Errorf("DeleteSecret status = %d, want 204", delResp.HttpStatusCode)
	}
	_, err = c.ShowSecret(&csms.ShowSecretRequest{SecretName: extraName})
	wantError(t, err, 404, "CSMS.0005")

	// 5. Versions & Stages on kmsName:
	// v1 was created under kmsKey1 with SecretBinary and holds SYSCURRENT.
	// Create v2 with SecretString (default stage -> v2 gets SYSCURRENT, v1 moves to SYSPREVIOUS; encrypted under kmsKey2).
	v2Val := "v2-string-payload-" + suffix
	v2Created, err := c.CreateSecretVersion(&csms.CreateSecretVersionRequest{
		SecretName: kmsName,
		Body: &csms.CreateSecretVersionRequestBody{
			SecretString: ptr(v2Val),
		},
	})
	if err != nil || v2Created.VersionMetadata == nil || v2Created.VersionMetadata.Id == nil || *v2Created.VersionMetadata.Id != "v2" {
		t.Fatalf("CreateSecretVersion(v2): %+v, %v", v2Created, err)
	}
	if v2Created.VersionMetadata.KmsKeyId == nil || *v2Created.VersionMetadata.KmsKeyId != kmsKey2 ||
		v2Created.VersionMetadata.VersionStages == nil || !slices.Equal(*v2Created.VersionMetadata.VersionStages, []string{"SYSCURRENT"}) {
		t.Fatalf("CreateSecretVersion(v2) metadata = %+v", v2Created.VersionMetadata)
	}

	// Create v3 with SecretBinary, custom VersionStages, and ExpireTime (does not move SYSCURRENT).
	v3Raw := []byte("v3-binary-payload-" + suffix)
	v3B64 := base64.StdEncoding.EncodeToString(v3Raw)
	v3Expire := time.Now().Add(48 * time.Hour).UnixMilli()
	v3Created, err := c.CreateSecretVersion(&csms.CreateSecretVersionRequest{
		SecretName: kmsName,
		Body: &csms.CreateSecretVersionRequestBody{
			SecretBinary:  ptr(v3B64),
			VersionStages: &[]string{"canary", "blue"},
			ExpireTime:    ptr(v3Expire),
		},
	})
	if err != nil || v3Created.VersionMetadata == nil || v3Created.VersionMetadata.Id == nil || *v3Created.VersionMetadata.Id != "v3" {
		t.Fatalf("CreateSecretVersion(v3): %+v, %v", v3Created, err)
	}
	if v3Created.VersionMetadata.ExpireTime == nil || *v3Created.VersionMetadata.ExpireTime != v3Expire ||
		v3Created.VersionMetadata.VersionStages == nil || !slices.Equal(*v3Created.VersionMetadata.VersionStages, []string{"blue", "canary"}) {
		t.Fatalf("CreateSecretVersion(v3) metadata = %+v", v3Created.VersionMetadata)
	}

	// Create v4 with SecretString (default stage -> v4 gets SYSCURRENT, v2 moves to SYSPREVIOUS, v1 loses SYSPREVIOUS).
	v4Val := "v4-latest-payload-" + suffix
	v4Created, err := c.CreateSecretVersion(&csms.CreateSecretVersionRequest{
		SecretName: kmsName,
		Body: &csms.CreateSecretVersionRequestBody{
			SecretString: ptr(v4Val),
		},
	})
	if err != nil || v4Created.VersionMetadata == nil || v4Created.VersionMetadata.Id == nil || *v4Created.VersionMetadata.Id != "v4" {
		t.Fatalf("CreateSecretVersion(v4): %+v, %v", v4Created, err)
	}

	// ListSecretVersions (with pagination Limit & Marker).
	verPageSize := int32(2)
	var verMarker *string
	gotVersions := make(map[string]csms.VersionMetadata)
	for range 10 {
		vres, err := c.ListSecretVersions(&csms.ListSecretVersionsRequest{
			SecretName: kmsName,
			Limit:      ptr(verPageSize),
			Marker:     verMarker,
		})
		if err != nil || vres.VersionMetadatas == nil || vres.PageInfo == nil {
			t.Fatalf("ListSecretVersions: %+v, %v", vres, err)
		}
		for _, vm := range *vres.VersionMetadatas {
			if vm.Id != nil {
				gotVersions[*vm.Id] = vm
			}
		}
		if vres.PageInfo.NextMarker == nil || *vres.PageInfo.NextMarker == "" {
			break
		}
		verMarker = vres.PageInfo.NextMarker
	}
	if len(gotVersions) != 4 {
		t.Fatalf("ListSecretVersions count = %d, want 4: %+v", len(gotVersions), gotVersions)
	}
	if len(*gotVersions["v1"].VersionStages) != 0 ||
		!slices.Equal(*gotVersions["v2"].VersionStages, []string{"SYSPREVIOUS"}) ||
		!slices.Equal(*gotVersions["v3"].VersionStages, []string{"blue", "canary"}) ||
		!slices.Equal(*gotVersions["v4"].VersionStages, []string{"SYSCURRENT"}) {
		t.Fatalf("unexpected version stages: v1=%v v2=%v v3=%v v4=%v",
			gotVersions["v1"].VersionStages, gotVersions["v2"].VersionStages,
			gotVersions["v3"].VersionStages, gotVersions["v4"].VersionStages)
	}

	// ShowSecretVersion for v1 (binary), v2 (string), and latest (v4), plus LastUsedTime check.
	sv1, err := c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: kmsName, VersionId: "v1"})
	if err != nil || sv1.Version == nil || sv1.Version.SecretBinary == nil || sv1.Version.SecretString != nil {
		t.Fatalf("ShowSecretVersion(v1): %+v, %v", sv1, err)
	}
	gotV1Bytes, err := base64.StdEncoding.DecodeString(*sv1.Version.SecretBinary)
	if err != nil || !bytes.Equal(gotV1Bytes, v1Raw) {
		t.Fatalf("ShowSecretVersion(v1) binary = %x (err=%v), want %x", gotV1Bytes, err, v1Raw)
	}

	afterRead := showSecretLastUsedTime(t, c, kmsName)
	if afterRead == nil || *afterRead <= 0 {
		t.Fatalf("expected positive last_used_time after ShowSecretVersion, got %v", afterRead)
	}

	sv2, err := c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: kmsName, VersionId: "v2"})
	if err != nil || sv2.Version == nil || sv2.Version.SecretString == nil || *sv2.Version.SecretString != v2Val || sv2.Version.SecretBinary != nil {
		t.Fatalf("ShowSecretVersion(v2): %+v, %v", sv2, err)
	}

	svLatest, err := c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: kmsName, VersionId: "latest"})
	if err != nil || svLatest.Version == nil || svLatest.Version.VersionMetadata == nil ||
		svLatest.Version.VersionMetadata.Id == nil || *svLatest.Version.VersionMetadata.Id != "v4" ||
		svLatest.Version.SecretString == nil || *svLatest.Version.SecretString != v4Val {
		t.Fatalf("ShowSecretVersion(latest): %+v, %v", svLatest, err)
	}

	// Also verify default-key secret round-trips through ShowSecretVersion.
	svDef, err := c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: defName, VersionId: "v1"})
	if err != nil || svDef.Version == nil || svDef.Version.SecretString == nil || *svDef.Version.SecretString != defVal {
		t.Fatalf("ShowSecretVersion(default v1): %+v, %v", svDef, err)
	}

	// UpdateVersion updates ExpireTime.
	updatedExpire := time.Now().Add(72 * time.Hour).UnixMilli()
	uvResp, err := c.UpdateVersion(&csms.UpdateVersionRequest{
		SecretName: kmsName,
		VersionId:  "v2",
		Body:       &csms.UpdateVersionRequestBody{ExpireTime: updatedExpire},
	})
	if err != nil || uvResp.VersionMetadata == nil || uvResp.VersionMetadata.ExpireTime == nil || *uvResp.VersionMetadata.ExpireTime != updatedExpire {
		t.Fatalf("UpdateVersion(v2): %+v, %v", uvResp, err)
	}

	// ShowSecretStage, UpdateSecretStage, and DeleteSecretStage.
	stCur, err := c.ShowSecretStage(&csms.ShowSecretStageRequest{SecretName: kmsName, StageName: "SYSCURRENT"})
	if err != nil || stCur.Stage == nil || stCur.Stage.VersionId == nil || *stCur.Stage.VersionId != "v4" {
		t.Fatalf("ShowSecretStage(SYSCURRENT): %+v, %v", stCur, err)
	}
	stCanary, err := c.ShowSecretStage(&csms.ShowSecretStageRequest{SecretName: kmsName, StageName: "canary"})
	if err != nil || stCanary.Stage == nil || stCanary.Stage.VersionId == nil || *stCanary.Stage.VersionId != "v3" {
		t.Fatalf("ShowSecretStage(canary): %+v, %v", stCanary, err)
	}

	// Move custom stage "canary" from v3 to v1.
	movedCanary, err := c.UpdateSecretStage(&csms.UpdateSecretStageRequest{
		SecretName: kmsName,
		StageName:  "canary",
		Body:       &csms.UpdateSecretStageRequestBody{VersionId: "v1"},
	})
	if err != nil || movedCanary.Stage == nil || movedCanary.Stage.VersionId == nil || *movedCanary.Stage.VersionId != "v1" {
		t.Fatalf("UpdateSecretStage(canary -> v1): %+v, %v", movedCanary, err)
	}

	// Move SYSCURRENT from v4 to v1 -> SYSPREVIOUS transitions to v4.
	movedCur, err := c.UpdateSecretStage(&csms.UpdateSecretStageRequest{
		SecretName: kmsName,
		StageName:  "SYSCURRENT",
		Body:       &csms.UpdateSecretStageRequestBody{VersionId: "v1"},
	})
	if err != nil || movedCur.Stage == nil || movedCur.Stage.VersionId == nil || *movedCur.Stage.VersionId != "v1" {
		t.Fatalf("UpdateSecretStage(SYSCURRENT -> v1): %+v, %v", movedCur, err)
	}
	stPrev, err := c.ShowSecretStage(&csms.ShowSecretStageRequest{SecretName: kmsName, StageName: "SYSPREVIOUS"})
	if err != nil || stPrev.Stage == nil || stPrev.Stage.VersionId == nil || *stPrev.Stage.VersionId != "v4" {
		t.Fatalf("ShowSecretStage(SYSPREVIOUS after SYSCURRENT move): %+v, %v", stPrev, err)
	}

	// Deleting SYSCURRENT or SYSPREVIOUS -> 400 CSMS.0105.
	_, err = c.DeleteSecretStage(&csms.DeleteSecretStageRequest{SecretName: kmsName, StageName: "SYSCURRENT"})
	wantError(t, err, 400, "CSMS.0105")
	_, err = c.DeleteSecretStage(&csms.DeleteSecretStageRequest{SecretName: kmsName, StageName: "SYSPREVIOUS"})
	wantError(t, err, 400, "CSMS.0105")

	// Deleting custom stage "canary" -> 204, then 404 CSMS.0005.
	delStageResp, err := c.DeleteSecretStage(&csms.DeleteSecretStageRequest{SecretName: kmsName, StageName: "canary"})
	if err != nil {
		t.Fatalf("DeleteSecretStage(canary): %v", err)
	}
	if delStageResp.HttpStatusCode != http.StatusNoContent {
		t.Errorf("DeleteSecretStage status = %d, want 204", delStageResp.HttpStatusCode)
	}
	_, err = c.ShowSecretStage(&csms.ShowSecretStageRequest{SecretName: kmsName, StageName: "canary"})
	wantError(t, err, 404, "CSMS.0005")

	// 6. Disabling kmsKey1 makes ShowSecretVersion(v1) fail with 400 CSMS.0401;
	// v2 (encrypted under kmsKey2) remains readable; re-enabling kmsKey1 restores v1.
	if _, err := kmsClient.DisableKey(&kms.DisableKeyRequest{Body: &kms.OperateKeyRequestBody{KeyId: kmsKey1}}); err != nil {
		t.Fatalf("DisableKey(kmsKey1): %v", err)
	}
	_, err = c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: kmsName, VersionId: "v1"})
	wantError(t, err, 400, "CSMS.0401")

	if _, err := c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: kmsName, VersionId: "v2"}); err != nil {
		t.Fatalf("ShowSecretVersion(v2 under enabled kmsKey2) failed while kmsKey1 disabled: %v", err)
	}

	if _, err := kmsClient.EnableKey(&kms.EnableKeyRequest{Body: &kms.OperateKeyRequestBody{KeyId: kmsKey1}}); err != nil {
		t.Fatalf("EnableKey(kmsKey1): %v", err)
	}
	sv1After, err := c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: kmsName, VersionId: "v1"})
	if err != nil || sv1After.Version == nil || sv1After.Version.SecretBinary == nil || *sv1After.Version.SecretBinary != v1B64 {
		t.Fatalf("ShowSecretVersion(v1 after EnableKey): %+v, %v", sv1After, err)
	}
}

// TestCSMSScheduleBackupAndPassword exercises scheduled deletion and restore,
// secret backup/restore blobs (including prefix, no-plaintext, duplicate, and
// cross-account checks), and random password generation.
func TestCSMSScheduleBackupAndPassword(t *testing.T) {
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	c := csmsAs(t, signingAK("AKCSMSSCHED000000000"), signingSK())

	secName := "sdk-csms-sched-" + suffix
	t.Cleanup(func() {
		_, _ = c.DeleteSecret(&csms.DeleteSecretRequest{SecretName: secName})
	})

	v1Plain := "super-sensitive-v1-value-" + suffix
	v2PlainRaw := []byte("super-sensitive-v2-binary-" + suffix)
	v2PlainB64 := base64.StdEncoding.EncodeToString(v2PlainRaw)

	if _, err := c.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
		Name:         secName,
		Description:  ptr("backup and schedule test"),
		SecretString: ptr(v1Plain),
	}}); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if _, err := c.UpdateSecretStage(&csms.UpdateSecretStageRequest{
		SecretName: secName,
		StageName:  "release",
		Body:       &csms.UpdateSecretStageRequestBody{VersionId: "v1"},
	}); err != nil {
		t.Fatalf("UpdateSecretStage(release): %v", err)
	}
	if _, err := c.CreateSecretVersion(&csms.CreateSecretVersionRequest{
		SecretName: secName,
		Body: &csms.CreateSecretVersionRequestBody{
			SecretBinary: ptr(v2PlainB64),
		},
	}); err != nil {
		t.Fatalf("CreateSecretVersion(v2): %v", err)
	}

	// 1. RestoreSecret while ENABLED -> 400 CSMS.0108.
	_, err := c.RestoreSecret(&csms.RestoreSecretRequest{SecretName: secName})
	wantError(t, err, 400, "CSMS.0108")

	// 2. DeleteSecretForSchedule sets PENDING_DELETE and ScheduledDeleteTime.
	recoveryDays := int32(7)
	schedResp, err := c.DeleteSecretForSchedule(&csms.DeleteSecretForScheduleRequest{
		SecretName: secName,
		Body:       &csms.DeleteSecretForScheduleRequestBody{RecoveryWindowInDays: recoveryDays},
	})
	if err != nil || schedResp.Secret == nil {
		t.Fatalf("DeleteSecretForSchedule: %+v, %v", schedResp, err)
	}
	if schedResp.Secret.State == nil || *schedResp.Secret.State != "PENDING_DELETE" ||
		schedResp.Secret.ScheduledDeleteTime == nil || *schedResp.Secret.ScheduledDeleteTime <= 0 {
		t.Fatalf("DeleteSecretForSchedule secret = %+v", schedResp.Secret)
	}

	// While PENDING_DELETE:
	// - ShowSecretVersion -> 403 CSMS.0109
	// - UpdateSecret -> 400 CSMS.0103
	// - CreateSecretVersion -> 400 CSMS.0103
	// - DeleteSecretForSchedule again -> 400 CSMS.0107
	_, err = c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: secName, VersionId: "latest"})
	wantError(t, err, 403, "CSMS.0109")

	_, err = c.UpdateSecret(&csms.UpdateSecretRequest{
		SecretName: secName,
		Body:       &csms.UpdateSecretRequestBody{Description: ptr("denied while pending delete")},
	})
	wantError(t, err, 400, "CSMS.0103")

	_, err = c.CreateSecretVersion(&csms.CreateSecretVersionRequest{
		SecretName: secName,
		Body:       &csms.CreateSecretVersionRequestBody{SecretString: ptr("denied")},
	})
	wantError(t, err, 400, "CSMS.0103")

	_, err = c.DeleteSecretForSchedule(&csms.DeleteSecretForScheduleRequest{
		SecretName: secName,
		Body:       &csms.DeleteSecretForScheduleRequestBody{RecoveryWindowInDays: recoveryDays},
	})
	wantError(t, err, 400, "CSMS.0107")

	// 3. RestoreSecret returns secret to ENABLED and clears ScheduledDeleteTime.
	restoredSched, err := c.RestoreSecret(&csms.RestoreSecretRequest{SecretName: secName})
	if err != nil || restoredSched.Secret == nil {
		t.Fatalf("RestoreSecret: %+v, %v", restoredSched, err)
	}
	if restoredSched.Secret.State == nil || *restoredSched.Secret.State != "ENABLED" ||
		restoredSched.Secret.ScheduledDeleteTime != nil {
		t.Fatalf("RestoreSecret secret = %+v", restoredSched.Secret)
	}

	// 4. DownloadSecretBlob -> check prefix and absence of plaintext -> DeleteSecret -> UploadSecretBlob.
	blobResp, err := c.DownloadSecretBlob(&csms.DownloadSecretBlobRequest{SecretName: secName})
	if err != nil || blobResp.SecretBlob == nil || *blobResp.SecretBlob == "" {
		t.Fatalf("DownloadSecretBlob: %+v, %v", blobResp, err)
	}
	blob := *blobResp.SecretBlob
	const wantPrefix = ")CloudSecretManagementBackupV1.com"
	if !strings.HasPrefix(blob, wantPrefix) {
		t.Fatalf("SecretBlob missing %q prefix: %q", wantPrefix, blob[:min(len(blob), len(wantPrefix))])
	}
	for _, needle := range []string{v1Plain, string(v2PlainRaw), v2PlainB64} {
		if strings.Contains(blob, needle) {
			t.Fatalf("SecretBlob leaked plaintext material")
		}
	}

	// Restoring while name still exists -> 409 CSMS.0101.
	_, err = c.UploadSecretBlob(&csms.UploadSecretBlobRequest{
		Body: &csms.UploadSecretBlobRequestBody{SecretBlob: blob},
	})
	wantError(t, err, 409, "CSMS.0101")

	// Restoring in another account -> 400 CSMS.0002.
	partner := addAccount(t, "sdk-csms-partner-"+suffix)
	partnerCSMS := csmsIn(t, partner.AK, partner.SK, partner.ProjectID)
	_, err = partnerCSMS.UploadSecretBlob(&csms.UploadSecretBlobRequest{
		Body: &csms.UploadSecretBlobRequestBody{SecretBlob: blob},
	})
	wantError(t, err, 400, "CSMS.0002")

	// Delete the original secret, then restore via UploadSecretBlob.
	if _, err := c.DeleteSecret(&csms.DeleteSecretRequest{SecretName: secName}); err != nil {
		t.Fatalf("DeleteSecret(%s): %v", secName, err)
	}
	_, err = c.ShowSecret(&csms.ShowSecretRequest{SecretName: secName})
	wantError(t, err, 404, "CSMS.0005")

	upResp, err := c.UploadSecretBlob(&csms.UploadSecretBlobRequest{
		Body: &csms.UploadSecretBlobRequestBody{SecretBlob: blob},
	})
	if err != nil || upResp.Secret == nil {
		t.Fatalf("UploadSecretBlob: %+v, %v", upResp, err)
	}
	if upResp.Secret.Name == nil || *upResp.Secret.Name != secName ||
		upResp.Secret.State == nil || *upResp.Secret.State != "ENABLED" ||
		upResp.Secret.Description == nil || *upResp.Secret.Description != "backup and schedule test" {
		t.Fatalf("UploadSecretBlob secret = %+v", upResp.Secret)
	}

	// Verify restored versions, stages, and decrypted values.
	gotV1, err := c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: secName, VersionId: "v1"})
	if err != nil || gotV1.Version == nil || gotV1.Version.SecretString == nil || *gotV1.Version.SecretString != v1Plain {
		t.Fatalf("ShowSecretVersion(restored v1): %+v, %v", gotV1, err)
	}
	gotV2, err := c.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: secName, VersionId: "v2"})
	if err != nil || gotV2.Version == nil || gotV2.Version.SecretBinary == nil || *gotV2.Version.SecretBinary != v2PlainB64 {
		t.Fatalf("ShowSecretVersion(restored v2): %+v, %v", gotV2, err)
	}
	relStage, err := c.ShowSecretStage(&csms.ShowSecretStageRequest{SecretName: secName, StageName: "release"})
	if err != nil || relStage.Stage == nil || relStage.Stage.VersionId == nil || *relStage.Stage.VersionId != "v1" {
		t.Fatalf("ShowSecretStage(restored release): %+v, %v", relStage, err)
	}

	// 5. GenerateRandomPassword (default + custom length/exclusions + invalid exclusion).
	defaultPasswordLen := 32
	pwDef, err := c.GenerateRandomPassword(&csms.GenerateRandomPasswordRequest{
		Body: &csms.CreatePasswordRequestBody{},
	})
	if err != nil || pwDef.Password == nil || len(*pwDef.Password) != defaultPasswordLen {
		t.Fatalf("GenerateRandomPassword(default): err=%v len=%d", err, len(derefStr(pwDef.Password)))
	}

	customLen := int32(24)
	excludedChars := "012345aeiou"
	pwCustom, err := c.GenerateRandomPassword(&csms.GenerateRandomPasswordRequest{
		Body: &csms.CreatePasswordRequestBody{
			Length:             ptr(customLen),
			ExcludeUppercase:   ptr(true),
			ExcludePunctuation: ptr(true),
			ExcludeCharacters:  ptr(excludedChars),
		},
	})
	if err != nil || pwCustom.Password == nil {
		t.Fatalf("GenerateRandomPassword(custom): %v", err)
	}
	pw := *pwCustom.Password
	if len(pw) != int(customLen) {
		t.Fatalf("GenerateRandomPassword(custom) length = %d, want %d", len(pw), customLen)
	}
	hasLower, hasDigit := false, false
	for i := range len(pw) {
		ch := pw[i]
		if ch >= 'A' && ch <= 'Z' {
			t.Fatalf("custom password unexpectedly contained uppercase character")
		}
		if strings.IndexByte(excludedChars, ch) >= 0 {
			t.Fatalf("custom password unexpectedly contained excluded character")
		}
		switch {
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '6' && ch <= '9':
			hasDigit = true
		default:
			t.Fatalf("custom password contained unexpected character class")
		}
	}
	if !hasLower || !hasDigit {
		t.Fatalf("custom password missing active character class: hasLower=%v hasDigit=%v", hasLower, hasDigit)
	}

	// Excluding every class -> 400 CSMS.0002.
	_, err = c.GenerateRandomPassword(&csms.GenerateRandomPasswordRequest{
		Body: &csms.CreatePasswordRequestBody{
			ExcludeLowercase:   ptr(true),
			ExcludeUppercase:   ptr(true),
			ExcludeNumbers:     ptr(true),
			ExcludePunctuation: ptr(true),
		},
	})
	wantError(t, err, 400, "CSMS.0002")
}

// TestCSMSTags exercises all six CSMS tag operations: CreateSecretTag,
// ListSecretTags, BatchCreateOrDeleteTags (create and delete), DeleteSecretTag,
// ListProjectSecretsTags, and ListResourceInstances (filter and count).
func TestCSMSTags(t *testing.T) {
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	c := csmsAs(t, signingAK("AKCSMSTAGS0000000000"), signingSK())

	makeSecret := func(label string) (name, id string) {
		t.Helper()
		name = "sdk-csms-tag-" + label + "-" + suffix
		t.Cleanup(func() {
			_, _ = c.DeleteSecret(&csms.DeleteSecretRequest{SecretName: name})
		})
		res, err := c.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
			Name:         name,
			SecretString: ptr("tag-secret-" + label),
		}})
		if err != nil || res.Secret == nil || res.Secret.Id == nil {
			t.Fatalf("CreateSecret(%s): %+v, %v", name, res, err)
		}
		return name, *res.Secret.Id
	}

	nameA, idA := makeSecret("a")
	nameB, idB := makeSecret("b")

	tagKeyEnv := "env-" + suffix
	tagKeyTeam := "team-" + suffix
	tagKeyTier := "tier-" + suffix

	// 1. CreateSecretTag.
	ctResp, err := c.CreateSecretTag(&csms.CreateSecretTagRequest{
		SecretId: idA,
		Body: &csms.CreateSecretTagRequestBody{
			Tag: &csms.TagItem{Key: tagKeyEnv, Value: ptr("prod")},
		},
	})
	if err != nil {
		t.Fatalf("CreateSecretTag(A): %v", err)
	}
	if ctResp.HttpStatusCode != http.StatusNoContent {
		t.Errorf("CreateSecretTag status = %d, want 204", ctResp.HttpStatusCode)
	}
	if _, err := c.CreateSecretTag(&csms.CreateSecretTagRequest{
		SecretId: idB,
		Body: &csms.CreateSecretTagRequestBody{
			Tag: &csms.TagItem{Key: tagKeyEnv, Value: ptr("staging")},
		},
	}); err != nil {
		t.Fatalf("CreateSecretTag(B): %v", err)
	}

	// 2. ListSecretTags.
	tagsA, err := c.ListSecretTags(&csms.ListSecretTagsRequest{SecretId: idA})
	if err != nil || tagsA.Tags == nil || len(*tagsA.Tags) != 1 ||
		(*tagsA.Tags)[0].Key != tagKeyEnv || derefStr((*tagsA.Tags)[0].Value) != "prod" {
		t.Fatalf("ListSecretTags(A): %+v, %v", tagsA, err)
	}

	// 3. BatchCreateOrDeleteTags (create).
	batchAdd, err := c.BatchCreateOrDeleteTags(&csms.BatchCreateOrDeleteTagsRequest{
		SecretId: idA,
		Body: &csms.BatchCreateOrDeleteTagsRequestBody{
			Action: "create",
			Tags: []csms.TagItem{
				{Key: tagKeyTeam, Value: ptr("platform")},
				{Key: tagKeyTier, Value: ptr("core")},
			},
		},
	})
	if err != nil {
		t.Fatalf("BatchCreateOrDeleteTags(create A): %v", err)
	}
	if batchAdd.HttpStatusCode != http.StatusNoContent {
		t.Errorf("BatchCreateOrDeleteTags(create) status = %d, want 204", batchAdd.HttpStatusCode)
	}
	if _, err := c.BatchCreateOrDeleteTags(&csms.BatchCreateOrDeleteTagsRequest{
		SecretId: idB,
		Body: &csms.BatchCreateOrDeleteTagsRequestBody{
			Action: "create",
			Tags: []csms.TagItem{
				{Key: tagKeyTeam, Value: ptr("platform")},
			},
		},
	}); err != nil {
		t.Fatalf("BatchCreateOrDeleteTags(create B): %v", err)
	}

	// 4. ListProjectSecretsTags.
	projTags, err := c.ListProjectSecretsTags(&csms.ListProjectSecretsTagsRequest{})
	if err != nil || projTags.Tags == nil {
		t.Fatalf("ListProjectSecretsTags: %+v, %v", projTags, err)
	}
	gotProj := make(map[string][]string)
	for _, tr := range *projTags.Tags {
		if tr.Key != nil && tr.Values != nil {
			gotProj[*tr.Key] = *tr.Values
		}
	}
	if !slices.Contains(gotProj[tagKeyEnv], "prod") || !slices.Contains(gotProj[tagKeyEnv], "staging") ||
		!slices.Equal(gotProj[tagKeyTeam], []string{"platform"}) ||
		!slices.Equal(gotProj[tagKeyTier], []string{"core"}) {
		t.Fatalf("ListProjectSecretsTags missing expected tags: %+v", gotProj)
	}

	// 5. ListResourceInstances (filter with tags + matches, and count).
	filterLimit := 10
	filteredBoth, err := c.ListResourceInstances(&csms.ListResourceInstancesRequest{
		ResourceInstances: "resource_instances",
		Body: &csms.ListResourceInstancesRequestBody{
			Action: "filter",
			Limit:  ptr(strconv.Itoa(filterLimit)),
			Offset: ptr("0"),
			Tags: &[]csms.Tag{
				{Key: ptr(tagKeyTeam), Values: &[]string{"platform"}},
			},
			Matches: &[]csms.TagMatches{
				{Key: ptr("resource_name"), Value: ptr(suffix)},
			},
		},
	})
	if err != nil || filteredBoth.Resources == nil || filteredBoth.TotalCount == nil || *filteredBoth.TotalCount != 2 {
		t.Fatalf("ListResourceInstances(filter both): %+v, %v", filteredBoth, err)
	}
	gotNames := make([]string, 0, len(*filteredBoth.Resources))
	for _, r := range *filteredBoth.Resources {
		if r.ResourceName != nil {
			gotNames = append(gotNames, *r.ResourceName)
		}
	}
	if !slices.Contains(gotNames, nameA) || !slices.Contains(gotNames, nameB) {
		t.Fatalf("ListResourceInstances(filter both) names = %v, want %s and %s", gotNames, nameA, nameB)
	}

	filteredProd, err := c.ListResourceInstances(&csms.ListResourceInstancesRequest{
		ResourceInstances: "resource_instances",
		Body: &csms.ListResourceInstancesRequestBody{
			Action: "filter",
			Tags: &[]csms.Tag{
				{Key: ptr(tagKeyTeam), Values: &[]string{"platform"}},
				{Key: ptr(tagKeyEnv), Values: &[]string{"prod"}},
			},
			Matches: &[]csms.TagMatches{
				{Key: ptr("resource_name"), Value: ptr(nameA)},
			},
		},
	})
	if err != nil || filteredProd.Resources == nil || filteredProd.TotalCount == nil ||
		*filteredProd.TotalCount != 1 || len(*filteredProd.Resources) != 1 ||
		derefStr((*filteredProd.Resources)[0].ResourceId) != idA {
		t.Fatalf("ListResourceInstances(filter prod): %+v, %v", filteredProd, err)
	}

	counted, err := c.ListResourceInstances(&csms.ListResourceInstancesRequest{
		ResourceInstances: "resource_instances",
		Body: &csms.ListResourceInstancesRequestBody{
			Action: "count",
			Tags: &[]csms.Tag{
				{Key: ptr(tagKeyTeam), Values: &[]string{"platform"}},
			},
			Matches: &[]csms.TagMatches{
				{Key: ptr("resource_name"), Value: ptr(suffix)},
			},
		},
	})
	if err != nil || counted.TotalCount == nil || *counted.TotalCount != 2 {
		t.Fatalf("ListResourceInstances(count): %+v, %v", counted, err)
	}

	// 6. BatchCreateOrDeleteTags (delete) & DeleteSecretTag.
	if _, err := c.BatchCreateOrDeleteTags(&csms.BatchCreateOrDeleteTagsRequest{
		SecretId: idA,
		Body: &csms.BatchCreateOrDeleteTagsRequestBody{
			Action: "delete",
			Tags:   []csms.TagItem{{Key: tagKeyTier}},
		},
	}); err != nil {
		t.Fatalf("BatchCreateOrDeleteTags(delete A): %v", err)
	}

	delTagResp, err := c.DeleteSecretTag(&csms.DeleteSecretTagRequest{
		SecretId: idA,
		Key:      tagKeyTeam,
	})
	if err != nil {
		t.Fatalf("DeleteSecretTag: %v", err)
	}
	if delTagResp.HttpStatusCode != http.StatusNoContent {
		t.Errorf("DeleteSecretTag status = %d, want 204", delTagResp.HttpStatusCode)
	}

	// Deleting an absent tag key -> 404 CSMS.0005.
	_, err = c.DeleteSecretTag(&csms.DeleteSecretTagRequest{
		SecretId: idA,
		Key:      tagKeyTeam,
	})
	wantError(t, err, 404, "CSMS.0005")

	tagsAfter, err := c.ListSecretTags(&csms.ListSecretTagsRequest{SecretId: idA})
	if err != nil || tagsAfter.Tags == nil || len(*tagsAfter.Tags) != 1 || (*tagsAfter.Tags)[0].Key != tagKeyEnv {
		t.Fatalf("ListSecretTags(A after delete): %+v, %v", tagsAfter, err)
	}
}

// TestCSMSPermissions runs only with WEISTACK_SDK_IAM=enforce and verifies:
//  1. CSMS ReadOnlyAccess allows listing/showing secrets and all 3 tag reads,
//     while denying CreateSecret and tag writes with 403 CSMS.0302.
//  2. Agent policy: an IAM 5.0 user allowed csms:secret:* + kms:cmk:* with an
//     explicit Deny on csms:secret:getVersion can create/list secrets and
//     versions, and is denied ShowSecretVersion with 403 CSMS.0302.
//  3. KMS dependency check: an IAM 5.0 user allowed csms:secret:* without
//     kms:cmk:decryptDataKey is denied ShowSecretVersion with 403 CSMS.0302.
func TestCSMSPermissions(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	admin, admin5 := iamClientsAs(t, adminAK, adminSK)
	adminCSMS := csmsAs(t, adminAK, adminSK)
	adminKMS := kmsAs(t, adminAK, adminSK)
	adminSTS := stsAs(t, adminAK, adminSK)

	// Shared KMS key and fixture secret created by administrator.
	km, err := adminKMS.CreateKey(&kms.CreateKeyRequest{Body: &kms.CreateKeyRequestBody{
		KeyAlias: "sdk-csms-iam-" + suffix,
	}})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	kmsKeyID := *km.KeyInfo.KeyId
	t.Cleanup(func() {
		_, _ = adminKMS.DeleteKey(&kms.DeleteKeyRequest{Body: &kms.ScheduleKeyDeletionRequestBody{
			KeyId: kmsKeyID, PendingDays: "7",
		}})
	})

	fixtureName := "sdk-csms-fixture-" + suffix
	t.Cleanup(func() {
		_, _ = adminCSMS.DeleteSecret(&csms.DeleteSecretRequest{SecretName: fixtureName})
	})
	fixtureCreated, err := adminCSMS.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
		Name:         fixtureName,
		KmsKeyId:     ptr(kmsKeyID),
		SecretString: ptr("top-secret-fixture-" + suffix),
	}})
	if err != nil || fixtureCreated.Secret == nil || fixtureCreated.Secret.Id == nil {
		t.Fatalf("CreateSecret(fixture): %+v, %v", fixtureCreated, err)
	}
	fixtureID := *fixtureCreated.Secret.Id
	if _, err := adminCSMS.CreateSecretTag(&csms.CreateSecretTagRequest{
		SecretId: fixtureID,
		Body: &csms.CreateSecretTagRequestBody{
			Tag: &csms.TagItem{Key: "scope", Value: ptr("enforce-" + suffix)},
		},
	}); err != nil {
		t.Fatalf("CreateSecretTag(fixture): %v", err)
	}

	makeV5UserWithPolicy := func(label, policyDoc string) *csmsv1.CsmsClient {
		t.Helper()
		u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{
			Name: "sdk-csms-" + label + "-" + suffix, Enabled: true,
		}})
		if err != nil {
			t.Fatalf("CreateUserV5(%s): %v", label, err)
		}
		uid := u.User.UserId
		t.Cleanup(func() {
			_, _ = admin5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: uid})
		})

		akResp, err := admin5.CreateAccessKeyV5(&v5.CreateAccessKeyV5Request{UserId: uid})
		if err != nil {
			t.Fatalf("CreateAccessKeyV5(%s): %v", label, err)
		}

		pol, err := admin5.CreatePolicyV5(&v5.CreatePolicyV5Request{Body: &v5.CreatePolicyReqBody{
			PolicyName:     "sdk-csms-" + label + "-" + suffix,
			PolicyDocument: policyDoc,
		}})
		if err != nil {
			t.Fatalf("CreatePolicyV5(%s): %v", label, err)
		}
		pid := pol.Policy.PolicyId
		t.Cleanup(func() {
			_, _ = admin5.DeletePolicyV5(&v5.DeletePolicyV5Request{PolicyId: pid})
		})

		if _, err := admin5.AttachUserPolicyV5(&v5.AttachUserPolicyV5Request{
			PolicyId: pid,
			Body:     &v5.AttachUserPolicyReqBody{UserId: uid},
		}); err != nil {
			t.Fatalf("AttachUserPolicyV5(%s): %v", label, err)
		}
		t.Cleanup(func() {
			_, _ = admin5.DetachUserPolicyV5(&v5.DetachUserPolicyV5Request{
				PolicyId: pid,
				Body:     &v5.DetachUserPolicyReqBody{UserId: uid},
			})
		})

		return csmsAs(t, akResp.AccessKey.AccessKeyId, akResp.AccessKey.SecretAccessKey)
	}

	// 1. User in a group with CSMS ReadOnlyAccess in the project.
	roUser, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{
		Name: "sdk-csms-ro-" + suffix, Enabled: true,
	}})
	if err != nil {
		t.Fatalf("CreateUserV5(ro): %v", err)
	}
	roUID := roUser.User.UserId
	t.Cleanup(func() {
		_, _ = admin5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: roUID})
	})
	roKey, err := admin.CreatePermanentAccessKey(&iam.CreatePermanentAccessKeyRequest{Body: &iam.CreatePermanentAccessKeyRequestBody{
		Credential: &iam.CreateCredentialOption{UserId: roUID},
	}})
	if err != nil {
		t.Fatalf("CreatePermanentAccessKey(ro): %v", err)
	}
	roGroup, err := admin.KeystoneCreateGroup(&iam.KeystoneCreateGroupRequest{Body: &iam.KeystoneCreateGroupRequestBody{
		Group: &iam.KeystoneCreateGroupOption{Name: "sdk-csms-ro-grp-" + suffix},
	}})
	if err != nil {
		t.Fatalf("KeystoneCreateGroup: %v", err)
	}
	roGID := roGroup.Group.Id
	t.Cleanup(func() {
		_, _ = admin.KeystoneDeleteGroup(&iam.KeystoneDeleteGroupRequest{GroupId: roGID})
	})
	if _, err := admin.KeystoneAddUserToGroup(&iam.KeystoneAddUserToGroupRequest{GroupId: roGID, UserId: roUID}); err != nil {
		t.Fatalf("KeystoneAddUserToGroup: %v", err)
	}
	perms, err := admin.KeystoneListPermissions(&iam.KeystoneListPermissionsRequest{DisplayName: ptr("CSMS ReadOnlyAccess")})
	if err != nil || perms.Roles == nil || len(*perms.Roles) != 1 {
		t.Fatalf("KeystoneListPermissions(CSMS ReadOnlyAccess) = %+v, %v", perms, err)
	}
	if _, err := admin.KeystoneAssociateGroupWithProjectPermission(&iam.KeystoneAssociateGroupWithProjectPermissionRequest{
		ProjectId: projectID, GroupId: roGID, RoleId: (*perms.Roles)[0].Id,
	}); err != nil {
		t.Fatalf("KeystoneAssociateGroupWithProjectPermission: %v", err)
	}

	roCSMS := csmsAs(t, roKey.Credential.Access, roKey.Credential.Secret)
	if _, err := roCSMS.ListSecrets(&csms.ListSecretsRequest{}); err != nil {
		t.Fatalf("ListSecrets with CSMS ReadOnlyAccess: %v", err)
	}
	if _, err := roCSMS.ShowSecret(&csms.ShowSecretRequest{SecretName: fixtureName}); err != nil {
		t.Fatalf("ShowSecret with CSMS ReadOnlyAccess: %v", err)
	}
	if _, err := roCSMS.ListSecretVersions(&csms.ListSecretVersionsRequest{SecretName: fixtureName}); err != nil {
		t.Fatalf("ListSecretVersions with CSMS ReadOnlyAccess: %v", err)
	}
	if _, err := roCSMS.ShowSecretStage(&csms.ShowSecretStageRequest{SecretName: fixtureName, StageName: "SYSCURRENT"}); err != nil {
		t.Fatalf("ShowSecretStage with CSMS ReadOnlyAccess: %v", err)
	}
	if _, err := roCSMS.ListSecretTags(&csms.ListSecretTagsRequest{SecretId: fixtureID}); err != nil {
		t.Fatalf("ListSecretTags with CSMS ReadOnlyAccess: %v", err)
	}
	if _, err := roCSMS.ListProjectSecretsTags(&csms.ListProjectSecretsTagsRequest{}); err != nil {
		t.Fatalf("ListProjectSecretsTags with CSMS ReadOnlyAccess: %v", err)
	}
	if _, err := roCSMS.ListResourceInstances(&csms.ListResourceInstancesRequest{
		ResourceInstances: "resource_instances",
		Body:              &csms.ListResourceInstancesRequestBody{Action: "filter"},
	}); err != nil {
		t.Fatalf("ListResourceInstances with CSMS ReadOnlyAccess: %v", err)
	}

	_, err = roCSMS.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
		Name:         "sdk-csms-ro-denied-" + suffix,
		SecretString: ptr("denied"),
	}})
	denialOf(t, err, "CSMS.0302")

	_, err = roCSMS.CreateSecretTag(&csms.CreateSecretTagRequest{
		SecretId: fixtureID,
		Body:     &csms.CreateSecretTagRequestBody{Tag: &csms.TagItem{Key: "denied", Value: ptr("1")}},
	})
	denialOf(t, err, "CSMS.0302")

	_, err = roCSMS.BatchCreateOrDeleteTags(&csms.BatchCreateOrDeleteTagsRequest{
		SecretId: fixtureID,
		Body: &csms.BatchCreateOrDeleteTagsRequestBody{
			Action: "create",
			Tags:   []csms.TagItem{{Key: "denied", Value: ptr("1")}},
		},
	})
	denialOf(t, err, "CSMS.0302")

	_, err = roCSMS.DeleteSecretTag(&csms.DeleteSecretTagRequest{
		SecretId: fixtureID,
		Key:      "scope",
	})
	denialOf(t, err, "CSMS.0302")

	// 2. Agent policy: Allow csms:secret:* + kms:cmk:*, explicit Deny csms:secret:getVersion.
	agentDoc := `{"Version":"5.0","Statement":[` +
		`{"Effect":"Allow","Action":["csms:secret:*","kms:cmk:*"]},` +
		`{"Effect":"Deny","Action":["csms:secret:getVersion"]}` +
		`]}`
	agentCSMS := makeV5UserWithPolicy("agent", agentDoc)

	agentSecret := "sdk-csms-agent-" + suffix
	t.Cleanup(func() {
		_, _ = adminCSMS.DeleteSecret(&csms.DeleteSecretRequest{SecretName: agentSecret})
	})
	if _, err := agentCSMS.CreateSecret(&csms.CreateSecretRequest{Body: &csms.CreateSecretRequestBody{
		Name:         agentSecret,
		KmsKeyId:     ptr(kmsKeyID),
		SecretString: ptr("agent-v1-secret"),
	}}); err != nil {
		t.Fatalf("agent CreateSecret: %v", err)
	}
	if _, err := agentCSMS.ListSecrets(&csms.ListSecretsRequest{}); err != nil {
		t.Fatalf("agent ListSecrets: %v", err)
	}
	if _, err := agentCSMS.CreateSecretVersion(&csms.CreateSecretVersionRequest{
		SecretName: agentSecret,
		Body:       &csms.CreateSecretVersionRequestBody{SecretString: ptr("agent-v2-secret")},
	}); err != nil {
		t.Fatalf("agent CreateSecretVersion: %v", err)
	}
	if _, err := agentCSMS.ListSecretVersions(&csms.ListSecretVersionsRequest{SecretName: agentSecret}); err != nil {
		t.Fatalf("agent ListSecretVersions: %v", err)
	}

	_, err = agentCSMS.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: agentSecret, VersionId: "latest"})
	agentEncoded := denialOf(t, err, "CSMS.0302")
	agentDecoded, err := adminSTS.DecodeAuthorizationMessage(&sts.DecodeAuthorizationMessageRequest{
		Body: &sts.DecodeAuthorizationMessageReq{EncodedMessage: agentEncoded},
	})
	if err != nil || agentDecoded.DecodedMessage == nil || !strings.Contains(*agentDecoded.DecodedMessage, `"csms:secret:getVersion"`) {
		t.Fatalf("decoded agent denial = %+v, %v", agentDecoded, err)
	}

	// 3. KMS dependency check: Allow csms:secret:* without kms:cmk:decryptDataKey.
	noKMSDoc := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["csms:secret:*"]}]}`
	noKMSCSMS := makeV5UserWithPolicy("nokms", noKMSDoc)

	if _, err := noKMSCSMS.ShowSecret(&csms.ShowSecretRequest{SecretName: fixtureName}); err != nil {
		t.Fatalf("noKMS ShowSecret: %v", err)
	}
	_, err = noKMSCSMS.ShowSecretVersion(&csms.ShowSecretVersionRequest{SecretName: fixtureName, VersionId: "v1"})
	depEncoded := denialOf(t, err, "CSMS.0302")
	depDecoded, err := adminSTS.DecodeAuthorizationMessage(&sts.DecodeAuthorizationMessageRequest{
		Body: &sts.DecodeAuthorizationMessageReq{EncodedMessage: depEncoded},
	})
	if err != nil || depDecoded.DecodedMessage == nil || !strings.Contains(*depDecoded.DecodedMessage, `"kms:cmk:decryptDataKey"`) {
		t.Fatalf("decoded KMS dependency denial = %+v, %v", depDecoded, err)
	}
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
