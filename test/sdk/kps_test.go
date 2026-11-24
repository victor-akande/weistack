package sdk

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	ims "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ims/v2/model"
	kms "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
	kpsv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kps/v3"
	kps "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kps/v3/model"
	kpsregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kps/v3/region"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

// kpsAs builds a KPS client that signs with ak and sk in the project, using
// Huawei Cloud's real regional endpoint through the emulator proxy.
func kpsAs(t *testing.T, ak, sk string) *kpsv3.KpsClient {
	t.Helper()
	creds, err := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithProjectId(projectID).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	hc, err := kpsv3.KpsClientBuilder().
		WithRegion(kpsregion.ValueOf(region)).
		WithCredential(creds).
		WithHttpConfig(proxyConfig(t)).
		SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	return kpsv3.NewKpsClient(hc)
}

func assertPKCS1PrivateKey(t *testing.T, pemStr string) {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("expected RSA PRIVATE KEY PEM block, got %v", block)
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatalf("ParsePKCS1PrivateKey: %v", err)
	}
}

func pollKPSTask(t *testing.T, c *kpsv3.KpsClient, taskID, wantStatus string) {
	t.Helper()
	var last string
	eventually(t, "kps task "+taskID+" to reach "+wantStatus, func() bool {
		res, err := c.ListKeypairTask(&kps.ListKeypairTaskRequest{TaskId: taskID})
		if err != nil {
			t.Fatalf("ListKeypairTask(%s): %v", taskID, err)
		}
		if res.TaskStatus == nil {
			return false
		}
		last = res.TaskStatus.Value()
		return last != "RUNNING_RESET" && last != "RUNNING_REPLACE" && last != "RUNNING_UNBIND" &&
			last != "READY_RESET" && last != "READY_REPLACE" && last != "READY_UNBIND"
	})
	if last != wantStatus {
		t.Fatalf("task %s ended with status %q, want %q", taskID, last, wantStatus)
	}
}

// TestKPSKeypairsAndProtection exercises keypair CRUD, pagination, private-key
// protection (default vault, explicit KMS key, kps/default), import/export,
// clear, batch import, and batch export through the official kps/v3 client.
func TestKPSKeypairsAndProtection(t *testing.T) {
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	c := kpsAs(t, signingAK("AKKPS000000000000000"), signingSK())
	kmsClient := kmsAs(t, signingAK("AKKPS000000000000000"), signingSK())

	cleanupKP := func(name string) {
		t.Cleanup(func() {
			_, _ = c.DeleteKeypair(&kps.DeleteKeypairRequest{KeypairName: name})
		})
	}

	// Create a real KMS key for KMS-protected keypair tests.
	km, err := kmsClient.CreateKey(&kms.CreateKeyRequest{Body: &kms.CreateKeyRequestBody{
		KeyAlias: "sdk-kps-" + suffix,
	}})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	kmsKeyID := *km.KeyInfo.KeyId
	t.Cleanup(func() {
		_, _ = kmsClient.EnableKey(&kms.EnableKeyRequest{Body: &kms.OperateKeyRequestBody{KeyId: kmsKeyID}})
		_, _ = kmsClient.DeleteKey(&kms.DeleteKeyRequest{Body: &kms.ScheduleKeyDeletionRequestBody{
			KeyId: kmsKeyID, PendingDays: "7",
		}})
	})

	encEnum := kps.GetEncryptionTypeEnum()

	// 1. Generate RSA keypair without protection.
	plainName := "sdk-kps-plain-" + suffix
	cleanupKP(plainName)
	plainCreated, err := c.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{Name: plainName},
	}})
	if err != nil {
		t.Fatalf("CreateKeypair(plain): %v", err)
	}
	if plainCreated.Keypair == nil || plainCreated.Keypair.PrivateKey == nil || *plainCreated.Keypair.PrivateKey == "" {
		t.Fatalf("CreateKeypair(plain) did not return a private key: %+v", plainCreated)
	}
	assertPKCS1PrivateKey(t, *plainCreated.Keypair.PrivateKey)
	if plainCreated.Keypair.PublicKey == nil || !strings.HasPrefix(*plainCreated.Keypair.PublicKey, "ssh-rsa ") {
		t.Fatalf("CreateKeypair(plain) public_key = %v", plainCreated.Keypair.PublicKey)
	}
	if plainCreated.Keypair.Fingerprint == nil || *plainCreated.Keypair.Fingerprint == "" {
		t.Fatalf("CreateKeypair(plain) missing fingerprint: %+v", plainCreated.Keypair)
	}
	plainPub := *plainCreated.Keypair.PublicKey
	plainPriv := *plainCreated.Keypair.PrivateKey
	plainFP := *plainCreated.Keypair.Fingerprint

	// Duplicate name returns 400 KPS.7004.
	_, err = c.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{Name: plainName},
	}})
	wantError(t, err, 400, "KPS.7004")

	// Unprotected keypair export returns 400 KPS.6005.
	_, err = c.ExportPrivateKey(&kps.ExportPrivateKeyRequest{Body: &kps.ExportPrivateKeyRequestBody{
		Keypair: &kps.KeypairBean{Name: plainName},
	}})
	wantError(t, err, 400, "KPS.6005")

	// 2. Generate keypair with default protection.
	defName := "sdk-kps-def-" + suffix
	cleanupKP(defName)
	defCreated, err := c.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{
			Name: defName,
			KeyProtection: &kps.KeyProtection{
				Encryption: &kps.Encryption{Type: encEnum.DEFAULT},
			},
		},
	}})
	if err != nil {
		t.Fatalf("CreateKeypair(default protection): %v", err)
	}
	if defCreated.Keypair == nil || defCreated.Keypair.PrivateKey == nil || *defCreated.Keypair.PrivateKey == "" {
		t.Fatalf("CreateKeypair(default) missing private key: %+v", defCreated)
	}
	defPriv := *defCreated.Keypair.PrivateKey

	// 3. Create imported keypair using the real RSA public key from plainCreated.
	impName := "sdk-kps-imp-" + suffix
	cleanupKP(impName)
	impCreated, err := c.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{
			Name:      impName,
			PublicKey: ptr(plainPub),
		},
	}})
	if err != nil {
		t.Fatalf("CreateKeypair(import): %v", err)
	}
	if impCreated.Keypair == nil {
		t.Fatalf("CreateKeypair(import) returned nil keypair")
	}
	if impCreated.Keypair.PrivateKey != nil && *impCreated.Keypair.PrivateKey != "" {
		t.Fatalf("CreateKeypair(import) unexpectedly returned a private key")
	}
	if impCreated.Keypair.Fingerprint == nil || *impCreated.Keypair.Fingerprint != plainFP {
		t.Fatalf("CreateKeypair(import) fingerprint = %v, want %q", impCreated.Keypair.Fingerprint, plainFP)
	}

	// 4. Create generated keypair with explicit KMS key protection.
	kmsName := "sdk-kps-kms-" + suffix
	cleanupKP(kmsName)
	kmsCreated, err := c.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{
			Name: kmsName,
			KeyProtection: &kps.KeyProtection{
				Encryption: &kps.Encryption{
					Type:     encEnum.KMS,
					KmsKeyId: ptr(kmsKeyID),
				},
			},
		},
	}})
	if err != nil {
		t.Fatalf("CreateKeypair(kms): %v", err)
	}
	if kmsCreated.Keypair == nil || kmsCreated.Keypair.PrivateKey == nil || *kmsCreated.Keypair.PrivateKey == "" {
		t.Fatalf("CreateKeypair(kms) missing private key: %+v", kmsCreated)
	}
	kmsPriv := *kmsCreated.Keypair.PrivateKey

	// 5. Create generated keypair with kms_key_name = "kps/default".
	kmsDefName := "sdk-kps-kmsdef-" + suffix
	cleanupKP(kmsDefName)
	kmsDefCreated, err := c.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{
			Name: kmsDefName,
			KeyProtection: &kps.KeyProtection{
				Encryption: &kps.Encryption{
					Type:       encEnum.KMS,
					KmsKeyName: ptr("kps/default"),
				},
			},
		},
	}})
	if err != nil {
		t.Fatalf("CreateKeypair(kps/default): %v", err)
	}
	if kmsDefCreated.Keypair == nil || kmsDefCreated.Keypair.PrivateKey == nil || *kmsDefCreated.Keypair.PrivateKey == "" {
		t.Fatalf("CreateKeypair(kps/default) missing private key: %+v", kmsDefCreated)
	}
	kmsDefPriv := *kmsDefCreated.Keypair.PrivateKey

	// 6. ListKeypairDetail & UpdateKeypairDescription.
	if _, err := c.UpdateKeypairDescription(&kps.UpdateKeypairDescriptionRequest{
		KeypairName: plainName,
		Body: &kps.UpdateKeypairDescriptionRequestBody{
			Keypair: &kps.UpdateKeypairDescriptionReq{Description: "sdk test description"},
		},
	}); err != nil {
		t.Fatalf("UpdateKeypairDescription: %v", err)
	}
	detail, err := c.ListKeypairDetail(&kps.ListKeypairDetailRequest{KeypairName: plainName})
	if err != nil || detail.Keypair == nil {
		t.Fatalf("ListKeypairDetail: %+v, %v", detail, err)
	}
	d := detail.Keypair
	if d.Name == nil || *d.Name != plainName ||
		d.Id == nil || *d.Id <= 0 ||
		d.Type == nil || d.Type.Value() != "ssh" ||
		d.Scope == nil || d.Scope.Value() != "user" ||
		d.PublicKey == nil || *d.PublicKey != plainPub ||
		d.Fingerprint == nil || *d.Fingerprint != plainFP ||
		d.IsKeyProtection == nil || *d.IsKeyProtection ||
		d.Description == nil || *d.Description != "sdk test description" ||
		d.Algorithm == nil || *d.Algorithm != "ssh-rsa" ||
		d.FrozenState == nil || *d.FrozenState != 0 {
		t.Fatalf("ListKeypairDetail(plain) = %+v", d)
	}

	// Check KMS-protected keypair detail exposes IsKeyProtection and KeyId.
	kmsDetail, err := c.ListKeypairDetail(&kps.ListKeypairDetailRequest{KeypairName: kmsName})
	if err != nil || kmsDetail.Keypair == nil ||
		kmsDetail.Keypair.IsKeyProtection == nil || !*kmsDetail.Keypair.IsKeyProtection ||
		kmsDetail.Keypair.KeyId == nil || *kmsDetail.Keypair.KeyId != kmsKeyID {
		t.Fatalf("ListKeypairDetail(kms) = %+v, %v", kmsDetail, err)
	}

	// Missing keypair detail -> 404 KPS.6004.
	_, err = c.ListKeypairDetail(&kps.ListKeypairDetailRequest{KeypairName: "no-such-keypair-" + suffix})
	wantError(t, err, 404, "KPS.6004")

	// 7. ListKeypairs pagination with limit and marker.
	wantNames := []string{plainName, defName, impName, kmsName, kmsDefName}
	seenOrder := make([]string, 0, len(wantNames))
	wantSet := make(map[string]bool, len(wantNames))
	for _, n := range wantNames {
		wantSet[n] = true
	}
	var marker *string
	pages := 0
	for {
		pages++
		if pages > 100 {
			t.Fatal("ListKeypairs pagination did not terminate")
		}
		res, err := c.ListKeypairs(&kps.ListKeypairsRequest{
			Limit:  ptr("2"),
			Marker: marker,
		})
		if err != nil {
			t.Fatalf("ListKeypairs(page %d): %v", pages, err)
		}
		if res.Keypairs == nil || res.PageInfo == nil || res.PageInfo.CurrentCount == nil {
			t.Fatalf("ListKeypairs(page %d) missing keypairs or page_info: %+v", pages, res)
		}
		if int(*res.PageInfo.CurrentCount) != len(*res.Keypairs) || len(*res.Keypairs) > 2 {
			t.Fatalf("ListKeypairs(page %d) count=%d len=%d", pages, *res.PageInfo.CurrentCount, len(*res.Keypairs))
		}
		for _, item := range *res.Keypairs {
			if item.Keypair != nil && item.Keypair.Name != nil && wantSet[*item.Keypair.Name] {
				seenOrder = append(seenOrder, *item.Keypair.Name)
			}
		}
		if res.PageInfo.NextMarker == nil || *res.PageInfo.NextMarker == "" {
			break
		}
		marker = res.PageInfo.NextMarker
	}
	if pages < 3 {
		t.Errorf("expected multiple pages with limit=2 and >=5 keypairs, got %d", pages)
	}
	if len(seenOrder) != len(wantNames) {
		t.Fatalf("paginated ListKeypairs saw %v, want %v", seenOrder, wantNames)
	}
	for i := range wantNames {
		if seenOrder[i] != wantNames[i] {
			t.Errorf("paginated ListKeypairs order = %v, want %v", seenOrder, wantNames)
			break
		}
	}

	// 8. ExportPrivateKey round-trips for default, explicit KMS, and kps/default.
	checkExport := func(name, wantPEM string) {
		t.Helper()
		exp, err := c.ExportPrivateKey(&kps.ExportPrivateKeyRequest{Body: &kps.ExportPrivateKeyRequestBody{
			Keypair: &kps.KeypairBean{Name: name},
		}})
		if err != nil {
			t.Fatalf("ExportPrivateKey(%s): %v", name, err)
		}
		if exp.Keypair == nil || exp.Keypair.Name != name || exp.Keypair.PrivateKey != wantPEM {
			t.Fatalf("ExportPrivateKey(%s) mismatch", name)
		}
	}
	checkExport(defName, defPriv)
	checkExport(kmsName, kmsPriv)
	checkExport(kmsDefName, kmsDefPriv)

	// Disabling the KMS key causes ExportPrivateKey to fail with 400 KPS.6008;
	// re-enabling makes it work again.
	if _, err := kmsClient.DisableKey(&kms.DisableKeyRequest{Body: &kms.OperateKeyRequestBody{KeyId: kmsKeyID}}); err != nil {
		t.Fatalf("DisableKey: %v", err)
	}
	_, err = c.ExportPrivateKey(&kps.ExportPrivateKeyRequest{Body: &kps.ExportPrivateKeyRequestBody{
		Keypair: &kps.KeypairBean{Name: kmsName},
	}})
	wantError(t, err, 400, "KPS.6008")
	if _, err := kmsClient.EnableKey(&kms.EnableKeyRequest{Body: &kms.OperateKeyRequestBody{KeyId: kmsKeyID}}); err != nil {
		t.Fatalf("EnableKey: %v", err)
	}
	checkExport(kmsName, kmsPriv)

	// 9. ImportPrivateKey: mismatch -> 400 KPS.6011; matching with default, then kms.
	_, err = c.ImportPrivateKey(&kps.ImportPrivateKeyRequest{Body: &kps.ImportPrivateKeyRequestBody{
		Keypair: &kps.ImportPrivateKeyKeypairBean{
			Name: impName,
			KeyProtection: &kps.ImportPrivateKeyProtection{
				PrivateKey: defPriv, // belongs to defName, not impName
				Encryption: &kps.Encryption{Type: encEnum.DEFAULT},
			},
		},
	}})
	wantError(t, err, 400, "KPS.6011")

	if _, err := c.ImportPrivateKey(&kps.ImportPrivateKeyRequest{Body: &kps.ImportPrivateKeyRequestBody{
		Keypair: &kps.ImportPrivateKeyKeypairBean{
			Name: impName,
			KeyProtection: &kps.ImportPrivateKeyProtection{
				PrivateKey: plainPriv,
				Encryption: &kps.Encryption{Type: encEnum.DEFAULT},
			},
		},
	}}); err != nil {
		t.Fatalf("ImportPrivateKey(default): %v", err)
	}
	checkExport(impName, plainPriv)

	if _, err := c.ImportPrivateKey(&kps.ImportPrivateKeyRequest{Body: &kps.ImportPrivateKeyRequestBody{
		Keypair: &kps.ImportPrivateKeyKeypairBean{
			Name: impName,
			KeyProtection: &kps.ImportPrivateKeyProtection{
				PrivateKey: plainPriv,
				Encryption: &kps.Encryption{
					Type:     encEnum.KMS,
					KmsKeyId: ptr(kmsKeyID),
				},
			},
		},
	}}); err != nil {
		t.Fatalf("ImportPrivateKey(kms): %v", err)
	}
	checkExport(impName, plainPriv)

	// 10. ClearPrivateKey removes protection and subsequent ExportPrivateKey -> 400 KPS.6005.
	if _, err := c.ClearPrivateKey(&kps.ClearPrivateKeyRequest{KeypairName: impName}); err != nil {
		t.Fatalf("ClearPrivateKey: %v", err)
	}
	clearedDetail, err := c.ListKeypairDetail(&kps.ListKeypairDetailRequest{KeypairName: impName})
	if err != nil || clearedDetail.Keypair == nil || clearedDetail.Keypair.IsKeyProtection == nil || *clearedDetail.Keypair.IsKeyProtection {
		t.Fatalf("ListKeypairDetail after ClearPrivateKey = %+v, %v", clearedDetail, err)
	}
	_, err = c.ExportPrivateKey(&kps.ExportPrivateKeyRequest{Body: &kps.ExportPrivateKeyRequestBody{
		Keypair: &kps.KeypairBean{Name: impName},
	}})
	wantError(t, err, 400, "KPS.6005")

	// 11. BatchImportKeypair: one new + one duplicate.
	batchNewName := "sdk-kps-batch-" + suffix
	cleanupKP(batchNewName)
	batchImp, err := c.BatchImportKeypair(&kps.BatchImportKeypairRequest{
		Body: &[]kps.CreateKeypairRequestBody{
			{Keypair: &kps.CreateKeypairAction{Name: batchNewName, PublicKey: ptr(plainPub)}},
			{Keypair: &kps.CreateKeypairAction{Name: plainName, PublicKey: ptr(plainPub)}},
		},
	})
	if err != nil {
		t.Fatalf("BatchImportKeypair: %v", err)
	}
	if batchImp.SucceededKeypairs == nil || len(*batchImp.SucceededKeypairs) != 1 ||
		(*batchImp.SucceededKeypairs)[0].Keypair == nil ||
		(*batchImp.SucceededKeypairs)[0].Keypair.Name == nil ||
		*(*batchImp.SucceededKeypairs)[0].Keypair.Name != batchNewName {
		t.Fatalf("BatchImportKeypair succeeded = %+v", batchImp.SucceededKeypairs)
	}
	if batchImp.FailedKeypairs == nil || len(*batchImp.FailedKeypairs) != 1 ||
		(*batchImp.FailedKeypairs)[0].KeypairName != plainName ||
		!strings.Contains((*batchImp.FailedKeypairs)[0].FailedReason, "KPS.7004") {
		t.Fatalf("BatchImportKeypair failed = %+v", batchImp.FailedKeypairs)
	}

	// 12. BatchExportPrivateKey returns a valid zip containing <name>.pem files.
	batchExp, err := c.BatchExportPrivateKey(&kps.BatchExportPrivateKeyRequest{
		Body: &[]kps.Keypairs{
			{Keypair: &kps.Keypair{Name: ptr(defName)}},
			{Keypair: &kps.Keypair{Name: ptr(kmsName)}},
		},
	})
	if err != nil {
		t.Fatalf("BatchExportPrivateKey: %v", err)
	}
	if batchExp.Body == nil || len(*batchExp.Body) == 0 {
		t.Fatalf("BatchExportPrivateKey returned empty body")
	}
	zipBytes := []byte(*batchExp.Body)
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("BatchExportPrivateKey body is not a valid zip: %v", err)
	}
	gotZip := make(map[string]string, len(zr.File))
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("opening zip entry %s: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("reading zip entry %s: %v", f.Name, err)
		}
		gotZip[f.Name] = string(data)
	}
	if len(gotZip) != 2 || gotZip[defName+".pem"] != defPriv || gotZip[kmsName+".pem"] != kmsPriv {
		t.Fatalf("BatchExportPrivateKey zip entries mismatch: keys=%v", len(gotZip))
	}

	// 13. DeleteKeypair returns 204 and keypair is subsequently 404 KPS.6004.
	delResp, err := c.DeleteKeypair(&kps.DeleteKeypairRequest{KeypairName: batchNewName})
	if err != nil {
		t.Fatalf("DeleteKeypair: %v", err)
	}
	if delResp.HttpStatusCode != 204 {
		t.Errorf("DeleteKeypair status = %d, want 204", delResp.HttpStatusCode)
	}
	_, err = c.ListKeypairDetail(&kps.ListKeypairDetailRequest{KeypairName: batchNewName})
	wantError(t, err, 404, "KPS.6004")
}

// TestKPSTasksAndECS exercises ECS key_name validation, associate/disassociate/
// batch-associate tasks, task status polling, running/failed task lists, and
// failed task deletion.
func TestKPSTasksAndECS(t *testing.T) {
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	kpsClient := kpsAs(t, signingAK("AKKPSTASKS0000000000"), signingSK())
	net2 := newV2(t, realEndpoint)
	compute := newECS(t)
	images := newIMS(t)

	cleanupKP := func(name string) {
		t.Cleanup(func() {
			_, _ = kpsClient.DeleteKeypair(&kps.DeleteKeypairRequest{KeypairName: name})
		})
	}

	// Network and image for an ECS server.
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("sdk-kps-vpc-" + suffix), Cidr: ptr("10.147.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	t.Cleanup(func() {
		_, _ = net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
	})
	eventually(t, "kps test VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "sdk-kps-sub-" + suffix, Cidr: "10.147.1.0/24", GatewayIp: "10.147.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	t.Cleanup(func() {
		_, _ = net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
	})
	eventually(t, "kps test subnet to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	listedImg, err := images.ListImages(&ims.ListImagesRequest{Name: ptr("Ubuntu 22.04 server 64bit")})
	if err != nil || listedImg.Images == nil || len(*listedImg.Images) != 1 {
		t.Fatalf("ListImages: %+v, %v", listedImg, err)
	}
	imageID := (*listedImg.Images)[0].Id

	waitECSJob := func(jobID string) {
		t.Helper()
		var last *ecs.ShowJobResponse
		eventually(t, "ecs job "+jobID+" to finish", func() bool {
			job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: jobID})
			if err != nil {
				t.Fatalf("ShowJob: %v", err)
			}
			last = job
			return job.Status != nil && job.Status.Value() != "RUNNING" && job.Status.Value() != "INIT"
		})
		if last.Status.Value() != "SUCCESS" {
			t.Fatalf("ecs job %s ended %s: %v", jobID, last.Status.Value(), last.FailReason)
		}
	}

	// 1. ECS server creation with unknown key_name -> 400 Ecs.0314.
	_, err = compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name:       "sdk-kps-bad-" + suffix,
			ImageRef:   imageID,
			FlavorRef:  "s6.large.2",
			Vpcid:      vpcID,
			KeyName:    ptr("no-such-keypair-" + suffix),
			Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().GPSSD},
		},
	}})
	wantError(t, err, 400, "Ecs.0314")

	// 2. Create initial keypair, create server with it, then delete the keypair
	// and verify the server retains key_name.
	initKP := "sdk-kps-init-" + suffix
	cleanupKP(initKP)
	if _, err := kpsClient.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{Name: initKP},
	}}); err != nil {
		t.Fatalf("CreateKeypair(init): %v", err)
	}

	srvRes, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name:       "sdk-kps-srv-" + suffix,
			ImageRef:   imageID,
			FlavorRef:  "s6.large.2",
			Vpcid:      vpcID,
			KeyName:    ptr(initKP),
			Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().GPSSD},
		},
	}})
	if err != nil || srvRes.JobId == nil || srvRes.ServerIds == nil || len(*srvRes.ServerIds) != 1 {
		t.Fatalf("CreatePostPaidServers: %+v, %v", srvRes, err)
	}
	serverID := (*srvRes.ServerIds)[0]
	t.Cleanup(func() {
		del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{
			Servers: []ecs.ServerId{{Id: serverID}},
		}})
		if err == nil && del.JobId != nil {
			waitECSJob(*del.JobId)
		}
	})
	waitECSJob(*srvRes.JobId)

	shown, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
	if err != nil || shown.Server == nil || shown.Server.KeyName != initKP {
		t.Fatalf("ShowServer after create = %+v, err=%v", shown, err)
	}

	if _, err := kpsClient.DeleteKeypair(&kps.DeleteKeypairRequest{KeypairName: initKP}); err != nil {
		t.Fatalf("DeleteKeypair(init): %v", err)
	}
	shown, err = compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
	if err != nil || shown.Server == nil || shown.Server.KeyName != initKP {
		t.Fatalf("ShowServer after DeleteKeypair = %+v, want key_name=%q, err=%v", shown, initKP, err)
	}

	// 3. DisassociateKeypair -> poll SUCCESS_UNBIND -> server key_name cleared.
	disRes, err := kpsClient.DisassociateKeypair(&kps.DisassociateKeypairRequest{Body: &kps.DisassociateKeypairRequestBody{
		Server: &kps.DisassociateEcsServerInfo{Id: serverID},
	}})
	if err != nil || disRes.TaskId == nil || *disRes.TaskId == "" {
		t.Fatalf("DisassociateKeypair = %+v, %v", disRes, err)
	}
	if disRes.HttpStatusCode != 202 {
		t.Errorf("DisassociateKeypair status = %d, want 202", disRes.HttpStatusCode)
	}
	pollKPSTask(t, kpsClient, *disRes.TaskId, "SUCCESS_UNBIND")

	shown, err = compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
	if err != nil || shown.Server == nil || shown.Server.KeyName != "" {
		t.Fatalf("ShowServer after DisassociateKeypair = %+v, want empty key_name, err=%v", shown, err)
	}

	// 4. AssociateKeypair with unknown keypair -> 400 KPS.4016.
	_, err = kpsClient.AssociateKeypair(&kps.AssociateKeypairRequest{Body: &kps.AssociateKeypairRequestBody{
		KeypairName: "no-such-keypair-" + suffix,
		Server:      &kps.EcsServerInfo{Id: serverID},
	}})
	wantError(t, err, 400, "KPS.4016")

	// 5. AssociateKeypair with a real keypair -> ListRunningTask -> poll SUCCESS_RESET.
	bindKP := "sdk-kps-bind-" + suffix
	cleanupKP(bindKP)
	if _, err := kpsClient.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{Name: bindKP},
	}}); err != nil {
		t.Fatalf("CreateKeypair(bind): %v", err)
	}

	assocRes, err := kpsClient.AssociateKeypair(&kps.AssociateKeypairRequest{Body: &kps.AssociateKeypairRequestBody{
		KeypairName: bindKP,
		Server:      &kps.EcsServerInfo{Id: serverID},
	}})
	if err != nil || assocRes.TaskId == nil || *assocRes.TaskId == "" {
		t.Fatalf("AssociateKeypair = %+v, %v", assocRes, err)
	}
	if assocRes.HttpStatusCode != 202 {
		t.Errorf("AssociateKeypair status = %d, want 202", assocRes.HttpStatusCode)
	}
	running, err := kpsClient.ListRunningTask(&kps.ListRunningTaskRequest{})
	if err != nil || running.HttpStatusCode != 200 || running.Total == nil {
		t.Fatalf("ListRunningTask = %+v, %v", running, err)
	}
	pollKPSTask(t, kpsClient, *assocRes.TaskId, "SUCCESS_RESET")

	shown, err = compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
	if err != nil || shown.Server == nil || shown.Server.KeyName != bindKP {
		t.Fatalf("ShowServer after AssociateKeypair = %+v, want key_name=%q, err=%v", shown, bindKP, err)
	}

	// 6. BatchAssociateKeypair -> poll SUCCESS_RESET -> server key_name updated.
	batchKP := "sdk-kps-bassoc-" + suffix
	cleanupKP(batchKP)
	if _, err := kpsClient.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{Name: batchKP},
	}}); err != nil {
		t.Fatalf("CreateKeypair(batch): %v", err)
	}

	batchRes, err := kpsClient.BatchAssociateKeypair(&kps.BatchAssociateKeypairRequest{Body: &kps.BatchAssociateKeypairRequestBody{
		BatchKeypairs: []kps.AssociateKeypairRequestBody{
			{KeypairName: batchKP, Server: &kps.EcsServerInfo{Id: serverID}},
		},
	}})
	if err != nil || batchRes.Tasks == nil || len(*batchRes.Tasks) != 1 || (*batchRes.Tasks)[0].TaskId == nil {
		t.Fatalf("BatchAssociateKeypair = %+v, %v", batchRes, err)
	}
	pollKPSTask(t, kpsClient, *(*batchRes.Tasks)[0].TaskId, "SUCCESS_RESET")

	shown, err = compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
	if err != nil || shown.Server == nil || shown.Server.KeyName != batchKP {
		t.Fatalf("ShowServer after BatchAssociateKeypair = %+v, want key_name=%q, err=%v", shown, batchKP, err)
	}

	// 7. Missing server UUID -> 202 with task_id -> FAILED_RESET -> ListFailedTask
	// -> DeleteFailedTask -> DeleteAllFailedTask.
	missingSrvID := "00000000-0000-0000-0000-000000000000"
	failRes1, err := kpsClient.AssociateKeypair(&kps.AssociateKeypairRequest{Body: &kps.AssociateKeypairRequestBody{
		KeypairName: bindKP,
		Server:      &kps.EcsServerInfo{Id: missingSrvID},
	}})
	if err != nil || failRes1.TaskId == nil || failRes1.HttpStatusCode != 202 {
		t.Fatalf("AssociateKeypair(missing server) = %+v, %v", failRes1, err)
	}
	failTask1 := *failRes1.TaskId
	pollKPSTask(t, kpsClient, failTask1, "FAILED_RESET")

	failedList, err := kpsClient.ListFailedTask(&kps.ListFailedTaskRequest{})
	if err != nil || failedList.Tasks == nil {
		t.Fatalf("ListFailedTask = %+v, %v", failedList, err)
	}
	foundFailed := false
	for _, ft := range *failedList.Tasks {
		if ft.TaskId != nil && *ft.TaskId == failTask1 {
			foundFailed = true
			if ft.ServerId == nil || *ft.ServerId != missingSrvID || ft.KeypairName == nil || *ft.KeypairName != bindKP {
				t.Errorf("failed task entry = %+v", ft)
			}
		}
	}
	if !foundFailed {
		t.Fatalf("failed task %s not found in ListFailedTask: %+v", failTask1, failedList.Tasks)
	}

	if _, err := kpsClient.DeleteFailedTask(&kps.DeleteFailedTaskRequest{TaskId: failTask1}); err != nil {
		t.Fatalf("DeleteFailedTask(%s): %v", failTask1, err)
	}
	// Deleting unknown failed task -> 400 KPS.0005.
	_, err = kpsClient.DeleteFailedTask(&kps.DeleteFailedTaskRequest{TaskId: failTask1})
	wantError(t, err, 400, "KPS.0005")

	// Trigger another failed task and clear all with DeleteAllFailedTask.
	failRes2, err := kpsClient.AssociateKeypair(&kps.AssociateKeypairRequest{Body: &kps.AssociateKeypairRequestBody{
		KeypairName: bindKP,
		Server:      &kps.EcsServerInfo{Id: missingSrvID},
	}})
	if err != nil || failRes2.TaskId == nil {
		t.Fatalf("AssociateKeypair(missing server 2) = %+v, %v", failRes2, err)
	}
	pollKPSTask(t, kpsClient, *failRes2.TaskId, "FAILED_RESET")

	if _, err := kpsClient.DeleteAllFailedTask(&kps.DeleteAllFailedTaskRequest{}); err != nil {
		t.Fatalf("DeleteAllFailedTask: %v", err)
	}
	afterClear, err := kpsClient.ListFailedTask(&kps.ListFailedTaskRequest{})
	if err != nil || afterClear.Total == nil || *afterClear.Total != 0 {
		t.Fatalf("ListFailedTask after DeleteAllFailedTask = %+v, %v", afterClear, err)
	}

	// 8. ListKeypairTask with unknown task ID -> 400 KPS.0001.
	_, err = kpsClient.ListKeypairTask(&kps.ListKeypairTaskRequest{TaskId: "00000000-0000-0000-0000-000000000099"})
	wantError(t, err, 400, "KPS.0001")
}

// TestKPSNovaKeypairs exercises all 4 Nova v2.1 os-keypairs operations through
// the official ecs/v2 client and verifies cross-visibility with KPS v3.
func TestKPSNovaKeypairs(t *testing.T) {
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	compute := newECS(t)
	kpsClient := kpsAs(t, signingAK("AKKPSNOVA00000000000"), signingSK())

	cleanupKP := func(name string) {
		t.Cleanup(func() {
			_, _ = kpsClient.DeleteKeypair(&kps.DeleteKeypairRequest{KeypairName: name})
		})
	}

	// 1. NovaCreateKeypair (generate).
	novaGenName := "sdk-nova-gen-" + suffix
	cleanupKP(novaGenName)
	genResp, err := compute.NovaCreateKeypair(&ecs.NovaCreateKeypairRequest{
		Body: &ecs.NovaCreateKeypairRequestBody{
			Keypair: &ecs.NovaCreateKeypairOption{Name: novaGenName},
		},
	})
	if err != nil || genResp.Keypair == nil {
		t.Fatalf("NovaCreateKeypair(generate) = %+v, %v", genResp, err)
	}
	if genResp.Keypair.PrivateKey == "" {
		t.Fatalf("NovaCreateKeypair(generate) returned empty private_key")
	}
	assertPKCS1PrivateKey(t, genResp.Keypair.PrivateKey)
	if !strings.HasPrefix(genResp.Keypair.PublicKey, "ssh-rsa ") || genResp.Keypair.Fingerprint == "" {
		t.Fatalf("NovaCreateKeypair(generate) = %+v", genResp.Keypair)
	}

	// Cross-visibility: Nova-created keypair is visible through KPS ListKeypairDetail.
	kpsDetail, err := kpsClient.ListKeypairDetail(&kps.ListKeypairDetailRequest{KeypairName: novaGenName})
	if err != nil || kpsDetail.Keypair == nil {
		t.Fatalf("KPS ListKeypairDetail(%s) = %+v, %v", novaGenName, kpsDetail, err)
	}
	if kpsDetail.Keypair.PublicKey == nil || *kpsDetail.Keypair.PublicKey != genResp.Keypair.PublicKey ||
		kpsDetail.Keypair.Fingerprint == nil || *kpsDetail.Keypair.Fingerprint != genResp.Keypair.Fingerprint ||
		kpsDetail.Keypair.Scope == nil || kpsDetail.Keypair.Scope.Value() != "user" {
		t.Fatalf("KPS detail for Nova keypair = %+v", kpsDetail.Keypair)
	}

	// 2. NovaCreateKeypair (import).
	novaImpName := "sdk-nova-imp-" + suffix
	cleanupKP(novaImpName)
	impResp, err := compute.NovaCreateKeypair(&ecs.NovaCreateKeypairRequest{
		Body: &ecs.NovaCreateKeypairRequestBody{
			Keypair: &ecs.NovaCreateKeypairOption{
				Name:      novaImpName,
				PublicKey: ptr(genResp.Keypair.PublicKey),
			},
		},
	})
	if err != nil || impResp.Keypair == nil {
		t.Fatalf("NovaCreateKeypair(import) = %+v, %v", impResp, err)
	}
	if impResp.Keypair.PrivateKey != "" {
		t.Fatalf("NovaCreateKeypair(import) unexpectedly returned private_key")
	}
	if impResp.Keypair.Fingerprint != genResp.Keypair.Fingerprint {
		t.Fatalf("NovaCreateKeypair(import) fingerprint = %q, want %q", impResp.Keypair.Fingerprint, genResp.Keypair.Fingerprint)
	}

	// 3. Cross-visibility: KPS-created keypair is visible through NovaShowKeypair.
	kpsMadeName := "sdk-kps-for-nova-" + suffix
	cleanupKP(kpsMadeName)
	kpsCreated, err := kpsClient.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{Name: kpsMadeName},
	}})
	if err != nil || kpsCreated.Keypair == nil {
		t.Fatalf("KPS CreateKeypair: %+v, %v", kpsCreated, err)
	}

	novaShown, err := compute.NovaShowKeypair(&ecs.NovaShowKeypairRequest{KeypairName: kpsMadeName})
	if err != nil || novaShown.Keypair == nil {
		t.Fatalf("NovaShowKeypair(%s) = %+v, %v", kpsMadeName, novaShown, err)
	}
	if novaShown.Keypair.Name != kpsMadeName ||
		novaShown.Keypair.PublicKey != *kpsCreated.Keypair.PublicKey ||
		novaShown.Keypair.Fingerprint != *kpsCreated.Keypair.Fingerprint ||
		novaShown.Keypair.Id <= 0 ||
		novaShown.Keypair.Deleted {
		t.Fatalf("NovaShowKeypair(%s) = %+v", kpsMadeName, novaShown.Keypair)
	}

	// 4. NovaListKeypairs includes all three keypairs.
	listed, err := compute.NovaListKeypairs(&ecs.NovaListKeypairsRequest{})
	if err != nil || listed.Keypairs == nil {
		t.Fatalf("NovaListKeypairs = %+v, %v", listed, err)
	}
	found := make(map[string]bool)
	for _, item := range *listed.Keypairs {
		if item.Keypair != nil {
			found[item.Keypair.Name] = true
		}
	}
	for _, name := range []string{novaGenName, novaImpName, kpsMadeName} {
		if !found[name] {
			t.Errorf("NovaListKeypairs missing %q", name)
		}
	}

	// 5. NovaDeleteKeypair removes the keypair from both Nova and KPS.
	if _, err := compute.NovaDeleteKeypair(&ecs.NovaDeleteKeypairRequest{KeypairName: novaGenName}); err != nil {
		t.Fatalf("NovaDeleteKeypair(%s): %v", novaGenName, err)
	}
	_, err = compute.NovaShowKeypair(&ecs.NovaShowKeypairRequest{KeypairName: novaGenName})
	wantError(t, err, 404, "KPS.6004")
	_, err = kpsClient.ListKeypairDetail(&kps.ListKeypairDetailRequest{KeypairName: novaGenName})
	wantError(t, err, 404, "KPS.6004")
}

// TestKPSPermissions runs only with WEISTACK_SDK_IAM=enforce: an IAM user with
// an IAM 5.0 policy granting only kps:SSHKeyPair:list may list key pairs and
// is refused create with 403 KPS.9003.
func TestKPSPermissions(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	_, admin5 := iamClientsAs(t, adminAK, adminSK)

	u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{
		Name: "sdk-kps-limited-" + suffix, Enabled: true,
	}})
	if err != nil {
		t.Fatalf("CreateUserV5: %v", err)
	}
	uid := u.User.UserId
	t.Cleanup(func() {
		_, _ = admin5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: uid})
	})

	akResp, err := admin5.CreateAccessKeyV5(&v5.CreateAccessKeyV5Request{UserId: uid})
	if err != nil {
		t.Fatalf("CreateAccessKeyV5: %v", err)
	}
	ak, sk := akResp.AccessKey.AccessKeyId, akResp.AccessKey.SecretAccessKey

	doc := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["kps:SSHKeyPair:list"]}]}`
	pol, err := admin5.CreatePolicyV5(&v5.CreatePolicyV5Request{Body: &v5.CreatePolicyReqBody{
		PolicyName:     "sdk-kps-list-only-" + suffix,
		PolicyDocument: doc,
	}})
	if err != nil {
		t.Fatalf("CreatePolicyV5: %v", err)
	}
	pid := pol.Policy.PolicyId
	t.Cleanup(func() {
		_, _ = admin5.DeletePolicyV5(&v5.DeletePolicyV5Request{PolicyId: pid})
	})

	if _, err := admin5.AttachUserPolicyV5(&v5.AttachUserPolicyV5Request{
		PolicyId: pid,
		Body:     &v5.AttachUserPolicyReqBody{UserId: uid},
	}); err != nil {
		t.Fatalf("AttachUserPolicyV5: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin5.DetachUserPolicyV5(&v5.DetachUserPolicyV5Request{
			PolicyId: pid,
			Body:     &v5.DetachUserPolicyReqBody{UserId: uid},
		})
	})

	userKPS := kpsAs(t, ak, sk)
	if _, err := userKPS.ListKeypairs(&kps.ListKeypairsRequest{}); err != nil {
		t.Fatalf("ListKeypairs with kps:SSHKeyPair:list: %v", err)
	}

	_, err = userKPS.CreateKeypair(&kps.CreateKeypairRequest{Body: &kps.CreateKeypairRequestBody{
		Keypair: &kps.CreateKeypairAction{Name: "sdk-kps-denied-" + suffix},
	}})
	denialOf(t, err, "KPS.9003")
}
