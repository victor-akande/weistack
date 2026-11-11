package sdk

import (
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
)

// TestOBSBucketConfigurationReads makes the reads Terraform's
// huaweicloud_obs_bucket does after every create, in both dialects, and
// checks each decodes and errs the way the provider expects.
func TestOBSBucketConfigurationReads(t *testing.T) {
	t.Parallel()
	for _, sig := range []obs.SignatureType{obs.SignatureObs, obs.SignatureV4} {
		t.Run(string(sig), func(t *testing.T) {
			t.Parallel()
			c := newOBS(t, "AKCONFIG"+string(sig), sig, false)
			bucket := "sdk-config-" + string(sig)
			if _, err := c.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
				t.Fatalf("CreateBucket: %v", err)
			}
			put := &obs.PutObjectInput{Body: strings.NewReader("hello")}
			put.Bucket, put.Key = bucket, "k"
			if _, err := c.PutObject(put); err != nil {
				t.Fatalf("PutObject: %v", err)
			}

			if out, err := c.GetBucketStoragePolicy(bucket); err != nil || out.StorageClass != "STANDARD" {
				t.Errorf("GetBucketStoragePolicy = %+v, %v", out, err)
			}
			if out, err := c.GetBucketVersioning(bucket); err != nil || out.Status != "" {
				t.Errorf("GetBucketVersioning = %+v, %v", out, err)
			}
			if out, err := c.GetBucketLoggingConfiguration(bucket); err != nil || out.TargetBucket != "" {
				t.Errorf("GetBucketLoggingConfiguration = %+v, %v", out, err)
			}
			if out, err := c.GetBucketQuota(bucket); err != nil || out.Quota != 0 {
				t.Errorf("GetBucketQuota = %+v, %v", out, err)
			}
			if out, err := c.GetBucketStorageInfo(bucket); err != nil || out.Size != 5 || out.ObjectNumber != 1 {
				t.Errorf("GetBucketStorageInfo = %+v, %v", out, err)
			}
			if out, err := c.GetBucketCustomDomain(bucket); err != nil || len(out.Domains) != 0 {
				t.Errorf("GetBucketCustomDomain = %+v, %v", out, err)
			}
			if out, err := c.GetBucketAcl(bucket); err != nil || len(out.Grants) != 1 || out.Grants[0].Permission != obs.PermissionFullControl || out.Grants[0].Grantee.ID != out.Owner.ID {
				t.Errorf("GetBucketAcl = %+v, %v", out, err)
			}

			wantOBSCode := func(what, code string, err error) {
				t.Helper()
				obsErr, ok := err.(obs.ObsError)
				if !ok || obsErr.StatusCode != 404 || obsErr.Code != code {
					t.Errorf("%s: %v, want a 404 %s", what, err, code)
				}
			}
			_, err := c.GetBucketPolicy(bucket)
			wantOBSCode("GetBucketPolicy", "NoSuchBucketPolicy", err)
			_, err = c.GetBucketLifecycleConfiguration(bucket)
			wantOBSCode("GetBucketLifecycleConfiguration", "NoSuchLifecycleConfiguration", err)
			_, err = c.GetBucketCors(bucket)
			wantOBSCode("GetBucketCors", "NoSuchCORSConfiguration", err)
			_, err = c.GetBucketTagging(bucket)
			wantOBSCode("GetBucketTagging", "NoSuchTagSet", err)
			_, err = c.GetBucketWebsiteConfiguration(bucket)
			wantOBSCode("GetBucketWebsiteConfiguration", "NoSuchWebsiteConfiguration", err)
			encryption := "NoSuchEncryptionConfiguration"
			if sig != obs.SignatureObs {
				encryption = "ServerSideEncryptionConfigurationNotFoundError"
			}
			_, err = c.GetBucketEncryption(bucket)
			wantOBSCode("GetBucketEncryption", encryption, err)
		})
	}
}
