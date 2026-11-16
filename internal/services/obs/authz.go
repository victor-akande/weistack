package obs

import (
	"net/http"
	"strings"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
)

// OBS's actions (usermanual-permissions iam_11_0011). OBS routes by
// method and query string, not by path, so each operation's action is
// named here, by the operation names route() gives, and checked once the
// operation is known. Its resources are buckets (obs:::bucket:<name>) and
// objects (obs:::object:<bucket>/<key>), as documented: OBS's URNs have
// neither region nor account.

// opActions maps an operation to its action and whether it acts on the
// object rather than the bucket. Operations OBS refuses or WeiStack does
// not implement need none: they do nothing.
var opActions = map[string]struct {
	action string
	object bool
}{
	"ListBuckets":             {"obs:bucket:listAllMyBuckets", false},
	"CreateBucket":            {"obs:bucket:createBucket", false},
	"HeadBucket":              {"obs:bucket:headBucket", false},
	"DeleteBucket":            {"obs:bucket:deleteBucket", false},
	"GetBucketLocation":       {"obs:bucket:getBucketLocation", false},
	"ListObjects":             {"obs:bucket:listBucket", false},
	"ListObjectsV2":           {"obs:bucket:listBucket", false},
	"ListMultipartUploads":    {"obs:bucket:listBucketMultipartUploads", false},
	"PutObject":               {"obs:object:putObject", true},
	"CopyObject":              {"obs:object:putObject", true},
	"InitiateMultipartUpload": {"obs:object:putObject", true},
	"UploadPart":              {"obs:object:putObject", true},
	"CompleteMultipartUpload": {"obs:object:putObject", true},
	"GetObject":               {"obs:object:getObject", true},
	"HeadObject":              {"obs:object:getObject", true},
	"DeleteObject":            {"obs:object:deleteObject", true},
	"AbortMultipartUpload":    {"obs:object:abortMultipartUpload", true},
	"ListParts":               {"obs:object:listMultipartUploadParts", true},
	"PutBucketEncryption":     {"obs:bucket:putEncryptionConfiguration", false},
	"DeleteBucketEncryption":  {"obs:bucket:putEncryptionConfiguration", false},
}

// configActions are the reads of bucket configuration by subresource.
// Those the action table has no read for (notification, requestPayment,
// storageClass) read the bucket's metadata, headBucket.
var configActions = map[string]string{
	"acl":            "obs:bucket:getBucketAcl",
	"policy":         "obs:bucket:getBucketPolicy",
	"lifecycle":      "obs:bucket:getLifecycleConfiguration",
	"cors":           "obs:bucket:getBucketCORS",
	"tagging":        "obs:bucket:getBucketTagging",
	"website":        "obs:bucket:getBucketWebsite",
	"encryption":     "obs:bucket:getEncryptionConfiguration",
	"versioning":     "obs:bucket:getBucketVersioning",
	"logging":        "obs:bucket:getBucketLogging",
	"quota":          "obs:bucket:getBucketQuota",
	"customdomain":   "obs:bucket:getBucketCustomDomainConfiguration",
	"storagePolicy":  "obs:bucket:getBucketStoragePolicy",
	"storageinfo":    "obs:bucket:getBucketStorage",
	"notification":   "obs:bucket:headBucket",
	"requestPayment": "obs:bucket:headBucket",
	"storageClass":   "obs:bucket:headBucket",
}

// errAccessDenied is OBS's documented denial (api-obs obs_errorcode_0003).
func denied(*authz.Denial) *apierr.Error { return errAccessDenied }

func bucketResource(bucket string) authz.Resource {
	return authz.Resource{Type: "bucket", Path: bucket}
}

func objectResource(bucket, key string) authz.Resource {
	return authz.Resource{Type: "object", Path: bucket + "/" + key}
}

// authorize checks the operation op of c. Copying also needs to read its
// source; batch deletes check each key as they go (handleDeleteObjects).
func (s *Service) authorize(c *call, op string) error {
	action, res := "", authz.Resource{}
	if sub, ok := strings.CutPrefix(op, "GetBucket?"); ok {
		action, res = configActions[sub], bucketResource(c.target.Bucket)
	} else if a, ok := opActions[op]; ok {
		action, res = a.action, bucketResource(c.target.Bucket)
		if a.object {
			res = objectResource(c.target.Bucket, c.target.Key)
		}
	}
	if action == "" {
		return nil
	}
	if op == "ListBuckets" {
		// Listing buckets acts on every bucket.
		res = bucketResource("*")
	}
	if err := authz.Check(c.r, action, res); err != nil {
		return err
	}
	if op == "CopyObject" {
		if bucket, key, err := parseCopySource(c.vendorHeader("copy-source")); err == nil {
			return authz.Check(c.r, "obs:object:getObject", objectResource(bucket, key))
		}
	}
	return nil
}

// mayDelete reports whether the caller may delete one key of a batch.
func mayDelete(r *http.Request, bucket, key string) bool {
	return authz.Check(r, "obs:object:deleteObject", objectResource(bucket, key)) == nil
}
