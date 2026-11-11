package sdk

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
)

// obsEndpoint is Huawei Cloud's real OBS endpoint for the region. As
// with the other services the SDK is pointed at it unchanged and only
// the TCP connection is redirected to the emulator, so bucket host
// names, signing and headers are what the real service would receive.
const obsEndpoint = "http://obs." + region + ".myhuaweicloud.com"

// newOBS builds a client of Huawei's OBS SDK using the given signature
// type, which also selects the dialect: SignatureObs speaks "x-obs-",
// the others speak the S3 dialect.
func newOBS(t *testing.T, accessKey string, signature obs.SignatureType, pathStyle bool) *obs.ObsClient {
	t.Helper()
	return newOBSAt(t, emulatorAddr, accessKey, signature, pathStyle)
}

func newOBSAt(t *testing.T, addr, accessKey string, signature obs.SignatureType, pathStyle bool) *obs.ObsClient {
	t.Helper()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client, err := obs.New(accessKey, "weistack-does-not-verify-signatures", obsEndpoint,
		obs.WithSignature(signature),
		obs.WithPathStyle(pathStyle),
		obs.WithRegion(region),
		obs.WithHttpTransport(transport),
		obs.WithMaxRetryCount(0),
	)
	if err != nil {
		t.Fatalf("building OBS client: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

// wantOBSError asserts an error as the OBS SDK decodes it.
func wantOBSError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var obsErr obs.ObsError
	if !errors.As(err, &obsErr) {
		t.Fatalf("error is %T (%v), want an ObsError with %d %s", err, err, status, code)
	}
	if obsErr.StatusCode != status || obsErr.Code != code {
		t.Fatalf("got %d %s (%s), want %d %s", obsErr.StatusCode, obsErr.Code, obsErr.Message, status, code)
	}
	if obsErr.RequestId == "" {
		t.Errorf("the SDK found no request ID on %d %s", status, code)
	}
}

// TestOBSBuckets runs the bucket operations through Huawei's OBS SDK in
// each of its signature modes and both addressing styles.
func TestOBSBuckets(t *testing.T) {
	modes := []struct {
		name      string
		signature obs.SignatureType
		pathStyle bool
	}{
		{"obs-signature-virtual-hosted", obs.SignatureObs, false},
		{"v2-signature-virtual-hosted", obs.SignatureV2, false},
		{"v4-signature-virtual-hosted", obs.SignatureV4, false},
		{"v2-signature-path-style", obs.SignatureV2, true},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			// One access key per mode: buckets belong to the key that made them.
			ak := "AK" + mode.name
			c := newOBS(t, ak, mode.signature, mode.pathStyle)
			bucket := "sdk-" + mode.name

			created, err := c.CreateBucket(&obs.CreateBucketInput{
				Bucket:         bucket,
				BucketLocation: obs.BucketLocation{Location: region},
			})
			if err != nil {
				t.Fatalf("CreateBucket: %v", err)
			}
			if created.StatusCode != 200 || created.RequestId == "" {
				t.Errorf("CreateBucket = %+v", created)
			}

			_, err = c.CreateBucket(&obs.CreateBucketInput{Bucket: bucket})
			wantOBSError(t, err, 409, "BucketAlreadyOwnedByYou")
			_, err = c.CreateBucket(&obs.CreateBucketInput{Bucket: "Not_A_Valid_Name"})
			if err == nil {
				t.Error("an invalid bucket name was accepted")
			}

			if head, err := c.HeadBucket(bucket); err != nil || head.StatusCode != 200 {
				t.Fatalf("HeadBucket = %+v, %v", head, err)
			}
			_, err = c.HeadBucket("sdk-no-such-bucket")
			wantOBSError(t, err, 404, "NoSuchBucket")

			loc, err := c.GetBucketLocation(bucket)
			if err != nil || loc.Location != region {
				t.Fatalf("GetBucketLocation = %+v, %v; want %s", loc, err, region)
			}

			list, err := c.ListBuckets(nil)
			if err != nil {
				t.Fatalf("ListBuckets: %v", err)
			}
			if len(list.Buckets) != 1 || list.Buckets[0].Name != bucket || list.Owner.ID == "" ||
				time.Since(list.Buckets[0].CreationDate) > time.Hour {
				t.Fatalf("ListBuckets = %+v, want exactly this client's bucket with a recent creation date", list)
			}

			// Another access key cannot see or touch the bucket.
			other := newOBS(t, ak+"-other", mode.signature, mode.pathStyle)
			if theirs, err := other.ListBuckets(nil); err != nil || len(theirs.Buckets) != 0 {
				t.Errorf("another access key lists %+v, %v", theirs, err)
			}
			_, err = other.DeleteBucket(bucket)
			wantOBSError(t, err, 403, "AccessDenied")
			_, err = other.CreateBucket(&obs.CreateBucketInput{Bucket: bucket})
			wantOBSError(t, err, 409, "BucketAlreadyExists")

			if deleted, err := c.DeleteBucket(bucket); err != nil || deleted.StatusCode != 204 {
				t.Fatalf("DeleteBucket = %+v, %v", deleted, err)
			}
			_, err = c.DeleteBucket(bucket)
			wantOBSError(t, err, 404, "NoSuchBucket")
		})
	}
}

// TestOBSObjects is end-to-end scenario 3 of the plan (multipart aside)
// through Huawei's OBS SDK: create a bucket, upload, list with prefix
// and delimiter, download whole and by range, copy, delete everything,
// delete the bucket. It runs in both dialects.
func TestOBSObjects(t *testing.T) {
	modes := []struct {
		name      string
		signature obs.SignatureType
	}{
		{"obs-dialect", obs.SignatureObs},
		{"s3-dialect", obs.SignatureV2},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			c := newOBS(t, "AKobjects-"+mode.name, mode.signature, false)
			bucket := "sdk-objects-" + mode.name
			if _, err := c.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
				t.Fatalf("CreateBucket: %v", err)
			}

			const content = "The quick brown fox jumps over the lazy dog"
			put := func(key, body string) {
				t.Helper()
				in := &obs.PutObjectInput{Body: strings.NewReader(body)}
				in.Bucket, in.Key = bucket, key
				in.ContentType = "text/plain"
				in.Metadata = map[string]string{"author": "sdk", "purpose": "testing"}
				out, err := c.PutObject(in)
				if err != nil {
					t.Fatalf("PutObject(%s): %v", key, err)
				}
				if sum := md5.Sum([]byte(body)); out.ETag != `"`+hex.EncodeToString(sum[:])+`"` {
					t.Errorf("PutObject(%s) ETag = %s", key, out.ETag)
				}
			}
			for _, key := range []string{"readme.txt", "docs/guide.txt", "docs/api/v1.txt", "docs/api/v2.txt", "img/logo.txt"} {
				put(key, content)
			}

			// --- Listing with prefix and delimiter ---------------------
			top, err := c.ListObjects(&obs.ListObjectsInput{Bucket: bucket, ListObjsInput: obs.ListObjsInput{Delimiter: "/"}})
			if err != nil {
				t.Fatalf("ListObjects: %v", err)
			}
			if len(top.Contents) != 1 || top.Contents[0].Key != "readme.txt" || top.Contents[0].Size != int64(len(content)) ||
				strings.Join(top.CommonPrefixes, ",") != "docs/,img/" || top.IsTruncated {
				t.Fatalf("top level = %+v prefixes %v", top.Contents, top.CommonPrefixes)
			}
			if time.Since(top.Contents[0].LastModified) > time.Hour || top.Contents[0].ETag == "" {
				t.Errorf("listed object = %+v", top.Contents[0])
			}
			docs, err := c.ListObjects(&obs.ListObjectsInput{Bucket: bucket, ListObjsInput: obs.ListObjsInput{Prefix: "docs/", Delimiter: "/"}})
			if err != nil || len(docs.Contents) != 1 || docs.Contents[0].Key != "docs/guide.txt" || strings.Join(docs.CommonPrefixes, ",") != "docs/api/" {
				t.Fatalf("docs/ = %+v, %v", docs, err)
			}

			// Paging with the marker until the listing is no longer truncated.
			var keys []string
			marker := ""
			for {
				page, err := c.ListObjects(&obs.ListObjectsInput{Bucket: bucket, Marker: marker, ListObjsInput: obs.ListObjsInput{MaxKeys: 2}})
				if err != nil {
					t.Fatalf("ListObjects(marker %q): %v", marker, err)
				}
				for _, o := range page.Contents {
					keys = append(keys, o.Key)
				}
				if !page.IsTruncated {
					break
				}
				marker = page.NextMarker
			}
			if got := strings.Join(keys, ","); got != "docs/api/v1.txt,docs/api/v2.txt,docs/guide.txt,img/logo.txt,readme.txt" {
				t.Fatalf("paged keys = %s", got)
			}

			// --- Download, whole and by range --------------------------
			getIn := &obs.GetObjectInput{}
			getIn.Bucket, getIn.Key = bucket, "docs/guide.txt"
			got, err := c.GetObject(getIn)
			if err != nil {
				t.Fatalf("GetObject: %v", err)
			}
			body, _ := io.ReadAll(got.Body)
			got.Body.Close()
			if string(body) != content || got.ContentLength != int64(len(content)) || got.ContentType != "text/plain" ||
				got.Metadata["author"] != "sdk" || got.Metadata["purpose"] != "testing" {
				t.Fatalf("GetObject: %q, length %d, type %q, metadata %v", body, got.ContentLength, got.ContentType, got.Metadata)
			}

			rangeIn := &obs.GetObjectInput{RangeStart: 4, RangeEnd: 8}
			rangeIn.Bucket, rangeIn.Key = bucket, "docs/guide.txt"
			part, err := c.GetObject(rangeIn)
			if err != nil {
				t.Fatalf("GetObject(range): %v", err)
			}
			body, _ = io.ReadAll(part.Body)
			part.Body.Close()
			if string(body) != "quick" || part.StatusCode != 206 {
				t.Fatalf("ranged GetObject: %q (status %d), want \"quick\" with 206", body, part.StatusCode)
			}

			meta, err := c.GetObjectMetadata(&obs.GetObjectMetadataInput{Bucket: bucket, Key: "readme.txt"})
			if err != nil || meta.ContentLength != int64(len(content)) || meta.Metadata["author"] != "sdk" || meta.ETag == "" ||
				time.Since(meta.LastModified) > time.Hour {
				t.Fatalf("GetObjectMetadata = %+v, %v", meta, err)
			}

			missing := &obs.GetObjectInput{}
			missing.Bucket, missing.Key = bucket, "no-such-key"
			_, err = c.GetObject(missing)
			wantOBSError(t, err, 404, "NoSuchKey")
			_, err = c.GetObjectMetadata(&obs.GetObjectMetadataInput{Bucket: bucket, Key: "no-such-key"})
			wantOBSError(t, err, 404, "NoSuchKey")

			// --- Copy ----------------------------------------------------
			copyIn := &obs.CopyObjectInput{CopySourceBucket: bucket, CopySourceKey: "readme.txt"}
			copyIn.Bucket, copyIn.Key = bucket, "backup/readme copy.txt"
			copied, err := c.CopyObject(copyIn)
			if err != nil || copied.ETag == "" || time.Since(copied.LastModified) > time.Hour {
				t.Fatalf("CopyObject = %+v, %v", copied, err)
			}
			copyMeta, err := c.GetObjectMetadata(&obs.GetObjectMetadataInput{Bucket: bucket, Key: "backup/readme copy.txt"})
			if err != nil || copyMeta.Metadata["author"] != "sdk" || copyMeta.ContentLength != int64(len(content)) {
				t.Fatalf("copied object = %+v, %v", copyMeta, err)
			}

			// --- Dependency error (scenario 5), then teardown -----------
			_, err = c.DeleteBucket(bucket)
			wantOBSError(t, err, 409, "BucketNotEmpty")

			if _, err := c.DeleteObject(&obs.DeleteObjectInput{Bucket: bucket, Key: "backup/readme copy.txt"}); err != nil {
				t.Fatalf("DeleteObject: %v", err)
			}
			batch, err := c.DeleteObjects(&obs.DeleteObjectsInput{Bucket: bucket, Objects: []obs.ObjectToDelete{
				{Key: "readme.txt"}, {Key: "docs/guide.txt"}, {Key: "docs/api/v1.txt"}, {Key: "docs/api/v2.txt"}, {Key: "img/logo.txt"},
			}})
			if err != nil || len(batch.Deleteds) != 5 || len(batch.Errors) != 0 {
				t.Fatalf("DeleteObjects = %+v, %v", batch, err)
			}
			left, err := c.ListObjects(&obs.ListObjectsInput{Bucket: bucket})
			if err != nil || len(left.Contents) != 0 {
				t.Fatalf("after deleting everything: %+v, %v", left, err)
			}
			if _, err := c.DeleteBucket(bucket); err != nil {
				t.Fatalf("DeleteBucket: %v", err)
			}
		})
	}
}
