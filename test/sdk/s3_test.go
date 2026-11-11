package sdk

import (
	"bytes"
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

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// newS3 builds a client of the AWS SDK for Go v2 pointed at the OBS
// endpoint. Plain S3 tools are a common way to use OBS, and this SDK
// exercises paths Huawei's does not: its own signature version 4
// headers, upload checksums and URL-encoded listings.
//
// The SDK only streams uploads in aws-chunked encoding over TLS, so that
// encoding is covered by the emulator's unit tests instead.
func newS3(t *testing.T, accessKey string, pathStyle bool) *s3.Client {
	t.Helper()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, emulatorAddr)
		},
		ResponseHeaderTimeout: 10 * time.Second,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return s3.New(s3.Options{
		Region:           region,
		Credentials:      awscreds.NewStaticCredentialsProvider(accessKey, "weistack-does-not-verify-signatures", ""),
		BaseEndpoint:     aws.String(obsEndpoint),
		UsePathStyle:     pathStyle,
		HTTPClient:       &http.Client{Transport: transport},
		RetryMaxAttempts: 1,
	})
}

// wantS3Error asserts an error as the AWS SDK decodes it.
func wantS3Error(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is %T (%v), want an API error with code %s", err, err, code)
	}
	if apiErr.ErrorCode() != code {
		t.Fatalf("got code %s (%s), want %s", apiErr.ErrorCode(), apiErr.ErrorMessage(), code)
	}
}

func TestS3Compatibility(t *testing.T) {
	for _, pathStyle := range []bool{false, true} {
		name := "virtual-hosted"
		if pathStyle {
			name = "path-style"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := newS3(t, "AKaws-"+name, pathStyle)
			bucket := aws.String("sdk-aws-" + name)

			if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{
				Bucket:                    bucket,
				CreateBucketConfiguration: &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(region)},
			}); err != nil {
				t.Fatalf("CreateBucket: %v", err)
			}
			if _, err := c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: bucket}); err != nil {
				t.Fatalf("HeadBucket: %v", err)
			}
			buckets, err := c.ListBuckets(ctx, &s3.ListBucketsInput{})
			if err != nil || len(buckets.Buckets) != 1 || aws.ToString(buckets.Buckets[0].Name) != *bucket {
				t.Fatalf("ListBuckets = %+v, %v", buckets, err)
			}

			// --- Uploads ---------------------------------------------------
			const content = "The quick brown fox jumps over the lazy dog"
			sum := md5.Sum([]byte(content))
			wantETag := `"` + hex.EncodeToString(sum[:]) + `"`
			for _, key := range []string{"readme.txt", "docs/guide.txt", "docs/api/v1.txt", "img/a b+c.txt"} {
				out, err := c.PutObject(ctx, &s3.PutObjectInput{
					Bucket: bucket, Key: aws.String(key), Body: strings.NewReader(content),
					ContentType: aws.String("text/plain"), Metadata: map[string]string{"author": "aws-sdk"},
				})
				if err != nil {
					t.Fatalf("PutObject(%s): %v", key, err)
				}
				if aws.ToString(out.ETag) != wantETag {
					t.Errorf("PutObject(%s) ETag = %s, want %s", key, aws.ToString(out.ETag), wantETag)
				}
			}

			big := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
			bigSum := md5.Sum(big)
			large, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: bucket, Key: aws.String("big.bin"), Body: bytes.NewReader(big)})
			if err != nil {
				t.Fatalf("PutObject(big.bin): %v", err)
			}
			if aws.ToString(large.ETag) != `"`+hex.EncodeToString(bigSum[:])+`"` {
				t.Errorf("large upload ETag = %s: the stored body is not what was sent", aws.ToString(large.ETag))
			}

			// --- Downloads ------------------------------------------------
			got, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: bucket, Key: aws.String("img/a b+c.txt")})
			if err != nil {
				t.Fatalf("GetObject: %v", err)
			}
			body, _ := io.ReadAll(got.Body)
			got.Body.Close()
			if string(body) != content || aws.ToString(got.ContentType) != "text/plain" || got.Metadata["author"] != "aws-sdk" ||
				aws.ToInt64(got.ContentLength) != int64(len(content)) {
				t.Fatalf("GetObject: %q type %q metadata %v", body, aws.ToString(got.ContentType), got.Metadata)
			}

			part, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: bucket, Key: aws.String("big.bin"), Range: aws.String("bytes=16-31")})
			if err != nil {
				t.Fatalf("GetObject(range): %v", err)
			}
			body, _ = io.ReadAll(part.Body)
			part.Body.Close()
			if string(body) != "0123456789abcdef" || aws.ToString(part.ContentRange) != "bytes 16-31/1048576" {
				t.Fatalf("ranged GetObject: %q, Content-Range %q", body, aws.ToString(part.ContentRange))
			}

			head, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: bucket, Key: aws.String("big.bin")})
			if err != nil || aws.ToInt64(head.ContentLength) != 1<<20 {
				t.Fatalf("HeadObject = %+v, %v", head, err)
			}
			_, err = c.GetObject(ctx, &s3.GetObjectInput{Bucket: bucket, Key: aws.String("missing")})
			wantS3Error(t, err, "NoSuchKey")

			// --- ListObjectsV2 with the SDK's paginator -------------------
			var keys, prefixes []string
			pager := s3.NewListObjectsV2Paginator(c, &s3.ListObjectsV2Input{Bucket: bucket, Delimiter: aws.String("/"), MaxKeys: aws.Int32(2)})
			for pager.HasMorePages() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					t.Fatalf("ListObjectsV2: %v", err)
				}
				for _, o := range page.Contents {
					keys = append(keys, aws.ToString(o.Key))
				}
				for _, p := range page.CommonPrefixes {
					prefixes = append(prefixes, aws.ToString(p.Prefix))
				}
			}
			if strings.Join(keys, ",") != "big.bin,readme.txt" || strings.Join(prefixes, ",") != "docs/,img/" {
				t.Fatalf("top level: keys %v prefixes %v", keys, prefixes)
			}
			// A key with a space and a plus survives the URL-encoded listing.
			img, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: bucket, Prefix: aws.String("img/")})
			if err != nil || len(img.Contents) != 1 || aws.ToString(img.Contents[0].Key) != "img/a b+c.txt" ||
				aws.ToInt64(img.Contents[0].Size) != int64(len(content)) {
				t.Fatalf("ListObjectsV2(img/) = %+v, %v", img.Contents, err)
			}
			v1, err := c.ListObjects(ctx, &s3.ListObjectsInput{Bucket: bucket, Prefix: aws.String("docs/")})
			if err != nil || len(v1.Contents) != 2 {
				t.Fatalf("ListObjects(docs/) = %+v, %v", v1.Contents, err)
			}

			// --- Copy -------------------------------------------------------
			if _, err := c.CopyObject(ctx, &s3.CopyObjectInput{
				Bucket: bucket, Key: aws.String("copy of readme.txt"), CopySource: aws.String(*bucket + "/readme.txt"),
			}); err != nil {
				t.Fatalf("CopyObject: %v", err)
			}
			copied, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: bucket, Key: aws.String("copy of readme.txt")})
			if err != nil || aws.ToString(copied.ETag) != wantETag || copied.Metadata["author"] != "aws-sdk" {
				t.Fatalf("copied object = %+v, %v", copied, err)
			}

			// --- Teardown ----------------------------------------------------
			_, err = c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: bucket})
			wantS3Error(t, err, "BucketNotEmpty")

			if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: bucket, Key: aws.String("copy of readme.txt")}); err != nil {
				t.Fatalf("DeleteObject: %v", err)
			}
			var doomed []types.ObjectIdentifier
			for _, key := range []string{"readme.txt", "docs/guide.txt", "docs/api/v1.txt", "img/a b+c.txt", "big.bin"} {
				doomed = append(doomed, types.ObjectIdentifier{Key: aws.String(key)})
			}
			batch, err := c.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: bucket, Delete: &types.Delete{Objects: doomed}})
			if err != nil || len(batch.Deleted) != 5 || len(batch.Errors) != 0 {
				t.Fatalf("DeleteObjects = %+v, %v", batch, err)
			}
			if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: bucket}); err != nil {
				t.Fatalf("DeleteBucket: %v", err)
			}
			_, err = c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: bucket})
			if err == nil {
				t.Fatal("the bucket still exists after DeleteBucket")
			}
		})
	}
}
