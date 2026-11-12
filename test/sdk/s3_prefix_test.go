package sdk

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// TestS3OverPathPrefix uses OBS the way the AWS CLI does with
// --endpoint-url http://127.0.0.1:8780/obs and path-style addressing:
// no DNS, no TLS, no proxy, only a base URL with a path.
func TestS3OverPathPrefix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	transport := &http.Transport{ResponseHeaderTimeout: 10 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	c := s3.New(s3.Options{
		Region:           region,
		Credentials:      awscreds.NewStaticCredentialsProvider("AKprefix", "weistack-does-not-verify-signatures", ""),
		BaseEndpoint:     aws.String("http://" + emulatorAddr + "/obs"),
		UsePathStyle:     true,
		HTTPClient:       &http.Client{Transport: transport},
		RetryMaxAttempts: 1,
	})
	bucket := aws.String("sdk-prefix")

	if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                    bucket,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(region)},
	}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if _, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: bucket, Key: aws.String("dir/hello.txt"), Body: strings.NewReader("hello")}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	listed, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: bucket, Prefix: aws.String("dir/")})
	if err != nil || len(listed.Contents) != 1 || aws.ToString(listed.Contents[0].Key) != "dir/hello.txt" {
		t.Fatalf("ListObjectsV2 = %+v, %v", listed, err)
	}
	got, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: bucket, Key: aws.String("dir/hello.txt")})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	body, _ := io.ReadAll(got.Body)
	got.Body.Close()
	if string(body) != "hello" {
		t.Fatalf("GetObject body = %q", body)
	}
	if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: bucket, Key: aws.String("dir/hello.txt")}); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: bucket}); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
}
