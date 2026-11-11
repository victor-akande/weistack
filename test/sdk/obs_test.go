package sdk

import (
	"context"
	"errors"
	"net"
	"net/http"
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
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, emulatorAddr)
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
