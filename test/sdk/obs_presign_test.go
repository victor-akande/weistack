package sdk

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
)

// TestOBSPresignedURLs downloads an object through a URL the OBS SDK
// pre-signed, in both of its v2 dialects, with a plain HTTP client. With
// credentials enforced, a URL with a changed signature is refused.
func TestOBSPresignedURLs(t *testing.T) {
	t.Parallel()
	// Every request goes to the emulator, whatever host the URL names.
	httpClient := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, emulatorAddr)
		},
	}, Timeout: 10 * time.Second}
	get := func(url string) (int, string) {
		t.Helper()
		res, err := httpClient.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body)
	}

	for _, sig := range []obs.SignatureType{obs.SignatureObs, obs.SignatureV2} {
		t.Run(string(sig), func(t *testing.T) {
			t.Parallel()
			c := newOBS(t, "AKpresign"+string(sig), sig, false)
			bucket := "sdk-presign-" + strings.ToLower(string(sig))
			if _, err := c.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
				t.Fatalf("CreateBucket: %v", err)
			}
			put := &obs.PutObjectInput{Body: strings.NewReader("shared")}
			put.Bucket, put.Key = bucket, "dir/file name.txt"
			if _, err := c.PutObject(put); err != nil {
				t.Fatalf("PutObject: %v", err)
			}

			signed, err := c.CreateSignedUrl(&obs.CreateSignedUrlInput{
				Method: obs.HttpMethodGet, Bucket: bucket, Key: "dir/file name.txt", Expires: 300,
			})
			if err != nil {
				t.Fatalf("CreateSignedUrl: %v", err)
			}
			if code, body := get(signed.SignedUrl); code != http.StatusOK || body != "shared" {
				t.Fatalf("GET the pre-signed URL = %d %q", code, body)
			}
			if enforcing {
				tampered := strings.Replace(signed.SignedUrl, "Expires=", "Expires=1", 1)
				if code, body := get(tampered); code != http.StatusForbidden || !strings.Contains(body, "SignatureDoesNotMatch") {
					t.Fatalf("GET a changed URL = %d %q", code, body)
				}
			}

			del := &obs.DeleteObjectInput{Bucket: bucket, Key: "dir/file name.txt"}
			if _, err := c.DeleteObject(del); err != nil {
				t.Fatalf("DeleteObject: %v", err)
			}
			if _, err := c.DeleteBucket(bucket); err != nil {
				t.Fatalf("DeleteBucket: %v", err)
			}
		})
	}
}
