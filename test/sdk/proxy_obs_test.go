package sdk

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
)

// TestOBSThroughProxyTrustingTheCA is the setup docs/clients.md gives
// for Huawei's OBS SDK: the real HTTPS endpoint, WeiStack as the proxy,
// and full certificate verification against the CA WeiStack serves.
func TestOBSThroughProxyTrustingTheCA(t *testing.T) {
	t.Parallel()
	res, err := http.Get("http://" + emulatorAddr + "/_weistack/ca")
	if err != nil {
		t.Fatalf("fetching the CA: %v", err)
	}
	caPEM, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(caPEM), "BEGIN CERTIFICATE") {
		t.Fatalf("GET /_weistack/ca = %d %q", res.StatusCode, caPEM)
	}

	c, err := obs.New("AKproxyobs", "weistack-does-not-verify-signatures", "https://obs."+region+".myhuaweicloud.com",
		obs.WithProxyUrl("http://"+emulatorAddr),
		obs.WithSslVerifyAndPemCerts(true, caPEM),
		obs.WithSignature(obs.SignatureObs),
		obs.WithRegion(region),
		obs.WithMaxRetryCount(0),
	)
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}
	t.Cleanup(c.Close)

	const bucket = "sdk-proxy-obs"
	if _, err := c.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
		t.Fatalf("CreateBucket through the proxy: %v", err)
	}
	put := &obs.PutObjectInput{Body: strings.NewReader("over TLS, verified")}
	put.Bucket, put.Key = bucket, "verified.txt"
	if _, err := c.PutObject(put); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	get := &obs.GetObjectInput{}
	get.Bucket, get.Key = bucket, "verified.txt"
	out, err := c.GetObject(get)
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	body, _ := io.ReadAll(out.Body)
	out.Body.Close()
	if string(body) != "over TLS, verified" {
		t.Fatalf("GetObject body = %q", body)
	}
	if _, err := c.DeleteObject(&obs.DeleteObjectInput{Bucket: bucket, Key: "verified.txt"}); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if _, err := c.DeleteBucket(bucket); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
}
