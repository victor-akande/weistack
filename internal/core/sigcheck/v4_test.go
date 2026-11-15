package sigcheck

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The SigV4 vectors were made by the real signers with this key pair:
// aws-sdk-go-v2 v1.48.0 (v4.Signer SignHTTP and PresignHTTP, with S3's
// DisableURIPathEscaping) at 2026-11-15T09:00:00Z, and the OBS SDK
// v3.26.6 in v4 mode, which dates requests with Date, not X-Amz-Date.
const (
	v4AK = "AKV4VECTOR0000000000"
	v4SK = "v4-vector-secret-key-0000000000000000000"
)

var v4Time = time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

func v4Request(method, target string, body string, headers map[string]string) *http.Request {
	u, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	r := httptest.NewRequest(method, u.RequestURI(), strings.NewReader(body))
	r.Host = u.Host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func checkV4(t *testing.T, r *http.Request, now time.Time) (*ChunkVerifier, error) {
	t.Helper()
	a, ok, err := ParseV4(r)
	if !ok || err != nil {
		t.Fatalf("ParseV4 = %+v, %v, %v", a, ok, err)
	}
	return VerifyV4(r, a, v4SK, []string{r.URL.EscapedPath()}, now)
}

func awsPut() *http.Request {
	return v4Request(http.MethodPut, "http://127.0.0.1:8780/v4-bucket/dir/my%20key.txt?tagging=", "hello", map[string]string{
		"Content-Type": "text/plain", "X-Amz-Meta-Team": "  a   b ", "X-Amz-Date": "20261115T090000Z",
		"X-Amz-Content-Sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		"Authorization": "AWS4-HMAC-SHA256 Credential=" + v4AK + "/20261115/ap-southeast-1/s3/aws4_request, " +
			"SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-team, " +
			"Signature=06f1871d32a24596fe17473338e6743675318a8f3e5a8b775f792530a165a366",
	})
}

const awsPresigned = "https://v4-bucket.obs.ap-southeast-1.myhuaweicloud.com/dir/my%20key.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
	"&X-Amz-Credential=" + v4AK + "%2F20261115%2Fap-southeast-1%2Fs3%2Faws4_request&X-Amz-Date=20261115T090000Z" +
	"&X-Amz-Expires=900&X-Amz-SignedHeaders=host&response-content-type=text%2Fplain" +
	"&X-Amz-Signature=ce4b4c180b681637342bd20a06c3c2efe6609d43cce2019420bb07db3e40ebdf"

func TestV4Signatures(t *testing.T) {
	t.Parallel()
	obsTime := time.Date(2026, 11, 15, 11, 41, 38, 0, time.UTC)
	for name, tc := range map[string]struct {
		r   *http.Request
		now time.Time
	}{
		"aws-sdk-go-v2, header-signed, with a body hash": {awsPut(), v4Time},
		"aws-sdk-go-v2, pre-signed":                      {v4Request(http.MethodGet, awsPresigned, "", nil), v4Time.Add(10 * time.Minute)},
		// The OBS SDK sent Host with :443 but signed it without.
		"OBS SDK, dated with Date": {v4Request(http.MethodPut, "https://v4-bucket.obs.ap-southeast-1.myhuaweicloud.com:443/dir/my%20key.txt", "hello", map[string]string{
			"Content-Type": "text/plain", "Date": "Sun, 15 Nov 2026 11:41:38 GMT", "X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD",
			"Authorization": "AWS4-HMAC-SHA256 Credential=" + v4AK + "/20261115/ap-southeast-1/s3/aws4_request," +
				"SignedHeaders=content-type;date;host;x-amz-content-sha256,Signature=494248db8941cf33a356e142b3ebd78556b9901c375dbd2107f8ba8cd321732d",
		}), obsTime},
		"OBS SDK, a sub-resource": {v4Request(http.MethodGet, "https://v4-bucket.obs.ap-southeast-1.myhuaweicloud.com:443/?uploads=", "", map[string]string{
			"Date": "Sun, 15 Nov 2026 11:41:38 GMT", "X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD",
			"Authorization": "AWS4-HMAC-SHA256 Credential=" + v4AK + "/20261115/ap-southeast-1/s3/aws4_request," +
				"SignedHeaders=date;host;x-amz-content-sha256,Signature=f483ffa31f6b1a95c24bd8e4b3b2b1713d6ed4c28c7f5811a57fc165a2589ef6",
		}), obsTime},
	} {
		if _, err := checkV4(t, tc.r, tc.now); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestV4SignaturesRejected(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		change func(*http.Request)
		now    time.Time
		want   error
	}{
		"changed header":     {func(r *http.Request) { r.Header.Set("X-Amz-Meta-Team", "c") }, v4Time, ErrMismatch},
		"changed query":      {func(r *http.Request) { r.URL.RawQuery = "acl=" }, v4Time, ErrMismatch},
		"changed length":     {func(r *http.Request) { r.ContentLength = 6 }, v4Time, ErrMismatch},
		"changed body claim": {func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD") }, v4Time, ErrMismatch},
		"too late":           {nil, v4Time.Add(16 * time.Minute), ErrSkewed},
		"scope of another day": {func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "/20261115/", "/20261114/", 1))
		}, v4Time, ErrMismatch},
	} {
		r := awsPut()
		if tc.change != nil {
			tc.change(r)
		}
		if _, err := checkV4(t, r, tc.now); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if _, err := checkV4(t, v4Request(http.MethodGet, awsPresigned, "", nil), v4Time.Add(15*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired URL: %v", err)
	}
	tampered := strings.Replace(awsPresigned, "text%2Fplain", "text%2Fhtml", 1)
	if _, err := checkV4(t, v4Request(http.MethodGet, tampered, "", nil), v4Time); !errors.Is(err, ErrMismatch) {
		t.Errorf("tampered URL: %v", err)
	}
}

func TestParseV4(t *testing.T) {
	t.Parallel()
	for _, h := range []string{
		"AWS4-HMAC-SHA256 Credential=AK/20261115/r/s3, SignedHeaders=host, Signature=ab",
		"AWS4-HMAC-SHA256 Credential=AK/20261115/r/s3/aws4_request, Signature=ab",
		"AWS4-HMAC-SHA256 Credential=AK/20261115/r/s3/aws4_request, SignedHeaders=host",
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", h)
		if _, ok, err := ParseV4(r); !ok || !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v %v", h, ok, err)
		}
	}
	for _, target := range []string{"/?X-Amz-Algorithm=AWS4-HMAC-SHA1", "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=604801"} {
		if _, ok, err := ParseV4(httptest.NewRequest(http.MethodGet, target, nil)); !ok || !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v %v", target, ok, err)
		}
	}
	if _, ok, _ := ParseV4(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Error("a request without a signature parsed")
	}
}

// TestChunkSignatures checks the chunk signature chain against Amazon's
// documented streaming example (Amazon S3 API reference, "Signature
// calculations for the Authorization header: transferring payload in
// multiple chunks"): a 66,560-byte object of "a" sent in chunks of
// 65,536 and 1,024 bytes and a final empty one, with the example secret
// key, on 2013-05-24 in us-east-1. Its seed signature and the three chunk
// signatures below are the documented ones; the first also appears in
// MinIO's streaming tests.
func TestChunkSignatures(t *testing.T) {
	t.Parallel()
	secret := "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY" // Amazon's published example key
	v := &ChunkVerifier{
		key: deriveV4Key(secret, "20130524", "us-east-1", "s3"), date: "20130524T000000Z",
		scope: "20130524/us-east-1/s3/aws4_request", prev: "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9",
	}
	chunks := []struct {
		size int
		sig  string
	}{
		{65536, "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"},
		{1024, "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"},
		{0, "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"},
	}
	for i, c := range chunks {
		sum := sha256.Sum256([]byte(strings.Repeat("a", c.size)))
		if err := v.Check(c.sig, sum[:]); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
	// A chunk out of order, or with other data, fails.
	sum := sha256.Sum256([]byte("b"))
	if err := v.Check(chunks[0].sig, sum[:]); !errors.Is(err, ErrChunk) {
		t.Fatalf("a wrong chunk: %v", err)
	}
}

func TestV4StreamingReturnsChunkVerifier(t *testing.T) {
	t.Parallel()
	r := v4Request(http.MethodPut, "http://obs.localhost/b/k", "", nil)
	SignV4(r, v4AK, v4SK, "ap-southeast-1", "/b/k", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", v4Time)
	chunks, err := checkV4(t, r, v4Time)
	if err != nil || chunks == nil {
		t.Fatalf("streaming = %v, %v", chunks, err)
	}
	// Any other payload has no chunks to check.
	r = v4Request(http.MethodPut, "http://obs.localhost/b/k", "", nil)
	SignV4(r, v4AK, v4SK, "ap-southeast-1", "/b/k", "UNSIGNED-PAYLOAD", v4Time)
	if chunks, err := checkV4(t, r, v4Time); err != nil || chunks != nil {
		t.Fatalf("unsigned payload = %v, %v", chunks, err)
	}
}
