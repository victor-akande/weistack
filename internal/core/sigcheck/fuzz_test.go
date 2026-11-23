package sigcheck

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var fuzzNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// fuzzRequest builds a request from fuzzed parts, or nil when they do not
// make one (an invalid method, path or header).
func fuzzRequest(method, path, query, header string) *http.Request {
	if method == "" || strings.ContainsAny(method, " \t\r\n") || !strings.HasPrefix(path, "/") {
		return nil
	}
	u := &url.URL{Path: path, RawQuery: query}
	if _, err := url.ParseRequestURI(u.RequestURI()); err != nil {
		return nil
	}
	r, err := http.NewRequest(method, "http://vpc.ap-southeast-1.myhuaweicloud.com"+u.RequestURI(), nil)
	if err != nil {
		return nil
	}
	if header != "" {
		if strings.ContainsAny(header, "\r\n\x00") {
			return nil
		}
		r.Header.Set("X-Project-Id", header)
	}
	return r
}

// FuzzParseAuthorization: no Authorization header crashes the parsers.
func FuzzParseAuthorization(f *testing.F) {
	for _, s := range []string{
		"SDK-HMAC-SHA256 Access=AK, SignedHeaders=host;x-sdk-date, Signature=abc",
		"OBS AK:c2lnbmF0dXJl",
		"AWS AK:c2ln",
		"AWS4-HMAC-SHA256 Credential=AK/20261123/ap-southeast-1/s3/aws4_request, SignedHeaders=host, Signature=00",
		"SDK-HMAC-SHA256 Access=, , ,",
		"AWS4-HMAC-SHA256 Credential=////, SignedHeaders=, Signature=",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, authorization string) {
		_, _ = ParseSDKHMAC(authorization)
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Header.Set("Authorization", authorization)
		_, _, _ = ParseV2(r)
		_, _, _ = ParseV4(r)
	})
}

// FuzzSDKHMACRoundTrip: whatever the request, a signature made the way
// the SDKs make it verifies, and a changed body does not.
func FuzzSDKHMACRoundTrip(f *testing.F) {
	f.Add("GET", "/v1/p/vpcs", "limit=10&marker=a", "p", []byte(""))
	f.Add("POST", "/v1/p/vpcs/a b/%2F", "x=%20&y&z=1&z=0", "", []byte(`{"vpc":{}}`))
	f.Add("DELETE", "/v3/p/ü", "a=b=c", "x y", []byte{0})
	f.Fuzz(func(t *testing.T, method, path, query, header string, body []byte) {
		r := fuzzRequest(method, path, query, header)
		if r == nil {
			return
		}
		SignSDKHMAC(r, "FUZZAK", "fuzz-secret", r.URL.Path, body, fuzzNow)
		a, err := ParseSDKHMAC(r.Header.Get("Authorization"))
		if err != nil {
			t.Fatalf("parsing our own signature: %v (%q)", err, r.Header.Get("Authorization"))
		}
		if err := VerifySDKHMAC(r, a, "fuzz-secret", body, []string{r.URL.Path}, fuzzNow); err != nil {
			t.Fatalf("our own signature does not verify: %v (%s %s?%s)", err, method, path, query)
		}
		if err := VerifySDKHMAC(r, a, "fuzz-secret", append(body, 'x'), []string{r.URL.Path}, fuzzNow); err == nil {
			t.Fatal("a changed body verified")
		}
	})
}

// FuzzV2RoundTrip: an OBS v2 signature over any request verifies.
func FuzzV2RoundTrip(f *testing.F) {
	f.Add("PUT", "/bucket/key", "acl", "v")
	f.Add("GET", "/bucket/a%20b", "uploads&prefix=x", "")
	f.Fuzz(func(t *testing.T, method, path, query, header string) {
		r := fuzzRequest(method, path, query, "")
		if r == nil {
			return
		}
		if header != "" && !strings.ContainsAny(header, "\r\n\x00") {
			r.Header.Set("X-Obs-Meta-Fuzz", header)
		}
		resource := r.URL.EscapedPath()
		SignV2(r, SchemeOBS, "FUZZAK", "fuzz-secret", resource, fuzzNow)
		a, ok, err := ParseV2(r)
		if !ok || err != nil {
			t.Fatalf("parsing our own signature: %v, %v", ok, err)
		}
		if err := VerifyV2(r, a, "fuzz-secret", []string{resource}, fuzzNow); err != nil {
			t.Fatalf("our own signature does not verify: %v (%s %s?%s)", err, method, path, query)
		}
	})
}

// FuzzV4RoundTrip: an S3 v4 signature over any request verifies.
func FuzzV4RoundTrip(f *testing.F) {
	f.Add("GET", "/bucket/key", "list-type=2&prefix=a")
	f.Add("PUT", "/bucket/a%20b/c", "partNumber=1&uploadId=x")
	f.Fuzz(func(t *testing.T, method, path, query string) {
		r := fuzzRequest(method, path, query, "")
		if r == nil {
			return
		}
		escaped := r.URL.EscapedPath()
		SignV4(r, "FUZZAK", "fuzz-secret", "ap-southeast-1", escaped, "UNSIGNED-PAYLOAD", fuzzNow)
		a, ok, err := ParseV4(r)
		if !ok || err != nil {
			t.Fatalf("parsing our own signature: %v, %v", ok, err)
		}
		if _, err := VerifyV4(r, a, "fuzz-secret", []string{escaped}, fuzzNow); err != nil {
			t.Fatalf("our own signature does not verify: %v (%s %s?%s)", err, method, path, query)
		}
	})
}
