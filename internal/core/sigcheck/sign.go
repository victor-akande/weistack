package sigcheck

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // v2 signatures are HMAC-SHA1
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SignSDKHMAC signs r with SDK-HMAC-SHA256 the way the official Go SDK
// does: it sets X-Sdk-Date, signs every header already on r (as
// golangsdk does), the path given, and body. It is for tests and tools;
// the canonical form is the one VerifySDKHMAC checks, which is tested
// against the real signers.
func SignSDKHMAC(r *http.Request, accessKey, secretKey, path string, body []byte, now time.Time) {
	date := now.UTC().Format(dateFormat)
	r.Header.Set(headerDate, date)
	var signed []string
	for name := range r.Header {
		if lower := strings.ToLower(name); lower != "authorization" {
			signed = append(signed, lower)
		}
	}
	sort.Strings(signed)
	bodyHash := r.Header.Get(headerContentSHA256)
	if bodyHash == "" {
		sum := sha256.Sum256(body)
		bodyHash = hex.EncodeToString(sum[:])
	}
	canonical := strings.Join([]string{
		r.Method, canonicalURI(path), canonicalQuery(r.URL.RawQuery),
		canonicalHeaders(r, signed), strings.Join(signed, ";"), bodyHash,
	}, "\n")
	crHash := sha256.Sum256([]byte(canonical))
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(SDKHMAC + "\n" + date + "\n" + hex.EncodeToString(crHash[:])))
	r.Header.Set("Authorization", SDKHMAC+" Access="+accessKey+", SignedHeaders="+strings.Join(signed, ";")+
		", Signature="+hex.EncodeToString(mac.Sum(nil)))
}

// SignV2 signs r with an OBS or S3 v2 signature in its Authorization
// header, dated now, over resource (the escaped path the server checks,
// with "/bucket" for a virtual-hosted request). For tests and tools.
func SignV2(r *http.Request, scheme, accessKey, secretKey, resource string, now time.Time) {
	date := now.UTC().Format(http.TimeFormat)
	r.Header.Set("Date", date)
	prefix := "x-amz-"
	if scheme == SchemeOBS {
		prefix = "x-obs-"
	}
	r.Header.Set("Authorization", scheme+" "+accessKey+":"+v2Signature(r, secretKey, date, resource, prefix))
}

// signV2 signs with the OBS vectors' secret, over dateLine.
func signV2(r *http.Request, dateLine, resource string) string {
	return v2Signature(r, "obs-vector-secret-key-000000000000000000", dateLine, resource, "x-obs-")
}

func v2Signature(r *http.Request, secretKey, dateLine, resource, prefix string) string {
	toSign := r.Method + "\n" + r.Header.Get("Content-MD5") + "\n" + r.Header.Get("Content-Type") + "\n" +
		dateLine + "\n" + v2Headers(r, prefix) + resource + v2SubResources(r.URL.RawQuery, prefix)
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(toSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// PresignV2 returns the URL-encoded signature of a pre-signed OBS or S3
// v2 URL with no extra headers or sub-resources. For tests and tools.
func PresignV2(method, secretKey, expires, resource string) string {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(method + "\n\n\n" + expires + "\n" + resource))
	return url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

// SignV4 signs r with S3 signature version 4 in its Authorization
// header, for region and service "s3", at now, over path (escaped), with
// payload as x-amz-content-sha256. It signs host, x-amz-content-sha256
// and x-amz-date. For tests and tools.
func SignV4(r *http.Request, accessKey, secretKey, region, path, payload string, now time.Time) {
	amzDate := now.UTC().Format(amzDateFormat)
	date := amzDate[:8]
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payload)
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonical := strings.Join([]string{
		r.Method, path, v4Query(r.URL.RawQuery, false), v4Headers(r, signed, r.Host), strings.Join(signed, ";"), payload,
	}, "\n")
	crHash := sha256.Sum256([]byte(canonical))
	scope := date + "/" + region + "/s3/aws4_request"
	sig := hex.EncodeToString(hmacSHA256(deriveV4Key(secretKey, date, region, "s3"),
		V4+"\n"+amzDate+"\n"+scope+"\n"+hex.EncodeToString(crHash[:])))
	r.Header.Set("Authorization", V4+" Credential="+accessKey+"/"+scope+", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
}
