package sigcheck

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
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
