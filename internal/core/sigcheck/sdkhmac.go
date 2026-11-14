// Package sigcheck verifies request signatures the way Huawei Cloud's
// gateways do, for -iam=enforce.
//
// SDK-HMAC-SHA256 is the API gateway's algorithm, used by the official
// SDKs, Terraform's provider and KooCLI. It follows the signers in
// huaweicloud-sdk-go-v3 (core/auth/signer/signer.go) and in
// chnsz/golangsdk (auth/core/signer), which agree on the canonical form
// and differ only in which headers and which path they sign; the
// Authorization header names the signed headers, and the caller passes
// every path a client may have signed.
package sigcheck

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SDKHMAC is the API gateway's signing algorithm.
const SDKHMAC = "SDK-HMAC-SHA256"

// The headers the algorithm uses.
const (
	headerDate          = "X-Sdk-Date"
	headerContentSHA256 = "X-Sdk-Content-Sha256"
	dateFormat          = "20060102T150405Z"
)

// MaxSkew is how far a request's signing time may be from the gateway's
// clock: 15 minutes, as Huawei documents.
const MaxSkew = 15 * time.Minute

// Errors a verification returns.
var (
	// ErrMalformed is an Authorization header or date that cannot be
	// read.
	ErrMalformed = errors.New("sigcheck: malformed authorization")
	// ErrSkewed is a signing time more than MaxSkew from now.
	ErrSkewed = errors.New("sigcheck: signing time too far from now")
	// ErrMismatch is a signature that does not match.
	ErrMismatch = errors.New("sigcheck: signature does not match")
)

// SDKHMACAuth is a parsed SDK-HMAC-SHA256 Authorization header.
type SDKHMACAuth struct {
	AccessKey     string
	SignedHeaders []string
	Signature     string
}

// ParseSDKHMAC reads "SDK-HMAC-SHA256 Access=AK, SignedHeaders=a;b,
// Signature=hex".
func ParseSDKHMAC(authorization string) (SDKHMACAuth, error) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(authorization), " ")
	if !ok || scheme != SDKHMAC {
		return SDKHMACAuth{}, ErrMalformed
	}
	var a SDKHMACAuth
	for part := range strings.SplitSeq(rest, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "Access":
			a.AccessKey = v
		case "SignedHeaders":
			if v != "" {
				a.SignedHeaders = strings.Split(v, ";")
			}
		case "Signature":
			a.Signature = v
		}
	}
	if a.AccessKey == "" || a.Signature == "" {
		return SDKHMACAuth{}, ErrMalformed
	}
	return a, nil
}

// VerifySDKHMAC checks r's SDK-HMAC-SHA256 signature with secret. body
// is the request body, needed unless X-Sdk-Content-Sha256 gives its
// hash. paths are the paths the client may have signed; the first that
// matches wins. The date must be within MaxSkew of now.
func VerifySDKHMAC(r *http.Request, a SDKHMACAuth, secret string, body []byte, paths []string, now time.Time) error {
	date := r.Header.Get(headerDate)
	t, err := time.Parse(dateFormat, date)
	if err != nil {
		return ErrMalformed
	}
	if d := now.Sub(t); d > MaxSkew || d < -MaxSkew {
		return ErrSkewed
	}
	bodyHash := r.Header.Get(headerContentSHA256)
	if bodyHash == "" {
		sum := sha256.Sum256(body)
		bodyHash = hex.EncodeToString(sum[:])
	}
	query := canonicalQuery(r.URL.RawQuery)
	headers := canonicalHeaders(r, a.SignedHeaders)
	signed := strings.Join(a.SignedHeaders, ";")
	want, err := hex.DecodeString(a.Signature)
	if err != nil {
		return ErrMalformed
	}
	for _, p := range paths {
		canonical := strings.Join([]string{r.Method, canonicalURI(p), query, headers, signed, bodyHash}, "\n")
		crHash := sha256.Sum256([]byte(canonical))
		toSign := SDKHMAC + "\n" + date + "\n" + hex.EncodeToString(crHash[:])
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(toSign))
		if subtle.ConstantTimeCompare(mac.Sum(nil), want) == 1 {
			return nil
		}
	}
	return ErrMismatch
}

// canonicalURI escapes each segment of the (unescaped) path and ends it
// with "/", as both signers do.
func canonicalURI(path string) string {
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = escape(s)
	}
	u := strings.Join(segments, "/")
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	return u
}

// canonicalQuery sorts the query by key, and each key's values, escaping
// both.
func canonicalQuery(raw string) string {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		values := append([]string(nil), q[k]...)
		sort.Strings(values)
		for _, v := range values {
			parts = append(parts, escape(k)+"="+escape(v))
		}
	}
	return strings.Join(parts, "&")
}

// canonicalHeaders writes "name:value\n" for each signed header, each
// value trimmed, values sorted; host is the request's Host.
func canonicalHeaders(r *http.Request, signed []string) string {
	var b strings.Builder
	for _, name := range signed {
		var values []string
		if name == "host" {
			values = []string{r.Host}
		} else {
			values = append(values, r.Header.Values(name)...)
		}
		sort.Strings(values)
		for _, v := range values {
			b.WriteString(name)
			b.WriteByte(':')
			b.WriteString(strings.TrimSpace(v))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// escape percent-encodes everything but A-Z a-z 0-9 _ - ~ . with upper
// case hex, as the signers' escape does.
func escape(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_' || c == '-' || c == '~' || c == '.' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}
