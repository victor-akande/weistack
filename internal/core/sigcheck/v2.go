package sigcheck

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is what OBS and S3 v2 signatures are
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// OBS's own signature and S3 signature version 2, in an Authorization
// header ("OBS AK:sig", "AWS AK:sig") or in a pre-signed URL
// (AccessKeyId or AWSAccessKeyId, Expires, Signature). They follow
// huaweicloud-sdk-go-obs v3.26.6 (auth.go, authV2.go, conf.go formatUrls)
// and Huawei's API reference (api-obs obs_04_0010 and obs_04_0011):
//
//	Base64(HMAC-SHA1(SK, Verb \n Content-MD5 \n Content-Type \n Date \n
//	CanonicalizedHeaders CanonicalizedResource))

// V2 schemes.
const (
	SchemeOBS = "OBS"
	SchemeAWS = "AWS"
)

// More errors.
var (
	// ErrNoDate is a header-signed request with neither Date nor
	// x-obs-date (x-amz-date).
	ErrNoDate = errors.New("sigcheck: no date")
	// ErrExpired is a pre-signed URL past its Expires.
	ErrExpired = errors.New("sigcheck: pre-signed URL expired")
)

// V2Auth is a parsed v2 signature.
type V2Auth struct {
	// Scheme is SchemeOBS (x-obs- headers) or SchemeAWS (x-amz-).
	Scheme    string
	AccessKey string
	Signature string
	// Presigned marks a signature in the query, valid until Expires.
	Presigned bool
	Expires   string
}

// ParseV2 finds a v2 signature in r: the Authorization header, or the
// query of a pre-signed URL. ok is false if r carries neither.
func ParseV2(r *http.Request) (a V2Auth, ok bool, err error) {
	if authz := strings.TrimSpace(r.Header.Get("Authorization")); authz != "" {
		scheme, rest, _ := strings.Cut(authz, " ")
		if scheme != SchemeOBS && scheme != SchemeAWS {
			return V2Auth{}, false, nil
		}
		ak, sig, found := strings.Cut(strings.TrimSpace(rest), ":")
		if !found || ak == "" || sig == "" {
			return V2Auth{}, true, ErrMalformed
		}
		return V2Auth{Scheme: scheme, AccessKey: ak, Signature: sig}, true, nil
	}
	q := r.URL.Query()
	a = V2Auth{Presigned: true, Signature: q.Get("Signature"), Expires: q.Get("Expires")}
	switch {
	case q.Get("AccessKeyId") != "":
		a.Scheme, a.AccessKey = SchemeOBS, q.Get("AccessKeyId")
	case q.Get("AWSAccessKeyId") != "":
		a.Scheme, a.AccessKey = SchemeAWS, q.Get("AWSAccessKeyId")
	default:
		return V2Auth{}, false, nil
	}
	if a.Signature == "" || a.Expires == "" {
		return V2Auth{}, true, ErrMalformed
	}
	return a, true, nil
}

// VerifyV2 checks a v2 signature with secret. resources are the paths
// the client may have signed, as sent (escaped): for a path-style
// request the path itself, for a virtual-hosted one "/bucket" and the
// path. Header-signed requests must be dated within MaxSkew of now;
// pre-signed ones must not have expired.
func VerifyV2(r *http.Request, a V2Auth, secret string, resources []string, now time.Time) error {
	want, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return ErrMalformed
	}
	prefix := "x-amz-"
	if a.Scheme == SchemeOBS {
		prefix = "x-obs-"
	}
	// The Date line: Expires for a pre-signed URL. Otherwise Date, which
	// Huawei's docs say x-obs-date overrides; the OBS SDK still signs the
	// Date header's value while S3 signs an empty line, so both pass.
	var dates []string
	if a.Presigned {
		exp, err := strconv.ParseInt(a.Expires, 10, 64)
		if err != nil {
			return ErrMalformed
		}
		if !now.Before(time.Unix(exp, 0)) {
			return ErrExpired
		}
		dates = []string{a.Expires}
	} else {
		dateHeader := r.Header.Get(prefix + "date")
		date := r.Header.Get("Date")
		effective := dateHeader
		if effective == "" {
			effective = date
		}
		if effective == "" {
			return ErrNoDate
		}
		t, err := http.ParseTime(effective)
		if err != nil {
			return ErrNoDate
		}
		if d := now.Sub(t); d > MaxSkew || d < -MaxSkew {
			return ErrSkewed
		}
		dates = []string{date}
		if dateHeader != "" && date != "" {
			dates = append(dates, "")
		}
	}

	headers := v2Headers(r, prefix)
	sub := v2SubResources(r.URL.RawQuery, prefix)
	for _, res := range resources {
		for _, date := range dates {
			toSign := r.Method + "\n" + r.Header.Get("Content-MD5") + "\n" + r.Header.Get("Content-Type") + "\n" +
				date + "\n" + headers + res + sub
			mac := hmac.New(sha1.New, []byte(secret))
			mac.Write([]byte(toSign))
			if subtle.ConstantTimeCompare(mac.Sum(nil), want) == 1 {
				return nil
			}
		}
	}
	return ErrMismatch
}

// v2Headers writes the x-obs- (or x-amz-) headers, lower-cased and
// sorted, each "name:value\n", values joined with ",".
func v2Headers(r *http.Request, prefix string) string {
	values := map[string][]string{}
	var names []string
	for name, vs := range r.Header {
		lower := strings.ToLower(strings.TrimSpace(name))
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		if _, seen := values[lower]; !seen {
			names = append(names, lower)
		}
		for _, v := range vs {
			values[lower] = append(values[lower], strings.TrimSpace(v))
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(strings.Join(values[n], ","))
		b.WriteByte('\n')
	}
	return b.String()
}

// v2SubResources returns the sub-resources of the canonical resource:
// "?" and the query parameters OBS signs, sorted, as "key" or
// "key=value" with the key escaped and the value not.
func v2SubResources(rawQuery, prefix string) string {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	var keys []string
	for k := range q {
		lower := strings.ToLower(k)
		if signedSubResources[lower] || strings.HasPrefix(lower, prefix) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		part := url.QueryEscape(k)
		if v := q.Get(k); v != "" {
			part += "=" + v
		}
		parts = append(parts, part)
	}
	return "?" + strings.Join(parts, "&")
}

// signedSubResources is the OBS SDK's allowedResourceParameterNames
// (const.go): the query parameters a v2 signature covers.
var signedSubResources = map[string]bool{
	"acl": true, "backtosource": true, "metadata": true, "policy": true, "torrent": true, "logging": true,
	"location": true, "storageinfo": true, "quota": true, "storageclass": true, "storagepolicy": true,
	"requestpayment": true, "versions": true, "versioning": true, "versionid": true, "uploads": true,
	"uploadid": true, "partnumber": true, "website": true, "notification": true, "lifecycle": true,
	"deletebucket": true, "delete": true, "cors": true, "restore": true, "encryption": true, "tagging": true,
	"append": true, "modify": true, "position": true, "replication": true, "response-content-type": true,
	"response-content-language": true, "response-expires": true, "response-cache-control": true,
	"response-content-disposition": true, "response-content-encoding": true, "x-image-process": true,
	"x-oss-process": true, "x-image-save-bucket": true, "x-image-save-object": true, "ignore-sign-in-query": true,
	"name": true, "rename": true, "customdomain": true, "mirrorbacktosource": true, "x-obs-accesslabel": true,
	"object-lock": true, "retention": true, "x-obs-security-token": true, "truncate": true, "length": true,
	"inventory": true, "directcoldaccess": true, "attname": true, "cdnnotifyconfiguration": true,
	"publicaccessblock": true, "bucketstatus": true, "policystatus": true, "obscompresspolicy": true,
	"dispolicy": true,
}
