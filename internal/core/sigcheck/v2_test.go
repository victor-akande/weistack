package sigcheck

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// These vectors were made by the real OBS SDK, huaweicloud-sdk-go-obs
// v3.26.6, with this key pair: requests captured from a PutObject and a
// ListMultipartUploads, and URLs from CreateSignedUrl, signed at
// obsVectorTime.
const (
	obsAK = "AKOBSVECTOR000000000"
	obsSK = "obs-vector-secret-key-000000000000000000"
)

var obsVectorTime = time.Date(2026, 11, 14, 15, 53, 54, 0, time.UTC)

const obsVectorDate = "Sat, 14 Nov 2026 15:53:54 GMT"

func obsRequest(method, target string, headers map[string]string) *http.Request {
	u, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	r := httptest.NewRequest(method, u.RequestURI(), nil)
	r.Host = u.Host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func checkV2(t *testing.T, r *http.Request, resources []string, now time.Time) error {
	t.Helper()
	a, ok, err := ParseV2(r)
	if !ok || err != nil {
		t.Fatalf("ParseV2 = %+v, %v, %v", a, ok, err)
	}
	if a.AccessKey != obsAK {
		t.Fatalf("access key = %q", a.AccessKey)
	}
	return VerifyV2(r, a, obsSK, resources, now)
}

func TestOBSSignatures(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		method, target string
		headers        map[string]string
		resources      []string
	}{
		"OBS, virtual-hosted, with x-obs- headers": {
			http.MethodPut, "https://vec-bucket.obs.ap-southeast-1.myhuaweicloud.com/dir/my%20key.txt",
			map[string]string{
				"Authorization": "OBS " + obsAK + ":bwM8NuwGqnA913xLTJXXN131pRM=", "Date": obsVectorDate,
				"Content-Type": "text/plain", "x-obs-acl": "private", "x-obs-meta-team": "a",
			},
			[]string{"/dir/my%20key.txt", "/vec-bucket/dir/my%20key.txt"},
		},
		"OBS, the bucket with a sub-resource": {
			http.MethodGet, "https://vec-bucket.obs.ap-southeast-1.myhuaweicloud.com/?uploads",
			map[string]string{"Authorization": "OBS " + obsAK + ":fAHqgN3K40L0vcP0f/b/wFKuGv4=", "Date": obsVectorDate},
			[]string{"/", "/vec-bucket/"},
		},
		"AWS v2, path-style, with x-amz- headers": {
			http.MethodPut, "https://obs.ap-southeast-1.myhuaweicloud.com/vec-bucket/dir/my%20key.txt",
			map[string]string{
				"Authorization": "AWS " + obsAK + ":KWvrdk/sPmKgpm/CUIA6SHfDswY=", "Date": obsVectorDate,
				"Content-Type": "text/plain", "x-amz-acl": "private", "x-amz-meta-team": "a",
			},
			[]string{"/vec-bucket/dir/my%20key.txt"},
		},
		"AWS v2, path-style bucket": {
			http.MethodGet, "https://obs.ap-southeast-1.myhuaweicloud.com/vec-bucket?uploads",
			map[string]string{"Authorization": "AWS " + obsAK + ":hDAQYa/MuZGkhpO5jzKznqY28NQ=", "Date": obsVectorDate},
			[]string{"/vec-bucket"},
		},
		"pre-signed, OBS": {
			http.MethodGet, "https://vec-bucket.obs.ap-southeast-1.myhuaweicloud.com/dir/my%20key.txt?response-content-type=text%2Fplain" +
				"&AccessKeyId=" + obsAK + "&Expires=1794675234&Signature=vO30TUpFhfcK5EHCkx5aE91cLnw%3D",
			nil, []string{"/dir/my%20key.txt", "/vec-bucket/dir/my%20key.txt"},
		},
		"pre-signed, AWS": {
			http.MethodGet, "https://obs.ap-southeast-1.myhuaweicloud.com/vec-bucket/dir/my%20key.txt?response-content-type=text%2Fplain" +
				"&AWSAccessKeyId=" + obsAK + "&Expires=1794675234&Signature=vO30TUpFhfcK5EHCkx5aE91cLnw%3D",
			nil, []string{"/vec-bucket/dir/my%20key.txt"},
		},
	} {
		r := obsRequest(tc.method, tc.target, tc.headers)
		if err := checkV2(t, r, tc.resources, obsVectorTime); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOBSSignaturesRejected(t *testing.T) {
	t.Parallel()
	put := func(change func(*http.Request)) *http.Request {
		r := obsRequest(http.MethodPut, "https://vec-bucket.obs.ap-southeast-1.myhuaweicloud.com/dir/my%20key.txt", map[string]string{
			"Authorization": "OBS " + obsAK + ":bwM8NuwGqnA913xLTJXXN131pRM=", "Date": obsVectorDate,
			"Content-Type": "text/plain", "x-obs-acl": "private", "x-obs-meta-team": "a",
		})
		if change != nil {
			change(r)
		}
		return r
	}
	resources := []string{"/vec-bucket/dir/my%20key.txt"}
	for name, tc := range map[string]struct {
		r    *http.Request
		now  time.Time
		want error
	}{
		"changed x-obs- header": {put(func(r *http.Request) { r.Header.Set("x-obs-acl", "public-read") }), obsVectorTime, ErrMismatch},
		"added x-obs- header":   {put(func(r *http.Request) { r.Header.Set("x-obs-storage-class", "COLD") }), obsVectorTime, ErrMismatch},
		"changed content type":  {put(func(r *http.Request) { r.Header.Set("Content-Type", "text/html") }), obsVectorTime, ErrMismatch},
		"changed method":        {put(func(r *http.Request) { r.Method = http.MethodDelete }), obsVectorTime, ErrMismatch},
		"too late":              {put(nil), obsVectorTime.Add(16 * time.Minute), ErrSkewed},
		"no date":               {put(func(r *http.Request) { r.Header.Del("Date") }), obsVectorTime, ErrNoDate},
	} {
		if err := checkV2(t, tc.r, resources, tc.now); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// A pre-signed URL expires.
	r := obsRequest(http.MethodGet, "https://vec-bucket.obs.ap-southeast-1.myhuaweicloud.com/dir/my%20key.txt?response-content-type=text%2Fplain"+
		"&AccessKeyId="+obsAK+"&Expires=1794675234&Signature=vO30TUpFhfcK5EHCkx5aE91cLnw%3D", nil)
	if err := checkV2(t, r, resources, obsVectorTime.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Errorf("an expired URL: %v", err)
	}
	// A changed sub-resource breaks it; an unsigned query parameter does
	// not.
	changed := obsRequest(http.MethodGet, "https://vec-bucket.obs.ap-southeast-1.myhuaweicloud.com/dir/my%20key.txt?response-content-type=text%2Fhtml"+
		"&AccessKeyId="+obsAK+"&Expires=1794675234&Signature=vO30TUpFhfcK5EHCkx5aE91cLnw%3D", nil)
	if err := checkV2(t, changed, resources, obsVectorTime); !errors.Is(err, ErrMismatch) {
		t.Errorf("a changed sub-resource: %v", err)
	}
	extra := obsRequest(http.MethodGet, "https://vec-bucket.obs.ap-southeast-1.myhuaweicloud.com/dir/my%20key.txt?response-content-type=text%2Fplain"+
		"&AccessKeyId="+obsAK+"&Expires=1794675234&Signature=vO30TUpFhfcK5EHCkx5aE91cLnw%3D&cachebuster=1", nil)
	if err := checkV2(t, extra, resources, obsVectorTime); err != nil {
		t.Errorf("an unsigned extra parameter: %v", err)
	}
}

func TestOBSDateHeader(t *testing.T) {
	t.Parallel()
	// With x-obs-date, its time is the one checked; the Date line may hold
	// the Date header (as the OBS SDK signs) or be empty (as S3 does).
	r := obsRequest(http.MethodGet, "https://b.obs.ap-southeast-1.myhuaweicloud.com/k", map[string]string{
		"x-obs-date": obsVectorDate, "Date": "Mon, 01 Jan 2024 00:00:00 GMT",
	})
	for _, dateLine := range []string{"Mon, 01 Jan 2024 00:00:00 GMT", ""} {
		r.Header.Set("Authorization", SchemeOBS+" "+obsAK+":"+signV2(r, dateLine, "/b/k"))
		if err := checkV2(t, r, []string{"/b/k"}, obsVectorTime); err != nil {
			t.Errorf("Date line %q: %v", dateLine, err)
		}
	}
}

func TestParseV2(t *testing.T) {
	t.Parallel()
	for _, h := range []string{"OBS nocolon", "AWS :sig", "OBS ak:"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", h)
		if _, ok, err := ParseV2(r); !ok || !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v %v", h, ok, err)
		}
	}
	for _, target := range []string{"/?AccessKeyId=ak&Expires=1", "/?AWSAccessKeyId=ak&Signature=s"} {
		if _, ok, err := ParseV2(httptest.NewRequest(http.MethodGet, target, nil)); !ok || !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v %v", target, ok, err)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "SDK-HMAC-SHA256 Access=x")
	if _, ok, _ := ParseV2(r); ok {
		t.Error("an SDK-HMAC header parsed as v2")
	}
}

func TestHostBucket(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]string{
		"My-Bucket.obs.ap-southeast-1.myhuaweicloud.com": "My-Bucket",
		"a.b.obs.ap-southeast-1.myhuaweicloud.com:443":   "a.b",
		"obs.obs.ap-southeast-1.myhuaweicloud.com":       "obs",
		"bucket.obs.localhost":                           "bucket",
		"obs.ap-southeast-1.myhuaweicloud.com":           "",
		"vpc.ap-southeast-1.myhuaweicloud.com":           "",
		"bucket.obs.localhost.example.com":               "",
	} {
		if got := HostBucketAsSent(host); got != want {
			t.Errorf("HostBucketAsSent(%q) = %q, want %q", host, got, want)
		}
		if got := HostBucket(host); got != strings.ToLower(want) {
			t.Errorf("HostBucket(%q) = %q", host, got)
		}
	}
}
