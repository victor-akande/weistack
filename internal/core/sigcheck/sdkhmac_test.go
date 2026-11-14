package sigcheck

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The vectors below were made by the real signers, not by this package:
// huaweicloud-sdk-go-v3 v0.1.222 (core/auth/signer.Sign) and golangsdk
// c09fbaa891fe (auth/core/signer.Signer.Sign), with this key pair and
// X-Sdk-Date 20261114T120000Z.
const (
	vectorAK   = "AKVECTOR000000000000"
	vectorSK   = "vector-secret-key-0000000000000000000000"
	vectorDate = "20261114T120000Z"
)

var vectorTime = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// sdkRequest is what the Go SDK sent for a POST to the endpoint
// http://127.0.0.1:8780/vpc: it signed the operation path only, without
// the endpoint's /vpc.
func sdkRequest() (*http.Request, string) {
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8780/vpc/v1/0123456789abcdef0123456789abcdef/vpcs?limit=10&name=a+b%2Fc",
		strings.NewReader(sdkBody))
	r.Header.Set("X-Sdk-Date", vectorDate)
	r.Header.Set("X-Project-Id", "0123456789abcdef0123456789abcdef")
	r.Header.Set("Content-Type", "application/json")
	auth := "SDK-HMAC-SHA256 Access=" + vectorAK + ", SignedHeaders=x-project-id;x-sdk-date, " +
		"Signature=396e8891de312d30b53126593907de63ab287a99a4313a0e2beaff5b86fd5380"
	r.Header.Set("Authorization", auth)
	return r, sdkBody
}

// sdkBody is the body the SDK sent and signed: its JSON encoder ends it
// with a newline.
const sdkBody = "{\"vpc\":{\"name\":\"v\"}}\n"

// golangsdkRequest is what Terraform's golangsdk sent: it signed every
// header, Host included, and the full path.
func golangsdkRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://vpc.ap-southeast-1.myhuaweicloud.com/v1/0123456789abcdef0123456789abcdef/vpcs?limit=5&marker=x", nil)
	r.Header.Set("X-Sdk-Date", vectorDate)
	r.Header.Set("User-Agent", "terraform")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "SDK-HMAC-SHA256 Access="+vectorAK+", SignedHeaders=content-type;host;user-agent;x-sdk-date, "+
		"Signature=22f07bf3064deefef56a8d2596706242e5aa328889954b9728dd4507ca73cdf6")
	return r
}

func verify(t *testing.T, r *http.Request, body string, paths []string, now time.Time) error {
	t.Helper()
	a, err := ParseSDKHMAC(r.Header.Get("Authorization"))
	if err != nil {
		t.Fatal(err)
	}
	if a.AccessKey != vectorAK {
		t.Fatalf("access key = %q", a.AccessKey)
	}
	return VerifySDKHMAC(r, a, vectorSK, []byte(body), paths, now)
}

func TestSDKSignatures(t *testing.T) {
	t.Parallel()
	r, body := sdkRequest()
	full := r.URL.Path
	stripped := strings.TrimPrefix(full, "/vpc")

	// The SDK signed the path without the endpoint's prefix: only the
	// stripped candidate matches.
	if err := verify(t, r, body, []string{full, stripped}, vectorTime); err != nil {
		t.Fatalf("SDK request: %v", err)
	}
	if err := verify(t, r, body, []string{full}, vectorTime); !errors.Is(err, ErrMismatch) {
		t.Fatalf("SDK request against the full path: %v", err)
	}

	g := golangsdkRequest()
	if err := verify(t, g, "", []string{g.URL.Path}, vectorTime); err != nil {
		t.Fatalf("golangsdk request: %v", err)
	}
}

func TestSDKSignaturesRejected(t *testing.T) {
	t.Parallel()
	paths := func(r *http.Request) []string { return []string{strings.TrimPrefix(r.URL.Path, "/vpc")} }

	for name, tc := range map[string]struct {
		change func(r *http.Request) (body string)
		now    time.Time
		want   error
	}{
		"changed body":  {func(*http.Request) string { return `{"vpc":{"name":"w"}}` }, vectorTime, ErrMismatch},
		"changed query": {func(r *http.Request) string { r.URL.RawQuery = "limit=11&name=a+b%2Fc"; return sdkBody }, vectorTime, ErrMismatch},
		"changed header": {func(r *http.Request) string {
			r.Header.Set("X-Project-Id", "ffffffffffffffffffffffffffffffff")
			return sdkBody
		}, vectorTime, ErrMismatch},
		"changed method": {func(r *http.Request) string { r.Method = http.MethodPut; return sdkBody }, vectorTime, ErrMismatch},
		"too old":        {func(*http.Request) string { return sdkBody }, vectorTime.Add(16 * time.Minute), ErrSkewed},
		"too new":        {func(*http.Request) string { return sdkBody }, vectorTime.Add(-16 * time.Minute), ErrSkewed},
		"no date": {func(r *http.Request) string {
			r.Header.Del("X-Sdk-Date")
			return sdkBody
		}, vectorTime, ErrMalformed},
	} {
		r, _ := sdkRequest()
		body := tc.change(r)
		if err := verify(t, r, body, paths(r), tc.now); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	// Within 15 minutes either way is fine.
	r, body := sdkRequest()
	if err := verify(t, r, body, paths(r), vectorTime.Add(14*time.Minute)); err != nil {
		t.Errorf("14 minutes late: %v", err)
	}

	// The wrong secret.
	a, _ := ParseSDKHMAC(r.Header.Get("Authorization"))
	if err := VerifySDKHMAC(r, a, "another-secret", []byte(body), paths(r), vectorTime); !errors.Is(err, ErrMismatch) {
		t.Errorf("wrong secret: %v", err)
	}
}

func TestUnsignedPayload(t *testing.T) {
	t.Parallel()
	// With X-Sdk-Content-Sha256, the body is not hashed: the header's
	// value stands in for it, and changing the body changes nothing.
	r := golangsdkRequest()
	r.Header.Set("X-Sdk-Content-Sha256", "UNSIGNED-PAYLOAD")
	a, _ := ParseSDKHMAC(r.Header.Get("Authorization"))
	err1 := VerifySDKHMAC(r, a, vectorSK, []byte("one"), []string{r.URL.Path}, vectorTime)
	err2 := VerifySDKHMAC(r, a, vectorSK, []byte("two"), []string{r.URL.Path}, vectorTime)
	if !errors.Is(err1, ErrMismatch) || !errors.Is(err2, ErrMismatch) {
		t.Fatalf("UNSIGNED-PAYLOAD replaced the hash the vector signed: %v, %v", err1, err2)
	}
}

func TestParseSDKHMAC(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"", "SDK-HMAC-SHA256", "OBS AK:sig", "SDK-HMAC-SHA256 SignedHeaders=a, Signature=b",
		"SDK-HMAC-SHA256 Access=AK, SignedHeaders=a",
	} {
		if _, err := ParseSDKHMAC(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	a, err := ParseSDKHMAC("SDK-HMAC-SHA256 Access=AK1, SignedHeaders=host;x-sdk-date, Signature=abc")
	if err != nil || a.AccessKey != "AK1" || strings.Join(a.SignedHeaders, ",") != "host,x-sdk-date" || a.Signature != "abc" {
		t.Fatalf("parsed = %+v, %v", a, err)
	}
}

func TestEscape(t *testing.T) {
	t.Parallel()
	if got := escape("a b/c~._-Z9é"); got != "a%20b%2Fc~._-Z9%C3%A9" {
		t.Fatalf("escape = %q", got)
	}
	if got := canonicalURI("/v1/p/vpcs"); got != "/v1/p/vpcs/" {
		t.Fatalf("canonicalURI = %q", got)
	}
	if got := canonicalQuery("b=2&a=z&a=y&c"); got != "a=y&a=z&b=2&c=" {
		t.Fatalf("canonicalQuery = %q", got)
	}
}

func TestSignRoundTrip(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "http://ecs.localhost/v1/p/cloudservers?limit=2", strings.NewReader("{}"))
	r.Header.Set("X-Project-Id", "p")
	SignSDKHMAC(r, vectorAK, vectorSK, r.URL.Path, []byte("{}"), vectorTime)
	if err := verify(t, r, "{}", []string{r.URL.Path}, vectorTime); err != nil {
		t.Fatal(err)
	}
}
