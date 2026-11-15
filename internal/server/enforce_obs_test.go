package server

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

// obsSend serves an OBS request, signed with a v2 signature over resource
// when ak is set, and returns the status and the XML error code.
func (e *enforceEnv) obsSend(t *testing.T, target, scheme, ak, sk, resource string, at time.Time, header ...string) (int, string) {
	t.Helper()
	r := request(http.MethodGet, target, "")
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	if ak != "" {
		sigcheck.SignV2(r, scheme, ak, sk, resource, at)
	}
	w := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(w, r)
	var body struct {
		Code string `xml:"Code"`
	}
	_ = xml.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body.Code
}

// reached reports a request that got past the credential check to the
// fake service, which answers 200, or 501 for a path it has no route for.
func reached(code int) bool { return code == http.StatusOK || code == http.StatusNotImplemented }

func TestEnforceOBS(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMEnforce)
	const pathStyle = "http://obs.ap-southeast-1.myhuaweicloud.com/bucket/v1/" + testProject + "/things"
	const virtual = "http://bucket.obs.ap-southeast-1.myhuaweicloud.com/v1/" + testProject + "/things"
	const prefixed = "http://127.0.0.1:8780/obs/bucket/v1/" + testProject + "/things"
	resource := "/bucket/v1/" + testProject + "/things"

	for name, tc := range map[string]struct {
		target, scheme, signedOver string
	}{
		"OBS, virtual-hosted":       {virtual, sigcheck.SchemeOBS, resource},
		"AWS v2, path-style":        {pathStyle, sigcheck.SchemeAWS, resource},
		"by prefix, over the rest":  {prefixed, sigcheck.SchemeOBS, resource},
		"by prefix, over all of it": {prefixed, sigcheck.SchemeOBS, "/obs" + resource},
	} {
		if code, errCode := e.obsSend(t, tc.target, tc.scheme, userKey, userSecret, tc.signedOver, enforceNow); !reached(code) {
			t.Errorf("%s: %d %s", name, code, errCode)
		}
	}

	for name, tc := range map[string]struct {
		ak, sk  string
		at      time.Time
		header  []string
		status  int
		errCode string
	}{
		"anonymous":     {status: 403, errCode: "AccessDenied"},
		"unknown key":   {ak: "UNKNOWNKEY0000000000", sk: userSecret, at: enforceNow, status: 403, errCode: "InvalidAccessKeyId"},
		"disabled user": {ak: disabledKey, sk: userSecret, at: enforceNow, status: 403, errCode: "InvalidAccessKeyId"},
		"wrong secret":  {ak: userKey, sk: "wrong", at: enforceNow, status: 403, errCode: "SignatureDoesNotMatch"},
		"skewed clock":  {ak: userKey, sk: userSecret, at: enforceNow.Add(-20 * time.Minute), status: 403, errCode: "RequestTimeTooSkewed"},
		"malformed":     {header: []string{"Authorization", "OBS no-colon"}, status: 403, errCode: "SignatureDoesNotMatch"},
	} {
		if code, errCode := e.obsSend(t, pathStyle, sigcheck.SchemeOBS, tc.ak, tc.sk, resource, tc.at, tc.header...); code != tc.status || errCode != tc.errCode {
			t.Errorf("%s: %d %s, want %d %s", name, code, errCode, tc.status, tc.errCode)
		}
	}

	// S3 signature version 4.
	v4 := func(ak, sk, path string, header ...string) (int, string) {
		t.Helper()
		r := request(http.MethodGet, pathStyle, "")
		for i := 0; i+1 < len(header); i += 2 {
			r.Header.Set(header[i], header[i+1])
		}
		if ak != "" {
			sigcheck.SignV4(r, ak, sk, "ap-southeast-1", path, "UNSIGNED-PAYLOAD", enforceNow)
		}
		w := httptest.NewRecorder()
		e.srv.Handler().ServeHTTP(w, r)
		var body struct {
			Code string `xml:"Code"`
		}
		_ = xml.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body.Code
	}
	if code, errCode := v4(userKey, userSecret, resource); !reached(code) {
		t.Errorf("SigV4 = %d %s", code, errCode)
	}
	for name, tc := range map[string]struct {
		ak, sk  string
		header  []string
		errCode string
	}{
		"SigV4, wrong secret": {ak: userKey, sk: "wrong", errCode: "SignatureDoesNotMatch"},
		"SigV4, unknown key":  {ak: "UNKNOWNKEY0000000000", sk: userSecret, errCode: "InvalidAccessKeyId"},
		"SigV4, malformed":    {header: []string{"Authorization", "AWS4-HMAC-SHA256 Credential=x"}, errCode: "SignatureDoesNotMatch"},
	} {
		if code, errCode := v4(tc.ak, tc.sk, resource, tc.header...); code != 403 || errCode != tc.errCode {
			t.Errorf("%s: %d %s, want 403 %s", name, code, errCode, tc.errCode)
		}
	}
}

func TestEnforceOBSPresigned(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMEnforce)
	resource := "/bucket/v1/" + testProject + "/things"
	presigned := func(expires time.Time, secret string) string {
		exp := strconv.FormatInt(expires.Unix(), 10)
		// A pre-signed URL signs Expires in place of the date.
		sig := sigcheck.PresignV2(http.MethodGet, secret, exp, resource)
		return "http://obs.localhost" + resource + "?AccessKeyId=" + userKey + "&Expires=" + exp + "&Signature=" + sig
	}
	if code, errCode := e.obsSend(t, presigned(enforceNow.Add(time.Hour), userSecret), "", "", "", "", enforceNow); !reached(code) {
		t.Fatalf("valid URL = %d %s", code, errCode)
	}
	if code, errCode := e.obsSend(t, presigned(enforceNow.Add(-time.Second), userSecret), "", "", "", "", enforceNow); code != 403 || errCode != "AccessDenied" {
		t.Fatalf("expired URL = %d %s", code, errCode)
	}
	if code, errCode := e.obsSend(t, presigned(enforceNow.Add(time.Hour), "wrong"), "", "", "", "", enforceNow); code != 403 || errCode != "SignatureDoesNotMatch" {
		t.Fatalf("wrong signature = %d %s", code, errCode)
	}
}

func TestEnforceOBSLockout(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMEnforce)
	const target = "http://obs.localhost/bucket/key"
	for range identity.MaxFailures + 1 {
		e.obsSend(t, target, sigcheck.SchemeOBS, userKey, "wrong", "/bucket/key", enforceNow)
	}
	if code, errCode := e.obsSend(t, target, sigcheck.SchemeOBS, userKey, userSecret, "/bucket/key", enforceNow); code != 400 || errCode != "TooManyWrongSignature" {
		t.Fatalf("after six failures = %d %s", code, errCode)
	}
}
