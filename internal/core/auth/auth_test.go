package auth

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers map[string]string
		want    Identity
	}{
		{
			name: "no credentials",
			want: Identity{Scheme: SchemeNone},
		},
		{
			name: "huawei sdk signing",
			headers: map[string]string{
				"Authorization": "SDK-HMAC-SHA256 Access=AKEXAMPLE123, SignedHeaders=host;x-sdk-date, Signature=deadbeef",
				"X-Project-Id":  "0123456789abcdef0123456789abcdef",
			},
			want: Identity{Scheme: SchemeSDKHMAC, AccessKey: "AKEXAMPLE123", ProjectID: "0123456789abcdef0123456789abcdef"},
		},
		{
			name: "huawei sdk signing with temporary credentials",
			headers: map[string]string{
				"Authorization":    "SDK-HMAC-SHA256 Access=AKTEMP, SignedHeaders=host, Signature=ff",
				"X-Security-Token": "sts-token",
			},
			want: Identity{Scheme: SchemeSDKHMAC, AccessKey: "AKTEMP", Temporary: true},
		},
		{
			name:    "obs header signing",
			headers: map[string]string{"Authorization": "OBS AKOBS:c2lnbmF0dXJl"},
			want:    Identity{Scheme: SchemeOBS, AccessKey: "AKOBS"},
		},
		{
			name:    "s3 v2 signing",
			headers: map[string]string{"Authorization": "AWS AKV2:c2lnbmF0dXJl"},
			want:    Identity{Scheme: SchemeAWSV2, AccessKey: "AKV2"},
		},
		{
			name: "s3 v4 signing",
			headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=AKV4/20261110/ap-southeast-1/s3/aws4_request, SignedHeaders=host, Signature=ab",
			},
			want: Identity{Scheme: SchemeAWSV4, AccessKey: "AKV4"},
		},
		{
			name:    "iam token",
			headers: map[string]string{"X-Auth-Token": "MIIF..."},
			want:    Identity{Scheme: SchemeToken, HasToken: true},
		},
		{
			name:    "unknown scheme is kept, nothing else guessed",
			headers: map[string]string{"Authorization": "Bearer abc.def"},
			want:    Identity{Scheme: "Bearer"},
		},
		{
			name:    "malformed sdk header",
			headers: map[string]string{"Authorization": "SDK-HMAC-SHA256 garbage"},
			want:    Identity{Scheme: SchemeSDKHMAC},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			if got := Parse(h); got != tt.want {
				t.Fatalf("Parse = %+v\n     want %+v", got, tt.want)
			}
		})
	}
}

func TestMiddlewareAcceptsAndNeverLogsSecrets(t *testing.T) {
	t.Parallel()

	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var seen Identity
	h := Middleware(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	r := httptest.NewRequest(http.MethodGet, "/v1/vpcs", nil)
	r.Header.Set("Authorization", "SDK-HMAC-SHA256 Access=AKEXAMPLE123, SignedHeaders=host, Signature=TOPSECRETSIG")
	r.Header.Set("X-Auth-Token", "TOPSECRETTOKEN")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d: accept mode must not reject", w.Code)
	}
	if seen.AccessKey != "AKEXAMPLE123" || !seen.HasToken {
		t.Fatalf("handler saw %+v", seen)
	}
	out := logs.String()
	if !strings.Contains(out, "AKEXAMPLE123") {
		t.Errorf("log does not record the access key:\n%s", out)
	}
	for _, secret := range []string{"TOPSECRETSIG", "TOPSECRETTOKEN"} {
		if strings.Contains(out, secret) {
			t.Errorf("log leaks %s:\n%s", secret, out)
		}
	}
}

func TestFromContextDefault(t *testing.T) {
	t.Parallel()

	if got := FromContext(context.Background()); got != (Identity{Scheme: SchemeNone}) {
		t.Fatalf("FromContext on an empty context = %+v", got)
	}
}
