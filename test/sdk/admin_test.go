package sdk

import (
	"net/http"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/signer"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/request"
)

// adminDo calls the emulator's admin API, signed with the administrator's
// keys as -iam=enforce requires, with the SDK's own signer.
func adminDo(t *testing.T, method, path, body string) *http.Response {
	t.Helper()
	endpoint := "http://" + emulatorAddr
	headers := map[string]string{"Host": emulatorAddr}
	if body != "" {
		headers["Content-Type"] = "application/json"
	}
	b := request.NewHttpRequestBuilder().WithEndpoint(endpoint).WithPath(path).WithMethod(method)
	for k, v := range headers {
		b.AddHeaderParam(k, v)
	}
	if body != "" {
		b.WithBody("application/json", body)
	}
	signed, err := signer.Sign(b.Build(), adminAK, adminSK)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(method, endpoint+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for k, v := range signed {
		r.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestAdminAPINeedsTheAdministrator checks that under -iam=enforce the
// admin API refuses unsigned requests, and answers signed ones.
func TestAdminAPINeedsTheAdministrator(t *testing.T) {
	t.Parallel()
	res, err := http.Get("http://" + emulatorAddr + "/_weistack/services")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	want := http.StatusOK
	if enforcing {
		want = http.StatusUnauthorized
	}
	if res.StatusCode != want {
		t.Errorf("unsigned GET /_weistack/services = %d, want %d", res.StatusCode, want)
	}
	res = adminDo(t, http.MethodGet, "/_weistack/services", "")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("signed GET /_weistack/services = %d", res.StatusCode)
	}
}
