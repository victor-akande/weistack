package server

import (
	"net/http"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
)

func TestAdminNeedsTheAdministratorUnderEnforce(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMEnforce)
	const services = "http://localhost/_weistack/services"
	admin, secret := enforceAdmin.AccessKey, enforceAdmin.SecretKey
	for _, tc := range []struct {
		name, method, target, ak, sk string
		header                       []string
		status                       int
		code                         string
	}{
		{name: "health is open", method: http.MethodGet, target: "http://localhost/_weistack/health", status: http.StatusOK},
		{name: "unsigned", method: http.MethodGet, target: services, status: http.StatusUnauthorized, code: "APIGW.0305"},
		{name: "the administrator", method: http.MethodGet, target: services, ak: admin, sk: secret, status: http.StatusOK},
		{name: "a bad signature", method: http.MethodGet, target: services, ak: admin, sk: userSecret, status: http.StatusUnauthorized, code: "APIGW.0301"},
		{name: "an IAM user", method: http.MethodGet, target: services, ak: userKey, sk: userSecret, status: http.StatusForbidden, code: "WeiStack.0403"},
		{name: "an IAM user's token", method: http.MethodGet, target: services, header: []string{"X-Auth-Token", goodToken}, status: http.StatusForbidden, code: "WeiStack.0403"},
		{name: "state unsigned", method: http.MethodGet, target: "http://localhost/_weistack/state", status: http.StatusUnauthorized, code: "APIGW.0305"},
		{name: "reset unsigned", method: http.MethodPost, target: "http://localhost/_weistack/reset", status: http.StatusUnauthorized, code: "APIGW.0305"},
		{name: "reset by an IAM user", method: http.MethodPost, target: "http://localhost/_weistack/reset", ak: userKey, sk: userSecret, status: http.StatusForbidden, code: "WeiStack.0403"},
		{name: "reset by the administrator", method: http.MethodPost, target: "http://localhost/_weistack/reset", ak: admin, sk: secret, status: http.StatusOK},
		{name: "an unknown admin path is not found", method: http.MethodGet, target: "http://localhost/_weistack/nothing", status: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, out := e.send(t, tc.method, tc.target, "", tc.ak, tc.sk, pathOf(tc.target), tc.header...)
			if status != tc.status || (tc.code != "" && out["error_code"] != tc.code) {
				t.Fatalf("%s %s = %d %v, want %d %s", tc.method, tc.target, status, out, tc.status, tc.code)
			}
		})
	}
}

func TestAdminOpenInAcceptMode(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMAccept)
	for _, path := range []string{"/_weistack/services", "/_weistack/state"} {
		if status, out := e.send(t, http.MethodGet, "http://localhost"+path, "", "", "", ""); status != http.StatusOK {
			t.Errorf("GET %s = %d %v", path, status, out)
		}
	}
}

func TestIsAdministrator(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMEnforce)
	admin := identity.Principal{AccountID: enforceAccount.ID, UserName: "admin", Admin: true}
	narrowed := admin
	narrowed.Session = &identity.Session{}
	other := admin
	other.AccountID = "0123456789abcdef0123456789abcdef"
	for p, want := range map[*identity.Principal]bool{
		&admin:    true,
		&narrowed: false, // temporary credentials with session policies
		&other:    false, // another account's
		{AccountID: enforceAccount.ID, UserID: "u1", UserName: "alice"}: false,
	} {
		if got := e.srv.isAdministrator(*p); got != want {
			t.Errorf("isAdministrator(%+v) = %v, want %v", *p, got, want)
		}
	}
}

func pathOf(target string) string {
	return request(http.MethodGet, target, "").URL.Path
}
