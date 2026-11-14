package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/sigcheck"
	"github.com/victor-akande/weistack/internal/core/store"
)

var (
	enforceAccount = identity.Account{ID: "fedcba9876543210fedcba9876543210", Name: identity.AccountName}
	enforceAdmin   = identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: strings.Repeat("a", 40)}
	enforceNow     = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
)

const (
	userKey      = "USERKEY0000000000000"
	disabledKey  = "DISABLEDKEY000000000"
	goodToken    = "good-token"
	expiredToken = "expired-token"
)

var userSecret = strings.Repeat("u", 40)

// fakeTokens accepts goodToken as alice, and knows expiredToken as
// expired.
type fakeTokens struct{}

func (fakeTokens) CheckToken(_ context.Context, token string) (identity.Principal, error) {
	switch token {
	case goodToken:
		return identity.Principal{AccountID: enforceAccount.ID, UserID: "u1", UserName: "alice"}, nil
	case expiredToken:
		return identity.Principal{}, auth.ErrTokenExpired
	}
	return identity.Principal{}, auth.ErrTokenUnknown
}

type enforceEnv struct {
	srv *Server
	dir *identity.Directory
}

func newEnforceEnv(t *testing.T, mode string) *enforceEnv {
	t.Helper()
	cfg, err := config.Load([]string{"-iam", mode}, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	dir := identity.NewDirectory(enforceAccount, enforceAdmin)
	if err := dir.Register(userKey, identity.Principal{AccountID: enforceAccount.ID, UserID: "u1", UserName: "alice"}, userSecret); err != nil {
		t.Fatal(err)
	}
	if err := dir.Register(disabledKey, identity.Principal{AccountID: enforceAccount.ID, UserID: "u2", UserName: "bob", Disabled: true}, userSecret); err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	srv, err := New(Options{
		Config: cfg, ProjectID: testProject, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Store: st, Engine: lifecycle.New(lifecycle.Options{}), IDs: ids.NewSeeded(1),
		Services:  []Service{&fakeService{name: "vpc"}, &fakeService{name: "iam"}, &fakeService{name: "obs"}},
		Directory: dir, Tokens: fakeTokens{}, Now: func() time.Time { return enforceNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &enforceEnv{srv: srv, dir: dir}
}

// send serves a request, signed by ak and sk over signPath if ak is set.
func (e *enforceEnv) send(t *testing.T, method, target, body, ak, sk, signPath string, header ...string) (int, map[string]any) {
	t.Helper()
	r := request(method, target, body)
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	if ak != "" {
		sigcheck.SignSDKHMAC(r, ak, sk, signPath, []byte(body), enforceNow)
	}
	w := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// request builds a request as a client sends it to WeiStack directly:
// the path as the target and the host in Host, so that it is not taken
// for a proxy request.
func request(method, target, body string) *http.Request {
	u, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	r := httptest.NewRequest(method, u.RequestURI(), strings.NewReader(body))
	r.Host = u.Host
	return r
}

const thingsPath = "/v1/" + testProject + "/things"

func TestEnforceAcceptsValidCredentials(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMEnforce)

	// By host, signed over the path as sent.
	if code, out := e.send(t, http.MethodGet, "http://vpc.ap-southeast-1.myhuaweicloud.com"+thingsPath, "", enforceAdmin.AccessKey, enforceAdmin.SecretKey, thingsPath); code != http.StatusOK {
		t.Fatalf("admin by host = %d %v", code, out)
	}
	// By path prefix, signed over either the full or the stripped path.
	for _, signed := range []string{"/vpc" + thingsPath, thingsPath} {
		if code, out := e.send(t, http.MethodGet, "http://127.0.0.1:8780/vpc"+thingsPath, "", userKey, userSecret, signed); code != http.StatusOK {
			t.Fatalf("user by prefix, signed over %s = %d %v", signed, code, out)
		}
	}
	// A body is part of the signature, and reaches the service intact.
	r := request(http.MethodPost, "http://vpc.localhost/v1/echo", `{"a":1}`)
	sigcheck.SignSDKHMAC(r, userKey, userSecret, "/v1/echo", []byte(`{"a":1}`), enforceNow)
	w := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != `{"a":1}` {
		t.Fatalf("echo = %d %s", w.Code, w.Body)
	}
	// A token.
	if code, out := e.send(t, http.MethodGet, "http://vpc.localhost"+thingsPath, "", "", "", "", "X-Auth-Token", goodToken); code != http.StatusOK {
		t.Fatalf("token = %d %v", code, out)
	}
	// Signing in needs no credentials; OBS and the admin API are not
	// checked here.
	if code, _ := e.send(t, http.MethodPost, "http://iam.localhost/v3/auth/tokens", "{}", "", "", ""); code == http.StatusUnauthorized {
		t.Fatal("password sign-in needed credentials")
	}
	if code, _ := e.send(t, http.MethodGet, "http://obs.localhost"+thingsPath, "", "", "", ""); code != http.StatusOK {
		t.Fatalf("OBS = %d", code)
	}
	if code, _ := e.send(t, http.MethodGet, "http://127.0.0.1:8780/_weistack/health", "", "", "", ""); code != http.StatusOK {
		t.Fatalf("admin API = %d", code)
	}
}

func TestEnforceRejects(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMEnforce)
	target := "http://vpc.localhost" + thingsPath
	const authInfo = "Incorrect IAM authentication information: "

	for name, tc := range map[string]struct {
		ak, sk, signPath string
		header           []string
		code, msg        string
		status           int
	}{
		"no credentials":  {code: "APIGW.0305", msg: "Incorrect authentication information.", status: 401},
		"unknown key":     {ak: "UNKNOWNKEY0000000000", sk: userSecret, signPath: thingsPath, code: "APIGW.0301", msg: authInfo + "Get secretKey failed,ak:UNKNOWNKEY0000000000,err:ak not exist", status: 401},
		"disabled user":   {ak: disabledKey, sk: userSecret, signPath: thingsPath, code: "APIGW.0301", msg: authInfo + "Get secretKey failed,ak:" + disabledKey + ",err:ak not exist", status: 401},
		"wrong secret":    {ak: userKey, sk: "wrong", signPath: thingsPath, code: "APIGW.0301", msg: authInfo + "verify aksk signature fail", status: 401},
		"wrong path":      {ak: userKey, sk: userSecret, signPath: "/v1/other", code: "APIGW.0301", msg: authInfo + "verify aksk signature fail", status: 401},
		"other algorithm": {header: []string{"Authorization", "V11-HMAC-SHA256 Credential=x, SignedHeaders=a, Signature=b"}, code: "APIGW.0301", msg: authInfo + "verify aksk signature fail", status: 401},
		"unknown token":   {header: []string{"X-Auth-Token", "nope"}, code: "APIGW.0301", msg: authInfo + "decrypt token fail", status: 401},
		"expired token":   {header: []string{"X-Auth-Token", expiredToken}, code: "APIGW.0307", msg: "The token must be updated.", status: 401},
	} {
		status, out := e.send(t, http.MethodGet, target, "", tc.ak, tc.sk, tc.signPath, tc.header...)
		if status != tc.status || out["error_code"] != tc.code || out["error_msg"] != tc.msg || out["request_id"] == "" {
			t.Errorf("%s: %d %v, want %d %s %q", name, status, out, tc.status, tc.code, tc.msg)
		}
	}
}

func TestEnforceLocksOutAfterFailures(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMEnforce)
	target := "http://vpc.localhost" + thingsPath
	for range identity.MaxFailures + 1 {
		e.send(t, http.MethodGet, target, "", userKey, "wrong", thingsPath)
	}
	// Locked: even the right secret is refused.
	_, out := e.send(t, http.MethodGet, target, "", userKey, userSecret, thingsPath)
	if out["error_msg"] != "Incorrect IAM authentication information: AK access failed to reach the limit,forbidden." {
		t.Fatalf("after six failures = %v", out)
	}
	// The administrator's key is never locked.
	for range 3 * identity.MaxFailures {
		e.send(t, http.MethodGet, target, "", enforceAdmin.AccessKey, "wrong", thingsPath)
	}
	if code, out := e.send(t, http.MethodGet, target, "", enforceAdmin.AccessKey, enforceAdmin.SecretKey, thingsPath); code != http.StatusOK {
		t.Fatalf("admin after failures = %d %v", code, out)
	}
}

func TestAcceptModeChecksNothing(t *testing.T) {
	t.Parallel()
	e := newEnforceEnv(t, config.IAMAccept)
	if code, out := e.send(t, http.MethodGet, "http://vpc.localhost"+thingsPath, "", "UNKNOWNKEY0000000000", "wrong", "/elsewhere"); code != http.StatusOK {
		t.Fatalf("accept mode = %d %v", code, out)
	}
	if code, _ := e.send(t, http.MethodGet, "http://vpc.localhost"+thingsPath, "", "", "", ""); code != http.StatusOK {
		t.Fatalf("accept mode without credentials = %d", code)
	}
}
