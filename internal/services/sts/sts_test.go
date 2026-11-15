package sts

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/vault"
)

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestDecodeAuthorizationMessage decodes a real denial: one the gate
// encoded for a user without permissions.
func TestDecodeAuthorizationMessage(t *testing.T) {
	t.Parallel()
	acct := identity.Account{ID: "fedcba9876543210fedcba9876543210", Name: identity.AccountName}
	dir := identity.NewDirectory(acct, identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "s"})
	v := testVault(t)
	svc, err := New(slog.New(slog.DiscardHandler), dir, v)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	svc.Routes(router)
	call := func(p identity.Principal, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v5/decode-authorization-message", strings.NewReader(body))
		g := authz.NewGate(authz.GateOptions{Principal: p, Account: acct.ID, Sealer: v})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r.WithContext(authz.WithGate(r.Context(), g)))
		return w
	}

	// A user without permissions is denied, with STS's documented code
	// and a message to decode.
	w := call(identity.Principal{UserID: "u-1", UserName: "dev"}, `{"encoded_message":"x"}`)
	var denial struct {
		Code    string `json:"error_code"`
		Encoded string `json:"encoded_authorization_message"`
	}
	if w.Code != http.StatusForbidden || json.Unmarshal(w.Body.Bytes(), &denial) != nil || denial.Code != "STS5.1001" || denial.Encoded == "" {
		t.Fatalf("unauthorized decode = %d %s", w.Code, w.Body)
	}

	// The administrator decodes it.
	admin := identity.Principal{Admin: true}
	w = call(admin, `{"encoded_message":"`+denial.Encoded+`"}`)
	var out struct {
		Decoded string `json:"decoded_message"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("decode = %d %s", w.Code, w.Body)
	}
	for _, want := range []string{`"user_name":"dev"`, `"action":"sts::decodeAuthorizationMessage"`, `"failure":"implicit deny by identity-based policy"`} {
		if !strings.Contains(out.Decoded, want) {
			t.Errorf("decoded %s lacks %s", out.Decoded, want)
		}
	}
	for _, body := range []string{`{}`, `{"encoded_message":"bm90IG91cnM="}`, `nope`, `{"encoded_message":"` + strings.Repeat("A", maxEncodedMessage+1) + `"}`} {
		if w := call(admin, body); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "STS5.1301") {
			t.Errorf("decode %.40s = %d %s", body, w.Code, w.Body)
		}
	}
}

func TestCallerIdentity(t *testing.T) {
	t.Parallel()
	acct := identity.Account{ID: "fedcba9876543210fedcba9876543210", Name: identity.AccountName}
	dir := identity.NewDirectory(acct, identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "s"})
	if err := dir.Register("USERKEY0000000000000", identity.Principal{AccountID: acct.ID, UserID: "u-1", UserName: "dev"}, "secret"); err != nil {
		t.Fatal(err)
	}
	svc, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), dir, testVault(t))
	if err != nil {
		t.Fatal(err)
	}
	h := auth.Middleware(slog.New(slog.NewTextHandler(io.Discard, nil)), dir)(http.HandlerFunc(svc.handleCallerIdentity))
	call := func(ak string) callerIdentity {
		r := httptest.NewRequest(http.MethodGet, "/v5/caller-identity", nil)
		if ak != "" {
			r.Header.Set("Authorization", "SDK-HMAC-SHA256 Access="+ak+", SignedHeaders=host, Signature=x")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out callerIdentity
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("caller identity for %q: %d %s", ak, w.Code, w.Body)
		}
		return out
	}
	root := callerIdentity{AccountID: acct.ID, PrincipalURN: "iam::" + acct.ID + ":user:weistack", PrincipalID: acct.RootUserID()}
	if got := call("ADMINKEY000000000000"); got != root {
		t.Fatalf("the administrator = %+v, want the root user %+v", got, root)
	}
	if got := call("AKNOBODY"); got != root {
		t.Fatalf("an unknown key = %+v", got)
	}
	if got := call("USERKEY0000000000000"); got.PrincipalID != "u-1" || got.PrincipalURN != "iam::"+acct.ID+":user:dev" {
		t.Fatalf("a user's key = %+v", got)
	}
	if _, err := New(nil, nil, nil); err == nil {
		t.Fatal("New accepted nil dependencies")
	}
	if svc.Name() != "sts" || svc.Version() == "" {
		t.Fatal("name or version")
	}
}
