package sts

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/identity"
)

func TestCallerIdentity(t *testing.T) {
	t.Parallel()
	acct := identity.Account{ID: "fedcba9876543210fedcba9876543210", Name: identity.AccountName}
	dir := identity.NewDirectory(acct, identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "s"})
	if err := dir.Register("USERKEY0000000000000", identity.Principal{AccountID: acct.ID, UserID: "u-1", UserName: "dev"}); err != nil {
		t.Fatal(err)
	}
	svc, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), dir)
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
	if _, err := New(nil, nil); err == nil {
		t.Fatal("New accepted nil dependencies")
	}
	if svc.Name() != "sts" || svc.Version() == "" {
		t.Fatal("name or version")
	}
}
