package obs

import (
	"net/http"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Keys WeiStack knows act for the account, as on Huawei Cloud: all of an
// account's users share its buckets. Other keys keep v0.1's behaviour.
func TestKnownKeysShareTheAccountsBuckets(t *testing.T) {
	t.Parallel()
	acct := identity.Account{ID: "0123456789abcdef0123456789abcdef", Name: identity.AccountName}
	keys := identity.NewDirectory(acct, identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "s"})
	if err := keys.Register("USERKEY0000000000000", identity.Principal{AccountID: acct.ID, UserName: "dev"}, "secret"); err != nil {
		t.Fatal(err)
	}
	e := newEnvDir(t, store.NewMemory(), t.TempDir(), keys)
	const admin, user, stranger = "OBS ADMINKEY000000000000:c2ln", "AWS USERKEY0000000000000:c2ln", "OBS AKSTRANGER:c2ln"

	mustStatus(t, e.as(t, admin, http.MethodPut, "/shared"), http.StatusOK)
	// Another key of the same account sees and uses the bucket.
	mustStatus(t, e.as(t, user, http.MethodHead, "/shared"), http.StatusOK)
	mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/shared/k", Auth: user, Body: "v"}), http.StatusOK)
	if got := e.as(t, admin, http.MethodGet, "/shared/k"); got.Status != http.StatusOK || got.Body != "v" {
		t.Fatalf("the admin reading the user's object: %d %q", got.Status, got.Body)
	}
	// Creating it again from another key of the account is "yours".
	wantError(t, e.as(t, user, http.MethodPut, "/shared"), http.StatusConflict, "BucketAlreadyOwnedByYou")

	// The owner shown is the account's ID.
	list := e.as(t, user, http.MethodGet, "/")
	if !strings.Contains(list.Body, "<ID>"+acct.ID+"</ID>") || !strings.Contains(list.Body, "<Name>shared</Name>") {
		t.Fatalf("listing as the account: %s", list.Body)
	}

	// A key WeiStack does not know is still an account of its own.
	wantError(t, e.as(t, stranger, http.MethodGet, "/shared"), http.StatusForbidden, "AccessDenied")
	wantError(t, e.as(t, stranger, http.MethodPut, "/shared"), http.StatusConflict, "BucketAlreadyExists")
	mustStatus(t, e.as(t, stranger, http.MethodPut, "/mine"), http.StatusOK)
	if got := e.as(t, admin, http.MethodHead, "/mine"); got.Status != http.StatusForbidden {
		t.Fatalf("the account reading an unknown key's bucket: %d", got.Status)
	}

	// Presigned URLs carry the key in the query string; it resolves too.
	got := e.do(t, req{Method: http.MethodGet, Path: "/shared/k?AccessKeyId=USERKEY0000000000000&Expires=1&Signature=x"})
	if got.Status != http.StatusOK || got.Body != "v" {
		t.Fatalf("presigned GET by the account's key: %d %q", got.Status, got.Body)
	}
}
