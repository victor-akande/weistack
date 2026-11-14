package iam

import (
	"bytes"
	"net/http"
	"testing"
)

// newUser creates a user through classic IAM and returns its ID.
func (e *env) newUser(t *testing.T, name string) string {
	t.Helper()
	out := e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-USER/users",
		`{"user":{"name":"`+name+`","domain_id":"`+testAccount.ID+`"}}`)
	return obj(out["user"])["id"].(string)
}

// signedBy sends a GET signed (in form only) with ak, as a client would.
func (e *env) signedBy(t *testing.T, ak, path string) map[string]any {
	t.Helper()
	w, out := e.do(t, http.MethodGet, path, "",
		"Authorization", "SDK-HMAC-SHA256 Access="+ak+", SignedHeaders=host, Signature=abc")
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s as %s = %d %v", path, ak, w.Code, out)
	}
	return out
}

func TestClassicAccessKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := e.newUser(t, "alice")

	out := e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-CREDENTIAL/credentials",
		`{"credential":{"user_id":"`+uid+`","description":"ci"}}`)
	c := obj(out["credential"])
	ak, sk := c["access"].(string), c["secret"].(string)
	if len(ak) != 20 || len(sk) != 40 || c["status"] != "active" || c["user_id"] != uid || c["description"] != "ci" {
		t.Fatalf("created = %v", c)
	}

	// The secret is sealed in the store, and opens with the AK.
	rec, err := e.svc.accessKeys().Get(t.Context(), ak)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rec.Secret, []byte(sk)) {
		t.Fatal("the secret key is stored in clear text")
	}
	if got, err := e.svc.vault.Open(rec.Secret, ak); err != nil || got != sk {
		t.Fatalf("Open = %q, %v", got, err)
	}

	// The key acts as alice.
	if p, ok := e.svc.dir.Lookup(ak); !ok || p.UserID != uid || p.UserName != "alice" || p.Admin {
		t.Fatalf("directory = %+v, %v", p, ok)
	}

	// Never used: the last use is the creation time, as documented.
	c = obj(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-CREDENTIAL/credentials/"+ak, "")["credential"])
	if c["last_use_time"] != c["create_time"] || c["secret"] != nil {
		t.Fatalf("shown = %v", c)
	}

	// Listing a user's keys, and the caller's: signed with alice's key,
	// it is alice.
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-CREDENTIAL/credentials?user_id="+uid, "")["credentials"]); len(got) != 1 {
		t.Fatalf("listed = %v", got)
	}
	if got := list(e.signedBy(t, ak, "/v3.0/OS-CREDENTIAL/credentials")["credentials"]); len(got) != 1 || obj(got[0])["access"] != ak {
		t.Fatalf("own keys = %v", got)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-CREDENTIAL/credentials", "")["credentials"]); len(got) != 0 {
		t.Fatalf("the root user's keys = %v", got)
	}

	// Description alone keeps the status; deactivating forgets the key.
	c = obj(e.want(t, http.StatusOK, http.MethodPut, "/v3.0/OS-CREDENTIAL/credentials/"+ak,
		`{"credential":{"description":"renamed"}}`)["credential"])
	if c["status"] != "active" || c["description"] != "renamed" {
		t.Fatalf("updated = %v", c)
	}
	e.want(t, http.StatusOK, http.MethodPut, "/v3.0/OS-CREDENTIAL/credentials/"+ak, `{"credential":{"status":"inactive"}}`)
	if _, ok := e.svc.dir.Lookup(ak); ok {
		t.Fatal("an inactive key is still registered")
	}
	// It was used (by the listing above), and that survives deactivation.
	c = obj(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-CREDENTIAL/credentials/"+ak, "")["credential"])
	if c["status"] != "inactive" || c["last_use_time"] == c["create_time"] {
		t.Fatalf("after deactivation = %v", c)
	}
	e.want(t, http.StatusOK, http.MethodPut, "/v3.0/OS-CREDENTIAL/credentials/"+ak, `{"credential":{"status":"active"}}`)
	if _, ok := e.svc.dir.Lookup(ak); !ok {
		t.Fatal("a reactivated key is not registered")
	}

	// Quota: two keys per user, refused in the documented form.
	e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-CREDENTIAL/credentials", `{"credential":{"user_id":"`+uid+`"}}`)
	w, out := e.do(t, http.MethodPost, "/v3.0/OS-CREDENTIAL/credentials", `{"credential":{"user_id":"`+uid+`"}}`)
	if w.Code != http.StatusBadRequest || obj(out["error"])["message"] != "akSkNumExceed" || obj(out["error"])["code"] != float64(400) {
		t.Fatalf("third key = %d %v", w.Code, out)
	}

	e.wantErr(t, http.StatusBadRequest, "IAM.0073", http.MethodPut, "/v3.0/OS-CREDENTIAL/credentials/"+ak, `{"credential":{"status":"off"}}`)
	e.wantErr(t, http.StatusBadRequest, "IAM.0072", http.MethodPost, "/v3.0/OS-CREDENTIAL/credentials", `{}`)
	e.wantErr(t, http.StatusBadRequest, "IAM.0072", http.MethodPost, "/v3.0/OS-CREDENTIAL/credentials", `{"credential":{}}`)
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPost, "/v3.0/OS-CREDENTIAL/credentials", `{"credential":{"user_id":"nobody"}}`)

	e.want(t, http.StatusNoContent, http.MethodDelete, "/v3.0/OS-CREDENTIAL/credentials/"+ak, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v3.0/OS-CREDENTIAL/credentials/"+ak, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodDelete, "/v3.0/OS-CREDENTIAL/credentials/"+ak, "")
	if _, ok := e.svc.dir.Lookup(ak); ok {
		t.Fatal("a deleted key is still registered")
	}
}

func TestV5AccessKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := e.newUser(t, "bob")
	other := e.newUser(t, "carol")
	base := "/v5/users/" + uid + "/access-keys"

	k := obj(e.want(t, http.StatusCreated, http.MethodPost, base, "")["access_key"])
	ak := k["access_key_id"].(string)
	if len(ak) != 20 || len(k["secret_access_key"].(string)) != 40 || k["status"] != "active" || k["user_id"] != uid || k["created_at"] == "" {
		t.Fatalf("created = %v", k)
	}
	e.want(t, http.StatusCreated, http.MethodPost, base, "")
	e.wantErr(t, http.StatusBadRequest, "PAP5.0257", http.MethodPost, base, "")
	e.wantErr(t, http.StatusNotFound, "PAP5.0021", http.MethodPost, "/v5/users/nobody/access-keys", "")

	// Paging, without secrets.
	out := e.want(t, http.StatusOK, http.MethodGet, base+"?limit=1", "")
	page1 := list(out["access_keys"])
	next := obj(out["page_info"])["next_marker"].(string)
	page2 := list(e.want(t, http.StatusOK, http.MethodGet, base+"?marker="+next, "")["access_keys"])
	if len(page1) != 1 || len(page2) != 1 || obj(page1[0])["secret_access_key"] != nil {
		t.Fatalf("pages = %v, %v", page1, page2)
	}

	// The owner of a key.
	users := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/users?access_key_id="+ak, "")["users"])
	if len(users) != 1 || obj(users[0])["user_id"] != uid {
		t.Fatalf("owner = %v", users)
	}
	if users := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/users?access_key_id=NOSUCHKEY", "")["users"]); len(users) != 0 {
		t.Fatalf("owner of an unknown key = %v", users)
	}

	// Last used: absent until the key signs a request.
	used := obj(e.want(t, http.StatusOK, http.MethodGet, base+"/"+ak+"/last-used", "")["access_key_last_used"])
	if _, ok := used["last_used_at"]; ok {
		t.Fatalf("never used = %v", used)
	}
	e.signedBy(t, ak, "/v3/auth/domains")
	used = obj(e.want(t, http.StatusOK, http.MethodGet, base+"/"+ak+"/last-used", "")["access_key_last_used"])
	if used["last_used_at"] == nil {
		t.Fatalf("used = %v", used)
	}

	k = obj(e.want(t, http.StatusOK, http.MethodPut, base+"/"+ak, `{"status":"inactive"}`)["access_key"])
	if k["status"] != "inactive" || k["secret_access_key"] != nil {
		t.Fatalf("updated = %v", k)
	}
	e.wantErr(t, http.StatusBadRequest, "PAP5.0257", http.MethodPut, base+"/"+ak, `{}`)
	e.wantErr(t, http.StatusBadRequest, "PAP5.0257", http.MethodPut, base+"/"+ak, `{"status":"off"}`)

	// A key is reached only through its own user.
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v5/users/"+other+"/access-keys/"+ak+"/last-used", "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodDelete, "/v5/users/"+other+"/access-keys/"+ak, "")

	e.want(t, http.StatusNoContent, http.MethodDelete, base+"/"+ak, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, base+"/"+ak, `{"status":"active"}`)
}

func TestAccessKeysFollowTheirUser(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := e.newUser(t, "dave")
	ak := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v5/users/"+uid+"/access-keys", "")["access_key"])["access_key_id"].(string)

	// A rename carries over to the directory.
	e.want(t, http.StatusOK, http.MethodPut, "/v5/users/"+uid, `{"new_user_name":"david"}`)
	if p, _ := e.svc.dir.Lookup(ak); p.UserName != "david" {
		t.Fatalf("after rename = %+v", p)
	}

	// A start registers stored keys again; a reset forgets them.
	e.svc.dir.Clear()
	if err := e.svc.Resume(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.svc.dir.Lookup(ak); !ok {
		t.Fatal("Resume did not register the stored key")
	}

	// Deleting the user deletes its keys.
	e.want(t, http.StatusNoContent, http.MethodDelete, "/v5/users/"+uid, "")
	if _, ok := e.svc.dir.Lookup(ak); ok {
		t.Fatal("the deleted user's key is still registered")
	}
	if _, err := e.svc.accessKeys().Get(t.Context(), ak); err == nil {
		t.Fatal("the deleted user's key is still stored")
	}
}

func TestResetForgetsAccessKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := e.newUser(t, "erin")
	ak := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v5/users/"+uid+"/access-keys", "")["access_key"])["access_key_id"].(string)

	e.want(t, http.StatusOK, http.MethodPost, "/_weistack/reset", "")
	if _, ok := e.svc.dir.Lookup(ak); ok {
		t.Fatal("a reset kept a user's key")
	}
}
