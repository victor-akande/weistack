package kms

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
)

const (
	testRegion  = "ap-southeast-1"
	testProject = "0123456789abcdef0123456789abcdef"
)

var testAccount = identity.Account{ID: "fedcba9876543210fedcba9876543210", Name: identity.AccountName}

type env struct {
	svc     *Service
	handler http.Handler
	dir     *identity.Directory
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	dir := identity.NewDirectory(testAccount, identity.Credentials{AccessKey: "ADMINKEY000000000000", SecretKey: "s"})
	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	vlt, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	svc, err := New(Deps{Store: st, Logger: log, IDs: ids.NewSeeded(1), Vault: vlt, Directory: dir, Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: st, Engine: lifecycle.New(lifecycle.Options{}),
		IDs: ids.New(), Services: []server.Service{svc}, Directory: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc, e.handler, e.dir = svc, srv.Handler(), dir
	return e
}

// call sends a KMS operation in the test project.
func (e *env) call(t *testing.T, method, op, body string) (int, map[string]any) {
	t.Helper()
	return e.callAs(t, "", testProject, method, op, body)
}

// callAs sends a KMS operation signed (in form only) with ak, in project.
func (e *env) callAs(t *testing.T, ak, project, method, op, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, "/v1.0/"+project+"/kms/"+op, strings.NewReader(body))
	if ak != "" {
		r.Header.Set("Authorization", "SDK-HMAC-SHA256 Access="+ak+", SignedHeaders=host, Signature=abc")
	}
	r.Host = "kms." + testRegion + ".myhuaweicloud.com"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: %v: %s", method, op, err, w.Body)
		}
	}
	return w.Code, out
}

func (e *env) ok(t *testing.T, op, body string) map[string]any {
	t.Helper()
	code, out := e.call(t, http.MethodPost, op, body)
	if code != http.StatusOK {
		t.Fatalf("%s %s = %d %v", op, body, code, out)
	}
	return out
}

func (e *env) wantErr(t *testing.T, status int, code, op, body string) {
	t.Helper()
	got, out := e.call(t, http.MethodPost, op, body)
	errObj, _ := out["error"].(map[string]any)
	if got != status || errObj == nil || errObj["error_code"] != code {
		t.Errorf("%s %s = %d %v, want %d %s", op, body, got, out, status, code)
	}
}

func (e *env) newKey(t *testing.T, body string) string {
	t.Helper()
	return e.ok(t, "create-key", body)["key_info"].(map[string]any)["key_id"].(string)
}

func (e *env) describe(t *testing.T, id string) map[string]any {
	t.Helper()
	return e.ok(t, "describe-key", `{"key_id":"`+id+`"}`)["key_info"].(map[string]any)
}

func ref(id string) string { return `{"key_id":"` + id + `"}` }

func TestKeyLifecycle(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.newKey(t, `{"key_alias":"app","key_description":"for the app"}`)
	d := e.describe(t, id)
	if d["key_state"] != "2" || d["key_spec"] != "AES_256" || d["key_usage"] != "ENCRYPT_DECRYPT" || d["domain_id"] != testAccount.ID ||
		d["realm"] != testRegion || d["origin"] != "kms" || d["default_key_flag"] != "0" || d["creation_date"] != "1794744000000" ||
		d["key_rotation_enabled"] != "false" || d["sys_enterprise_project_id"] != "0" {
		t.Fatalf("describe = %v", d)
	}

	// Disable, enable, schedule deletion, cancel.
	if s := e.ok(t, "disable-key", ref(id))["key_info"].(map[string]any)["key_state"]; s != "3" {
		t.Errorf("disabled state = %v", s)
	}
	e.wantErr(t, 400, "KMS.1301", "disable-key", ref(id))
	e.wantErr(t, 400, "KMS.0209", "encrypt-data", `{"key_id":"`+id+`","plain_text":"x"}`)
	e.ok(t, "enable-key", ref(id))
	e.wantErr(t, 400, "KMS.1201", "enable-key", ref(id))
	e.wantErr(t, 400, "KMS.1401", "schedule-key-deletion", `{"key_id":"`+id+`","pending_days":"6"}`)
	out := e.ok(t, "schedule-key-deletion", `{"key_id":"`+id+`","pending_days":"7"}`)
	if out["key_state"] != "4" {
		t.Errorf("schedule = %v", out)
	}
	if d := e.describe(t, id); d["scheduled_deletion_date"] != "1795348800000" {
		t.Errorf("scheduled_deletion_date = %v", d["scheduled_deletion_date"])
	}
	e.wantErr(t, 400, "KMS.1402", "schedule-key-deletion", `{"key_id":"`+id+`","pending_days":7}`)
	e.wantErr(t, 400, "KMS.0210", "encrypt-data", `{"key_id":"`+id+`","plain_text":"x"}`)
	if s := e.ok(t, "cancel-key-deletion", ref(id))["key_state"]; s != "3" {
		t.Errorf("cancelled state = %v, want disabled", s)
	}
	e.wantErr(t, 400, "KMS.1501", "cancel-key-deletion", ref(id))

	// Alias and description.
	e.ok(t, "update-key-alias", `{"key_id":"`+id+`","key_alias":"app-2"}`)
	e.ok(t, "update-key-description", `{"key_id":"`+id+`","key_description":""}`)
	if d := e.describe(t, id); d["key_alias"] != "app-2" || d["key_description"] != "" {
		t.Errorf("updated = %v", d)
	}

	// The deletion comes.
	e.ok(t, "schedule-key-deletion", `{"key_id":"`+id+`","pending_days":"7"}`)
	e.now = e.now.AddDate(0, 0, 7)
	e.wantErr(t, 404, "KMS.0207", "describe-key", ref(id))

	// Errors.
	e.newKey(t, `{"key_alias":"taken"}`)
	for _, c := range []struct{ body, code string }{
		{`{"key_alias":"taken"}`, "KMS.1104"},
		{`{"key_alias":"obs/default"}`, "KMS.1101"},
		{`{"key_alias":"has space"}`, "KMS.1101"},
		{`{"key_alias":"` + strings.Repeat("a", 256) + `"}`, "KMS.1101"},
		{`{}`, "KMS.0204"},
		{`{"key_alias":"x","key_spec":"DES"}`, "KMS.0308"},
		{`{"key_alias":"x","key_spec":"EC_P256","key_usage":"ENCRYPT_DECRYPT"}`, "KMS.0308"},
		{`{"key_alias":"x","origin":"external"}`, "KMS.0308"},
		{`{"key_alias":"x","key_description":"` + strings.Repeat("d", 256) + `"}`, "KMS.1103"},
		{`nope`, "KMS.0202"},
	} {
		e.wantErr(t, 400, c.code, "create-key", c.body)
	}
	e.wantErr(t, 400, "KMS.0205", "describe-key", ref("nope"))
	e.wantErr(t, 404, "KMS.0207", "describe-key", ref("00000000-0000-0000-0000-000000000000"))
}

func TestEverySpec(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for spec, usage := range map[string]string{
		"AES_256": "ENCRYPT_DECRYPT", "SM4": "ENCRYPT_DECRYPT", "RSA_2048": "SIGN_VERIFY", "EC_P256": "SIGN_VERIFY",
		"EC_P384": "SIGN_VERIFY", "SECP256K1": "SIGN_VERIFY", "SM2": "SIGN_VERIFY", "ED25519": "SIGN_VERIFY",
		"HMAC_256": "GENERATE_VERIFY_MAC", "HMAC_SM3": "GENERATE_VERIFY_MAC",
	} {
		id := e.newKey(t, `{"key_alias":"k-`+strings.ToLower(spec)+`","key_spec":"`+spec+`"}`)
		if d := e.describe(t, id); d["key_spec"] != spec || d["key_usage"] != usage {
			t.Errorf("%s: %v", spec, d)
		}
	}
	e.newKey(t, `{"key_alias":"rsa-enc","key_spec":"RSA_2048","key_usage":"ENCRYPT_DECRYPT"}`)
}

func TestEncryption(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, spec := range []string{"AES_256", "SM4"} {
		id := e.newKey(t, `{"key_alias":"enc-`+spec+`","key_spec":"`+spec+`"}`)
		ct := e.ok(t, "encrypt-data", `{"key_id":"`+id+`","plain_text":"hello world","additional_authenticated_data":"aad"}`)["cipher_text"].(string)
		if len(ct) < minCipherText {
			t.Errorf("%s: ciphertext of %d characters", spec, len(ct))
		}
		// The ciphertext names its key: decrypting needs no key ID.
		out := e.ok(t, "decrypt-data", `{"cipher_text":"`+ct+`","additional_authenticated_data":"aad"}`)
		if out["plain_text"] != "hello world" || out["plain_text_base64"] != "aGVsbG8gd29ybGQ=" || out["key_id"] != id {
			t.Errorf("%s: decrypt = %v", spec, out)
		}
		e.wantErr(t, 400, "KMS.2201", "decrypt-data", `{"cipher_text":"`+ct+`","additional_authenticated_data":"other"}`)
		raw := []byte(ct)
		raw[len(raw)-10] ^= 1
		e.wantErr(t, 400, "KMS.2201", "decrypt-data", `{"cipher_text":"`+string(raw)+`","additional_authenticated_data":"aad"}`)
		e.wantErr(t, 400, "KMS.2201", "decrypt-data", `{"cipher_text":"`+ct+`","key_id":"00000000-0000-0000-0000-000000000000","additional_authenticated_data":"aad"}`)
		// A disabled key does not decrypt.
		e.ok(t, "disable-key", ref(id))
		e.wantErr(t, 400, "KMS.0209", "decrypt-data", `{"cipher_text":"`+ct+`","additional_authenticated_data":"aad"}`)
	}
	ec := e.newKey(t, `{"key_alias":"signer","key_spec":"EC_P256"}`)
	e.wantErr(t, 400, "KMS.1114", "encrypt-data", `{"key_id":"`+ec+`","plain_text":"x"}`)
	rsaSigner := e.newKey(t, `{"key_alias":"rsa-signer","key_spec":"RSA_2048"}`)
	e.wantErr(t, 400, "KMS.0335", "encrypt-data", `{"key_id":"`+rsaSigner+`","plain_text":"x","encryption_algorithm":"RSAES_OAEP_SHA_256"}`)
	id := e.newKey(t, `{"key_alias":"limits"}`)
	e.wantErr(t, 400, "KMS.2101", "encrypt-data", `{"key_id":"`+id+`","plain_text":"`+strings.Repeat("x", 4097)+`"}`)
	e.wantErr(t, 400, "KMS.2105", "encrypt-data", `{"key_id":"`+id+`","plain_text":"x","encryption_algorithm":"RSAES_OAEP_SHA_256"}`)
	e.wantErr(t, 400, "KMS.2201", "decrypt-data", `{"cipher_text":"`+strings.Repeat("A", 200)+`"}`)
}

func TestDataKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.newKey(t, `{"key_alias":"dek"}`)
	out := e.ok(t, "create-datakey", `{"key_id":"`+id+`","datakey_length":"512"}`)
	plain, ct := out["plain_text"].(string), out["cipher_text"].(string)
	if len(plain) != 128 || strings.ToUpper(plain) != plain {
		t.Fatalf("plain_text = %q", plain)
	}
	got := e.ok(t, "decrypt-datakey", `{"key_id":"`+id+`","cipher_text":"`+ct+`","datakey_cipher_length":"64"}`)
	dk, _ := hex.DecodeString(plain)
	sum := sha256.Sum256(dk)
	if got["data_key"] != plain || got["datakey_length"] != "64" || got["datakey_dgst"] != strings.ToUpper(hex.EncodeToString(sum[:])) {
		t.Errorf("decrypt-datakey = %v", got)
	}
	e.wantErr(t, 400, "KMS.2204", "decrypt-datakey", `{"key_id":"`+id+`","cipher_text":"`+ct+`","datakey_cipher_length":"32"}`)

	// Encrypting a data key the caller made: the key and its hash.
	mine := bytes.Repeat([]byte{7}, 32)
	h := sha256.Sum256(mine)
	pt := hex.EncodeToString(append(mine, h[:]...))
	enc := e.ok(t, "encrypt-datakey", `{"key_id":"`+id+`","plain_text":"`+pt+`","datakey_plain_length":"32"}`)
	if enc["datakey_length"] != "32" {
		t.Errorf("encrypt-datakey = %v", enc)
	}
	back := e.ok(t, "decrypt-datakey", `{"key_id":"`+id+`","cipher_text":"`+enc["cipher_text"].(string)+`","datakey_cipher_length":"32"}`)
	if back["data_key"] != strings.ToUpper(hex.EncodeToString(mine)) {
		t.Errorf("round trip = %v", back)
	}
	bad := hex.EncodeToString(append(mine, make([]byte, 32)...))
	e.wantErr(t, 400, "KMS.2103", "encrypt-datakey", `{"key_id":"`+id+`","plain_text":"`+bad+`","datakey_plain_length":"32"}`)
	e.wantErr(t, 400, "KMS.2104", "encrypt-datakey", `{"key_id":"`+id+`","plain_text":"`+pt+`","datakey_plain_length":"16"}`)

	if out := e.ok(t, "create-datakey-without-plaintext", `{"key_id":"`+id+`","key_spec":"AES_128"}`); out["plain_text"] != nil || out["cipher_text"] == "" {
		t.Errorf("without plaintext = %v", out)
	}
	e.wantErr(t, 400, "KMS.1901", "create-datakey", `{"key_id":"`+id+`","datakey_length":"8200"}`)
	e.wantErr(t, 400, "KMS.1903", "create-datakey", `{"key_id":"`+id+`","datakey_length":"12"}`)
	e.wantErr(t, 400, "KMS.1902", "create-datakey", `{"key_id":"`+id+`","key_spec":"DES"}`)

	if r := e.ok(t, "gen-random", `{"random_data_length":"512"}`)["random_data"].(string); len(r) != 128 {
		t.Errorf("random = %q", r)
	}
	e.wantErr(t, 400, "KMS.1801", "gen-random", `{"random_data_length":"256"}`)
}

func TestRotation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.newKey(t, `{"key_alias":"rot"}`)
	old := e.ok(t, "encrypt-data", `{"key_id":"`+id+`","plain_text":"before"}`)["cipher_text"].(string)
	e.ok(t, "enable-key-rotation", ref(id))
	e.wantErr(t, 400, "KMS.2901", "enable-key-rotation", ref(id))
	e.wantErr(t, 400, "KMS.3001", "update-key-rotation-interval", `{"key_id":"`+id+`","rotation_interval":29}`)
	e.ok(t, "update-key-rotation-interval", `{"key_id":"`+id+`","rotation_interval":30}`)
	if d := e.describe(t, id); d["key_rotation_enabled"] != "true" {
		t.Errorf("describe = %v", d)
	}

	// After the interval, the next use rotates; old ciphertexts still open.
	e.now = e.now.AddDate(0, 0, 31)
	e.ok(t, "encrypt-data", `{"key_id":"`+id+`","plain_text":"after"}`)
	st := e.ok(t, "get-key-rotation-status", ref(id))
	if st["number_of_rotations"] != float64(1) || st["rotation_interval"] != float64(30) || st["key_rotation_enabled"] != true {
		t.Errorf("status = %v", st)
	}
	if e.ok(t, "decrypt-data", `{"cipher_text":"`+old+`"}`)["plain_text"] != "before" {
		t.Error("old material does not decrypt")
	}
	e.ok(t, "disable-key-rotation", ref(id))
	e.wantErr(t, 400, "KMS.0313", "disable-key-rotation", ref(id))
	sign := e.newKey(t, `{"key_alias":"rsa","key_spec":"RSA_2048"}`)
	e.wantErr(t, 400, "KMS.0325", "enable-key-rotation", ref(sign))
}

func TestTagsAndQuotas(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.newKey(t, `{"key_alias":"tag-a"}`)
	e.newKey(t, `{"key_alias":"tag-b"}`)
	if code, out := e.call(t, http.MethodPost, a+"/tags", `{"tag":{"key":"env","value":"prod"}}`); code != http.StatusNoContent {
		t.Fatalf("create tag = %d %v", code, out)
	}
	if code, _ := e.call(t, http.MethodPost, a+"/tags/action", `{"action":"create","tags":[{"key":"team","value":"core"}]}`); code != http.StatusNoContent {
		t.Fatalf("batch = %d", code)
	}
	_, out := e.call(t, http.MethodGet, a+"/tags", "")
	if out["existTagsNum"] != float64(2) {
		t.Errorf("tags = %v", out)
	}
	_, out = e.call(t, http.MethodGet, "tags", "")
	if len(out["tags"].([]any)) != 2 {
		t.Errorf("project tags = %v", out)
	}
	res := e.ok(t, "resource_instances/action", `{"action":"filter","tags":[{"key":"env","values":["prod"]}]}`)
	if res["total_count"] != float64(1) || res["resources"].([]any)[0].(map[string]any)["resource_id"] != a {
		t.Errorf("by tags = %v", res)
	}
	if res := e.ok(t, "resource_instances/action", `{"action":"count","matches":[{"key":"resource_name","value":"tag-"}]}`); res["total_count"] != float64(2) {
		t.Errorf("count = %v", res)
	}
	if code, _ := e.call(t, http.MethodDelete, a+"/tags/env", ""); code != http.StatusNoContent {
		t.Errorf("delete tag = %d", code)
	}
	if code, out := e.call(t, http.MethodDelete, a+"/tags/env", ""); code != 404 || out["error"].(map[string]any)["error_code"] != "KMS.0416" {
		t.Errorf("delete missing tag = %d %v", code, out)
	}
	if code, out := e.call(t, http.MethodPost, a+"/tags", `{"tag":{"key":"a=b","value":"x"}}`); code != 400 || out["error"].(map[string]any)["error_code"] != "KMS.0406" {
		t.Errorf("bad tag key = %d %v", code, out)
	}
	_, out = e.call(t, http.MethodGet, "user-instances", "")
	if out["instance_num"] != float64(2) {
		t.Errorf("instances = %v", out)
	}
	list := e.ok(t, "list-keys", `{"limit":"1"}`)
	if list["total"] != float64(2) || list["truncated"] != "true" || list["next_marker"] != "1" || len(list["keys"].([]any)) != 1 {
		t.Errorf("list = %v", list)
	}
	if list := e.ok(t, "list-keys", `{"limit":"1","marker":"1"}`); list["truncated"] != "false" || list["keys"].([]any)[0] == a {
		t.Errorf("page 2 = %v", list)
	}
}

func TestDefaultKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tn := tenant{Region: testRegion, ProjectID: testProject, Account: testAccount}
	k, err := e.svc.defaultKey(t.Context(), tn, "obs")
	if err != nil {
		t.Fatal(err)
	}
	again, err := e.svc.defaultKey(t.Context(), tn, "obs")
	if err != nil || again.ID != k.ID {
		t.Fatalf("second default key = %v, %v", again.ID, err)
	}
	if d := e.describe(t, k.ID); d["key_alias"] != "obs/default" || d["default_key_flag"] != "1" {
		t.Errorf("default key = %v", d)
	}
	e.wantErr(t, 400, "KMS.0211", "disable-key", ref(k.ID))
	e.wantErr(t, 400, "KMS.0211", "schedule-key-deletion", `{"key_id":"`+k.ID+`","pending_days":"7"}`)
	e.wantErr(t, 400, "KMS.0211", "enable-key-rotation", ref(k.ID))
}
