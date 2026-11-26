package csms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

func seedSecretForVersionTest(t *testing.T, e *env, name, kmsKeyID, initString string) Secret {
	t.Helper()
	ctx := context.Background()
	dk, err := e.svc.keys.NewDataKey(ctx, testRegion, kmsKeyID, kmsServiceName)
	if err != nil {
		t.Fatalf("NewDataKey: %v", err)
	}
	defer clear(dk.Plain)

	resolvedKeyID := kmsKeyIDFromURN(dk.KeyURN)
	secID := e.svc.ids.UUID()
	now := e.svc.nowMillis()

	ct, err := seal(dk.Plain, secID, "v1", []byte(initString))
	if err != nil {
		t.Fatalf("seal initial version: %v", err)
	}

	ver := Version{
		ID:         "v1",
		SecretID:   secID,
		KMSKeyID:   resolvedKeyID,
		Binary:     false,
		SealedKey:  dk.Sealed,
		Ciphertext: ct,
		CreatedAt:  now,
	}
	if err := e.svc.versions(testTenant).Put(ctx, versionStoreKey(name, "v1"), ver); err != nil {
		t.Fatalf("put initial version: %v", err)
	}

	sec := Secret{
		ID:                  secID,
		Name:                name,
		State:               stateEnabled,
		KMSKeyID:            resolvedKeyID,
		SecretType:          secretTypeCommon,
		EnterpriseProjectID: "0",
		Stages: map[string]Stage{
			stageCurrent: {VersionID: "v1", UpdatedAt: now},
		},
		NextVersion: 2,
		Tags:        []Tag{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := e.svc.secrets(testTenant).Put(ctx, name, sec); err != nil {
		t.Fatalf("put initial secret: %v", err)
	}
	return sec
}

func mustCreateTestKMSKey(t *testing.T, e *env, alias string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"key_alias": alias})
	if err != nil {
		t.Fatalf("marshal kms create-key: %v", err)
	}
	status, raw := e.call(t, http.MethodPost, "/v1.0/{project}/kms/create-key", string(body))
	if status != http.StatusOK {
		t.Fatalf("kms create-key status = %d, body = %s", status, raw)
	}
	resp := decodeInto[struct {
		KeyInfo struct {
			KeyID string `json:"key_id"`
		} `json:"key_info"`
	}](t, raw)
	if resp.KeyInfo.KeyID == "" {
		t.Fatalf("empty key_id in kms create-key response: %s", raw)
	}
	return resp.KeyInfo.KeyID
}

func callSigned(t *testing.T, e *env, host string, creds identity.Credentials, method, path, body string) (int, []byte) {
	t.Helper()
	resolvedPath := strings.ReplaceAll(path, "{project}", testProject)
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, resolvedPath, rd)
	r.Host = host
	r.Header.Set("Host", host)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	sigcheck.SignSDKHMAC(r, creds.AccessKey, creds.SecretKey, r.URL.Path, []byte(body), time.Now())
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading signed response: %v", err)
	}
	return res.StatusCode, out
}

func createIAMV5UserWithPolicy(t *testing.T, e *env, userName, policyName, policyDoc string) identity.Credentials {
	t.Helper()
	const iamHost = "iam.myhuaweicloud.com"

	userBody, _ := json.Marshal(map[string]any{"name": userName, "enabled": true})
	status, raw := callSigned(t, e, iamHost, e.admin, http.MethodPost, "/v5/users", string(userBody))
	if status != http.StatusCreated {
		t.Fatalf("CreateUserV5(%s): status = %d, body = %s", userName, status, raw)
	}
	userResp := decodeInto[struct {
		User struct {
			UserID string `json:"user_id"`
		} `json:"user"`
	}](t, raw)

	status, raw = callSigned(t, e, iamHost, e.admin, http.MethodPost, "/v5/users/"+userResp.User.UserID+"/access-keys", `{}`)
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("CreateAccessKeyV5(%s): status = %d, body = %s", userName, status, raw)
	}
	akResp := decodeInto[struct {
		AccessKey struct {
			AccessKeyID     string `json:"access_key_id"`
			SecretAccessKey string `json:"secret_access_key"`
		} `json:"access_key"`
	}](t, raw)

	polBody, _ := json.Marshal(map[string]string{
		"policy_name":     policyName,
		"policy_document": policyDoc,
	})
	status, raw = callSigned(t, e, iamHost, e.admin, http.MethodPost, "/v5/policies", string(polBody))
	if status != http.StatusCreated {
		t.Fatalf("CreatePolicyV5(%s): status = %d, body = %s", policyName, status, raw)
	}
	polResp := decodeInto[struct {
		Policy struct {
			PolicyID string `json:"policy_id"`
		} `json:"policy"`
	}](t, raw)

	attBody, _ := json.Marshal(map[string]string{"user_id": userResp.User.UserID})
	status, raw = callSigned(t, e, iamHost, e.admin, http.MethodPost, "/v5/policies/"+polResp.Policy.PolicyID+"/attach-user", string(attBody))
	if status != http.StatusOK {
		t.Fatalf("AttachUserPolicyV5(%s): status = %d, body = %s", policyName, status, raw)
	}

	return identity.Credentials{
		AccessKey: akResp.AccessKey.AccessKeyID,
		SecretKey: akResp.AccessKey.SecretAccessKey,
	}
}

func TestVersionCRUDAndGolden(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// Missing secret returns 404 CSMS.0005 across all version endpoints.
	e.expect(t, "version_error_0005", http.MethodPost, "/v1/{project}/secrets/missing-sec/versions", `{"secret_string":"x"}`)
	e.expect(t, "version_error_0005", http.MethodGet, "/v1/{project}/secrets/missing-sec/versions", "")
	e.expect(t, "version_error_0005", http.MethodGet, "/v1/{project}/secrets/missing-sec/versions/v1", "")
	e.expect(t, "version_error_0005", http.MethodPut, "/v1/{project}/secrets/missing-sec/versions/v1", `{"expire_time":1800000000000}`)

	seedSecretForVersionTest(t, e, "demo-secret", "", "initial-secret-v1")

	// Before any read, LastUsedAt is unset.
	secBefore, err := e.svc.secrets(testTenant).Get(ctx, "demo-secret")
	if err != nil {
		t.Fatalf("Get secret before read: %v", err)
	}
	if secBefore.LastUsedAt != 0 {
		t.Fatalf("LastUsedAt before read = %d, want 0", secBefore.LastUsedAt)
	}

	// Advance clock by 5s -> 1795521605000, create v2 (string).
	e.clock.Advance(5 * time.Second)
	e.expect(t, "version_create", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{"secret_string":"rotated-secret-v2"}`)

	// List all versions and paginated versions.
	listOut := e.expect(t, "version_list", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions", "")
	if strings.Contains(string(listOut), "rotated-secret-v2") || strings.Contains(string(listOut), "initial-secret-v1") {
		t.Fatalf("ListSecretVersions leaked secret value: %s", listOut)
	}
	e.expect(t, "version_list_page1", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions?limit=1", "")
	e.expect(t, "version_list_page2", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions?limit=1&marker=v1", "")

	// ShowSecretVersion for v2 (string) and verify last_used_time updated.
	e.clock.Advance(2 * time.Second)
	readMillis := e.svc.nowMillis()
	e.expect(t, "version_show_string", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions/v2", "")

	secAfter, err := e.svc.secrets(testTenant).Get(ctx, "demo-secret")
	if err != nil {
		t.Fatalf("Get secret after read: %v", err)
	}
	if secAfter.LastUsedAt != readMillis {
		t.Fatalf("LastUsedAt after read = %d, want %d", secAfter.LastUsedAt, readMillis)
	}

	// Advance clock by 3s -> total +10s (1795521610000), create v3 (binary: []byte{0,1,2,3} -> "AAECAw==").
	e.clock.Advance(3 * time.Second)
	binRaw := []byte{0x00, 0x01, 0x02, 0x03}
	binB64 := base64.StdEncoding.EncodeToString(binRaw)
	status, createBinOut := e.call(t, http.MethodPost, "/v1/{project}/secrets/demo-secret/versions",
		fmt.Sprintf(`{"secret_binary":%q}`, binB64))
	if status != http.StatusOK {
		t.Fatalf("create binary v3: status = %d, body = %s", status, createBinOut)
	}

	// ShowSecretVersion via explicit v3 and via "latest" both return v3 binary.
	e.expect(t, "version_show_binary", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions/v3", "")
	e.expect(t, "version_show_binary", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions/latest", "")

	// UpdateVersion sets expire_time on v2 (which now holds SYSPREVIOUS).
	e.expect(t, "version_update", http.MethodPut, "/v1/{project}/secrets/demo-secret/versions/v2", `{"expire_time":1800000000000}`)

	// Verify raw store records never contain plaintext secret values.
	dump, err := e.store.Dump(ctx)
	if err != nil {
		t.Fatalf("store.Dump: %v", err)
	}
	for scope, recs := range dump {
		for _, rec := range recs {
			for _, needle := range [][]byte{
				[]byte("initial-secret-v1"),
				[]byte("rotated-secret-v2"),
				[]byte(binB64),
			} {
				if bytes.Contains(rec.Data, needle) {
					t.Fatalf("stored record %s/%s contains plaintext %q", scope, rec.ID, needle)
				}
			}
		}
	}

	// Validation & missing-version errors.
	e.expect(t, "version_error_0005", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions/v99", "")
	e.expect(t, "version_error_0005", http.MethodPut, "/v1/{project}/secrets/demo-secret/versions/v99", `{"expire_time":1800000000000}`)

	e.expect(t, "version_error_0004", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{bad-json`)
	e.expect(t, "version_error_0004", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", ``)
	e.expect(t, "version_error_0004", http.MethodPut, "/v1/{project}/secrets/demo-secret/versions/v1", `{bad-json`)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"bad secret name on create", http.MethodPost, "/v1/{project}/secrets/bad.name/versions", `{"secret_string":"x"}`},
		{"neither string nor binary", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{}`},
		{"both string and binary", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{"secret_string":"a","secret_binary":"YQ=="}`},
		{"invalid base64 binary", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{"secret_binary":"!!!not-base64!!!"}`},
		{"empty version_stages", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{"secret_string":"x","version_stages":[]}`},
		{"invalid stage name", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{"secret_string":"x","version_stages":["bad.stage"]}`},
		{"duplicate stage names", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{"secret_string":"x","version_stages":["dup","dup"]}`},
		{"negative expire_time on create", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{"secret_string":"x","expire_time":-1}`},
		{"bad secret name on list", http.MethodGet, "/v1/{project}/secrets/bad.name/versions", ""},
		{"limit zero", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions?limit=0", ""},
		{"limit over max", http.MethodGet, fmt.Sprintf("/v1/{project}/secrets/demo-secret/versions?limit=%d", maxListLimit+1), ""},
		{"bad marker syntax", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions?marker=bad", ""},
		{"unknown marker", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions?marker=v99", ""},
		{"bad version_id on show", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions/not-a-ver", ""},
		{"latest disallowed on update", http.MethodPut, "/v1/{project}/secrets/demo-secret/versions/latest", `{"expire_time":1800000000000}`},
		{"missing expire_time on update", http.MethodPut, "/v1/{project}/secrets/demo-secret/versions/v1", `{}`},
		{"negative expire_time on update", http.MethodPut, "/v1/{project}/secrets/demo-secret/versions/v1", `{"expire_time":-5}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "version_error_0002", tc.method, tc.path, tc.body)
		})
	}

	// Secret in PENDING_DELETE blocks ShowSecretVersion with 403 CSMS.0109 and mutations with 400 CSMS.0103.
	secPending, err := e.svc.secrets(testTenant).Get(ctx, "demo-secret")
	if err != nil {
		t.Fatalf("Get secret: %v", err)
	}
	secPending.State = statePendingDelete
	secPending.ScheduledDeleteAt = e.svc.nowMillis() + 7*24*3600*1000
	if err := e.svc.secrets(testTenant).Put(ctx, "demo-secret", secPending); err != nil {
		t.Fatalf("Put pending secret: %v", err)
	}

	e.expect(t, "version_error_0109", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions/v2", "")
	e.expect(t, "version_error_0109", http.MethodGet, "/v1/{project}/secrets/demo-secret/versions/latest", "")
	e.expect(t, "version_error_0103", http.MethodPost, "/v1/{project}/secrets/demo-secret/versions", `{"secret_string":"blocked"}`)
	e.expect(t, "version_error_0103", http.MethodPut, "/v1/{project}/secrets/demo-secret/versions/v2", `{"expire_time":1800000000000}`)
}

func TestVersionSizeBoundary(t *testing.T) {
	e := newEnv(t)
	seedSecretForVersionTest(t, e, "size-sec", "", "init")

	exactStr := strings.Repeat("s", maxValueBytes)
	overStr := strings.Repeat("s", maxValueBytes+1)

	status, raw := e.call(t, http.MethodPost, "/v1/{project}/secrets/size-sec/versions",
		fmt.Sprintf(`{"secret_string":%q}`, exactStr))
	if status != http.StatusOK {
		t.Fatalf("maxValueBytes string rejected: status = %d, body = %s", status, raw)
	}

	status, raw = e.call(t, http.MethodGet, "/v1/{project}/secrets/size-sec/versions/v2", "")
	if status != http.StatusOK {
		t.Fatalf("ShowSecretVersion maxValueBytes string: status = %d, body = %s", status, raw)
	}
	gotStr := decodeInto[versionResponse](t, raw)
	if gotStr.Version.SecretString == nil || len(*gotStr.Version.SecretString) != maxValueBytes {
		t.Fatalf("round-trip string length mismatch")
	}

	e.expect(t, "version_error_0002", http.MethodPost, "/v1/{project}/secrets/size-sec/versions",
		fmt.Sprintf(`{"secret_string":%q}`, overStr))

	exactBin := bytes.Repeat([]byte{0xab}, maxValueBytes)
	overBin := bytes.Repeat([]byte{0xab}, maxValueBytes+1)

	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets/size-sec/versions",
		fmt.Sprintf(`{"secret_binary":%q}`, base64.StdEncoding.EncodeToString(exactBin)))
	if status != http.StatusOK {
		t.Fatalf("maxValueBytes binary rejected: status = %d, body = %s", status, raw)
	}

	e.expect(t, "version_error_0002", http.MethodPost, "/v1/{project}/secrets/size-sec/versions",
		fmt.Sprintf(`{"secret_binary":%q}`, base64.StdEncoding.EncodeToString(overBin)))
}

func TestStageLifecycleAndGolden(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// Create v1 (at testEpoch), v2 (+5s), v3 (+10s -> 1795521610000).
	seedSecretForVersionTest(t, e, "stage-demo", "", "val-1")
	e.clock.Advance(5 * time.Second)
	status, raw := e.call(t, http.MethodPost, "/v1/{project}/secrets/stage-demo/versions", `{"secret_string":"val-2"}`)
	if status != http.StatusOK {
		t.Fatalf("create v2: status = %d, body = %s", status, raw)
	}
	e.clock.Advance(5 * time.Second)
	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets/stage-demo/versions", `{"secret_string":"val-3"}`)
	if status != http.StatusOK {
		t.Fatalf("create v3: status = %d, body = %s", status, raw)
	}

	// Verify three versions leave SYSCURRENT on v3, SYSPREVIOUS on v2, and v1 stage-less.
	status, raw = e.call(t, http.MethodGet, "/v1/{project}/secrets/stage-demo/versions", "")
	if status != http.StatusOK {
		t.Fatalf("list versions: status = %d, body = %s", status, raw)
	}
	listed := decodeInto[listVersionsResponse](t, raw)
	if len(listed.VersionMetadatas) != 3 {
		t.Fatalf("version count = %d, want 3", len(listed.VersionMetadatas))
	}
	if len(listed.VersionMetadatas[0].VersionStages) != 0 {
		t.Fatalf("v1 stages = %v, want empty", listed.VersionMetadatas[0].VersionStages)
	}
	if got := listed.VersionMetadatas[1].VersionStages; len(got) != 1 || got[0] != stagePrevious {
		t.Fatalf("v2 stages = %v, want [%s]", got, stagePrevious)
	}
	if got := listed.VersionMetadatas[2].VersionStages; len(got) != 1 || got[0] != stageCurrent {
		t.Fatalf("v3 stages = %v, want [%s]", got, stageCurrent)
	}

	// ShowSecretStage golden for SYSCURRENT (v3 at 1795521610000).
	e.expect(t, "stage_show", http.MethodGet, "/v1/{project}/secrets/stage-demo/stages/SYSCURRENT", "")

	// Advance clock +5s -> 1795521615000, create custom stage "canary" on v1 (golden).
	e.clock.Advance(5 * time.Second)
	e.expect(t, "stage_update", http.MethodPut, "/v1/{project}/secrets/stage-demo/stages/canary", `{"version_id":"v1"}`)

	// Move custom stage "canary" from v1 to v2 and verify v1 loses it.
	e.clock.Advance(5 * time.Second)
	status, raw = e.call(t, http.MethodPut, "/v1/{project}/secrets/stage-demo/stages/canary", `{"version_id":"v2"}`)
	if status != http.StatusOK {
		t.Fatalf("move canary to v2: status = %d, body = %s", status, raw)
	}
	stResp := decodeInto[stageResponse](t, raw)
	if stResp.Stage.VersionID != "v2" {
		t.Fatalf("canary version_id = %q, want v2", stResp.Stage.VersionID)
	}

	status, raw = e.call(t, http.MethodGet, "/v1/{project}/secrets/stage-demo/versions", "")
	if status != http.StatusOK {
		t.Fatalf("list after stage move: status = %d", status)
	}
	listed = decodeInto[listVersionsResponse](t, raw)
	if len(listed.VersionMetadatas[0].VersionStages) != 0 {
		t.Fatalf("v1 stages after moving canary = %v, want empty", listed.VersionMetadatas[0].VersionStages)
	}
	if got := listed.VersionMetadatas[1].VersionStages; len(got) != 2 || got[0] != stagePrevious || got[1] != "canary" {
		t.Fatalf("v2 stages = %v, want [SYSPREVIOUS canary]", got)
	}

	// Deleting SYSCURRENT or SYSPREVIOUS returns 400 CSMS.0105.
	e.expect(t, "stage_error_0105", http.MethodDelete, "/v1/{project}/secrets/stage-demo/stages/SYSCURRENT", "")
	e.expect(t, "stage_error_0105", http.MethodDelete, "/v1/{project}/secrets/stage-demo/stages/SYSPREVIOUS", "")

	// Deleting custom stage "canary" returns 204, then Show/Delete return 404 CSMS.0005.
	e.expect(t, "stage_delete", http.MethodDelete, "/v1/{project}/secrets/stage-demo/stages/canary", "")
	e.expect(t, "version_error_0005", http.MethodGet, "/v1/{project}/secrets/stage-demo/stages/canary", "")
	e.expect(t, "version_error_0005", http.MethodDelete, "/v1/{project}/secrets/stage-demo/stages/canary", "")

	// Missing secret / unknown version_id / bad format / bad params on stages.
	e.expect(t, "version_error_0005", http.MethodGet, "/v1/{project}/secrets/no-such-secret/stages/SYSCURRENT", "")
	e.expect(t, "version_error_0005", http.MethodPut, "/v1/{project}/secrets/no-such-secret/stages/canary", `{"version_id":"v1"}`)
	e.expect(t, "version_error_0005", http.MethodDelete, "/v1/{project}/secrets/no-such-secret/stages/SYSCURRENT", "")
	e.expect(t, "version_error_0005", http.MethodPut, "/v1/{project}/secrets/stage-demo/stages/canary", `{"version_id":"v99"}`)
	e.expect(t, "version_error_0004", http.MethodPut, "/v1/{project}/secrets/stage-demo/stages/canary", `{bad-json`)
	e.expect(t, "version_error_0002", http.MethodPut, "/v1/{project}/secrets/stage-demo/stages/canary", `{"version_id":""}`)
	e.expect(t, "version_error_0002", http.MethodPut, "/v1/{project}/secrets/stage-demo/stages/canary", `{"version_id":"latest"}`)
	e.expect(t, "version_error_0002", http.MethodGet, "/v1/{project}/secrets/stage-demo/stages/bad.stage", "")
	e.expect(t, "version_error_0002", http.MethodDelete, "/v1/{project}/secrets/stage-demo/stages/bad.stage", "")

	// PENDING_DELETE secret blocks stage updates & deletes with 400 CSMS.0103.
	sec, err := e.svc.secrets(testTenant).Get(ctx, "stage-demo")
	if err != nil {
		t.Fatalf("Get stage-demo: %v", err)
	}
	sec.State = statePendingDelete
	if err := e.svc.secrets(testTenant).Put(ctx, "stage-demo", sec); err != nil {
		t.Fatalf("Put stage-demo pending: %v", err)
	}
	e.expect(t, "version_error_0103", http.MethodPut, "/v1/{project}/secrets/stage-demo/stages/canary", `{"version_id":"v1"}`)
	e.expect(t, "version_error_0103", http.MethodDelete, "/v1/{project}/secrets/stage-demo/stages/SYSCURRENT", "")
}

func TestVersionPruningAndStageLimit(t *testing.T) {
	e := newEnv(t)

	// Seed v1 and pin a custom stage "pinned" on v1 so v1 is never stage-less.
	seedSecretForVersionTest(t, e, "prune-sec", "", "val-1")
	status, raw := e.call(t, http.MethodPut, "/v1/{project}/secrets/prune-sec/stages/pinned", `{"version_id":"v1"}`)
	if status != http.StatusOK {
		t.Fatalf("pin v1: status = %d, body = %s", status, raw)
	}

	limit, extra := maxVersionsPerSecret, 3
	total := limit + extra
	for n := 2; n <= total; n++ {
		e.clock.Advance(time.Second)
		status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets/prune-sec/versions",
			fmt.Sprintf(`{"secret_string":"val-%d"}`, n))
		if status != http.StatusOK {
			t.Fatalf("create v%d: status = %d, body = %s", n, status, raw)
		}
	}

	status, raw = e.call(t, http.MethodGet, "/v1/{project}/secrets/prune-sec/versions", "")
	if status != http.StatusOK {
		t.Fatalf("list pruned versions: status = %d, body = %s", status, raw)
	}
	listed := decodeInto[listVersionsResponse](t, raw)
	if len(listed.VersionMetadatas) != limit {
		t.Fatalf("stored version count = %d, want %d", len(listed.VersionMetadatas), limit)
	}
	// v1 must still exist because it holds "pinned"; v2..v(1+extra) were oldest stage-less and pruned.
	if listed.VersionMetadatas[0].ID != "v1" {
		t.Fatalf("first remaining version = %q, want v1", listed.VersionMetadatas[0].ID)
	}
	wantSecond := fmt.Sprintf("v%d", 2+extra)
	if listed.VersionMetadatas[1].ID != wantSecond {
		t.Fatalf("second remaining version = %q, want %q", listed.VersionMetadatas[1].ID, wantSecond)
	}
	for n := 2; n < 2+extra; n++ {
		prunedVer := fmt.Sprintf("v%d", n)
		e.expect(t, "version_error_0005", http.MethodGet, "/v1/{project}/secrets/prune-sec/versions/"+prunedVer, "")
	}

	// Stage quota check derived from maxStagesPerSecret:
	// prune-sec currently has 3 stages: SYSCURRENT, SYSPREVIOUS, pinned.
	stageLimit := maxStagesPerSecret
	existingStages := 3
	latestID := fmt.Sprintf("v%d", total)
	for i := 1; i <= stageLimit-existingStages; i++ {
		stageName := fmt.Sprintf("custom-%d", i)
		status, raw = e.call(t, http.MethodPut, "/v1/{project}/secrets/prune-sec/stages/"+stageName,
			fmt.Sprintf(`{"version_id":%q}`, latestID))
		if status != http.StatusOK {
			t.Fatalf("add stage %s: status = %d, body = %s", stageName, status, raw)
		}
	}

	// Moving an existing stage when at maxStagesPerSecret still succeeds.
	status, raw = e.call(t, http.MethodPut, "/v1/{project}/secrets/prune-sec/stages/custom-1", `{"version_id":"v1"}`)
	if status != http.StatusOK {
		t.Fatalf("move existing stage at limit: status = %d, body = %s", status, raw)
	}

	// Adding one more stage via UpdateSecretStage or CreateSecretVersion fails with 400 CSMS.0203.
	e.expect(t, "version_error_0203", http.MethodPut, "/v1/{project}/secrets/prune-sec/stages/overflow-stage", `{"version_id":"v1"}`)
	e.expect(t, "version_error_0203", http.MethodPost, "/v1/{project}/secrets/prune-sec/versions",
		`{"secret_string":"overflow","version_stages":["brand-new-stage"]}`)

	tooMany := make([]string, stageLimit+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("st-%d", i)
	}
	tooManyBody, _ := json.Marshal(map[string]any{
		"secret_string":  "overflow",
		"version_stages": tooMany,
	})
	e.expect(t, "version_error_0203", http.MethodPost, "/v1/{project}/secrets/prune-sec/versions", string(tooManyBody))
}

func TestVersionKMSDisableAndPermissions(t *testing.T) {
	t.Run("disable_and_enable_kms_key", func(t *testing.T) {
		e := newEnv(t)
		keyID := mustCreateTestKMSKey(t, e, "csms-ver-cmk")
		seedSecretForVersionTest(t, e, "kms-sec", keyID, "kms-protected-v1")

		status, raw := e.call(t, http.MethodPost, "/v1/{project}/secrets/kms-sec/versions", `{"secret_string":"kms-protected-v2"}`)
		if status != http.StatusOK {
			t.Fatalf("create v2 with KMS key: status = %d, body = %s", status, raw)
		}

		// Disable KMS key: reading fails with 400 CSMS.0401, creating new version fails with 400 CSMS.0002.
		disBody, _ := json.Marshal(map[string]string{"key_id": keyID})
		status, raw = e.call(t, http.MethodPost, "/v1.0/{project}/kms/disable-key", string(disBody))
		if status != http.StatusOK {
			t.Fatalf("kms disable-key: status = %d, body = %s", status, raw)
		}

		e.expect(t, "version_error_0401", http.MethodGet, "/v1/{project}/secrets/kms-sec/versions/v2", "")
		e.expect(t, "version_error_0401", http.MethodGet, "/v1/{project}/secrets/kms-sec/versions/latest", "")

		status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets/kms-sec/versions", `{"secret_string":"cannot-encrypt"}`)
		if status != http.StatusBadRequest {
			t.Fatalf("create version with disabled key: status = %d, want 400 (body: %s)", status, raw)
		}
		errResp := decodeInto[struct {
			ErrorCode string `json:"error_code"`
		}](t, raw)
		if errResp.ErrorCode != "CSMS.0002" {
			t.Fatalf("create version with disabled key: error_code = %q, want CSMS.0002", errResp.ErrorCode)
		}

		// Re-enable KMS key: reading works again!
		status, raw = e.call(t, http.MethodPost, "/v1.0/{project}/kms/enable-key", string(disBody))
		if status != http.StatusOK {
			t.Fatalf("kms enable-key: status = %d, body = %s", status, raw)
		}
		status, raw = e.call(t, http.MethodGet, "/v1/{project}/secrets/kms-sec/versions/v2", "")
		if status != http.StatusOK {
			t.Fatalf("ShowSecretVersion after enable-key: status = %d, body = %s", status, raw)
		}
		got := decodeInto[versionResponse](t, raw)
		if got.Version.SecretString == nil || *got.Version.SecretString != "kms-protected-v2" {
			t.Fatalf("unexpected secret_string after enable-key: %+v", got.Version)
		}
	})

	t.Run("enforce_kms_dependency_and_agent_policy", func(t *testing.T) {
		e := newEnvWith(t, envOptions{iam: config.IAMEnforce})
		seedSecretForVersionTest(t, e, "agent-sec", "", "top-secret-agent-val")

		// 1. User with csms:secret:* but WITHOUT kms:cmk:decryptDataKey / kms:cmk:createDataKey.
		noKMSDoc := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["csms:secret:*"],"Resource":["*"]}]}`
		noKMSCreds := createIAMV5UserWithPolicy(t, e, "no-kms-user", "csms-without-kms", noKMSDoc)

		status, raw := callSigned(t, e, testHost, noKMSCreds, http.MethodGet, "/v1/{project}/secrets/agent-sec/versions", "")
		if status != http.StatusOK {
			t.Fatalf("no-kms-user ListSecretVersions: status = %d, body = %s", status, raw)
		}

		status, raw = callSigned(t, e, testHost, noKMSCreds, http.MethodGet, "/v1/{project}/secrets/agent-sec/versions/v1", "")
		if status != http.StatusForbidden {
			t.Fatalf("no-kms-user ShowSecretVersion: status = %d, want 403 (body: %s)", status, raw)
		}
		if code := decodeInto[struct {
			ErrorCode string `json:"error_code"`
		}](t, raw).ErrorCode; code != "CSMS.0302" {
			t.Fatalf("no-kms-user ShowSecretVersion error_code = %q, want CSMS.0302", code)
		}

		status, raw = callSigned(t, e, testHost, noKMSCreds, http.MethodPost, "/v1/{project}/secrets/agent-sec/versions", `{"secret_string":"denied"}`)
		if status != http.StatusForbidden {
			t.Fatalf("no-kms-user CreateSecretVersion: status = %d, want 403 (body: %s)", status, raw)
		}

		// 2. Agent user with csms:secret:* + kms:cmk:* but explicit Deny on csms:secret:getVersion.
		agentDoc := `{"Version":"5.0","Statement":[` +
			`{"Effect":"Allow","Action":["csms:secret:*","kms:cmk:*"],"Resource":["*"]},` +
			`{"Effect":"Deny","Action":["csms:secret:getVersion"],"Resource":["*"]}` +
			`]}`
		agentCreds := createIAMV5UserWithPolicy(t, e, "agent-user", "agent-no-read-value", agentDoc)

		status, raw = callSigned(t, e, testHost, agentCreds, http.MethodPost, "/v1/{project}/secrets/agent-sec/versions", `{"secret_string":"agent-wrote-v2"}`)
		if status != http.StatusOK {
			t.Fatalf("agent-user CreateSecretVersion: status = %d, body = %s", status, raw)
		}

		status, raw = callSigned(t, e, testHost, agentCreds, http.MethodGet, "/v1/{project}/secrets/agent-sec/versions", "")
		if status != http.StatusOK {
			t.Fatalf("agent-user ListSecretVersions: status = %d, body = %s", status, raw)
		}

		status, raw = callSigned(t, e, testHost, agentCreds, http.MethodGet, "/v1/{project}/secrets/agent-sec/stages/SYSCURRENT", "")
		if status != http.StatusOK {
			t.Fatalf("agent-user ShowSecretStage: status = %d, body = %s", status, raw)
		}

		status, raw = callSigned(t, e, testHost, agentCreds, http.MethodGet, "/v1/{project}/secrets/agent-sec/versions/latest", "")
		if status != http.StatusForbidden {
			t.Fatalf("agent-user ShowSecretVersion: status = %d, want 403 (body: %s)", status, raw)
		}
		if code := decodeInto[struct {
			ErrorCode string `json:"error_code"`
		}](t, raw).ErrorCode; code != "CSMS.0302" {
			t.Fatalf("agent-user ShowSecretVersion error_code = %q, want CSMS.0302", code)
		}
	})
}

func TestVersionNoSecretsInLogs(t *testing.T) {
	e := newEnv(t)

	const (
		initSentinel = "sentinel-initial-value-alpha-9001"
		strSentinel  = "sentinel-string-value-bravo-9002"
		binSentinel  = "sentinel-binary-value-charlie-9003"
	)
	binB64 := base64.StdEncoding.EncodeToString([]byte(binSentinel))

	seedSecretForVersionTest(t, e, "log-hygiene", "", initSentinel)

	status, raw := e.call(t, http.MethodPost, "/v1/{project}/secrets/log-hygiene/versions",
		fmt.Sprintf(`{"secret_string":%q}`, strSentinel))
	if status != http.StatusOK {
		t.Fatalf("create string version: status = %d, body = %s", status, raw)
	}

	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets/log-hygiene/versions",
		fmt.Sprintf(`{"secret_binary":%q}`, binB64))
	if status != http.StatusOK {
		t.Fatalf("create binary version: status = %d, body = %s", status, raw)
	}

	for _, verID := range []string{"v1", "v2", "v3", "latest"} {
		status, raw = e.call(t, http.MethodGet, "/v1/{project}/secrets/log-hygiene/versions/"+verID, "")
		if status != http.StatusOK {
			t.Fatalf("ShowSecretVersion(%s): status = %d, body = %s", verID, status, raw)
		}
	}

	status, raw = e.call(t, http.MethodPut, "/v1/{project}/secrets/log-hygiene/stages/prod", `{"version_id":"v2"}`)
	if status != http.StatusOK {
		t.Fatalf("UpdateSecretStage: status = %d, body = %s", status, raw)
	}

	logs := e.logs.String()
	if !strings.Contains(logs, "csms secret version created") || !strings.Contains(logs, "csms secret version read") {
		t.Fatalf("expected debug logs to be captured, got:\n%s", logs)
	}
	for _, forbidden := range []string{initSentinel, strSentinel, binSentinel, binB64} {
		if strings.Contains(logs, forbidden) {
			t.Fatalf("logs leaked secret material %q:\n%s", forbidden, logs)
		}
	}
}
