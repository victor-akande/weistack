package csms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

func TestSecretCRUDGolden(t *testing.T) {
	e := newEnv(t)

	// Empty list and 404s on missing secret.
	e.expect(t, "secret_list_empty", http.MethodGet, "/v1/{project}/secrets", "")
	e.expect(t, "secret_error_0005", http.MethodGet, "/v1/{project}/secrets/missing", "")
	e.expect(t, "secret_error_0005", http.MethodPut, "/v1/{project}/secrets/missing", `{"description":"x"}`)
	e.expect(t, "secret_error_0005", http.MethodDelete, "/v1/{project}/secrets/missing", "")

	// Create secret with default KMS key, description, and event subscription.
	createBody := `{
		"name": "demo-secret",
		"description": "initial description",
		"secret_string": "s3cr3t-v1",
		"event_subscriptions": ["pocEvent"]
	}`
	createdRaw := e.expect(t, "secret_create", http.MethodPost, "/v1/{project}/secrets", createBody)
	created := decodeInto[secretResponse](t, createdRaw)

	// Duplicate create gets 409 CSMS.0101.
	e.expect(t, "secret_error_0101", http.MethodPost, "/v1/{project}/secrets", createBody)

	// Show and list match golden responses.
	e.expect(t, "secret_show", http.MethodGet, "/v1/{project}/secrets/demo-secret", "")
	e.expect(t, "secret_list", http.MethodGet, "/v1/{project}/secrets", "")

	// Advance clock and update metadata.
	e.clock.Advance(5 * time.Second)
	updateBody := `{
		"description": "updated description",
		"event_subscriptions": ["pocEvent2"]
	}`
	updatedRaw := e.expect(t, "secret_update", http.MethodPut, "/v1/{project}/secrets/demo-secret", updateBody)
	updated := decodeInto[secretResponse](t, updatedRaw)
	if updated.Secret.ID != created.Secret.ID {
		t.Fatalf("secret ID changed across update: got %q, want %q", updated.Secret.ID, created.Secret.ID)
	}

	// Clearing description and event_subscriptions works cleanly.
	status, clearedRaw := e.call(t, http.MethodPut, "/v1/{project}/secrets/demo-secret",
		`{"description":"","event_subscriptions":[]}`)
	if status != http.StatusOK {
		t.Fatalf("clear metadata: status = %d, body = %s", status, clearedRaw)
	}
	cleared := decodeInto[secretResponse](t, clearedRaw)
	if cleared.Secret.Description != "" || len(cleared.Secret.EventSubscriptions) != 0 {
		t.Fatalf("cleared secret = %+v, want empty description and event_subscriptions", cleared.Secret)
	}

	// Delete secret immediately: 204 No Content, versions purged, subsequent show/delete 404.
	e.expect(t, "secret_delete", http.MethodDelete, "/v1/{project}/secrets/demo-secret", "")
	e.expect(t, "secret_error_0005", http.MethodGet, "/v1/{project}/secrets/demo-secret", "")
	e.expect(t, "secret_error_0005", http.MethodDelete, "/v1/{project}/secrets/demo-secret", "")
	e.expect(t, "secret_list_empty", http.MethodGet, "/v1/{project}/secrets", "")

	vers, err := e.svc.versions(testTenant).List(context.Background(), nil)
	if err != nil {
		t.Fatalf("versions.List: %v", err)
	}
	if len(vers) != 0 {
		t.Fatalf("leftover versions after DeleteSecret: %d", len(vers))
	}
}

func TestSecretPaginationAndFiltersGolden(t *testing.T) {
	e := newEnv(t)

	for _, name := range []string{"sec-1", "sec-2", "sec-3", "sec-4"} {
		status, out := e.call(t, http.MethodPost, "/v1/{project}/secrets",
			fmt.Sprintf(`{"name":%q,"secret_string":"val-%s"}`, name, name))
		if status != http.StatusOK {
			t.Fatalf("create %s: status = %d, body = %s", name, status, out)
		}
	}

	// Page 1: limit=2 -> sec-1, sec-2; next_marker="sec-2", previous_marker="sec-1".
	e.expect(t, "secret_list_page1", http.MethodGet, "/v1/{project}/secrets?limit=2", "")
	// Page 2: limit=1&marker=sec-2 -> sec-3; next_marker="sec-3", previous_marker="sec-3".
	e.expect(t, "secret_list_page2", http.MethodGet, "/v1/{project}/secrets?limit=1&marker=sec-2", "")
	// Page 3: limit=2&marker=sec-3 -> sec-4; previous_marker="sec-4", no next_marker.
	e.expect(t, "secret_list_page3", http.MethodGet, "/v1/{project}/secrets?limit=2&marker=sec-3", "")
	// Past last item returns empty page cleanly (needed for marker-based ListAllItems callers).
	e.expect(t, "secret_list_empty", http.MethodGet, "/v1/{project}/secrets?limit=2&marker=sec-4", "")

	// event_name filter matches nothing while events are out of scope.
	e.expect(t, "secret_list_empty", http.MethodGet, "/v1/{project}/secrets?event_name=pocEvent", "")

	// with_shared=true and with_shared=false are accepted and ignored.
	e.expect(t, "secret_list_page1", http.MethodGet, "/v1/{project}/secrets?limit=2&with_shared=true", "")
	e.expect(t, "secret_list_page1", http.MethodGet, "/v1/{project}/secrets?limit=2&with_shared=false", "")

	// Invalid query parameters return 400 CSMS.0002.
	badQueries := []string{
		"limit=0",
		"limit=-1",
		fmt.Sprintf("limit=%d", maxListLimit+1),
		"limit=abc",
		"marker=unknown-secret",
		"marker=bad!marker",
		"event_name=bad!event",
		"with_shared=maybe",
	}
	for _, q := range badQueries {
		t.Run(q, func(t *testing.T) {
			e.expect(t, "secret_error_0002", http.MethodGet, "/v1/{project}/secrets?"+q, "")
		})
	}
}

func TestSecretValidationAndUnsupported(t *testing.T) {
	e := newEnv(t)

	// Malformed JSON / empty body -> 400 CSMS.0004.
	for _, body := range []string{"", "{not-json", `{"name":"a","secret_string":"x"}{"extra":1}`} {
		e.expect(t, "secret_error_0004", http.MethodPost, "/v1/{project}/secrets", body)
	}

	// Unsupported secret types and rotation settings -> 501 WeiStack.0501 naming the setting.
	e.expect(t, "secret_error_0501_rds_fg", http.MethodPost, "/v1/{project}/secrets",
		`{"name":"rds-sec","secret_string":"x","secret_type":"RDS-FG"}`)
	e.expect(t, "secret_error_0501_auto_rotation", http.MethodPost, "/v1/{project}/secrets",
		`{"name":"rot-sec","secret_string":"x","auto_rotation":true}`)

	for _, tc := range []struct {
		label string
		body  string
		want  string
	}{
		{"RDS", `{"name":"s1","secret_string":"x","secret_type":"RDS"}`, "secret_type RDS"},
		{"GaussDB-FG", `{"name":"s1","secret_string":"x","secret_type":"GaussDB-FG"}`, "secret_type GaussDB-FG"},
		{"rotation_period", `{"name":"s1","secret_string":"x","rotation_period":"1d"}`, "rotation_period"},
		{"rotation_config", `{"name":"s1","secret_string":"x","rotation_config":"{}"}`, "rotation_config"},
		{"rotation_func_urn", `{"name":"s1","secret_string":"x","rotation_func_urn":"urn:fss:x"}`, "rotation_func_urn"},
	} {
		t.Run("501/"+tc.label, func(t *testing.T) {
			status, raw := e.call(t, http.MethodPost, "/v1/{project}/secrets", tc.body)
			if status != http.StatusNotImplemented {
				t.Fatalf("status = %d, want 501 (body: %s)", status, raw)
			}
			errBody := decodeInto[struct {
				ErrorCode string `json:"error_code"`
				ErrorMsg  string `json:"error_msg"`
			}](t, raw)
			if errBody.ErrorCode != "WeiStack.0501" || !strings.Contains(errBody.ErrorMsg, tc.want) {
				t.Fatalf("got (%q, %q), want WeiStack.0501 mentioning %q", errBody.ErrorCode, errBody.ErrorMsg, tc.want)
			}
		})
	}

	maxValStr := strings.Repeat("v", maxValueBytes)
	overValStr := strings.Repeat("v", maxValueBytes+1)
	maxValBin := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, maxValueBytes))
	overValBin := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, maxValueBytes+1))
	maxDesc := strings.Repeat("d", maxDescriptionBytes)
	overDesc := strings.Repeat("d", maxDescriptionBytes+1)
	overName := strings.Repeat("n", maxDescriptionBytes)

	// Exact boundary values succeed: maxValueBytes string, maxValueBytes binary, maxDescriptionBytes, custom EP ID.
	status, raw := e.call(t, http.MethodPost, "/v1/{project}/secrets", fmt.Sprintf(
		`{"name":"max-str","secret_string":%q,"description":%q,"enterprise_project_id":"11111111-2222-3333-4444-555555555555"}`,
		maxValStr, maxDesc,
	))
	if status != http.StatusOK {
		t.Fatalf("create max-str: status = %d, body = %s", status, raw)
	}
	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets", fmt.Sprintf(
		`{"name":"max-bin","secret_binary":%q,"secret_type":"COMMON","auto_rotation":false}`,
		maxValBin,
	))
	if status != http.StatusOK {
		t.Fatalf("create max-bin: status = %d, body = %s", status, raw)
	}

	// Parameter validation failures -> 400 CSMS.0002.
	var tooManySubs []string
	for i := 0; i <= maxEventSubs; i++ {
		tooManySubs = append(tooManySubs, fmt.Sprintf("ev-%d", i))
	}
	subsJSON, _ := json.Marshal(tooManySubs)

	badCreates := []struct {
		label string
		body  string
	}{
		{"missing name", `{"secret_string":"x"}`},
		{"name with space", `{"name":"bad name","secret_string":"x"}`},
		{"name with dot", `{"name":"bad.name","secret_string":"x"}`},
		{"name too long", fmt.Sprintf(`{"name":%q,"secret_string":"x"}`, overName)},
		{"neither value", `{"name":"no-val"}`},
		{"empty string value", `{"name":"empty-val","secret_string":""}`},
		{"both values", `{"name":"both-val","secret_string":"x","secret_binary":"eA=="}`},
		{"invalid base64", `{"name":"bad-b64","secret_binary":"!!!not-base64!!!"}`},
		{"string over maxValueBytes", fmt.Sprintf(`{"name":"over-str","secret_string":%q}`, overValStr)},
		{"binary over maxValueBytes", fmt.Sprintf(`{"name":"over-bin","secret_binary":%q}`, overValBin)},
		{"description too long", fmt.Sprintf(`{"name":"over-desc","secret_string":"x","description":%q}`, overDesc)},
		{"unknown secret_type", `{"name":"bad-type","secret_string":"x","secret_type":"OTHER"}`},
		{"bad enterprise_project_id", `{"name":"bad-ep","secret_string":"x","enterprise_project_id":"not-an-ep"}`},
		{"bad event subscription name", `{"name":"bad-ev","secret_string":"x","event_subscriptions":["bad!name"]}`},
		{"too many event subscriptions", fmt.Sprintf(`{"name":"many-ev","secret_string":"x","event_subscriptions":%s}`, subsJSON)},
	}
	for _, tc := range badCreates {
		t.Run("create-400/"+tc.label, func(t *testing.T) {
			e.expect(t, "secret_error_0002", http.MethodPost, "/v1/{project}/secrets", tc.body)
		})
	}

	// Update validation & unsupported errors on existing secret "max-str".
	e.expect(t, "secret_error_0004", http.MethodPut, "/v1/{project}/secrets/max-str", "{bad")
	e.expect(t, "secret_error_0501_auto_rotation", http.MethodPut, "/v1/{project}/secrets/max-str", `{"auto_rotation":true}`)
	e.expect(t, "secret_error_0002", http.MethodPut, "/v1/{project}/secrets/max-str", fmt.Sprintf(`{"description":%q}`, overDesc))
	e.expect(t, "secret_error_0002", http.MethodPut, "/v1/{project}/secrets/max-str", `{"event_subscriptions":["bad!ev"]}`)
	e.expect(t, "secret_error_0002", http.MethodPut, "/v1/{project}/secrets/max-str", fmt.Sprintf(`{"event_subscriptions":%s}`, subsJSON))

	// Invalid secret_name in path -> 400 CSMS.0002 on Show, Update, Delete.
	e.expect(t, "secret_error_0002", http.MethodGet, "/v1/{project}/secrets/bad.name", "")
	e.expect(t, "secret_error_0002", http.MethodPut, "/v1/{project}/secrets/bad.name", `{"description":"x"}`)
	e.expect(t, "secret_error_0002", http.MethodDelete, "/v1/{project}/secrets/bad.name", "")
}

func TestSecretPendingDeleteState(t *testing.T) {
	e := newEnv(t)

	status, out := e.call(t, http.MethodPost, "/v1/{project}/secrets",
		`{"name":"pending-sec","secret_string":"keep-safe"}`)
	if status != http.StatusOK {
		t.Fatalf("create pending-sec: status = %d, body = %s", status, out)
	}

	schedAt := testEpoch.Add(minRecoveryDays * 24 * time.Hour).UnixMilli()
	if _, err := e.svc.secrets(testTenant).Update(context.Background(), "pending-sec", func(sec *Secret) error {
		sec.State = statePendingDelete
		sec.ScheduledDeleteAt = schedAt
		return nil
	}); err != nil {
		t.Fatalf("mark pending delete: %v", err)
	}

	// ShowSecret includes scheduled_delete_time while PENDING_DELETE.
	status, showRaw := e.call(t, http.MethodGet, "/v1/{project}/secrets/pending-sec", "")
	if status != http.StatusOK {
		t.Fatalf("show pending-sec: status = %d, body = %s", status, showRaw)
	}
	shown := decodeInto[secretResponse](t, showRaw)
	if shown.Secret.State != statePendingDelete {
		t.Fatalf("state = %q, want %q", shown.Secret.State, statePendingDelete)
	}
	if shown.Secret.ScheduledDeleteTime == nil || *shown.Secret.ScheduledDeleteTime != schedAt {
		t.Fatalf("scheduled_delete_time = %v, want %d", shown.Secret.ScheduledDeleteTime, schedAt)
	}

	// Creating with the same name while PENDING_DELETE gets 409 CSMS.0101.
	e.expect(t, "secret_error_0101", http.MethodPost, "/v1/{project}/secrets",
		`{"name":"pending-sec","secret_string":"replacement"}`)

	// Updating while PENDING_DELETE gets 400 CSMS.0103.
	e.expect(t, "secret_error_0103", http.MethodPut, "/v1/{project}/secrets/pending-sec",
		`{"description":"cannot update"}`)

	// Immediate DeleteSecret succeeds with 204 even while PENDING_DELETE.
	e.expect(t, "secret_delete", http.MethodDelete, "/v1/{project}/secrets/pending-sec", "")
	e.expect(t, "secret_error_0005", http.MethodGet, "/v1/{project}/secrets/pending-sec", "")
}

func TestSecretNoPlaintextInStoreOrLogs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	const (
		strMarker = "SUPER_SECRET_PLAINTEXT_MARKER_99"
		binMarker = "SUPER_SECRET_BINARY_MARKER_88"
	)
	b64BinMarker := base64.StdEncoding.EncodeToString([]byte(binMarker))

	status, out := e.call(t, http.MethodPost, "/v1/{project}/secrets",
		fmt.Sprintf(`{"name":"str-sec","secret_string":%q}`, strMarker))
	if status != http.StatusOK {
		t.Fatalf("create str-sec: status = %d, body = %s", status, out)
	}
	status, out = e.call(t, http.MethodPost, "/v1/{project}/secrets",
		fmt.Sprintf(`{"name":"bin-sec","secret_binary":%q}`, b64BinMarker))
	if status != http.StatusOK {
		t.Fatalf("create bin-sec: status = %d, body = %s", status, out)
	}

	// Exercise show, list, update, and malformed body carrying strMarker.
	e.call(t, http.MethodGet, "/v1/{project}/secrets/str-sec", "")
	e.call(t, http.MethodGet, "/v1/{project}/secrets", "")
	e.call(t, http.MethodPut, "/v1/{project}/secrets/str-sec", `{"description":"non-sensitive"}`)
	e.call(t, http.MethodPost, "/v1/{project}/secrets", `{"name":"broken","secret_string":"`+strMarker)

	// Scan every record in the store across all scopes.
	dump, err := e.store.Dump(ctx)
	if err != nil {
		t.Fatalf("store.Dump: %v", err)
	}
	if len(dump) == 0 {
		t.Fatal("expected non-empty store dump")
	}
	for scope, recs := range dump {
		for _, rec := range recs {
			for _, forbidden := range []string{strMarker, binMarker, b64BinMarker} {
				if bytes.Contains(rec.Data, []byte(forbidden)) || strings.Contains(rec.ID, forbidden) {
					t.Fatalf("plaintext marker %q leaked into store scope %s record %s", forbidden, scope, rec.ID)
				}
			}
		}
	}

	// Confirm the stored v1 ciphertexts genuinely seal strMarker and binMarker under KMS.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(reqctx.With(ctx, &reqctx.Info{Region: testRegion}))
	acctID := e.dir.Account().ID
	for _, tc := range []struct {
		name   string
		binary bool
		want   string
	}{
		{"str-sec", false, strMarker},
		{"bin-sec", true, binMarker},
	} {
		ver, err := e.svc.versions(testTenant).Get(ctx, versionStoreKey(tc.name, "v1"))
		if err != nil {
			t.Fatalf("get %s/v1: %v", tc.name, err)
		}
		if ver.Binary != tc.binary {
			t.Fatalf("%s Binary = %v, want %v", tc.name, ver.Binary, tc.binary)
		}
		dk, err := e.svc.openVersionDataKey(req, testRegion, acctID, ver.KMSKeyID, ver.SealedKey)
		if err != nil {
			t.Fatalf("openVersionDataKey %s: %v", tc.name, err)
		}
		plain, err := open(dk, ver.SecretID, ver.ID, ver.Ciphertext)
		clear(dk)
		if err != nil {
			t.Fatalf("open %s: %v", tc.name, err)
		}
		if string(plain) != tc.want {
			t.Fatalf("decrypted %s = %q, want %q", tc.name, plain, tc.want)
		}
	}

	// Delete one secret and verify debug logs captured activity without any secret material.
	e.expect(t, "secret_delete", http.MethodDelete, "/v1/{project}/secrets/str-sec", "")
	logOut := e.logs.String()
	if !strings.Contains(logOut, "csms secret created") {
		t.Fatalf("expected debug log output to contain 'csms secret created', got:\n%s", logOut)
	}
	for _, forbidden := range []string{strMarker, binMarker, b64BinMarker} {
		if strings.Contains(logOut, forbidden) {
			t.Fatalf("plaintext marker %q leaked into debug logs:\n%s", forbidden, logOut)
		}
	}
}

func TestSecretKMSChecks(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// Before any secret uses the default key, csms/default does not exist.
	if _, err := e.kms.ResolveAlias(ctx, testRegion, "csms/default"); err == nil {
		t.Fatal("expected csms/default to not exist before first secret creation")
	}

	// Creating without kms_key_id creates and uses csms/default.
	status, raw := e.call(t, http.MethodPost, "/v1/{project}/secrets",
		`{"name":"default-kms-sec","secret_string":"alpha"}`)
	if status != http.StatusOK {
		t.Fatalf("create default-kms-sec: status = %d, body = %s", status, raw)
	}
	defResp := decodeInto[secretResponse](t, raw)
	defaultKeyID, err := e.kms.ResolveAlias(ctx, testRegion, "csms/default")
	if err != nil {
		t.Fatalf("ResolveAlias(csms/default): %v", err)
	}
	if defResp.Secret.KMSKeyID != defaultKeyID {
		t.Fatalf("kms_key_id = %q, want csms/default %q", defResp.Secret.KMSKeyID, defaultKeyID)
	}

	// Create a customer KMS key and verify CreateSecret + UpdateSecret use it.
	status, keyRaw := e.call(t, http.MethodPost, "/v1.0/{project}/kms/create-key", `{"key_alias":"custom-cmk"}`)
	if status != http.StatusOK {
		t.Fatalf("kms create-key: status = %d, body = %s", status, keyRaw)
	}
	customKeyID := decodeInto[struct {
		KeyInfo struct {
			KeyID string `json:"key_id"`
		} `json:"key_info"`
	}](t, keyRaw).KeyInfo.KeyID

	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets",
		fmt.Sprintf(`{"name":"custom-kms-sec","kms_key_id":%q,"secret_string":"beta"}`, customKeyID))
	if status != http.StatusOK {
		t.Fatalf("create custom-kms-sec: status = %d, body = %s", status, raw)
	}
	custResp := decodeInto[secretResponse](t, raw)
	if custResp.Secret.KMSKeyID != customKeyID {
		t.Fatalf("kms_key_id = %q, want %q", custResp.Secret.KMSKeyID, customKeyID)
	}

	// Updating default-kms-sec's kms_key_id updates Secret.KMSKeyID while preserving v1's KMSKeyID.
	status, raw = e.call(t, http.MethodPut, "/v1/{project}/secrets/default-kms-sec",
		fmt.Sprintf(`{"kms_key_id":%q}`, customKeyID))
	if status != http.StatusOK {
		t.Fatalf("update kms_key_id: status = %d, body = %s", status, raw)
	}
	updResp := decodeInto[secretResponse](t, raw)
	if updResp.Secret.KMSKeyID != customKeyID {
		t.Fatalf("updated secret kms_key_id = %q, want %q", updResp.Secret.KMSKeyID, customKeyID)
	}
	v1, err := e.svc.versions(testTenant).Get(ctx, versionStoreKey("default-kms-sec", "v1"))
	if err != nil {
		t.Fatalf("get default-kms-sec/v1: %v", err)
	}
	if v1.KMSKeyID != defaultKeyID {
		t.Fatalf("existing v1 kms_key_id = %q, want unchanged %q", v1.KMSKeyID, defaultKeyID)
	}

	// Malformed or unknown kms_key_id -> 400 CSMS.0002 naming kms_key_id.
	for _, badKey := range []string{"not-a-uuid", "11111111-2222-3333-4444-555555555555"} {
		e.expect(t, "secret_error_0002_kms", http.MethodPost, "/v1/{project}/secrets",
			fmt.Sprintf(`{"name":"bad-key-sec","kms_key_id":%q,"secret_string":"x"}`, badKey))
		e.expect(t, "secret_error_0002_kms", http.MethodPut, "/v1/{project}/secrets/custom-kms-sec",
			fmt.Sprintf(`{"kms_key_id":%q}`, badKey))
	}

	// Disabled KMS key -> 400 CSMS.0002 naming kms_key_id on both CreateSecret and UpdateSecret.
	status, disRaw := e.call(t, http.MethodPost, "/v1.0/{project}/kms/disable-key",
		fmt.Sprintf(`{"key_id":%q}`, customKeyID))
	if status != http.StatusOK {
		t.Fatalf("kms disable-key: status = %d, body = %s", status, disRaw)
	}
	e.expect(t, "secret_error_0002_kms", http.MethodPost, "/v1/{project}/secrets",
		fmt.Sprintf(`{"name":"disabled-key-sec","kms_key_id":%q,"secret_string":"x"}`, customKeyID))
	e.expect(t, "secret_error_0002_kms", http.MethodPut, "/v1/{project}/secrets/custom-kms-sec",
		fmt.Sprintf(`{"kms_key_id":%q}`, customKeyID))
}

func TestSecretConcurrency(t *testing.T) {
	e := newEnv(t)

	const workers = 8
	type result struct {
		status int
		code   string
	}
	results := make([]result, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			<-start
			status, body := e.call(t, http.MethodPost, "/v1/{project}/secrets",
				fmt.Sprintf(`{"name":"race-secret","secret_string":"val-%d"}`, idx))
			var errResp struct {
				ErrorCode string `json:"error_code"`
			}
			if status != http.StatusOK {
				_ = json.Unmarshal(body, &errResp)
			}
			results[idx] = result{status: status, code: errResp.ErrorCode}
		}(i)
	}
	close(start)
	wg.Wait()

	var okCount, dupCount int
	for _, r := range results {
		switch {
		case r.status == http.StatusOK:
			okCount++
		case r.status == http.StatusConflict && r.code == "CSMS.0101":
			dupCount++
		default:
			t.Errorf("unexpected response: status=%d code=%q", r.status, r.code)
		}
	}
	if okCount != 1 || dupCount != workers-1 {
		t.Fatalf("ok=%d dup=%d, want ok=1 dup=%d", okCount, dupCount, workers-1)
	}
}

func TestSecretQuota(t *testing.T) {
	limit, extra := 4, 3
	e := newEnvQuotas(t, quota.For(map[quota.Key]int{quota.CSMSSecret: limit}))

	for i := range limit + extra {
		body := fmt.Sprintf(`{"name":"quota-sec-%d","secret_string":"val-%d"}`, i, i)
		if i < limit {
			status, out := e.call(t, http.MethodPost, "/v1/{project}/secrets", body)
			if status != http.StatusOK {
				t.Fatalf("create %d (< limit %d): status = %d, body = %s", i, limit, status, out)
			}
		} else {
			e.expect(t, "secret_error_0202", http.MethodPost, "/v1/{project}/secrets", body)
		}
	}

	// Deleting one secret frees a quota slot.
	e.expect(t, "secret_delete", http.MethodDelete, "/v1/{project}/secrets/quota-sec-0", "")
	status, out := e.call(t, http.MethodPost, "/v1/{project}/secrets",
		`{"name":"quota-sec-replacement","secret_string":"val"}`)
	if status != http.StatusOK {
		t.Fatalf("create after delete: status = %d, body = %s", status, out)
	}
	e.expect(t, "secret_error_0202", http.MethodPost, "/v1/{project}/secrets",
		`{"name":"quota-sec-over-again","secret_string":"val"}`)
}
