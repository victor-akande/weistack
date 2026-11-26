package csms

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	const (
		customEP     = "11111111-2222-3333-4444-555555555555"
		otherProject = "fedcba9876543210fedcba9876543210"
		secretStrV1  = "super-secret-plaintext-v1-value"
		pendingStr   = "pending-delete-secret-plaintext"
		otherStr     = "other-project-secret-plaintext"
		customStage  = "STAGE_CANARY"
		secretDesc   = "internal-rotation-notes-not-reported"
	)
	secretBinV2 := []byte("super-secret-binary-v2-payload\x00\xfe")
	secretBinV2B64 := base64.StdEncoding.EncodeToString(secretBinV2)

	// Active secret in testProject with string v1, binary v2, custom stage, custom EP, and tags.
	createdAt := e.clock.Now()
	status, raw := e.call(t, http.MethodPost, "/v1/{project}/secrets",
		fmt.Sprintf(`{"name":"app-db-secret","secret_string":%q,"enterprise_project_id":%q,"description":%q}`,
			secretStrV1, customEP, secretDesc))
	if status != http.StatusOK {
		t.Fatalf("creating app-db-secret: %d %s", status, raw)
	}
	sec1 := decodeInto[secretResponse](t, raw).Secret

	e.clock.Advance(5 * time.Second)
	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets/app-db-secret/versions",
		fmt.Sprintf(`{"secret_binary":%q}`, secretBinV2B64))
	if status != http.StatusOK {
		t.Fatalf("creating binary v2: %d %s", status, raw)
	}

	e.clock.Advance(3 * time.Second)
	updatedAt := e.clock.Now()
	status, raw = e.call(t, http.MethodPut, "/v1/{project}/secrets/app-db-secret/stages/"+customStage,
		`{"version_id":"v2"}`)
	if status != http.StatusOK {
		t.Fatalf("updating custom stage: %d %s", status, raw)
	}

	status, raw = e.call(t, http.MethodPost, "/v1/{project}/csms/"+sec1.ID+"/tags/action",
		`{"action":"create","tags":[{"key":"tier","value":"prod"},{"key":"team","value":"platform"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("creating tags: %d %s", status, raw)
	}

	// Secret scheduled for deletion (PENDING_DELETE) in testProject.
	e.clock.Advance(4 * time.Second)
	pendingCreated := e.clock.Now()
	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets",
		fmt.Sprintf(`{"name":"pending-del-secret","secret_string":%q}`, pendingStr))
	if status != http.StatusOK {
		t.Fatalf("creating pending-del-secret: %d %s", status, raw)
	}
	sec2 := decodeInto[secretResponse](t, raw).Secret

	e.clock.Advance(2 * time.Second)
	pendingUpdated := e.clock.Now()
	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets/pending-del-secret/scheduled-deleted-tasks/create",
		fmt.Sprintf(`{"recovery_window_in_days":%d}`, minRecoveryDays))
	if status != http.StatusOK {
		t.Fatalf("scheduling deletion: %d %s", status, raw)
	}
	if scheduled := decodeInto[secretResponse](t, raw).Secret; scheduled.State != statePendingDelete {
		t.Fatalf("scheduled secret state = %q, want %q", scheduled.State, statePendingDelete)
	}

	// Secret in a second project.
	e.clock.Advance(6 * time.Second)
	otherCreated := e.clock.Now()
	status, raw = e.call(t, http.MethodPost, "/v1/"+otherProject+"/secrets",
		fmt.Sprintf(`{"name":"other-proj-secret","secret_string":%q}`, otherStr))
	if status != http.StatusOK {
		t.Fatalf("creating secret in second project: %d %s", status, raw)
	}
	sec3 := decodeInto[secretResponse](t, raw).Secret

	// Confirm csms.version records exist in the store with sealed keys and ciphertext
	// before collecting, proving they are intentionally omitted from the inventory.
	ver1, err := e.svc.versions(testTenant).Get(t.Context(), versionStoreKey("app-db-secret", "v1"))
	if err != nil {
		t.Fatalf("store Get v1: %v", err)
	}
	ver2, err := e.svc.versions(testTenant).Get(t.Context(), versionStoreKey("app-db-secret", "v2"))
	if err != nil {
		t.Fatalf("store Get v2: %v", err)
	}
	if len(ver1.SealedKey) == 0 || len(ver1.Ciphertext) == 0 || len(ver2.SealedKey) == 0 || len(ver2.Ciphertext) == 0 {
		t.Fatalf("expected populated version crypto fields in store")
	}

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := make(map[string]inventory.Resource, len(snap.Resources))
	for _, r := range snap.Resources {
		got[r.Type.String()+"/"+r.ProjectID+"/"+r.ID] = r
	}
	at := func(project, id string) inventory.Resource {
		t.Helper()
		r, ok := got[inventory.CSMSSecrets.String()+"/"+project+"/"+id]
		if !ok {
			t.Fatalf("%s %s in %s is not reported; got %+v", inventory.CSMSSecrets, id, project, snap.Resources)
		}
		return r
	}

	wantTags := map[string]string{"tier": "prod", "team": "platform"}
	if r := at(testProject, sec1.ID); r.ID != sec1.ID || r.Name != "app-db-secret" ||
		r.RegionID != testRegion || r.ProjectID != testProject || r.AccountID != "" ||
		r.EnterpriseProjectID != customEP ||
		!r.Created.Equal(createdAt) || !r.Updated.Equal(updatedAt) ||
		r.State != inventory.Succeeded || !reflect.DeepEqual(r.Tags, wantTags) || len(r.Relations) != 0 {
		t.Errorf("app-db-secret = %+v", r)
	}

	if r := at(testProject, sec2.ID); r.ID != sec2.ID || r.Name != "pending-del-secret" ||
		r.RegionID != testRegion || r.ProjectID != testProject || r.AccountID != "" ||
		r.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!r.Created.Equal(pendingCreated) || !r.Updated.Equal(pendingUpdated) ||
		r.State != inventory.Succeeded || len(r.Tags) != 0 || len(r.Relations) != 0 {
		t.Errorf("pending-del-secret = %+v", r)
	}

	if r := at(otherProject, sec3.ID); r.ID != sec3.ID || r.Name != "other-proj-secret" ||
		r.RegionID != testRegion || r.ProjectID != otherProject || r.AccountID != "" ||
		r.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!r.Created.Equal(otherCreated) || !r.Updated.Equal(otherCreated) ||
		r.State != inventory.Succeeded || len(r.Tags) != 0 || len(r.Relations) != 0 {
		t.Errorf("other-proj-secret = %+v", r)
	}

	reportedSecrets := []string{sec1.ID, sec2.ID, sec3.ID}
	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.CSMSSecrets: len(reportedSecrets),
	}
	if !reflect.DeepEqual(count, want) {
		t.Errorf("reported %v, want %v", count, want)
	}

	// Verify no secret string, binary payload, version/stage metadata, KMS key ID,
	// or cryptographic material appears anywhere in the snapshot.
	dump := fmt.Sprintf("%+v", snap)
	forbidden := []struct {
		label string
		text  string
	}{
		{"v1 secret string", secretStrV1},
		{"pending secret string", pendingStr},
		{"other project secret string", otherStr},
		{"v2 binary raw", string(secretBinV2)},
		{"v2 binary base64", secretBinV2B64},
		{"v2 binary hex", hex.EncodeToString(secretBinV2)},
		{"v1 sealed key raw", string(ver1.SealedKey)},
		{"v1 sealed key base64", base64.StdEncoding.EncodeToString(ver1.SealedKey)},
		{"v1 sealed key hex", hex.EncodeToString(ver1.SealedKey)},
		{"v1 ciphertext raw", string(ver1.Ciphertext)},
		{"v1 ciphertext base64", base64.StdEncoding.EncodeToString(ver1.Ciphertext)},
		{"v1 ciphertext hex", hex.EncodeToString(ver1.Ciphertext)},
		{"v2 sealed key base64", base64.StdEncoding.EncodeToString(ver2.SealedKey)},
		{"v2 sealed key hex", hex.EncodeToString(ver2.SealedKey)},
		{"v2 ciphertext base64", base64.StdEncoding.EncodeToString(ver2.Ciphertext)},
		{"v2 ciphertext hex", hex.EncodeToString(ver2.Ciphertext)},
		{"KMS key ID", sec1.KMSKeyID},
		{"secret description", secretDesc},
		{"version v1 ID", "v1"},
		{"version v2 ID", "v2"},
		{"stage SYSCURRENT", stageCurrent},
		{"stage SYSPREVIOUS", stagePrevious},
		{"custom stage", customStage},
	}
	for _, tc := range forbidden {
		if tc.text != "" && strings.Contains(dump, tc.text) {
			t.Errorf("inventory snapshot leaked %s", tc.label)
		}
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()

	sc := store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindSecret}
	for state, want := range map[string]inventory.State{
		stateEnabled:       inventory.Succeeded,
		statePendingDelete: inventory.Succeeded,
	} {
		res := resourceOf(sc, Secret{ID: "sec-id", Name: "sec-name", State: state})
		if res.State != want {
			t.Errorf("resourceOf(State: %s).State = %s, want %s", state, res.State, want)
		}
		if !res.Created.IsZero() || !res.Updated.IsZero() {
			t.Errorf("resourceOf zero timestamps = (%v, %v), want zero", res.Created, res.Updated)
		}
		if res.Tags != nil {
			t.Errorf("resourceOf empty tags = %v, want nil", res.Tags)
		}
	}

	e := newEnv(t)
	status, raw := e.call(t, http.MethodPost, "/v1/{project}/secrets",
		`{"name":"enabled-sec","secret_string":"enabled-val"}`)
	if status != http.StatusOK {
		t.Fatalf("creating enabled-sec: %d %s", status, raw)
	}
	enabledID := decodeInto[secretResponse](t, raw).Secret.ID

	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets",
		`{"name":"scheduled-sec","secret_string":"scheduled-val"}`)
	if status != http.StatusOK {
		t.Fatalf("creating scheduled-sec: %d %s", status, raw)
	}
	scheduledID := decodeInto[secretResponse](t, raw).Secret.ID
	status, raw = e.call(t, http.MethodPost, "/v1/{project}/secrets/scheduled-sec/scheduled-deleted-tasks/create",
		fmt.Sprintf(`{"recovery_window_in_days":%d}`, minRecoveryDays))
	if status != http.StatusOK {
		t.Fatalf("scheduling deletion of scheduled-sec: %d %s", status, raw)
	}

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	states := make(map[string]inventory.State, len(snap.Resources))
	for _, r := range snap.Resources {
		states[r.ID] = r.State
	}
	for id, label := range map[string]string{
		enabledID:   stateEnabled,
		scheduledID: statePendingDelete,
	} {
		if got := states[id]; got != inventory.Succeeded {
			t.Errorf("state(%s / %s) = %s, want %s", label, id, got, inventory.Succeeded)
		}
	}
}
