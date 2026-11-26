package csms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/faults"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/services/kms"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

type lcGrants struct {
	doc string
}

func (g lcGrants) Grants(context.Context, identity.Principal, authz.Scope) (authz.Grants, error) {
	if g.doc == "" {
		return authz.Grants{}, nil
	}
	p, err := policydoc.Parse([]byte(g.doc))
	if err != nil {
		return authz.Grants{}, err
	}
	return authz.Grants{
		Sources: []policydoc.Source{{Name: "lc-test-policy", Policy: p}},
	}, nil
}

func lcDoWithGate(t *testing.T, e *env, policyJSON, method, path, body string) (int, []byte) {
	t.Helper()
	r := chi.NewRouter()
	e.kms.Routes(r)

	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, strings.ReplaceAll(path, "{project}", testProject), rd)
	req.Host = testHost
	req.Header.Set("Content-Type", "application/json")

	acct := e.dir.Account()
	gate := authz.NewGate(authz.GateOptions{
		Principal: identity.Principal{AccountID: acct.ID, UserID: "u-lc-test", UserName: "lc-tester"},
		Account:   acct.ID,
		Provider:  lcGrants{doc: policyJSON},
		Sealer:    e.vault,
		Log:       e.svc.log,
	})
	ctx := reqctx.With(req.Context(), &reqctx.Info{RequestID: "req-lc-authz", Service: "kms", Region: testRegion})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req.WithContext(authz.WithGate(ctx, gate)))
	return w.Code, w.Body.Bytes()
}

func lcSeedSecretWithVersions(
	t *testing.T,
	svc *Service,
	kmsSvc *kms.Service,
	ten Tenant,
	name, desc string,
	stringVal string,
	binaryVal []byte,
	tags []Tag,
) Secret {
	t.Helper()
	ctx := context.Background()
	now := svc.nowMillis()
	secID := svc.ids.UUID()

	dk1, err := kmsSvc.NewDataKey(ctx, ten.Region, "", kmsServiceName)
	if err != nil {
		t.Fatalf("NewDataKey v1: %v", err)
	}
	keyID := kmsKeyIDFromURN(dk1.KeyURN)
	ct1, err := seal(dk1.Plain, secID, "v1", []byte(stringVal))
	if err != nil {
		t.Fatalf("seal v1: %v", err)
	}
	v1 := Version{
		ID:         "v1",
		SecretID:   secID,
		KMSKeyID:   keyID,
		Binary:     false,
		SealedKey:  dk1.Sealed,
		Ciphertext: ct1,
		CreatedAt:  now,
	}
	if err := svc.versions(ten).Put(ctx, versionStoreKey(name, v1.ID), v1); err != nil {
		t.Fatalf("put v1: %v", err)
	}

	stages := map[string]Stage{
		stageCurrent: {VersionID: "v1", UpdatedAt: now},
	}
	nextVer := 2

	if len(binaryVal) > 0 {
		dk2, err := kmsSvc.NewDataKey(ctx, ten.Region, keyID, kmsServiceName)
		if err != nil {
			t.Fatalf("NewDataKey v2: %v", err)
		}
		ct2, err := seal(dk2.Plain, secID, "v2", binaryVal)
		if err != nil {
			t.Fatalf("seal v2: %v", err)
		}
		v2 := Version{
			ID:         "v2",
			SecretID:   secID,
			KMSKeyID:   keyID,
			Binary:     true,
			SealedKey:  dk2.Sealed,
			Ciphertext: ct2,
			CreatedAt:  now,
		}
		if err := svc.versions(ten).Put(ctx, versionStoreKey(name, v2.ID), v2); err != nil {
			t.Fatalf("put v2: %v", err)
		}
		stages[stagePrevious] = Stage{VersionID: "v1", UpdatedAt: now}
		stages[stageCurrent] = Stage{VersionID: "v2", UpdatedAt: now}
		stages["PROD"] = Stage{VersionID: "v1", UpdatedAt: now}
		nextVer = 3
	}

	if tags == nil {
		tags = []Tag{}
	}
	sec := Secret{
		ID:                  secID,
		Name:                name,
		State:               stateEnabled,
		KMSKeyID:            keyID,
		Description:         desc,
		SecretType:          secretTypeCommon,
		EnterpriseProjectID: "0",
		Stages:              stages,
		NextVersion:         nextVer,
		Tags:                tags,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := svc.secrets(ten).Put(ctx, sec.Name, sec); err != nil {
		t.Fatalf("put secret %q: %v", name, err)
	}
	return sec
}

func lcDecryptVersion(t *testing.T, kmsSvc *kms.Service, region, secID string, ver Version) []byte {
	t.Helper()
	plainKey, err := kmsSvc.OpenDataKey(context.Background(), region, ver.SealedKey)
	if err != nil {
		t.Fatalf("OpenDataKey(%s): %v", ver.ID, err)
	}
	raw, err := open(plainKey, secID, ver.ID, ver.Ciphertext)
	if err != nil {
		t.Fatalf("open(%s): %v", ver.ID, err)
	}
	return raw
}

func TestScheduleDeleteAndRestoreGoldenAndLifecycle(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	const (
		secretVal1 = "SCHED-SUPER-SECRET-VAL-1"
		secretVal2 = "SCHED-SUPER-SECRET-VAL-2"
		windowDays = 15
	)

	lcSeedSecretWithVersions(t, e.svc, e.kms, testTenant, "sched-sec", "scheduled test secret", secretVal1, []byte(secretVal2), nil)
	lcSeedSecretWithVersions(t, e.svc, e.kms, testTenant, "sched-default", "scheduled default secret", secretVal1, nil, nil)

	// Schedule deletion with explicit recovery_window_in_days.
	raw := e.expect(t, "schedule_create", http.MethodPost,
		"/v1/{project}/secrets/sched-sec/scheduled-deleted-tasks/create",
		fmt.Sprintf(`{"recovery_window_in_days":%d}`, windowDays))
	resp := decodeInto[secretResponse](t, raw)
	wantDeleteMillis := testEpoch.Add(time.Duration(windowDays) * 24 * time.Hour).UnixMilli()
	if resp.Secret.ScheduledDeleteTime == nil || *resp.Secret.ScheduledDeleteTime != wantDeleteMillis {
		t.Fatalf("scheduled_delete_time = %v, want %d", resp.Secret.ScheduledDeleteTime, wantDeleteMillis)
	}

	// Scheduling again returns 400 CSMS.0107.
	e.expect(t, "schedule_error_0107", http.MethodPost,
		"/v1/{project}/secrets/sched-sec/scheduled-deleted-tasks/create",
		fmt.Sprintf(`{"recovery_window_in_days":%d}`, minRecoveryDays))

	// Schedule with empty body uses defaultRecoveryDays.
	rawDef := e.expect(t, "schedule_create_default", http.MethodPost,
		"/v1/{project}/secrets/sched-default/scheduled-deleted-tasks/create", "")
	respDef := decodeInto[secretResponse](t, rawDef)
	wantDefMillis := testEpoch.Add(time.Duration(defaultRecoveryDays) * 24 * time.Hour).UnixMilli()
	if respDef.Secret.ScheduledDeleteTime == nil || *respDef.Secret.ScheduledDeleteTime != wantDefMillis {
		t.Fatalf("default scheduled_delete_time = %v, want %d", respDef.Secret.ScheduledDeleteTime, wantDefMillis)
	}

	// Restore sched-sec returns it to ENABLED and omits scheduled_delete_time.
	rawRestored := e.expect(t, "schedule_restore", http.MethodPost,
		"/v1/{project}/secrets/sched-sec/scheduled-deleted-tasks/cancel", "")
	respRestored := decodeInto[secretResponse](t, rawRestored)
	if respRestored.Secret.ScheduledDeleteTime != nil {
		t.Fatalf("restored secret still has scheduled_delete_time = %v", *respRestored.Secret.ScheduledDeleteTime)
	}

	// Restoring a non-pending secret returns 400 CSMS.0108.
	e.expect(t, "schedule_error_0108", http.MethodPost,
		"/v1/{project}/secrets/sched-sec/scheduled-deleted-tasks/cancel", "")

	// Parameter and body error golden checks.
	e.expect(t, "schedule_error_0002", http.MethodPost,
		"/v1/{project}/secrets/bad!name/scheduled-deleted-tasks/create", "")
	e.expect(t, "schedule_error_0002", http.MethodPost,
		"/v1/{project}/secrets/bad!name/scheduled-deleted-tasks/cancel", "")
	e.expect(t, "schedule_error_0002", http.MethodPost,
		"/v1/{project}/secrets/sched-sec/scheduled-deleted-tasks/create",
		fmt.Sprintf(`{"recovery_window_in_days":%d}`, minRecoveryDays-1))
	e.expect(t, "schedule_error_0002", http.MethodPost,
		"/v1/{project}/secrets/sched-sec/scheduled-deleted-tasks/create",
		fmt.Sprintf(`{"recovery_window_in_days":%d}`, maxRecoveryDays+1))
	e.expect(t, "schedule_error_0004", http.MethodPost,
		"/v1/{project}/secrets/sched-sec/scheduled-deleted-tasks/create", `{not-valid-json`)
	e.expect(t, "schedule_error_0005", http.MethodPost,
		"/v1/{project}/secrets/missing-sec/scheduled-deleted-tasks/create", "")
	e.expect(t, "schedule_error_0005", http.MethodPost,
		"/v1/{project}/secrets/missing-sec/scheduled-deleted-tasks/cancel", "")

	// Re-schedule sched-sec for minRecoveryDays and advance clock past window.
	status, _ := e.call(t, http.MethodPost,
		"/v1/{project}/secrets/sched-sec/scheduled-deleted-tasks/create",
		fmt.Sprintf(`{"recovery_window_in_days":%d}`, minRecoveryDays))
	if status != http.StatusOK {
		t.Fatalf("re-schedule status = %d, want 200", status)
	}

	// Just before expiry: secret and versions still exist.
	e.clock.Advance(time.Duration(minRecoveryDays)*24*time.Hour - time.Minute)
	if _, err := e.svc.secrets(testTenant).Get(context.Background(), "sched-sec"); err != nil {
		t.Fatalf("secret deleted before scheduled window elapsed: %v", err)
	}

	// Move past expiry: sched-sec and both its versions are removed; sched-default remains.
	e.clock.Advance(2 * time.Minute)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := e.engine.WaitIdle(waitCtx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	if _, err := e.svc.secrets(testTenant).Get(context.Background(), "sched-sec"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected sched-sec to be deleted, got err=%v", err)
	}
	vers, err := e.svc.listSecretVersionsSorted(context.Background(), testTenant, "sched-sec")
	if err != nil {
		t.Fatalf("listSecretVersionsSorted: %v", err)
	}
	if len(vers) != 0 {
		t.Fatalf("expected 0 versions remaining for sched-sec, got %d", len(vers))
	}
	if _, err := e.svc.secrets(testTenant).Get(context.Background(), "sched-default"); err != nil {
		t.Fatalf("sched-default should still exist before defaultRecoveryDays: %v", err)
	}

	// Restoring after actual deletion returns 404 CSMS.0005.
	e.expect(t, "schedule_error_0005", http.MethodPost,
		"/v1/{project}/secrets/sched-sec/scheduled-deleted-tasks/cancel", "")

	for _, s := range []string{secretVal1, secretVal2} {
		if strings.Contains(e.logs.String(), s) {
			t.Fatalf("debug logs leaked secret value %q", s)
		}
	}
}

func TestResumeBoltScheduledDeletion(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "csms-resume.db")
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	vkey, err := vault.NewKey()
	if err != nil {
		t.Fatalf("vault.NewKey: %v", err)
	}
	vlt, err := vault.New(vkey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	acct, err := identity.NewAccount()
	if err != nil {
		t.Fatalf("NewAccount: %v", err)
	}
	adm, err := identity.NewCredentials()
	if err != nil {
		t.Fatalf("NewCredentials: %v", err)
	}
	dir := identity.NewDirectory(acct, adm)

	const secretVal = "BOLT-RESUME-SECRET-VALUE"

	// Phase 1: open Bolt, create secret + 2 versions, schedule deletion, close before expiry.
	st1, err := store.OpenBolt(dbPath)
	if err != nil {
		t.Fatalf("OpenBolt #1: %v", err)
	}
	clock1 := lifecycle.NewFakeClock(testEpoch)
	eng1 := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock1, Logger: logger})
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan struct{})
	go func() { defer close(done1); eng1.Run(ctx1) }()

	gen1 := ids.NewSeeded(11)
	kms1, err := kms.New(kms.Deps{
		Store: st1, Logger: logger, IDs: gen1, Vault: vlt, Directory: dir,
		DefaultRegion: testRegion, DefaultProjectID: testProject, Now: clock1.Now,
	})
	if err != nil {
		t.Fatalf("kms.New #1: %v", err)
	}
	svc1, err := New(Deps{
		Store: st1, IDs: gen1, Engine: eng1, Logger: logger, Vault: vlt,
		Keys: kms1, Directory: dir, Clock: clock1.Now,
	})
	if err != nil {
		t.Fatalf("csms.New #1: %v", err)
	}
	kms1.Extend(svc1.KMSExtension())

	lcSeedSecretWithVersions(t, svc1, kms1, testTenant, "resume-sec", "persisted secret", secretVal, []byte("BIN-VAL"), nil)

	r1 := chi.NewRouter()
	kms1.Routes(r1)
	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/"+testProject+"/secrets/resume-sec/scheduled-deleted-tasks/create",
		strings.NewReader(fmt.Sprintf(`{"recovery_window_in_days":%d}`, minRecoveryDays)),
	)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(reqctx.With(req.Context(), &reqctx.Info{RequestID: "req-1", Service: "kms", Region: testRegion}))
	w := httptest.NewRecorder()
	r1.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("schedule on Bolt #1 = %d %s, want 200", w.Code, w.Body.String())
	}
	if eng1.Pending() != 1 {
		t.Fatalf("eng1.Pending() = %d, want 1", eng1.Pending())
	}

	cancel1()
	<-done1
	if err := st1.Close(); err != nil {
		t.Fatalf("Close Bolt #1: %v", err)
	}

	// Phase 2: reopen Bolt in a fresh Service + Engine, call Resume, advance clock past deletion date.
	st2, err := store.OpenBolt(dbPath)
	if err != nil {
		t.Fatalf("OpenBolt #2: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	clock2 := lifecycle.NewFakeClock(testEpoch.Add(time.Hour))
	eng2 := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock2, Logger: logger})
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { defer close(done2); eng2.Run(ctx2) }()
	t.Cleanup(func() {
		cancel2()
		<-done2
	})

	gen2 := ids.NewSeeded(12)
	kms2, err := kms.New(kms.Deps{
		Store: st2, Logger: logger, IDs: gen2, Vault: vlt, Directory: dir,
		DefaultRegion: testRegion, DefaultProjectID: testProject, Now: clock2.Now,
	})
	if err != nil {
		t.Fatalf("kms.New #2: %v", err)
	}
	svc2, err := New(Deps{
		Store: st2, IDs: gen2, Engine: eng2, Logger: logger, Vault: vlt,
		Keys: kms2, Directory: dir, Clock: clock2.Now,
	})
	if err != nil {
		t.Fatalf("csms.New #2: %v", err)
	}

	if err := svc2.Resume(ctx2); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if eng2.Pending() != 1 {
		t.Fatalf("eng2.Pending() after Resume = %d, want 1", eng2.Pending())
	}

	clock2.Advance(time.Duration(minRecoveryDays)*24*time.Hour + time.Minute)
	waitCtx, waitCancel := context.WithTimeout(ctx2, 2*time.Second)
	defer waitCancel()
	if err := eng2.WaitIdle(waitCtx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	if _, err := svc2.secrets(testTenant).Get(ctx2, "resume-sec"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected resume-sec to be deleted after Resume, got err=%v", err)
	}
	vers, err := svc2.listSecretVersionsSorted(ctx2, testTenant, "resume-sec")
	if err != nil {
		t.Fatalf("listSecretVersionsSorted: %v", err)
	}
	if len(vers) != 0 {
		t.Fatalf("expected 0 versions after Resume deletion, got %d", len(vers))
	}
	if strings.Contains(logs.String(), secretVal) {
		t.Fatalf("logs leaked secret value %q", secretVal)
	}
}

func TestScheduleDeleteFaultInjection(t *testing.T) {
	t.Parallel()
	reg := faults.New(nil)
	if _, err := reg.Add(faults.Rule{
		Type:       faults.TypeLifecycle,
		Transition: kindDeleteTransition,
		Times:      1,
	}); err != nil {
		t.Fatalf("reg.Add: %v", err)
	}

	e := newEnvFaulty(t, reg)
	const secretVal = "FAULT-INJECTED-SECRET-VAL"
	lcSeedSecretWithVersions(t, e.svc, e.kms, testTenant, "fault-sec", "fault test", secretVal, nil, nil)

	status, raw := e.call(t, http.MethodPost,
		"/v1/{project}/secrets/fault-sec/scheduled-deleted-tasks/create",
		fmt.Sprintf(`{"recovery_window_in_days":%d}`, minRecoveryDays))
	if status != http.StatusOK {
		t.Fatalf("schedule status = %d (%s), want 200", status, raw)
	}

	e.settle(t, time.Duration(minRecoveryDays)*24*time.Hour+time.Minute)

	sec, err := e.svc.secrets(testTenant).Get(context.Background(), "fault-sec")
	if err != nil {
		t.Fatalf("expected faulted secret to remain in store, got err=%v", err)
	}
	if sec.State != statePendingDelete {
		t.Fatalf("secret state = %q, want %q", sec.State, statePendingDelete)
	}
	vers, err := e.svc.listSecretVersionsSorted(context.Background(), testTenant, "fault-sec")
	if err != nil || len(vers) != 1 {
		t.Fatalf("expected version to remain intact after fault, got len=%d err=%v", len(vers), err)
	}
	if !strings.Contains(e.logs.String(), "csms scheduled secret deletion faulted") {
		t.Fatalf("expected warning log for faulted deletion, got logs: %s", e.logs.String())
	}
	if strings.Contains(e.logs.String(), secretVal) {
		t.Fatalf("logs leaked secret value %q", secretVal)
	}
}

func TestBackupAndRestore(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	const (
		plainV1 = "BACKUP-PLAINTEXT-SECRET-V1-DO-NOT-LEAK"
		plainV2 = "BACKUP-PLAINTEXT-BINARY-V2-DO-NOT-LEAK"
	)
	tags := []Tag{{Key: "env", Value: "prod"}, {Key: "team", Value: "sec"}}
	orig := lcSeedSecretWithVersions(t, e.svc, e.kms, testTenant, "backup-sec", "backed up secret", plainV1, []byte(plainV2), tags)

	// Download backup blob.
	rawDownload := e.expect(t, "backup_download", http.MethodPost,
		"/v1/{project}/secrets/backup-sec/backup", "")
	dl := decodeInto[downloadSecretBlobResponse](t, rawDownload)

	if !strings.HasPrefix(dl.SecretBlob, backupPrefix) {
		t.Fatalf("secret_blob %q missing prefix %q", dl.SecretBlob, backupPrefix)
	}
	if gotName := e.svc.peekBackupSecretName(dl.SecretBlob); gotName != "backup-sec" {
		t.Fatalf("peekBackupSecretName = %q, want backup-sec", gotName)
	}

	// Verify blob never contains plaintext in raw, base64url-decoded, or vault-opened layers.
	encodedPart := strings.TrimPrefix(dl.SecretBlob, backupPrefix)
	sealedBytes, err := base64.RawURLEncoding.DecodeString(encodedPart)
	if err != nil {
		t.Fatalf("DecodeString backup blob: %v", err)
	}
	openedJSON, err := e.vault.Open(sealedBytes, backupVaultLabel)
	if err != nil {
		t.Fatalf("vault.Open backup blob: %v", err)
	}
	b64V1 := base64.StdEncoding.EncodeToString([]byte(plainV1))
	b64V2 := base64.StdEncoding.EncodeToString([]byte(plainV2))
	for _, needle := range []string{plainV1, plainV2, b64V1, b64V2} {
		if strings.Contains(dl.SecretBlob, needle) {
			t.Fatalf("secret_blob leaked %q", needle)
		}
		if bytes.Contains(sealedBytes, []byte(needle)) {
			t.Fatalf("decoded blob bytes leaked %q", needle)
		}
		if strings.Contains(openedJSON, needle) {
			t.Fatalf("vault-opened backup JSON leaked %q", needle)
		}
	}

	// Restoring while secret still exists returns 409 CSMS.0101.
	uploadBody, err := json.Marshal(uploadSecretBlobRequest(dl))
	if err != nil {
		t.Fatalf("marshal upload body: %v", err)
	}
	e.expect(t, "backup_error_0101", http.MethodPost, "/v1/{project}/secrets/restore", string(uploadBody))

	// Download on PENDING_DELETE secret returns 403 CSMS.0109.
	status, _ := e.call(t, http.MethodPost,
		"/v1/{project}/secrets/backup-sec/scheduled-deleted-tasks/create",
		fmt.Sprintf(`{"recovery_window_in_days":%d}`, minRecoveryDays))
	if status != http.StatusOK {
		t.Fatalf("schedule status = %d, want 200", status)
	}
	e.expect(t, "backup_error_0109", http.MethodPost, "/v1/{project}/secrets/backup-sec/backup", "")

	// Delete secret and versions, then restore from backup.
	e.engine.Cancel(orig.ID)
	if err := e.svc.deleteSecretVersionsLocked(context.Background(), testTenant, "backup-sec"); err != nil {
		t.Fatalf("delete versions: %v", err)
	}
	if err := e.svc.secrets(testTenant).Delete(context.Background(), "backup-sec"); err != nil {
		t.Fatalf("delete secret: %v", err)
	}

	e.expect(t, "backup_upload", http.MethodPost, "/v1/{project}/secrets/restore", string(uploadBody))

	// Verify restored secret, stages, tags, and KMS-sealed versions round-trip cleanly.
	restored, err := e.svc.secrets(testTenant).Get(context.Background(), "backup-sec")
	if err != nil {
		t.Fatalf("get restored secret: %v", err)
	}
	if restored.State != stateEnabled || restored.ScheduledDeleteAt != 0 {
		t.Fatalf("restored state=%q scheduled=%d, want ENABLED/0", restored.State, restored.ScheduledDeleteAt)
	}
	if restored.Stages[stageCurrent].VersionID != "v2" ||
		restored.Stages[stagePrevious].VersionID != "v1" ||
		restored.Stages["PROD"].VersionID != "v1" {
		t.Fatalf("restored stages mismatch: %+v", restored.Stages)
	}
	if len(restored.Tags) != len(tags) || restored.Tags[0].Key != "env" || restored.Tags[0].Value != "prod" {
		t.Fatalf("restored tags mismatch: %+v", restored.Tags)
	}
	vers, err := e.svc.listSecretVersionsSorted(context.Background(), testTenant, "backup-sec")
	if err != nil || len(vers) != 2 {
		t.Fatalf("restored versions len=%d err=%v, want 2", len(vers), err)
	}
	if gotV1 := string(lcDecryptVersion(t, e.kms, testRegion, restored.ID, vers[0])); gotV1 != plainV1 {
		t.Fatalf("restored v1 = %q, want %q", gotV1, plainV1)
	}
	if gotV2 := string(lcDecryptVersion(t, e.kms, testRegion, restored.ID, vers[1])); gotV2 != plainV2 || !vers[1].Binary {
		t.Fatalf("restored v2 = %q (binary=%v), want %q (true)", gotV2, vers[1].Binary, plainV2)
	}

	// Error cases on DownloadSecretBlob & UploadSecretBlob.
	e.expect(t, "backup_error_0005", http.MethodPost, "/v1/{project}/secrets/missing-sec/backup", "")
	e.expect(t, "backup_error_0002", http.MethodPost, "/v1/{project}/secrets/bad!name/backup", "")
	e.expect(t, "backup_error_0004", http.MethodPost, "/v1/{project}/secrets/restore", `{bad-json`)
	for _, badBlob := range []string{
		`{}`,
		`{"secret_blob":"not-a-valid-prefix"}`,
		`{"secret_blob":")CloudSecretManagementBackupV1.com"}`,
		`{"secret_blob":")CloudSecretManagementBackupV1.com!!!not-base64!!!"}`,
		`{"secret_blob":")CloudSecretManagementBackupV1.comaGVsbG8td29ybGQ"}`,
	} {
		e.expect(t, "backup_error_0002", http.MethodPost, "/v1/{project}/secrets/restore", badBlob)
	}

	// Restoring in another region fails with 400 CSMS.0002.
	statusOtherRegion, outOtherRegion := e.callHost(t, "kms.cn-north-4.myhuaweicloud.com",
		http.MethodPost, "/v1/{project}/secrets/restore", string(uploadBody), "")
	golden.Assert(t, filepath.Join("testdata", "golden", "backup_error_0002.json"), statusOtherRegion, outOtherRegion)

	// Restoring in another account (even sharing the same vault key) fails with 400 CSMS.0002.
	acct2, err := identity.NewAccount()
	if err != nil {
		t.Fatalf("NewAccount #2: %v", err)
	}
	adm2, err := identity.NewCredentials()
	if err != nil {
		t.Fatalf("NewCredentials #2: %v", err)
	}
	dir2 := identity.NewDirectory(acct2, adm2)
	st2 := store.NewMemory()
	t.Cleanup(func() { _ = st2.Close() })
	kms2, err := kms.New(kms.Deps{
		Store: st2, Logger: e.svc.log, IDs: ids.NewSeeded(99), Vault: e.vault, Directory: dir2,
		DefaultRegion: testRegion, DefaultProjectID: testProject, Now: e.clock.Now,
	})
	if err != nil {
		t.Fatalf("kms.New #2: %v", err)
	}
	svc2, err := New(Deps{
		Store: st2, IDs: ids.NewSeeded(99), Engine: e.engine, Logger: e.svc.log, Vault: e.vault,
		Keys: kms2, Directory: dir2, Clock: e.clock.Now,
	})
	if err != nil {
		t.Fatalf("csms.New #2: %v", err)
	}
	kms2.Extend(svc2.KMSExtension())
	r2 := chi.NewRouter()
	kms2.Routes(r2)
	reqOtherAcct := httptest.NewRequest(http.MethodPost, "/v1/"+testProject+"/secrets/restore", bytes.NewReader(uploadBody))
	reqOtherAcct.Header.Set("Content-Type", "application/json")
	reqOtherAcct = reqOtherAcct.WithContext(reqctx.With(reqOtherAcct.Context(), &reqctx.Info{RequestID: "req-acct2", Service: "kms", Region: testRegion}))
	wOtherAcct := httptest.NewRecorder()
	r2.ServeHTTP(wOtherAcct, reqOtherAcct)
	golden.Assert(t, filepath.Join("testdata", "golden", "backup_error_0002.json"), wOtherAcct.Code, wOtherAcct.Body.Bytes())

	// Quota check on UploadSecretBlob using non-magic variable limit.
	limit, extra := 1, 1
	_ = extra
	eq := newEnvQuotas(t, quota.For(map[quota.Key]int{quota.CSMSSecret: limit}))
	toBackup := lcSeedSecretWithVersions(t, eq.svc, eq.kms, testTenant, "quota-restore", "quota test", plainV1, nil, nil)
	_, dlQuotaRaw := eq.call(t, http.MethodPost, "/v1/{project}/secrets/quota-restore/backup", "")
	dlQuota := decodeInto[downloadSecretBlobResponse](t, dlQuotaRaw)
	if err := eq.svc.deleteSecretVersionsLocked(context.Background(), testTenant, toBackup.Name); err != nil {
		t.Fatalf("delete versions: %v", err)
	}
	if err := eq.svc.secrets(testTenant).Delete(context.Background(), toBackup.Name); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	for i := range limit {
		lcSeedSecretWithVersions(t, eq.svc, eq.kms, testTenant, fmt.Sprintf("fill-%d", i), "filler", "val", nil, nil)
	}
	quotaUploadBody, err := json.Marshal(uploadSecretBlobRequest(dlQuota))
	if err != nil {
		t.Fatalf("marshal quota upload: %v", err)
	}
	eq.expect(t, "backup_error_0202", http.MethodPost, "/v1/{project}/secrets/restore", string(quotaUploadBody))

	// Enforce-mode KMS dependency checks on DownloadSecretBlob and UploadSecretBlob.
	// Delete backup-sec in e so UploadSecretBlob can be tested under gate.
	if err := e.svc.deleteSecretVersionsLocked(context.Background(), testTenant, "backup-sec"); err != nil {
		t.Fatalf("delete versions for authz test: %v", err)
	}
	if err := e.svc.secrets(testTenant).Delete(context.Background(), "backup-sec"); err != nil {
		t.Fatalf("delete secret for authz test: %v", err)
	}
	lcSeedSecretWithVersions(t, e.svc, e.kms, testTenant, "dep-sec", "dep test", plainV1, nil, nil)

	csmsOnly := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["csms:secret:*"],"Resource":["*"]}]}`
	if st, _ := lcDoWithGate(t, e, csmsOnly, http.MethodPost, "/v1/{project}/secrets/dep-sec/backup", ""); st != http.StatusForbidden {
		t.Fatalf("DownloadSecretBlob without KMS permissions = %d, want 403", st)
	}
	if st, _ := lcDoWithGate(t, e, csmsOnly, http.MethodPost, "/v1/{project}/secrets/restore", string(uploadBody)); st != http.StatusForbidden {
		t.Fatalf("UploadSecretBlob without kms:cmk:decryptDataKey = %d, want 403", st)
	}

	csmsPlusDecrypt := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["csms:secret:*","kms:cmk:decryptDataKey"],"Resource":["*"]}]}`
	if st, _ := lcDoWithGate(t, e, csmsPlusDecrypt, http.MethodPost, "/v1/{project}/secrets/dep-sec/backup", ""); st != http.StatusForbidden {
		t.Fatalf("DownloadSecretBlob without kms:cmk:createDataKey = %d, want 403", st)
	}
	if st, out := lcDoWithGate(t, e, csmsPlusDecrypt, http.MethodPost, "/v1/{project}/secrets/restore", string(uploadBody)); st != http.StatusOK {
		t.Fatalf("UploadSecretBlob with kms:cmk:decryptDataKey = %d (%s), want 200", st, out)
	}

	csmsPlusBoth := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["csms:secret:*","kms:cmk:createDataKey","kms:cmk:decryptDataKey"],"Resource":["*"]}]}`
	if st, out := lcDoWithGate(t, e, csmsPlusBoth, http.MethodPost, "/v1/{project}/secrets/dep-sec/backup", ""); st != http.StatusOK {
		t.Fatalf("DownloadSecretBlob with both KMS deps = %d (%s), want 200", st, out)
	}

	for _, s := range []string{plainV1, plainV2} {
		if strings.Contains(e.logs.String(), s) {
			t.Fatalf("debug logs leaked secret value %q", s)
		}
	}
}

func TestPasswordGenerateAndEnforceOpenRoute(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	var generatedForLogCheck []string

	// Default length (empty body and empty object).
	for _, body := range []string{"", `{}`} {
		raw := e.expect(t, "password_generate", http.MethodPost, "/v1/{project}/csms/generate-password", body)
		pw := decodeInto[generatePasswordResponse](t, raw).Password
		if len(pw) != defaultPasswordLen {
			t.Fatalf("default password len = %d, want %d", len(pw), defaultPasswordLen)
		}
		generatedForLogCheck = append(generatedForLogCheck, pw)
	}

	// Boundary lengths minPasswordLen and maxPasswordLen.
	for _, wantLen := range []int{minPasswordLen, maxPasswordLen} {
		raw := e.expect(t, "password_generate", http.MethodPost,
			"/v1/{project}/csms/generate-password",
			fmt.Sprintf(`{"length":%d}`, wantLen))
		pw := decodeInto[generatePasswordResponse](t, raw).Password
		if len(pw) != wantLen {
			t.Fatalf("password len = %d, want %d", len(pw), wantLen)
		}
		if wantLen >= defaultPasswordLen {
			generatedForLogCheck = append(generatedForLogCheck, pw)
		}
	}

	// Class exclusions: numbers only.
	rawDigits := e.expect(t, "password_generate", http.MethodPost,
		"/v1/{project}/csms/generate-password",
		fmt.Sprintf(`{"length":%d,"exclude_lowercase":true,"exclude_uppercase":true,"exclude_punctuation":true}`, defaultPasswordLen))
	pwDigits := decodeInto[generatePasswordResponse](t, rawDigits).Password
	for i := range len(pwDigits) {
		if !strings.ContainsRune(charsDigits, rune(pwDigits[i])) {
			t.Fatalf("digits-only password contained unexpected char %q in %q", pwDigits[i], pwDigits)
		}
	}
	generatedForLogCheck = append(generatedForLogCheck, pwDigits)

	// Exclude characters & include_space & require_each_included_type.
	exclChars := "aeiouAEIOU01234!@#$"
	rawCustom := e.expect(t, "password_generate", http.MethodPost,
		"/v1/{project}/csms/generate-password",
		fmt.Sprintf(`{"length":%d,"exclude_characters":%q,"include_space":true,"require_each_included_type":true}`,
			defaultPasswordLen, exclChars))
	pwCustom := decodeInto[generatePasswordResponse](t, rawCustom).Password
	if len(pwCustom) != defaultPasswordLen {
		t.Fatalf("custom password len = %d, want %d", len(pwCustom), defaultPasswordLen)
	}
	for _, ch := range exclChars {
		if strings.ContainsRune(pwCustom, ch) {
			t.Fatalf("password contained excluded character %q", ch)
		}
	}
	if !strings.Contains(pwCustom, " ") {
		t.Fatalf("expected space in password when include_space=true and length >= active classes")
	}
	hasLower, hasUpper, hasDigit, hasPunct := false, false, false, false
	for i := range len(pwCustom) {
		c := rune(pwCustom[i])
		switch {
		case strings.ContainsRune(charsLowercase, c):
			hasLower = true
		case strings.ContainsRune(charsUppercase, c):
			hasUpper = true
		case strings.ContainsRune(charsDigits, c):
			hasDigit = true
		case strings.ContainsRune(charsPunctuation, c):
			hasPunct = true
		}
	}
	if !hasLower || !hasUpper || !hasDigit || !hasPunct {
		t.Fatalf("expected all 4 main character classes in password, got lower=%v upper=%v digit=%v punct=%v",
			hasLower, hasUpper, hasDigit, hasPunct)
	}
	generatedForLogCheck = append(generatedForLogCheck, pwCustom)

	// Validation error golden checks.
	e.expect(t, "password_error_0004", http.MethodPost, "/v1/{project}/csms/generate-password", `{bad-json`)
	badBodies := []string{
		fmt.Sprintf(`{"length":%d}`, minPasswordLen-1),
		fmt.Sprintf(`{"length":%d}`, maxPasswordLen+1),
		`{"length":-1}`,
		`{"password_policy_name":"default-policy"}`,
		`{"exclude_lowercase":true,"exclude_uppercase":true,"exclude_numbers":true,"exclude_punctuation":true}`,
		`{"exclude_lowercase":true,"require_each_included_type":true}`,
		`{"length":3,"require_each_included_type":true}`,
		`{"exclude_characters":"0123456789","require_each_included_type":true}`,
		"{\"exclude_characters\":\"bad\\nchar\"}",
		`{"exclude_characters":"bad space"}`,
	}
	for _, b := range badBodies {
		e.expect(t, "password_error_0002", http.MethodPost, "/v1/{project}/csms/generate-password", b)
	}

	// Callable by a no-grants principal under -iam=enforce (openRoutes / authz.Public).
	stOpen, outOpen := lcDoWithGate(t, e, "", http.MethodPost, "/v1/{project}/csms/generate-password", "")
	golden.Assert(t, filepath.Join("testdata", "golden", "password_generate.json"), stOpen, outOpen)
	pwOpen := decodeInto[generatePasswordResponse](t, outOpen).Password
	generatedForLogCheck = append(generatedForLogCheck, pwOpen)

	// Verify none of the generated passwords appear anywhere in debug logs.
	logText := e.logs.String()
	for _, pw := range generatedForLogCheck {
		if strings.Contains(logText, pw) {
			t.Fatalf("debug logs leaked generated password")
		}
	}
}
