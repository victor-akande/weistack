package kps

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/faults"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
)

func seedTaskKeypair(t *testing.T, e *env, name, scope, userID string) {
	t.Helper()
	if scope == "" {
		scope = "user"
	}
	if userID == "" {
		userID = e.dir.Account().RootUserID()
	}
	kp := Keypair{
		ID:          1,
		Name:        name,
		Type:        "ssh",
		Scope:       scope,
		UserID:      userID,
		PublicKey:   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0 test@example",
		Fingerprint: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
		Algorithm:   "ssh-rsa",
		CreatedAt:   testEpoch.UnixMilli(),
		UpdatedAt:   testEpoch.UnixMilli(),
	}
	if err := e.svc.keypairs(testTenant).Put(context.Background(), name, kp); err != nil {
		t.Fatalf("seed keypair %q: %v", name, err)
	}
}

func TestTaskAssociateAndDisassociate(t *testing.T) {
	e := newEnv(t)
	seedTaskKeypair(t, e, "kp-1", "user", "")
	e.servers.add("srv-1", "web-1", "")

	// Associate (reset mode: no auth).
	raw := e.expect(t, "task_associate", http.MethodPost, "/v3/{project}/keypairs/associate",
		`{"keypair_name":"kp-1","server":{"id":"srv-1"}}`)
	assoc := decodeInto[taskActionResponse](t, raw)

	// Before settle: task is RUNNING_RESET and appears in /running-tasks.
	e.expect(t, "task_show_running_reset", http.MethodGet, "/v3/{project}/tasks/"+assoc.TaskID, "")
	runningRaw := e.expect(t, "task_list_running", http.MethodGet, "/v3/{project}/running-tasks", "")
	running := decodeInto[listRunningTaskResponse](t, runningRaw)
	if len(running.Tasks) != 1 {
		t.Fatalf("expected 1 running task, got %d", len(running.Tasks))
	}
	if _, err := strconv.ParseInt(running.Tasks[0].TaskTime, 10, 64); err != nil {
		t.Fatalf("task_time %q is not an integer epoch ms: %v", running.Tasks[0].TaskTime, err)
	}

	// Settle: server gets key_name, task becomes SUCCESS_RESET, /running-tasks is empty.
	e.settle(t)
	if got := e.servers.keyName("srv-1"); got != "kp-1" {
		t.Fatalf("server key_name = %q, want %q", got, "kp-1")
	}
	e.expect(t, "task_show_success_reset", http.MethodGet, "/v3/{project}/tasks/"+assoc.TaskID, "")
	e.expect(t, "task_list_running_empty", http.MethodGet, "/v3/{project}/running-tasks", "")

	// Disassociate.
	raw = e.expect(t, "task_disassociate", http.MethodPost, "/v3/{project}/keypairs/disassociate",
		`{"server":{"id":"srv-1"}}`)
	disassoc := decodeInto[taskActionResponse](t, raw)

	// Before settle: task is RUNNING_UNBIND and /running-tasks reports FAILED_UNBIND operate_type.
	e.expect(t, "task_show_running_unbind", http.MethodGet, "/v3/{project}/tasks/"+disassoc.TaskID, "")
	status, body := e.call(t, http.MethodGet, "/v3/{project}/running-tasks", "")
	if status != http.StatusOK {
		t.Fatalf("running-tasks status = %d, want 200", status)
	}
	running = decodeInto[listRunningTaskResponse](t, body)
	if running.Total != 1 || len(running.Tasks) != 1 || running.Tasks[0].OperateType != "FAILED_UNBIND" {
		t.Fatalf("unexpected running disassociate task: %+v", running)
	}

	// Settle: server key_name cleared, task becomes SUCCESS_UNBIND.
	e.settle(t)
	if got := e.servers.keyName("srv-1"); got != "" {
		t.Fatalf("server key_name = %q, want empty", got)
	}
	e.expect(t, "task_show_success_unbind", http.MethodGet, "/v3/{project}/tasks/"+disassoc.TaskID, "")
	e.expect(t, "task_list_running_empty", http.MethodGet, "/v3/{project}/running-tasks", "")
}

func TestTaskAssociateReplaceWithAuthAndNoSecretLogs(t *testing.T) {
	e := newEnv(t)
	seedTaskKeypair(t, e, "kp-2", "domain", "other-user")
	e.servers.add("srv-1", "web-1", "old-kp")

	const (
		secretPEM      = "-----BEGIN RSA PRIVATE KEY-----\\nSUPER-SECRET-AUTH-KEY\\n-----END RSA PRIVATE KEY-----"
		secretPassword = "SUPER-SECRET-VM-PASSWORD"
	)

	body := fmt.Sprintf(`{"keypair_name":"kp-2","server":{"id":"srv-1","port":2222,"disable_password":true,"auth":{"type":"keypair","key":%q}}}`, secretPEM)
	raw := e.expect(t, "task_associate", http.MethodPost, "/v3/{project}/keypairs/associate", body)
	assoc := decodeInto[taskActionResponse](t, raw)

	// Before settle: RUNNING_REPLACE and operate_type FAILED_REPLACE.
	e.expect(t, "task_show_running_replace", http.MethodGet, "/v3/{project}/tasks/"+assoc.TaskID, "")
	status, runningBody := e.call(t, http.MethodGet, "/v3/{project}/running-tasks", "")
	if status != http.StatusOK {
		t.Fatalf("running-tasks status = %d, want 200", status)
	}
	running := decodeInto[listRunningTaskResponse](t, runningBody)
	if len(running.Tasks) != 1 || running.Tasks[0].OperateType != "FAILED_REPLACE" {
		t.Fatalf("unexpected running replace task: %+v", running)
	}

	// After settle: SDK enum maps replace success to SUCCESS_RESET.
	e.settle(t)
	if got := e.servers.keyName("srv-1"); got != "kp-2" {
		t.Fatalf("server key_name = %q, want %q", got, "kp-2")
	}
	e.expect(t, "task_show_success_reset", http.MethodGet, "/v3/{project}/tasks/"+assoc.TaskID, "")

	// Disassociate with password auth.
	disBody := fmt.Sprintf(`{"server":{"id":"srv-1","auth":{"type":"password","key":%q}}}`, secretPassword)
	e.expect(t, "task_disassociate", http.MethodPost, "/v3/{project}/keypairs/disassociate", disBody)
	e.settle(t)

	logOut := e.logs.String()
	for _, secret := range []string{"PRIVATE KEY", "SUPER-SECRET-AUTH-KEY", secretPassword} {
		if strings.Contains(logOut, secret) {
			t.Fatalf("log output leaked secret %q", secret)
		}
	}
}

func TestTaskErrors(t *testing.T) {
	e := newEnv(t)
	seedTaskKeypair(t, e, "other-user-kp", "user", "someone-else")
	seedTaskKeypair(t, e, "kp-1", "user", "")

	// Unknown keypair -> 400 KPS.4016.
	e.expect(t, "task_associate_unknown_keypair", http.MethodPost, "/v3/{project}/keypairs/associate",
		`{"keypair_name":"missing-kp","server":{"id":"srv-1"}}`)

	// Another user's user-scoped keypair -> not visible -> 400 KPS.4016.
	e.expect(t, "task_associate_unknown_keypair", http.MethodPost, "/v3/{project}/keypairs/associate",
		`{"keypair_name":"other-user-kp","server":{"id":"srv-1"}}`)

	// Bad bodies and parameters -> 400 KPS.0002.
	badAssociateBodies := []string{
		`{not json`,
		`{}`,
		`{"keypair_name":"kp-1"}`,
		`{"keypair_name":"kp-1","server":{"id":""}}`,
		`{"keypair_name":"kp-1","server":{"id":"srv-1","port":-1}}`,
		`{"keypair_name":"kp-1","server":{"id":"srv-1","port":65536}}`,
		`{"keypair_name":"kp-1","server":{"id":"srv-1","auth":{"type":"invalid","key":"x"}}}`,
	}
	for _, payload := range badAssociateBodies {
		e.expect(t, "task_associate_bad_param", http.MethodPost, "/v3/{project}/keypairs/associate", payload)
	}

	badDisassociateBodies := []string{
		`{}`,
		`{"server":{"id":""}}`,
		`{"server":{"id":"srv-1","auth":{"type":"token","key":"x"}}}`,
	}
	for _, payload := range badDisassociateBodies {
		e.expect(t, "task_associate_bad_param", http.MethodPost, "/v3/{project}/keypairs/disassociate", payload)
	}

	// Unknown task ID -> 400 KPS.0001.
	e.expect(t, "task_show_unknown", http.MethodGet, "/v3/{project}/tasks/nonexistent-id", "")

	// Unknown failed task on delete -> 400 KPS.0005.
	e.expect(t, "task_delete_failed_not_found", http.MethodDelete, "/v3/{project}/failed-tasks/nonexistent-id", "")
}

func TestTaskMissingServerAndFailedTasksCRUD(t *testing.T) {
	e := newEnv(t)
	seedTaskKeypair(t, e, "kp-1", "user", "")

	// Associate with a missing server: request succeeds with 202, task fails asynchronously.
	status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs/associate",
		`{"keypair_name":"kp-1","server":{"id":"srv-missing"}}`)
	if status != http.StatusAccepted {
		t.Fatalf("associate missing server status = %d, want 202 (%s)", status, raw)
	}
	assoc := decodeInto[taskActionResponse](t, raw)

	e.settle(t)
	e.expect(t, "task_show_failed_reset", http.MethodGet, "/v3/{project}/tasks/"+assoc.TaskID, "")
	e.expect(t, "task_list_failed", http.MethodGet, "/v3/{project}/failed-tasks", "")

	// Delete the single failed task.
	e.expect(t, "task_delete_failed", http.MethodDelete, "/v3/{project}/failed-tasks/"+assoc.TaskID, "")
	// Deleting it again returns 400 KPS.0005.
	e.expect(t, "task_delete_failed_not_found", http.MethodDelete, "/v3/{project}/failed-tasks/"+assoc.TaskID, "")

	// Create two failed tasks (one associate, one disassociate) and test pagination + delete-all.
	status, _ = e.call(t, http.MethodPost, "/v3/{project}/keypairs/associate",
		`{"keypair_name":"kp-1","server":{"id":"srv-missing-1"}}`)
	if status != http.StatusAccepted {
		t.Fatalf("associate status = %d, want 202", status)
	}
	status, rawDis := e.call(t, http.MethodPost, "/v3/{project}/keypairs/disassociate",
		`{"server":{"id":"srv-missing-2"}}`)
	if status != http.StatusAccepted {
		t.Fatalf("disassociate status = %d, want 202", status)
	}
	dis := decodeInto[taskActionResponse](t, rawDis)

	e.settle(t)

	// Disassociate failure reports FAILED_UNBIND.
	status, taskRaw := e.call(t, http.MethodGet, "/v3/{project}/tasks/"+dis.TaskID, "")
	if status != http.StatusOK {
		t.Fatalf("get disassociate task status = %d, want 200", status)
	}
	taskResp := decodeInto[listKeypairTaskResponse](t, taskRaw)
	if taskResp.TaskStatus != "FAILED_UNBIND" {
		t.Fatalf("task_status = %q, want FAILED_UNBIND", taskResp.TaskStatus)
	}

	// Paginate failed tasks.
	status, pageRaw := e.call(t, http.MethodGet, "/v3/{project}/failed-tasks?limit=1&offset=1", "")
	if status != http.StatusOK {
		t.Fatalf("list failed tasks page status = %d, want 200", status)
	}
	page := decodeInto[listFailedTaskResponse](t, pageRaw)
	if page.Total != 2 || len(page.Tasks) != 1 || page.Tasks[0].OperateType != "FAILED_UNBIND" {
		t.Fatalf("unexpected failed tasks page: %+v", page)
	}

	// Delete all failed tasks.
	e.expect(t, "task_delete_all_failed", http.MethodDelete, "/v3/{project}/failed-tasks", "")

	status, emptyRaw := e.call(t, http.MethodGet, "/v3/{project}/failed-tasks", "")
	if status != http.StatusOK {
		t.Fatalf("list failed tasks after delete-all status = %d, want 200", status)
	}
	empty := decodeInto[listFailedTaskResponse](t, emptyRaw)
	if empty.Total != 0 || len(empty.Tasks) != 0 {
		t.Fatalf("expected 0 failed tasks after delete-all, got %+v", empty)
	}
}

func TestTaskFaultInjection(t *testing.T) {
	reg := faults.New(nil)
	if _, err := reg.Add(faults.Rule{
		Type:       faults.TypeLifecycle,
		Transition: taskAssociate,
		Times:      1,
	}); err != nil {
		t.Fatalf("add associate fault: %v", err)
	}
	if _, err := reg.Add(faults.Rule{
		Type:       faults.TypeLifecycle,
		Transition: taskDisassociate,
		Times:      1,
	}); err != nil {
		t.Fatalf("add disassociate fault: %v", err)
	}

	e := newEnvFaulty(t, reg)
	seedTaskKeypair(t, e, "kp-1", "user", "")
	e.servers.add("srv-1", "web-1", "orig-kp")

	// Faulted associate.
	status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs/associate",
		`{"keypair_name":"kp-1","server":{"id":"srv-1"}}`)
	if status != http.StatusAccepted {
		t.Fatalf("associate status = %d, want 202", status)
	}
	assoc := decodeInto[taskActionResponse](t, raw)

	// Faulted disassociate.
	status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs/disassociate",
		`{"server":{"id":"srv-1"}}`)
	if status != http.StatusAccepted {
		t.Fatalf("disassociate status = %d, want 202", status)
	}
	disassoc := decodeInto[taskActionResponse](t, raw)

	e.settle(t)

	// Server key_name must be unchanged.
	if got := e.servers.keyName("srv-1"); got != "orig-kp" {
		t.Fatalf("server key_name = %q, want %q", got, "orig-kp")
	}

	// Both tasks failed and appear in /failed-tasks.
	_, assocTaskRaw := e.call(t, http.MethodGet, "/v3/{project}/tasks/"+assoc.TaskID, "")
	if got := decodeInto[listKeypairTaskResponse](t, assocTaskRaw).TaskStatus; got != "FAILED_RESET" {
		t.Fatalf("assoc task_status = %q, want FAILED_RESET", got)
	}
	_, disTaskRaw := e.call(t, http.MethodGet, "/v3/{project}/tasks/"+disassoc.TaskID, "")
	if got := decodeInto[listKeypairTaskResponse](t, disTaskRaw).TaskStatus; got != "FAILED_UNBIND" {
		t.Fatalf("disassoc task_status = %q, want FAILED_UNBIND", got)
	}

	status, failedRaw := e.call(t, http.MethodGet, "/v3/{project}/failed-tasks", "")
	if status != http.StatusOK {
		t.Fatalf("failed-tasks status = %d, want 200", status)
	}
	failed := decodeInto[listFailedTaskResponse](t, failedRaw)
	if failed.Total != 2 || len(failed.Tasks) != 2 {
		t.Fatalf("expected 2 failed tasks, got %+v", failed)
	}
	for _, ft := range failed.Tasks {
		if ft.ServerName != "web-1" {
			t.Fatalf("failed task server_name = %q, want web-1", ft.ServerName)
		}
		if !strings.Contains(ft.TaskErrorMsg, "injected fault") {
			t.Fatalf("failed task error msg = %q, want injected fault", ft.TaskErrorMsg)
		}
	}
}

func TestTaskBatchAssociate(t *testing.T) {
	e := newEnv(t)
	seedTaskKeypair(t, e, "kp-1", "user", "")
	e.servers.add("srv-1", "web-1", "")
	e.servers.add("srv-2", "web-2", "")

	// Mix of valid keypair and unknown keypair.
	raw := e.expect(t, "task_batch_associate", http.MethodPost, "/v3/{project}/keypairs/batch-associate",
		`{"batch_keypairs":[{"keypair_name":"kp-1","server":{"id":"srv-1"}},{"keypair_name":"unknown-kp","server":{"id":"srv-2"}}]}`)
	resp := decodeInto[batchAssociateResponse](t, raw)
	if len(resp.Tasks) != 2 || resp.Tasks[0].TaskID == "" {
		t.Fatalf("unexpected batch response: %+v", resp)
	}

	e.settle(t)
	if got := e.servers.keyName("srv-1"); got != "kp-1" {
		t.Fatalf("srv-1 key_name = %q, want kp-1", got)
	}
	if got := e.servers.keyName("srv-2"); got != "" {
		t.Fatalf("srv-2 key_name = %q, want empty", got)
	}

	// Item with invalid parameters reports per-item KPS.0002 failure.
	status, itemErrRaw := e.call(t, http.MethodPost, "/v3/{project}/keypairs/batch-associate",
		`{"batch_keypairs":[{"keypair_name":"kp-1","server":{"id":""}}]}`)
	if status != http.StatusAccepted {
		t.Fatalf("batch item error status = %d, want 202", status)
	}
	itemErr := decodeInto[batchAssociateResponse](t, itemErrRaw)
	if len(itemErr.Tasks) != 1 || itemErr.Tasks[0].Status != "FAILED" || itemErr.Tasks[0].ErrorCode != "KPS.0002" {
		t.Fatalf("unexpected item error response: %+v", itemErr)
	}

	// Empty batch and >10 items -> 400 KPS.0002.
	e.expect(t, "task_associate_bad_param", http.MethodPost, "/v3/{project}/keypairs/batch-associate",
		`{"batch_keypairs":[]}`)

	var items []string
	for i := range 11 {
		items = append(items, fmt.Sprintf(`{"keypair_name":"kp-1","server":{"id":"srv-%d"}}`, i))
	}
	e.expect(t, "task_associate_bad_param", http.MethodPost, "/v3/{project}/keypairs/batch-associate",
		`{"batch_keypairs":[`+strings.Join(items, ",")+`]}`)
}

func TestTaskPaginationAndValidation(t *testing.T) {
	e := newEnv(t)
	seedTaskKeypair(t, e, "kp-1", "user", "")
	e.servers.add("srv-1", "web-1", "")
	e.servers.add("srv-2", "web-2", "")

	// Queue two running tasks.
	_, _ = e.call(t, http.MethodPost, "/v3/{project}/keypairs/associate",
		`{"keypair_name":"kp-1","server":{"id":"srv-1"}}`)
	_, _ = e.call(t, http.MethodPost, "/v3/{project}/keypairs/associate",
		`{"keypair_name":"kp-1","server":{"id":"srv-2"}}`)

	// Valid limit/offset on running-tasks.
	status, raw := e.call(t, http.MethodGet, "/v3/{project}/running-tasks?limit=1&offset=1", "")
	if status != http.StatusOK {
		t.Fatalf("running-tasks page status = %d, want 200", status)
	}
	page := decodeInto[listRunningTaskResponse](t, raw)
	if page.Total != 2 || len(page.Tasks) != 1 || page.Tasks[0].ServerID != "srv-2" {
		t.Fatalf("unexpected running-tasks page: %+v", page)
	}

	// Offset beyond length returns empty array with full total.
	status, raw = e.call(t, http.MethodGet, "/v3/{project}/running-tasks?offset=5", "")
	if status != http.StatusOK {
		t.Fatalf("running-tasks past-end status = %d, want 200", status)
	}
	past := decodeInto[listRunningTaskResponse](t, raw)
	if past.Total != 2 || len(past.Tasks) != 0 {
		t.Fatalf("unexpected past-end page: %+v", past)
	}

	// Invalid limit/offset queries on both endpoints -> 400 KPS.0002.
	for _, endpoint := range []string{"/v3/{project}/running-tasks", "/v3/{project}/failed-tasks"} {
		for _, q := range []string{"?limit=0", "?limit=1001", "?limit=abc", "?offset=-1", "?offset=xyz"} {
			e.expect(t, "task_associate_bad_param", http.MethodGet, endpoint+q, "")
		}
	}
}

func TestTaskResumeBolt(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "kps.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vkey, err := vault.NewKey()
	if err != nil {
		t.Fatalf("vault.NewKey: %v", err)
	}
	vlt, err := vault.New(vkey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	// Phase 1: open Bolt store, schedule associate & disassociate tasks, then stop before settling.
	st1, err := store.OpenBolt(dbPath)
	if err != nil {
		t.Fatalf("OpenBolt #1: %v", err)
	}
	clock1 := lifecycle.NewFakeClock(testEpoch)
	eng1 := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock1, Logger: logger})
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan struct{})
	go func() { defer close(done1); eng1.Run(ctx1) }()

	servers1 := newFakeServers()
	servers1.add("srv-1", "web-1", "")
	servers1.add("srv-2", "web-2", "old-kp")

	svc1, err := New(Deps{
		Store:   st1,
		IDs:     ids.NewSeeded(7),
		Engine:  eng1,
		Logger:  logger,
		Vault:   vlt,
		Servers: servers1,
		Clock:   clock1.Now,
	})
	if err != nil {
		t.Fatalf("kps.New #1: %v", err)
	}

	assocTask := Task{
		ID:          "11111111-1111-1111-1111-111111111111",
		Operation:   taskOpReset,
		KeypairName: "kp-resume",
		ServerID:    "srv-1",
		Status:      taskStatusRunning,
		CreatedAt:   testEpoch.UnixMilli(),
	}
	disassocTask := Task{
		ID:        "22222222-2222-2222-2222-222222222222",
		Operation: taskOpUnbind,
		ServerID:  "srv-2",
		Status:    taskStatusRunning,
		CreatedAt: testEpoch.UnixMilli(),
	}
	if err := svc1.tasks(testTenant).Create(ctx1, assocTask.ID, assocTask); err != nil {
		t.Fatalf("create assoc task: %v", err)
	}
	if err := svc1.tasks(testTenant).Create(ctx1, disassocTask.ID, disassocTask); err != nil {
		t.Fatalf("create disassoc task: %v", err)
	}
	svc1.scheduleTask(testTenant, assocTask)
	svc1.scheduleTask(testTenant, disassocTask)

	// Shut down before clock advances so both tasks stay RUNNING in Bolt.
	cancel1()
	<-done1
	if err := st1.Close(); err != nil {
		t.Fatalf("Close Bolt #1: %v", err)
	}

	// Phase 2: reopen Bolt store, create new Service, call Resume, advance clock.
	st2, err := store.OpenBolt(dbPath)
	if err != nil {
		t.Fatalf("OpenBolt #2: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })

	clock2 := lifecycle.NewFakeClock(testEpoch.Add(time.Minute))
	eng2 := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock2, Logger: logger})
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { defer close(done2); eng2.Run(ctx2) }()
	t.Cleanup(func() {
		cancel2()
		<-done2
	})

	servers2 := newFakeServers()
	servers2.add("srv-1", "web-1", "")
	servers2.add("srv-2", "web-2", "old-kp")

	svc2, err := New(Deps{
		Store:   st2,
		IDs:     ids.NewSeeded(8),
		Engine:  eng2,
		Logger:  logger,
		Vault:   vlt,
		Servers: servers2,
		Clock:   clock2.Now,
	})
	if err != nil {
		t.Fatalf("kps.New #2: %v", err)
	}

	if err := svc2.Resume(ctx2); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if eng2.Pending() != 2 {
		t.Fatalf("pending after Resume = %d, want 2", eng2.Pending())
	}

	clock2.Advance(testDelay + time.Second)
	waitCtx, waitCancel := context.WithTimeout(ctx2, 2*time.Second)
	defer waitCancel()
	if err := eng2.WaitIdle(waitCtx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}

	if got := servers2.keyName("srv-1"); got != "kp-resume" {
		t.Fatalf("resumed srv-1 key_name = %q, want %q", got, "kp-resume")
	}
	if got := servers2.keyName("srv-2"); got != "" {
		t.Fatalf("resumed srv-2 key_name = %q, want empty", got)
	}

	gotAssoc, err := svc2.tasks(testTenant).Get(ctx2, assocTask.ID)
	if err != nil {
		t.Fatalf("get resumed assoc task: %v", err)
	}
	if wireTaskStatus(gotAssoc.Operation, gotAssoc.Status) != "SUCCESS_RESET" {
		t.Fatalf("resumed assoc status = %q, want SUCCESS_RESET", wireTaskStatus(gotAssoc.Operation, gotAssoc.Status))
	}

	gotDisassoc, err := svc2.tasks(testTenant).Get(ctx2, disassocTask.ID)
	if err != nil {
		t.Fatalf("get resumed disassoc task: %v", err)
	}
	if wireTaskStatus(gotDisassoc.Operation, gotDisassoc.Status) != "SUCCESS_UNBIND" {
		t.Fatalf("resumed disassoc status = %q, want SUCCESS_UNBIND", wireTaskStatus(gotDisassoc.Operation, gotDisassoc.Status))
	}
}
