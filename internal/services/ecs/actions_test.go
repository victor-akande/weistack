package ecs

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/store"
)

const actionPath = serversPath + "/action"

func actionBody(kind, typ string, ids ...string) string {
	t := ""
	if typ != "" {
		t = `"type": "` + typ + `", `
	}
	return fmt.Sprintf(`{%q: {%s"servers": [{"id": "%s"}]}}`, kind, t, strings.Join(ids, `"}, {"id": "`))
}

// mustServer creates one server and waits for it to be ACTIVE.
func (e *env) mustServer(t *testing.T, n network, extra ...string) string {
	t.Helper()
	_, ids := e.mustCreate(t, n.serverBody(extra...))
	e.settle(t)
	return ids[0]
}

// state summarises what a client sees of a server.
func (e *env) state(t *testing.T, id string) string {
	t.Helper()
	status, out := e.call(t, http.MethodGet, serversPath+"/"+id, "")
	if status != http.StatusOK {
		t.Fatalf("show %s: %d %s", id, status, out)
	}
	d := decodeInto[serverResponse](t, out).Server
	task := "-"
	if d.TaskState != nil {
		task = *d.TaskState
	}
	return fmt.Sprintf("%s/%s/%s/%d", d.Status, task, d.VMState, d.PowerState)
}

func (e *env) jobStatus(t *testing.T, id string) string {
	t.Helper()
	job, err := e.svc.GetJob(t.Context(), testTenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return job.JobType + ":" + job.Status
}

func TestStopStartRebootCycle(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	id := e.mustServer(t, n)
	launched := e.server(t, id).LaunchedAt

	steps := []struct {
		body          string
		during, after string
		wantJob       string
	}{
		{actionBody("os-stop", "", id), "ACTIVE/powering-off/active/1", "SHUTOFF/-/stopped/4", "stopServer"},
		{actionBody("os-start", "", id), "SHUTOFF/powering-on/stopped/4", "ACTIVE/-/active/1", "startServer"},
		{actionBody("reboot", "SOFT", id), "REBOOT/rebooting/active/1", "ACTIVE/-/active/1", "rebootServer"},
		{actionBody("reboot", "HARD", id), "HARD_REBOOT/rebooting/active/1", "ACTIVE/-/active/1", "rebootServer"},
		{actionBody("os-stop", "HARD", id), "ACTIVE/powering-off/active/1", "SHUTOFF/-/stopped/4", "stopServer"},
	}
	for _, step := range steps {
		out := e.expect(t, "job_accepted", http.MethodPost, actionPath, step.body)
		jobID := decodeInto[jobResponse](t, out).JobID
		if got := e.state(t, id); got != step.during {
			t.Fatalf("%s: during = %s, want %s", step.body, got, step.during)
		}
		if got := e.jobStatus(t, jobID); got != step.wantJob+":RUNNING" {
			t.Fatalf("%s: job = %s", step.body, got)
		}
		e.settle(t)
		if got := e.state(t, id); got != step.after {
			t.Fatalf("%s: after = %s, want %s", step.body, got, step.after)
		}
		if got := e.jobStatus(t, jobID); got != step.wantJob+":SUCCESS" {
			t.Fatalf("%s: job = %s", step.body, got)
		}
	}
	// A start records a new launch time.
	if e.server(t, id).LaunchedAt == launched {
		t.Error("launched_at did not change across a stop and start")
	}
}

func TestInvalidTransitionsAreRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	running := e.mustServer(t, n, "name", `"running"`)
	stopped := e.mustServer(t, n, "name", `"stopped"`)
	if _, err := e.svc.StopServers(t.Context(), testTenant, []string{stopped}, ""); err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	_, building := e.mustCreate(t, n.serverBody("name", `"building"`))

	tests := []struct{ name, body, golden string }{
		{"start a running server", actionBody("os-start", "", running), "error_ecs_0100"},
		{"stop a stopped server", actionBody("os-stop", "", stopped), "error_ecs_0100"},
		{"reboot a stopped server", actionBody("reboot", "SOFT", stopped), "error_ecs_0100"},
		{"stop a building server", actionBody("os-stop", "", building[0]), "error_ecs_0100"},
		{"start a building server", actionBody("os-start", "", building[0]), "error_ecs_0100"},
		{"unknown server", actionBody("os-stop", "", unknownID), "error_ecs_0114"},
		{"one bad server fails the batch", actionBody("os-stop", "", running, stopped), "error_ecs_0100"},
		{"one unknown server fails the batch", actionBody("os-stop", "", running, unknownID), "error_ecs_0114"},
		{"server listed twice", actionBody("os-stop", "", running, running), "error_ecs_0005"},
		{"no servers", `{"os-stop": {"servers": []}}`, "error_ecs_0005"},
		{"bad stop type", actionBody("os-stop", "GENTLE", running), "error_ecs_0005"},
		{"reboot without type", actionBody("reboot", "", running), "error_ecs_0005"},
		{"bad reboot type", actionBody("reboot", "WARM", running), "error_ecs_0005"},
		{"no action", `{}`, "error_ecs_0005"},
		{"two actions", `{"os-start": {"servers": [{"id": "` + stopped + `"}]}, "os-stop": {"servers": [{"id": "` + running + `"}]}}`, "error_ecs_0005"},
		{"unknown action", `{"pause": {"servers": [{"id": "` + running + `"}]}}`, "error_ecs_0005"},
		{"empty body", ``, "error_ecs_0005"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, actionPath, tt.body)
		})
	}
	// A refused batch touched nothing.
	if got := e.state(t, running); got != "ACTIVE/-/active/1" {
		t.Errorf("running server after refused batches: %s", got)
	}

	// While an operation is in flight, another is refused.
	if _, err := e.svc.StopServers(t.Context(), testTenant, []string{running}, ""); err != nil {
		t.Fatal(err)
	}
	e.expect(t, "error_ecs_0100", http.MethodPost, actionPath, actionBody("reboot", "SOFT", running))
	e.expect(t, "error_ecs_0100", http.MethodPost, actionPath, actionBody("os-stop", "", running))

	// More than 1000 servers in one batch.
	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = fmt.Sprintf("%08d-0000-4000-8000-000000000000", i)
	}
	e.expect(t, "error_ecs_0118", http.MethodPost, actionPath, actionBody("os-start", "", ids...))
}

func TestBatchActsOnEveryServer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	_, ids := e.mustCreate(t, n.serverBody("count", `3`))
	e.settle(t)

	job, err := e.svc.StopServers(t.Context(), testTenant, ids, "SOFT")
	if err != nil {
		t.Fatal(err)
	}
	if job.Entities.SubJobsTotal != 3 || job.Entities.SubJobs[0].JobType != "stopSingleServer" {
		t.Fatalf("job = %+v", job)
	}
	e.settle(t)
	for _, id := range ids {
		if got := e.state(t, id); got != "SHUTOFF/-/stopped/4" {
			t.Errorf("server %s: %s", id, got)
		}
	}
	if got := e.jobStatus(t, job.JobID); got != "stopServer:SUCCESS" {
		t.Errorf("job = %s", got)
	}
}

func TestResize(t *testing.T) {
	t.Parallel()
	e := newEnvFull(t, store.NewMemory(), "", Quota{Servers: 10, VCPUs: 10})
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	id := e.mustServer(t, n) // s6.large.2: 2 vCPUs
	path := serversPath + "/" + id + "/resize"
	resize := func(flavor, mode string) string {
		if mode == "" {
			return `{"resize": {"flavorRef": "` + flavor + `"}}`
		}
		return `{"resize": {"flavorRef": "` + flavor + `", "mode": "` + mode + `"}}`
	}

	// A running server must be stopped first, or resized with the stop mode.
	e.expect(t, "error_ecs_0100", http.MethodPost, path, resize("s6.xlarge.2", ""))

	out := e.expect(t, "job_accepted", http.MethodPost, path, resize("s6.xlarge.2", "withStopServer"))
	jobID := decodeInto[jobResponse](t, out).JobID
	if got := e.state(t, id); got != "RESIZE/resize_prep/resized/4" {
		t.Fatalf("during resize: %s", got)
	}
	if e.server(t, id).Flavor != "s6.large.2" {
		t.Fatal("the flavor changed before the resize finished")
	}
	e.expect(t, "error_ecs_0100", http.MethodPost, path, resize("s6.2xlarge.2", "withStopServer")) // busy
	e.settle(t)
	if got := e.state(t, id); got != "ACTIVE/-/active/1" {
		t.Fatalf("after resize with stop mode: %s, want it running again", got)
	}
	if srv := e.server(t, id); srv.Flavor != "s6.xlarge.2" {
		t.Fatalf("flavor = %q, want s6.xlarge.2", srv.Flavor)
	}
	if got := e.jobStatus(t, jobID); got != "resizeServer:SUCCESS" {
		t.Fatalf("job = %s", got)
	}
	status, body := e.call(t, http.MethodGet, serversPath+"/"+id, "")
	if d := decodeInto[serverResponse](t, body).Server; status != 200 || d.Flavor.VCPUs != "4" || d.Flavor.RAM != "8192" {
		t.Fatalf("detail after resize: %+v", d.Flavor)
	}

	// A stopped server resizes and stays stopped.
	if _, err := e.svc.StopServers(t.Context(), testTenant, []string{id}, ""); err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	e.expect(t, "job_accepted", http.MethodPost, path, resize("s6.large.4", ""))
	e.settle(t)
	if got := e.state(t, id); got != "SHUTOFF/-/stopped/4" {
		t.Fatalf("after resizing a stopped server: %s", got)
	}

	tests := []struct{ name, body, golden string }{
		{"same flavor", resize("s6.large.4", ""), "error_ecs_0810"},
		{"unknown flavor", resize("z9.huge.1", ""), "error_ecs_0029"},
		{"other architecture", resize("kc1.large.2", ""), "error_ecs_0804"},
		{"over the vCPU quota", resize("s6.2xlarge.4", ""), "error_ecs_0001"}, // 8 would be fine; make it not
		{"missing flavor", `{"resize": {}}`, "error_ecs_0005"},
		{"bad mode", resize("s6.small.1", "live"), "error_ecs_0005"},
		{"missing resize object", `{}`, "error_ecs_0005"},
		{"dry run", `{"dry_run": true, "resize": {"flavorRef": "s6.small.1"}}`, "error_not_implemented"},
	}
	// Use up quota so that growing this server to 8 vCPUs exceeds 10.
	e.mustServer(t, n, "name", `"other"`, "flavorRef", `"s6.xlarge.2"`) // +4 = 6 in use
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, path, tt.body)
		})
	}
	e.expect(t, "error_ecs_0114", http.MethodPost, serversPath+"/"+unknownID+"/resize", resize("s6.small.1", ""))

	// Shrinking is always within quota.
	e.expect(t, "job_accepted", http.MethodPost, path, resize("s6.small.1", ""))
}

func TestOperationFaultsLeaveServerInError(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{taskServerStop, taskServerResize} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			e := newEnvFaulty(t, failKind(kind))
			n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
			id := e.mustServer(t, n)

			var (
				job Job
				err error
			)
			if kind == taskServerStop {
				job, err = e.svc.StopServers(t.Context(), testTenant, []string{id}, "")
			} else {
				job, err = e.svc.ResizeServer(t.Context(), testTenant, id, ResizeOption{FlavorRef: "s6.xlarge.2", Mode: modeWithStop})
			}
			if err != nil {
				t.Fatal(err)
			}
			e.settle(t)
			srv := e.server(t, id)
			if srv.Status != StatusError || srv.TaskState != "" || srv.Pending != nil || srv.Flavor != "s6.large.2" {
				t.Fatalf("server = %+v", srv)
			}
			if got, _ := e.svc.GetJob(t.Context(), testTenant, job.JobID); got.Status != JobFail {
				t.Fatalf("job status = %q", got.Status)
			}
		})
	}
}

func TestDeleteAbandonsAPendingOperation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	id := e.mustServer(t, n)

	stop, err := e.svc.StopServers(t.Context(), testTenant, []string{id}, "")
	if err != nil {
		t.Fatal(err)
	}
	del, err := e.svc.DeleteServers(t.Context(), testTenant, []string{id})
	if err != nil {
		t.Fatalf("deleting a server that is stopping: %v", err)
	}
	if got := e.jobStatus(t, stop.JobID); got != "stopServer:FAIL" {
		t.Errorf("abandoned stop job = %s", got)
	}
	e.settle(t)
	if got := e.jobStatus(t, del.JobID); got != "deleteServer:SUCCESS" {
		t.Errorf("delete job = %s", got)
	}
	if n := e.engine.Pending(); n != 0 {
		t.Errorf("%d lifecycle tasks left", n)
	}
}

func TestUpdateServer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	id := e.mustServer(t, n)
	path := serversPath + "/" + id

	e.clock.Advance(60 * 1e9)
	e.expect(t, "update_server", http.MethodPut, path,
		`{"server": {"name": "renamed", "description": "now with a description"}}`)
	srv := e.server(t, id)
	if srv.Name != "renamed" || srv.Description != "now with a description" || srv.Updated == srv.Created {
		t.Fatalf("after update: %+v", srv)
	}

	// Only the fields sent change; user data shows up when set.
	status, out := e.call(t, http.MethodPut, path, `{"server": {"user_data": "IyEvYmluL3No"}}`)
	res := decodeInto[updateServerResponse](t, out).Server
	if status != http.StatusOK || res.Name != "renamed" || res.UserData == nil || *res.UserData != "IyEvYmluL3No" {
		t.Fatalf("user_data update: %d %s", status, out)
	}
	// An empty update is accepted and changes nothing.
	if status, _ := e.call(t, http.MethodPut, path, `{"server": {}}`); status != http.StatusOK {
		t.Errorf("empty update: %d", status)
	}

	tests := []struct{ name, body, golden string }{
		{"empty body", ``, "error_ecs_0005"},
		{"missing server object", `{}`, "error_ecs_0005"},
		{"empty name", `{"server": {"name": ""}}`, "error_ecs_0915"},
		{"bad name", `{"server": {"name": "a b"}}`, "error_ecs_0915"},
		{"long name", `{"server": {"name": "` + strings.Repeat("n", 65) + `"}}`, "error_ecs_0914"},
		{"bad description", `{"server": {"description": "<b>"}}`, "error_ecs_0005"},
		{"hostname", `{"server": {"hostname": "other"}}`, "error_ecs_0005"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPut, path, tt.body)
		})
	}
	e.expect(t, "error_ecs_0114", http.MethodPut, serversPath+"/"+unknownID, `{"server": {"name": "x"}}`)
}

func TestServerTags(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	id := e.mustServer(t, n)
	other := e.mustServer(t, n, "name", `"other"`, "server_tags", `[{"key": "env", "value": "dev"}]`)
	tags := serversPath + "/" + id + "/tags"
	act := func(action, list string) string { return `{"action": "` + action + `", "tags": ` + list + `}` }

	e.expect(t, "show_tags_empty", http.MethodGet, tags, "")
	e.expect(t, "no_content", http.MethodPost, tags+"/action", act("create", `[{"key": "env", "value": "test"}, {"key": "team"}]`))
	// Creating a tag whose key exists replaces its value.
	e.expect(t, "no_content", http.MethodPost, tags+"/action", act("create", `[{"key": "env", "value": "prod"}]`))
	e.expect(t, "show_tags", http.MethodGet, tags, "")
	e.expect(t, "list_project_tags", http.MethodGet, serversPath+"/tags", "")

	// Tags show on the server and filter the list.
	if srv := e.server(t, id); strings.Join(srv.Tags, ",") != "env=prod,team" {
		t.Errorf("stored tags = %v", srv.Tags)
	}
	status, out := e.call(t, http.MethodGet, serversPath+"/detail?tags=env%3Dprod", "")
	if res := decodeInto[listServersResponse](t, out); status != 200 || res.Count != 1 || res.Servers[0].ID != id {
		t.Errorf("list by tag: %s", out)
	}

	// Delete by key; unknown keys are ignored.
	e.expect(t, "no_content", http.MethodPost, tags+"/action", act("delete", `[{"key": "env"}, {"key": "team", "value": ""}, {"key": "absent"}]`))
	e.expect(t, "show_tags_empty", http.MethodGet, tags, "")
	if srv := e.server(t, other); strings.Join(srv.Tags, ",") != "env=dev" {
		t.Errorf("another server's tags changed: %v", srv.Tags)
	}

	many := make([]string, 11)
	for i := range many {
		many[i] = fmt.Sprintf(`{"key": "k%d", "value": "v"}`, i)
	}
	tests := []struct{ name, body, golden string }{
		{"empty body", ``, "error_ecs_0005"},
		{"unknown action", act("replace", `[{"key": "a"}]`), "error_ecs_0005"},
		{"no tags", act("create", `[]`), "error_ecs_0005"},
		{"no tags to delete", act("delete", `[]`), "error_ecs_0005"},
		{"empty key", act("create", `[{"key": "", "value": "v"}]`), "error_ecs_0906"},
		{"delete without key", act("delete", `[{"value": "v"}]`), "error_ecs_0906"},
		{"key too long", act("create", `[{"key": "`+strings.Repeat("k", 37)+`"}]`), "error_ecs_0906"},
		{"bad character", act("create", `[{"key": "a", "value": "b*c"}]`), "error_ecs_0907"},
		{"repeated key", act("create", `[{"key": "a", "value": "1"}, {"key": "a", "value": "2"}]`), "error_ecs_0908"},
		{"too many", act("create", "["+strings.Join(many, ",")+"]"), "error_ecs_0905"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, tags+"/action", tt.body)
		})
	}
	// The limit counts existing tags too.
	e.expect(t, "no_content", http.MethodPost, tags+"/action", act("create", "["+strings.Join(many[:9], ",")+"]"))
	e.expect(t, "error_ecs_0905", http.MethodPost, tags+"/action", act("create", `[{"key": "x1"}, {"key": "x2"}]`))

	unknown := serversPath + "/" + unknownID + "/tags"
	e.expect(t, "error_ecs_0114", http.MethodGet, unknown, "")
	e.expect(t, "error_ecs_0114", http.MethodPost, unknown+"/action", act("create", `[{"key": "a"}]`))
	e.expect(t, "error_ecs_0114", http.MethodPost, unknown+"/action", act("delete", `[{"key": "a"}]`))
}

func TestResumeContinuesPendingOperations(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "weistack.db")
	st, err := store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	first := newEnvWith(t, st, "")
	n := first.mustNetwork(t, testTenant, "192.168.1.0/24")
	stopping := first.mustServer(t, n, "name", `"stopping"`)
	resizing := first.mustServer(t, n, "name", `"resizing"`)

	stopJob, err := first.svc.StopServers(t.Context(), testTenant, []string{stopping}, "")
	if err != nil {
		t.Fatal(err)
	}
	resizeJob, err := first.svc.ResizeServer(t.Context(), testTenant, resizing, ResizeOption{FlavorRef: "c7.large.2", Mode: modeWithStop})
	if err != nil {
		t.Fatal(err)
	}
	first.engine.CancelAll() // the process "dies" mid-operation
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, st, "")
	if err := e.svc.Resume(t.Context()); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	e.settle(t)

	if got := e.state(t, stopping); got != "SHUTOFF/-/stopped/4" {
		t.Errorf("interrupted stop: %s", got)
	}
	if srv := e.server(t, resizing); srv.Status != StatusActive || srv.Flavor != "c7.large.2" || srv.Pending != nil {
		t.Errorf("interrupted resize: %+v", srv)
	}
	for _, id := range []string{stopJob.JobID, resizeJob.JobID} {
		if got, _ := e.svc.GetJob(t.Context(), testTenant, id); got.Status != JobSuccess {
			t.Errorf("job %s (%s): %s", id, got.JobType, got.Status)
		}
	}
}
