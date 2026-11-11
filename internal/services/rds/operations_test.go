package rds

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/store"
)

// active creates an instance and waits for it to be ACTIVE.
func (e *env) active(t *testing.T, extra ...string) string {
	t.Helper()
	id, _ := e.mustCreate(t, e.body(extra...))
	e.settle(t)
	return id
}

func (e *env) view(t *testing.T, id string) InstanceResponse {
	t.Helper()
	_, out := e.call(t, http.MethodGet, "/instances?id="+id, "")
	res := decodeInto[listInstancesResponse](t, out)
	if len(res.Instances) != 1 {
		t.Fatalf("instance %s not listed: %s", id, out)
	}
	return res.Instances[0]
}

func TestRestart(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.active(t)

	out := e.expect(t, "job_accepted", http.MethodPost, "/instances/"+id+"/action", `{"restart": {}}`)
	job := decodeInto[jobIDResponse](t, out).JobID
	if v := e.view(t, id); v.Status != StatusRebooting || v.Nodes[0].Status != StatusActive {
		t.Errorf("during restart: %s, node %s", v.Status, v.Nodes[0].Status)
	}
	if got := e.jobStatus(t, job); got != "RestartInstance:Running" {
		t.Errorf("job = %s", got)
	}
	// One operation at a time.
	e.expect(t, "error_dbs_200011", http.MethodPost, "/instances/"+id+"/action", `{"restart": {}}`)
	e.expect(t, "error_dbs_200011", http.MethodDelete, "/instances/"+id, "")
	e.settle(t)
	if v := e.view(t, id); v.Status != StatusActive {
		t.Errorf("after restart: %s", v.Status)
	}
	if got := e.jobStatus(t, job); got != "RestartInstance:Completed" {
		t.Errorf("job = %s", got)
	}
}

func TestResize(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.active(t)

	e.expect(t, "job_accepted", http.MethodPost, "/instances/"+id+"/action", `{"resize_flavor": {"spec_code": "rds.mysql.n1.xlarge.4"}}`)
	v := e.view(t, id)
	if v.Status != StatusModifying || v.FlavorRef != "rds.mysql.n1.large.2" {
		t.Errorf("during resize: %s with %s; the flavor must change only when the job completes", v.Status, v.FlavorRef)
	}
	e.settle(t)
	v = e.view(t, id)
	if v.Status != StatusActive || v.FlavorRef != "rds.mysql.n1.xlarge.4" || v.CPU != "4" || v.Mem != "16" {
		t.Errorf("after resize: %+v", v)
	}

	tests := []struct{ name, body, golden string }{
		{"same spec", `{"resize_flavor": {"spec_code": "rds.mysql.n1.xlarge.4"}}`, "error_dbs_200001"},
		{"unknown spec", `{"resize_flavor": {"spec_code": "rds.mysql.x9.huge"}}`, "error_dbs_200053"},
		{"other engine", `{"resize_flavor": {"spec_code": "rds.pg.n1.large.2"}}`, "error_dbs_200054"},
		{"single to HA", `{"resize_flavor": {"spec_code": "rds.mysql.n1.large.2.ha"}}`, "error_dbs_200054"},
		{"missing spec", `{"resize_flavor": {}}`, "error_dbs_200001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, "/instances/"+id+"/action", tt.body)
		})
	}
}

func TestEnlargeVolume(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.active(t)
	path := "/instances/" + id + "/action"

	out := e.expect(t, "job_accepted", http.MethodPost, path, `{"enlarge_volume": {"size": 200}}`)
	job := decodeInto[jobIDResponse](t, out).JobID
	if v := e.view(t, id); v.Status != StatusModifying || v.Volume.Size != 100 {
		t.Errorf("during enlargement: %s, %d GB", v.Status, v.Volume.Size)
	}
	e.settle(t)
	if v := e.view(t, id); v.Status != StatusActive || v.Volume.Size != 200 {
		t.Errorf("after enlargement: %s, %d GB", v.Status, v.Volume.Size)
	}
	e.expect(t, "show_job_enlarge_completed", http.MethodGet, "/jobs?id="+job, "")

	e.expect(t, "error_dbs_200306", http.MethodPost, path, `{"enlarge_volume": {"size": 200}}`)
	e.expect(t, "error_dbs_200306", http.MethodPost, path, `{"enlarge_volume": {"size": 100}}`)
	e.expect(t, "error_dbs_200027", http.MethodPost, path, `{"enlarge_volume": {"size": 255}}`)
	e.expect(t, "error_dbs_200023", http.MethodPost, path, `{"enlarge_volume": {"size": 20000}}`)
}

func TestActionRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.active(t)
	failed, _ := e.mustCreate(t, e.body("name", `"failed"`))
	e.settle(t)
	if _, err := e.svc.instances(testTenant).Update(t.Context(), failed, func(i *Instance) error { i.Status = StatusFailed; return nil }); err != nil {
		t.Fatal(err)
	}
	building, _ := e.mustCreate(t, e.body("name", `"building"`))

	tests := []struct{ name, id, body, golden string }{
		{"empty body", id, ``, "error_dbs_200001"},
		{"no action", id, `{}`, "error_dbs_200001"},
		{"two actions", id, `{"restart": {}, "enlarge_volume": {"size": 200}}`, "error_dbs_200001"},
		{"unknown instance", "00000000000000000000000000000000in01", `{"restart": {}}`, "error_dbs_200002"},
		{"failed instance", failed, `{"restart": {}}`, "error_dbs_200086"},
		{"failed instance resize", failed, `{"resize_flavor": {"spec_code": "rds.mysql.n1.large.4"}}`, "error_dbs_200086"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, "/instances/"+tt.id+"/action", tt.body)
		})
	}
	// An instance still being created.
	e.expect(t, "error_dbs_200011", http.MethodPost, "/instances/"+building+"/action", `{"restart": {}}`)
	// Another project's instance does not exist for the caller.
	if status, _ := e.callAs(t, otherProject, http.MethodPost, "/instances/"+id+"/action", `{"restart": {}}`); status != 404 {
		t.Errorf("another project restarted the instance: %d", status)
	}
}

func TestBackups(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.active(t)
	backupBody := `{"instance_id": "` + id + `", "name": "nightly-01", "description": "before the upgrade", "databases": [{"name": "shop"}]}`

	e.expect(t, "list_backups_empty", http.MethodGet, "/backups?instance_id="+id, "")
	out := e.expect(t, "create_backup", http.MethodPost, "/backups", backupBody)
	backupID := decodeInto[createBackupResponse](t, out).Backup.ID
	if !strings.HasSuffix(backupID, "br01") || len(backupID) != 36 {
		t.Errorf("backup ID %q", backupID)
	}
	if v := e.view(t, id); v.Status != StatusBackingUp {
		t.Errorf("instance during backup: %s", v.Status)
	}
	e.expect(t, "list_backups_building", http.MethodGet, "/backups?instance_id="+id, "")
	// No second backup, and no other operation, while one runs; it cannot
	// be deleted mid-way either.
	e.expect(t, "error_dbs_200011", http.MethodPost, "/backups", strings.Replace(backupBody, "nightly-01", "nightly-02", 1))
	e.expect(t, "error_dbs_200011", http.MethodPost, "/instances/"+id+"/action", `{"restart": {}}`)
	e.expect(t, "error_dbs_201208", http.MethodDelete, "/backups/"+backupID, "")

	e.settle(t)
	if v := e.view(t, id); v.Status != StatusActive {
		t.Errorf("instance after backup: %s", v.Status)
	}
	e.expect(t, "list_backups_completed", http.MethodGet, "/backups?instance_id="+id, "")

	// Filters and paging; newest first.
	if _, err := e.svc.CreateBackup(t.Context(), testTenant, CreateBackupOption{InstanceID: id, Name: "second"}); err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	list := func(q string) (string, int) {
		t.Helper()
		_, out := e.call(t, http.MethodGet, "/backups?instance_id="+id+q, "")
		res := decodeInto[listBackupsResponse](t, out)
		var n []string
		for _, b := range res.Backups {
			n = append(n, b.Name)
		}
		return strings.Join(n, ","), res.TotalCount
	}
	for q, want := range map[string]string{
		"": "second,nightly-01", "&limit=1": "second", "&offset=1": "nightly-01", "&backup_id=" + backupID: "nightly-01",
		"&backup_type=manual": "second,nightly-01", "&backup_type=auto": "", "&status=COMPLETED": "second,nightly-01", "&status=FAILED": "",
	} {
		if got, _ := list(q); got != want {
			t.Errorf("list %q = %q, want %q", q, got, want)
		}
	}
	for _, bad := range []string{"", "?instance_id=" + id + "&limit=0", "?instance_id=" + id + "&offset=-1"} {
		e.expect(t, "error_dbs_200001", http.MethodGet, "/backups"+bad, "")
	}

	// Manual backups outlive their instance.
	if _, err := e.svc.DeleteInstance(t.Context(), testTenant, id); err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	if got, total := list(""); total != 2 {
		t.Errorf("after deleting the instance, backups = %q", got)
	}
	e.expect(t, "delete_backup", http.MethodDelete, "/backups/"+backupID, "")
	e.expect(t, "error_dbs_201010", http.MethodDelete, "/backups/"+backupID, "")
	if _, total := list(""); total != 1 {
		t.Errorf("%d backups after one was deleted, want 1", total)
	}
}

func TestBackupValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.active(t)
	for name, body := range map[string]string{
		"malformed":         `{"instance_id": `,
		"missing instance":  `{"name": "nightly"}`,
		"short name":        `{"instance_id": "` + id + `", "name": "abc"}`,
		"name with a space": `{"instance_id": "` + id + `", "name": "my backup"}`,
		"digit first":       `{"instance_id": "` + id + `", "name": "1backup"}`,
		"long description":  `{"instance_id": "` + id + `", "name": "nightly", "description": "` + strings.Repeat("d", 257) + `"}`,
		"unnamed database":  `{"instance_id": "` + id + `", "name": "nightly", "databases": [{"name": ""}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			e.expect(t, "error_dbs_200001", http.MethodPost, "/backups", body)
		})
	}
	e.expect(t, "error_dbs_200002", http.MethodPost, "/backups", `{"instance_id": "00000000000000000000000000000000in01", "name": "nightly"}`)

	// A refused backup leaves no record behind.
	if _, err := e.svc.RestartInstance(t.Context(), testTenant, id); err != nil {
		t.Fatal(err)
	}
	e.expect(t, "error_dbs_200011", http.MethodPost, "/backups", `{"instance_id": "`+id+`", "name": "nightly"}`)
	if b, _ := e.svc.ListBackups(t.Context(), testTenant, id, "", "", ""); len(b) != 0 {
		t.Errorf("a refused backup was recorded: %+v", b)
	}
}

func TestOperationFaults(t *testing.T) {
	t.Parallel()

	t.Run("resize", func(t *testing.T) {
		t.Parallel()
		e := newEnvWith(t, options{faults: failKind(taskResize)})
		id := e.active(t)
		job, err := e.svc.ResizeInstance(t.Context(), testTenant, id, ResizeOption{SpecCode: "rds.mysql.n1.large.4"})
		if err != nil {
			t.Fatal(err)
		}
		e.settle(t)
		inst := e.instance(t, id)
		if inst.Status != StatusFailed || inst.FlavorRef != "rds.mysql.n1.large.2" || inst.Pending != nil {
			t.Errorf("after a failed resize: %+v", inst)
		}
		if got := e.jobStatus(t, job.ID); got != "ResizeFlavor:Failed" {
			t.Errorf("job = %s", got)
		}
	})

	t.Run("backup", func(t *testing.T) {
		t.Parallel()
		e := newEnvWith(t, options{faults: failKind(taskBackup)})
		id := e.active(t)
		b, err := e.svc.CreateBackup(t.Context(), testTenant, CreateBackupOption{InstanceID: id, Name: "doomed"})
		if err != nil {
			t.Fatal(err)
		}
		e.settle(t)
		if inst := e.instance(t, id); inst.Status != StatusActive {
			t.Errorf("a failed backup left the instance %s, want ACTIVE", inst.Status)
		}
		got, _ := e.svc.ListBackups(t.Context(), testTenant, id, b.ID, "", "")
		if len(got) != 1 || got[0].Status != BackupFailed || got[0].EndTime == "" {
			t.Fatalf("backup = %+v", got)
		}
		// A failed backup can be deleted.
		if err := e.svc.DeleteBackup(t.Context(), testTenant, b.ID); err != nil {
			t.Errorf("deleting a failed backup: %v", err)
		}
	})
}

func TestResumeContinuesInstanceOperations(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "weistack.db")
	st, err := store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	first := newEnvWith(t, options{store: st})
	resizing := first.active(t, "name", `"resizing"`)
	backing := first.active(t, "name", `"backing-up"`)
	if _, err := first.svc.ResizeInstance(t.Context(), testTenant, resizing, ResizeOption{SpecCode: "rds.mysql.n1.2xlarge.4"}); err != nil {
		t.Fatal(err)
	}
	b, err := first.svc.CreateBackup(t.Context(), testTenant, CreateBackupOption{InstanceID: backing, Name: "resumed"})
	if err != nil {
		t.Fatal(err)
	}
	first.engine.CancelAll()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, options{store: st, reuse: &first.net})
	if err := e.svc.Resume(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	if inst := e.instance(t, resizing); inst.Status != StatusActive || inst.FlavorRef != "rds.mysql.n1.2xlarge.4" {
		t.Errorf("interrupted resize: %+v", inst)
	}
	if inst := e.instance(t, backing); inst.Status != StatusActive {
		t.Errorf("interrupted backup left the instance %s", inst.Status)
	}
	if got, _ := e.svc.ListBackups(t.Context(), testTenant, backing, b.ID, "", ""); len(got) != 1 || got[0].Status != BackupCompleted {
		t.Errorf("interrupted backup: %+v", got)
	}
}
