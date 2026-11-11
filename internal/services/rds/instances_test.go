package rds

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/store"
)

func TestInstanceLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.expect(t, "list_instances_empty", http.MethodGet, "/instances", "")

	out := e.expect(t, "create_instance", http.MethodPost, "/instances", e.body(
		"backup_strategy", `{"start_time": "08:15-09:15", "keep_days": 12}`,
		"tags", `[{"key": "env", "value": "test"}]`,
	))
	res := decodeInto[createInstanceResponse](t, out)
	id := res.Instance.ID
	if len(id) != 36 || !strings.HasSuffix(id, "in01") {
		t.Errorf("instance ID %q is not 32 hex characters and in01", id)
	}

	e.expect(t, "list_instances_build", http.MethodGet, "/instances", "")
	e.expect(t, "show_job_create_running", http.MethodGet, "/jobs?id="+res.JobID, "")
	// Nothing can be done to it while it is being created.
	e.expect(t, "error_dbs_200011", http.MethodDelete, "/instances/"+id, "")

	e.settle(t)
	e.expect(t, "list_instances_active", http.MethodGet, "/instances", "")
	e.expect(t, "show_job_create_completed", http.MethodGet, "/jobs?id="+res.JobID, "")
	if free := e.subnetFree(t); free != 250 {
		t.Errorf("%d free addresses in the subnet, want 250", free)
	}

	out = e.expect(t, "delete_instance", http.MethodDelete, "/instances/"+id, "")
	deleteJob := decodeInto[jobIDResponse](t, out).JobID
	e.expect(t, "error_dbs_200011", http.MethodDelete, "/instances/"+id, "") // already being deleted
	e.settle(t)
	e.expect(t, "show_job_delete_completed", http.MethodGet, "/jobs?id="+deleteJob, "")
	e.expect(t, "list_instances_empty", http.MethodGet, "/instances", "")
	e.expect(t, "error_dbs_200002", http.MethodDelete, "/instances/"+id, "")
	if free := e.subnetFree(t); free != 251 {
		t.Errorf("the address was not released: %d free", free)
	}

	e.expect(t, "error_dbs_200543", http.MethodGet, "/jobs?id="+unknownUUID, "")
	e.expect(t, "error_dbs_200001", http.MethodGet, "/jobs", "")
}

func TestEnginesAndFlavors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	e.expect(t, "list_datastores_mysql", http.MethodGet, "/datastores/MySQL", "")
	e.expect(t, "list_datastores_mysql", http.MethodGet, "/datastores/mysql", "")
	_, out := e.call(t, http.MethodGet, "/datastores/PostgreSQL", "")
	var pg []string
	for _, v := range decodeInto[listDatastoresResponse](t, out).DataStores {
		pg = append(pg, v.Name)
	}
	if strings.Join(pg, ",") != "13,14,15,16,17,18" {
		t.Errorf("PostgreSQL versions = %v", pg)
	}

	e.expect(t, "list_flavors_one", http.MethodGet, "/flavors/MySQL?version_name=8.0&spec_code=rds.mysql.n1.large.2", "")
	_, out = e.call(t, http.MethodGet, "/flavors/PostgreSQL", "")
	flavors := decodeInto[listFlavorsResponse](t, out).Flavors
	if len(flavors) != 12 {
		t.Fatalf("%d PostgreSQL flavors, want 12", len(flavors))
	}
	ha := 0
	for _, f := range flavors {
		if !strings.HasPrefix(f.SpecCode, "rds.pg.n1.") {
			t.Errorf("unexpected spec code %s", f.SpecCode)
		}
		if f.InstanceMode == "ha" {
			ha++
			if !strings.HasSuffix(f.SpecCode, ".ha") {
				t.Errorf("HA flavor without .ha suffix: %s", f.SpecCode)
			}
		}
	}
	if ha != 6 {
		t.Errorf("%d HA flavors, want 6", ha)
	}
	e.expect(t, "error_dbs_200040", http.MethodGet, "/flavors/MySQL?version_name=5.6", "")
	e.expect(t, "error_dbs_200001", http.MethodGet, "/flavors/Oracle", "")
	e.expect(t, "error_not_implemented", http.MethodGet, "/flavors/SQLServer", "")
	e.expect(t, "error_not_implemented", http.MethodGet, "/datastores/MariaDB", "")
}

func TestCreateValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	other := e.makeNetwork(t, testTenant, "192.168.2.0/24")
	e.mustCreate(t, e.body("name", `"taken"`))

	tests := []struct{ name, body, golden string }{
		{"malformed", `{"name": `, "error_dbs_200001"},
		{"missing datastore", e.body("datastore", "<omit>"), "error_dbs_200001"},
		{"unknown engine", e.body("datastore", `{"type": "Oracle", "version": "19c"}`), "error_dbs_200040"},
		{"unsupported version", e.body("datastore", `{"type": "MySQL", "version": "5.6"}`), "error_dbs_200040"},
		{"sql server", e.body("datastore", `{"type": "SQLServer", "version": "2022_SE"}`), "error_not_implemented"},
		{"name too short", e.body("name", `"abc"`), "error_dbs_200021"},
		{"name starts with a digit", e.body("name", `"1mysql"`), "error_dbs_200021"},
		{"name too long", e.body("name", `"`+strings.Repeat("n", 65)+`"`), "error_dbs_200021"},
		{"name with a space", e.body("name", `"my db"`), "error_dbs_200021"},
		{"period in a PostgreSQL name", e.body("name", `"pg.db"`, "datastore", `{"type": "PostgreSQL", "version": "16"}`, "flavor_ref", `"rds.pg.n1.large.2"`), "error_dbs_200021"},
		{"duplicate name", e.body("name", `"taken"`), "error_dbs_200022"},
		{"short password", e.body("password", `"Ab1@"`), "error_dbs_200052"},
		{"MySQL needs four kinds", e.body("password", `"Weistack2026"`), "error_dbs_200052"},
		{"password with a space", e.body("password", `"Weist ack@2026"`), "error_dbs_200052"},
		{"port not a number", e.body("port", `"db"`), "error_dbs_280364"},
		{"MySQL reserved port", e.body("port", `"33071"`), "error_dbs_280364"},
		{"MySQL port too low", e.body("port", `"80"`), "error_dbs_280364"},
		{"missing flavor", e.body("flavor_ref", "<omit>"), "error_dbs_200001"},
		{"unknown flavor", e.body("flavor_ref", `"rds.mysql.x9.huge"`), "error_dbs_200053"},
		{"flavor of another engine", e.body("flavor_ref", `"rds.pg.n1.large.2"`), "error_dbs_200054"},
		{"HA flavor for a single instance", e.body("flavor_ref", `"rds.mysql.n1.large.2.ha"`), "error_dbs_200054"},
		{"single flavor for an HA instance", e.body("ha", `{"mode": "Ha", "replication_mode": "semisync"}`, "availability_zone", `"ap-southeast-1a,ap-southeast-1b"`), "error_dbs_200054"},
		{"bad HA mode", e.body("ha", `{"mode": "Cluster"}`, "flavor_ref", `"rds.mysql.n1.large.2.ha"`, "availability_zone", `"ap-southeast-1a,ap-southeast-1b"`), "error_dbs_200001"},
		{"sync replication for MySQL", e.body("ha", `{"mode": "Ha", "replication_mode": "sync"}`, "flavor_ref", `"rds.mysql.n1.large.2.ha"`, "availability_zone", `"ap-southeast-1a,ap-southeast-1b"`), "error_dbs_200001"},
		{"HA with one zone", e.body("ha", `{"mode": "Ha"}`, "flavor_ref", `"rds.mysql.n1.large.2.ha"`), "error_dbs_200025"},
		{"single with two zones", e.body("availability_zone", `"ap-southeast-1a,ap-southeast-1b"`), "error_dbs_200025"},
		{"unknown zone", e.body("availability_zone", `"ap-southeast-1z"`), "error_dbs_200025"},
		{"missing volume", e.body("volume", "<omit>"), "error_dbs_200001"},
		{"bad volume type", e.body("volume", `{"type": "FLOPPY", "size": 100}`), "error_dbs_200001"},
		{"volume not a multiple of ten", e.body("volume", `{"type": "CLOUDSSD", "size": 105}`), "error_dbs_200027"},
		{"volume too small", e.body("volume", `{"type": "CLOUDSSD", "size": 10}`), "error_dbs_200023"},
		{"volume too large", e.body("volume", `{"type": "CLOUDSSD", "size": 20000}`), "error_dbs_200023"},
		{"PostgreSQL volume too small", e.body("name", `"pg-small"`, "datastore", `{"type": "PostgreSQL", "version": "16"}`, "flavor_ref", `"rds.pg.n1.large.2"`, "volume", `{"type": "CLOUDSSD", "size": 30}`), "error_dbs_200023"},
		{"wrong region", e.body("region", `"cn-north-4"`), "error_dbs_200001"},
		{"backup window not one hour", e.body("backup_strategy", `{"start_time": "08:00-10:00"}`), "error_dbs_200001"},
		{"backup window minutes differ", e.body("backup_strategy", `{"start_time": "08:00-09:15"}`), "error_dbs_200001"},
		{"backup window off the quarter", e.body("backup_strategy", `{"start_time": "08:10-09:10"}`), "error_dbs_200001"},
		{"keep days too many", e.body("backup_strategy", `{"start_time": "08:00-09:00", "keep_days": 733}`), "error_dbs_200001"},
		{"keep days zero", e.body("backup_strategy", `{"start_time": "08:00-09:00", "keep_days": 0}`), "error_dbs_200001"},
		{"system tag", e.body("tags", `[{"key": "_sys_x", "value": "1"}]`), "error_dbs_200001"},
		{"duplicate tag", e.body("tags", `[{"key": "a", "value": "1"}, {"key": "a", "value": "2"}]`), "error_dbs_200001"},
		{"unknown vpc", e.body("vpc_id", `"`+unknownUUID+`"`), "error_dbs_200503"},
		{"malformed vpc", e.body("vpc_id", `"not-a-vpc"`), "error_dbs_200503"},
		{"unknown subnet", e.body("subnet_id", `"`+unknownUUID+`"`), "error_dbs_200501"},
		{"subnet of another vpc", e.body("subnet_id", `"`+other.subnet+`"`), "error_dbs_200501"},
		{"unknown security group", e.body("security_group_id", `"`+unknownUUID+`"`), "error_dbs_200050"},
		{"read replica", e.body("replica_of_id", `"abc"`), "error_not_implemented"},
		{"restore", e.body("restore_point", `{"instance_id": "x", "type": "backup"}`), "error_not_implemented"},
		{"dry run", e.body("dry_run", `true`), "error_not_implemented"},
		{"count", e.body("count", `3`), "error_not_implemented"},
		{"yearly", e.body("charge_info", `{"charge_mode": "prePaid", "period_type": "month", "period_num": 1}`), "error_not_implemented"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, "/instances", tt.body)
		})
	}

	all, _ := e.svc.ListInstances(t.Context(), testTenant, ListInstancesFilter{})
	if len(all) != 1 {
		t.Errorf("%d instances after rejected requests, want 1", len(all))
	}
	if free := e.subnetFree(t); free != 250 {
		t.Errorf("rejected requests consumed addresses: %d free", free)
	}
}

func TestCreateOptions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	// A PostgreSQL primary/standby pair across two zones.
	id, _ := e.mustCreate(t, e.body(
		"name", `"pg_ha-01"`,
		"datastore", `{"type": "PostgreSQL", "version": "16"}`,
		"flavor_ref", `"rds.pg.n1.xlarge.4.ha"`,
		"ha", `{"mode": "ha"}`,
		"availability_zone", `"ap-southeast-1a,ap-southeast-1b"`,
		"volume", `{"type": "ESSD", "size": 200}`,
		"password", `"Weistack2026"`, // three kinds are enough for PostgreSQL
		"port", `"5433"`,
		"time_zone", `"UTC+08:00"`,
		"configuration_id", `"6a2b0bd3a5ef4b4da1c1e2f9f2c1a0f1pr01"`,
		"enterprise_project_id", `"0aad99bc-f5f6-4f78-8404-c598d76b0ed2"`,
	))
	e.settle(t)
	_, out := e.call(t, http.MethodGet, "/instances?id="+id, "")
	v := decodeInto[listInstancesResponse](t, out).Instances[0]
	if v.Type != "Ha" || v.HA == nil || v.HA.ReplicationMode != "async" || v.SwitchStrategy != "reliability" ||
		v.Port != 5433 || v.CPU != "4" || v.Mem != "16" || v.TimeZone != "UTC+08:00" || v.EnterpriseProjectID == "0" {
		t.Errorf("HA instance = %+v", v)
	}
	if len(v.Nodes) != 2 || v.Nodes[0].Role != "master" || v.Nodes[1].Role != "slave" ||
		v.Nodes[0].AvailabilityZone != "ap-southeast-1a" || v.Nodes[1].AvailabilityZone != "ap-southeast-1b" ||
		v.Nodes[1].Name != "pg_ha-01_node1" || !strings.HasSuffix(v.Nodes[1].ID, "no01") {
		t.Errorf("nodes = %+v", v.Nodes)
	}

	// Defaults: port, backup window, no password at all.
	id, _ = e.mustCreate(t, e.body("name", `"pg-defaults"`, "datastore", `{"type": "PostgreSQL", "version": "13"}`,
		"flavor_ref", `"rds.pg.n1.large.2"`, "password", "<omit>", "volume", `{"type": "ULTRAHIGH", "size": 40}`))
	inst := e.instance(t, id)
	if inst.Port != 5432 || inst.BackupStart != "02:00-03:00" || inst.KeepDays != 7 || inst.Mode != ModeSingle {
		t.Errorf("defaults = %+v", inst)
	}

	// The password is never stored or returned.
	if raw, _ := e.store.Dump(t.Context()); strings.Contains(fmt.Sprint(raw), "Weistack") {
		t.Error("a password reached the store")
	}
	_, out = e.call(t, http.MethodGet, "/instances", "")
	if strings.Contains(string(out), "Weistack") {
		t.Error("a password appears in a response")
	}
}

func TestListFiltersAndPaging(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	other := e.makeNetwork(t, testTenant, "192.168.2.0/24")
	e.mustCreate(t, e.body("name", `"orders-db"`, "tags", `[{"key": "team", "value": "shop"}]`))
	e.mustCreate(t, e.body("name", `"users-db"`, "tags", `[{"key": "team", "value": "auth"}, {"key": "tier", "value": "1"}]`))
	pgID, _ := e.mustCreate(t, e.bodyIn(other, "name", `"reports"`, "datastore", `{"type": "PostgreSQL", "version": "15"}`, "flavor_ref", `"rds.pg.n1.large.2.ha"`,
		"ha", `{"mode": "Ha", "replication_mode": "sync"}`, "availability_zone", `"ap-southeast-1b,ap-southeast-1c"`))
	e.settle(t)

	names := func(query string) (string, int) {
		t.Helper()
		status, out := e.call(t, http.MethodGet, "/instances"+query, "")
		if status != 200 {
			t.Fatalf("list %s: %d %s", query, status, out)
		}
		res := decodeInto[listInstancesResponse](t, out)
		var n []string
		for _, i := range res.Instances {
			n = append(n, i.Name)
		}
		return strings.Join(n, ","), res.TotalCount
	}
	tests := []struct {
		query, want string
		total       int
	}{
		{"", "orders-db,users-db,reports", 3},
		{"?name=users-db", "users-db", 1},
		{"?name=*-db", "orders-db,users-db", 2},
		{"?name=-db", "", 0},
		{"?id=" + pgID, "reports", 1},
		{"?id=*" + pgID[4:12], "reports", 1},
		{"?type=Ha", "reports", 1},
		{"?type=Single", "orders-db,users-db", 2},
		{"?datastore_type=PostgreSQL", "reports", 1},
		{"?vpc_id=" + other.vpc, "reports", 1},
		{"?subnet_id=" + e.net.subnet, "orders-db,users-db", 2},
		{"?eps_id=0", "orders-db,users-db,reports", 3},
		{"?tags=team", "orders-db,users-db", 2},
		{"?tags=team=auth", "users-db", 1},
		{"?tags=team=auth,tier=1", "users-db", 1},
		{"?tags=team=auth,tier=2", "", 0},
		{"?limit=2", "orders-db,users-db", 3},
		{"?limit=2&offset=2", "reports", 3},
		{"?offset=3", "", 3},
		{"?offset=99", "", 3},
	}
	for _, tt := range tests {
		got, total := names(tt.query)
		if got != tt.want || total != tt.total {
			t.Errorf("list %q = %q (total %d), want %q (total %d)", tt.query, got, total, tt.want, tt.total)
		}
	}
	for _, bad := range []string{"?limit=0", "?limit=101", "?limit=x", "?offset=-1", "?id=*"} {
		e.expect(t, "error_dbs_200001", http.MethodGet, "/instances"+bad, "")
	}

	// Instances are invisible to other projects.
	_, out := e.callAs(t, otherProject, http.MethodGet, "/instances", "")
	if decodeInto[listInstancesResponse](t, out).TotalCount != 0 {
		t.Errorf("another project sees instances: %s", out)
	}
	if status, _ := e.callAs(t, otherProject, http.MethodDelete, "/instances/"+pgID, ""); status != 404 {
		t.Errorf("another project can delete the instance: %d", status)
	}
}

func TestQuota(t *testing.T) {
	t.Parallel()
	e := newEnvWith(t, options{quota: 2})
	e.mustCreate(t, e.body("name", `"db-one"`))
	id, _ := e.mustCreate(t, e.body("name", `"db-two"`))
	e.expect(t, "error_dbs_200046", http.MethodPost, "/instances", e.body("name", `"db-three"`))

	e.settle(t)
	if _, err := e.svc.DeleteInstance(t.Context(), testTenant, id); err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	e.mustCreate(t, e.body("name", `"db-three"`))
}

func TestSubnetExhaustion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	// Take every address of the subnet.
	for {
		if _, err := e.network.AllocateIP(ctx, testTenant.vpc(), e.net.subnet, "test", ""); err != nil {
			break
		}
	}
	e.expect(t, "error_dbs_200001", http.MethodPost, "/instances", e.body())
	all, _ := e.svc.ListInstances(ctx, testTenant, ListInstancesFilter{})
	if len(all) != 0 {
		t.Errorf("an instance was created without an address")
	}
}

type failKind string

func (f failKind) Fault(kind, _ string) error {
	if kind == string(f) {
		return errors.New("injected storage failure")
	}
	return nil
}

func TestCreateFault(t *testing.T) {
	t.Parallel()
	e := newEnvWith(t, options{faults: failKind(taskCreate)})
	id, job := e.mustCreate(t, e.body())
	e.settle(t)

	_, out := e.call(t, http.MethodGet, "/instances", "")
	v := decodeInto[listInstancesResponse](t, out).Instances[0]
	if v.Status != StatusCreateFail || v.Nodes[0].Status != StatusCreateFail {
		t.Errorf("instance after a failed create: %s, node %s", v.Status, v.Nodes[0].Status)
	}
	got, _ := e.svc.GetJob(t.Context(), testTenant, job)
	if got.Status != JobFailed || !strings.Contains(got.FailReason, "injected") || got.Ended == "" || got.Process != "" {
		t.Errorf("job = %+v", got)
	}
	// A failed instance can be cleaned up.
	if _, err := e.svc.DeleteInstance(t.Context(), testTenant, id); err != nil {
		t.Fatalf("deleting a failed instance: %v", err)
	}
}

func TestDeleteFaultKeepsTheInstance(t *testing.T) {
	t.Parallel()
	e := newEnvWith(t, options{faults: failKind(taskDelete)})
	id, _ := e.mustCreate(t, e.body())
	e.settle(t)
	job, err := e.svc.DeleteInstance(t.Context(), testTenant, id)
	if err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	if inst := e.instance(t, id); inst.Status != StatusFailed || inst.Pending != nil {
		t.Errorf("instance after a failed delete = %+v", inst)
	}
	if got := e.jobStatus(t, job.ID); got != "DeleteInstance:Failed" {
		t.Errorf("job = %s", got)
	}
	if free := e.subnetFree(t); free != 250 {
		t.Errorf("a failed delete released the address: %d free", free)
	}
}

func TestConcurrentCreatesRespectQuotaAndNames(t *testing.T) {
	t.Parallel()
	e := newEnvWith(t, options{quota: 5})

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		ok       int
		failures = map[string]int{}
	)
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("db-%d", i%8) // some names collide
			opt := CreateInstanceOption{
				Name: name, Datastore: &Datastore{Type: "MySQL", Version: "8.0"}, FlavorRef: "rds.mysql.n1.large.2",
				Volume: &Volume{Type: "CLOUDSSD", Size: 40}, Region: testRegion, AvailabilityZone: "ap-southeast-1a",
				VPCID: e.net.vpc, SubnetID: e.net.subnet, SecurityGroupID: e.net.group,
			}
			_, _, err := e.svc.CreateInstance(t.Context(), testTenant, opt)
			mu.Lock()
			defer mu.Unlock()
			var apiErr *apierr.Error
			switch {
			case err == nil:
				ok++
			case errors.As(err, &apiErr):
				failures[apiErr.Code]++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	all, _ := e.svc.ListInstances(t.Context(), testTenant, ListInstancesFilter{})
	names := map[string]bool{}
	for _, i := range all {
		if names[i.Name] {
			t.Errorf("name %s used twice", i.Name)
		}
		names[i.Name] = true
	}
	if ok != 5 || len(all) != 5 || failures["DBS.200046"]+failures["DBS.200022"] != 15 {
		t.Fatalf("%d created, %d stored, failures %v", ok, len(all), failures)
	}
	if free := e.subnetFree(t); free != 246 {
		t.Errorf("%d free addresses, want 246", free)
	}
}

func TestResumeContinuesOperations(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "weistack.db")
	st, err := store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	first := newEnvWith(t, options{store: st})
	deleting, _ := first.mustCreate(t, first.body("name", `"deleting"`))
	first.settle(t)
	// A create and a delete that the "crash" interrupts midway.
	building, createJob := first.mustCreate(t, first.body("name", `"building"`))
	delJob, err := first.svc.DeleteInstance(t.Context(), testTenant, deleting)
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
		t.Fatalf("Resume: %v", err)
	}
	e.settle(t)
	if inst := e.instance(t, building); inst.Status != StatusActive {
		t.Errorf("interrupted create: %s", inst.Status)
	}
	if got := e.jobStatus(t, createJob); got != "CreateMysqlInstance:Completed" {
		t.Errorf("create job: %s", got)
	}
	if _, err := e.svc.GetInstance(t.Context(), testTenant, deleting); err == nil {
		t.Error("interrupted delete did not finish")
	}
	if got := e.jobStatus(t, delJob.ID); got != "DeleteInstance:Completed" {
		t.Errorf("delete job: %s", got)
	}

	scope := store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindInstance}
	if _, err := e.store.Put(t.Context(), scope, "bad", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Resume(t.Context()); err == nil {
		t.Fatal("Resume ignored a corrupt record")
	}
}

func TestRules(t *testing.T) {
	t.Parallel()

	for w, want := range map[string]bool{
		"08:15-09:15": true, "23:00-00:00": true, "00:45-01:45": true,
		"08:00-10:00": false, "08:00-09:15": false, "08:10-09:10": false, "24:00-01:00": false, "8:00-9:00": false, "": false,
	} {
		if got := checkBackupWindow(w); got != want {
			t.Errorf("checkBackupWindow(%q) = %v", w, got)
		}
	}
	mysql, _ := engineNamed("mysql")
	pg, _ := engineNamed("POSTGRESQL")
	for p, want := range map[string]bool{
		"Weistack@2026": true, "Weistack2026": false, "weistack@2026": false, "Short@1": false,
		"Weistack@2026" + strings.Repeat("x", 20): false, "Weistack@2026é": false,
	} {
		if got := mysql.checkPassword(p) == nil; got != want {
			t.Errorf("MySQL password %q accepted = %v", p, got)
		}
	}
	if pg.checkPassword("Weistack2026") != nil || pg.checkPassword("Weistack(2026)") == nil {
		t.Error("PostgreSQL password rules are wrong")
	}
	if _, ok := flavorByCode("rds.mysql.n1.2xlarge.4.ha"); !ok {
		t.Error("an HA flavor is missing")
	}
	if !matchName("*abc", "xxabcxx") || matchName("abc", "xxabcxx") || !matchName("", "any") {
		t.Error("matchName is wrong")
	}
	if _, err := New(Deps{}); err == nil {
		t.Error("New succeeded without dependencies")
	}
}
