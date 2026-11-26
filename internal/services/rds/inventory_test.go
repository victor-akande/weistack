package rds

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
)

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	instID := e.active(t,
		"name", `"primary-db"`,
		"enterprise_project_id", `"ep-1"`,
		"tags", `[{"key": "env", "value": "prod"}]`,
	)
	status, out := e.call(t, http.MethodPost, "/backups",
		fmt.Sprintf(`{"instance_id": %q, "name": "nightly-01"}`, instID))
	if status != http.StatusAccepted {
		t.Fatalf("creating a backup: %d %s", status, out)
	}
	createdBackup := decodeInto[createBackupResponse](t, out).Backup
	e.settle(t)
	instRecord := e.instance(t, instID)

	// An instance in another project, still being created.
	otherNet := e.makeNetwork(t, Tenant{Region: testRegion, ProjectID: otherProject}, "192.168.2.0/24")
	status, out = e.callAs(t, otherProject, http.MethodPost, "/instances", e.bodyIn(otherNet, "name", `"pending-db"`))
	if status != http.StatusAccepted {
		t.Fatalf("creating an instance in another project: %d %s", status, out)
	}
	pendingID := decodeInto[createInstanceResponse](t, out).Instance.ID

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", snap), "Weistack@2026") {
		t.Fatalf("database password appeared in inventory snapshot")
	}

	got := make(map[string]inventory.Resource)
	for _, r := range snap.Resources {
		got[r.Type.String()+"/"+r.ProjectID+"/"+r.ID] = r
	}
	at := func(typ inventory.Type, project, id string) inventory.Resource {
		t.Helper()
		r, ok := got[typ.String()+"/"+project+"/"+id]
		if !ok {
			t.Fatalf("%s %s is not reported; got %v", typ, id, snap.Resources)
		}
		return r
	}

	inst := at(inventory.RDSInstances, testProject, instID)
	if inst.Name != "primary-db" || inst.RegionID != testRegion || inst.ProjectID != testProject ||
		inst.EnterpriseProjectID != "ep-1" || inst.State != inventory.Succeeded ||
		inst.Created.IsZero() || !inst.Created.Equal(instRecord.Created) || !inst.Updated.Equal(instRecord.Updated) ||
		inst.Tags["env"] != "prod" || len(inst.Tags) != 1 || len(inst.Relations) != 0 {
		t.Errorf("instance = %+v", inst)
	}

	pending := at(inventory.RDSInstances, otherProject, pendingID)
	if pending.Name != "pending-db" || pending.RegionID != testRegion || pending.ProjectID != otherProject ||
		pending.EnterpriseProjectID != inventory.DefaultEnterpriseProject || pending.State != inventory.Processing ||
		pending.Created.IsZero() || len(pending.Tags) != 0 || len(pending.Relations) != 0 {
		t.Errorf("pending instance = %+v, want Processing", pending)
	}

	wantBackupCreated, err := time.Parse(timeLayout, createdBackup.BeginTime)
	if err != nil {
		t.Fatalf("parsing backup BeginTime %q: %v", createdBackup.BeginTime, err)
	}
	b := at(inventory.RDSBackups, testProject, createdBackup.ID)
	if b.Name != "nightly-01" || b.RegionID != testRegion || b.ProjectID != testProject ||
		b.EnterpriseProjectID != inventory.DefaultEnterpriseProject || b.State != inventory.Succeeded ||
		b.Created.IsZero() || !b.Created.Equal(wantBackupCreated.UTC()) || !b.Updated.After(b.Created) ||
		len(b.Tags) != 0 || len(b.Relations) != 0 {
		t.Errorf("backup = %+v", b)
	}

	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.RDSInstances: 2,
		inventory.RDSBackups:   1,
	}
	if fmt.Sprint(count) != fmt.Sprint(want) {
		t.Errorf("reported %v, want %v", count, want)
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	for status, want := range map[string]inventory.State{
		StatusBuild:      inventory.Processing,
		StatusRebooting:  inventory.Processing,
		StatusModifying:  inventory.Processing,
		StatusBackingUp:  inventory.Processing,
		StatusCreateFail: inventory.Failed,
		StatusFailed:     inventory.Failed,
		StatusActive:     inventory.Succeeded,
	} {
		if got := instanceState(status); got != want {
			t.Errorf("instanceState(%s) = %s, want %s", status, got, want)
		}
	}
	for status, want := range map[string]inventory.State{
		BackupBuilding:  inventory.Processing,
		BackupFailed:    inventory.Failed,
		BackupCompleted: inventory.Succeeded,
	} {
		if got := backupState(status); got != want {
			t.Errorf("backupState(%s) = %s, want %s", status, got, want)
		}
	}
}
