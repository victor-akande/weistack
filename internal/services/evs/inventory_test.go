package evs

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
)

type fakeReporter []inventory.Resource

func (f fakeReporter) ReportResources(_ context.Context, emit func(inventory.Resource) error) error {
	for _, r := range f {
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newSnapshotEnv(t, nil, nil, nil)

	const (
		serverID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		otherProject = "fedcba9876543210fedcba9876543210"
		az           = "ap-southeast-1a"
	)
	e.svc.SetServers(&stubServers{
		servers: map[string]ServerInfo{
			serverID: {AvailabilityZone: az, Status: "ACTIVE"},
		},
		attach: func(ctx context.Context, ten Tenant, srvID, volID string) error {
			if _, err := e.svc.BeginAttach(ctx, ten, volID, srvID, az, "", "job-attach", false); err != nil {
				return err
			}
			e.svc.FinishAttach(ctx, ten, volID, "job-attach", nil)
			return nil
		},
	})

	status, out, raw := e.do(t, http.MethodPost, "/v2.1/{p}/cloudvolumes", fmt.Sprintf(`{
		"server_id": %q,
		"volume": {
			"name": "data",
			"availability_zone": %q,
			"volume_type": "GPSSD",
			"size": %d,
			"enterprise_project_id": "ep-1",
			"tags": {"env": "prod"}
		}
	}`, serverID, az, minEmptySizeGB))
	if status != http.StatusAccepted {
		t.Fatalf("creating a volume: %d %s", status, raw)
	}
	volID := out["volume_ids"].([]any)[0].(string)
	e.settle(t)

	status, volShow, raw := e.do(t, http.MethodGet, "/v2/{p}/cloudvolumes/"+volID, "")
	if status != http.StatusOK {
		t.Fatalf("showing volume: %d %s", status, raw)
	}
	volCreatedAt, err := time.Parse(volumeTimeLayout, volShow["volume"].(map[string]any)["created_at"].(string))
	if err != nil {
		t.Fatalf("parsing volume created_at: %v", err)
	}

	status, out, raw = e.do(t, http.MethodPost, "/v2/{p}/cloudsnapshots", fmt.Sprintf(`{
		"snapshot": {
			"volume_id": %q,
			"name": "snap-1"
		}
	}`, volID))
	if status != http.StatusAccepted {
		t.Fatalf("creating a snapshot: %d %s", status, raw)
	}
	snapID := out["snapshot"].(map[string]any)["id"].(string)
	e.settle(t)

	status, snapShow, raw := e.do(t, http.MethodGet, "/v2/{p}/cloudsnapshots/"+snapID, "")
	if status != http.StatusOK {
		t.Fatalf("showing snapshot: %d %s", status, raw)
	}
	snapCreatedAt, err := time.Parse(volumeTimeLayout, snapShow["snapshot"].(map[string]any)["created_at"].(string))
	if err != nil {
		t.Fatalf("parsing snapshot created_at: %v", err)
	}

	// A volume in a second project, left in creating status.
	status, out, raw = e.do(t, http.MethodPost, "/v2.1/"+otherProject+"/cloudvolumes", fmt.Sprintf(`{
		"volume": {
			"name": "pending",
			"availability_zone": %q,
			"volume_type": "SSD",
			"size": %d
		}
	}`, az, minEmptySizeGB))
	if status != http.StatusAccepted {
		t.Fatalf("creating pending volume: %d %s", status, raw)
	}
	pendingID := out["volume_ids"].([]any)[0].(string)

	fakeECS := fakeReporter{{
		Type:      inventory.ECSServers,
		ID:        serverID,
		Name:      "web",
		RegionID:  region,
		ProjectID: project,
	}}
	owner := func(proj, _ string) (string, bool) {
		return "acct-" + proj[:4], true
	}
	snap, err := inventory.New(inventory.Options{
		Reporters: []inventory.Reporter{e.svc, fakeECS},
		Owner:     owner,
	}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := make(map[string]inventory.Resource)
	for _, r := range snap.Resources {
		got[r.Type.String()+"/"+r.ProjectID+"/"+r.ID] = r
	}
	at := func(typ inventory.Type, proj, id string) inventory.Resource {
		t.Helper()
		r, ok := got[typ.String()+"/"+proj+"/"+id]
		if !ok {
			t.Fatalf("%s %s is not reported; got %v", typ, id, snap.Resources)
		}
		return r
	}

	v := at(inventory.EVSVolumes, project, volID)
	if v.Name != "data" || v.RegionID != region || v.ProjectID != project || v.AccountID != "acct-"+project[:4] ||
		v.EnterpriseProjectID != "ep-1" || v.State != inventory.Succeeded ||
		v.Created.IsZero() || !v.Created.Equal(volCreatedAt) || v.Updated.Before(v.Created) ||
		v.Tags["env"] != "prod" || len(v.Tags) != 1 {
		t.Errorf("volume = %+v", v)
	}
	wantVolRels := []inventory.Ref{{
		Relation: inventory.IsAttachedTo,
		Type:     inventory.ECSServers,
		ID:       serverID,
	}}
	if !reflect.DeepEqual(v.Relations, wantVolRels) {
		t.Errorf("volume.Relations = %+v, want %+v", v.Relations, wantVolRels)
	}

	p := at(inventory.EVSVolumes, otherProject, pendingID)
	if p.Name != "pending" || p.RegionID != region || p.ProjectID != otherProject || p.AccountID != "acct-"+otherProject[:4] ||
		p.EnterpriseProjectID != inventory.DefaultEnterpriseProject || p.State != inventory.Processing ||
		p.Created.IsZero() || len(p.Tags) != 0 || len(p.Relations) != 0 {
		t.Errorf("pending volume = %+v, want Processing", p)
	}

	sn := at(inventory.EVSSnapshots, project, snapID)
	if sn.Name != "snap-1" || sn.RegionID != region || sn.ProjectID != project || sn.AccountID != "acct-"+project[:4] ||
		sn.EnterpriseProjectID != "ep-1" || sn.State != inventory.Succeeded ||
		sn.Created.IsZero() || !sn.Created.Equal(snapCreatedAt) || sn.Updated.Before(sn.Created) ||
		len(sn.Tags) != 0 || len(sn.Relations) != 0 {
		t.Errorf("snapshot = %+v", sn)
	}

	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.ECSServers:   len(fakeECS),
		inventory.EVSVolumes:   2,
		inventory.EVSSnapshots: 1,
	}
	if !reflect.DeepEqual(count, want) {
		t.Errorf("reported %v, want %v", count, want)
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	for status, want := range map[string]inventory.State{
		statusCreating:         inventory.Processing,
		statusExtending:        inventory.Processing,
		statusDeleting:         inventory.Processing,
		statusAttaching:        inventory.Processing,
		statusDetaching:        inventory.Processing,
		statusRollbacking:      inventory.Processing,
		statusError:            inventory.Failed,
		statusErrorExtending:   inventory.Failed,
		statusErrorDeleting:    inventory.Failed,
		statusErrorRestoring:   inventory.Failed,
		statusErrorRollbacking: inventory.Failed,
		"error_other":          inventory.Failed,
		statusAvailable:        inventory.Succeeded,
		statusInUse:            inventory.Succeeded,
	} {
		if got := evsState(status); got != want {
			t.Errorf("evsState(%q) = %s, want %s", status, got, want)
		}
	}
}
