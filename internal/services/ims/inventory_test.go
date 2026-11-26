package ims

import (
	"fmt"
	"maps"
	"net/http"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
)

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.SetServers(fakeServers{
		testProject + "/" + serverID:  {ID: serverID, ImageID: ubuntuImageID},
		otherProject + "/" + serverID: {ID: serverID, ImageID: ubuntuImageID},
	})

	// Seed public images into store.Global and verify they are not reported.
	status, out := e.call(t, testProject, http.MethodGet, "/v2/cloudimages", "")
	if status != http.StatusOK {
		t.Fatalf("listing images: %d %s", status, out)
	}
	if len(decodeInto[listImagesResponse](t, out).Images) == 0 {
		t.Fatal("expected seeded public images")
	}
	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect before private images: %v", err)
	}
	if len(snap.Resources) != 0 {
		t.Fatalf("public images reported: %+v", snap.Resources)
	}

	const epID = "0aad99bc-f5f6-4f78-8404-c598d76b0ed2"
	status, out = e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", fmt.Sprintf(
		`{"name": "app-base", "instance_id": %q, "enterprise_project_id": %q, "tags": ["env=prod", "role=web=v1", "bare"]}`,
		serverID, epID))
	if status != http.StatusOK {
		t.Fatalf("creating image: %d %s", status, out)
	}
	jobID := decodeInto[createImageResponse](t, out).JobID
	status, out = e.call(t, testProject, http.MethodGet, "/v1/"+testProject+"/jobs/"+jobID, "")
	if status != http.StatusOK {
		t.Fatalf("getting job: %d %s", status, out)
	}
	activeID := decodeInto[Job](t, out).Entities.ImageID
	e.settle(t)
	e.settle(t)
	status, out = e.call(t, testProject, http.MethodGet, "/v2/images/"+activeID, "")
	if status != http.StatusOK {
		t.Fatalf("getting active image: %d %s", status, out)
	}
	active := decodeInto[Image](t, out)

	// A private image in a second project, still saving.
	status, out = e.call(t, otherProject, http.MethodPost, "/v2/cloudimages/action",
		fmt.Sprintf(`{"name": "in-flight", "instance_id": %q}`, serverID))
	if status != http.StatusOK {
		t.Fatalf("creating second image: %d %s", status, out)
	}
	otherJobID := decodeInto[createImageResponse](t, out).JobID
	status, out = e.call(t, otherProject, http.MethodGet, "/v1/"+otherProject+"/jobs/"+otherJobID, "")
	if status != http.StatusOK {
		t.Fatalf("getting second job: %d %s", status, out)
	}
	savingID := decodeInto[Job](t, out).Entities.ImageID
	e.settle(t)
	status, out = e.call(t, otherProject, http.MethodGet, "/v2/images/"+savingID, "")
	if status != http.StatusOK {
		t.Fatalf("getting saving image: %d %s", status, out)
	}
	saving := decodeInto[Image](t, out)
	if saving.Status != StatusSaving {
		t.Fatalf("status = %q, want %q", saving.Status, StatusSaving)
	}

	snap, err = inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
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

	wantTags := map[string]string{"env": "prod", "role": "web=v1", "bare": ""}
	img := at(inventory.IMSImages, testProject, active.ID)
	if img.Name != "app-base" || img.RegionID != testRegion || img.ProjectID != testProject || img.AccountID != "" ||
		img.EnterpriseProjectID != epID || img.State != inventory.Succeeded ||
		img.Created.IsZero() || !img.Created.Equal(time.Time(active.CreatedAt)) ||
		!img.Updated.Equal(time.Time(active.UpdatedAt)) || !maps.Equal(img.Tags, wantTags) || len(img.Relations) != 0 {
		t.Errorf("active image = %+v", img)
	}

	p := at(inventory.IMSImages, otherProject, saving.ID)
	if p.Name != "in-flight" || p.RegionID != testRegion || p.ProjectID != otherProject || p.AccountID != "" ||
		p.EnterpriseProjectID != inventory.DefaultEnterpriseProject || p.State != inventory.Processing ||
		p.Created.IsZero() || !p.Created.Equal(time.Time(saving.CreatedAt)) ||
		!p.Updated.Equal(time.Time(saving.UpdatedAt)) || len(p.Tags) != 0 || len(p.Relations) != 0 {
		t.Errorf("saving image = %+v, want Processing", p)
	}

	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.IMSImages: 2,
	}
	if !maps.Equal(count, want) {
		t.Errorf("reported %v, want %v", count, want)
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	for status, want := range map[string]inventory.State{
		StatusQueued: inventory.Processing,
		StatusSaving: inventory.Processing,
		StatusActive: inventory.Succeeded,
		StatusKilled: inventory.Failed,
	} {
		if got := imageState(status); got != want {
			t.Errorf("imageState(%s) = %s, want %s", status, got, want)
		}
	}
}
