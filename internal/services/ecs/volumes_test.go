package ecs

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/victor-akande/weistack/internal/core/store"
)

type attachFault struct {
	kind string
	err  error
}

func (f *attachFault) Fault(kind, _ string) error {
	if kind == f.kind {
		return f.err
	}
	return nil
}

// seedVolume creates a standalone available volume in EVS via store.Of[map[string]any].
func (e *env) seedVolume(t *testing.T, id, az string, sizeGB int, multiattach bool) string {
	t.Helper()
	if id == "" {
		id = e.svc.ids.UUID()
	}
	col := store.Of[map[string]any](e.store, store.Scope{
		Region:    testTenant.Region,
		ProjectID: testTenant.ProjectID,
		Kind:      "evs.volume",
	})
	err := col.Create(t.Context(), id, map[string]any{
		"id":                    id,
		"name":                  "vol-" + id[:8],
		"description":           "",
		"status":                "available",
		"size":                  sizeGB,
		"volume_type":           "GPSSD",
		"availability_zone":     az,
		"bootable":              false,
		"multiattach":           multiattach,
		"enterprise_project_id": "0",
		"attachments":           []any{},
		"created_at":            "2026-11-10T09:30:00.000000",
		"updated_at":            "2026-11-10T09:30:00.000000",
	})
	if err != nil {
		t.Fatalf("seedVolume: %v", err)
	}
	return id
}

func (e *env) getEVSVolumeStatus(t *testing.T, volID string) (string, bool) {
	t.Helper()
	code, out := e.callHost(t, "evs."+testRegion+".myhuaweicloud.com", http.MethodGet, "/v2/{project}/cloudvolumes/"+volID, "")
	if code == http.StatusNotFound {
		return "", false
	}
	if code != http.StatusOK {
		t.Fatalf("getEVSVolume %s: %d %s", volID, code, out)
	}
	var resp struct {
		Volume struct {
			Status string `json:"status"`
		} `json:"volume"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Volume.Status, true
}

func TestAttachDetachUpdateBlockDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	srvID := e.mustServer(t, n)

	vol1 := e.seedVolume(t, "", "ap-southeast-1a", 50, false)
	vol2 := e.seedVolume(t, "", "ap-southeast-1a", 60, false)

	// Dry run returns 202 with empty body and keeps volume available.
	code, out := e.call(t, http.MethodPost, serversPath+"/"+srvID+"/attachvolume",
		fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q},"dry_run":true}`, vol1))
	if code != http.StatusAccepted || len(out) != 0 {
		t.Fatalf("dry_run = %d %q", code, out)
	}
	if st, ok := e.getEVSVolumeStatus(t, vol1); !ok || st != "available" {
		t.Fatalf("after dry_run status = %q, ok=%v", st, ok)
	}

	// Attach vol1 without device -> auto-picks /dev/vdb.
	code, out = e.call(t, http.MethodPost, serversPath+"/"+srvID+"/attachvolume",
		fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, vol1))
	if code != http.StatusOK {
		t.Fatalf("attach vol1 = %d %s", code, out)
	}
	job1 := decodeInto[jobResponse](t, out).JobID
	if st, _ := e.getEVSVolumeStatus(t, vol1); st != "attaching" {
		t.Fatalf("during attach status = %q, want attaching", st)
	}
	if got := e.jobStatus(t, job1); got != "attachVolume:RUNNING" {
		t.Fatalf("job1 = %s", got)
	}
	e.settle(t)
	if st, _ := e.getEVSVolumeStatus(t, vol1); st != "in-use" {
		t.Fatalf("after attach status = %q, want in-use", st)
	}
	if got := e.jobStatus(t, job1); got != "attachVolume:SUCCESS" {
		t.Fatalf("job1 after = %s", got)
	}

	// Attach vol2 with explicit device /dev/sdf.
	code, out = e.call(t, http.MethodPost, serversPath+"/"+srvID+"/attachvolume",
		fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q,"device":"/dev/sdf"}}`, vol2))
	if code != http.StatusOK {
		t.Fatalf("attach vol2 = %d %s", code, out)
	}
	e.settle(t)

	disks, err := e.volumes.DisksOf(t.Context(), testTenant.evs(), srvID)
	if err != nil || len(disks) != 3 {
		t.Fatalf("DisksOf = %+v, err=%v", disks, err)
	}
	if disks[1].VolumeID != vol1 || disks[1].Device != "/dev/vdb" || disks[1].DeleteOnTermination {
		t.Fatalf("disk[1] = %+v", disks[1])
	}
	if disks[2].VolumeID != vol2 || disks[2].Device != "/dev/sdf" || disks[2].DeleteOnTermination {
		t.Fatalf("disk[2] = %+v", disks[2])
	}

	// UpdateServerBlockDevice: set delete_on_termination = true on vol1.
	code, out = e.call(t, http.MethodPut, serversPath+"/"+srvID+"/block_device/"+vol1,
		`{"block_device":{"delete_on_termination":true}}`)
	if code != http.StatusOK || len(out) != 0 {
		t.Fatalf("update block device = %d %q", code, out)
	}
	disks, _ = e.volumes.DisksOf(t.Context(), testTenant.evs(), srvID)
	if !disks[1].DeleteOnTermination {
		t.Fatalf("delete_on_termination not updated: %+v", disks[1])
	}

	// Detach vol2 with delete_flag=1.
	code, out = e.call(t, http.MethodDelete, serversPath+"/"+srvID+"/detachvolume/"+vol2+"?delete_flag=1", "")
	if code != http.StatusOK {
		t.Fatalf("detach vol2 = %d %s", code, out)
	}
	job2 := decodeInto[jobResponse](t, out).JobID
	if st, _ := e.getEVSVolumeStatus(t, vol2); st != "detaching" {
		t.Fatalf("during detach status = %q, want detaching", st)
	}
	e.settle(t)
	if st, _ := e.getEVSVolumeStatus(t, vol2); st != "available" {
		t.Fatalf("after detach status = %q, want available", st)
	}
	if got := e.jobStatus(t, job2); got != "detachVolume:SUCCESS" {
		t.Fatalf("job2 after = %s", got)
	}
}

func TestAttachDetachUpdateErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	srvID := e.mustServer(t, n)

	availVol := e.seedVolume(t, "", "ap-southeast-1a", 20, false)
	otherAZVol := e.seedVolume(t, "", "ap-southeast-1b", 20, false)
	multiVol := e.seedVolume(t, "", "ap-southeast-1a", 20, true)

	// Attach multiVol so we can test UpdateServerBlockDevice on multiattach.
	code, _ := e.call(t, http.MethodPost, serversPath+"/"+srvID+"/attachvolume",
		fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, multiVol))
	if code != http.StatusOK {
		t.Fatalf("attach multiVol = %d", code)
	}
	e.settle(t)

	disks, _ := e.volumes.DisksOf(t.Context(), testTenant.evs(), srvID)
	rootVol := disks[0].VolumeID

	errCode := func(raw []byte) string {
		var m map[string]map[string]any
		_ = json.Unmarshal(raw, &m)
		if eObj, ok := m["error"]; ok {
			if c, ok := eObj["code"].(string); ok {
				return c
			}
		}
		return ""
	}

	cases := []struct {
		name     string
		method   string
		path     string
		body     string
		wantHTTP int
		wantCode string
	}{
		{"attach missing server", http.MethodPost, serversPath + "/missing-srv/attachvolume", fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, availVol), 404, "Ecs.0114"},
		{"attach missing volumeId", http.MethodPost, serversPath + "/" + srvID + "/attachvolume", `{"volumeAttachment":{}}`, 400, "Ecs.0005"},
		{"attach unknown volume", http.MethodPost, serversPath + "/" + srvID + "/attachvolume", `{"volumeAttachment":{"volumeId":"missing-vol"}}`, 400, "Ecs.0103"},
		{"attach already attached", http.MethodPost, serversPath + "/" + srvID + "/attachvolume", fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, multiVol), 400, "Ecs.0057"},
		{"attach other AZ", http.MethodPost, serversPath + "/" + srvID + "/attachvolume", fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, otherAZVol), 400, "Ecs.0121"},
		{"attach bad device", http.MethodPost, serversPath + "/" + srvID + "/attachvolume", fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q,"device":"/dev/vda"}}`, availVol), 400, "Ecs.0005"},
		{"attach occupied device", http.MethodPost, serversPath + "/" + srvID + "/attachvolume", fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q,"device":"/dev/vdb"}}`, availVol), 400, "Ecs.0005"},
		{"detach missing server", http.MethodDelete, serversPath + "/missing-srv/detachvolume/" + availVol, "", 404, "Ecs.0114"},
		{"detach not attached", http.MethodDelete, serversPath + "/" + srvID + "/detachvolume/" + availVol, "", 400, "Ecs.0111"},
		{"detach system disk", http.MethodDelete, serversPath + "/" + srvID + "/detachvolume/" + rootVol, "", 400, "Ecs.0005"},
		{"update missing body", http.MethodPut, serversPath + "/" + srvID + "/block_device/" + multiVol, `{}`, 400, "Ecs.0005"},
		{"update missing server", http.MethodPut, serversPath + "/missing-srv/block_device/" + multiVol, `{"block_device":{"delete_on_termination":true}}`, 404, "Ecs.0114"},
		{"update not attached", http.MethodPut, serversPath + "/" + srvID + "/block_device/" + availVol, `{"block_device":{"delete_on_termination":true}}`, 400, "Ecs.0111"},
		{"update system disk", http.MethodPut, serversPath + "/" + srvID + "/block_device/" + rootVol, `{"block_device":{"delete_on_termination":false}}`, 400, "Ecs.0005"},
		{"update multiattach", http.MethodPut, serversPath + "/" + srvID + "/block_device/" + multiVol, `{"block_device":{"delete_on_termination":true}}`, 400, "Ecs.0005"},
	}
	for _, tc := range cases {
		c, out := e.call(t, tc.method, tc.path, tc.body)
		if got := errCode(out); c != tc.wantHTTP || got != tc.wantCode {
			t.Errorf("%s: got %d %s (%s), want %d %s", tc.name, c, got, out, tc.wantHTTP, tc.wantCode)
		}
	}
}

func TestAttachDetachFaults(t *testing.T) {
	t.Parallel()
	e := newEnvFaulty(t, &attachFault{kind: taskVolumeAttach, err: errors.New("attach failed")})
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	srvID := e.mustServer(t, n)
	vol := e.seedVolume(t, "", "ap-southeast-1a", 20, false)

	code, out := e.call(t, http.MethodPost, serversPath+"/"+srvID+"/attachvolume",
		fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, vol))
	if code != http.StatusOK {
		t.Fatalf("attach = %d %s", code, out)
	}
	jobID := decodeInto[jobResponse](t, out).JobID
	e.settle(t)
	if st, _ := e.getEVSVolumeStatus(t, vol); st != "available" {
		t.Fatalf("faulted attach status = %q, want available", st)
	}
	if got := e.jobStatus(t, jobID); got != "attachVolume:FAIL" {
		t.Fatalf("faulted attach job = %s", got)
	}

	// Test detach fault in a separate faulty env.
	e2 := newEnvFaulty(t, &attachFault{kind: taskVolumeDetach, err: errors.New("detach failed")})
	n2 := e2.mustNetwork(t, testTenant, "192.168.1.0/24")
	srv2 := e2.mustServer(t, n2)
	vol2 := e2.seedVolume(t, "", "ap-southeast-1a", 20, false)

	code, out = e2.call(t, http.MethodPost, serversPath+"/"+srv2+"/attachvolume",
		fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, vol2))
	if code != http.StatusOK {
		t.Fatalf("attach2 = %d %s", code, out)
	}
	e2.settle(t)

	code, out = e2.call(t, http.MethodDelete, serversPath+"/"+srv2+"/detachvolume/"+vol2, "")
	if code != http.StatusOK {
		t.Fatalf("detach2 = %d %s", code, out)
	}
	job2 := decodeInto[jobResponse](t, out).JobID
	e2.settle(t)
	if st, _ := e2.getEVSVolumeStatus(t, vol2); st != "in-use" {
		t.Fatalf("faulted detach status = %q, want in-use", st)
	}
	if got := e2.jobStatus(t, job2); got != "detachVolume:FAIL" {
		t.Fatalf("faulted detach job = %s", got)
	}
}

func TestAttachConcurrency(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	const workers = 8
	srvs := make([]string, workers)
	for i := 0; i < workers; i++ {
		srvs[i] = e.mustServer(t, n, "name", fmt.Sprintf(`"conc-%d"`, i))
	}
	vol := e.seedVolume(t, "", "ap-southeast-1a", 20, false)

	type res struct {
		status int
		code   string
	}
	results := make([]res, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			status, out := e.call(t, http.MethodPost, serversPath+"/"+srvs[idx]+"/attachvolume",
				fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, vol))
			var m map[string]map[string]any
			_ = json.Unmarshal(out, &m)
			code, _ := m["error"]["code"].(string)
			results[idx] = res{status: status, code: code}
		}(i)
	}
	close(start)
	wg.Wait()

	okCount, conflictCount := 0, 0
	for _, r := range results {
		switch r.status {
		case http.StatusOK:
			okCount++
		case http.StatusBadRequest:
			if r.code == "Ecs.0103" {
				conflictCount++
			} else {
				t.Errorf("unexpected error code %q", r.code)
			}
		default:
			t.Errorf("unexpected status %d", r.status)
		}
	}
	if okCount != 1 || conflictCount != workers-1 {
		t.Fatalf("concurrency results: ok=%d, Ecs.0103=%d (want 1 and %d)", okCount, conflictCount, workers-1)
	}
	e.settle(t)
}

func TestServerDeleteVolumeBehavior(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	// 1. Server with 2 attached data disks: one delete_on_termination=false, one true.
	// Delete server WITHOUT delete_volume -> false survives (available), true is deleted.
	srv1 := e.mustServer(t, n, "name", `"del-no-vol"`)
	disks1, _ := e.volumes.DisksOf(t.Context(), testTenant.evs(), srv1)
	root1 := disks1[0].VolumeID
	keepVol := e.seedVolume(t, "", "ap-southeast-1a", 20, false)
	delVol := e.seedVolume(t, "", "ap-southeast-1a", 20, false)

	for _, vid := range []string{keepVol, delVol} {
		if code, out := e.call(t, http.MethodPost, serversPath+"/"+srv1+"/attachvolume",
			fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, vid)); code != http.StatusOK {
			t.Fatalf("attach %s: %d %s", vid, code, out)
		}
	}
	e.settle(t)
	if code, _ := e.call(t, http.MethodPut, serversPath+"/"+srv1+"/block_device/"+delVol,
		`{"block_device":{"delete_on_termination":true}}`); code != http.StatusOK {
		t.Fatal("update delete_on_termination failed")
	}

	if code, out := e.call(t, http.MethodPost, serversPath+"/delete",
		fmt.Sprintf(`{"servers":[{"id":%q}],"delete_volume":false}`, srv1)); code != http.StatusOK {
		t.Fatalf("delete srv1: %d %s", code, out)
	}
	e.settle(t)
	if _, ok := e.getEVSVolumeStatus(t, root1); ok {
		t.Errorf("root1 %s should have been deleted", root1)
	}
	if _, ok := e.getEVSVolumeStatus(t, delVol); ok {
		t.Errorf("delVol %s should have been deleted", delVol)
	}
	if st, ok := e.getEVSVolumeStatus(t, keepVol); !ok || st != "available" {
		t.Errorf("keepVol %s = (%q, %v), want (available, true)", keepVol, st, ok)
	}

	// 2. Server with delete_on_termination=false data disk, deleted WITH delete_volume=true -> disk deleted.
	srv2 := e.mustServer(t, n, "name", `"del-with-vol"`)
	if code, _ := e.call(t, http.MethodPost, serversPath+"/"+srv2+"/attachvolume",
		fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, keepVol)); code != http.StatusOK {
		t.Fatal("re-attach keepVol failed")
	}
	e.settle(t)
	if code, out := e.call(t, http.MethodPost, serversPath+"/delete",
		fmt.Sprintf(`{"servers":[{"id":%q}],"delete_volume":true}`, srv2)); code != http.StatusOK {
		t.Fatalf("delete srv2: %d %s", code, out)
	}
	e.settle(t)
	if _, ok := e.getEVSVolumeStatus(t, keepVol); ok {
		t.Errorf("keepVol %s should have been deleted with delete_volume=true", keepVol)
	}

	// 3. Server deleted while a volume is attaching to it -> volume returns to available
	// and the subsequent FinishAttach does nothing.
	srv3 := e.mustServer(t, n, "name", `"del-attaching"`)
	attachingVol := e.seedVolume(t, "", "ap-southeast-1a", 20, false)
	if code, out := e.call(t, http.MethodPost, serversPath+"/"+srv3+"/attachvolume",
		fmt.Sprintf(`{"volumeAttachment":{"volumeId":%q}}`, attachingVol)); code != http.StatusOK {
		t.Fatalf("attach attachingVol: %d %s", code, out)
	}
	if st, _ := e.getEVSVolumeStatus(t, attachingVol); st != "attaching" {
		t.Fatalf("expected attaching, got %q", st)
	}
	if err := e.volumes.ServerDeleted(t.Context(), testTenant.evs(), srv3, true); err != nil {
		t.Fatalf("ServerDeleted while attaching: %v", err)
	}
	if st, ok := e.getEVSVolumeStatus(t, attachingVol); !ok || st != "available" {
		t.Fatalf("attachingVol immediately after ServerDeleted = (%q, %v), want (available, true)", st, ok)
	}
	e.settle(t)
	if st, ok := e.getEVSVolumeStatus(t, attachingVol); !ok || st != "available" {
		t.Errorf("attachingVol after settle = (%q, %v), want (available, true)", st, ok)
	}
}
