package evs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

type snapshotEnv struct {
	svc     *Service
	handler http.Handler
	clock   *lifecycle.FakeClock
	engine  *lifecycle.Engine
	store   store.Store
}

func newSnapshotEnv(t *testing.T, vols []volume, snaps []snapshot, faults lifecycle.FaultInjector) *snapshotEnv {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	clock := lifecycle.NewFakeClock(time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC))
	engine := lifecycle.New(lifecycle.Options{Delay: 2 * time.Second, Clock: clock, Logger: log, Faults: faults})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(11)
	svc, err := New(Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}

	ten := Tenant{Region: region, ProjectID: project}
	for _, v := range vols {
		if err := svc.volumes(ten).Create(context.Background(), v.ID, v); err != nil {
			t.Fatal(err)
		}
	}
	for _, sn := range snaps {
		if err := svc.snapshots(ten).Create(context.Background(), sn.ID, sn); err != nil {
			t.Fatal(err)
		}
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: project, Logger: log, Store: st, Engine: engine,
		IDs: gen, Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &snapshotEnv{svc: svc, handler: srv.Handler(), clock: clock, engine: engine, store: st}
}

func (e *snapshotEnv) do(t *testing.T, method, path, body string) (int, map[string]any, string) {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, strings.ReplaceAll(path, "{p}", project), strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, strings.ReplaceAll(path, "{p}", project), nil)
	}
	r.Host = "evs." + region + ".myhuaweicloud.com"
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	raw := w.Body.String()
	var out map[string]any
	if raw != "" {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, raw)
		}
	}
	return w.Code, out, raw
}

func (e *snapshotEnv) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(3 * time.Second)
	if err := e.engine.WaitIdle(t.Context()); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

func TestSnapshotCreateShowUpdateDeleteSuccess(t *testing.T) {
	t.Parallel()
	vols := []volume{
		{ID: rootID, Name: "vol-avail", Status: statusAvailable, VolumeType: "GPSSD", SizeGB: 40, AvailabilityZone: "ap-southeast-1a", EnterpriseProjectID: "ep-1"},
		{ID: dataID, Name: "vol-inuse", Status: statusInUse, VolumeType: "SSD", SizeGB: 20, AvailabilityZone: "ap-southeast-1a"},
		{ID: otherID, Name: "vol-attaching", Status: statusAttaching, VolumeType: "SAS", SizeGB: 10, AvailabilityZone: "ap-southeast-1b"},
	}
	e := newSnapshotEnv(t, vols, nil, nil)

	// Create on available volume.
	code, out, _ := e.do(t, http.MethodPost, "/v2/{p}/cloudsnapshots", `{
		"snapshot": {
			"volume_id": "`+rootID+`",
			"name": "snap-1",
			"description": "first snap",
			"metadata": {"env": "prod"}
		}
	}`)
	if code != http.StatusAccepted {
		t.Fatalf("CreateSnapshot: %d %v", code, out)
	}
	sn := out["snapshot"].(map[string]any)
	snapID := sn["id"].(string)
	if sn["status"] != statusCreating ||
		sn["name"] != "snap-1" ||
		sn["description"] != "first snap" ||
		sn["volume_id"] != rootID ||
		sn["size"] != 40.0 ||
		sn["os-extended-snapshot-attributes:progress"] != "0%" ||
		sn["os-extended-snapshot-attributes:project_id"] != project ||
		sn["service_type"] != "EVS" ||
		sn["metadata"].(map[string]any)["env"] != "prod" {
		t.Fatalf("unexpected create snapshot body: %v", sn)
	}

	// Settle lifecycle and ShowSnapshot.
	e.settle(t)
	code, out, _ = e.do(t, http.MethodGet, "/v2/{p}/cloudsnapshots/"+snapID, "")
	if code != http.StatusOK {
		t.Fatalf("ShowSnapshot: %d %v", code, out)
	}
	sn = out["snapshot"].(map[string]any)
	if sn["status"] != statusAvailable || sn["os-extended-snapshot-attributes:progress"] != "100%" {
		t.Fatalf("after settle: %v", sn)
	}

	// Create on in-use and attaching (with force: true).
	for _, body := range []string{
		`{"snapshot": {"volume_id": "` + dataID + `", "name": "snap-inuse"}}`,
		`{"snapshot": {"volume_id": "` + otherID + `", "name": "snap-force", "force": true}}`,
	} {
		code, out, _ = e.do(t, http.MethodPost, "/v2/{p}/cloudsnapshots", body)
		if code != http.StatusAccepted {
			t.Fatalf("CreateSnapshot(%s): %d %v", body, code, out)
		}
	}
	e.settle(t)

	// UpdateSnapshot.
	code, out, _ = e.do(t, http.MethodPut, "/v2/{p}/cloudsnapshots/"+snapID, `{"snapshot": {"name": "snap-1-renamed", "description": "updated"}}`)
	if code != http.StatusOK {
		t.Fatalf("UpdateSnapshot: %d %v", code, out)
	}
	sn = out["snapshot"].(map[string]any)
	if sn["name"] != "snap-1-renamed" || sn["description"] != "updated" {
		t.Fatalf("after update: %v", sn)
	}

	// DeleteSnapshot: 202 empty body, then 404 on Show.
	code, _, raw := e.do(t, http.MethodDelete, "/v2/{p}/cloudsnapshots/"+snapID, "")
	if code != http.StatusAccepted || raw != "" {
		t.Fatalf("DeleteSnapshot: %d %q", code, raw)
	}
	code, out, _ = e.do(t, http.MethodGet, "/v2/{p}/cloudsnapshots/"+snapID, "")
	if code != http.StatusNotFound || out["error"].(map[string]any)["code"] != "EVS.5404" {
		t.Fatalf("Show after delete: %d %v", code, out)
	}
}

func TestSnapshotCreateAndUpdateErrors(t *testing.T) {
	t.Parallel()
	vols := []volume{
		{ID: rootID, Name: "vol-attaching", Status: statusAttaching, VolumeType: "GPSSD", SizeGB: 40, AvailabilityZone: "ap-southeast-1a"},
		{ID: dataID, Name: "vol-creating", Status: statusCreating, VolumeType: "SSD", SizeGB: 20, AvailabilityZone: "ap-southeast-1a"},
	}
	snaps := []snapshot{
		{ID: "sn-creating", Name: "s1", Status: statusCreating, VolumeID: rootID, SizeGB: 40},
		{ID: "sn-avail", Name: "s2", Status: statusAvailable, VolumeID: rootID, SizeGB: 40},
	}
	e := newSnapshotEnv(t, vols, snaps, nil)

	longName := strings.Repeat("a", 65)
	longDesc := strings.Repeat("b", 86)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
		status int
		code   string
	}{
		{"bad json", http.MethodPost, "/v2/{p}/cloudsnapshots", `{`, http.StatusBadRequest, "EVS.1070"},
		{"nil snapshot", http.MethodPost, "/v2/{p}/cloudsnapshots", `{}`, http.StatusBadRequest, "EVS.1070"},
		{"empty volume_id", http.MethodPost, "/v2/{p}/cloudsnapshots", `{"snapshot": {"name": "x"}}`, http.StatusBadRequest, "EVS.1032"},
		{"missing volume", http.MethodPost, "/v2/{p}/cloudsnapshots", `{"snapshot": {"volume_id": "missing"}}`, http.StatusNotFound, "EVS.5404"},
		{"attaching without force", http.MethodPost, "/v2/{p}/cloudsnapshots", `{"snapshot": {"volume_id": "` + rootID + `"}}`, http.StatusBadRequest, "EVS.1031"},
		{"creating volume", http.MethodPost, "/v2/{p}/cloudsnapshots", `{"snapshot": {"volume_id": "` + dataID + `", "force": true}}`, http.StatusBadRequest, "EVS.1031"},
		{"name too long", http.MethodPost, "/v2/{p}/cloudsnapshots", `{"snapshot": {"volume_id": "` + rootID + `", "force": true, "name": "` + longName + `"}}`, http.StatusBadRequest, "EVS.1003"},
		{"desc too long", http.MethodPost, "/v2/{p}/cloudsnapshots", `{"snapshot": {"volume_id": "` + rootID + `", "force": true, "description": "` + longDesc + `"}}`, http.StatusBadRequest, "EVS.1004"},
		{"show missing", http.MethodGet, "/v2/{p}/cloudsnapshots/missing", "", http.StatusNotFound, "EVS.5404"},
		{"update missing", http.MethodPut, "/v2/{p}/cloudsnapshots/missing", `{"snapshot": {"name": "x"}}`, http.StatusNotFound, "EVS.5404"},
		{"update bad json", http.MethodPut, "/v2/{p}/cloudsnapshots/sn-avail", `{`, http.StatusBadRequest, "EVS.1070"},
		{"update both empty", http.MethodPut, "/v2/{p}/cloudsnapshots/sn-avail", `{"snapshot": {}}`, http.StatusBadRequest, "EVS.1007"},
		{"update name too long", http.MethodPut, "/v2/{p}/cloudsnapshots/sn-avail", `{"snapshot": {"name": "` + longName + `"}}`, http.StatusBadRequest, "EVS.1003"},
		{"update desc too long", http.MethodPut, "/v2/{p}/cloudsnapshots/sn-avail", `{"snapshot": {"description": "` + longDesc + `"}}`, http.StatusBadRequest, "EVS.1004"},
		{"delete missing", http.MethodDelete, "/v2/{p}/cloudsnapshots/missing", "", http.StatusNotFound, "EVS.5404"},
		{"delete creating", http.MethodDelete, "/v2/{p}/cloudsnapshots/sn-creating", "", http.StatusBadRequest, "EVS.1047"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, _ := e.do(t, tc.method, tc.path, tc.body)
			errObj, _ := out["error"].(map[string]any)
			if code != tc.status || errObj["code"] != tc.code {
				t.Fatalf("got %d %v, want %d %s", code, out, tc.status, tc.code)
			}
		})
	}
}

func TestListSnapshots(t *testing.T) {
	t.Parallel()
	snaps := []snapshot{
		{ID: "sn-1", Name: "alpha", Status: statusAvailable, VolumeID: rootID, SizeGB: 40, AvailabilityZone: "ap-southeast-1a", EnterpriseProjectID: "0"},
		{ID: "sn-2", Name: "alpha-two", Status: statusError, VolumeID: rootID, SizeGB: 40, AvailabilityZone: "ap-southeast-1a", EnterpriseProjectID: "ep-1"},
		{ID: "sn-3", Name: "beta", Status: statusAvailable, VolumeID: dataID, SizeGB: 20, AvailabilityZone: "ap-southeast-1b", EnterpriseProjectID: "ep-1"},
	}
	e := newSnapshotEnv(t, nil, snaps, nil)

	ids := func(path string) ([]string, float64) {
		t.Helper()
		code, out, _ := e.do(t, http.MethodGet, path, "")
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", path, code, out)
		}
		var got []string
		for _, item := range out["snapshots"].([]any) {
			got = append(got, item.(map[string]any)["id"].(string))
		}
		return got, out["count"].(float64)
	}

	for path, want := range map[string]int{
		"/v2/{p}/cloudsnapshots/detail":                                       3,
		"/v2/{p}/cloudsnapshots/detail?id=sn-1":                               1,
		"/v2/{p}/cloudsnapshots/detail?id=sn-1&id=sn-3":                       2,
		"/v2/{p}/cloudsnapshots/detail?name=alpha":                            1, // exact match, not alpha-two
		"/v2/{p}/cloudsnapshots/detail?status=error":                          1,
		"/v2/{p}/cloudsnapshots/detail?volume_id=" + rootID:                   2,
		"/v2/{p}/cloudsnapshots/detail?availability_zone=ap-southeast-1b":     1,
		"/v2/{p}/cloudsnapshots/detail?enterprise_project_id=ep-1":            2,
		"/v2/{p}/cloudsnapshots/detail?enterprise_project_id=all_granted_eps": 3,
		"/v2/{p}/cloudsnapshots/detail?limit=2":                               2,
		"/v2/{p}/cloudsnapshots/detail?limit=2&offset=2":                      1,
		"/v2/ffffffffffffffffffffffffffffffff/cloudsnapshots/detail":          0,
	} {
		got, _ := ids(path)
		if len(got) != want {
			t.Errorf("%s: got %d (%v), want %d", path, len(got), got, want)
		}
	}

	if got, count := ids("/v2/{p}/cloudsnapshots/detail?limit=1"); len(got) != 1 || count != 3 {
		t.Errorf("limit=1: len=%d count=%v, want 1 and 3", len(got), count)
	}

	for path, wantCode := range map[string]string{
		"/v2/{p}/cloudsnapshots/detail?limit=x":    "EVS.1023",
		"/v2/{p}/cloudsnapshots/detail?limit=1001": "EVS.2142",
		"/v2/{p}/cloudsnapshots/detail?offset=-1":  "EVS.1070",
	} {
		code, out, _ := e.do(t, http.MethodGet, path, "")
		if errObj, _ := out["error"].(map[string]any); code != http.StatusBadRequest || errObj["code"] != wantCode {
			t.Errorf("%s: got %d %v, want %s", path, code, out, wantCode)
		}
	}
}

func TestRollbackSnapshotSuccessAndErrors(t *testing.T) {
	t.Parallel()
	vols := []volume{
		{ID: rootID, Name: "vol-avail", Status: statusAvailable, VolumeType: "GPSSD", SizeGB: 40, AvailabilityZone: "ap-southeast-1a"},
		{ID: dataID, Name: "vol-inuse", Status: statusInUse, VolumeType: "SSD", SizeGB: 20, AvailabilityZone: "ap-southeast-1a"},
		{ID: otherID, Name: "vol-err-rb", Status: statusErrorRollbacking, VolumeType: "SAS", SizeGB: 10, AvailabilityZone: "ap-southeast-1a"},
	}
	snaps := []snapshot{
		{ID: "sn-ok", Name: "snap-ok", Status: statusAvailable, VolumeID: rootID, SizeGB: 40},
		{ID: "sn-err-rb", Name: "snap-err-rb", Status: statusAvailable, VolumeID: otherID, SizeGB: 10},
		{ID: "sn-inuse", Name: "snap-inuse", Status: statusAvailable, VolumeID: dataID, SizeGB: 20},
		{ID: "sn-creating", Name: "snap-creating", Status: statusCreating, VolumeID: rootID, SizeGB: 40},
		{ID: "sn-autobk", Name: "autobk_snapshot_123", Status: statusAvailable, VolumeID: rootID, SizeGB: 40},
	}
	e := newSnapshotEnv(t, vols, snaps, nil)

	// Error cases.
	for _, tc := range []struct {
		name   string
		snapID string
		body   string
		status int
		code   string
	}{
		{"bad json", "sn-ok", `{`, http.StatusBadRequest, "EVS.1070"},
		{"nil rollback", "sn-ok", `{}`, http.StatusBadRequest, "EVS.1070"},
		{"empty volume_id", "sn-ok", `{"rollback": {}}`, http.StatusBadRequest, "EVS.1032"},
		{"missing snapshot", "missing", `{"rollback": {"volume_id": "` + rootID + `"}}`, http.StatusNotFound, "EVS.5404"},
		{"autobk prefix", "sn-autobk", `{"rollback": {"volume_id": "` + rootID + `"}}`, http.StatusBadRequest, "EVS.1031"},
		{"wrong volume_id", "sn-ok", `{"rollback": {"volume_id": "` + dataID + `"}}`, http.StatusBadRequest, "EVS.1032"},
		{"snapshot not available", "sn-creating", `{"rollback": {"volume_id": "` + rootID + `"}}`, http.StatusBadRequest, "EVS.2043"},
		{"volume in-use", "sn-inuse", `{"rollback": {"volume_id": "` + dataID + `"}}`, http.StatusBadRequest, "EVS.1031"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, _ := e.do(t, http.MethodPost, "/v2/{p}/cloudsnapshots/"+tc.snapID+"/rollback", tc.body)
			errObj, _ := out["error"].(map[string]any)
			if code != tc.status || errObj["code"] != tc.code {
				t.Fatalf("got %d %v, want %d %s", code, out, tc.status, tc.code)
			}
		})
	}

	// Success from available and error_rollbacking.
	for _, tc := range []struct {
		snapID string
		volID  string
	}{
		{"sn-ok", rootID},
		{"sn-err-rb", otherID},
	} {
		code, out, _ := e.do(t, http.MethodPost, "/v2/{p}/cloudsnapshots/"+tc.snapID+"/rollback", `{"rollback": {"volume_id": "`+tc.volID+`"}}`)
		if code != http.StatusAccepted {
			t.Fatalf("RollbackSnapshot(%s): %d %v", tc.snapID, code, out)
		}
		rb := out["rollback"].(map[string]any)
		if rb["volume_id"] != tc.volID {
			t.Fatalf("rollback response = %v", out)
		}
		v, err := e.svc.volumes(Tenant{Region: region, ProjectID: project}).Get(t.Context(), tc.volID)
		if err != nil || v.Status != statusRollbacking {
			t.Fatalf("during rollback: v=%+v err=%v", v, err)
		}
		e.settle(t)
		v, err = e.svc.volumes(Tenant{Region: region, ProjectID: project}).Get(t.Context(), tc.volID)
		if err != nil || v.Status != statusAvailable || v.Pending != nil {
			t.Fatalf("after rollback: v=%+v err=%v", v, err)
		}
	}
}

func TestSnapshotLifecycleFaultsAndResume(t *testing.T) {
	t.Parallel()
	ten := Tenant{Region: region, ProjectID: project}

	t.Run("create fault", func(t *testing.T) {
		t.Parallel()
		vols := []volume{{ID: rootID, Name: "vol", Status: statusAvailable, VolumeType: "GPSSD", SizeGB: 40, AvailabilityZone: "ap-southeast-1a"}}
		e := newSnapshotEnv(t, vols, nil, &faultOnce{kind: taskSnapshotCreate, err: errors.New("boom")})

		code, out, _ := e.do(t, http.MethodPost, "/v2/{p}/cloudsnapshots", `{"snapshot": {"volume_id": "`+rootID+`", "name": "s1"}}`)
		if code != http.StatusAccepted {
			t.Fatalf("CreateSnapshot: %d %v", code, out)
		}
		snapID := out["snapshot"].(map[string]any)["id"].(string)
		e.settle(t)

		sn, err := e.svc.snapshots(ten).Get(t.Context(), snapID)
		if err != nil || sn.Status != statusError {
			t.Fatalf("after fault: sn=%+v err=%v", sn, err)
		}
		// Snapshot in error status can be deleted.
		code, _, _ = e.do(t, http.MethodDelete, "/v2/{p}/cloudsnapshots/"+snapID, "")
		if code != http.StatusAccepted {
			t.Fatalf("DeleteSnapshot(error): %d", code)
		}
	})

	t.Run("rollback fault", func(t *testing.T) {
		t.Parallel()
		vols := []volume{{ID: rootID, Name: "vol", Status: statusAvailable, VolumeType: "GPSSD", SizeGB: 40, AvailabilityZone: "ap-southeast-1a"}}
		snaps := []snapshot{{ID: "sn-1", Name: "s1", Status: statusAvailable, VolumeID: rootID, SizeGB: 40}}
		e := newSnapshotEnv(t, vols, snaps, &faultOnce{kind: taskSnapshotRollback, err: errors.New("boom")})

		code, out, _ := e.do(t, http.MethodPost, "/v2/{p}/cloudsnapshots/sn-1/rollback", `{"rollback": {"volume_id": "`+rootID+`"}}`)
		if code != http.StatusAccepted {
			t.Fatalf("RollbackSnapshot: %d %v", code, out)
		}
		e.settle(t)

		v, err := e.svc.volumes(ten).Get(t.Context(), rootID)
		if err != nil || v.Status != statusErrorRollbacking || v.Pending != nil {
			t.Fatalf("after rollback fault: v=%+v err=%v", v, err)
		}
	})

	t.Run("resume creating snapshot and rollbacking volume", func(t *testing.T) {
		t.Parallel()
		vols := []volume{{
			ID: rootID, Name: "vol", Status: statusRollbacking, VolumeType: "GPSSD", SizeGB: 40,
			Pending: &pending{Op: "rollback", SnapshotID: "sn-done"},
		}}
		snaps := []snapshot{
			{ID: "sn-creating", Name: "s1", Status: statusCreating, VolumeID: rootID, SizeGB: 40},
		}
		e := newSnapshotEnv(t, vols, snaps, nil)
		if err := e.svc.Resume(t.Context()); err != nil {
			t.Fatalf("Resume: %v", err)
		}
		e.settle(t)

		v, err := e.svc.volumes(ten).Get(t.Context(), rootID)
		if err != nil || v.Status != statusAvailable || v.Pending != nil {
			t.Fatalf("resumed volume: %+v err=%v", v, err)
		}
		sn, err := e.svc.snapshots(ten).Get(t.Context(), "sn-creating")
		if err != nil || sn.Status != statusAvailable {
			t.Fatalf("resumed snapshot: %+v err=%v", sn, err)
		}
	})
}
