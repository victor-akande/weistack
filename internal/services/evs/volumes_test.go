package evs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

type stubServers struct {
	mu      sync.Mutex
	servers map[string]ServerInfo
	attach  func(ctx context.Context, t Tenant, serverID, volumeID string) error
	calls   []string
}

func (s *stubServers) ServerForVolume(_ context.Context, _ Tenant, id string) (ServerInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.servers[id]
	if !ok {
		return ServerInfo{}, ErrServerNotFound
	}
	return info, nil
}

func (s *stubServers) AttachVolume(ctx context.Context, t Tenant, serverID, volumeID string) error {
	s.mu.Lock()
	s.calls = append(s.calls, serverID+":"+volumeID)
	fn := s.attach
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, t, serverID, volumeID)
	}
	return nil
}

type faultOn struct {
	kind string
}

func (f faultOn) Fault(kind, _ string) error {
	if kind == f.kind {
		return errors.New("injected fault")
	}
	return nil
}

type testEnv struct {
	handler http.Handler
	svc     *Service
	engine  *lifecycle.Engine
	store   store.Store
}

func startEngine(t *testing.T, faults lifecycle.FaultInjector) *lifecycle.Engine {
	t.Helper()
	engine := lifecycle.New(lifecycle.Options{Faults: faults})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("engine did not stop after its context was cancelled")
		}
	})
	return engine
}

func newTestEnv(t *testing.T, faults lifecycle.FaultInjector, srvs Servers) testEnv {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })

	engine := startEngine(t, faults)

	gen := ids.NewSeeded(1)
	svc, err := New(Deps{
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		Now:    func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if srvs != nil {
		svc.SetServers(srvs)
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
	return testEnv{
		handler: srv.Handler(),
		svc:     svc,
		engine:  engine,
		store:   st,
	}
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			rdr = strings.NewReader(v)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			rdr = bytes.NewReader(b)
		}
	}
	req := httptest.NewRequest(method, strings.ReplaceAll(path, "{p}", project), rdr)
	req.Host = "evs." + region + ".myhuaweicloud.com"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, w.Body.String())
		}
	}
	return w.Code, out
}

func waitEngine(t *testing.T, e *lifecycle.Engine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

func TestCreateVolumeAndShowJob(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil, nil)

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", map[string]any{
		"volume": map[string]any{
			"name":              "data-1",
			"description":       "my disk",
			"availability_zone": "ap-southeast-1a",
			"volume_type":       "GPSSD",
			"size":              50,
			"multiattach":       true,
			"metadata": map[string]any{
				"hw:passthrough":       "true",
				"create_for_volume_id": "true",
			},
			"tags": map[string]any{
				"env": "prod",
			},
		},
	})
	if status != http.StatusAccepted {
		t.Fatalf("CreateVolume: %d %v", status, out)
	}
	jobID := out["job_id"].(string)
	volIDs := out["volume_ids"].([]any)
	if jobID == "" || len(volIDs) != 1 {
		t.Fatalf("unexpected CreateVolume response: %v", out)
	}
	volID := volIDs[0].(string)

	waitEngine(t, env.engine)

	status, volOut := get(t, env.handler, "/v2/{p}/cloudvolumes/"+volID)
	if status != http.StatusOK {
		t.Fatalf("ShowVolume: %d %v", status, volOut)
	}
	v := volOut["volume"].(map[string]any)
	if v["status"] != statusAvailable || v["name"] != "data-1" || v["description"] != "my disk" ||
		v["size"] != 50.0 || v["volume_type"] != "GPSSD" || v["multiattach"] != true ||
		v["shareable"] != "true" || v["enterprise_project_id"] != "0" {
		t.Fatalf("volume = %v", v)
	}
	meta := v["metadata"].(map[string]any)
	if meta["hw:passthrough"] != "true" || meta["create_for_volume_id"] != "true" {
		t.Fatalf("metadata = %v", meta)
	}
	tags := v["tags"].(map[string]any)
	if tags["env"] != "prod" {
		t.Fatalf("tags = %v", tags)
	}

	status, jobOut := get(t, env.handler, "/v1/{p}/jobs/"+jobID)
	if status != http.StatusOK {
		t.Fatalf("ShowJob: %d %v", status, jobOut)
	}
	if jobOut["status"] != jobStatusSuccess || jobOut["job_type"] != jobTypeCreateVolume {
		t.Fatalf("job = %v", jobOut)
	}
	ent := jobOut["entities"].(map[string]any)
	if ent["volume_id"] != volID || ent["name"] != "data-1" || ent["size"] != 50.0 || ent["volume_type"] != "GPSSD" {
		t.Fatalf("job entities = %v", ent)
	}

	// Unknown job -> 400 Common.0011 "No jobs found."
	status, errOut := get(t, env.handler, "/v1/{p}/jobs/nonexistent")
	if status != http.StatusBadRequest {
		t.Fatalf("unknown job status = %d %v", status, errOut)
	}
	errObj := errOut["error"].(map[string]any)
	if errObj["code"] != "Common.0011" || errObj["message"] != "No jobs found." {
		t.Fatalf("unknown job error = %v", errObj)
	}
}

func TestBatchCreateVolume(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil, nil)

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", map[string]any{
		"volume": map[string]any{
			"name":                  "batch",
			"availability_zone":     "ap-southeast-1b",
			"volume_type":           "SSD",
			"size":                  20,
			"count":                 3,
			"enterprise_project_id": "ep-123",
		},
	})
	if status != http.StatusAccepted {
		t.Fatalf("CreateVolume batch: %d %v", status, out)
	}
	volIDs := out["volume_ids"].([]any)
	if len(volIDs) != 3 {
		t.Fatalf("expected 3 volume_ids, got %v", volIDs)
	}
	jobID := out["job_id"].(string)

	waitEngine(t, env.engine)

	for i, rawID := range volIDs {
		_, volOut := get(t, env.handler, "/v2/{p}/cloudvolumes/"+rawID.(string))
		v := volOut["volume"].(map[string]any)
		wantName := "batch-000" + string(rune('1'+i))
		if v["name"] != wantName || v["status"] != statusAvailable || v["enterprise_project_id"] != "ep-123" {
			t.Fatalf("vol[%d] = %v", i, v)
		}
	}

	_, jobOut := get(t, env.handler, "/v1/{p}/jobs/"+jobID)
	if jobOut["status"] != jobStatusSuccess || jobOut["job_type"] != jobTypeBatchCreateVolume {
		t.Fatalf("batch job = %v", jobOut)
	}
	ent := jobOut["entities"].(map[string]any)
	subs := ent["sub_jobs"].([]any)
	if len(subs) != 3 || ent["sub_jobs_total"] != 3.0 {
		t.Fatalf("sub_jobs = %v", ent)
	}
	for _, s := range subs {
		sub := s.(map[string]any)
		if sub["status"] != jobStatusSuccess || sub["job_type"] != jobTypeCreateVolume {
			t.Fatalf("sub_job = %v", sub)
		}
	}
}

func TestCreateVolumeWithServerID(t *testing.T) {
	t.Parallel()
	srvs := &stubServers{
		servers: map[string]ServerInfo{
			"srv-ok": {AvailabilityZone: "ap-southeast-1a", Status: "ACTIVE"},
			"srv-az": {AvailabilityZone: "ap-southeast-1c", Status: "ACTIVE"},
		},
	}
	env := newTestEnv(t, nil, srvs)

	// Unknown server -> EVS.2229
	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", map[string]any{
		"server_id": "srv-missing",
		"volume": map[string]any{
			"name":              "d1",
			"availability_zone": "ap-southeast-1a",
			"volume_type":       "GPSSD",
			"size":              10,
		},
	})
	if status != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "EVS.2229" {
		t.Fatalf("missing server: %d %v", status, out)
	}

	// AZ mismatch -> EVS.2263
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", map[string]any{
		"server_id": "srv-az",
		"volume": map[string]any{
			"name":              "d1",
			"availability_zone": "ap-southeast-1a",
			"volume_type":       "GPSSD",
			"size":              10,
		},
	})
	if status != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "EVS.2263" {
		t.Fatalf("az mismatch: %d %v", status, out)
	}

	// count > 1 with server_id -> EVS.1021
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", map[string]any{
		"server_id": "srv-ok",
		"volume": map[string]any{
			"name":              "d1",
			"availability_zone": "ap-southeast-1a",
			"volume_type":       "GPSSD",
			"size":              10,
			"count":             2,
		},
	})
	if status != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "EVS.1021" {
		t.Fatalf("count > 1 with server_id: %d %v", status, out)
	}

	// Valid server_id triggers AttachVolume after create completes.
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", map[string]any{
		"server_id": "srv-ok",
		"volume": map[string]any{
			"name":              "d1",
			"availability_zone": "ap-southeast-1a",
			"volume_type":       "GPSSD",
			"size":              10,
		},
	})
	if status != http.StatusAccepted {
		t.Fatalf("create with server_id: %d %v", status, out)
	}
	volID := out["volume_ids"].([]any)[0].(string)
	waitEngine(t, env.engine)

	srvs.mu.Lock()
	calls := append([]string(nil), srvs.calls...)
	srvs.mu.Unlock()
	if len(calls) != 1 || calls[0] != "srv-ok:"+volID {
		t.Fatalf("AttachVolume calls = %v", calls)
	}

	// If AttachVolume fails, volume remains available and job still succeeds.
	srvs.mu.Lock()
	srvs.attach = func(context.Context, Tenant, string, string) error {
		return errors.New("attach failed")
	}
	srvs.mu.Unlock()
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", map[string]any{
		"server_id": "srv-ok",
		"volume": map[string]any{
			"name":              "d2",
			"availability_zone": "ap-southeast-1a",
			"volume_type":       "GPSSD",
			"size":              10,
		},
	})
	if status != http.StatusAccepted {
		t.Fatalf("create with failing attach: %d %v", status, out)
	}
	vol2ID := out["volume_ids"].([]any)[0].(string)
	job2ID := out["job_id"].(string)
	waitEngine(t, env.engine)

	_, v2 := get(t, env.handler, "/v2/{p}/cloudvolumes/"+vol2ID)
	if v2["volume"].(map[string]any)["status"] != statusAvailable {
		t.Fatalf("expected available after failed attach, got %v", v2)
	}
	_, j2 := get(t, env.handler, "/v1/{p}/jobs/"+job2ID)
	if j2["status"] != jobStatusSuccess {
		t.Fatalf("expected SUCCESS job after failed attach, got %v", j2)
	}
}

func TestCreateVolumeValidationErrors(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil, nil)

	tooManyTags := map[string]string{}
	for i := range 11 {
		tooManyTags["k"+string(rune('a'+i))] = "v"
	}

	cases := []struct {
		name string
		body any
		code string
	}{
		{name: "malformed json", body: "{", code: "EVS.1070"},
		{name: "missing volume", body: map[string]any{}, code: "EVS.1008"},
		{name: "prePaid", body: map[string]any{"bssParam": map[string]any{"chargingMode": "prePaid"}, "volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10}}, code: "EVS.2147"},
		{name: "bad az", body: map[string]any{"volume": map[string]any{"availability_zone": "bad-az", "volume_type": "GPSSD", "size": 10}}, code: "EVS.1036"},
		{name: "bad type", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "NOPE", "size": 10}}, code: "EVS.1020"},
		{name: "long name", body: map[string]any{"volume": map[string]any{"name": strings.Repeat("a", 65), "availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10}}, code: "EVS.1003"},
		{name: "long desc", body: map[string]any{"volume": map[string]any{"description": strings.Repeat("a", 86), "availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10}}, code: "EVS.1004"},
		{name: "count 0", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10, "count": 0}}, code: "EVS.1021"},
		{name: "count 101", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10, "count": 101}}, code: "EVS.1021"},
		{name: "multiple sources", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10, "imageRef": "i1", "snapshot_id": "s1"}}, code: "EVS.1016"},
		{name: "backup_id", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10, "backup_id": "b1"}}, code: "EVS.1006"},
		{name: "size too small", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 9}}, code: "EVS.1010"},
		{name: "size too large", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 32769}}, code: "EVS.1010"},
		{name: "too many tags", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10, "tags": tooManyTags}}, code: "EVS.1061"},
		{name: "bad tag key", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10, "tags": map[string]string{"bad key!": "v"}}}, code: "EVS.1062"},
		{name: "bad passthrough", body: map[string]any{"volume": map[string]any{"availability_zone": "ap-southeast-1a", "volume_type": "GPSSD", "size": 10, "metadata": map[string]string{"hw:passthrough": "yes"}}}, code: "EVS.1057"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %v", status, out)
			}
			if got := out["error"].(map[string]any)["code"]; got != tc.code {
				t.Fatalf("code = %v, want %s", got, tc.code)
			}
		})
	}
}

func TestCreateVolumeLifecycleFault(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, faultOn{kind: taskVolumeCreate}, nil)

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", map[string]any{
		"volume": map[string]any{
			"name":              "faulty",
			"availability_zone": "ap-southeast-1a",
			"volume_type":       "GPSSD",
			"size":              10,
		},
	})
	if status != http.StatusAccepted {
		t.Fatalf("CreateVolume: %d %v", status, out)
	}
	volID := out["volume_ids"].([]any)[0].(string)
	jobID := out["job_id"].(string)

	waitEngine(t, env.engine)

	_, v := get(t, env.handler, "/v2/{p}/cloudvolumes/"+volID)
	if v["volume"].(map[string]any)["status"] != statusError {
		t.Fatalf("expected error status, got %v", v)
	}
	_, j := get(t, env.handler, "/v1/{p}/jobs/"+jobID)
	if j["status"] != jobStatusFail || j["error_code"] != "EVS.2024" {
		t.Fatalf("expected FAIL/EVS.2024 job, got %v", j)
	}
}

func TestUpdateVolume(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil, nil)
	ten := Tenant{Region: region, ProjectID: project}
	if err := env.svc.volumes(ten).Create(context.Background(), rootID, volume{
		ID: rootID, Name: "old", Description: "old-desc", Status: statusAvailable,
		SizeGB: 20, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a",
	}); err != nil {
		t.Fatal(err)
	}

	status, out := doJSON(t, env.handler, http.MethodPut, "/v2/{p}/cloudvolumes/"+rootID, map[string]any{
		"volume": map[string]any{"name": "new-name", "description": "new-desc"},
	})
	if status != http.StatusOK {
		t.Fatalf("UpdateVolume: %d %v", status, out)
	}
	// Flat UpdateVolumeResponse: no "volume" wrapper.
	if _, wrapped := out["volume"]; wrapped {
		t.Fatalf("expected flat response, got wrapped: %v", out)
	}
	if out["id"] != rootID || out["name"] != "new-name" || out["description"] != "new-desc" {
		t.Fatalf("out = %v", out)
	}

	// Both absent -> EVS.1007
	status, out = doJSON(t, env.handler, http.MethodPut, "/v2/{p}/cloudvolumes/"+rootID, map[string]any{
		"volume": map[string]any{},
	})
	if status != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "EVS.1007" {
		t.Fatalf("both empty: %d %v", status, out)
	}

	// Unknown volume -> 404 EVS.5404
	status, out = doJSON(t, env.handler, http.MethodPut, "/v2/{p}/cloudvolumes/44444444-4444-4444-8444-444444444444", map[string]any{
		"volume": map[string]any{"name": "x"},
	})
	if status != http.StatusNotFound || out["error"].(map[string]any)["code"] != "EVS.5404" {
		t.Fatalf("missing volume: %d %v", status, out)
	}
}

func TestDeleteVolumeAndSnapshots(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil, nil)
	ten := Tenant{Region: region, ProjectID: project}
	ctx := context.Background()

	// Non-deletable statuses -> EVS.1046
	for _, st := range []string{statusCreating, statusInUse, statusAttaching, statusDetaching, statusExtending, statusDeleting, statusRollbacking} {
		id := "vol-" + st
		if err := env.svc.volumes(ten).Create(ctx, id, volume{ID: id, Status: st, SizeGB: 10, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a"}); err != nil {
			t.Fatal(err)
		}
		status, out := doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudvolumes/"+id, nil)
		if status != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "EVS.1046" {
			t.Fatalf("delete %s: %d %v", st, status, out)
		}
	}

	// Deletable volume with a snapshot
	if err := env.svc.volumes(ten).Create(ctx, rootID, volume{
		ID: rootID, Name: "del-me", Status: statusAvailable, SizeGB: 20, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.snapshots(ten).Create(ctx, "snap-1", snapshot{
		ID: "snap-1", Name: "s1", Status: statusAvailable, VolumeID: rootID, SizeGB: 20, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a",
	}); err != nil {
		t.Fatal(err)
	}

	status, out := doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudvolumes/"+rootID, nil)
	if status != http.StatusOK {
		t.Fatalf("DeleteVolume: %d %v", status, out)
	}
	jobID := out["job_id"].(string)
	waitEngine(t, env.engine)

	status, _ = get(t, env.handler, "/v2/{p}/cloudvolumes/"+rootID)
	if status != http.StatusNotFound {
		t.Fatalf("expected volume deleted, got %d", status)
	}
	if _, err := env.svc.snapshots(ten).Get(ctx, "snap-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected snapshot deleted with volume, got err=%v", err)
	}
	_, j := get(t, env.handler, "/v1/{p}/jobs/"+jobID)
	if j["status"] != jobStatusSuccess || j["job_type"] != jobTypeDeleteVolume {
		t.Fatalf("delete job = %v", j)
	}

	// Unknown volume -> 404 EVS.5404
	status, out = doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudvolumes/44444444-4444-4444-8444-444444444444", nil)
	if status != http.StatusNotFound || out["error"].(map[string]any)["code"] != "EVS.5404" {
		t.Fatalf("delete missing: %d %v", status, out)
	}
}

func TestDeleteVolumeLifecycleFault(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, faultOn{kind: taskVolumeDelete}, nil)
	ten := Tenant{Region: region, ProjectID: project}
	if err := env.svc.volumes(ten).Create(context.Background(), rootID, volume{
		ID: rootID, Name: "del-fault", Status: statusError, SizeGB: 20, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a",
	}); err != nil {
		t.Fatal(err)
	}

	status, out := doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudvolumes/"+rootID, nil)
	if status != http.StatusOK {
		t.Fatalf("DeleteVolume: %d %v", status, out)
	}
	jobID := out["job_id"].(string)
	waitEngine(t, env.engine)

	_, v := get(t, env.handler, "/v2/{p}/cloudvolumes/"+rootID)
	if v["volume"].(map[string]any)["status"] != statusErrorDeleting {
		t.Fatalf("expected error_deleting, got %v", v)
	}
	_, j := get(t, env.handler, "/v1/{p}/jobs/"+jobID)
	if j["status"] != jobStatusFail || j["error_code"] != "EVS.2020" {
		t.Fatalf("expected FAIL/EVS.2020, got %v", j)
	}
}

func TestListVolumesExtendedFilters(t *testing.T) {
	t.Parallel()
	vols := disks()
	vols[0].Multiattach = true
	h := newHandler(t, vols)

	countOf := func(path string) int {
		t.Helper()
		status, out := get(t, h, path)
		if status != http.StatusOK {
			t.Fatalf("%s: %d %v", path, status, out)
		}
		return int(out["count"].(float64))
	}

	if got := countOf("/v2/{p}/cloudvolumes/detail?multiattach=true"); got != 1 {
		t.Fatalf("multiattach=true: got %d, want 1", got)
	}
	if got := countOf("/v2/{p}/cloudvolumes/detail?multiattach=false"); got != 2 {
		t.Fatalf("multiattach=false: got %d, want 2", got)
	}
	// GPSSD type ID
	if got := countOf("/v2/{p}/cloudvolumes/detail?volume_type_id=fdfb39b6-1af9-44a3-b379-63d157efbb0c"); got != 1 {
		t.Fatalf("volume_type_id=GPSSD: got %d, want 1", got)
	}
	if got := countOf("/v2/{p}/cloudvolumes/detail?volume_type_id=unknown-type-id"); got != 0 {
		t.Fatalf("volume_type_id=unknown: got %d, want 0", got)
	}
	if got := countOf("/v2/{p}/cloudvolumes/detail?enterprise_project_id=ep"); got != 1 {
		t.Fatalf("enterprise_project_id=ep: got %d, want 1", got)
	}
	if got := countOf("/v2/{p}/cloudvolumes/detail?enterprise_project_id=0"); got != 2 {
		t.Fatalf("enterprise_project_id=0: got %d, want 2", got)
	}
	if got := countOf("/v2/{p}/cloudvolumes/detail?enterprise_project_id=all_granted_eps"); got != 3 {
		t.Fatalf("enterprise_project_id=all_granted_eps: got %d, want 3", got)
	}
}

func TestResumePendingOperationsBolt(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "evs.db")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ten := Tenant{Region: region, ProjectID: project}
	ctx := context.Background()

	// Seed pending operations in Bolt and close.
	st1, err := store.OpenBolt(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	e1 := lifecycle.New(lifecycle.Options{})
	svc1, err := New(Deps{Store: st1, Engine: e1, IDs: ids.NewSeeded(1), Logger: log})
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"job-c", "job-e", "job-d"} {
		if err := svc1.jobs(ten).Create(ctx, id, job{JobID: id, Status: jobStatusRunning, JobType: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	seedVols := []volume{
		{ID: "v-create", Status: statusCreating, SizeGB: 10, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a", Pending: &pending{Op: "create", JobID: "job-c"}},
		{ID: "v-extend", Status: statusExtending, SizeGB: 20, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a", Attachments: []attachment{{ID: "att-1", ServerID: "srv-1", Device: "/dev/vdb", BootIndex: -1}}, Pending: &pending{Op: "extend", JobID: "job-e", NewSize: 40}},
		{ID: "v-delete", Status: statusDeleting, SizeGB: 10, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a", Pending: &pending{Op: "delete", JobID: "job-d"}},
		{ID: "v-rollback", Status: statusRollbacking, SizeGB: 10, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a", Pending: &pending{Op: "rollback"}},
	}
	for _, v := range seedVols {
		if err := svc1.volumes(ten).Create(ctx, v.ID, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc1.snapshots(ten).Create(ctx, "sn-create", snapshot{ID: "sn-create", Status: statusCreating, VolumeID: "v-rollback", SizeGB: 10, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a"}); err != nil {
		t.Fatal(err)
	}
	if err := st1.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen Bolt and call Resume.
	st2, err := store.OpenBolt(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()

	e2 := startEngine(t, nil)

	svc2, err := New(Deps{Store: st2, Engine: e2, IDs: ids.NewSeeded(2), Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc2.Resume(ctx); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	waitEngine(t, e2)

	vCreate, err := svc2.volumes(ten).Get(ctx, "v-create")
	if err != nil || vCreate.Status != statusAvailable || vCreate.Pending != nil {
		t.Fatalf("v-create = %+v, err=%v", vCreate, err)
	}
	vExtend, err := svc2.volumes(ten).Get(ctx, "v-extend")
	if err != nil || vExtend.Status != statusInUse || vExtend.SizeGB != 40 || vExtend.Pending != nil {
		t.Fatalf("v-extend = %+v, err=%v", vExtend, err)
	}
	if _, err := svc2.volumes(ten).Get(ctx, "v-delete"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("v-delete still exists: err=%v", err)
	}
	vRollback, err := svc2.volumes(ten).Get(ctx, "v-rollback")
	if err != nil || vRollback.Status != statusAvailable || vRollback.Pending != nil {
		t.Fatalf("v-rollback = %+v, err=%v", vRollback, err)
	}
	sn, err := svc2.snapshots(ten).Get(ctx, "sn-create")
	if err != nil || sn.Status != statusAvailable {
		t.Fatalf("sn-create = %+v, err=%v", sn, err)
	}
	for _, id := range []string{"job-c", "job-e", "job-d"} {
		j, err := svc2.jobs(ten).Get(ctx, id)
		if err != nil || j.Status != jobStatusSuccess {
			t.Fatalf("job %s = %+v, err=%v", id, j, err)
		}
	}
}
