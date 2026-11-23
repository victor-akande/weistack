package evs

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

func newQuotaTestEnv(t *testing.T, quotas quota.Limits) testEnv {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })

	engine := startEngine(t, nil)
	gen := ids.NewSeeded(1)
	svc, err := New(Deps{
		Quotas: quotas,
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		Now:    func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
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

func assertQuotaError(t *testing.T, status int, out map[string]any, wantStatus int, wantCode, wantMsg string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d; body = %v", status, wantStatus, out)
	}
	errObj, ok := out["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error object in %v", out)
	}
	if errObj["code"] != wantCode || errObj["message"] != wantMsg {
		t.Fatalf("error = %v, want code=%q message=%q", errObj, wantCode, wantMsg)
	}
}

func createVolReq(name string, size, count int) map[string]any {
	vol := map[string]any{
		"name":              name,
		"availability_zone": "ap-southeast-1a",
		"volume_type":       "GPSSD",
		"size":              size,
	}
	if count > 0 {
		vol["count"] = count
	}
	return map[string]any{"volume": vol}
}

func TestVolumeCountQuotaAndDeleteFreesOne(t *testing.T) {
	t.Parallel()
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{quota.EVSVolumes: 2}))

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v1", 10, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create v1: %d %v", status, out)
	}
	v1ID := out["volume_ids"].([]any)[0].(string)

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v2", 10, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create v2: %d %v", status, out)
	}

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v3", 10, 1))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")

	waitEngine(t, env.engine)
	status, out = doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudvolumes/"+v1ID, nil)
	if status != http.StatusOK {
		t.Fatalf("delete v1: %d %v", status, out)
	}
	waitEngine(t, env.engine)

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v3-retry", 10, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create after delete: %d %v", status, out)
	}
}

func TestVolumeBatchCountAndGigabytesQuota(t *testing.T) {
	t.Parallel()
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{
		quota.EVSVolumes:   3,
		quota.EVSGigabytes: 50,
	}))
	ten := Tenant{Region: region, ProjectID: project}

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v1", 20, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create v1: %d %v", status, out)
	}

	// Batch of 3 would exceed evs.volumes (1+3 > 3); nothing is created.
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("batch-too-many", 10, 3))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")
	if vols, err := env.svc.volumes(ten).List(context.Background(), nil); err != nil || len(vols) != 1 {
		t.Fatalf("volumes after rejected batch = %d, err=%v; want 1", len(vols), err)
	}

	// Batch of 2 * 20 GiB would exceed evs.gigabytes (20+40 > 50); nothing is created.
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("batch-too-big", 20, 2))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1042", "volume gigabytes exceeded volume gigabytes quota!")
	if vols, err := env.svc.volumes(ten).List(context.Background(), nil); err != nil || len(vols) != 1 {
		t.Fatalf("volumes after rejected batch = %d, err=%v; want 1", len(vols), err)
	}

	// Batch of 2 * 15 GiB fits exactly (3 vols, 50 GiB).
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("batch-ok", 15, 2))
	if status != http.StatusAccepted {
		t.Fatalf("create batch-ok: %d %v", status, out)
	}
}

func TestResizeVolumeGigabytesQuota(t *testing.T) {
	t.Parallel()
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{quota.EVSGigabytes: 50}))

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v1", 30, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create v1: %d %v", status, out)
	}
	v1ID := out["volume_ids"].([]any)[0].(string)
	waitEngine(t, env.engine)

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes/"+v1ID+"/action", map[string]any{
		"os-extend": map[string]any{"new_size": 60},
	})
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1042", "volume gigabytes exceeded volume gigabytes quota!")

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes/"+v1ID+"/action", map[string]any{
		"os-extend": map[string]any{"new_size": 50},
	})
	if status != http.StatusAccepted {
		t.Fatalf("resize to 50: %d %v", status, out)
	}
}

func TestSnapshotQuotaAndDeleteFreesOne(t *testing.T) {
	t.Parallel()
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{quota.EVSSnapshots: 2}))

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v1", 10, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create v1: %d %v", status, out)
	}
	v1ID := out["volume_ids"].([]any)[0].(string)
	waitEngine(t, env.engine)

	snapBody := func(name string) map[string]any {
		return map[string]any{"snapshot": map[string]any{"volume_id": v1ID, "name": name}}
	}
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", snapBody("s1"))
	if status != http.StatusAccepted {
		t.Fatalf("create s1: %d %v", status, out)
	}
	s1ID := out["snapshot"].(map[string]any)["id"].(string)

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", snapBody("s2"))
	if status != http.StatusAccepted {
		t.Fatalf("create s2: %d %v", status, out)
	}
	waitEngine(t, env.engine)

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", snapBody("s3"))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")

	status, out = doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudsnapshots/"+s1ID, nil)
	if status != http.StatusAccepted {
		t.Fatalf("delete s1: %d %v", status, out)
	}

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", snapBody("s3-retry"))
	if status != http.StatusAccepted {
		t.Fatalf("create s3-retry: %d %v", status, out)
	}
}

func TestQuotaUnlimited(t *testing.T) {
	t.Parallel()
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{
		quota.EVSVolumes:   quota.Unlimited,
		quota.EVSGigabytes: quota.Unlimited,
		quota.EVSSnapshots: quota.Unlimited,
	}))

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("many", 100, 3))
	if status != http.StatusAccepted {
		t.Fatalf("create unlimited: %d %v", status, out)
	}
	v1ID := out["volume_ids"].([]any)[0].(string)
	waitEngine(t, env.engine)

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes/"+v1ID+"/action", map[string]any{
		"os-extend": map[string]any{"new_size": 200},
	})
	if status != http.StatusAccepted {
		t.Fatalf("resize unlimited: %d %v", status, out)
	}

	for _, name := range []string{"s1", "s2", "s3"} {
		status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", map[string]any{
			"snapshot": map[string]any{"volume_id": v1ID, "name": name},
		})
		if status != http.StatusAccepted {
			t.Fatalf("snapshot %s unlimited: %d %v", name, status, out)
		}
	}
}

func TestQuotaExistingDataOverLimit(t *testing.T) {
	t.Parallel()
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{
		quota.EVSVolumes:   2,
		quota.EVSGigabytes: 50,
		quota.EVSSnapshots: 1,
	}))
	ten := Tenant{Region: region, ProjectID: project}
	ctx := context.Background()

	for _, id := range []string{"v-over-1", "v-over-2", "v-over-3"} {
		if err := env.svc.volumes(ten).Create(ctx, id, volume{
			ID: id, Name: id, Status: statusAvailable, SizeGB: 30, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a",
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"sn-over-1", "sn-over-2"} {
		if err := env.svc.snapshots(ten).Create(ctx, id, snapshot{
			ID: id, Name: id, Status: statusAvailable, VolumeID: "v-over-1", SizeGB: 30, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a",
		}); err != nil {
			t.Fatal(err)
		}
	}

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v-new", 10, 1))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes/v-over-1/action", map[string]any{
		"os-extend": map[string]any{"new_size": 40},
	})
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1042", "volume gigabytes exceeded volume gigabytes quota!")

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", map[string]any{
		"snapshot": map[string]any{"volume_id": "v-over-1", "name": "sn-new"},
	})
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")

	if vols, err := env.svc.volumes(ten).List(ctx, nil); err != nil || len(vols) != 3 {
		t.Fatalf("existing volumes = %d, err=%v; want 3", len(vols), err)
	}
	if snaps, err := env.svc.snapshots(ten).List(ctx, nil); err != nil || len(snaps) != 2 {
		t.Fatalf("existing snapshots = %d, err=%v; want 2", len(snaps), err)
	}
}
