package evs

import (
	"context"
	"fmt"
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
	limit := 2
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{quota.EVSVolumes: limit}))

	var firstID string
	for i := range limit {
		status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq(fmt.Sprintf("v%d", i+1), 10, 1))
		if status != http.StatusAccepted {
			t.Fatalf("create v%d: %d %v", i+1, status, out)
		}
		if i == 0 {
			firstID = out["volume_ids"].([]any)[0].(string)
		}
	}

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v-extra", 10, 1))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")

	waitEngine(t, env.engine)
	status, out = doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudvolumes/"+firstID, nil)
	if status != http.StatusOK {
		t.Fatalf("delete v1: %d %v", status, out)
	}
	waitEngine(t, env.engine)

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v-retry", 10, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create after delete: %d %v", status, out)
	}
}

func TestVolumeBatchCountAndGigabytesQuota(t *testing.T) {
	t.Parallel()
	volLimit, gbLimit := 3, 50
	firstSize := 20
	remainingVols := volLimit - 1
	fitSize := (gbLimit - firstSize) / remainingVols
	tooBigSize := fitSize + 1
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{
		quota.EVSVolumes:   volLimit,
		quota.EVSGigabytes: gbLimit,
	}))
	ten := Tenant{Region: region, ProjectID: project}

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v1", firstSize, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create v1: %d %v", status, out)
	}

	// Batch exceeding evs.volumes; nothing is created.
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("batch-too-many", 10, remainingVols+1))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")
	if vols, err := env.svc.volumes(ten).List(context.Background(), nil); err != nil || len(vols) != 1 {
		t.Fatalf("volumes after rejected batch = %d, err=%v; want 1", len(vols), err)
	}

	// Batch exceeding evs.gigabytes; nothing is created.
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("batch-too-big", tooBigSize, remainingVols))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1042", "volume gigabytes exceeded volume gigabytes quota!")
	if vols, err := env.svc.volumes(ten).List(context.Background(), nil); err != nil || len(vols) != 1 {
		t.Fatalf("volumes after rejected batch = %d, err=%v; want 1", len(vols), err)
	}

	// Batch fitting within both limits succeeds.
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("batch-ok", fitSize, remainingVols))
	if status != http.StatusAccepted {
		t.Fatalf("create batch-ok: %d %v", status, out)
	}
}

func TestResizeVolumeGigabytesQuota(t *testing.T) {
	t.Parallel()
	gbLimit, initialSize := 50, 30
	overSize := gbLimit + 10
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{quota.EVSGigabytes: gbLimit}))

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v1", initialSize, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create v1: %d %v", status, out)
	}
	v1ID := out["volume_ids"].([]any)[0].(string)
	waitEngine(t, env.engine)

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes/"+v1ID+"/action", map[string]any{
		"os-extend": map[string]any{"new_size": overSize},
	})
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1042", "volume gigabytes exceeded volume gigabytes quota!")

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes/"+v1ID+"/action", map[string]any{
		"os-extend": map[string]any{"new_size": gbLimit},
	})
	if status != http.StatusAccepted {
		t.Fatalf("resize to %d: %d %v", gbLimit, status, out)
	}
}

func TestSnapshotQuotaAndDeleteFreesOne(t *testing.T) {
	t.Parallel()
	limit := 2
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{quota.EVSSnapshots: limit}))

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v1", 10, 1))
	if status != http.StatusAccepted {
		t.Fatalf("create v1: %d %v", status, out)
	}
	v1ID := out["volume_ids"].([]any)[0].(string)
	waitEngine(t, env.engine)

	snapBody := func(name string) map[string]any {
		return map[string]any{"snapshot": map[string]any{"volume_id": v1ID, "name": name}}
	}
	var firstID string
	for i := range limit {
		status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", snapBody(fmt.Sprintf("s%d", i+1)))
		if status != http.StatusAccepted {
			t.Fatalf("create s%d: %d %v", i+1, status, out)
		}
		if i == 0 {
			firstID = out["snapshot"].(map[string]any)["id"].(string)
		}
	}
	waitEngine(t, env.engine)

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", snapBody("s-extra"))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")

	status, out = doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudsnapshots/"+firstID, nil)
	if status != http.StatusAccepted {
		t.Fatalf("delete s1: %d %v", status, out)
	}

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", snapBody("s-retry"))
	if status != http.StatusAccepted {
		t.Fatalf("create s-retry: %d %v", status, out)
	}
}

func TestQuotaUnlimited(t *testing.T) {
	t.Parallel()
	creates := 3
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{
		quota.EVSVolumes:   quota.Unlimited,
		quota.EVSGigabytes: quota.Unlimited,
		quota.EVSSnapshots: quota.Unlimited,
	}))

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("many", 100, creates))
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
	waitEngine(t, env.engine)

	for i := range creates {
		name := fmt.Sprintf("s%d", i+1)
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
	volLimit, gbLimit, snapLimit := 2, 50, 1
	seededVols, seededSize, seededSnaps := volLimit+1, 30, snapLimit+1
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{
		quota.EVSVolumes:   volLimit,
		quota.EVSGigabytes: gbLimit,
		quota.EVSSnapshots: snapLimit,
	}))
	ten := Tenant{Region: region, ProjectID: project}
	ctx := context.Background()

	for i := range seededVols {
		id := fmt.Sprintf("v-over-%d", i+1)
		if err := env.svc.volumes(ten).Create(ctx, id, volume{
			ID: id, Name: id, Status: statusAvailable, SizeGB: seededSize, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a",
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range seededSnaps {
		id := fmt.Sprintf("sn-over-%d", i+1)
		if err := env.svc.snapshots(ten).Create(ctx, id, snapshot{
			ID: id, Name: id, Status: statusAvailable, VolumeID: "v-over-1", SizeGB: seededSize, VolumeType: "GPSSD", AvailabilityZone: "ap-southeast-1a",
		}); err != nil {
			t.Fatal(err)
		}
	}

	status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", createVolReq("v-new", 10, 1))
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes/v-over-1/action", map[string]any{
		"os-extend": map[string]any{"new_size": seededSize + 10},
	})
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1042", "volume gigabytes exceeded volume gigabytes quota!")

	status, out = doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", map[string]any{
		"snapshot": map[string]any{"volume_id": "v-over-1", "name": "sn-new"},
	})
	assertQuotaError(t, status, out, http.StatusBadRequest, "EVS.1034", "Insufficient disk or snapshot quantity quota assigned to the tenant.")

	if vols, err := env.svc.volumes(ten).List(ctx, nil); err != nil || len(vols) != seededVols {
		t.Fatalf("existing volumes = %d, err=%v; want %d", len(vols), err, seededVols)
	}
	if snaps, err := env.svc.snapshots(ten).List(ctx, nil); err != nil || len(snaps) != seededSnaps {
		t.Fatalf("existing snapshots = %d, err=%v; want %d", len(snaps), err, seededSnaps)
	}
}
