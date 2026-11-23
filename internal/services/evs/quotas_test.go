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

func assertQuotaItem(t *testing.T, qs map[string]any, key string, wantInUse, wantLimit int) {
	t.Helper()
	raw, ok := qs[key]
	if !ok {
		t.Fatalf("quota_set missing key %q", key)
	}
	item, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("quota_set[%q] = %T, want object", key, raw)
	}
	if len(item) != 3 {
		t.Fatalf("quota_set[%q] = %v, want 3 fields (in_use, limit, reserved)", key, item)
	}
	if got := int(item["in_use"].(float64)); got != wantInUse {
		t.Errorf("quota_set[%q].in_use = %d, want %d", key, got, wantInUse)
	}
	if got := int(item["limit"].(float64)); got != wantLimit {
		t.Errorf("quota_set[%q].limit = %d, want %d", key, got, wantLimit)
	}
	if got := int(item["reserved"].(float64)); got != 0 {
		t.Errorf("quota_set[%q].reserved = %d, want 0", key, got)
	}
}

func TestListQuotasDefaultAndShape(t *testing.T) {
	t.Parallel()
	defaults := quota.Limits{}
	wantVolLimit := defaults.Get(quota.EVSVolumes)
	wantGBLimit := defaults.Get(quota.EVSGigabytes)
	wantSnapLimit := defaults.Get(quota.EVSSnapshots)

	env := newQuotaTestEnv(t, defaults)

	for _, path := range []string{
		"/v2/{p}/os-quota-sets/{p}?usage=True",
		"/v2/{p}/os-quota-sets/{p}",
		"/v2/{p}/os-quota-sets/{p}?usage=False",
	} {
		status, out := get(t, env.handler, path)
		if status != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 (%v)", path, status, out)
		}
		qs, ok := out["quota_set"].(map[string]any)
		if !ok {
			t.Fatalf("%s: missing quota_set in %v", path, out)
		}
		if qs["id"] != project {
			t.Errorf("%s: quota_set.id = %v, want %q", path, qs["id"], project)
		}

		assertQuotaItem(t, qs, "volumes", 0, wantVolLimit)
		assertQuotaItem(t, qs, "gigabytes", 0, wantGBLimit)
		assertQuotaItem(t, qs, "snapshots", 0, wantSnapLimit)

		for _, spec := range supportedVolumeTypes {
			assertQuotaItem(t, qs, "volumes_"+spec.Name, 0, quota.Unlimited)
			assertQuotaItem(t, qs, "gigabytes_"+spec.Name, 0, quota.Unlimited)
			assertQuotaItem(t, qs, "snapshots_"+spec.Name, 0, quota.Unlimited)
		}

		for _, omitted := range []string{"backups", "backup_gigabytes", "per_volume_gigabytes"} {
			if _, exists := qs[omitted]; exists {
				t.Errorf("%s: unexpected key %q in quota_set", path, omitted)
			}
		}
	}
}

func TestListQuotasTracksUsageAndPerType(t *testing.T) {
	t.Parallel()
	volLimit, gbLimit, snapLimit := 6, 500, 5
	env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{
		quota.EVSVolumes:   volLimit,
		quota.EVSGigabytes: gbLimit,
		quota.EVSSnapshots: snapLimit,
	}))

	createTyped := func(name, volType string, size int, extra map[string]any) string {
		t.Helper()
		vol := map[string]any{
			"name":              name,
			"availability_zone": "ap-southeast-1a",
			"volume_type":       volType,
			"size":              size,
		}
		for k, v := range extra {
			vol[k] = v
		}
		status, out := doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes", map[string]any{"volume": vol})
		if status != http.StatusAccepted {
			t.Fatalf("create %s (%s): %d %v", name, volType, status, out)
		}
		return out["volume_ids"].([]any)[0].(string)
	}

	// Seed a volume and snapshot in another project; must not count toward project.
	otherTen := Tenant{Region: region, ProjectID: "ffffffffffffffffffffffffffffffff"}
	if err := env.svc.volumes(otherTen).Create(context.Background(), "other-vol", volume{
		ID: "other-vol", Name: "other", Status: statusAvailable, SizeGB: 99, VolumeType: "SATA", AvailabilityZone: "ap-southeast-1a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.snapshots(otherTen).Create(context.Background(), "other-snap", snapshot{
		ID: "other-snap", Name: "other-sn", Status: statusAvailable, VolumeID: "other-vol", SizeGB: 99, VolumeType: "SATA", AvailabilityZone: "ap-southeast-1a",
	}); err != nil {
		t.Fatal(err)
	}

	gpssd1 := createTyped("g1", "GPSSD", 20, nil)
	ssd1 := createTyped("s1", "SSD", 30, nil)
	_ = createTyped("g2", "GPSSD2", 40, map[string]any{"iops": 3000, "throughput": 125})
	waitEngine(t, env.engine)

	status, out := get(t, env.handler, "/v2/{p}/os-quota-sets/{p}?usage=True")
	if status != http.StatusOK {
		t.Fatalf("get quotas: %d %v", status, out)
	}
	qs := out["quota_set"].(map[string]any)
	assertQuotaItem(t, qs, "volumes", 3, volLimit)
	assertQuotaItem(t, qs, "gigabytes", 90, gbLimit)
	assertQuotaItem(t, qs, "snapshots", 0, snapLimit)
	assertQuotaItem(t, qs, "volumes_GPSSD", 1, quota.Unlimited)
	assertQuotaItem(t, qs, "gigabytes_GPSSD", 20, quota.Unlimited)
	assertQuotaItem(t, qs, "volumes_SSD", 1, quota.Unlimited)
	assertQuotaItem(t, qs, "gigabytes_SSD", 30, quota.Unlimited)
	assertQuotaItem(t, qs, "volumes_GPSSD2", 1, quota.Unlimited)
	assertQuotaItem(t, qs, "gigabytes_GPSSD2", 40, quota.Unlimited)
	assertQuotaItem(t, qs, "volumes_SATA", 0, quota.Unlimited)
	assertQuotaItem(t, qs, "gigabytes_SATA", 0, quota.Unlimited)

	// Resize GPSSD volume from 20 to 50 GiB.
	status, out = doJSON(t, env.handler, http.MethodPost, "/v2.1/{p}/cloudvolumes/"+gpssd1+"/action", map[string]any{
		"os-extend": map[string]any{"new_size": 50},
	})
	if status != http.StatusAccepted {
		t.Fatalf("resize: %d %v", status, out)
	}
	waitEngine(t, env.engine)

	// Create snapshots on GPSSD and SSD volumes.
	snap1Status, snap1Out := doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", map[string]any{
		"snapshot": map[string]any{"volume_id": gpssd1, "name": "sn-gpssd"},
	})
	if snap1Status != http.StatusAccepted {
		t.Fatalf("create sn-gpssd: %d %v", snap1Status, snap1Out)
	}
	snap2Status, snap2Out := doJSON(t, env.handler, http.MethodPost, "/v2/{p}/cloudsnapshots", map[string]any{
		"snapshot": map[string]any{"volume_id": ssd1, "name": "sn-ssd"},
	})
	if snap2Status != http.StatusAccepted {
		t.Fatalf("create sn-ssd: %d %v", snap2Status, snap2Out)
	}
	snap2ID := snap2Out["snapshot"].(map[string]any)["id"].(string)
	waitEngine(t, env.engine)

	status, out = get(t, env.handler, "/v2/{p}/os-quota-sets/{p}?usage=True")
	if status != http.StatusOK {
		t.Fatalf("get quotas after resize+snaps: %d %v", status, out)
	}
	qs = out["quota_set"].(map[string]any)
	assertQuotaItem(t, qs, "volumes", 3, volLimit)
	assertQuotaItem(t, qs, "gigabytes", 120, gbLimit)
	assertQuotaItem(t, qs, "snapshots", 2, snapLimit)
	assertQuotaItem(t, qs, "gigabytes_GPSSD", 50, quota.Unlimited)
	assertQuotaItem(t, qs, "snapshots_GPSSD", 1, quota.Unlimited)
	assertQuotaItem(t, qs, "snapshots_SSD", 1, quota.Unlimited)
	assertQuotaItem(t, qs, "snapshots_GPSSD2", 0, quota.Unlimited)

	// Delete SSD snapshot; then delete GPSSD volume (which cascades its snapshot).
	status, out = doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudsnapshots/"+snap2ID, nil)
	if status != http.StatusAccepted {
		t.Fatalf("delete sn-ssd: %d %v", status, out)
	}
	status, out = doJSON(t, env.handler, http.MethodDelete, "/v2/{p}/cloudvolumes/"+gpssd1, nil)
	if status != http.StatusOK {
		t.Fatalf("delete gpssd1: %d %v", status, out)
	}
	waitEngine(t, env.engine)

	status, out = get(t, env.handler, "/v2/{p}/os-quota-sets/{p}?usage=True")
	if status != http.StatusOK {
		t.Fatalf("get quotas after deletes: %d %v", status, out)
	}
	qs = out["quota_set"].(map[string]any)
	assertQuotaItem(t, qs, "volumes", 2, volLimit)
	assertQuotaItem(t, qs, "gigabytes", 70, gbLimit)
	assertQuotaItem(t, qs, "snapshots", 0, snapLimit)
	assertQuotaItem(t, qs, "volumes_GPSSD", 0, quota.Unlimited)
	assertQuotaItem(t, qs, "gigabytes_GPSSD", 0, quota.Unlimited)
	assertQuotaItem(t, qs, "snapshots_GPSSD", 0, quota.Unlimited)
	assertQuotaItem(t, qs, "snapshots_SSD", 0, quota.Unlimited)
}

func TestListQuotasUnlimitedAndExistingOverLimit(t *testing.T) {
	t.Parallel()

	t.Run("unlimited", func(t *testing.T) {
		t.Parallel()
		env := newQuotaTestEnv(t, quota.For(map[quota.Key]int{
			quota.EVSVolumes:   quota.Unlimited,
			quota.EVSGigabytes: quota.Unlimited,
			quota.EVSSnapshots: quota.Unlimited,
		}))
		status, out := get(t, env.handler, "/v2/{p}/os-quota-sets/{p}?usage=True")
		if status != http.StatusOK {
			t.Fatalf("status = %d (%v)", status, out)
		}
		qs := out["quota_set"].(map[string]any)
		assertQuotaItem(t, qs, "volumes", 0, quota.Unlimited)
		assertQuotaItem(t, qs, "gigabytes", 0, quota.Unlimited)
		assertQuotaItem(t, qs, "snapshots", 0, quota.Unlimited)
	})

	t.Run("existing over limit", func(t *testing.T) {
		t.Parallel()
		volLimit, gbLimit, snapLimit := 2, 50, 1
		seededVols, seededSize, seededSnaps := volLimit+1, 30, snapLimit+2
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
				ID: id, Name: id, Status: statusAvailable, SizeGB: seededSize, VolumeType: "SAS", AvailabilityZone: "ap-southeast-1a",
			}); err != nil {
				t.Fatal(err)
			}
		}
		for i := range seededSnaps {
			id := fmt.Sprintf("sn-over-%d", i+1)
			if err := env.svc.snapshots(ten).Create(ctx, id, snapshot{
				ID: id, Name: id, Status: statusAvailable, VolumeID: "v-over-1", SizeGB: seededSize, VolumeType: "SAS", AvailabilityZone: "ap-southeast-1a",
			}); err != nil {
				t.Fatal(err)
			}
		}

		status, out := get(t, env.handler, "/v2/{p}/os-quota-sets/{p}?usage=True")
		if status != http.StatusOK {
			t.Fatalf("status = %d (%v)", status, out)
		}
		qs := out["quota_set"].(map[string]any)
		assertQuotaItem(t, qs, "volumes", seededVols, volLimit)
		assertQuotaItem(t, qs, "gigabytes", seededVols*seededSize, gbLimit)
		assertQuotaItem(t, qs, "snapshots", seededSnaps, snapLimit)
		assertQuotaItem(t, qs, "volumes_SAS", seededVols, quota.Unlimited)
		assertQuotaItem(t, qs, "gigabytes_SAS", seededVols*seededSize, quota.Unlimited)
		assertQuotaItem(t, qs, "snapshots_SAS", seededSnaps, quota.Unlimited)
	})
}

func TestListQuotasTargetProjectMismatch(t *testing.T) {
	t.Parallel()
	env := newQuotaTestEnv(t, quota.Limits{})

	status, out := get(t, env.handler, "/v2/{p}/os-quota-sets/ffffffffffffffffffffffffffffffff?usage=True")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (%v)", status, out)
	}
	errObj, ok := out["error"].(map[string]any)
	if !ok || errObj["code"] != "EVS.5404" {
		t.Fatalf("error = %v, want EVS.5404", out)
	}
}
