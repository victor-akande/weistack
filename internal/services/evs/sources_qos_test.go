package evs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/cmk"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/ims"
)

type fakeKeys struct {
	checkFn func(ctx context.Context, region, projectID, keyID, service string) (string, error)
}

func (f *fakeKeys) NewDataKey(context.Context, string, string, string) (cmk.DataKey, error) {
	return cmk.DataKey{}, nil
}

func (f *fakeKeys) OpenDataKey(context.Context, string, []byte) ([]byte, error) {
	return nil, nil
}

func (f *fakeKeys) Check(ctx context.Context, region, projectID, keyID, service string) (string, error) {
	return f.checkFn(ctx, region, projectID, keyID, service)
}

func newTestServiceWithDeps(t *testing.T, keys cmk.Keys) (*Service, store.Store, *ims.Service) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	engine := lifecycle.New(lifecycle.Options{})
	gen := ids.NewSeeded(1)

	imsSvc, err := ims.New(ims.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, DefaultProjectID: project})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Deps{
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		Images: imsSvc,
		Keys:   keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, imsSvc
}

func assertAPIError(t *testing.T, err error, wantStatus int, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got nil error, want %d %s", wantStatus, wantCode)
	}
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("got %T (%v), want *apierr.Error", err, err)
	}
	if ae.Status != wantStatus || ae.Code != wantCode {
		t.Fatalf("got (%d, %s, %q), want (%d, %s)", ae.Status, ae.Code, ae.Message, wantStatus, wantCode)
	}
}

func TestValidateCreateSource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ten := Tenant{Region: region, ProjectID: project}
	svc, st, imsSvc := newTestServiceWithDeps(t, nil)

	// Pick a seeded active public image from IMS.
	imgs, err := imsSvc.ListImages(ctx, ims.Tenant{Region: region, ProjectID: project}, ims.ListImagesFilter{Status: ims.StatusActive})
	if err != nil || len(imgs) == 0 {
		t.Fatalf("ListImages: %v (len=%d)", err, len(imgs))
	}
	activeImg := imgs[0]

	// Seed a non-active private image in the store.
	inactiveImgID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	imgCol := store.Of[ims.Image](st, store.Scope{Region: region, ProjectID: project, Kind: "ims.image"})
	if err := imgCol.Create(ctx, inactiveImgID, ims.Image{
		ID:      inactiveImgID,
		Name:    "queued-img",
		Status:  ims.StatusQueued,
		MinDisk: 40,
	}); err != nil {
		t.Fatal(err)
	}

	// Seed source volume + snapshots (available, creating, with KMSKeyID).
	srcVolID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if err := svc.volumes(ten).Create(ctx, srcVolID, volume{
		ID:               srcVolID,
		Name:             "src-vol",
		Status:           statusAvailable,
		SizeGB:           50,
		VolumeType:       "GPSSD",
		AvailabilityZone: "ap-southeast-1a",
		KMSKeyID:         "kms-key-from-vol",
	}); err != nil {
		t.Fatal(err)
	}
	availSnapID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	if err := svc.snapshots(ten).Create(ctx, availSnapID, snapshot{
		ID:               availSnapID,
		Name:             "snap-ok",
		Status:           statusAvailable,
		VolumeID:         srcVolID,
		SizeGB:           50,
		VolumeType:       "GPSSD",
		AvailabilityZone: "ap-southeast-1a",
	}); err != nil {
		t.Fatal(err)
	}
	creatingSnapID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if err := svc.snapshots(ten).Create(ctx, creatingSnapID, snapshot{
		ID:               creatingSnapID,
		Name:             "snap-creating",
		Status:           statusCreating,
		VolumeID:         srcVolID,
		SizeGB:           50,
		VolumeType:       "GPSSD",
		AvailabilityZone: "ap-southeast-1a",
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("empty disk valid and bounds", func(t *testing.T) {
		res, err := svc.validateCreateSource(ctx, ten, createSourceParams{
			AvailabilityZone: "ap-southeast-1a",
			VolumeType:       "GPSSD",
			SizeGB:           10,
		})
		if err != nil {
			t.Fatalf("min empty size: %v", err)
		}
		if res.Bootable || res.ImageID != "" || res.SnapshotID != "" || res.KMSKeyID != "" {
			t.Fatalf("unexpected result: %+v", res)
		}
		if _, err := svc.validateCreateSource(ctx, ten, createSourceParams{
			AvailabilityZone: "ap-southeast-1a",
			VolumeType:       "GPSSD",
			SizeGB:           32768,
		}); err != nil {
			t.Fatalf("max empty size: %v", err)
		}
		for _, badSize := range []int{0, 9, 32769} {
			_, err := svc.validateCreateSource(ctx, ten, createSourceParams{
				AvailabilityZone: "ap-southeast-1a",
				VolumeType:       "GPSSD",
				SizeGB:           badSize,
			})
			assertAPIError(t, err, http.StatusBadRequest, "EVS.1010")
		}
	})

	t.Run("multiple sources and backup_id", func(t *testing.T) {
		_, err := svc.validateCreateSource(ctx, ten, createSourceParams{
			ImageRef:   activeImg.ID,
			SnapshotID: availSnapID,
			SizeGB:     100,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.1016")

		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			ImageRef: activeImg.ID,
			BackupID: "bkp-1",
			SizeGB:   100,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.1016")

		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			BackupID: "bkp-1",
			SizeGB:   100,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.1006")
	})

	t.Run("imageRef", func(t *testing.T) {
		res, err := svc.validateCreateSource(ctx, ten, createSourceParams{
			ImageRef:         activeImg.ID,
			AvailabilityZone: "ap-southeast-1a",
			VolumeType:       "GPSSD",
			SizeGB:           max(activeImg.MinDisk, 40),
		})
		if err != nil {
			t.Fatalf("valid imageRef: %v", err)
		}
		if !res.Bootable || res.ImageID != activeImg.ID || res.ImageName != activeImg.Name {
			t.Fatalf("unexpected image result: %+v", res)
		}

		// Missing image
		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			ImageRef: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
			SizeGB:   40,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2046")

		// Non-active image
		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			ImageRef: inactiveImgID,
			SizeGB:   40,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2046")

		// Size below min_disk or above 1024
		if activeImg.MinDisk > 1 {
			_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
				ImageRef: activeImg.ID,
				SizeGB:   activeImg.MinDisk - 1,
			})
			assertAPIError(t, err, http.StatusBadRequest, "EVS.1010")
		}
		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			ImageRef: activeImg.ID,
			SizeGB:   1025,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.1010")
	})

	t.Run("snapshot_id", func(t *testing.T) {
		res, err := svc.validateCreateSource(ctx, ten, createSourceParams{
			SnapshotID:       availSnapID,
			AvailabilityZone: "ap-southeast-1a",
			VolumeType:       "GPSSD",
			SizeGB:           50,
		})
		if err != nil {
			t.Fatalf("valid snapshot_id: %v", err)
		}
		if res.SnapshotID != availSnapID || res.KMSKeyID != "kms-key-from-vol" {
			t.Fatalf("unexpected snapshot result: %+v", res)
		}

		// Missing snapshot
		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			SnapshotID:       "ffffffff-ffff-4fff-8fff-ffffffffffff",
			AvailabilityZone: "ap-southeast-1a",
			VolumeType:       "GPSSD",
			SizeGB:           50,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2045")

		// Snapshot not available
		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			SnapshotID:       creatingSnapID,
			AvailabilityZone: "ap-southeast-1a",
			VolumeType:       "GPSSD",
			SizeGB:           50,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2043")

		// AZ mismatch
		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			SnapshotID:       availSnapID,
			AvailabilityZone: "ap-southeast-1b",
			VolumeType:       "GPSSD",
			SizeGB:           50,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2054")

		// Volume type mismatch
		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			SnapshotID:       availSnapID,
			AvailabilityZone: "ap-southeast-1a",
			VolumeType:       "SSD",
			SizeGB:           50,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2096")

		// Size smaller than snapshot
		_, err = svc.validateCreateSource(ctx, ten, createSourceParams{
			SnapshotID:       availSnapID,
			AvailabilityZone: "ap-southeast-1a",
			VolumeType:       "GPSSD",
			SizeGB:           49,
		})
		assertAPIError(t, err, http.StatusBadRequest, "EVS.1010")
	})
}

func TestValidateCreateQoS(t *testing.T) {
	t.Parallel()
	intPtr := func(v int) *int { return &v }

	tests := []struct {
		name       string
		volType    string
		iops       *int
		throughput *int
		wantIOPS   int
		wantTP     int
		wantCode   string
	}{
		{name: "GPSSD2 valid", volType: "GPSSD2", iops: intPtr(3000), throughput: intPtr(125), wantIOPS: 3000, wantTP: 125},
		{name: "GPSSD2 missing iops", volType: "GPSSD2", throughput: intPtr(125), wantCode: "EVS.2233"},
		{name: "GPSSD2 missing throughput", volType: "GPSSD2", iops: intPtr(3000), wantCode: "EVS.2233"},
		{name: "GPSSD2 iops < 1", volType: "GPSSD2", iops: intPtr(0), throughput: intPtr(125), wantCode: "EVS.2231"},
		{name: "GPSSD2 throughput < 1", volType: "GPSSD2", iops: intPtr(3000), throughput: intPtr(0), wantCode: "EVS.2231"},
		{name: "ESSD2 valid", volType: "ESSD2", iops: intPtr(5000), wantIOPS: 5000},
		{name: "ESSD2 missing iops", volType: "ESSD2", wantCode: "EVS.2232"},
		{name: "ESSD2 with throughput", volType: "ESSD2", iops: intPtr(5000), throughput: intPtr(100), wantCode: "EVS.2232"},
		{name: "ESSD2 iops < 1", volType: "ESSD2", iops: intPtr(-1), wantCode: "EVS.2231"},
		{name: "GPSSD valid without qos", volType: "GPSSD"},
		{name: "GPSSD with iops", volType: "GPSSD", iops: intPtr(1000), wantCode: "EVS.2235"},
		{name: "SSD with throughput", volType: "SSD", throughput: intPtr(100), wantCode: "EVS.2235"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := validateCreateQoS(tc.volType, tc.iops, tc.throughput)
			if tc.wantCode != "" {
				assertAPIError(t, err, http.StatusBadRequest, tc.wantCode)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.IOPS != tc.wantIOPS || got.Throughput != tc.wantTP {
				t.Fatalf("got %+v, want IOPS=%d TP=%d", got, tc.wantIOPS, tc.wantTP)
			}
		})
	}
}

func TestValidateCreateMetadata(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ten := Tenant{Region: region, ProjectID: project}

	keys := &fakeKeys{
		checkFn: func(_ context.Context, reg, proj, keyID, svcName string) (string, error) {
			if reg != region || proj != project || svcName != "evs" {
				t.Fatalf("unexpected Check args: %s %s %s", reg, proj, svcName)
			}
			switch keyID {
			case "":
				return "default-evs-key", nil
			case "enabled-key":
				return "enabled-key", nil
			case "disabled-key":
				return "", cmk.ErrDisabled
			default:
				return "", cmk.ErrNotFound
			}
		},
	}
	svc, _, _ := newTestServiceWithDeps(t, keys)

	t.Run("valid encrypted default key and caller metadata", func(t *testing.T) {
		res, err := svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__encrypted":  "1",
			"hw:passthrough":       "true",
			"create_for_volume_id": "vol-123",
		}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.KMSKeyID != "default-evs-key" || !res.Passthrough {
			t.Fatalf("unexpected result: %+v", res)
		}
		if len(res.Metadata) != 1 || res.Metadata["create_for_volume_id"] != "vol-123" {
			t.Fatalf("caller metadata = %v", res.Metadata)
		}
	})

	t.Run("valid encrypted explicit key and unencrypted", func(t *testing.T) {
		res, err := svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__encrypted": "1",
			"__system__cmkid":     "enabled-key",
		}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.KMSKeyID != "enabled-key" || res.Passthrough || res.Metadata != nil {
			t.Fatalf("unexpected result: %+v", res)
		}

		res, err = svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__encrypted": "0",
			"hw:passthrough":      "false",
		}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.KMSKeyID != "" || res.Passthrough {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("invalid encryption params", func(t *testing.T) {
		_, err := svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__encrypted": "yes",
		}, false)
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2041")

		_, err = svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__cmkid": "enabled-key",
		}, false)
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2041")

		_, err = svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__encrypted": "0",
			"__system__cmkid":     "enabled-key",
		}, false)
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2041")
	})

	t.Run("kms key not found or disabled or nil keys", func(t *testing.T) {
		_, err := svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__encrypted": "1",
			"__system__cmkid":     "missing-key",
		}, false)
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2040")

		_, err = svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__encrypted": "1",
			"__system__cmkid":     "disabled-key",
		}, false)
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2040")

		noKMSSvc, _, _ := newTestServiceWithDeps(t, nil)
		_, err = noKMSSvc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__encrypted": "1",
		}, false)
		assertAPIError(t, err, http.StatusBadRequest, "EVS.2040")
	})

	t.Run("encryption with image or snapshot", func(t *testing.T) {
		_, err := svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__encrypted": "1",
		}, true)
		assertAPIError(t, err, http.StatusBadRequest, "EVS.1043")

		_, err = svc.validateCreateMetadata(ctx, ten, map[string]string{
			"__system__cmkid": "enabled-key",
		}, true)
		assertAPIError(t, err, http.StatusBadRequest, "EVS.1043")
	})

	t.Run("invalid hw:passthrough", func(t *testing.T) {
		_, err := svc.validateCreateMetadata(ctx, ten, map[string]string{
			"hw:passthrough": "yes",
		}, false)
		assertAPIError(t, err, http.StatusBadRequest, "EVS.1057")
	})
}
