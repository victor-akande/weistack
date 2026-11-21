package evs

import (
	"context"
	"errors"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/cmk"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/ims"
)

const (
	minEmptyVolumeGB   = 10
	maxEmptyVolumeGB   = 32768
	maxImageVolumeGB   = 1024
	volumeTypeGPSSD2   = "GPSSD2"
	volumeTypeESSD2    = "ESSD2"
	metaEncryptedKey   = "__system__encrypted"
	metaCMKIDKey       = "__system__cmkid"
	metaPassthroughKey = "hw:passthrough"
)

var (
	errInvalidImageRef     = apierr.New(http.StatusBadRequest, "EVS.2046", "invalid imageRef!")
	errInvalidSnapshotID   = apierr.New(http.StatusBadRequest, "EVS.2045", "invalid snapshot_id!")
	errSnapshotUnavailable = apierr.New(http.StatusBadRequest, "EVS.2043", "The status of snapshot is not available or backing-up.")
	errSnapshotAZMismatch  = apierr.New(http.StatusBadRequest, "EVS.2054", "Cannot create volume from snapshot as the az is invalid!")

	errGPSSD2QoSRequired   = apierr.New(http.StatusBadRequest, "EVS.2233", "GPSSD2 type must input iops and throughput.")
	errESSD2QoSInvalid     = apierr.New(http.StatusBadRequest, "EVS.2232", "ESSD2 type must input iops and not input throughput.")
	errQoSNotSupported     = apierr.New(http.StatusBadRequest, "EVS.2235", "only ESSD2 and GPSSD2 can set iops or throughput")
	errInvalidQoSValue     = apierr.New(http.StatusBadRequest, "EVS.2231", "invalid iops value, iops must between [1, 128000] invalid throughput value, throughput must between [1, 1000]")
	errInvalidEncryptParam = apierr.New(http.StatusBadRequest, "EVS.2041", "The encrypt Param is invalid!")
	errKeyNotEnabled       = apierr.New(http.StatusBadRequest, "EVS.2040", "The status of encrypt Key is not enable!")
	errEncryptWithSource   = apierr.New(http.StatusBadRequest, "EVS.1043", "encrypt and cmk and passthrougth in metadata is not support when create volume from snapshot or image!")
)

func errSnapshotTypeMismatch(volType, snapType string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "EVS.2096", "Target volumeType[%s] is not matched with snapshot[%s] !", volType, snapType)
}

type createSourceParams struct {
	ImageRef         string
	SnapshotID       string
	BackupID         string
	AvailabilityZone string
	VolumeType       string
	SizeGB           int
}

type createSourceResult struct {
	Bootable   bool
	ImageID    string
	ImageName  string
	SnapshotID string
	KMSKeyID   string
}

type createQoSResult struct {
	IOPS       int
	Throughput int
}

type createMetadataResult struct {
	KMSKeyID    string
	Passthrough bool
	Metadata    map[string]string
}

// validateCreateSource validates the optional source (imageRef, snapshot_id,
// or backup_id) and disk size bounds for CreateVolume.
func (s *Service) validateCreateSource(ctx context.Context, t Tenant, p createSourceParams) (createSourceResult, error) {
	sources := 0
	if p.ImageRef != "" {
		sources++
	}
	if p.SnapshotID != "" {
		sources++
	}
	if p.BackupID != "" {
		sources++
	}
	if sources > 1 {
		return createSourceResult{}, errMultipleSources
	}
	if p.BackupID != "" {
		return createSourceResult{}, errInvalidBackupID
	}

	if p.ImageRef != "" {
		if s.images == nil {
			return createSourceResult{}, errInvalidImageRef
		}
		img, err := s.images.GetImage(ctx, ims.Tenant{Region: t.Region, ProjectID: t.ProjectID}, p.ImageRef)
		if err != nil {
			var ae *apierr.Error
			if errors.As(err, &ae) {
				return createSourceResult{}, errInvalidImageRef
			}
			return createSourceResult{}, err
		}
		if img.Status != ims.StatusActive {
			return createSourceResult{}, errInvalidImageRef
		}
		if p.SizeGB < 1 || p.SizeGB < img.MinDisk || p.SizeGB > maxImageVolumeGB {
			return createSourceResult{}, errInvalidVolumeSize
		}
		return createSourceResult{
			Bootable:  true,
			ImageID:   img.ID,
			ImageName: img.Name,
		}, nil
	}

	if p.SnapshotID != "" {
		snap, err := s.snapshots(t).Get(ctx, p.SnapshotID)
		if errors.Is(err, store.ErrNotFound) {
			return createSourceResult{}, errInvalidSnapshotID
		}
		if err != nil {
			return createSourceResult{}, err
		}
		if snap.Status != statusAvailable {
			return createSourceResult{}, errSnapshotUnavailable
		}
		if snap.AvailabilityZone != p.AvailabilityZone {
			return createSourceResult{}, errSnapshotAZMismatch
		}
		if snap.VolumeType != p.VolumeType {
			return createSourceResult{}, errSnapshotTypeMismatch(p.VolumeType, snap.VolumeType)
		}
		if p.SizeGB < 1 || p.SizeGB < snap.SizeGB || p.SizeGB > maxEmptyVolumeGB {
			return createSourceResult{}, errInvalidVolumeSize
		}
		kmsKeyID := snap.Metadata[metaCMKIDKey]
		if snap.VolumeID != "" {
			if srcVol, err := s.volumes(t).Get(ctx, snap.VolumeID); err == nil && srcVol.KMSKeyID != "" {
				kmsKeyID = srcVol.KMSKeyID
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				return createSourceResult{}, err
			}
		}
		return createSourceResult{
			SnapshotID: snap.ID,
			KMSKeyID:   kmsKeyID,
		}, nil
	}

	if p.SizeGB < minEmptyVolumeGB || p.SizeGB > maxEmptyVolumeGB {
		return createSourceResult{}, errInvalidVolumeSize
	}
	return createSourceResult{}, nil
}

// validateCreateQoS validates iops and throughput against the volume type for CreateVolume.
func validateCreateQoS(volumeType string, iops, throughput *int) (createQoSResult, error) {
	switch volumeType {
	case volumeTypeGPSSD2:
		if iops == nil || throughput == nil {
			return createQoSResult{}, errGPSSD2QoSRequired
		}
		if *iops < 1 || *throughput < 1 {
			return createQoSResult{}, errInvalidQoSValue
		}
		return createQoSResult{IOPS: *iops, Throughput: *throughput}, nil
	case volumeTypeESSD2:
		if iops == nil || throughput != nil {
			return createQoSResult{}, errESSD2QoSInvalid
		}
		if *iops < 1 {
			return createQoSResult{}, errInvalidQoSValue
		}
		return createQoSResult{IOPS: *iops}, nil
	default:
		if iops != nil || throughput != nil {
			return createQoSResult{}, errQoSNotSupported
		}
		return createQoSResult{}, nil
	}
}

// validateCreateMetadata validates encryption and passthrough system keys in
// metadata and returns the resolved KMS key, passthrough flag, and caller-only metadata.
func (s *Service) validateCreateMetadata(ctx context.Context, t Tenant, meta map[string]string, hasSource bool) (createMetadataResult, error) {
	var out createMetadataResult
	if len(meta) == 0 {
		return out, nil
	}

	enc, hasEnc := meta[metaEncryptedKey]
	cmkid, hasCMK := meta[metaCMKIDKey]
	if hasSource && (hasEnc || hasCMK) {
		return createMetadataResult{}, errEncryptWithSource
	}

	if hasEnc && enc != "0" && enc != "1" {
		return createMetadataResult{}, errInvalidEncryptParam
	}
	if cmkid != "" && enc != "1" {
		return createMetadataResult{}, errInvalidEncryptParam
	}
	if enc == "1" {
		if s.keys == nil {
			return createMetadataResult{}, errKeyNotEnabled
		}
		keyID, err := s.keys.Check(ctx, t.Region, t.ProjectID, cmkid, "evs")
		switch {
		case errors.Is(err, cmk.ErrNotFound), errors.Is(err, cmk.ErrDisabled):
			return createMetadataResult{}, errKeyNotEnabled
		case err != nil:
			return createMetadataResult{}, err
		}
		out.KMSKeyID = keyID
	}

	if pt, hasPT := meta[metaPassthroughKey]; hasPT {
		switch pt {
		case "true":
			out.Passthrough = true
		case "false":
			out.Passthrough = false
		default:
			return createMetadataResult{}, errInvalidPassthrough
		}
	}

	for k, v := range meta {
		if k == metaEncryptedKey || k == metaCMKIDKey || k == metaPassthroughKey {
			continue
		}
		if out.Metadata == nil {
			out.Metadata = make(map[string]string)
		}
		out.Metadata[k] = v
	}
	return out, nil
}
