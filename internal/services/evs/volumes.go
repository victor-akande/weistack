package evs

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/zones"
)

const (
	taskVolumeCreate = "evs.volume.create"
	taskVolumeDelete = "evs.volume.delete"

	maxVolumeNameLen = 64
	maxVolumeDescLen = 85
	maxVolumeCount   = 100
	minEmptySizeGB   = 10
	maxEmptySizeGB   = 32768
	maxTagsPerVolume = 10
)

var validVolumeTypes = map[string]bool{
	"SATA":   true,
	"SAS":    true,
	"GPSSD":  true,
	"SSD":    true,
	"ESSD":   true,
	"GPSSD2": true,
	"ESSD2":  true,
}

var volumeTypeByID = map[string]string{
	"f3454cbe-d625-4edd-8de0-7bd3784ec143": "SATA",
	"27f8d1f1-52fa-4d6c-976a-0881849963f5": "SAS",
	"fdfb39b6-1af9-44a3-b379-63d157efbb0c": "GPSSD",
	"e2a523ff-35ef-4cf6-ac9f-cedb3183f858": "SSD",
	"e97c0dde-1a56-4bd4-b8a6-ff86ae28518e": "ESSD",
	"2ce7f24b-c4b0-4d64-a67e-7af8da40cde8": "GPSSD2",
	"a96564af-93a9-4c82-8400-6ccd551cb30a": "ESSD2",
}

var (
	tagKeyRE = regexp.MustCompile(`^[a-zA-Z0-9_\-\x{4E00}-\x{9FFF}]{1,36}$`)
	tagValRE = regexp.MustCompile(`^[a-zA-Z0-9_.\-\x{4E00}-\x{9FFF}]{0,43}$`)
)

type createVolumeRequestBody struct {
	BssParam *bssParamForCreateVolume `json:"bssParam"`
	Volume   *createVolumeOption      `json:"volume"`
	ServerID string                   `json:"server_id"`
}

type bssParamForCreateVolume struct {
	ChargingMode string `json:"chargingMode"`
}

type createVolumeOption struct {
	AvailabilityZone    string            `json:"availability_zone"`
	BackupID            string            `json:"backup_id"`
	Count               *int              `json:"count"`
	Description         string            `json:"description"`
	EnterpriseProjectID string            `json:"enterprise_project_id"`
	ImageRef            string            `json:"imageRef"`
	Metadata            map[string]string `json:"metadata"`
	Multiattach         bool              `json:"multiattach"`
	Name                string            `json:"name"`
	Size                int               `json:"size"`
	SnapshotID          string            `json:"snapshot_id"`
	VolumeType          string            `json:"volume_type"`
	Tags                map[string]string `json:"tags"`
	IOPS                *int              `json:"iops"`
	Throughput          *int              `json:"throughput"`
}

type createVolumeResponse struct {
	JobID     string   `json:"job_id"`
	VolumeIDs []string `json:"volume_ids"`
}

type updateVolumeRequestBody struct {
	Volume *updateVolumeOption `json:"volume"`
}

type updateVolumeOption struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type deleteVolumeResponse struct {
	JobID string `json:"job_id"`
}

func (s *Service) handleCreateVolume(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var body createVolumeRequestBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return errInvalidRequest
	}
	if body.Volume == nil {
		return errNullCreateVolumeReq
	}
	if body.BssParam != nil && body.BssParam.ChargingMode == "prePaid" {
		return errInvalidBssParam
	}

	opt := *body.Volume
	if !zones.Exists(t.Region, opt.AvailabilityZone) {
		return errInvalidAZ
	}
	if !validVolumeTypes[opt.VolumeType] {
		return errInvalidVolumeType
	}
	if utf8.RuneCountInString(opt.Name) > maxVolumeNameLen {
		return errInvalidVolumeName
	}
	if utf8.RuneCountInString(opt.Description) > maxVolumeDescLen {
		return errInvalidVolumeDesc
	}

	count := 1
	if opt.Count != nil {
		count = *opt.Count
	}
	if count < 1 || count > maxVolumeCount {
		return errInvalidVolumeCount
	}
	if body.ServerID != "" && count != 1 {
		return errInvalidVolumeCount
	}

	sources := 0
	for _, src := range []string{opt.ImageRef, opt.SnapshotID, opt.BackupID} {
		if src != "" {
			sources++
		}
	}
	if sources > 1 {
		return errMultipleSources
	}
	if opt.BackupID != "" {
		return errInvalidBackupID
	}

	if opt.ImageRef == "" && opt.SnapshotID == "" {
		if opt.Size < minEmptySizeGB || opt.Size > maxEmptySizeGB {
			return errInvalidVolumeSize
		}
	}

	if err := validateTags(opt.Tags); err != nil {
		return err
	}

	passthrough, userMeta, err := parseMetadata(opt.Metadata)
	if err != nil {
		return err
	}

	base := volume{
		Description:         opt.Description,
		Status:              statusCreating,
		SizeGB:              opt.Size,
		VolumeType:          opt.VolumeType,
		AvailabilityZone:    opt.AvailabilityZone,
		Passthrough:         passthrough,
		Multiattach:         opt.Multiattach,
		Metadata:            userMeta,
		Tags:                maps.Clone(opt.Tags),
		EnterpriseProjectID: opt.EnterpriseProjectID,
		Attachments:         []attachment{},
	}
	if base.EnterpriseProjectID == "" {
		base.EnterpriseProjectID = "0"
	}

	if err := s.prepareVolumeSourcesAndQoS(r.Context(), t, opt, &base); err != nil {
		return err
	}

	if body.ServerID != "" {
		srv := s.getServers()
		if srv == nil {
			return errServerNotFound
		}
		info, err := srv.ServerForVolume(r.Context(), t, body.ServerID)
		if errors.Is(err, ErrServerNotFound) {
			return errServerNotFound
		}
		if err != nil {
			return err
		}
		if info.AvailabilityZone != opt.AvailabilityZone {
			return errServerAZMismatch
		}
	}

	now := s.now().UTC().Format(volumeTimeLayout)
	vols := make([]volume, count)
	volIDs := make([]string, count)
	for i := range vols {
		v := base
		v.ID = s.ids.UUID()
		if count > 1 {
			v.Name = fmt.Sprintf("%s-%04d", opt.Name, i+1)
		} else {
			v.Name = opt.Name
		}
		v.Metadata = maps.Clone(base.Metadata)
		v.Tags = maps.Clone(base.Tags)
		v.Attachments = []attachment{}
		v.CreatedAt = now
		v.UpdatedAt = now
		vols[i] = v
		volIDs[i] = v.ID
	}

	var j job
	if count == 1 {
		j, err = s.newVolumeJob(r.Context(), t, jobTypeCreateVolume, vols[0])
	} else {
		j, err = s.newBatchCreateJob(r.Context(), t, vols)
	}
	if err != nil {
		return err
	}

	s.mu.Lock()
	for i := range vols {
		vols[i].Pending = &pending{
			Op:       "create",
			JobID:    j.JobID,
			AttachTo: body.ServerID,
		}
		if err := s.volumes(t).Create(r.Context(), vols[i].ID, vols[i]); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Unlock()

	for _, v := range vols {
		s.scheduleCreate(t, v.ID, j.JobID, body.ServerID)
	}

	return httpx.WriteJSON(w, http.StatusAccepted, createVolumeResponse{
		JobID:     j.JobID,
		VolumeIDs: volIDs,
	})
}

func (s *Service) handleUpdateVolume(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "volume_id")
	var body updateVolumeRequestBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return errInvalidRequest
	}
	if body.Volume == nil || (body.Volume.Name == nil && body.Volume.Description == nil) {
		return errUpdateBothEmpty
	}
	opt := body.Volume
	if opt.Name != nil && utf8.RuneCountInString(*opt.Name) > maxVolumeNameLen {
		return errInvalidVolumeName
	}
	if opt.Description != nil && utf8.RuneCountInString(*opt.Description) > maxVolumeDescLen {
		return errInvalidVolumeDesc
	}

	now := s.now().UTC().Format(volumeTimeLayout)
	s.mu.Lock()
	updated, err := s.volumes(t).Update(r.Context(), id, func(v *volume) error {
		if opt.Name != nil {
			v.Name = *opt.Name
		}
		if opt.Description != nil {
			v.Description = *opt.Description
		}
		v.UpdatedAt = now
		return nil
	})
	s.mu.Unlock()
	if errors.Is(err, store.ErrNotFound) {
		return errVolumeNotFound
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, detail(updated, t, r))
}

func (s *Service) handleDeleteVolume(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "volume_id")

	s.mu.Lock()
	v, err := s.volumes(t).Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.mu.Unlock()
		return errVolumeNotFound
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if !canDeleteVolume(v) {
		s.mu.Unlock()
		return errDeleteInvalidStatus
	}
	j, err := s.newVolumeJob(r.Context(), t, jobTypeDeleteVolume, v)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	now := s.now().UTC().Format(volumeTimeLayout)
	_, err = s.volumes(t).Update(r.Context(), id, func(cur *volume) error {
		cur.Status = statusDeleting
		cur.Pending = &pending{Op: "delete", JobID: j.JobID}
		cur.UpdatedAt = now
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		return err
	}

	s.scheduleDelete(t, id, j.JobID)
	return httpx.WriteJSON(w, http.StatusOK, deleteVolumeResponse{JobID: j.JobID})
}

func canDeleteVolume(v volume) bool {
	if v.Pending != nil {
		return false
	}
	switch v.Status {
	case statusAvailable, statusError, statusErrorExtending, statusErrorRestoring, statusErrorRollbacking:
		return true
	default:
		return false
	}
}

func (s *Service) scheduleCreate(t Tenant, volumeID, jobID, attachTo string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  volumeID,
		Kind: taskVolumeCreate,
		Run: func(ctx context.Context, fault error) {
			now := s.now().UTC().Format(volumeTimeLayout)
			if fault != nil {
				s.mu.Lock()
				_, err := s.volumes(t).Update(ctx, volumeID, func(v *volume) error {
					v.Status = statusError
					v.Pending = nil
					v.UpdatedAt = now
					return nil
				})
				s.mu.Unlock()
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					s.log.ErrorContext(ctx, "marking volume create error failed", "volume_id", volumeID, "error", err)
				}
				s.finishJob(ctx, t, jobID, volumeID, "EVS.2024", "volume is error!")
				return
			}

			s.mu.Lock()
			_, err := s.volumes(t).Update(ctx, volumeID, func(v *volume) error {
				v.Status = statusAvailable
				v.Pending = nil
				v.UpdatedAt = now
				return nil
			})
			s.mu.Unlock()
			if err != nil {
				if !errors.Is(err, store.ErrNotFound) {
					s.log.ErrorContext(ctx, "completing volume create failed", "volume_id", volumeID, "error", err)
				}
				s.finishJob(ctx, t, jobID, volumeID, "EVS.2024", "volume is error!")
				return
			}

			if attachTo != "" {
				if srv := s.getServers(); srv != nil {
					if err := srv.AttachVolume(ctx, t, attachTo, volumeID); err != nil {
						s.log.ErrorContext(ctx, "post-create attach failed", "volume_id", volumeID, "server_id", attachTo, "error", err)
					}
				}
			}
			s.finishJob(ctx, t, jobID, volumeID, "", "")
		},
	})
}

func (s *Service) scheduleDelete(t Tenant, volumeID, jobID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  volumeID,
		Kind: taskVolumeDelete,
		Run: func(ctx context.Context, fault error) {
			now := s.now().UTC().Format(volumeTimeLayout)
			if fault != nil {
				s.mu.Lock()
				_, err := s.volumes(t).Update(ctx, volumeID, func(v *volume) error {
					v.Status = statusErrorDeleting
					v.Pending = nil
					v.UpdatedAt = now
					return nil
				})
				s.mu.Unlock()
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					s.log.ErrorContext(ctx, "marking volume delete error failed", "volume_id", volumeID, "error", err)
				}
				s.finishJob(ctx, t, jobID, volumeID, "EVS.2020", "volume is error_deleting!")
				return
			}

			s.mu.Lock()
			err := s.deleteVolumeAndSnapshotsLocked(ctx, t, volumeID)
			s.mu.Unlock()
			if err != nil {
				s.log.ErrorContext(ctx, "deleting volume failed", "volume_id", volumeID, "error", err)
				s.finishJob(ctx, t, jobID, volumeID, "EVS.2020", "volume is error_deleting!")
				return
			}
			s.finishJob(ctx, t, jobID, volumeID, "", "")
		},
	})
}

func (s *Service) getServers() Servers {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.servers
}

func validateTags(tags map[string]string) error {
	if len(tags) > maxTagsPerVolume {
		return errTooManyTags
	}
	for k, v := range tags {
		if !tagKeyRE.MatchString(k) || !tagValRE.MatchString(v) {
			return errInvalidTag
		}
	}
	return nil
}

func parseMetadata(meta map[string]string) (passthrough bool, user map[string]string, err error) {
	if len(meta) == 0 {
		return false, nil, nil
	}
	for k, val := range meta {
		switch k {
		case "hw:passthrough":
			switch val {
			case "true":
				passthrough = true
			case "false":
				passthrough = false
			default:
				return false, nil, errInvalidPassthrough
			}
		case "__system__encrypted", "__system__cmkid":
			// Handled by prepareVolumeSourcesAndQoS.
		default:
			if user == nil {
				user = make(map[string]string)
			}
			user[k] = val
		}
	}
	return passthrough, user, nil
}

// prepareVolumeSourcesAndQoS validates imageRef, snapshot_id, encryption
// metadata, and QoS (iops/throughput) and populates the derived fields on v.
func (s *Service) prepareVolumeSourcesAndQoS(ctx context.Context, t Tenant, opt createVolumeOption, v *volume) error {
	src, err := s.validateCreateSource(ctx, t, createSourceParams{
		ImageRef:         opt.ImageRef,
		SnapshotID:       opt.SnapshotID,
		BackupID:         opt.BackupID,
		AvailabilityZone: opt.AvailabilityZone,
		VolumeType:       opt.VolumeType,
		SizeGB:           opt.Size,
	})
	if err != nil {
		return err
	}
	qos, err := validateCreateQoS(opt.VolumeType, opt.IOPS, opt.Throughput)
	if err != nil {
		return err
	}
	hasSource := opt.ImageRef != "" || opt.SnapshotID != ""
	meta, err := s.validateCreateMetadata(ctx, t, opt.Metadata, hasSource)
	if err != nil {
		return err
	}
	v.Bootable = src.Bootable
	v.ImageID = src.ImageID
	v.ImageName = src.ImageName
	v.SnapshotID = src.SnapshotID
	v.KMSKeyID = src.KMSKeyID
	if meta.KMSKeyID != "" {
		v.KMSKeyID = meta.KMSKeyID
	}
	v.Passthrough = meta.Passthrough
	v.Metadata = meta.Metadata
	v.IOPS = qos.IOPS
	v.Throughput = qos.Throughput
	if v.IOPS > 0 || v.Throughput > 0 {
		v.QoSID = s.ids.UUID()
	}
	return nil
}
