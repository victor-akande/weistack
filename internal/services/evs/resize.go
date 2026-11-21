package evs

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	taskVolumeExtend = "evs.volume.extend"
	jobExtendVolume  = "extendVolume"

	maxDataDiskSizeGB   = 32768
	maxSystemDiskSizeGB = 1024
)

var (
	errNullExtendReq      = apierr.New(http.StatusBadRequest, "EVS.1011", "null extendVolumeReq!")
	errExtendSizeTooSmall = apierr.New(http.StatusBadRequest, "EVS.1015", "new volume Size must be greater than old Size!")
	errExtendSizeInvalid  = apierr.New(http.StatusBadRequest, "EVS.1010", "invalid volume size!")
	errExtendMultiattach  = apierr.New(http.StatusBadRequest, "EVS.1065", "multiattach volume status must be available when extending!")
	errExtendServerState  = apierr.New(http.StatusBadRequest, "EVS.1066", "status of ECS or BMS does not support volume online extension!")
	errExtendBadStatus    = apierr.New(http.StatusBadRequest, "EVS.1064", "volume status must be available or in-use when extending!")
)

type resizeVolumeRequest struct {
	OSExtend *osExtendRequest `json:"os-extend"`
}

type osExtendRequest struct {
	NewSize int `json:"new_size"`
}

type resizeVolumeResponse struct {
	JobID string `json:"job_id"`
}

func (s *Service) handleResizeVolume(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req resizeVolumeRequest
	if err := httpx.DecodeJSON(r, &req); err != nil || req.OSExtend == nil {
		return errNullExtendReq
	}

	id := chi.URLParam(r, "volume_id")
	jobID, err := s.resizeVolume(r.Context(), t, id, req.OSExtend.NewSize)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusAccepted, resizeVolumeResponse{JobID: jobID})
}

func (s *Service) resizeVolume(ctx context.Context, t Tenant, volumeID string, newSize int) (string, error) {
	v, err := s.volumes(t).Get(ctx, volumeID)
	if errors.Is(err, store.ErrNotFound) {
		return "", errVolumeNotFound
	}
	if err != nil {
		return "", err
	}

	if err := s.checkResize(ctx, t, v, newSize); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-read under lock to avoid racing with another state transition.
	v, err = s.volumes(t).Get(ctx, volumeID)
	if errors.Is(err, store.ErrNotFound) {
		return "", errVolumeNotFound
	}
	if err != nil {
		return "", err
	}
	if err := s.checkResizeLocal(v, newSize); err != nil {
		return "", err
	}

	now := s.now().UTC()
	jobID := s.ids.Hex32()
	j := job{
		Status:    "RUNNING",
		JobID:     jobID,
		JobType:   jobExtendVolume,
		BeginTime: now.Format(jobTimeLayout),
		Entities: jobEntities{
			VolumeID:   v.ID,
			Name:       v.Name,
			Size:       newSize,
			VolumeType: v.VolumeType,
		},
	}
	if err := s.jobs(t).Create(ctx, jobID, j); err != nil {
		return "", err
	}

	volNow := now.Format(volumeTimeLayout)
	if _, err := s.volumes(t).Update(ctx, volumeID, func(cur *volume) error {
		cur.Status = statusExtending
		cur.Pending = &pending{
			Op:      "extend",
			JobID:   jobID,
			NewSize: newSize,
		}
		cur.UpdatedAt = volNow
		return nil
	}); err != nil {
		_ = s.jobs(t).Delete(ctx, jobID)
		return "", err
	}

	s.scheduleExtend(t, volumeID, jobID)
	return jobID, nil
}

func (s *Service) checkResize(ctx context.Context, t Tenant, v volume, newSize int) error {
	if err := s.checkResizeLocal(v, newSize); err != nil {
		return err
	}
	if v.Status == statusInUse {
		s.mu.Lock()
		srv := s.servers
		s.mu.Unlock()
		if srv != nil && len(v.Attachments) > 0 {
			info, err := srv.ServerForVolume(ctx, t, v.Attachments[0].ServerID)
			if err != nil {
				if errors.Is(err, ErrServerNotFound) {
					return errExtendServerState
				}
				return err
			}
			if info.Status != "ACTIVE" && info.Status != "SHUTOFF" {
				return errExtendServerState
			}
		}
	}
	return nil
}

func (s *Service) checkResizeLocal(v volume, newSize int) error {
	if newSize <= v.SizeGB {
		return errExtendSizeTooSmall
	}
	maxSize := maxDataDiskSizeGB
	if v.Bootable {
		maxSize = maxSystemDiskSizeGB
	}
	if newSize > maxSize {
		return errExtendSizeInvalid
	}
	if v.Pending != nil {
		return errExtendBadStatus
	}
	switch v.Status {
	case statusAvailable:
		return nil
	case statusInUse:
		if v.Multiattach {
			return errExtendMultiattach
		}
		return nil
	default:
		return errExtendBadStatus
	}
}

func (s *Service) scheduleExtend(t Tenant, volumeID, jobID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  volumeID,
		Kind: taskVolumeExtend,
		Run: func(ctx context.Context, fault error) {
			s.finishExtend(ctx, t, volumeID, jobID, fault)
		},
	})
}

func (s *Service) finishExtend(ctx context.Context, t Tenant, volumeID, jobID string, fault error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()
	failed := fault != nil
	volNow := now.Format(volumeTimeLayout)
	_, err := s.volumes(t).Update(ctx, volumeID, func(cur *volume) error {
		if cur.Pending == nil || cur.Pending.Op != "extend" || cur.Pending.JobID != jobID {
			return nil
		}
		if failed {
			cur.Status = statusErrorExtending
			cur.Pending = nil
			cur.UpdatedAt = volNow
			return nil
		}
		cur.SizeGB = cur.Pending.NewSize
		cur.Pending = nil
		if len(cur.Attachments) > 0 {
			cur.Status = statusInUse
		} else {
			cur.Status = statusAvailable
		}
		cur.UpdatedAt = volNow
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "evs finishExtend volume update failed", "volume_id", volumeID, "error", err)
	}

	end := now.Format(jobTimeLayout)
	_, jErr := s.jobs(t).Update(ctx, jobID, func(j *job) error {
		if j.Status != "RUNNING" {
			return nil
		}
		j.EndTime = end
		if failed {
			j.Status = "FAIL"
			j.ErrorCode = "EVS.2026"
			j.FailReason = fault.Error()
			return nil
		}
		j.Status = "SUCCESS"
		return nil
	})
	if jErr != nil && !errors.Is(jErr, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "evs finishExtend job update failed", "job_id", jobID, "error", jErr)
	}
}
