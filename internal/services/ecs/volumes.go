package ecs

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/evs"
)

const (
	taskVolumeAttach = "ecs.volume.attach"
	taskVolumeDetach = "ecs.volume.detach"

	jobAttachVolume = "attachVolume"
	jobDetachVolume = "detachVolume"
)

// ServerForVolume implements evs.Servers.
func (s *Service) ServerForVolume(ctx context.Context, t evs.Tenant, id string) (evs.ServerInfo, error) {
	srv, err := s.servers(Tenant{Region: t.Region, ProjectID: t.ProjectID}).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return evs.ServerInfo{}, evs.ErrServerNotFound
	}
	if err != nil {
		return evs.ServerInfo{}, err
	}
	return evs.ServerInfo{AvailabilityZone: srv.AvailabilityZone, Status: srv.Status}, nil
}

// AttachVolume implements evs.Servers, attaching an available volume to
// serverID using the same path as AttachServerVolume.
func (s *Service) AttachVolume(ctx context.Context, t evs.Tenant, serverID, volumeID string) error {
	_, err := s.attachVolume(ctx, Tenant{Region: t.Region, ProjectID: t.ProjectID}, serverID, volumeID, "", false)
	return err
}

type attachVolumeRequest struct {
	VolumeAttachment *attachVolumeOption `json:"volumeAttachment"`
	DryRun           bool                `json:"dry_run"`
}

type attachVolumeOption struct {
	VolumeID string `json:"volumeId"`
	Device   string `json:"device"`
}

func (s *Service) handleAttachVolume(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req attachVolumeRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.VolumeAttachment == nil || req.VolumeAttachment.VolumeID == "" {
		return errInvalidRequest("volumeAttachment.volumeId is required")
	}
	serverID := chi.URLParam(r, "server_id")
	jobID, err := s.attachVolume(r.Context(), t, serverID, req.VolumeAttachment.VolumeID, req.VolumeAttachment.Device, req.DryRun)
	if err != nil {
		return err
	}
	if req.DryRun {
		w.WriteHeader(http.StatusAccepted)
		return nil
	}
	return httpx.WriteJSON(w, http.StatusOK, jobResponse{JobID: jobID})
}

func (s *Service) attachVolume(ctx context.Context, t Tenant, serverID, volumeID, device string, dryRun bool) (string, error) {
	srv, err := s.GetServer(ctx, t, serverID)
	if err != nil {
		return "", err
	}
	if srv.TaskState != "" || srv.Pending != nil {
		return "", errStatus(srv.ID, srv.Status, "another operation ("+srv.TaskState+") is in progress")
	}
	if srv.Status != StatusActive && srv.Status != StatusShutoff {
		return "", errStatus(srv.ID, srv.Status, "must be ACTIVE or SHUTOFF")
	}

	var jobID string
	if !dryRun {
		jobID = s.ids.Hex32()
	}
	if _, err := s.volumes.BeginAttach(ctx, t.evs(), volumeID, serverID, srv.AvailabilityZone, device, jobID, dryRun); err != nil {
		return "", mapAttachError(err, device)
	}
	if dryRun {
		return "", nil
	}

	if err := s.newVolumeJob(ctx, t, jobID, jobAttachVolume, serverID); err != nil {
		s.volumes.FinishAttach(ctx, t.evs(), volumeID, jobID, err)
		return "", err
	}
	s.scheduleAttach(t, volumeID, serverID, jobID)
	return jobID, nil
}

func mapAttachError(err error, device string) error {
	switch {
	case errors.Is(err, evs.ErrVolumeNotFound), errors.Is(err, evs.ErrNotAvailable):
		return bad("Ecs.0103", "A disk can be attached to a server only if the disk exists and is in the available state. Make sure the disk state is available and try again.")
	case errors.Is(err, evs.ErrAlreadyAttached):
		return bad("Ecs.0057", "The disk has already been attached to the ECS and you cannot repeatedly attach it.")
	case errors.Is(err, evs.ErrOtherAZ):
		return bad("Ecs.0121", "The disk cannot be attached to the ECS because the disk and the ECS are in different failure domains.")
	case errors.Is(err, evs.ErrTooManyDisks):
		return bad("Ecs.0104", "The number of EVS disks that can be attached to the ECS has reached the maximum number allowed. Detach some disks and try again.")
	case errors.Is(err, evs.ErrBadDevice):
		return errInvalidRequest("Invalid or occupied device %q: must be /dev/vd[b-z] or /dev/sd[b-z].", device)
	default:
		return err
	}
}

func (s *Service) handleDetachVolume(w http.ResponseWriter, r *http.Request, t Tenant) error {
	serverID := chi.URLParam(r, "server_id")
	volumeID := chi.URLParam(r, "volume_id")
	jobID, err := s.detachVolume(r.Context(), t, serverID, volumeID)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, jobResponse{JobID: jobID})
}

func (s *Service) detachVolume(ctx context.Context, t Tenant, serverID, volumeID string) (string, error) {
	if _, err := s.GetServer(ctx, t, serverID); err != nil {
		return "", err
	}
	jobID := s.ids.Hex32()
	if err := s.volumes.BeginDetach(ctx, t.evs(), volumeID, serverID, jobID); err != nil {
		switch {
		case errors.Is(err, evs.ErrVolumeNotFound), errors.Is(err, evs.ErrNotAttached):
			return "", errVolumeNotAttached(volumeID, serverID)
		case errors.Is(err, evs.ErrSystemDisk):
			return "", errInvalidRequest("WeiStack does not detach system disks")
		default:
			return "", err
		}
	}
	if err := s.newVolumeJob(ctx, t, jobID, jobDetachVolume, serverID); err != nil {
		s.volumes.FinishDetach(ctx, t.evs(), volumeID, jobID, err)
		return "", err
	}
	s.scheduleDetach(t, volumeID, serverID, jobID)
	return jobID, nil
}

type updateBlockDeviceRequest struct {
	BlockDevice *struct {
		DeleteOnTermination *bool `json:"delete_on_termination"`
	} `json:"block_device"`
}

func (s *Service) handleUpdateBlockDevice(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateBlockDeviceRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.BlockDevice == nil || req.BlockDevice.DeleteOnTermination == nil {
		return errInvalidRequest("block_device.delete_on_termination is required")
	}
	serverID := chi.URLParam(r, "server_id")
	volumeID := chi.URLParam(r, "volume_id")
	if _, err := s.GetServer(r.Context(), t, serverID); err != nil {
		return err
	}
	if err := s.volumes.SetDeleteOnTermination(r.Context(), t.evs(), volumeID, serverID, *req.BlockDevice.DeleteOnTermination); err != nil {
		switch {
		case errors.Is(err, evs.ErrVolumeNotFound), errors.Is(err, evs.ErrNotAttached):
			return errVolumeNotAttached(volumeID, serverID)
		case errors.Is(err, evs.ErrSystemDisk):
			return errInvalidRequest("cannot update delete_on_termination on system disk")
		case errors.Is(err, evs.ErrShared):
			return errInvalidRequest("cannot update delete_on_termination on multiattach volume")
		default:
			return err
		}
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) newVolumeJob(ctx context.Context, t Tenant, jobID, jobType, serverID string) error {
	begin := s.now().UTC().Format(jobTimeLayout)
	job := Job{
		Status:    JobRunning,
		JobID:     jobID,
		JobType:   jobType,
		BeginTime: begin,
		Entities: JobEntities{
			SubJobsTotal: 1,
			SubJobs: []SubJob{{
				Status:    JobRunning,
				JobID:     s.ids.Hex32(),
				JobType:   jobType,
				BeginTime: begin,
				Entities:  SubJobEntities{ServerID: serverID},
			}},
		},
	}
	return s.jobs(t).Create(ctx, job.JobID, job)
}

func (s *Service) scheduleAttach(t Tenant, volumeID, serverID, jobID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  volumeID,
		Kind: taskVolumeAttach,
		Run: func(ctx context.Context, fault error) {
			s.volumes.FinishAttach(ctx, t.evs(), volumeID, jobID, fault)
			s.finishSubJob(ctx, t, jobID, serverID, fault)
		},
	})
}

func (s *Service) scheduleDetach(t Tenant, volumeID, serverID, jobID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  volumeID,
		Kind: taskVolumeDetach,
		Run: func(ctx context.Context, fault error) {
			s.volumes.FinishDetach(ctx, t.evs(), volumeID, jobID, fault)
			s.finishSubJob(ctx, t, jobID, serverID, fault)
		},
	})
}
