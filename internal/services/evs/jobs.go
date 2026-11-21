package evs

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	jobStatusRunning = "RUNNING"
	jobStatusSuccess = "SUCCESS"
	jobStatusFail    = "FAIL"

	jobTypeCreateVolume      = "createVolume"
	jobTypeBatchCreateVolume = "batchCreateVolume"
	jobTypeDeleteVolume      = "deleteVolume"
	jobTypeExtendVolume      = "extendVolume"
)

func (s *Service) handleShowJob(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "job_id")
	j, err := s.jobs(t).Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return errJobNotFound
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, j)
}

func (s *Service) newVolumeJob(ctx context.Context, t Tenant, jobType string, v volume) (job, error) {
	begin := s.now().UTC().Format(jobTimeLayout)
	j := job{
		Status:    jobStatusRunning,
		JobID:     s.ids.Hex32(),
		JobType:   jobType,
		BeginTime: begin,
		Entities: jobEntities{
			VolumeType: v.VolumeType,
			Size:       v.SizeGB,
			VolumeID:   v.ID,
			Name:       v.Name,
		},
	}
	if err := s.jobs(t).Create(ctx, j.JobID, j); err != nil {
		return job{}, err
	}
	return j, nil
}

func (s *Service) newBatchCreateJob(ctx context.Context, t Tenant, vols []volume) (job, error) {
	begin := s.now().UTC().Format(jobTimeLayout)
	subs := make([]subJob, 0, len(vols))
	for _, v := range vols {
		subs = append(subs, subJob{
			Status:    jobStatusRunning,
			JobID:     s.ids.Hex32(),
			JobType:   jobTypeCreateVolume,
			BeginTime: begin,
			Entities: jobEntities{
				VolumeType: v.VolumeType,
				Size:       v.SizeGB,
				VolumeID:   v.ID,
				Name:       v.Name,
			},
		})
	}
	j := job{
		Status:    jobStatusRunning,
		JobID:     s.ids.Hex32(),
		JobType:   jobTypeBatchCreateVolume,
		BeginTime: begin,
		Entities: jobEntities{
			SubJobsTotal: len(subs),
			SubJobs:      subs,
		},
	}
	if err := s.jobs(t).Create(ctx, j.JobID, j); err != nil {
		return job{}, err
	}
	return j, nil
}

// finishJob closes a single-volume job or one sub-job of a batch job.
// For batch jobs, the parent job closes once all sub-jobs are closed.
func (s *Service) finishJob(ctx context.Context, t Tenant, jobID, volumeID, errCode, failReason string) {
	if jobID == "" {
		return
	}
	end := s.now().UTC().Format(jobTimeLayout)
	_, err := s.jobs(t).Update(ctx, jobID, func(j *job) error {
		if len(j.Entities.SubJobs) == 0 {
			if j.Status != jobStatusRunning {
				return nil
			}
			j.EndTime = end
			if errCode != "" {
				j.Status = jobStatusFail
				j.ErrorCode = errCode
				j.FailReason = failReason
			} else {
				j.Status = jobStatusSuccess
			}
			return nil
		}

		open, failed := 0, 0
		var firstCode string
		for i := range j.Entities.SubJobs {
			sub := &j.Entities.SubJobs[i]
			if sub.Entities.VolumeID == volumeID && sub.Status == jobStatusRunning {
				sub.EndTime = end
				if errCode != "" {
					sub.Status = jobStatusFail
					sub.ErrorCode = errCode
					sub.FailReason = failReason
				} else {
					sub.Status = jobStatusSuccess
				}
			}
			switch sub.Status {
			case jobStatusRunning:
				open++
			case jobStatusFail:
				failed++
				if firstCode == "" {
					firstCode = sub.ErrorCode
				}
			}
		}
		if open == 0 && j.Status == jobStatusRunning {
			j.EndTime = end
			if failed > 0 {
				j.Status = jobStatusFail
				j.ErrorCode = firstCode
				j.FailReason = "one or more sub-jobs failed"
			} else {
				j.Status = jobStatusSuccess
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "closing evs job failed", "job_id", jobID, "volume_id", volumeID, "error", err)
	}
}
