package ecs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/victor-akande/weistack/internal/core/store"
)

// kindJob is the store kind of asynchronous jobs.
const kindJob = "ecs.job"

func (s *Service) jobs(t Tenant) store.Collection[Job] {
	return store.Of[Job](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindJob})
}

// newJob stores a running job with one sub-job per server and returns it.
func (s *Service) newJob(ctx context.Context, t Tenant, jobType, subType string, serverIDs []string) (Job, error) {
	begin := s.now().UTC().Format(jobTimeLayout)
	job := Job{
		Status:    JobRunning,
		JobID:     s.ids.Hex32(),
		JobType:   jobType,
		BeginTime: begin,
		Entities:  JobEntities{SubJobsTotal: len(serverIDs), SubJobs: make([]SubJob, 0, len(serverIDs))},
	}
	for _, id := range serverIDs {
		job.Entities.SubJobs = append(job.Entities.SubJobs, SubJob{
			Status:    JobRunning,
			JobID:     s.ids.Hex32(),
			JobType:   subType,
			BeginTime: begin,
			Entities:  SubJobEntities{ServerID: id},
		})
	}
	if err := s.jobs(t).Create(ctx, job.JobID, job); err != nil {
		return Job{}, err
	}
	return job, nil
}

// finishSubJob closes the sub-job of one server, and the job itself once
// every sub-job is closed. A job fails if any of its sub-jobs failed.
func (s *Service) finishSubJob(ctx context.Context, t Tenant, jobID, serverID string, fault error) {
	end := s.now().UTC().Format(jobTimeLayout)
	_, err := s.jobs(t).Update(ctx, jobID, func(j *Job) error {
		open, failed := 0, 0
		for i := range j.Entities.SubJobs {
			sub := &j.Entities.SubJobs[i]
			if sub.Entities.ServerID == serverID && sub.Status == JobRunning {
				sub.EndTime = end
				sub.Status = JobSuccess
				if fault != nil {
					code, reason := jobFailureCode, fault.Error()
					sub.Status, sub.ErrorCode, sub.FailReason = JobFail, &code, &reason
				}
			}
			switch sub.Status {
			case JobRunning:
				open++
			case JobFail:
				failed++
			}
		}
		if open == 0 && j.Status == JobRunning {
			j.EndTime = end
			j.Status = JobSuccess
			if failed > 0 {
				code, reason := jobFailureCode, "one or more sub-jobs failed"
				j.Status, j.ErrorCode, j.FailReason = JobFail, &code, &reason
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "closing sub-job failed", "job_id", jobID, "server_id", serverID, "error", err)
	}
}

// GetJob returns an asynchronous job of the project.
func (s *Service) GetJob(ctx context.Context, t Tenant, id string) (Job, error) {
	job, err := s.jobs(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return Job{}, errJobNotFound(id)
	}
	return job, err
}

// Resume continues the jobs that were running when a persistent
// emulator last stopped, so no server is stranded in BUILD or stuck
// "deleting". Call it once at startup.
func (s *Service) Resume(ctx context.Context) error {
	dump, err := s.store.Dump(ctx)
	if err != nil {
		return fmt.Errorf("ecs: resuming jobs: %w", err)
	}
	for key, recs := range dump {
		scope, err := store.ParseScope(key)
		if err != nil || scope.Kind != kindJob {
			continue
		}
		t := Tenant{Region: scope.Region, ProjectID: scope.ProjectID}
		for _, rec := range recs {
			var job Job
			if err := json.Unmarshal(rec.Data, &job); err != nil {
				return fmt.Errorf("ecs: decoding %s/%s: %w", key, rec.ID, err)
			}
			if job.Status != JobRunning {
				continue
			}
			for _, sub := range job.Entities.SubJobs {
				if sub.Status == JobRunning {
					if err := s.resumeSubJob(ctx, t, job, sub); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (s *Service) resumeSubJob(ctx context.Context, t Tenant, job Job, sub SubJob) error {
	id := sub.Entities.ServerID
	srv, err := s.servers(t).Get(ctx, id)
	gone := errors.Is(err, store.ErrNotFound)
	if err != nil && !gone {
		return err
	}
	switch {
	case sub.JobType == jobDeleteSingleServer && gone:
		s.finishSubJob(ctx, t, job.JobID, id, nil) // the delete had completed
	case sub.JobType == jobDeleteSingleServer:
		s.scheduleDelete(t, id, job.JobID)
	case gone:
		s.finishSubJob(ctx, t, job.JobID, id, errors.New("the ECS no longer exists"))
	case sub.JobType == jobCreateSingleServer && srv.Status == StatusBuild:
		s.scheduleBuild(t, id, job.JobID)
	default:
		s.finishSubJob(ctx, t, job.JobID, id, nil) // the work had completed
	}
	return nil
}
