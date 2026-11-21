package evs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	taskSnapshotCreate   = "evs.snapshot.create"
	taskSnapshotRollback = "evs.snapshot.rollback"
)

// Resume continues any asynchronous volume or snapshot operations that
// were in flight when a persistent emulator last stopped.
func (s *Service) Resume(ctx context.Context) error {
	dump, err := s.store.Dump(ctx)
	if err != nil {
		return fmt.Errorf("evs: resuming operations: %w", err)
	}
	for key, recs := range dump {
		scope, err := store.ParseScope(key)
		if err != nil {
			continue
		}
		t := Tenant{Region: scope.Region, ProjectID: scope.ProjectID}
		switch scope.Kind {
		case kindVolume:
			for _, rec := range recs {
				var v volume
				if err := json.Unmarshal(rec.Data, &v); err != nil {
					return fmt.Errorf("evs: decoding %s/%s: %w", key, rec.ID, err)
				}
				if v.Pending == nil {
					continue
				}
				switch v.Pending.Op {
				case "create":
					s.scheduleCreate(t, v.ID, v.Pending.JobID, v.Pending.AttachTo)
				case "delete":
					s.scheduleDelete(t, v.ID, v.Pending.JobID)
				case "extend":
					s.resumeExtend(t, v.ID, v.Pending.JobID, v.Pending.NewSize)
				case "rollback":
					s.resumeRollback(t, v.ID)
				}
			}
		case kindSnapshot:
			for _, rec := range recs {
				var sn snapshot
				if err := json.Unmarshal(rec.Data, &sn); err != nil {
					return fmt.Errorf("evs: decoding %s/%s: %w", key, rec.ID, err)
				}
				if sn.Status == statusCreating {
					s.resumeSnapshotCreate(t, sn.ID)
				}
			}
		}
	}
	return nil
}

func (s *Service) resumeExtend(t Tenant, volumeID, jobID string, newSize int) {
	s.engine.Schedule(lifecycle.Task{
		Key:  volumeID,
		Kind: taskVolumeExtend,
		Run: func(ctx context.Context, fault error) {
			now := s.now().UTC().Format(volumeTimeLayout)
			if fault != nil {
				s.mu.Lock()
				_, err := s.volumes(t).Update(ctx, volumeID, func(v *volume) error {
					v.Status = statusErrorExtending
					v.Pending = nil
					v.UpdatedAt = now
					return nil
				})
				s.mu.Unlock()
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					s.log.ErrorContext(ctx, "marking volume extend error failed", "volume_id", volumeID, "error", err)
				}
				s.finishJob(ctx, t, jobID, volumeID, "EVS.2026", "volume is error_extending!")
				return
			}

			s.mu.Lock()
			_, err := s.volumes(t).Update(ctx, volumeID, func(v *volume) error {
				v.SizeGB = newSize
				if len(v.Attachments) > 0 {
					v.Status = statusInUse
				} else {
					v.Status = statusAvailable
				}
				v.Pending = nil
				v.UpdatedAt = now
				return nil
			})
			s.mu.Unlock()
			if err != nil {
				if !errors.Is(err, store.ErrNotFound) {
					s.log.ErrorContext(ctx, "completing volume extend failed", "volume_id", volumeID, "error", err)
				}
				s.finishJob(ctx, t, jobID, volumeID, "EVS.2026", "volume is error_extending!")
				return
			}
			s.finishJob(ctx, t, jobID, volumeID, "", "")
		},
	})
}

func (s *Service) resumeRollback(t Tenant, volumeID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  volumeID,
		Kind: taskSnapshotRollback,
		Run: func(ctx context.Context, fault error) {
			now := s.now().UTC().Format(volumeTimeLayout)
			s.mu.Lock()
			_, err := s.volumes(t).Update(ctx, volumeID, func(v *volume) error {
				if fault != nil {
					v.Status = statusErrorRollbacking
				} else {
					v.Status = statusAvailable
				}
				v.Pending = nil
				v.UpdatedAt = now
				return nil
			})
			s.mu.Unlock()
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "resuming snapshot rollback failed", "volume_id", volumeID, "error", err)
			}
		},
	})
}

func (s *Service) resumeSnapshotCreate(t Tenant, snapshotID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  snapshotID,
		Kind: taskSnapshotCreate,
		Run: func(ctx context.Context, fault error) {
			now := s.now().UTC().Format(volumeTimeLayout)
			s.mu.Lock()
			_, err := s.snapshots(t).Update(ctx, snapshotID, func(sn *snapshot) error {
				if fault != nil {
					sn.Status = statusError
				} else {
					sn.Status = statusAvailable
				}
				sn.UpdatedAt = now
				return nil
			})
			s.mu.Unlock()
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "resuming snapshot create failed", "snapshot_id", snapshotID, "error", err)
			}
		},
	})
}
