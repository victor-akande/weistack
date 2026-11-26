package rds

import (
	"context"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: DB instances and manual
// backups. Config's relationship table relates RDS instances only to nodes,
// which WeiStack does not report as separate resources.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	err := inventory.Each(ctx, s.store, kindInstance, func(sc store.Scope, inst Instance) error {
		return emit(inventory.Resource{
			Type: inventory.RDSInstances, ID: inst.ID, Name: inst.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID, EnterpriseProjectID: inst.EnterpriseProj,
			Created: inst.Created, Updated: inst.Updated,
			State: instanceState(inst.Status),
			Tags:  tagMap(inst.Tags),
		})
	})
	if err != nil {
		return err
	}
	return inventory.Each(ctx, s.store, kindBackup, func(sc store.Scope, b Backup) error {
		return emit(inventory.Resource{
			Type: inventory.RDSBackups, ID: b.ID, Name: b.Name,
			RegionID: sc.Region, ProjectID: sc.ProjectID,
			Created: parseTime(b.BeginTime), Updated: parseTime(b.EndTime),
			State: backupState(b.Status),
		})
	})
}

func instanceState(status string) inventory.State {
	switch status {
	case StatusBuild, StatusRebooting, StatusModifying, StatusBackingUp:
		return inventory.Processing
	case StatusCreateFail, StatusFailed:
		return inventory.Failed
	default:
		return inventory.Succeeded
	}
}

func backupState(status string) inventory.State {
	switch status {
	case BackupBuilding:
		return inventory.Processing
	case BackupFailed:
		return inventory.Failed
	default:
		return inventory.Succeeded
	}
}

func parseTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	t, err := time.Parse(timeLayout, raw)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func tagMap(tags []Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[t.Key] = t.Value
	}
	return m
}
