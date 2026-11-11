package rds

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/store"
)

// Lifecycle task kinds of instance operations.
const (
	taskRestart = "rds.instance.restart"
	taskResize  = "rds.instance.resize"
	taskEnlarge = "rds.instance.enlarge"
	taskBackup  = "rds.instance.backup"
)

// Job names, assumed by analogy with the documented creation job.
const (
	jobRestart = "RestartInstance"
	jobResize  = "ResizeFlavor"
	jobEnlarge = "EnlargeVolume"
	jobBackup  = "CreateManualBackup"
)

const kindBackup = "rds.backup"

func (s *Service) backups(t Tenant) store.Collection[Backup] {
	return store.Of[Backup](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindBackup})
}

// RestartInstance reboots a running instance.
func (s *Service) RestartInstance(ctx context.Context, t Tenant, id string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.begin(ctx, t, id, jobRestart, StatusRebooting, Pending{Kind: taskRestart}, nil, StatusActive)
}

// ResizeInstance changes an instance's specification to another of the
// same engine and mode. The new specification applies when the job
// completes.
func (s *Service) ResizeInstance(ctx context.Context, t Tenant, id string, opt ResizeOption) (Job, error) {
	if opt.SpecCode == "" {
		return Job{}, errInvalid("resize_flavor.spec_code is required")
	}
	target, ok := flavorByCode(opt.SpecCode)
	if !ok {
		return Job{}, errFlavorNotFound(opt.SpecCode)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	inst, err := s.GetInstance(ctx, t, id)
	if err != nil {
		return Job{}, err
	}
	switch {
	case target.Engine.Name != inst.Engine:
		return Job{}, errFlavorInvalid("The specification %s is not for %s.", target.Code, inst.Engine)
	case target.Mode != inst.Mode:
		return Job{}, errFlavorInvalid("The specification %s is for %s instances; this instance is %s.", target.Code, target.Mode, inst.Mode)
	case target.Code == inst.FlavorRef:
		return Job{}, errInvalid("The DB instance already uses the specification %s.", target.Code)
	}
	return s.begin(ctx, t, id, jobResize, StatusModifying, Pending{Kind: taskResize, Flavor: target.Code}, nil, StatusActive)
}

// EnlargeVolume grows an instance's storage. Storage cannot shrink.
func (s *Service) EnlargeVolume(ctx context.Context, t Tenant, id string, opt EnlargeOption) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, err := s.GetInstance(ctx, t, id)
	if err != nil {
		return Job{}, err
	}
	engine, _ := engineNamed(inst.Engine)
	switch {
	case opt.Size%10 != 0:
		return Job{}, errVolumeMultiple
	case opt.Size <= inst.VolumeSize:
		return Job{}, errVolumeShrink
	case opt.Size > engine.MaxVolume:
		return Job{}, errVolumeRange(engine.MinVolume, engine.MaxVolume)
	}
	// The job reports the change, as the API's job entities do.
	entities := map[string]any{"volume": map[string]string{
		"type": inst.VolumeType, "original_size": strconv.Itoa(inst.VolumeSize), "target_size": strconv.Itoa(opt.Size),
	}}
	return s.begin(ctx, t, id, jobEnlarge, StatusModifying, Pending{Kind: taskEnlarge, Size: opt.Size}, entities, StatusActive)
}

var backupNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_\-]{3,63}$`)

// emptyBackupKB is the size reported for a backup. With no data behind
// an instance, every backup is that of a fresh database.
const emptyBackupKB = 2048

// CreateBackup starts a manual backup of a running instance. The
// instance shows BACKING UP until the backup completes.
func (s *Service) CreateBackup(ctx context.Context, t Tenant, opt CreateBackupOption) (Backup, error) {
	if opt.InstanceID == "" {
		return Backup{}, errInvalid("instance_id is required")
	}
	if !backupNameRE.MatchString(opt.Name) {
		return Backup{}, errInvalid("The backup name must be 4 to 64 characters, start with a letter, and contain only letters, digits, hyphens and underscores.")
	}
	if utf8.RuneCountInString(opt.Description) > 256 {
		return Backup{}, errInvalid("The backup description can have at most 256 characters.")
	}
	for _, db := range opt.Databases {
		if db.Name == "" {
			return Backup{}, errInvalid("databases must name each database")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	inst, err := s.GetInstance(ctx, t, opt.InstanceID)
	if err != nil {
		return Backup{}, err
	}
	b := Backup{
		ID: s.ids.Hex32() + "br01", InstanceID: inst.ID, Name: opt.Name, Description: opt.Description,
		Databases: opt.Databases, BeginTime: stamp(s.now()), Status: BackupBuilding, Type: BackupManual,
		Size: emptyBackupKB, Datastore: Datastore{Type: inst.Engine, Version: inst.Version},
	}
	// The record exists before the operation is scheduled, so even an
	// instant completion finds it.
	if err := s.backups(t).Create(ctx, b.ID, b); err != nil {
		return Backup{}, err
	}
	if _, err := s.begin(ctx, t, inst.ID, jobBackup, StatusBackingUp,
		Pending{Kind: taskBackup, Backup: b.ID, Final: StatusActive}, nil, StatusActive); err != nil {
		if derr := s.backups(t).Delete(ctx, b.ID); derr != nil {
			s.log.ErrorContext(ctx, "removing a refused backup failed", "backup_id", b.ID, "error", derr)
		}
		return Backup{}, err
	}
	return b, nil
}

// finishBackup records the outcome of a backup.
func (s *Service) finishBackup(ctx context.Context, t Tenant, id string, fault error) {
	end := stamp(s.now())
	_, err := s.backups(t).Update(ctx, id, func(b *Backup) error {
		b.Status, b.EndTime = BackupCompleted, end
		if fault != nil {
			b.Status = BackupFailed
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "closing an RDS backup failed", "backup_id", id, "error", err)
	}
}

// ListBackups returns an instance's backups, newest first. The instance
// need not exist any more: manual backups outlive it.
func (s *Service) ListBackups(ctx context.Context, t Tenant, instanceID, backupID, backupType, status string) ([]Backup, error) {
	all, err := s.backups(t).List(ctx, func(b Backup) bool {
		eq := func(want, got string) bool { return want == "" || want == got }
		return b.InstanceID == instanceID && eq(backupID, b.ID) && eq(backupType, b.Type) && eq(status, b.Status)
	})
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all, nil
}

// DeleteBackup removes a completed or failed manual backup.
func (s *Service) DeleteBackup(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.backups(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errBackupNotFound(id)
	}
	if err != nil {
		return err
	}
	if b.Status == BackupBuilding {
		return errBackupStatus(id, b.Status)
	}
	return s.backups(t).Delete(ctx, id)
}
