package rds

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/zones"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// Lifecycle task kinds, matched by fault injection.
const (
	taskCreate = "rds.instance.create"
	taskDelete = "rds.instance.delete"
)

// Job names. Only creation's is documented; the others follow it.
const (
	jobCreate = "CreateMysqlInstance"
	jobDelete = "DeleteInstance"
)

// Volume types the API accepts for new instances.
var volumeTypes = []string{"ULTRAHIGH", "CLOUDSSD", "ESSD", "ESSD2"}

const (
	defaultBackupStart = "02:00-03:00"
	defaultKeepDays    = 7
	maintenanceWindow  = "02:00-06:00"
	maxTags            = 20
	dbUser             = "root"
)

// backupWindowRE: "hh:mm-HH:MM" with minutes on a quarter hour.
var backupWindowRE = regexp.MustCompile(`^([01]\d|2[0-3]):(00|15|30|45)-([01]\d|2[0-3]):(00|15|30|45)$`)

// checkBackupWindow enforces that the window is one hour long and the
// two minute parts are equal.
func checkBackupWindow(w string) bool {
	m := backupWindowRE.FindStringSubmatch(w)
	if m == nil || m[2] != m[4] {
		return false
	}
	start, _ := strconv.Atoi(m[1])
	end, _ := strconv.Atoi(m[3])
	return end == (start+1)%24
}

// plan is a validated create request.
type plan struct {
	engine   Engine
	flavor   FlavorSpec
	zones    []string
	port     int
	repl     string
	start    string
	keepDays int
}

func (s *Service) validate(ctx context.Context, t Tenant, opt CreateInstanceOption) (plan, error) {
	var p plan

	// Features that are not emulated are reported as gaps.
	switch {
	case opt.ReplicaOfID != nil:
		return p, errNotImplemented("CreateInstance of a read replica (replica_of_id)")
	case opt.RestorePoint != nil:
		return p, errNotImplemented("CreateInstance from a backup (restore_point)")
	case opt.DryRun != nil && *opt.DryRun:
		return p, errNotImplemented("CreateInstance with dry_run")
	case opt.Count != nil && *opt.Count != 1:
		return p, errNotImplemented("CreateInstance with count greater than 1")
	case opt.ChargeInfo != nil && opt.ChargeInfo.ChargeMode != "" && opt.ChargeInfo.ChargeMode != "postPaid":
		return p, errNotImplemented("yearly/monthly instances (charge_mode prePaid)")
	}

	if opt.Datastore == nil || opt.Datastore.Type == "" {
		return p, errInvalid("datastore.type is required")
	}
	if unemulated(opt.Datastore.Type) {
		return p, errNotImplemented("the " + opt.Datastore.Type + " engine")
	}
	engine, ok := engineNamed(opt.Datastore.Type)
	if !ok || !slices.Contains(engine.Versions, opt.Datastore.Version) {
		return p, errEngineUnsupported(opt.Datastore.Type, opt.Datastore.Version)
	}
	p.engine = engine

	if !engine.nameRE.MatchString(opt.Name) {
		return p, errName("The DB instance name must be 4 to 64 characters, start with a letter, and contain only letters, digits, hyphens and underscores%s.",
			map[bool]string{true: " and periods", false: ""}[engine.Code == "mysql"])
	}
	if opt.Password != nil {
		if err := engine.checkPassword(*opt.Password); err != nil {
			return p, err
		}
	}
	port, err := engine.parsePort(opt.Port)
	if err != nil {
		return p, err
	}
	p.port = port

	// Specification and HA.
	if opt.FlavorRef == "" {
		return p, errInvalid("flavor_ref is required")
	}
	flavor, ok := flavorByCode(opt.FlavorRef)
	if !ok {
		return p, errFlavorNotFound(opt.FlavorRef)
	}
	if flavor.Engine.Name != engine.Name {
		return p, errFlavorInvalid("The specification %s is not for %s.", flavor.Code, engine.Name)
	}
	wantHA := opt.HA != nil && opt.HA.Mode != ""
	if wantHA && !strings.EqualFold(opt.HA.Mode, "ha") {
		return p, errInvalid("ha.mode must be Ha")
	}
	if wantHA != (flavor.Mode == ModeHA) {
		return p, errFlavorInvalid("The specification %s is for %s instances; the request is for a %s instance.",
			flavor.Code, strings.ToLower(flavor.Mode), map[bool]string{true: "primary/standby", false: "single"}[wantHA])
	}
	p.flavor = flavor
	if wantHA {
		p.repl = engine.ReplicationModes[0]
		if opt.HA.ReplicationMode != "" {
			if !slices.Contains(engine.ReplicationModes, opt.HA.ReplicationMode) {
				return p, errInvalid("ha.replication_mode must be one of %s for %s", strings.Join(engine.ReplicationModes, ", "), engine.Name)
			}
			p.repl = opt.HA.ReplicationMode
		}
	}

	// Storage.
	if opt.Volume == nil {
		return p, errInvalid("volume is required")
	}
	if !slices.Contains(volumeTypes, opt.Volume.Type) {
		return p, errInvalid("volume.type must be one of %s", strings.Join(volumeTypes, ", "))
	}
	if err := engine.checkVolume(opt.Volume.Size); err != nil {
		return p, err
	}

	// Placement: one zone per node.
	if opt.Region != t.Region {
		return p, errInvalid("region %q is not the region of this endpoint (%s)", opt.Region, t.Region)
	}
	p.zones = strings.Split(opt.AvailabilityZone, ",")
	want := 1
	if wantHA {
		want = 2
	}
	if len(p.zones) != want {
		return p, errZone(opt.AvailabilityZone)
	}
	for _, az := range p.zones {
		if !zones.Exists(t.Region, az) {
			return p, errZone(az)
		}
	}

	// Backups.
	p.start, p.keepDays = defaultBackupStart, defaultKeepDays
	if b := opt.BackupStrategy; b != nil {
		if !checkBackupWindow(b.StartTime) {
			return p, errInvalid("backup_strategy.start_time must be a one-hour window such as 08:15-09:15")
		}
		p.start = b.StartTime
		if b.KeepDays != nil {
			if *b.KeepDays < 1 || *b.KeepDays > engine.MaxKeepDays {
				return p, errInvalid("backup_strategy.keep_days must be between 1 and %d", engine.MaxKeepDays)
			}
			p.keepDays = *b.KeepDays
		}
	}

	if len(opt.Tags) > maxTags {
		return p, errInvalid("an instance can have at most %d tags", maxTags)
	}
	seen := map[string]bool{}
	for _, tag := range opt.Tags {
		if tag.Key == "" || strings.HasPrefix(tag.Key, "_sys_") || len(tag.Key) > 128 || len(tag.Value) > 255 || seen[tag.Key] {
			return p, errInvalid("tag keys must be unique, 1 to 128 characters and not start with _sys_; values at most 255 characters")
		}
		seen[tag.Key] = true
	}

	// Network references, checked against the VPC service.
	var subnet vpc.Subnet
	if _, err := s.network.GetVPC(ctx, t.vpc(), opt.VPCID); err != nil {
		return p, notFoundAs(err, errVPCNotFound(opt.VPCID))
	}
	subnet, err = s.network.GetSubnet(ctx, t.vpc(), opt.SubnetID)
	if err != nil {
		return p, notFoundAs(err, errSubnetNotFound(opt.SubnetID, opt.VPCID))
	}
	if subnet.VPCID != opt.VPCID {
		return p, errSubnetNotFound(opt.SubnetID, opt.VPCID)
	}
	if _, err := s.network.GetSecurityGroup(ctx, t.vpc(), opt.SecurityGroupID); err != nil {
		return p, notFoundAs(err, errSecurityGroupNotFound(opt.SecurityGroupID))
	}
	return p, nil
}

// notFoundAs maps an API error from another service (the resource is
// missing or the ID malformed) to this service's error; anything else is
// an internal failure and returned as is.
func notFoundAs(err error, mapped *apierr.Error) error {
	var e *apierr.Error
	if errors.As(err, &e) {
		return mapped
	}
	return err
}

func (e Engine) checkVolume(size int) error {
	if size%10 != 0 {
		return errVolumeMultiple
	}
	if size < e.MinVolume || size > e.MaxVolume {
		return errVolumeRange(e.MinVolume, e.MaxVolume)
	}
	return nil
}

// CreateInstance creates an instance in status BUILD and returns it with
// the job that tracks it. It becomes ACTIVE after the lifecycle delay.
func (s *Service) CreateInstance(ctx context.Context, t Tenant, opt CreateInstanceOption) (Instance, Job, error) {
	p, err := s.validate(ctx, t, opt)
	if err != nil {
		return Instance{}, Job{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.instances(t).List(ctx, nil)
	if err != nil {
		return Instance{}, Job{}, err
	}
	if len(existing) >= s.maxInstances {
		return Instance{}, Job{}, errQuota(s.maxInstances)
	}
	if slices.ContainsFunc(existing, func(i Instance) bool { return i.Name == opt.Name }) {
		return Instance{}, Job{}, errNameExists(opt.Name)
	}

	now := s.now().UTC()
	inst := Instance{
		ID:              s.ids.Hex32() + "in01",
		Name:            opt.Name,
		Status:          StatusBuild,
		Engine:          p.engine.Name,
		Version:         opt.Datastore.Version,
		Mode:            p.flavor.Mode,
		ReplicationMode: p.repl,
		FlavorRef:       p.flavor.Code,
		VolumeType:      opt.Volume.Type,
		VolumeSize:      opt.Volume.Size,
		Region:          t.Region,
		Zones:           p.zones,
		VPCID:           opt.VPCID,
		SubnetID:        opt.SubnetID,
		SecurityGroupID: opt.SecurityGroupID,
		Port:            p.port,
		BackupStart:     p.start,
		KeepDays:        p.keepDays,
		EnterpriseProj:  "0",
		Tags:            append([]Tag{}, opt.Tags...),
		Created:         now,
		Updated:         now,
	}
	if opt.ConfigurationID != nil {
		inst.ConfigurationID = *opt.ConfigurationID
	}
	if opt.EnterpriseProjectID != nil && *opt.EnterpriseProjectID != "" {
		inst.EnterpriseProj = *opt.EnterpriseProjectID
	}
	if opt.TimeZone != nil {
		inst.TimeZone = *opt.TimeZone
	}
	for range p.zones {
		inst.NodeIDs = append(inst.NodeIDs, s.ids.Hex32()+"no01")
	}

	ip, err := s.network.AllocateIP(ctx, t.vpc(), opt.SubnetID, "rds:"+inst.ID, "")
	switch {
	case errors.Is(err, vpc.ErrSubnetFull):
		return Instance{}, Job{}, errInvalid("The subnet %s has no free IP address.", opt.SubnetID)
	case errors.Is(err, vpc.ErrSubnetNotFound):
		return Instance{}, Job{}, errSubnetNotFound(opt.SubnetID, opt.VPCID)
	case err != nil:
		return Instance{}, Job{}, err
	}
	inst.PrivateIP = ip

	job := s.newJob(jobCreate, inst)
	job.Entities = map[string]any{"instance": map[string]any{
		"endpoint": ip + ":" + strconv.Itoa(inst.Port), "type": inst.Mode,
		"datastore": map[string]string{"type": inst.Engine, "version": inst.Version},
	}}
	inst.Pending = &Pending{Kind: taskCreate, JobID: job.ID, Final: StatusActive}
	if err := s.instances(t).Create(ctx, inst.ID, inst); err != nil {
		s.releaseIP(ctx, t, inst)
		return Instance{}, Job{}, err
	}
	if err := s.jobs(t).Create(ctx, job.ID, job); err != nil {
		return Instance{}, Job{}, err
	}
	s.schedule(t, inst.ID, *inst.Pending)
	return inst, job, nil
}

func (s *Service) releaseIP(ctx context.Context, t Tenant, inst Instance) {
	if inst.PrivateIP == "" {
		return
	}
	if err := s.network.ReleaseIP(ctx, t.vpc(), inst.SubnetID, inst.PrivateIP); err != nil {
		s.log.ErrorContext(ctx, "releasing an RDS address failed", "instance_id", inst.ID, "error", err)
	}
}

func (s *Service) newJob(name string, inst Instance) Job {
	return Job{
		ID:       s.ids.UUID(),
		Name:     name,
		Status:   JobRunning,
		Created:  stamp(s.now()),
		Instance: JobInstance{ID: inst.ID, Name: inst.Name},
	}
}

// schedule queues the completion of an instance's pending operation.
func (s *Service) schedule(t Tenant, id string, op Pending) {
	s.engine.Schedule(lifecycle.Task{
		Key:  id,
		Kind: op.Kind,
		Run:  func(ctx context.Context, fault error) { s.finish(ctx, t, id, op, fault) },
	})
}

// finish completes a pending operation, or fails it on an injected fault.
func (s *Service) finish(ctx context.Context, t Tenant, id string, op Pending, fault error) {
	if op.Kind == taskDelete && fault == nil {
		inst, err := s.instances(t).Get(ctx, id)
		if err == nil {
			s.releaseIP(ctx, t, inst)
			err = s.instances(t).Delete(ctx, id)
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.ErrorContext(ctx, "deleting an RDS instance failed", "instance_id", id, "error", err)
			s.endJob(ctx, t, op.JobID, err)
			return
		}
		s.endJob(ctx, t, op.JobID, nil)
		return
	}

	now := s.now().UTC()
	_, err := s.instances(t).Update(ctx, id, func(inst *Instance) error {
		inst.Pending = nil
		inst.Updated = now
		switch {
		case fault != nil && op.Kind == taskCreate:
			inst.Status = StatusCreateFail
		case fault != nil:
			inst.Status = StatusFailed
		default:
			inst.Status = op.Final
			s.apply(inst, op)
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "completing an RDS operation failed", "instance_id", id, "kind", op.Kind, "error", err)
	}
	if errors.Is(err, store.ErrNotFound) && fault == nil {
		fault = errors.New("the DB instance no longer exists")
	}
	s.endJob(ctx, t, op.JobID, fault)
}

// apply makes the lasting change of a completed operation. Operations
// added later extend it.
func (s *Service) apply(inst *Instance, op Pending) {
	if op.Flavor != "" {
		inst.FlavorRef = op.Flavor
	}
	if op.Size != 0 {
		inst.VolumeSize = op.Size
	}
}

func (s *Service) endJob(ctx context.Context, t Tenant, jobID string, fault error) {
	end := stamp(s.now())
	_, err := s.jobs(t).Update(ctx, jobID, func(j *Job) error {
		j.Ended, j.Status, j.Process = end, JobCompleted, "100%"
		if fault != nil {
			j.Status, j.FailReason, j.Process = JobFailed, fault.Error(), ""
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "closing an RDS job failed", "job_id", jobID, "error", err)
	}
}

// GetJob returns a job of the project.
func (s *Service) GetJob(ctx context.Context, t Tenant, id string) (Job, error) {
	job, err := s.jobs(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return Job{}, errJobNotFound(id)
	}
	return job, err
}

// GetInstance returns an instance of the project.
func (s *Service) GetInstance(ctx context.Context, t Tenant, id string) (Instance, error) {
	inst, err := s.instances(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return Instance{}, errInstanceNotFound(id)
	}
	return inst, err
}

// matchName implements the API's matching of id and name: exact, or a
// substring when the filter starts with "*".
func matchName(filter, value string) bool {
	if filter == "" {
		return true
	}
	if rest, fuzzy := strings.CutPrefix(filter, "*"); fuzzy {
		return strings.Contains(value, rest)
	}
	return filter == value
}

// ListInstances returns the project's instances matching f, in creation
// order.
func (s *Service) ListInstances(ctx context.Context, t Tenant, f ListInstancesFilter) ([]Instance, error) {
	return s.instances(t).List(ctx, func(i Instance) bool {
		eq := func(want, got string) bool { return want == "" || want == got }
		if !matchName(f.ID, i.ID) || !matchName(f.Name, i.Name) || !eq(f.Type, i.Mode) || !eq(f.Engine, i.Engine) ||
			!eq(f.VPCID, i.VPCID) || !eq(f.SubnetID, i.SubnetID) || !eq(f.EnterpriseProjectID, i.EnterpriseProj) {
			return false
		}
		for _, want := range f.Tags {
			if !slices.ContainsFunc(i.Tags, func(t Tag) bool { return t.Key == want.Key && (want.Value == "" || t.Value == want.Value) }) {
				return false
			}
		}
		return true
	})
}

// begin starts an operation on an instance: it checks the instance is
// idle and in a status the operation accepts, records the pending
// operation and returns the job. The caller must hold s.mu.
func (s *Service) begin(ctx context.Context, t Tenant, id, jobName string, during string, op Pending, accept ...string) (Job, error) {
	inst, err := s.GetInstance(ctx, t, id)
	if err != nil {
		return Job{}, err
	}
	if inst.Pending != nil || inst.Status == StatusBuild {
		return Job{}, errBusy(id)
	}
	if len(accept) > 0 && !slices.Contains(accept, inst.Status) {
		return Job{}, errStatus(id, inst.Status)
	}
	job := s.newJob(jobName, inst)
	op.JobID = job.ID
	if op.Final == "" {
		op.Final = inst.Status
	}
	if err := s.jobs(t).Create(ctx, job.ID, job); err != nil {
		return Job{}, err
	}
	now := s.now().UTC()
	if _, err := s.instances(t).Update(ctx, id, func(i *Instance) error {
		i.Pending, i.Updated = &op, now
		if during != "" {
			i.Status = during
		}
		return nil
	}); err != nil {
		return Job{}, err
	}
	s.schedule(t, id, op)
	return job, nil
}

// DeleteInstance starts deleting an instance and returns the job.
func (s *Service) DeleteInstance(ctx context.Context, t Tenant, id string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.begin(ctx, t, id, jobDelete, "", Pending{Kind: taskDelete})
}

// view renders the API form of an instance.
func (inst Instance) view() InstanceResponse {
	flavor, _ := flavorByCode(inst.FlavorRef)
	r := InstanceResponse{
		ID: inst.ID, Status: inst.Status, Name: inst.Name, Port: inst.Port, Type: inst.Mode, Region: inst.Region,
		Datastore: Datastore{Type: inst.Engine, Version: inst.Version},
		Created:   stamp(inst.Created), Updated: stamp(inst.Updated),
		Volume:              Volume{Type: inst.VolumeType, Size: inst.VolumeSize},
		PublicIPs:           []string{},
		DBUserName:          dbUser,
		VPCID:               inst.VPCID,
		SubnetID:            inst.SubnetID,
		SecurityGroupID:     inst.SecurityGroupID,
		FlavorRef:           inst.FlavorRef,
		CPU:                 strconv.Itoa(flavor.VCPUs),
		Mem:                 strconv.Itoa(flavor.RAMGB),
		ChargeInfo:          ChargeInfo{ChargeMode: "postPaid"},
		BackupStrategy:      BackupStrategyOut{StartTime: inst.BackupStart, KeepDays: inst.KeepDays},
		MaintenanceWindow:   maintenanceWindow,
		RelatedInstance:     []RelatedInstance{},
		EnterpriseProjectID: inst.EnterpriseProj,
		TimeZone:            inst.TimeZone,
		Tags:                append([]Tag{}, inst.Tags...),
		PrivateIPs:          []string{},
	}
	if inst.PrivateIP != "" {
		r.PrivateIPs = []string{inst.PrivateIP}
	}
	if inst.Mode == ModeHA {
		r.HA = &HAResponse{ReplicationMode: inst.ReplicationMode}
		r.SwitchStrategy = "reliability"
	}
	nodeStatus := inst.Status
	switch inst.Status {
	case StatusBuild, StatusCreateFail, StatusFailed:
	default:
		nodeStatus = StatusActive
	}
	for i, id := range inst.NodeIDs {
		role := "master"
		if i > 0 {
			role = "slave"
		}
		r.Nodes = append(r.Nodes, Node{
			ID: id, Name: inst.Name + "_node" + strconv.Itoa(i), Role: role, Status: nodeStatus, AvailabilityZone: inst.Zones[i],
		})
	}
	return r
}

// created renders the response item of a create request.
func (inst Instance) created() CreatedInstance {
	c := CreatedInstance{
		ID: inst.ID, Name: inst.Name, Status: inst.Status,
		Datastore:           Datastore{Type: inst.Engine, Version: inst.Version},
		ConfigurationID:     inst.ConfigurationID,
		Port:                strconv.Itoa(inst.Port),
		EnterpriseProjectID: inst.EnterpriseProj,
		FlavorRef:           inst.FlavorRef,
		Volume:              Volume{Type: inst.VolumeType, Size: inst.VolumeSize},
		Region:              inst.Region,
		AvailabilityZone:    strings.Join(inst.Zones, ","),
		VPCID:               inst.VPCID,
		SubnetID:            inst.SubnetID,
		SecurityGroupID:     inst.SecurityGroupID,
		ChargeInfo:          ChargeInfo{ChargeMode: "postPaid"},
	}
	keep := inst.KeepDays
	c.BackupStrategy = BackupStrategy{StartTime: inst.BackupStart, KeepDays: &keep}
	if inst.Mode == ModeHA {
		c.HA = &HA{Mode: ModeHA, ReplicationMode: inst.ReplicationMode}
	}
	return c
}
