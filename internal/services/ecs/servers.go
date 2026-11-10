package ecs

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/ims"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// kindServer is the store kind of servers.
const kindServer = "ecs.server"

// Lifecycle task kinds, matched by fault injection.
const (
	taskServerBuild  = "ecs.server.build"
	taskServerDelete = "ecs.server.delete"
)

// Job types, as the real API reports them.
const (
	jobCreateServer       = "createServer"
	jobCreateSingleServer = "createSingleServer"
	jobDeleteServer       = "deleteServer"
	jobDeleteSingleServer = "deleteSingleServer"
)

// Limits of a create request.
const (
	maxCreateCount = 500
	maxNICs        = 12
	maxDataVolumes = 23
	maxTags        = 10
	maxNameLen     = 64
	maxDescLen     = 85
	maxRootGB      = 1024
	minDataGB      = 10
	maxDataGB      = 32768
)

var (
	serverNameRE = regexp.MustCompile(`^[\p{L}\p{N}_.\-]+$`)
	uuidRE       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// volumeTypes are the EVS disk types the API accepts.
	volumeTypes = map[string]bool{
		"SATA": true, "SAS": true, "GPSSD": true, "SSD": true, "ESSD": true, "GPSSD2": true, "ESSD2": true,
	}
)

func (s *Service) servers(t Tenant) store.Collection[Server] {
	return store.Of[Server](s.store, store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindServer})
}

func (t Tenant) vpc() vpc.Tenant { return vpc.Tenant{Region: t.Region, ProjectID: t.ProjectID} }
func (t Tenant) ims() ims.Tenant { return ims.Tenant{Region: t.Region, ProjectID: t.ProjectID} }

// plan is a validated create request: everything resolved, nothing
// written yet.
type plan struct {
	opt     CreateServerOption
	count   int
	flavor  FlavorSpec
	image   ims.Image
	az      string
	subnets []vpc.Subnet // one per NIC
	groups  []string
	rootGB  int
	tags    []string
}

func checkServerName(name string) error {
	switch {
	case name == "" || !serverNameRE.MatchString(name):
		return errNameInvalid
	case utf8.RuneCountInString(name) > maxNameLen:
		return errNameTooLong
	}
	return nil
}

// checkPassword enforces the documented complexity rule.
func checkPassword(p string) error {
	if n := utf8.RuneCountInString(p); n < 8 || n > 26 {
		return errPassword
	}
	var upper, lower, digit, special int
	for _, r := range p {
		switch {
		case unicode.IsUpper(r):
			upper = 1
		case unicode.IsLower(r):
			lower = 1
		case unicode.IsDigit(r):
			digit = 1
		case strings.ContainsRune("!@$%^-_=+[{}]:,./?~#*", r):
			special = 1
		default:
			return errPassword
		}
	}
	if upper+lower+digit+special < 3 {
		return errPassword
	}
	return nil
}

// buildTags merges the two tag forms of a create request into
// "key=value" strings ("key" alone for an empty value).
func buildTags(opt CreateServerOption) ([]string, error) {
	if len(opt.ServerTags) > 0 && len(opt.Tags) > 0 {
		return nil, errTag("Ecs.0906", "tags and server_tags cannot be used together.")
	}
	out := []string{}
	keys := map[string]bool{}
	add := func(key, value string) error {
		if key == "" || utf8.RuneCountInString(key) > 36 || utf8.RuneCountInString(value) > 43 {
			return errTag("Ecs.0906", "The tag %q is invalid: a key has 1 to 36 characters and a value at most 43.", key)
		}
		if strings.ContainsAny(key+value, "=*<>\\,|/") {
			return errTag("Ecs.0907", "The tag %q contains characters that are not allowed.", key)
		}
		if keys[key] {
			return errTag("Ecs.0908", "The tag key %q is repeated.", key)
		}
		keys[key] = true
		if value == "" {
			out = append(out, key)
		} else {
			out = append(out, key+"="+value)
		}
		return nil
	}
	for _, tag := range opt.ServerTags {
		if err := add(tag.Key, tag.Value); err != nil {
			return nil, err
		}
	}
	for _, tag := range opt.Tags {
		// The older form writes a pair as "key.value".
		key, value, _ := strings.Cut(tag, ".")
		if err := add(key, value); err != nil {
			return nil, err
		}
	}
	if len(out) > maxTags {
		return nil, errTooManyTags
	}
	return out, nil
}

// validate resolves and checks everything a create request refers to.
func (s *Service) validate(ctx context.Context, t Tenant, opt CreateServerOption) (plan, error) {
	p := plan{opt: opt, count: 1}

	if err := checkServerName(opt.Name); err != nil {
		return p, err
	}
	if utf8.RuneCountInString(opt.Description) > maxDescLen || strings.ContainsAny(opt.Description, "<>") {
		return p, errInvalidRequest("description can have at most %d characters and no angle brackets", maxDescLen)
	}
	if opt.Count != nil {
		p.count = *opt.Count
	}
	if p.count < 1 {
		return p, errInvalidRequest("count must be at least 1")
	}
	if p.count > maxCreateCount {
		return p, errTooManyServers(p.count)
	}
	if opt.AdminPass != nil {
		if err := checkPassword(*opt.AdminPass); err != nil {
			return p, err
		}
	}

	// Flavor and image.
	if opt.FlavorRef == "" {
		return p, errInvalidRequest("flavorRef is required")
	}
	flavor, ok := s.FlavorByName(opt.FlavorRef)
	if !ok {
		return p, errFlavorNotFound(opt.FlavorRef)
	}
	p.flavor = flavor
	if opt.ImageRef == "" {
		return p, errInvalidRequest("imageRef is required")
	}
	image, err := s.images.GetImage(ctx, t.ims(), opt.ImageRef)
	if isAPIError(err) {
		return p, errImageNotFound(opt.ImageRef)
	}
	if err != nil {
		return p, err
	}
	if image.Status != ims.StatusActive {
		return p, errImageNotActive(image.ID, image.Status)
	}
	if (image.SupportArm == "true") != (flavor.Arch == ArchARM) {
		return p, errImageFlavorMismatch(image.Name, flavor.Name)
	}
	p.image = image

	// Availability zone: the first one when the client leaves it open.
	p.az = opt.AvailabilityZone
	if p.az == "" {
		p.az = Zones(t.Region)[0]
	} else if !ZoneExists(t.Region, p.az) {
		return p, errInvalidRequest("availability_zone %q does not exist in region %s", p.az, t.Region)
	}

	// Disks.
	if opt.RootVolume == nil {
		return p, errInvalidRequest("root_volume is required")
	}
	if !volumeTypes[opt.RootVolume.VolumeType] {
		return p, errDiskType(opt.RootVolume.VolumeType)
	}
	p.rootGB = image.MinDisk
	if opt.RootVolume.Size != nil {
		p.rootGB = *opt.RootVolume.Size
		if p.rootGB < image.MinDisk || p.rootGB > maxRootGB {
			return p, errInvalidRequest("root_volume size must be between %d (the image's minimum) and %d GB", image.MinDisk, maxRootGB)
		}
	}
	if len(opt.DataVolumes) > maxDataVolumes {
		return p, errTooManyDisks
	}
	for _, dv := range opt.DataVolumes {
		if !volumeTypes[dv.VolumeType] {
			return p, errDiskType(dv.VolumeType)
		}
		if dv.Size == nil || *dv.Size < minDataGB || *dv.Size > maxDataGB {
			return p, errInvalidRequest("data_volumes size is required and must be between %d and %d GB", minDataGB, maxDataGB)
		}
	}

	// Network.
	if opt.VPCID == "" {
		return p, errInvalidRequest("vpcid is required")
	}
	if _, err := s.network.GetVPC(ctx, t.vpc(), opt.VPCID); isAPIError(err) {
		return p, errNetworkInvalid("The VPC %s does not exist.", opt.VPCID)
	} else if err != nil {
		return p, err
	}
	if len(opt.NICs) == 0 {
		return p, errInvalidRequest("nics must contain at least one NIC")
	}
	if len(opt.NICs) > maxNICs {
		return p, errTooManyNICs
	}
	seenSubnet := map[string]bool{}
	for _, nic := range opt.NICs {
		if nic.SubnetID == "" {
			return p, errInvalidRequest("nics.subnet_id is required")
		}
		if nic.IPAddress != "" && p.count > 1 {
			return p, errInvalidRequest("ip_address cannot be specified when count is greater than 1")
		}
		if seenSubnet[nic.SubnetID] {
			return p, errInvalidRequest("the subnet %s is used by more than one NIC", nic.SubnetID)
		}
		seenSubnet[nic.SubnetID] = true
		subnet, err := s.network.GetSubnet(ctx, t.vpc(), nic.SubnetID)
		if isAPIError(err) {
			return p, errSubnetNotFound(nic.SubnetID)
		}
		if err != nil {
			return p, err
		}
		if subnet.VPCID != opt.VPCID {
			return p, errSubnetNotInVPC(nic.SubnetID, opt.VPCID)
		}
		p.subnets = append(p.subnets, subnet)
	}

	// Security groups: the project's default group when none is given.
	if len(opt.SecurityGroups) == 0 {
		defaults, err := s.network.ListSecurityGroups(ctx, t.vpc(), vpc.ListSecurityGroupsFilter{Names: []string{"default"}})
		if err != nil {
			return p, err
		}
		for _, g := range defaults {
			p.groups = append(p.groups, g.ID)
		}
	}
	for _, g := range opt.SecurityGroups {
		if _, err := s.network.GetSecurityGroup(ctx, t.vpc(), g.ID); isAPIError(err) {
			return p, errNetworkInvalid("The security group %s does not exist.", g.ID)
		} else if err != nil {
			return p, err
		}
		if !slices.Contains(p.groups, g.ID) {
			p.groups = append(p.groups, g.ID)
		}
	}

	if ep := enterpriseProject(opt); ep != "0" && !uuidRE.MatchString(ep) {
		return p, errInvalidRequest("enterprise_project_id %q is invalid", ep)
	}
	if p.tags, err = buildTags(opt); err != nil {
		return p, err
	}
	return p, nil
}

func enterpriseProject(opt CreateServerOption) string {
	if opt.ExtendParam != nil && opt.ExtendParam.EnterpriseProjectID != "" {
		return opt.ExtendParam.EnterpriseProjectID
	}
	return "0"
}

func isAPIError(err error) bool {
	var e *apierr.Error
	return errors.As(err, &e)
}

// usage returns the project's server and vCPU consumption.
func (s *Service) usage(ctx context.Context, t Tenant) (servers, vcpus int, err error) {
	all, err := s.servers(t).List(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	for _, srv := range all {
		if f, ok := s.FlavorByName(srv.Flavor); ok {
			vcpus += f.VCPUs
		}
	}
	return len(all), vcpus, nil
}

// CreateServers validates the request, creates count servers in status
// BUILD and returns the job that tracks them. Each server becomes ACTIVE
// after the lifecycle delay. Nothing is created if any part fails.
func (s *Service) CreateServers(ctx context.Context, t Tenant, opt CreateServerOption) (Job, []string, error) {
	p, err := s.validate(ctx, t, opt)
	if err != nil {
		return Job{}, nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	used, usedCPUs, err := s.usage(ctx, t)
	if err != nil {
		return Job{}, nil, err
	}
	if used+p.count > s.quota.Servers {
		return Job{}, nil, errQuota("ECS", p.count, used, s.quota.Servers)
	}
	if want := p.count * p.flavor.VCPUs; usedCPUs+want > s.quota.VCPUs {
		return Job{}, nil, errQuota("vCPU", want, usedCPUs, s.quota.VCPUs)
	}

	now := s.now().UTC().Format(timeLayout)
	reservation := "r-" + s.ids.Hex32()[:8]
	servers := make([]Server, 0, p.count)

	// On any failure, give back every address taken so far.
	rollback := func() {
		for _, srv := range servers {
			s.releaseAddresses(ctx, t, srv)
		}
	}

	for i := range p.count {
		srv := Server{
			ID:                  s.ids.UUID(),
			Name:                opt.Name,
			Description:         opt.Description,
			Status:              StatusBuild,
			TaskState:           "spawning",
			Flavor:              p.flavor.Name,
			ImageID:             p.image.ID,
			ImageName:           p.image.Name,
			ImageType:           p.image.ImageType,
			OSType:              p.image.OSType,
			OSBit:               p.image.OSBit,
			VPCID:               opt.VPCID,
			AvailabilityZone:    p.az,
			SecurityGroups:      p.groups,
			KeyName:             opt.KeyName,
			UserData:            opt.UserData,
			Metadata:            opt.Metadata,
			Tags:                p.tags,
			EnterpriseProjectID: enterpriseProject(opt),
			TenantID:            t.ProjectID,
			UserID:              t.ProjectID,
			HostID:              s.ids.Hex32() + s.ids.Hex32()[:24],
			InstanceName:        "instance-" + s.ids.Hex32()[:8],
			ReservationID:       reservation,
			LaunchIndex:         i,
			Created:             now,
			Updated:             now,
			RootVolume:          Volume{ID: s.ids.UUID(), Type: opt.RootVolume.VolumeType, SizeGB: p.rootGB, Device: "/dev/vda"},
		}
		if p.count > 1 {
			srv.Name = fmt.Sprintf("%s-%04d", opt.Name, i+1)
		}
		for n, dv := range opt.DataVolumes {
			srv.DataVolumes = append(srv.DataVolumes, Volume{
				ID: s.ids.UUID(), Type: dv.VolumeType, SizeGB: *dv.Size, Device: "/dev/vd" + string(rune('b'+n)),
			})
		}
		if len(opt.PublicIP) > 0 && string(opt.PublicIP) != "null" {
			srv.PublicIP = pseudoPublicIP(srv.ID)
		}
		servers = append(servers, srv)
		cur := &servers[len(servers)-1]

		for n, nic := range opt.NICs {
			ip, err := s.network.AllocateIP(ctx, t.vpc(), nic.SubnetID, "ecs:"+srv.ID, nic.IPAddress)
			if err != nil {
				rollback()
				return Job{}, nil, mapIPError(err, nic.IPAddress, p.subnets[n].ID)
			}
			mac := s.ids.Hex32()
			cur.NICs = append(cur.NICs, NIC{
				SubnetID: nic.SubnetID, PortID: s.ids.UUID(), IP: ip,
				MAC: fmt.Sprintf("fa:16:3e:%s:%s:%s", mac[0:2], mac[2:4], mac[4:6]),
			})
		}
	}

	ids := make([]string, 0, len(servers))
	for _, srv := range servers {
		if err := s.servers(t).Create(ctx, srv.ID, srv); err != nil {
			rollback()
			return Job{}, nil, err
		}
		ids = append(ids, srv.ID)
	}
	job, err := s.newJob(ctx, t, jobCreateServer, jobCreateSingleServer, ids)
	if err != nil {
		return Job{}, nil, err
	}
	for _, id := range ids {
		s.scheduleBuild(t, id, job.JobID)
	}
	return job, ids, nil
}

// mapIPError translates an address allocation failure to an ECS error.
func mapIPError(err error, ip, subnet string) error {
	switch {
	case errors.Is(err, vpc.ErrIPInUse):
		return errIPInUse(ip)
	case errors.Is(err, vpc.ErrIPNotUsable):
		return errIPNotInSubnet(ip, subnet)
	case errors.Is(err, vpc.ErrSubnetFull):
		return errSubnetFull(subnet)
	case errors.Is(err, vpc.ErrSubnetNotFound):
		return errSubnetNotFound(subnet)
	}
	return err
}

// pseudoPublicIP derives a stable address from the documentation range
// 198.51.100.0/24 for a server that asked for an elastic IP.
func pseudoPublicIP(serverID string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(serverID))
	return "198.51.100." + strconv.Itoa(int(h.Sum32()%254)+1)
}

func (s *Service) releaseAddresses(ctx context.Context, t Tenant, srv Server) {
	for _, nic := range srv.NICs {
		if err := s.network.ReleaseIP(ctx, t.vpc(), nic.SubnetID, nic.IP); err != nil {
			s.log.ErrorContext(ctx, "releasing private IP failed", "server_id", srv.ID, "ip", nic.IP, "error", err)
		}
	}
}

// scheduleBuild queues BUILD -> ACTIVE for one server.
func (s *Service) scheduleBuild(t Tenant, serverID, jobID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  serverID,
		Kind: taskServerBuild,
		Run: func(ctx context.Context, fault error) {
			now := s.now().UTC()
			failed := fault != nil
			_, err := s.servers(t).Update(ctx, serverID, func(srv *Server) error {
				srv.TaskState = ""
				srv.Updated = now.Format(timeLayout)
				srv.Status = StatusError
				if !failed {
					srv.Status = StatusActive
					srv.LaunchedAt = now.Format(usageTimeLayout)
				}
				return nil
			})
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "server build failed", "server_id", serverID, "error", err)
			}
			s.finishSubJob(ctx, t, jobID, serverID, fault)
		},
	})
}

// GetServer returns the stored record of a server.
func (s *Service) GetServer(ctx context.Context, t Tenant, id string) (Server, error) {
	srv, err := s.servers(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return Server{}, errServerNotFound(id)
	}
	return srv, err
}

// LookupServer implements ims.ServerLookup, so IMS can make images of
// servers.
func (s *Service) LookupServer(ctx context.Context, region, projectID, id string) (ims.Server, error) {
	srv, err := s.servers(Tenant{Region: region, ProjectID: projectID}).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return ims.Server{}, ims.ErrServerNotFound
	}
	if err != nil {
		return ims.Server{}, err
	}
	return ims.Server{ID: srv.ID, ImageID: srv.ImageID, SystemDiskGB: srv.RootVolume.SizeGB}, nil
}

// ListServers returns the project's servers that match f, in creation
// order.
func (s *Service) ListServers(ctx context.Context, t Tenant, f ListServersFilter) ([]Server, error) {
	return s.servers(t).List(ctx, f.matches)
}

func (f ListServersFilter) matches(srv Server) bool {
	eq := func(want, got string) bool { return want == "" || want == got }
	if !eq(f.Status, srv.Status) || !eq(f.Flavor, srv.Flavor) || !eq(f.ServerID, srv.ID) ||
		!eq(f.ReservationID, srv.ReservationID) || !eq(f.EnterpriseProjectID, srv.EnterpriseProjectID) {
		return false
	}
	if f.Name != "" && !strings.Contains(srv.Name, f.Name) {
		return false
	}
	if f.IP != "" && !slices.ContainsFunc(srv.NICs, func(n NIC) bool { return strings.HasPrefix(n.IP, f.IP) }) {
		return false
	}
	if f.IPEq != "" && !slices.ContainsFunc(srv.NICs, func(n NIC) bool { return n.IP == f.IPEq }) {
		return false
	}
	for _, tag := range f.Tags {
		if !hasTag(srv.Tags, tag) {
			return false
		}
	}
	for _, tag := range f.NotTags {
		if hasTag(srv.Tags, tag) {
			return false
		}
	}
	return true
}

// hasTag matches "key=value" exactly, or "key" against any value.
func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		key, _, _ := strings.Cut(tag, "=")
		if tag == want || key == want {
			return true
		}
	}
	return false
}

// DeleteServers starts deleting the given servers and returns the job
// that tracks it. Every server must exist; none is touched otherwise.
func (s *Service) DeleteServers(ctx context.Context, t Tenant, ids []string) (Job, error) {
	if len(ids) == 0 {
		return Job{}, errInvalidRequest("servers must contain at least one ECS")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return Job{}, errInvalidRequest("the ECS %s is listed more than once", id)
		}
		seen[id] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, id := range ids {
		if _, err := s.GetServer(ctx, t, id); err != nil {
			return Job{}, err
		}
	}
	job, err := s.newJob(ctx, t, jobDeleteServer, jobDeleteSingleServer, ids)
	if err != nil {
		return Job{}, err
	}
	now := s.now().UTC().Format(timeLayout)
	for _, id := range ids {
		// Whatever the server was in the middle of is abandoned.
		s.engine.Cancel(id)
		s.closeOtherSubJobs(ctx, t, id, job.JobID)
		if _, err := s.servers(t).Update(ctx, id, func(srv *Server) error {
			srv.TaskState = "deleting"
			srv.Updated = now
			return nil
		}); err != nil && !errors.Is(err, store.ErrNotFound) {
			return Job{}, err
		}
		s.scheduleDelete(t, id, job.JobID)
	}
	return job, nil
}

// closeOtherSubJobs fails the running sub-jobs of a server that belong
// to jobs other than keep: their work was cancelled by a delete.
func (s *Service) closeOtherSubJobs(ctx context.Context, t Tenant, serverID, keep string) {
	running, err := s.jobs(t).List(ctx, func(j Job) bool {
		return j.JobID != keep && j.Status == JobRunning &&
			slices.ContainsFunc(j.Entities.SubJobs, func(sub SubJob) bool {
				return sub.Entities.ServerID == serverID && sub.Status == JobRunning
			})
	})
	if err != nil {
		s.log.ErrorContext(ctx, "listing jobs failed", "error", err)
		return
	}
	for _, j := range running {
		s.finishSubJob(ctx, t, j.JobID, serverID, errors.New("the ECS was deleted"))
	}
}

// scheduleDelete queues the removal of one server.
func (s *Service) scheduleDelete(t Tenant, serverID, jobID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  serverID,
		Kind: taskServerDelete,
		Run: func(ctx context.Context, fault error) {
			if fault != nil {
				_, err := s.servers(t).Update(ctx, serverID, func(srv *Server) error {
					srv.TaskState = ""
					srv.Status = StatusError
					return nil
				})
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					s.log.ErrorContext(ctx, "marking server failed", "server_id", serverID, "error", err)
				}
				s.finishSubJob(ctx, t, jobID, serverID, fault)
				return
			}
			srv, err := s.servers(t).Get(ctx, serverID)
			if err == nil {
				s.releaseAddresses(ctx, t, srv)
				err = s.servers(t).Delete(ctx, serverID)
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "deleting server failed", "server_id", serverID, "error", err)
				s.finishSubJob(ctx, t, jobID, serverID, err)
				return
			}
			s.finishSubJob(ctx, t, jobID, serverID, nil)
		},
	})
}

// detail renders the API form of a server.
func (s *Service) detail(ctx context.Context, t Tenant, srv Server) ServerDetail {
	d := ServerDetail{
		ID:                 srv.ID,
		Name:               srv.Name,
		Description:        srv.Description,
		Status:             srv.Status,
		Created:            srv.Created,
		Updated:            srv.Updated,
		HostID:             srv.HostID,
		Host:               "pod01." + srv.AvailabilityZone,
		HypervisorHostname: "nova001@" + srv.AvailabilityZone,
		InstanceName:       srv.InstanceName,
		Image:              ServerImage{ID: srv.ImageID},
		AvailabilityZone:   srv.AvailabilityZone,
		UserID:             srv.UserID,
		TenantID:           srv.TenantID,
		DiskConfig:         "MANUAL",
		HostStatus:         "UP",
		Hostname:           srv.Name,
		ReservationID:      srv.ReservationID,
		LaunchIndex:        srv.LaunchIndex,
		RootDeviceName:     srv.RootVolume.Device,
		Tags:               append([]string{}, srv.Tags...),
		SchedulerHints:     map[string]any{},
		EnterpriseProject:  srv.EnterpriseProjectID,
		SysTags:            []ServerSystemTag{{Key: "_sys_enterprise_project_id", Value: srv.EnterpriseProjectID}},
		Addresses:          map[string][]ServerAddress{},
		SecurityGroups:     []ServerSecurityGroup{},
	}
	d.VMState, d.PowerState = vmState(srv.Status)
	if srv.TaskState != "" {
		d.TaskState = &srv.TaskState
	}
	if srv.KeyName != "" {
		d.KeyName = &srv.KeyName
	}
	if srv.UserData != "" {
		d.UserData = &srv.UserData
	}
	if srv.LaunchedAt != "" {
		d.LaunchedAt = &srv.LaunchedAt
	}

	d.Flavor = ServerFlavor{ID: srv.Flavor, Name: srv.Flavor, Disk: "0"}
	if f, ok := s.FlavorByName(srv.Flavor); ok {
		d.Flavor.VCPUs, d.Flavor.RAM = strconv.Itoa(f.VCPUs), strconv.Itoa(f.RAM)
	}

	// Addresses are keyed by VPC ID; the first NIC is the primary one.
	addrs := make([]ServerAddress, 0, len(srv.NICs)+1)
	for i, nic := range srv.NICs {
		addrs = append(addrs, ServerAddress{
			Version: "4", Addr: nic.IP, Type: "fixed", MACAddr: nic.MAC, PortID: nic.PortID, Primary: i == 0,
		})
	}
	if srv.PublicIP != "" && len(srv.NICs) > 0 {
		addrs = append(addrs, ServerAddress{
			Version: "4", Addr: srv.PublicIP, Type: "floating", MACAddr: srv.NICs[0].MAC, PortID: srv.NICs[0].PortID,
		})
	}
	d.Addresses[srv.VPCID] = addrs

	for _, id := range srv.SecurityGroups {
		g := ServerSecurityGroup{ID: id}
		if info, err := s.network.GetSecurityGroup(ctx, t.vpc(), id); err == nil {
			g.Name = info.Name
		}
		d.SecurityGroups = append(d.SecurityGroups, g)
	}

	d.VolumesAttached = []ServerVolume{{ID: srv.RootVolume.ID, DeleteOnTermination: "true", BootIndex: "0", Device: srv.RootVolume.Device}}
	for _, v := range srv.DataVolumes {
		d.VolumesAttached = append(d.VolumesAttached, ServerVolume{ID: v.ID, DeleteOnTermination: "false", BootIndex: "-1", Device: v.Device})
	}

	// System metadata the platform adds, then the user's own.
	d.Metadata = map[string]string{
		"charging_mode":             "0",
		"vpc_id":                    srv.VPCID,
		"image_name":                srv.ImageName,
		"os_type":                   srv.OSType,
		"os_bit":                    srv.OSBit,
		"metering.image_id":         srv.ImageID,
		"metering.imagetype":        srv.ImageType,
		"metering.resourcetype":     "1",
		"metering.resourcespeccode": srv.Flavor + "." + strings.ToLower(srv.OSType),
	}
	for k, v := range srv.Metadata {
		d.Metadata[k] = v
	}
	return d
}

// vmState maps a server status to OS-EXT-STS:vm_state and power_state.
func vmState(status string) (state string, power int) {
	switch status {
	case StatusBuild:
		return "building", 0
	case StatusActive:
		return "active", 1
	case StatusShutoff:
		return "stopped", 4
	case StatusError:
		return "error", 0
	}
	return strings.ToLower(status), 1
}
