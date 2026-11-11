package ecs

import (
	"context"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Lifecycle task kinds of server operations, matched by fault injection.
const (
	taskServerStart  = "ecs.server.start"
	taskServerStop   = "ecs.server.stop"
	taskServerReboot = "ecs.server.reboot"
	taskServerResize = "ecs.server.resize"
)

// maxBatch is the most servers one batch operation accepts.
const maxBatch = 1000

// modeWithStop is the resize mode that stops and restarts the server.
const modeWithStop = "withStopServer"

// action describes one batch operation.
type action struct {
	kind             string
	jobType, subType string
	// from is the status a server must be in.
	from string
	// during and task are what the server shows while the operation
	// runs; final is where it lands.
	during, task, final string
}

var (
	actionStart = action{
		kind: taskServerStart, jobType: "startServer", subType: "startSingleServer",
		from: StatusShutoff, during: StatusShutoff, task: "powering-on", final: StatusActive,
	}
	actionStop = action{
		kind: taskServerStop, jobType: "stopServer", subType: "stopSingleServer",
		from: StatusActive, during: StatusActive, task: "powering-off", final: StatusShutoff,
	}
	actionReboot = action{
		kind: taskServerReboot, jobType: "rebootServer", subType: "rebootSingleServer",
		from: StatusActive, during: StatusReboot, task: "rebooting", final: StatusActive,
	}
)

// checkIdle enforces that a server is in the status an operation needs
// and has nothing else in flight.
func checkIdle(srv Server, need string) error {
	if srv.TaskState != "" || srv.Pending != nil {
		return errStatus(srv.ID, srv.Status, "another operation ("+srv.TaskState+") is in progress")
	}
	if srv.Status != need {
		return errStatus(srv.ID, srv.Status, "the ECS must be "+need)
	}
	return nil
}

func checkBatch(ids []string) error {
	if len(ids) == 0 {
		return errInvalidRequest("servers must contain at least one ECS")
	}
	if len(ids) > maxBatch {
		return errBatchTooLarge(len(ids))
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return errInvalidRequest("the ECS %s is listed more than once", id)
		}
		seen[id] = true
	}
	return nil
}

// batch runs one operation on several servers and returns its job.
// Every server must exist and be in the right status, or none is touched.
func (s *Service) batch(ctx context.Context, t Tenant, a action, ids []string) (Job, error) {
	if err := checkBatch(ids); err != nil {
		return Job{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, id := range ids {
		srv, err := s.GetServer(ctx, t, id)
		if err != nil {
			return Job{}, err
		}
		if err := checkIdle(srv, a.from); err != nil {
			return Job{}, err
		}
	}
	job, err := s.newJob(ctx, t, a.jobType, a.subType, ids)
	if err != nil {
		return Job{}, err
	}
	now := s.now().UTC().Format(timeLayout)
	for _, id := range ids {
		op := PendingOp{Kind: a.kind, JobID: job.JobID, Final: a.final}
		if _, err := s.servers(t).Update(ctx, id, func(srv *Server) error {
			srv.Status, srv.TaskState, srv.Updated = a.during, a.task, now
			srv.Pending = &op
			return nil
		}); err != nil {
			return Job{}, err
		}
		s.scheduleOp(t, id, op)
	}
	return job, nil
}

// StartServers powers on stopped servers.
func (s *Service) StartServers(ctx context.Context, t Tenant, ids []string) (Job, error) {
	return s.batch(ctx, t, actionStart, ids)
}

// StopServers powers off running servers. kind is "SOFT" (the default)
// or "HARD"; with no guest to shut down the two behave alike.
func (s *Service) StopServers(ctx context.Context, t Tenant, ids []string, kind string) (Job, error) {
	if kind != "" && kind != "SOFT" && kind != "HARD" {
		return Job{}, errInvalidRequest("type must be SOFT or HARD")
	}
	return s.batch(ctx, t, actionStop, ids)
}

// RebootServers restarts running servers. kind is "SOFT" or "HARD"; a
// hard reboot shows status HARD_REBOOT while it runs.
func (s *Service) RebootServers(ctx context.Context, t Tenant, ids []string, kind string) (Job, error) {
	a := actionReboot
	switch kind {
	case "SOFT":
	case "HARD":
		a.during = StatusHardReboot
	default:
		return Job{}, errInvalidRequest("type is required and must be SOFT or HARD")
	}
	return s.batch(ctx, t, a, ids)
}

// ResizeServer changes a server's flavor and returns the job. The server
// must be stopped, unless mode is "withStopServer", in which case a
// running server is stopped, resized and started again.
func (s *Service) ResizeServer(ctx context.Context, t Tenant, id string, opt ResizeOption) (Job, error) {
	if opt.FlavorRef == "" {
		return Job{}, errInvalidRequest("flavorRef is required")
	}
	if opt.Mode != "" && opt.Mode != modeWithStop {
		return Job{}, errInvalidRequest("mode must be %s", modeWithStop)
	}
	target, ok := s.FlavorByName(opt.FlavorRef)
	if !ok {
		return Job{}, errFlavorNotFound(opt.FlavorRef)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	srv, err := s.GetServer(ctx, t, id)
	if err != nil {
		return Job{}, err
	}
	// The server returns to the status it was resized in: stopped, or
	// running when the request asked for a stop-resize-start.
	final := StatusShutoff
	if opt.Mode == modeWithStop && srv.Status == StatusActive {
		final = StatusActive
	}
	if err := checkIdle(srv, final); err != nil {
		return Job{}, err
	}
	if target.Name == srv.Flavor {
		return Job{}, errSameFlavor(target.Name)
	}
	current, known := s.FlavorByName(srv.Flavor)
	if known && current.Arch != target.Arch {
		return Job{}, errFlavorSwitch(current.Name, target.Name)
	}
	_, usedCPUs, err := s.usage(ctx, t)
	if err != nil {
		return Job{}, err
	}
	if after := usedCPUs - current.VCPUs + target.VCPUs; after > s.quota.VCPUs {
		return Job{}, errQuota("vCPU", target.VCPUs-current.VCPUs, usedCPUs, s.quota.VCPUs)
	}

	job, err := s.newJob(ctx, t, "resizeServer", "resizeSingleServer", []string{id})
	if err != nil {
		return Job{}, err
	}
	op := PendingOp{Kind: taskServerResize, JobID: job.JobID, Final: final, Flavor: target.Name}
	now := s.now().UTC().Format(timeLayout)
	if _, err := s.servers(t).Update(ctx, id, func(srv *Server) error {
		srv.Status, srv.TaskState, srv.Updated = StatusResize, "resize_prep", now
		srv.Pending = &op
		return nil
	}); err != nil {
		return Job{}, err
	}
	s.scheduleOp(t, id, op)
	return job, nil
}

// scheduleOp queues the completion of a pending operation.
func (s *Service) scheduleOp(t Tenant, serverID string, op PendingOp) {
	s.engine.Schedule(lifecycle.Task{
		Key:  serverID,
		Kind: op.Kind,
		Run: func(ctx context.Context, fault error) {
			now := s.now().UTC()
			failed := fault != nil
			_, err := s.servers(t).Update(ctx, serverID, func(srv *Server) error {
				srv.TaskState, srv.Pending = "", nil
				srv.Updated = now.Format(timeLayout)
				if failed {
					srv.Status = StatusError
					return nil
				}
				srv.Status = op.Final
				if op.Flavor != "" {
					srv.Flavor = op.Flavor
				}
				if op.Kind == taskServerStart {
					srv.LaunchedAt = now.Format(usageTimeLayout)
				}
				return nil
			})
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "server operation failed", "server_id", serverID, "kind", op.Kind, "error", err)
			}
			s.finishSubJob(ctx, t, op.JobID, serverID, fault)
		},
	})
}

// UpdateServer changes the fields set in opt.
func (s *Service) UpdateServer(ctx context.Context, t Tenant, id string, opt UpdateServerOption) (Server, error) {
	if opt.Name != nil {
		if err := checkServerName(*opt.Name); err != nil {
			return Server{}, err
		}
	}
	if opt.Description != nil {
		if utf8.RuneCountInString(*opt.Description) > maxDescLen || strings.ContainsAny(*opt.Description, "<>") {
			return Server{}, errInvalidRequest("description can have at most %d characters and no angle brackets", maxDescLen)
		}
	}
	if opt.Hostname != nil {
		return Server{}, errInvalidRequest("hostname cannot be changed on the emulator: it always follows the name")
	}
	now := s.now().UTC().Format(timeLayout)
	srv, err := s.servers(t).Update(ctx, id, func(srv *Server) error {
		if opt.Name != nil {
			srv.Name = *opt.Name
		}
		if opt.Description != nil {
			srv.Description = *opt.Description
		}
		if opt.UserData != nil {
			srv.UserData = *opt.UserData
		}
		srv.Updated = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return Server{}, errServerNotFound(id)
	}
	return srv, err
}

// updateResult renders the Nova form of a server returned by an update.
func (s *Service) updateResult(t Tenant, srv Server) UpdateServerResult {
	base := "https://ecs." + t.Region + ".myhuaweicloud.com/v2.1/" + t.ProjectID
	res := UpdateServerResult{
		ID:          srv.ID,
		Name:        srv.Name,
		Description: srv.Description,
		Status:      srv.Status,
		TenantID:    srv.TenantID,
		UserID:      srv.UserID,
		HostID:      srv.HostID,
		Image:       srv.ImageID,
		Created:     srv.Created,
		Updated:     srv.Updated,
		DiskConfig:  "MANUAL",
		Hostname:    srv.Name,
		Tags:        append([]string{}, srv.Tags...),
		Metadata:    map[string]string{},
		Addresses:   map[string][]UpdateServerAddress{},
		Flavor: SimpleFlavor{ID: srv.Flavor, Links: []Link{
			{Rel: "bookmark", Href: base + "/flavors/" + srv.Flavor},
		}},
		Links: []Link{
			{Rel: "self", Href: base + "/servers/" + srv.ID},
			{Rel: "bookmark", Href: base + "/servers/" + srv.ID},
		},
	}
	for k, v := range srv.Metadata {
		res.Metadata[k] = v
	}
	addrs := make([]UpdateServerAddress, 0, len(srv.NICs))
	for _, nic := range srv.NICs {
		addrs = append(addrs, UpdateServerAddress{Version: 4, Addr: nic.IP})
	}
	res.Addresses[srv.VPCID] = addrs
	if srv.UserData != "" {
		res.UserData = &srv.UserData
	}
	return res
}

// Tags are stored on the server as "key" or "key=value".

func splitTag(tag string) ServerTag {
	key, value, _ := strings.Cut(tag, "=")
	return ServerTag{Key: key, Value: value}
}

func joinTag(tag ServerTag) string {
	if tag.Value == "" {
		return tag.Key
	}
	return tag.Key + "=" + tag.Value
}

func checkTag(tag ServerTag) error {
	if tag.Key == "" || utf8.RuneCountInString(tag.Key) > 36 || utf8.RuneCountInString(tag.Value) > 43 {
		return errTag("Ecs.0906", "The tag %q is invalid: a key has 1 to 36 characters and a value at most 43.", tag.Key)
	}
	if strings.ContainsAny(tag.Key+tag.Value, "=*<>\\,|/") {
		return errTag("Ecs.0907", "The tag %q contains characters that are not allowed.", tag.Key)
	}
	return nil
}

// GetServerTags returns a server's tags.
func (s *Service) GetServerTags(ctx context.Context, t Tenant, id string) ([]ServerTag, error) {
	srv, err := s.GetServer(ctx, t, id)
	if err != nil {
		return nil, err
	}
	out := make([]ServerTag, 0, len(srv.Tags))
	for _, tag := range srv.Tags {
		out = append(out, splitTag(tag))
	}
	return out, nil
}

// AddServerTags adds tags to a server; a tag whose key exists replaces
// that tag's value.
func (s *Service) AddServerTags(ctx context.Context, t Tenant, id string, tags []ServerTag) error {
	if len(tags) == 0 {
		return errInvalidRequest("tags must contain at least one tag")
	}
	keys := map[string]bool{}
	for _, tag := range tags {
		if err := checkTag(tag); err != nil {
			return err
		}
		if keys[tag.Key] {
			return errTag("Ecs.0908", "The tag key %q is repeated.", tag.Key)
		}
		keys[tag.Key] = true
	}
	_, err := s.servers(t).Update(ctx, id, func(srv *Server) error {
		// A tag whose key exists is replaced where it stands, so the
		// order of a server's tags is stable; new keys go to the end.
		merged := append([]string{}, srv.Tags...)
		position := map[string]int{}
		for i, old := range merged {
			position[splitTag(old).Key] = i
		}
		for _, tag := range tags {
			if i, exists := position[tag.Key]; exists {
				merged[i] = joinTag(tag)
				continue
			}
			merged = append(merged, joinTag(tag))
		}
		if len(merged) > maxTags {
			return errTooManyTags
		}
		srv.Tags = merged
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errServerNotFound(id)
	}
	return err
}

// DeleteServerTags removes the tags with the given keys from a server.
// Keys the server does not have are ignored.
func (s *Service) DeleteServerTags(ctx context.Context, t Tenant, id string, tags []ServerTag) error {
	if len(tags) == 0 {
		return errInvalidRequest("tags must contain at least one tag")
	}
	keys := map[string]bool{}
	for _, tag := range tags {
		if tag.Key == "" {
			return errTag("Ecs.0906", "A tag key is required.")
		}
		keys[tag.Key] = true
	}
	_, err := s.servers(t).Update(ctx, id, func(srv *Server) error {
		kept := srv.Tags[:0:0]
		for _, old := range srv.Tags {
			if !keys[splitTag(old).Key] {
				kept = append(kept, old)
			}
		}
		srv.Tags = kept
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errServerNotFound(id)
	}
	return err
}

// ListProjectTags returns every tag key used by the project's servers
// with the values it takes, sorted.
func (s *Service) ListProjectTags(ctx context.Context, t Tenant) ([]ProjectTag, error) {
	all, err := s.servers(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	values := map[string]map[string]bool{}
	for _, srv := range all {
		for _, raw := range srv.Tags {
			tag := splitTag(raw)
			if values[tag.Key] == nil {
				values[tag.Key] = map[string]bool{}
			}
			values[tag.Key][tag.Value] = true
		}
	}
	out := make([]ProjectTag, 0, len(values))
	for key, set := range values {
		pt := ProjectTag{Key: key, Values: make([]string, 0, len(set))}
		for v := range set {
			pt.Values = append(pt.Values, v)
		}
		sort.Strings(pt.Values)
		out = append(out, pt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
