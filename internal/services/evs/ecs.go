package evs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/victor-akande/weistack/internal/core/store"
)

const maxDataDisksPerServer = 23

var validAttachDeviceRE = regexp.MustCompile(`^/dev/(vd|sd)[b-z]$`)

// Disk is a volume attached to a server, as ECS shows it.
type Disk struct {
	VolumeID, Device, Type, KMSKeyID, AttachedAt string
	SizeGB, BootIndex                            int
	DeleteOnTermination                          bool
}

// NewDisk describes a disk to create when creating an ECS server.
type NewDisk struct {
	Type                string
	SizeGB              int
	KMSKeyID            string
	DeleteOnTermination bool
}

// ServerDisks describes the root and data disks of a newly created server.
type ServerDisks struct {
	ServerID, ServerName, AvailabilityZone, EnterpriseProjectID string
	ImageID, ImageName, Created                                 string
	Root                                                        NewDisk
	Data                                                        []NewDisk
}

// CreateForServer creates the root and data volumes of a newly created
// server, all immediately in-use.
func (s *Service) CreateForServer(ctx context.Context, t Tenant, d ServerDisks) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	wantGB := d.Root.SizeGB
	for _, dd := range d.Data {
		wantGB += dd.SizeGB
	}
	if err := s.checkVolumeQuotaLocked(ctx, t, 1+len(d.Data), wantGB); err != nil {
		if errors.Is(err, errQuotaCountExceeded) || errors.Is(err, errQuotaGigabytesExceeded) {
			return ErrQuotaExceeded
		}
		return err
	}

	ep := d.EnterpriseProjectID
	if ep == "" {
		ep = "0"
	}

	makeVol := func(idx int, nd NewDisk, device string, bootable bool, bootIdx int, delOnTerm bool) volume {
		volID := s.ids.UUID()
		var imgID, imgName string
		if bootable {
			imgID, imgName = d.ImageID, d.ImageName
		}
		return volume{
			ID:                  volID,
			Name:                fmt.Sprintf("%s-volume-%04d", d.ServerName, idx),
			Status:              statusInUse,
			SizeGB:              nd.SizeGB,
			VolumeType:          nd.Type,
			AvailabilityZone:    d.AvailabilityZone,
			Bootable:            bootable,
			ImageID:             imgID,
			ImageName:           imgName,
			KMSKeyID:            nd.KMSKeyID,
			EnterpriseProjectID: ep,
			Attachments: []attachment{{
				ID:                  s.ids.UUID(),
				ServerID:            d.ServerID,
				Device:              device,
				BootIndex:           bootIdx,
				DeleteOnTermination: delOnTerm,
				AttachedAt:          d.Created,
			}},
			CreatedAt: d.Created,
			UpdatedAt: d.Created,
		}
	}

	vols := make([]volume, 0, 1+len(d.Data))
	vols = append(vols, makeVol(0, d.Root, "/dev/vda", true, 0, true))
	for i, dd := range d.Data {
		vols = append(vols, makeVol(i+1, dd, "/dev/vd"+string(rune('b'+i)), false, -1, dd.DeleteOnTermination))
	}

	var created []string
	for _, v := range vols {
		if err := s.volumes(t).Create(ctx, v.ID, v); err != nil {
			for _, id := range created {
				_ = s.volumes(t).Delete(ctx, id)
			}
			return err
		}
		created = append(created, v.ID)
	}
	return nil
}

// ReleaseForServer deletes the volumes created for a server on rollback.
func (s *Service) ReleaseForServer(ctx context.Context, t Tenant, serverID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	vols, err := s.volumes(t).List(ctx, nil)
	if err != nil {
		return err
	}
	for _, v := range vols {
		if hasServerAttachment(v, serverID) {
			if err := s.deleteVolumeAndSnapshotsLocked(ctx, t, v.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// ServerDeleted deletes the system disk and the data disks that
// deleteVolumes or their delete_on_termination says to (with their
// snapshots), detaches the rest, and drops any attach or detach in
// flight for the server.
func (s *Service) ServerDeleted(ctx context.Context, t Tenant, serverID string, deleteVolumes bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	vols, err := s.volumes(t).List(ctx, nil)
	if err != nil {
		return err
	}
	now := s.now().UTC().Format(volumeTimeLayout)
	for _, v := range vols {
		attIdx := -1
		for i, a := range v.Attachments {
			if a.ServerID == serverID {
				attIdx = i
				break
			}
		}
		pendingForServer := v.Pending != nil && v.Pending.ServerID == serverID &&
			(v.Pending.Op == "attach" || v.Pending.Op == "detach")
		if attIdx < 0 && !pendingForServer {
			continue
		}

		if attIdx >= 0 {
			att := v.Attachments[attIdx]
			shouldDelete := att.BootIndex == 0 || deleteVolumes || att.DeleteOnTermination
			if shouldDelete && len(v.Attachments) == 1 && !pendingForServer {
				if err := s.deleteVolumeAndSnapshotsLocked(ctx, t, v.ID); err != nil {
					return err
				}
				continue
			}
		}

		if _, err := s.volumes(t).Update(ctx, v.ID, func(cur *volume) error {
			if cur.Pending != nil && cur.Pending.ServerID == serverID &&
				(cur.Pending.Op == "attach" || cur.Pending.Op == "detach") {
				cur.Pending = nil
			}
			filtered := cur.Attachments[:0]
			for _, a := range cur.Attachments {
				if a.ServerID != serverID {
					filtered = append(filtered, a)
				}
			}
			cur.Attachments = filtered
			if len(cur.Attachments) == 0 {
				cur.Status = statusAvailable
			} else {
				cur.Status = statusInUse
			}
			cur.UpdatedAt = now
			return nil
		}); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

func (s *Service) deleteVolumeAndSnapshotsLocked(ctx context.Context, t Tenant, volumeID string) error {
	snaps, err := s.snapshots(t).List(ctx, func(sn snapshot) bool { return sn.VolumeID == volumeID })
	if err != nil {
		return err
	}
	for _, sn := range snaps {
		if err := s.snapshots(t).Delete(ctx, sn.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	if err := s.volumes(t).Delete(ctx, volumeID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// DisksOf returns the disks attached to serverID, system disk first,
// then data disks by attach time.
func (s *Service) DisksOf(ctx context.Context, t Tenant, serverID string) ([]Disk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	vols, err := s.volumes(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	var out []Disk
	for _, v := range vols {
		for _, a := range v.Attachments {
			if a.ServerID == serverID {
				out = append(out, diskFromAttachment(v, a))
			}
		}
	}
	sortDisks(out)
	return out, nil
}

// DisksByServer returns the disks attached to every server in t,
// keyed by server ID.
func (s *Service) DisksByServer(ctx context.Context, t Tenant) (map[string][]Disk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	vols, err := s.volumes(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]Disk)
	for _, v := range vols {
		for _, a := range v.Attachments {
			out[a.ServerID] = append(out[a.ServerID], diskFromAttachment(v, a))
		}
	}
	for id := range out {
		sortDisks(out[id])
	}
	return out, nil
}

func diskFromAttachment(v volume, a attachment) Disk {
	return Disk{
		VolumeID:            v.ID,
		Device:              a.Device,
		Type:                v.VolumeType,
		KMSKeyID:            v.KMSKeyID,
		AttachedAt:          a.AttachedAt,
		SizeGB:              v.SizeGB,
		BootIndex:           a.BootIndex,
		DeleteOnTermination: a.DeleteOnTermination,
	}
}

func sortDisks(disks []Disk) {
	sort.SliceStable(disks, func(i, j int) bool {
		if (disks[i].BootIndex == 0) != (disks[j].BootIndex == 0) {
			return disks[i].BootIndex == 0
		}
		if disks[i].AttachedAt != disks[j].AttachedAt {
			return disks[i].AttachedAt < disks[j].AttachedAt
		}
		return disks[i].Device < disks[j].Device
	})
}

func hasServerAttachment(v volume, serverID string) bool {
	for _, a := range v.Attachments {
		if a.ServerID == serverID {
			return true
		}
	}
	return false
}

// BeginAttach reserves a volume for a server (status attaching) and
// returns the device; dryRun checks only.
func (s *Service) BeginAttach(ctx context.Context, t Tenant, volumeID, serverID, serverAZ, device, jobID string, dryRun bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := s.volumes(t).Get(ctx, volumeID)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrVolumeNotFound
	}
	if err != nil {
		return "", err
	}
	if hasServerAttachment(v, serverID) || (v.Pending != nil && v.Pending.Op == "attach" && v.Pending.ServerID == serverID) {
		return "", ErrAlreadyAttached
	}
	if v.AvailabilityZone != serverAZ {
		return "", ErrOtherAZ
	}
	if v.Pending != nil || (v.Status != statusAvailable && (!v.Multiattach || v.Status != statusInUse)) {
		return "", ErrNotAvailable
	}

	all, err := s.volumes(t).List(ctx, nil)
	if err != nil {
		return "", err
	}
	dataCount := 0
	usedDevices := map[string]bool{}
	for _, item := range all {
		for _, a := range item.Attachments {
			if a.ServerID == serverID {
				usedDevices[a.Device] = true
				if a.BootIndex != 0 {
					dataCount++
				}
			}
		}
		if item.Pending != nil && item.Pending.Op == "attach" && item.Pending.ServerID == serverID {
			usedDevices[item.Pending.Device] = true
			dataCount++
		}
	}
	if dataCount >= maxDataDisksPerServer {
		return "", ErrTooManyDisks
	}

	if device != "" {
		if !validAttachDeviceRE.MatchString(device) || usedDevices[device] {
			return "", ErrBadDevice
		}
	} else {
		for c := 'b'; c <= 'z'; c++ {
			cand := "/dev/vd" + string(c)
			if !usedDevices[cand] {
				device = cand
				break
			}
		}
		if device == "" {
			return "", ErrTooManyDisks
		}
	}

	if dryRun {
		return device, nil
	}

	now := s.now().UTC().Format(volumeTimeLayout)
	if _, err := s.volumes(t).Update(ctx, volumeID, func(cur *volume) error {
		cur.Status = statusAttaching
		cur.Pending = &pending{Op: "attach", JobID: jobID, ServerID: serverID, Device: device}
		cur.UpdatedAt = now
		return nil
	}); err != nil {
		return "", err
	}
	return device, nil
}

// BeginDetach marks an attached data volume as detaching for jobID.
func (s *Service) BeginDetach(ctx context.Context, t Tenant, volumeID, serverID, jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := s.volumes(t).Get(ctx, volumeID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrVolumeNotFound
	}
	if err != nil {
		return err
	}
	var found *attachment
	for i := range v.Attachments {
		if v.Attachments[i].ServerID == serverID {
			found = &v.Attachments[i]
			break
		}
	}
	if found == nil || v.Pending != nil {
		return ErrNotAttached
	}
	if found.BootIndex == 0 {
		return ErrSystemDisk
	}

	now := s.now().UTC().Format(volumeTimeLayout)
	_, err = s.volumes(t).Update(ctx, volumeID, func(cur *volume) error {
		cur.Status = statusDetaching
		cur.Pending = &pending{Op: "detach", JobID: jobID, ServerID: serverID}
		cur.UpdatedAt = now
		return nil
	})
	return err
}

// FinishAttach completes the attach operation that jobID began; it does
// nothing if it is no longer pending.
func (s *Service) FinishAttach(ctx context.Context, t Tenant, volumeID, jobID string, fault error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	attID := s.ids.UUID()
	now := s.now().UTC().Format(volumeTimeLayout)
	failed := fault != nil
	_, err := s.volumes(t).Update(ctx, volumeID, func(cur *volume) error {
		if cur.Pending == nil || cur.Pending.Op != "attach" || cur.Pending.JobID != jobID {
			return nil
		}
		if failed {
			cur.Pending = nil
			if len(cur.Attachments) > 0 {
				cur.Status = statusInUse
			} else {
				cur.Status = statusAvailable
			}
			cur.UpdatedAt = now
			return nil
		}
		cur.Attachments = append(cur.Attachments, attachment{
			ID:                  attID,
			ServerID:            cur.Pending.ServerID,
			Device:              cur.Pending.Device,
			BootIndex:           -1,
			DeleteOnTermination: false,
			AttachedAt:          now,
		})
		cur.Pending = nil
		cur.Status = statusInUse
		cur.UpdatedAt = now
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "evs FinishAttach failed", "volume_id", volumeID, "error", err)
	}
}

// FinishDetach completes the detach operation that jobID began; it does
// nothing if it is no longer pending.
func (s *Service) FinishDetach(ctx context.Context, t Tenant, volumeID, jobID string, fault error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	failed := fault != nil
	now := s.now().UTC().Format(volumeTimeLayout)
	_, err := s.volumes(t).Update(ctx, volumeID, func(cur *volume) error {
		if cur.Pending == nil || cur.Pending.Op != "detach" || cur.Pending.JobID != jobID {
			return nil
		}
		if failed {
			cur.Pending = nil
			cur.Status = statusInUse
			cur.UpdatedAt = now
			return nil
		}
		srvID := cur.Pending.ServerID
		kept := cur.Attachments[:0]
		for _, a := range cur.Attachments {
			if a.ServerID != srvID {
				kept = append(kept, a)
			}
		}
		cur.Attachments = kept
		cur.Pending = nil
		if len(cur.Attachments) > 0 {
			cur.Status = statusInUse
		} else {
			cur.Status = statusAvailable
		}
		cur.UpdatedAt = now
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "evs FinishDetach failed", "volume_id", volumeID, "error", err)
	}
}

// SetDeleteOnTermination updates delete_on_termination for an attached
// non-system, non-multiattach data volume.
func (s *Service) SetDeleteOnTermination(ctx context.Context, t Tenant, volumeID, serverID string, v bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	vol, err := s.volumes(t).Get(ctx, volumeID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrVolumeNotFound
	}
	if err != nil {
		return err
	}
	attIdx := -1
	for i, a := range vol.Attachments {
		if a.ServerID == serverID {
			attIdx = i
			break
		}
	}
	if attIdx < 0 {
		return ErrNotAttached
	}
	if vol.Attachments[attIdx].BootIndex == 0 {
		return ErrSystemDisk
	}
	if vol.Multiattach {
		return ErrShared
	}
	now := s.now().UTC().Format(volumeTimeLayout)
	_, err = s.volumes(t).Update(ctx, volumeID, func(cur *volume) error {
		for i := range cur.Attachments {
			if cur.Attachments[i].ServerID == serverID {
				cur.Attachments[i].DeleteOnTermination = v
			}
		}
		cur.UpdatedAt = now
		return nil
	})
	return err
}

// PendingAttach returns the volume an ECS job attaches or detaches.
func (s *Service) PendingAttach(ctx context.Context, t Tenant, jobID string) (volumeID, op string, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	vols, err := s.volumes(t).List(ctx, nil)
	if err != nil {
		return "", "", false, err
	}
	for _, v := range vols {
		if v.Pending != nil && v.Pending.JobID == jobID && (v.Pending.Op == "attach" || v.Pending.Op == "detach") {
			return v.ID, v.Pending.Op, true, nil
		}
	}
	return "", "", false, nil
}
