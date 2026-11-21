package ecs

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/services/evs"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// A server's disks live in EVS; its NICs are part of its record. This
// file shows the disks through ECS's block device API, and the NICs to
// VPC as ports.

// blockDevice mirrors the SDK model ecs/v2 ServerBlockDevice.
type blockDevice struct {
	ID         string `json:"id"`
	ServerID   string `json:"serverId"`
	VolumeID   string `json:"volumeId"`
	Device     string `json:"device"`
	Size       int    `json:"size"`
	BootIndex  int    `json:"bootIndex"`
	PCIAddress string `json:"pciAddress"`
	Bus        string `json:"bus"`
}

func blockDevices(serverID string, disks []evs.Disk) []blockDevice {
	out := make([]blockDevice, len(disks))
	for i, d := range disks {
		out[i] = blockDevice{
			ID: d.VolumeID, ServerID: serverID, VolumeID: d.VolumeID, Device: d.Device, Size: d.SizeGB, BootIndex: d.BootIndex,
			// Virtio disks occupy consecutive PCI slots from 0000:02:01.0.
			PCIAddress: fmt.Sprintf("0000:02:%02x.0", i+1), Bus: "virtio",
		}
	}
	return out
}

type attachableQuantity struct {
	FreeBlk  int `json:"free_blk"`
	FreeDisk int `json:"free_disk"`
}

type listBlockDevicesResponse struct {
	AttachableQuantity attachableQuantity `json:"attachableQuantity"`
	VolumeAttachments  []blockDevice      `json:"volumeAttachments"`
}

func (s *Service) handleListBlockDevices(w http.ResponseWriter, r *http.Request, t Tenant) error {
	srv, err := s.GetServer(r.Context(), t, chi.URLParam(r, "server_id"))
	if err != nil {
		return err
	}
	disks, err := s.volumes.DisksOf(r.Context(), t.evs(), srv.ID)
	if err != nil {
		return err
	}
	dataCount := 0
	for _, d := range disks {
		if d.BootIndex != 0 {
			dataCount++
		}
	}
	free := maxDataVolumes - dataCount
	return httpx.WriteJSON(w, http.StatusOK, listBlockDevicesResponse{
		AttachableQuantity: attachableQuantity{FreeBlk: free, FreeDisk: free},
		VolumeAttachments:  blockDevices(srv.ID, disks),
	})
}

type showBlockDeviceResponse struct {
	VolumeAttachment blockDevice `json:"volumeAttachment"`
}

func (s *Service) handleShowBlockDevice(w http.ResponseWriter, r *http.Request, t Tenant) error {
	srv, err := s.GetServer(r.Context(), t, chi.URLParam(r, "server_id"))
	if err != nil {
		return err
	}
	disks, err := s.volumes.DisksOf(r.Context(), t.evs(), srv.ID)
	if err != nil {
		return err
	}
	id := chi.URLParam(r, "volume_id")
	for _, bd := range blockDevices(srv.ID, disks) {
		if bd.VolumeID == id {
			return httpx.WriteJSON(w, http.StatusOK, showBlockDeviceResponse{VolumeAttachment: bd})
		}
	}
	return errVolumeNotAttached(id, srv.ID)
}

// errVolumeNotAttached is Ecs.0111, which the API reference lists as a
// 400: the disk is not in the server's attachment list.
func errVolumeNotAttached(volume, server string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "Ecs.0111", "The EVS disk %s is not attached to the ECS %s.", volume, server)
}

// Ports implements vpc.PortSource: the NICs of the project's servers.
func (s *Service) Ports(ctx context.Context, t vpc.Tenant) ([]vpc.Port, error) {
	servers, err := s.servers(Tenant{Region: t.Region, ProjectID: t.ProjectID}).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	var out []vpc.Port
	for _, srv := range servers {
		for _, nic := range srv.NICs {
			out = append(out, vpc.Port{
				ID: nic.PortID, SubnetID: nic.SubnetID, IP: nic.IP, MAC: nic.MAC,
				DeviceID: srv.ID, DeviceOwner: "compute:" + srv.AvailabilityZone,
				SecurityGroups: append([]string(nil), srv.SecurityGroups...),
			})
		}
	}
	return out, nil
}
