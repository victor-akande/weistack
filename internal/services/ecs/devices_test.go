package ecs

import (
	"net/http"
	"testing"
)

func TestServerDisks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	_, ids := e.mustCreate(t, n.serverBody("name", `"web"`, "root_volume", `{"volumetype": "GPSSD", "size": 50}`,
		"data_volumes", `[{"volumetype": "SSD", "size": 100}, {"volumetype": "SAS", "size": 20}]`))
	e.settle(t)
	srv := e.server(t, ids[0])

	// ECS's own view.
	status, out := e.call(t, http.MethodGet, serversPath+"/"+srv.ID+"/block_device", "")
	if status != http.StatusOK {
		t.Fatalf("ListServerBlockDevices: %d %s", status, out)
	}
	list := decodeInto[listBlockDevicesResponse](t, out)
	if len(list.VolumeAttachments) != 3 || list.AttachableQuantity.FreeDisk != maxDataVolumes-2 {
		t.Fatalf("block devices = %+v", list)
	}
	root, data := list.VolumeAttachments[0], list.VolumeAttachments[1]
	if root.VolumeID != srv.RootVolume.ID || root.BootIndex != 0 || root.Size != 50 || root.Device != "/dev/vda" ||
		data.BootIndex != -1 || data.Size != 100 || data.Device != "/dev/vdb" || root.PCIAddress == data.PCIAddress {
		t.Fatalf("block devices = %+v", list.VolumeAttachments)
	}

	status, out = e.call(t, http.MethodGet, serversPath+"/"+srv.ID+"/block_device/"+data.VolumeID, "")
	if got := decodeInto[showBlockDeviceResponse](t, out).VolumeAttachment; status != http.StatusOK || got != data {
		t.Fatalf("ShowServerBlockDevice: %d %s", status, out)
	}
	if status, out = e.call(t, http.MethodGet, serversPath+"/"+srv.ID+"/block_device/"+unknownID, ""); status != http.StatusBadRequest {
		t.Fatalf("a disk of no server: %d %s", status, out)
	}
	if status, _ = e.call(t, http.MethodGet, serversPath+"/"+unknownID+"/block_device", ""); status != http.StatusNotFound {
		t.Fatalf("a missing server: %d", status)
	}

	// EVS's view.
	vols, err := e.svc.Volumes(t.Context(), testTenant.Region, testTenant.ProjectID)
	if err != nil || len(vols) != 3 {
		t.Fatalf("Volumes = %+v, %v", vols, err)
	}
	if v := vols[0]; v.ID != srv.RootVolume.ID || !v.Bootable || v.ImageID != ubuntuImage || v.Name != "web-volume-0000" ||
		v.ServerID != srv.ID || v.AvailabilityZone != srv.AvailabilityZone || v.Type != "GPSSD" {
		t.Fatalf("system disk = %+v", v)
	}
	if v := vols[2]; v.Bootable || v.ImageID != "" || v.Name != "web-volume-0002" || v.Type != "SAS" || v.SizeGB != 20 {
		t.Fatalf("data disk = %+v", v)
	}
	if other, err := e.svc.Volumes(t.Context(), testTenant.Region, otherProject); err != nil || len(other) != 0 {
		t.Fatalf("another project sees %d disks (%v)", len(other), err)
	}
}

func TestServerPorts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	_, ids := e.mustCreate(t, n.serverBody("security_groups", `[{"id": "`+n.groupID+`"}]`))
	e.settle(t)
	srv := e.server(t, ids[0])

	// VPC shows the server's NIC as a port.
	e.network.SetPorts(e.svc)
	ports, err := e.svc.Ports(t.Context(), testTenant.vpc())
	if err != nil || len(ports) != 1 {
		t.Fatalf("Ports = %+v, %v", ports, err)
	}
	p, nic := ports[0], srv.NICs[0]
	if p.ID != nic.PortID || p.SubnetID != n.subnetID || p.IP != nic.IP || p.MAC != nic.MAC || p.DeviceID != srv.ID ||
		p.DeviceOwner != "compute:"+srv.AvailabilityZone || len(p.SecurityGroups) != 1 || p.SecurityGroups[0] != n.groupID {
		t.Fatalf("port = %+v, NIC = %+v", p, nic)
	}
	if other, err := e.svc.Ports(t.Context(), Tenant{Region: testTenant.Region, ProjectID: otherProject}.vpc()); err != nil || len(other) != 0 {
		t.Fatalf("another project sees %d ports (%v)", len(other), err)
	}
}
