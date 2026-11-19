package sdk

import (
	"strings"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	eipv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2/model"
	eipv3client "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v3"
	eipv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v3/model"
	ims "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ims/v2/model"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

func newEIPv3(t *testing.T) *eipv3client.EipClient {
	t.Helper()
	return eipV3As(t, signingAK("AKEIPV3SDKEXAMPLE000"), signingSK())
}

// eipV3As builds an EIP v3 client that signs with ak and sk against the VPC endpoint.
func eipV3As(t *testing.T, ak, sk string) *eipv3client.EipClient {
	t.Helper()
	cred, err := basic.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		WithProjectId(projectID).
		SafeBuild()
	if err != nil {
		t.Fatalf("building credentials: %v", err)
	}
	hc, err := eipv3client.EipClientBuilder().
		WithEndpoints([]string{realEndpoint}).
		WithCredential(cred).
		WithHttpConfig(httpConfigAt(emulatorAddr)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building EIP v3 client: %v", err)
	}
	return eipv3client.NewEipClient(hc)
}

// TestEIPv3Operations drives §3.4 through the official EIP v3 SDK:
// ShowPublicip, ListPublicips (filters and pagination), UpdatePublicip
// (alias, description, binding), AssociatePublicips, DisassociatePublicips
// (including idempotent disassociation when already unbound), and error paths.
func TestEIPv3Operations(t *testing.T) {
	c2 := newEIP(t)
	c3 := newEIPv3(t)
	net2 := newV2(t, realEndpoint)
	compute := newECS(t)
	images := newIMS(t)

	// --- Set up a VPC, subnet and two ECS servers so we have two NIC ports ---
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("eip-v3-sdk-vpc"), Cidr: ptr("10.61.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "the v3 test VPC to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
			return err == nil
		})
	})
	eventually(t, "the v3 test VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "eip-v3-sdk-subnet", Cidr: "10.61.1.0/24", GatewayIp: "10.61.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	t.Cleanup(func() {
		eventually(t, "the v3 test subnet to be deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
			return err == nil
		})
	})
	eventually(t, "the v3 test subnet to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	imgList, err := images.ListImages(&ims.ListImagesRequest{Name: ptr("Ubuntu 22.04 server 64bit")})
	if err != nil || imgList.Images == nil || len(*imgList.Images) != 1 {
		t.Fatalf("ListImages: %+v, %v", imgList, err)
	}
	imageID := (*imgList.Images)[0].Id

	srvCreated, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name:       "eip-v3-sdk-srv",
			ImageRef:   imageID,
			FlavorRef:  "s6.large.2",
			Vpcid:      vpcID,
			Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
			Count:      ptr(int32(2)),
		},
	}})
	if err != nil || srvCreated.JobId == nil || srvCreated.ServerIds == nil || len(*srvCreated.ServerIds) != 2 {
		t.Fatalf("CreatePostPaidServers: %+v, %v", srvCreated, err)
	}
	serverIDs := *srvCreated.ServerIds
	t.Cleanup(func() {
		var delServers []ecs.ServerId
		for _, id := range serverIDs {
			delServers = append(delServers, ecs.ServerId{Id: id})
		}
		del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{Servers: delServers}})
		if err == nil && del.JobId != nil {
			eventually(t, "v3 test delete servers job to finish", func() bool {
				job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *del.JobId})
				return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
			})
		}
	})
	eventually(t, "v3 test create servers job to finish", func() bool {
		job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *srvCreated.JobId})
		return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
	})

	type portDetails struct {
		id     string
		privIP string
		mac    string
	}
	portFor := func(srvID string) portDetails {
		t.Helper()
		ports, err := net2.ListPorts(&v2.ListPortsRequest{DeviceId: &srvID})
		if err != nil || ports.Ports == nil || len(*ports.Ports) != 1 || len((*ports.Ports)[0].FixedIps) == 0 {
			t.Fatalf("ListPorts(%s) = %+v, %v", srvID, ports, err)
		}
		p := (*ports.Ports)[0]
		return portDetails{id: p.Id, privIP: *p.FixedIps[0].IpAddress, mac: p.MacAddress}
	}
	port1 := portFor(serverIDs[0])
	port2 := portFor(serverIDs[1])

	// --- Create two EIPs via v1 and wait until DOWN --------------------
	perShare := eipv2.GetCreatePublicipBandwidthOptionShareTypeEnum().PER
	makeEIP := func(alias, bwName string, size int32) (id, addr, bwID string) {
		t.Helper()
		res, err := c2.CreatePublicip(&eipv2.CreatePublicipRequest{Body: &eipv2.CreatePublicipRequestBody{
			Publicip:  &eipv2.CreatePublicipOption{Type: "5_bgp", Alias: ptr(alias)},
			Bandwidth: &eipv2.CreatePublicipBandwidthOption{Name: ptr(bwName), ShareType: perShare, Size: ptr(size)},
		}})
		if err != nil || res.Publicip == nil || res.Publicip.Id == nil || res.Publicip.PublicIpAddress == nil {
			t.Fatalf("CreatePublicip(%s): %+v, %v", alias, res, err)
		}
		id = *res.Publicip.Id
		addr = *res.Publicip.PublicIpAddress
		t.Cleanup(func() {
			_, _ = c3.DisassociatePublicips(&eipv3.DisassociatePublicipsRequest{PublicipId: id})
			_, _ = c2.DeletePublicip(&eipv2.DeletePublicipRequest{PublicipId: id})
		})
		eventually(t, alias+" to become DOWN", func() bool {
			s, err := c2.ShowPublicip(&eipv2.ShowPublicipRequest{PublicipId: id})
			if err != nil {
				return false
			}
			if s.Publicip.BandwidthId != nil {
				bwID = *s.Publicip.BandwidthId
			}
			return s.Publicip.Status.Value() == "DOWN"
		})
		return id, addr, bwID
	}

	id1, addr1, bw1ID := makeEIP("sdk-v3-eip-1", "sdk-v3-bw-1", 5)
	id2, addr2, _ := makeEIP("sdk-v3-eip-2", "sdk-v3-bw-2", 10)

	// --- ShowPublicip (v3) on unbound EIP ------------------------------
	shown1, err := c3.ShowPublicip(&eipv3.ShowPublicipRequest{PublicipId: id1})
	if err != nil || shown1.RequestId == nil || *shown1.RequestId == "" || shown1.Publicip == nil {
		t.Fatalf("v3 ShowPublicip(1) = %+v, %v", shown1, err)
	}
	p1 := shown1.Publicip
	if p1.Id == nil || *p1.Id != id1 ||
		p1.ProjectId == nil || *p1.ProjectId != projectID ||
		p1.IpVersion == nil || p1.IpVersion.Value() != 4 ||
		p1.PublicIpAddress == nil || *p1.PublicIpAddress != addr1 ||
		p1.Status == nil || p1.Status.Value() != "DOWN" ||
		p1.Alias == nil || *p1.Alias != "sdk-v3-eip-1" ||
		p1.NetworkType == nil || *p1.NetworkType != "5_bgp" ||
		p1.PublicipPoolName == nil || *p1.PublicipPoolName != "5_bgp" ||
		p1.PublicBorderGroup == nil || *p1.PublicBorderGroup != "center" ||
		p1.EnterpriseProjectId == nil || *p1.EnterpriseProjectId != "0" ||
		p1.Type == nil || p1.Type.Value() != "EIP" ||
		p1.Vnic != nil ||
		p1.AssociateInstanceType != nil || p1.AssociateInstanceId != nil {
		t.Errorf("v3 ShowPublicip(1) unbound = %+v", p1)
	}
	if p1.CreatedAt == nil || time.Since(time.Time(*p1.CreatedAt)) > time.Hour ||
		p1.UpdatedAt == nil || time.Since(time.Time(*p1.UpdatedAt)) > time.Hour {
		t.Errorf("v3 timestamps not decoded as recent UTC times: created=%v updated=%v", p1.CreatedAt, p1.UpdatedAt)
	}
	if p1.Bandwidth == nil || p1.Bandwidth.Id == nil || *p1.Bandwidth.Id != bw1ID ||
		p1.Bandwidth.Size == nil || *p1.Bandwidth.Size != 5 ||
		p1.Bandwidth.ShareType == nil || *p1.Bandwidth.ShareType != "PER" ||
		p1.Bandwidth.ChargeMode == nil || *p1.Bandwidth.ChargeMode != "bandwidth" ||
		p1.Bandwidth.Name == nil || *p1.Bandwidth.Name != "sdk-v3-bw-1" {
		t.Errorf("v3 ShowPublicip(1) bandwidth = %+v", p1.Bandwidth)
	}

	_, err = c3.ShowPublicip(&eipv3.ShowPublicipRequest{PublicipId: unknownID})
	wantError(t, err, 404, "VPC.0504")

	// --- UpdatePublicip (v3): alias and description --------------------
	upd1, err := c3.UpdatePublicip(&eipv3.UpdatePublicipRequest{
		PublicipId: id1,
		Body: &eipv3.UpdatePublicipsRequestBody{
			Publicip: &eipv3.UpdatePublicipOption{
				Alias:       ptr("sdk-v3-eip-1-upd"),
				Description: ptr("updated via eip v3 sdk"),
			},
		},
	})
	if err != nil || upd1.RequestId == nil || *upd1.RequestId == "" || upd1.Publicip == nil {
		t.Fatalf("v3 UpdatePublicip(alias+desc) = %+v, %v", upd1, err)
	}
	if upd1.Publicip.Alias == nil || *upd1.Publicip.Alias != "sdk-v3-eip-1-upd" ||
		upd1.Publicip.Description == nil || *upd1.Publicip.Description != "updated via eip v3 sdk" ||
		upd1.Publicip.Status == nil || upd1.Publicip.Status.Value() != "DOWN" {
		t.Errorf("v3 UpdatePublicip(alias+desc) publicip = %+v", upd1.Publicip)
	}

	// UpdatePublicip error cases.
	_, err = c3.UpdatePublicip(&eipv3.UpdatePublicipRequest{
		PublicipId: unknownID,
		Body: &eipv3.UpdatePublicipsRequestBody{
			Publicip: &eipv3.UpdatePublicipOption{Alias: ptr("ghost")},
		},
	})
	wantError(t, err, 404, "VPC.0504")

	tooLongDesc := strings.Repeat("d", 256)
	_, err = c3.UpdatePublicip(&eipv3.UpdatePublicipRequest{
		PublicipId: id1,
		Body: &eipv3.UpdatePublicipsRequestBody{
			Publicip: &eipv3.UpdatePublicipOption{Description: &tooLongDesc},
		},
	})
	wantError(t, err, 400, "EIP.7901")

	_, err = c3.UpdatePublicip(&eipv3.UpdatePublicipRequest{
		PublicipId: id1,
		Body: &eipv3.UpdatePublicipsRequestBody{
			Publicip: &eipv3.UpdatePublicipOption{Alias: ptr("bad alias!")},
		},
	})
	wantError(t, err, 400, "EIP.7901")

	updNATGW := eipv3.GetUpdatePublicipOptionAssociateInstanceTypeEnum().NATGW
	_, err = c3.UpdatePublicip(&eipv3.UpdatePublicipRequest{
		PublicipId: id1,
		Body: &eipv3.UpdatePublicipsRequestBody{
			Publicip: &eipv3.UpdatePublicipOption{
				AssociateInstanceType: &updNATGW,
				AssociateInstanceId:   ptr(port1.id),
			},
		},
	})
	wantError(t, err, 501, "WeiStack.0501")

	// --- AssociatePublicips (v3) ---------------------------------------
	assocPort := eipv3.GetAssociatePublicipsOptionAssociateInstanceTypeEnum().PORT
	assocNATGW := eipv3.GetAssociatePublicipsOptionAssociateInstanceTypeEnum().NATGW
	assocELB := eipv3.GetAssociatePublicipsOptionAssociateInstanceTypeEnum().ELB

	// Error cases before binding.
	_, err = c3.AssociatePublicips(&eipv3.AssociatePublicipsRequest{
		PublicipId: unknownID,
		Body: &eipv3.AssociatePublicipsRequestBody{
			Publicip: &eipv3.AssociatePublicipsOption{
				AssociateInstanceType: assocPort,
				AssociateInstanceId:   port1.id,
			},
		},
	})
	wantError(t, err, 404, "VPC.0504")

	_, err = c3.AssociatePublicips(&eipv3.AssociatePublicipsRequest{
		PublicipId: id1,
		Body: &eipv3.AssociatePublicipsRequestBody{
			Publicip: &eipv3.AssociatePublicipsOption{
				AssociateInstanceType: assocNATGW,
				AssociateInstanceId:   port1.id,
			},
		},
	})
	wantError(t, err, 501, "WeiStack.0501")

	_, err = c3.AssociatePublicips(&eipv3.AssociatePublicipsRequest{
		PublicipId: id1,
		Body: &eipv3.AssociatePublicipsRequestBody{
			Publicip: &eipv3.AssociatePublicipsOption{
				AssociateInstanceType: assocELB,
				AssociateInstanceId:   port1.id,
			},
		},
	})
	wantError(t, err, 501, "WeiStack.0501")

	_, err = c3.AssociatePublicips(&eipv3.AssociatePublicipsRequest{
		PublicipId: id1,
		Body: &eipv3.AssociatePublicipsRequestBody{
			Publicip: &eipv3.AssociatePublicipsOption{
				AssociateInstanceType: assocPort,
				AssociateInstanceId:   unknownID,
			},
		},
	})
	wantError(t, err, 500, "VPC.0508")

	// Bind EIP 1 to server 1's NIC port.
	assoc1, err := c3.AssociatePublicips(&eipv3.AssociatePublicipsRequest{
		PublicipId: id1,
		Body: &eipv3.AssociatePublicipsRequestBody{
			Publicip: &eipv3.AssociatePublicipsOption{
				AssociateInstanceType: assocPort,
				AssociateInstanceId:   port1.id,
			},
		},
	})
	if err != nil || assoc1.RequestId == nil || *assoc1.RequestId == "" || assoc1.Publicip == nil {
		t.Fatalf("v3 AssociatePublicips(1 -> port1) = %+v, %v", assoc1, err)
	}
	a1 := assoc1.Publicip
	if a1.Status == nil || a1.Status.Value() != "ACTIVE" ||
		a1.AssociateInstanceType == nil || a1.AssociateInstanceType.Value() != "PORT" ||
		a1.AssociateInstanceId == nil || *a1.AssociateInstanceId != port1.id ||
		a1.Alias == nil || *a1.Alias != "sdk-v3-eip-1-upd" ||
		a1.Description == nil || *a1.Description != "updated via eip v3 sdk" {
		t.Errorf("v3 AssociatePublicips(1) = %+v", a1)
	}
	if a1.Vnic == nil ||
		a1.Vnic.PortId == nil || *a1.Vnic.PortId != port1.id ||
		a1.Vnic.PrivateIpAddress == nil || *a1.Vnic.PrivateIpAddress != port1.privIP ||
		a1.Vnic.DeviceId == nil || *a1.Vnic.DeviceId != serverIDs[0] ||
		a1.Vnic.VpcId == nil || *a1.Vnic.VpcId != vpcID ||
		a1.Vnic.Mac == nil || *a1.Vnic.Mac != port1.mac {
		t.Errorf("v3 AssociatePublicips(1) vnic = %+v, want port=%s ip=%s dev=%s vpc=%s mac=%s",
			a1.Vnic, port1.id, port1.privIP, serverIDs[0], vpcID, port1.mac)
	}
	if a1.Bandwidth == nil || a1.Bandwidth.Id == nil || *a1.Bandwidth.Id != bw1ID {
		t.Errorf("v3 AssociatePublicips(1) bandwidth = %+v", a1.Bandwidth)
	}

	// Verify ShowPublicip reflects bound vnic and associate fields.
	shownBound, err := c3.ShowPublicip(&eipv3.ShowPublicipRequest{PublicipId: id1})
	if err != nil || shownBound.Publicip == nil ||
		shownBound.Publicip.Status == nil || shownBound.Publicip.Status.Value() != "ACTIVE" ||
		shownBound.Publicip.AssociateInstanceType == nil || shownBound.Publicip.AssociateInstanceType.Value() != "PORT" ||
		shownBound.Publicip.AssociateInstanceId == nil || *shownBound.Publicip.AssociateInstanceId != port1.id ||
		shownBound.Publicip.Vnic == nil || shownBound.Publicip.Vnic.PortId == nil || *shownBound.Publicip.Vnic.PortId != port1.id {
		t.Fatalf("v3 ShowPublicip(1) after bind = %+v, %v", shownBound, err)
	}

	// Binding already-bound EIP 1 to port 2 -> VPC.0510.
	_, err = c3.AssociatePublicips(&eipv3.AssociatePublicipsRequest{
		PublicipId: id1,
		Body: &eipv3.AssociatePublicipsRequestBody{
			Publicip: &eipv3.AssociatePublicipsOption{
				AssociateInstanceType: assocPort,
				AssociateInstanceId:   port2.id,
			},
		},
	})
	wantError(t, err, 409, "VPC.0510")

	// Binding EIP 2 to already-bound port 1 -> VPC.0511.
	_, err = c3.AssociatePublicips(&eipv3.AssociatePublicipsRequest{
		PublicipId: id2,
		Body: &eipv3.AssociatePublicipsRequestBody{
			Publicip: &eipv3.AssociatePublicipsOption{
				AssociateInstanceType: assocPort,
				AssociateInstanceId:   port1.id,
			},
		},
	})
	wantError(t, err, 409, "VPC.0511")

	// --- UpdatePublicip (v3) binding EIP 2 to port 2 -------------------
	updPort := eipv3.GetUpdatePublicipOptionAssociateInstanceTypeEnum().PORT
	updBind, err := c3.UpdatePublicip(&eipv3.UpdatePublicipRequest{
		PublicipId: id2,
		Body: &eipv3.UpdatePublicipsRequestBody{
			Publicip: &eipv3.UpdatePublicipOption{
				AssociateInstanceType: &updPort,
				AssociateInstanceId:   &port2.id,
			},
		},
	})
	if err != nil || updBind.Publicip == nil ||
		updBind.Publicip.Status == nil || updBind.Publicip.Status.Value() != "ACTIVE" ||
		updBind.Publicip.AssociateInstanceType == nil || updBind.Publicip.AssociateInstanceType.Value() != "PORT" ||
		updBind.Publicip.AssociateInstanceId == nil || *updBind.Publicip.AssociateInstanceId != port2.id ||
		updBind.Publicip.Vnic == nil || updBind.Publicip.Vnic.PortId == nil || *updBind.Publicip.Vnic.PortId != port2.id {
		t.Fatalf("v3 UpdatePublicip(bind port2) = %+v, %v", updBind, err)
	}

	// --- ListPublicips (v3): filters and pagination --------------------
	listActive := eipv3.GetListPublicipsRequestStatusEnum().ACTIVE
	listPortType := eipv3.GetListPublicipsRequestAssociateInstanceTypeEnum().PORT
	listPer := eipv3.GetListPublicipsRequestBandwidthShareTypeEnum().PER
	listV4 := eipv3.GetListPublicipsRequestIpVersionEnum().E_4

	filtered, err := c3.ListPublicips(&eipv3.ListPublicipsRequest{
		Id:                    &[]string{id1},
		PublicIpAddress:       &[]string{addr1},
		IpVersion:             &[]eipv3.ListPublicipsRequestIpVersion{listV4},
		Status:                &[]eipv3.ListPublicipsRequestStatus{listActive},
		Alias:                 &[]string{"sdk-v3-eip-1-upd"},
		VnicPortId:            &[]string{port1.id},
		VnicPrivateIpAddress:  &[]string{port1.privIP},
		VnicDeviceId:          &[]string{serverIDs[0]},
		VnicVpcId:             &[]string{vpcID},
		BandwidthId:           &[]string{bw1ID},
		BandwidthShareType:    &[]eipv3.ListPublicipsRequestBandwidthShareType{listPer},
		AssociateInstanceType: &[]eipv3.ListPublicipsRequestAssociateInstanceType{listPortType},
		AssociateInstanceId:   &[]string{port1.id},
		EnterpriseProjectId:   &[]string{"all_granted_eps"},
	})
	if err != nil || filtered.RequestId == nil || *filtered.RequestId == "" ||
		filtered.Publicips == nil || len(*filtered.Publicips) != 1 ||
		*(*filtered.Publicips)[0].Id != id1 ||
		filtered.PageInfo == nil || filtered.PageInfo.CurrentCount == nil || *filtered.PageInfo.CurrentCount != 1 {
		t.Fatalf("v3 ListPublicips(filters) = %+v, %v", filtered, err)
	}

	// Paginate across both EIPs with limit=1.
	seen := map[string]int{}
	var marker *string
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("v3 ListPublicips paging did not terminate")
		}
		res, err := c3.ListPublicips(&eipv3.ListPublicipsRequest{
			Id:     &[]string{id1, id2},
			Limit:  ptr(int32(1)),
			Marker: marker,
		})
		if err != nil {
			t.Fatalf("v3 ListPublicips(page %d): %v", pages, err)
		}
		if res.RequestId == nil || *res.RequestId == "" {
			t.Errorf("v3 ListPublicips(page %d) missing request_id", pages)
		}
		if res.Publicips == nil || len(*res.Publicips) == 0 {
			break
		}
		for _, p := range *res.Publicips {
			seen[*p.Id]++
		}
		if res.PageInfo == nil || res.PageInfo.NextMarker == nil || *res.PageInfo.NextMarker == "" {
			break
		}
		marker = res.PageInfo.NextMarker
	}
	if seen[id1] != 1 || seen[id2] != 1 {
		t.Errorf("v3 ListPublicips paging seen = %v, want 1 each for %s (%s) and %s (%s)", seen, id1, addr1, id2, addr2)
	}

	_, err = c3.ListPublicips(&eipv3.ListPublicipsRequest{Marker: ptr(unknownID)})
	wantError(t, err, 404, "VPC.0504")
	_, err = c3.ListPublicips(&eipv3.ListPublicipsRequest{Limit: ptr(int32(-1))})
	wantError(t, err, 400, "VPC.0501")

	// --- DisassociatePublicips (v3) ------------------------------------
	dis1, err := c3.DisassociatePublicips(&eipv3.DisassociatePublicipsRequest{PublicipId: id1})
	if err != nil || dis1.RequestId == nil || *dis1.RequestId == "" || dis1.Publicip == nil ||
		dis1.Publicip.Status == nil || dis1.Publicip.Status.Value() != "DOWN" ||
		dis1.Publicip.Vnic != nil ||
		dis1.Publicip.AssociateInstanceType != nil || dis1.Publicip.AssociateInstanceId != nil {
		t.Fatalf("v3 DisassociatePublicips(1) = %+v, %v", dis1, err)
	}

	// Disassociating an already-unbound EIP is not an error (§3.4).
	disAgain, err := c3.DisassociatePublicips(&eipv3.DisassociatePublicipsRequest{PublicipId: id1})
	if err != nil || disAgain.RequestId == nil || *disAgain.RequestId == "" || disAgain.Publicip == nil ||
		disAgain.Publicip.Status == nil || disAgain.Publicip.Status.Value() != "DOWN" {
		t.Fatalf("v3 DisassociatePublicips(already unbound) = %+v, %v", disAgain, err)
	}

	dis2, err := c3.DisassociatePublicips(&eipv3.DisassociatePublicipsRequest{PublicipId: id2})
	if err != nil || dis2.Publicip == nil || dis2.Publicip.Status == nil || dis2.Publicip.Status.Value() != "DOWN" {
		t.Fatalf("v3 DisassociatePublicips(2) = %+v, %v", dis2, err)
	}

	_, err = c3.DisassociatePublicips(&eipv3.DisassociatePublicipsRequest{PublicipId: unknownID})
	wantError(t, err, 404, "VPC.0504")
}
