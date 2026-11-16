package sdk

import (
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	eipv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2"
	eip "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2/model"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	ims "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ims/v2/model"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

func newEIP(t *testing.T) *eipv2.EipClient {
	t.Helper()
	return eipAs(t, signingAK("AKEIPSDKEXAMPLE00000"), signingSK())
}

// eipAs builds an EIP v2 client that signs with ak and sk against the VPC endpoint.
func eipAs(t *testing.T, ak, sk string) *eipv2.EipClient {
	t.Helper()
	cred, err := basic.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		WithProjectId(projectID).
		SafeBuild()
	if err != nil {
		t.Fatalf("building credentials: %v", err)
	}
	hc, err := eipv2.EipClientBuilder().
		WithEndpoints([]string{realEndpoint}).
		WithCredential(cred).
		WithHttpConfig(httpConfigAt(emulatorAddr)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building EIP client: %v", err)
	}
	return eipv2.NewEipClient(hc)
}

// TestPublicIPLifecycleAndBinding drives §3.1 through the official EIP v2
// SDK: creating EIPs (auto-allocated and explicit IP, bound and unbound),
// PENDING_CREATE -> DOWN/ACTIVE lifecycle transitions, binding/unbinding
// to VPC ports, renaming without unbinding, listing with filters and
// pagination, deleting, and error cases.
func TestPublicIPLifecycleAndBinding(t *testing.T) {
	c := newEIP(t)
	net2 := newV2(t, realEndpoint)
	compute := newECS(t)
	images := newIMS(t)

	// --- Set up a VPC, subnet and two servers so we have two ports -----
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("eip-sdk-vpc"), Cidr: ptr("10.60.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "the VPC to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
			return err == nil
		})
	})
	eventually(t, "the VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "eip-sdk-subnet", Cidr: "10.60.1.0/24", GatewayIp: "10.60.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	t.Cleanup(func() {
		eventually(t, "the subnet to be deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
			return err == nil
		})
	})
	eventually(t, "the subnet to become ACTIVE", func() bool {
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
			Name:       "eip-sdk-srv",
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
			eventually(t, "delete servers job to finish", func() bool {
				job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *del.JobId})
				return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
			})
		}
	})
	eventually(t, "create servers job to finish", func() bool {
		job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *srvCreated.JobId})
		return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
	})

	portFor := func(srvID string) (portID, privIP string) {
		t.Helper()
		ports, err := net2.ListPorts(&v2.ListPortsRequest{DeviceId: &srvID})
		if err != nil || ports.Ports == nil || len(*ports.Ports) != 1 || len((*ports.Ports)[0].FixedIps) == 0 {
			t.Fatalf("ListPorts(%s) = %+v, %v", srvID, ports, err)
		}
		p := (*ports.Ports)[0]
		return p.Id, *p.FixedIps[0].IpAddress
	}
	port1, privIP1 := portFor(serverIDs[0])
	port2, privIP2 := portFor(serverIDs[1])

	// --- CreatePublicip validation errors -----------------------------
	perShare := eip.GetCreatePublicipBandwidthOptionShareTypeEnum().PER
	wholeShare := eip.GetCreatePublicipBandwidthOptionShareTypeEnum().WHOLE
	ipv4 := eip.GetCreatePublicipOptionIpVersionEnum().E_4
	ipv6 := eip.GetCreatePublicipOptionIpVersionEnum().E_6

	// Invalid EIP type -> VPC.0501.
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "invalid_type"},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("bw"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	wantError(t, err, 400, "VPC.0501")

	// IPv6 is not emulated -> WeiStack.0501.
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp", IpVersion: &ipv6},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("bw"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	wantError(t, err, 501, "WeiStack.0501")

	// Requested IP outside the pool ranges -> VPC.0522.
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp", IpAddress: ptr("10.0.0.1")},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("bw"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	wantError(t, err, 409, "VPC.0522")

	// Invalid alias -> VPC.0501.
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp", Alias: ptr("bad alias!")},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("bw"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	wantError(t, err, 400, "VPC.0501")

	// Unknown port_id on create -> VPC.0508 (500).
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp", PortId: ptr(unknownID)},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("bw"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	wantError(t, err, 500, "VPC.0508")

	// Invalid PER bandwidth size -> VPC.0301.
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp"},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("bw"), ShareType: perShare, Size: ptr(int32(301))},
	}})
	wantError(t, err, 400, "VPC.0301")

	// Unknown WHOLE bandwidth -> VPC.0306.
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp"},
		Bandwidth: &eip.CreatePublicipBandwidthOption{ShareType: wholeShare, Id: ptr(unknownID)},
	}})
	wantError(t, err, 404, "VPC.0306")

	// Invalid enterprise_project_id -> VPC.0011.
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:            &eip.CreatePublicipOption{Type: "5_bgp"},
		Bandwidth:           &eip.CreatePublicipBandwidthOption{Name: ptr("bw"), ShareType: perShare, Size: ptr(int32(5))},
		EnterpriseProjectId: ptr("not-a-uuid"),
	}})
	wantError(t, err, 400, "VPC.0011")

	// --- Create first EIP (unbound) -----------------------------------
	created1, err := c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip: &eip.CreatePublicipOption{
			Type:      "5_bgp",
			IpVersion: &ipv4,
			Alias:     ptr("sdk-eip-1"),
		},
		Bandwidth: &eip.CreatePublicipBandwidthOption{
			Name:      ptr("sdk-bw-1"),
			ShareType: perShare,
			Size:      ptr(int32(5)),
		},
	}})
	if err != nil || created1.Publicip == nil || created1.Publicip.Id == nil {
		t.Fatalf("CreatePublicip(1): %+v, %v", created1, err)
	}
	pip1 := created1.Publicip
	id1 := *pip1.Id
	t.Cleanup(func() {
		_, _ = c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id1, Body: &eip.UpdatePublicipsRequestBody{Publicip: &eip.UpdatePublicipOption{}}})
		_, _ = c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: id1})
	})

	if pip1.Status == nil || pip1.Status.Value() != "PENDING_CREATE" {
		t.Errorf("new EIP status = %v, want PENDING_CREATE", pip1.Status)
	}
	if pip1.BandwidthSize == nil || *pip1.BandwidthSize != 0 {
		t.Errorf("create response bandwidth_size = %v, want 0", pip1.BandwidthSize)
	}
	if pip1.Type == nil || *pip1.Type != "5_bgp" || pip1.IpVersion == nil || pip1.IpVersion.Value() != 4 ||
		pip1.TenantId == nil || *pip1.TenantId != projectID || pip1.EnterpriseProjectId == nil || *pip1.EnterpriseProjectId != "0" ||
		pip1.Alias == nil || *pip1.Alias != "sdk-eip-1" || pip1.PublicIpAddress == nil || *pip1.PublicIpAddress == "" {
		t.Errorf("created EIP = %+v", pip1)
	}
	if pip1.CreateTime == nil || time.Since(time.Time(*pip1.CreateTime)) > time.Hour {
		t.Errorf("create_time not decoded as recent time: %v", pip1.CreateTime)
	}
	addr1 := *pip1.PublicIpAddress

	// Deleting while PENDING_CREATE is refused with VPC.0512.
	_, err = c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: id1})
	wantError(t, err, 409, "VPC.0512")

	eventually(t, "EIP 1 to become DOWN", func() bool {
		shown, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: id1})
		if err != nil {
			t.Fatalf("ShowPublicip(1): %v", err)
		}
		return shown.Publicip.Status.Value() == "DOWN"
	})

	shown1, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: id1})
	if err != nil {
		t.Fatalf("ShowPublicip(1): %v", err)
	}
	s1 := shown1.Publicip
	if s1.BandwidthId == nil || *s1.BandwidthId == "" || s1.BandwidthName == nil || *s1.BandwidthName != "sdk-bw-1" ||
		s1.BandwidthShareType == nil || s1.BandwidthShareType.Value() != "PER" || s1.BandwidthSize == nil || *s1.BandwidthSize != 5 ||
		s1.PublicBorderGroup == nil || *s1.PublicBorderGroup != "center" || s1.PortId != nil || s1.PrivateIpAddress != nil {
		t.Errorf("ShowPublicip(1) = %+v", s1)
	}
	bw1ID := *s1.BandwidthId

	// Requesting an address already in use -> VPC.0522.
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp", IpAddress: &addr1},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("bw-dup"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	wantError(t, err, 409, "VPC.0522")

	// --- Create second EIP with explicit IP and port_id ---------------
	const explicitIP = "198.51.100.200"
	created2, err := c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip: &eip.CreatePublicipOption{
			Type:      "5_bgp",
			IpAddress: ptr(explicitIP),
			PortId:    &port2,
			Alias:     ptr("sdk-eip-2"),
		},
		Bandwidth: &eip.CreatePublicipBandwidthOption{
			Name:      ptr("sdk-bw-2"),
			ShareType: perShare,
			Size:      ptr(int32(10)),
		},
	}})
	if err != nil || created2.Publicip == nil || created2.Publicip.Id == nil {
		t.Fatalf("CreatePublicip(2): %+v, %v", created2, err)
	}
	id2 := *created2.Publicip.Id
	t.Cleanup(func() {
		_, _ = c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id2, Body: &eip.UpdatePublicipsRequestBody{Publicip: &eip.UpdatePublicipOption{}}})
		_, _ = c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: id2})
	})
	if *created2.Publicip.PublicIpAddress != explicitIP {
		t.Errorf("EIP 2 address = %q, want %q", *created2.Publicip.PublicIpAddress, explicitIP)
	}

	eventually(t, "EIP 2 (created with port_id) to become ACTIVE", func() bool {
		shown, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: id2})
		if err != nil {
			t.Fatalf("ShowPublicip(2): %v", err)
		}
		return shown.Publicip.Status.Value() == "ACTIVE"
	})
	shown2, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: id2})
	if err != nil || shown2.Publicip.PortId == nil || *shown2.Publicip.PortId != port2 ||
		shown2.Publicip.PrivateIpAddress == nil || *shown2.Publicip.PrivateIpAddress != privIP2 {
		t.Fatalf("ShowPublicip(2) bound = %+v, %v", shown2, err)
	}

	// Creating another EIP on an already-bound port -> VPC.0511.
	_, err = c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp", PortId: &port2},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("bw"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	wantError(t, err, 409, "VPC.0511")

	// --- UpdatePublicip (bind, rename, unbind, error cases) -----------
	_, err = c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: unknownID})
	wantError(t, err, 404, "VPC.0504")

	_, err = c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: unknownID, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{Alias: ptr("ghost")},
	}})
	wantError(t, err, 404, "VPC.0504")

	// Unknown port on update -> VPC.0501.
	_, err = c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id1, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{PortId: ptr(unknownID)},
	}})
	wantError(t, err, 400, "VPC.0501")

	// Port 2 already has EIP 2 -> VPC.0511.
	_, err = c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id1, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{PortId: &port2},
	}})
	wantError(t, err, 409, "VPC.0511")

	// Bind EIP 1 to port 1.
	upd1, err := c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id1, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{PortId: &port1},
	}})
	if err != nil || upd1.Publicip == nil || upd1.Publicip.Status.Value() != "ACTIVE" ||
		upd1.Publicip.PortId == nil || *upd1.Publicip.PortId != port1 ||
		upd1.Publicip.PrivateIpAddress == nil || *upd1.Publicip.PrivateIpAddress != privIP1 {
		t.Fatalf("UpdatePublicip(bind port1) = %+v, %v", upd1, err)
	}

	// Binding an already-bound EIP to a different port -> VPC.0510.
	// First unbind EIP 2 from port 2 using port_id="" so port 2 is free.
	upd2Unbind, err := c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id2, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{PortId: ptr("")},
	}})
	if err != nil || upd2Unbind.Publicip == nil || upd2Unbind.Publicip.Status.Value() != "DOWN" || upd2Unbind.Publicip.PortId != nil {
		t.Fatalf("UpdatePublicip(unbind port2 with empty string) = %+v, %v", upd2Unbind, err)
	}

	_, err = c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id1, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{PortId: &port2},
	}})
	wantError(t, err, 409, "VPC.0510")

	// Binding to the same port is a no-op.
	sameBind, err := c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id1, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{PortId: &port1},
	}})
	if err != nil || sameBind.Publicip.Status.Value() != "ACTIVE" {
		t.Fatalf("UpdatePublicip(same port) = %+v, %v", sameBind, err)
	}

	// Renaming by sending only alias must NOT unbind the EIP (§3.1).
	renamed, err := c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id1, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{Alias: ptr("sdk-eip-1-renamed")},
	}})
	if err != nil || renamed.Publicip == nil || renamed.Publicip.Alias == nil || *renamed.Publicip.Alias != "sdk-eip-1-renamed" ||
		renamed.Publicip.Status.Value() != "ACTIVE" || renamed.Publicip.PortId == nil || *renamed.Publicip.PortId != port1 {
		t.Fatalf("UpdatePublicip(rename bound EIP) = %+v, %v", renamed, err)
	}

	// port_id and ip_version together -> VPC.0501.
	updIPv4 := eip.GetUpdatePublicipOptionIpVersionEnum().E_4
	_, err = c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id1, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{PortId: &port1, IpVersion: &updIPv4},
	}})
	wantError(t, err, 400, "VPC.0501")

	// Deleting a bound EIP -> VPC.0517.
	_, err = c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: id1})
	wantError(t, err, 409, "VPC.0517")

	// --- ListPublicips (filters and paging) ---------------------------
	listVer4 := eip.GetListPublicipsRequestIpVersionEnum().E_4
	byPort, err := c.ListPublicips(&eip.ListPublicipsRequest{
		PortId:              &[]string{port1},
		PrivateIpAddress:    &[]string{privIP1},
		PublicIpAddress:     &[]string{addr1},
		IpVersion:           &listVer4,
		EnterpriseProjectId: ptr("all_granted_eps"),
	})
	if err != nil || byPort.Publicips == nil || len(*byPort.Publicips) != 1 || *(*byPort.Publicips)[0].Id != id1 {
		t.Fatalf("ListPublicips(filters) = %+v, %v", byPort, err)
	}

	// Paging across the two EIPs.
	seen := map[string]int{}
	var marker *string
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("ListPublicips paging did not terminate")
		}
		res, err := c.ListPublicips(&eip.ListPublicipsRequest{
			Id:     &[]string{id1, id2},
			Limit:  ptr(int32(1)),
			Marker: marker,
		})
		if err != nil {
			t.Fatalf("ListPublicips(page): %v", err)
		}
		if res.Publicips == nil || len(*res.Publicips) == 0 {
			break
		}
		for _, p := range *res.Publicips {
			seen[*p.Id]++
		}
		last := *(*res.Publicips)[len(*res.Publicips)-1].Id
		marker = &last
	}
	if seen[id1] != 1 || seen[id2] != 1 {
		t.Errorf("ListPublicips paging seen = %v, want 1 each for %s and %s", seen, id1, id2)
	}

	_, err = c.ListPublicips(&eip.ListPublicipsRequest{Marker: ptr(unknownID)})
	wantError(t, err, 404, "VPC.0504")
	_, err = c.ListPublicips(&eip.ListPublicipsRequest{Limit: ptr(int32(-1))})
	wantError(t, err, 400, "VPC.0501")

	// --- Unbind with empty object (Terraform style) and delete --------
	unbound1, err := c.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: id1, Body: &eip.UpdatePublicipsRequestBody{
		Publicip: &eip.UpdatePublicipOption{},
	}})
	if err != nil || unbound1.Publicip == nil || unbound1.Publicip.Status.Value() != "DOWN" || unbound1.Publicip.PortId != nil {
		t.Fatalf("UpdatePublicip(empty object unbind) = %+v, %v", unbound1, err)
	}

	if _, err := c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: id1}); err != nil {
		t.Fatalf("DeletePublicip(1): %v", err)
	}
	if _, err := c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: id2}); err != nil {
		t.Fatalf("DeletePublicip(2): %v", err)
	}
	_, err = c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: id1})
	wantError(t, err, 404, "VPC.0504")
	_, err = c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: id1})
	wantError(t, err, 404, "VPC.0504")
	// Deleting the EIP also deletes its dedicated PER bandwidth.
	_, err = c.ShowBandwidth(&eip.ShowBandwidthRequest{BandwidthId: bw1ID})
	wantError(t, err, 404, "VPC.0306")
}

// TestBandwidthsAndSharedBandwidth drives §3.2 through the official EIP v2
// SDK: dedicated and shared bandwidths, v1 and v2.0 updates, inserting
// and removing EIPs, creating an EIP directly on a shared bandwidth, and
// error cases.
func TestBandwidthsAndSharedBandwidth(t *testing.T) {
	c := newEIP(t)
	perShare := eip.GetCreatePublicipBandwidthOptionShareTypeEnum().PER
	wholeShare := eip.GetCreatePublicipBandwidthOptionShareTypeEnum().WHOLE

	// Create an EIP with a dedicated (PER) bandwidth.
	created, err := c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp", Alias: ptr("sdk-bw-eip")},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("sdk-per-bw"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	if err != nil || created.Publicip == nil || created.Publicip.Id == nil {
		t.Fatalf("CreatePublicip: %+v, %v", created, err)
	}
	pipID := *created.Publicip.Id
	t.Cleanup(func() {
		_, _ = c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: pipID})
	})
	eventually(t, "EIP to become DOWN", func() bool {
		s, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pipID})
		return err == nil && s.Publicip.Status.Value() == "DOWN"
	})
	shownPIP, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pipID})
	if err != nil {
		t.Fatalf("ShowPublicip: %v", err)
	}
	perBWID := *shownPIP.Publicip.BandwidthId

	// --- ShowBandwidth and UpdateBandwidth (v1) -----------------------
	shownBW, err := c.ShowBandwidth(&eip.ShowBandwidthRequest{BandwidthId: perBWID})
	if err != nil || shownBW.Bandwidth == nil {
		t.Fatalf("ShowBandwidth(PER): %+v, %v", shownBW, err)
	}
	bw := shownBW.Bandwidth
	if bw.Name == nil || *bw.Name != "sdk-per-bw" || bw.Size == nil || *bw.Size != 5 ||
		bw.ShareType == nil || bw.ShareType.Value() != "PER" ||
		bw.BandwidthType == nil || *bw.BandwidthType != "bgp" ||
		bw.ChargeMode == nil || bw.ChargeMode.Value() != "bandwidth" ||
		bw.Status == nil || bw.Status.Value() != "NORMAL" ||
		bw.PublicBorderGroup == nil || *bw.PublicBorderGroup != "center" ||
		bw.EnableBandwidthRules == nil || *bw.EnableBandwidthRules ||
		bw.RuleQuota == nil || *bw.RuleQuota != 0 ||
		bw.PublicipInfo == nil || len(*bw.PublicipInfo) != 1 || *(*bw.PublicipInfo)[0].PublicipId != pipID {
		t.Errorf("ShowBandwidth(PER) = %+v", bw)
	}

	traffic := eip.GetUpdateBandwidthOptionChargeModeEnum().TRAFFIC
	updBW, err := c.UpdateBandwidth(&eip.UpdateBandwidthRequest{
		BandwidthId: perBWID,
		Body: &eip.UpdateBandwidthRequestBody{Bandwidth: &eip.UpdateBandwidthOption{
			Name:       ptr("sdk-per-bw-renamed"),
			Size:       ptr(int32(15)),
			ChargeMode: &traffic,
		}},
	})
	if err != nil || updBW.Bandwidth == nil || *updBW.Bandwidth.Name != "sdk-per-bw-renamed" ||
		*updBW.Bandwidth.Size != 15 || updBW.Bandwidth.ChargeMode.Value() != "traffic" {
		t.Fatalf("UpdateBandwidth(v1) = %+v, %v", updBW, err)
	}

	// Error cases for Show/Update/Delete on PER or unknown bandwidth.
	_, err = c.ShowBandwidth(&eip.ShowBandwidthRequest{BandwidthId: unknownID})
	wantError(t, err, 404, "VPC.0306")
	_, err = c.UpdateBandwidth(&eip.UpdateBandwidthRequest{BandwidthId: unknownID, Body: &eip.UpdateBandwidthRequestBody{
		Bandwidth: &eip.UpdateBandwidthOption{Size: ptr(int32(10))},
	}})
	wantError(t, err, 404, "VPC.0306")
	_, err = c.UpdateBandwidth(&eip.UpdateBandwidthRequest{BandwidthId: perBWID, Body: &eip.UpdateBandwidthRequestBody{
		Bandwidth: &eip.UpdateBandwidthOption{Size: ptr(int32(301))},
	}})
	wantError(t, err, 400, "VPC.0301")
	// A PER bandwidth cannot be deleted via DeleteSharedBandwidth -> VPC.0323.
	_, err = c.DeleteSharedBandwidth(&eip.DeleteSharedBandwidthRequest{BandwidthId: perBWID})
	wantError(t, err, 400, "VPC.0323")

	// --- CreateSharedBandwidth and UpdatePrePaidBandwidth (v2.0) ------
	_, err = c.CreateSharedBandwidth(&eip.CreateSharedBandwidthRequest{Body: &eip.CreateSharedBandwidhRequestBody{
		Bandwidth: &eip.CreateSharedBandwidthOption{Name: "too-small", Size: 4},
	}})
	wantError(t, err, 400, "VPC.0301")

	sharedCreated, err := c.CreateSharedBandwidth(&eip.CreateSharedBandwidthRequest{Body: &eip.CreateSharedBandwidhRequestBody{
		Bandwidth: &eip.CreateSharedBandwidthOption{
			Name: "sdk-shared-bw",
			Size: 10,
		},
	}})
	if err != nil || sharedCreated.Bandwidth == nil || sharedCreated.Bandwidth.Id == nil {
		t.Fatalf("CreateSharedBandwidth: %+v, %v", sharedCreated, err)
	}
	sharedID := *sharedCreated.Bandwidth.Id
	t.Cleanup(func() {
		_, _ = c.DeleteSharedBandwidth(&eip.DeleteSharedBandwidthRequest{BandwidthId: sharedID})
	})
	if sharedCreated.Bandwidth.ShareType == nil || sharedCreated.Bandwidth.ShareType.Value() != "WHOLE" ||
		sharedCreated.Bandwidth.BandwidthType == nil || *sharedCreated.Bandwidth.BandwidthType != "share" ||
		sharedCreated.Bandwidth.Size == nil || *sharedCreated.Bandwidth.Size != 10 {
		t.Errorf("created shared bandwidth = %+v", sharedCreated.Bandwidth)
	}

	updPrePaid, err := c.UpdatePrePaidBandwidth(&eip.UpdatePrePaidBandwidthRequest{
		BandwidthId: sharedID,
		Body: &eip.UpdatePrePaidBandwidthRequestBody{Bandwidth: &eip.UpdatePrePaidBandwidthOption{
			Name: ptr("sdk-shared-bw-renamed"),
			Size: ptr(int32(25)),
		}},
	})
	if err != nil || updPrePaid.Bandwidth == nil || *updPrePaid.Bandwidth.Name != "sdk-shared-bw-renamed" || *updPrePaid.Bandwidth.Size != 25 {
		t.Fatalf("UpdatePrePaidBandwidth = %+v, %v", updPrePaid, err)
	}

	// --- ListBandwidths -----------------------------------------------
	wholeFilter := eip.GetListBandwidthsRequestShareTypeEnum().WHOLE
	listedWhole, err := c.ListBandwidths(&eip.ListBandwidthsRequest{
		ShareType:           &wholeFilter,
		EnterpriseProjectId: ptr("all_granted_eps"),
	})
	if err != nil || listedWhole.Bandwidths == nil || len(*listedWhole.Bandwidths) == 0 {
		t.Fatalf("ListBandwidths(WHOLE) = %+v, %v", listedWhole, err)
	}
	foundShared := false
	for _, b := range *listedWhole.Bandwidths {
		if b.Id != nil && *b.Id == sharedID {
			foundShared = true
		}
	}
	if !foundShared {
		t.Errorf("ListBandwidths(WHOLE) did not include %s", sharedID)
	}

	_, err = c.ListBandwidths(&eip.ListBandwidthsRequest{Marker: ptr(unknownID)})
	wantError(t, err, 404, "VPC.0306")
	_, err = c.ListBandwidths(&eip.ListBandwidthsRequest{Limit: ptr(int32(-1))})
	wantError(t, err, 400, "VPC.0301")

	// --- AddPublicipsIntoSharedBandwidth ------------------------------
	// Target must be WHOLE, not PER -> VPC.0323.
	_, err = c.AddPublicipsIntoSharedBandwidth(&eip.AddPublicipsIntoSharedBandwidthRequest{
		BandwidthId: perBWID,
		Body: &eip.AddPublicipsIntoSharedBandwidthRequestBody{Bandwidth: &eip.AddPublicipsIntoSharedBandwidthOption{
			PublicipInfo: []eip.InsertPublicipInfo{{PublicipId: pipID}},
		}},
	})
	wantError(t, err, 400, "VPC.0323")

	// Unknown publicip_id -> VPC.0301.
	_, err = c.AddPublicipsIntoSharedBandwidth(&eip.AddPublicipsIntoSharedBandwidthRequest{
		BandwidthId: sharedID,
		Body: &eip.AddPublicipsIntoSharedBandwidthRequestBody{Bandwidth: &eip.AddPublicipsIntoSharedBandwidthOption{
			PublicipInfo: []eip.InsertPublicipInfo{{PublicipId: unknownID}},
		}},
	})
	wantError(t, err, 400, "VPC.0301")

	inserted, err := c.AddPublicipsIntoSharedBandwidth(&eip.AddPublicipsIntoSharedBandwidthRequest{
		BandwidthId: sharedID,
		Body: &eip.AddPublicipsIntoSharedBandwidthRequestBody{Bandwidth: &eip.AddPublicipsIntoSharedBandwidthOption{
			PublicipInfo: []eip.InsertPublicipInfo{{PublicipId: pipID}},
		}},
	})
	if err != nil || inserted.Bandwidth == nil || inserted.Bandwidth.PublicipInfo == nil || len(*inserted.Bandwidth.PublicipInfo) != 1 ||
		*(*inserted.Bandwidth.PublicipInfo)[0].PublicipId != pipID {
		t.Fatalf("AddPublicipsIntoSharedBandwidth = %+v, %v", inserted, err)
	}

	// Old PER bandwidth was deleted when EIP moved into shared bandwidth.
	_, err = c.ShowBandwidth(&eip.ShowBandwidthRequest{BandwidthId: perBWID})
	wantError(t, err, 404, "VPC.0306")

	// Inserting an EIP that is already on a WHOLE bandwidth -> VPC.0323.
	_, err = c.AddPublicipsIntoSharedBandwidth(&eip.AddPublicipsIntoSharedBandwidthRequest{
		BandwidthId: sharedID,
		Body: &eip.AddPublicipsIntoSharedBandwidthRequestBody{Bandwidth: &eip.AddPublicipsIntoSharedBandwidthOption{
			PublicipInfo: []eip.InsertPublicipInfo{{PublicipId: pipID}},
		}},
	})
	wantError(t, err, 400, "VPC.0323")

	// Deleting a shared bandwidth while it still has EIPs -> VPC.0304.
	_, err = c.DeleteSharedBandwidth(&eip.DeleteSharedBandwidthRequest{BandwidthId: sharedID})
	wantError(t, err, 409, "VPC.0304")

	// --- Create a second EIP directly on the shared bandwidth ---------
	createdOnShared, err := c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp"},
		Bandwidth: &eip.CreatePublicipBandwidthOption{ShareType: wholeShare, Id: &sharedID},
	}})
	if err != nil || createdOnShared.Publicip == nil || createdOnShared.Publicip.Id == nil {
		t.Fatalf("CreatePublicip(WHOLE): %+v, %v", createdOnShared, err)
	}
	pip2ID := *createdOnShared.Publicip.Id
	t.Cleanup(func() {
		_, _ = c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: pip2ID})
	})
	eventually(t, "EIP 2 on shared bandwidth to become DOWN", func() bool {
		s, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pip2ID})
		return err == nil && s.Publicip.Status.Value() == "DOWN"
	})
	// Deleting EIP 2 removes it from the shared bandwidth's publicip_info.
	if _, err := c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: pip2ID}); err != nil {
		t.Fatalf("DeletePublicip(2): %v", err)
	}

	// --- RemovePublicipsFromSharedBandwidth ---------------------------
	remCharge := eip.GetRemoveFromSharedBandwidthOptionChargeModeEnum().BANDWIDTH
	// Invalid size (> 300) -> VPC.0301.
	_, err = c.RemovePublicipsFromSharedBandwidth(&eip.RemovePublicipsFromSharedBandwidthRequest{
		BandwidthId: sharedID,
		Body: &eip.RemovePublicipsFromSharedBandwidthRequestBody{Bandwidth: &eip.RemoveFromSharedBandwidthOption{
			ChargeMode:   remCharge,
			Size:         301,
			PublicipInfo: []eip.RemovePublicipInfo{{PublicipId: pipID}},
		}},
	})
	wantError(t, err, 400, "VPC.0301")

	// Removing an EIP not in this shared bandwidth -> VPC.0323.
	_, err = c.RemovePublicipsFromSharedBandwidth(&eip.RemovePublicipsFromSharedBandwidthRequest{
		BandwidthId: sharedID,
		Body: &eip.RemovePublicipsFromSharedBandwidthRequestBody{Bandwidth: &eip.RemoveFromSharedBandwidthOption{
			ChargeMode:   remCharge,
			Size:         8,
			PublicipInfo: []eip.RemovePublicipInfo{{PublicipId: unknownID}},
		}},
	})
	wantError(t, err, 400, "VPC.0323")

	if _, err := c.RemovePublicipsFromSharedBandwidth(&eip.RemovePublicipsFromSharedBandwidthRequest{
		BandwidthId: sharedID,
		Body: &eip.RemovePublicipsFromSharedBandwidthRequestBody{Bandwidth: &eip.RemoveFromSharedBandwidthOption{
			ChargeMode:   remCharge,
			Size:         8,
			PublicipInfo: []eip.RemovePublicipInfo{{PublicipId: pipID}},
		}},
	}); err != nil {
		t.Fatalf("RemovePublicipsFromSharedBandwidth: %v", err)
	}

	// EIP 1 now has a new PER bandwidth named "bandwidth-<first 8 chars of EIP ID>" with size 8.
	afterRemove, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pipID})
	if err != nil {
		t.Fatalf("ShowPublicip after remove: %v", err)
	}
	wantBWName := "bandwidth-" + pipID[:8]
	if afterRemove.Publicip.BandwidthShareType == nil || afterRemove.Publicip.BandwidthShareType.Value() != "PER" ||
		afterRemove.Publicip.BandwidthName == nil || *afterRemove.Publicip.BandwidthName != wantBWName ||
		afterRemove.Publicip.BandwidthSize == nil || *afterRemove.Publicip.BandwidthSize != 8 {
		t.Errorf("EIP after remove = %+v, want PER bandwidth %q of size 8", afterRemove.Publicip, wantBWName)
	}

	// Shared bandwidth is now empty and can be deleted.
	if _, err := c.DeleteSharedBandwidth(&eip.DeleteSharedBandwidthRequest{BandwidthId: sharedID}); err != nil {
		t.Fatalf("DeleteSharedBandwidth: %v", err)
	}
	_, err = c.ShowBandwidth(&eip.ShowBandwidthRequest{BandwidthId: sharedID})
	wantError(t, err, 404, "VPC.0306")

	if _, err := c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: pipID}); err != nil {
		t.Fatalf("DeletePublicip: %v", err)
	}
}

// TestEIPTags drives §3.3 through the official EIP v2 SDK: single and
// batch tag creation and deletion, tag overwrite, idempotent deletion of
// absent keys, listing project tags, and filtering/counting EIPs by tags.
func TestEIPTags(t *testing.T) {
	c := newEIP(t)
	perShare := eip.GetCreatePublicipBandwidthOptionShareTypeEnum().PER

	makeEIP := func(alias string) string {
		t.Helper()
		res, err := c.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
			Publicip:  &eip.CreatePublicipOption{Type: "5_bgp", Alias: ptr(alias)},
			Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr(alias + "-bw"), ShareType: perShare, Size: ptr(int32(5))},
		}})
		if err != nil || res.Publicip == nil || res.Publicip.Id == nil {
			t.Fatalf("CreatePublicip(%s): %+v, %v", alias, res, err)
		}
		id := *res.Publicip.Id
		t.Cleanup(func() {
			_, _ = c.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: id})
		})
		eventually(t, alias+" to become DOWN", func() bool {
			s, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: id})
			return err == nil && s.Publicip.Status.Value() == "DOWN"
		})
		return id
	}

	id1 := makeEIP("sdk-tag-eip-1")
	id2 := makeEIP("sdk-tag-eip-2")

	// --- CreatePublicipTag and overwrite ------------------------------
	_, err := c.CreatePublicipTag(&eip.CreatePublicipTagRequest{
		PublicipId: unknownID,
		Body:       &eip.CreatePublicipTagRequestBody{Tag: &eip.ResourceTagOption{Key: "env", Value: "dev"}},
	})
	wantError(t, err, 404, "VPC.0504")

	// Empty key -> VPC.0501.
	_, err = c.CreatePublicipTag(&eip.CreatePublicipTagRequest{
		PublicipId: id1,
		Body:       &eip.CreatePublicipTagRequestBody{Tag: &eip.ResourceTagOption{Key: "", Value: "dev"}},
	})
	wantError(t, err, 400, "VPC.0501")

	if _, err := c.CreatePublicipTag(&eip.CreatePublicipTagRequest{
		PublicipId: id1,
		Body:       &eip.CreatePublicipTagRequestBody{Tag: &eip.ResourceTagOption{Key: "env", Value: "dev"}},
	}); err != nil {
		t.Fatalf("CreatePublicipTag(env=dev): %v", err)
	}
	// Overwrite existing key.
	if _, err := c.CreatePublicipTag(&eip.CreatePublicipTagRequest{
		PublicipId: id1,
		Body:       &eip.CreatePublicipTagRequestBody{Tag: &eip.ResourceTagOption{Key: "env", Value: "prod"}},
	}); err != nil {
		t.Fatalf("CreatePublicipTag(env=prod): %v", err)
	}

	tags1, err := c.ShowPublicipTags(&eip.ShowPublicipTagsRequest{PublicipId: id1})
	if err != nil || tags1.Tags == nil || len(*tags1.Tags) != 1 ||
		*(*tags1.Tags)[0].Key != "env" || *(*tags1.Tags)[0].Value != "prod" {
		t.Fatalf("ShowPublicipTags(1) = %+v, %v", tags1, err)
	}
	shown1, err := c.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: id1})
	if err != nil || shown1.Publicip.Tags == nil || len(*shown1.Publicip.Tags) != 1 || (*shown1.Publicip.Tags)[0] != "env=prod" {
		t.Fatalf("ShowPublicip(1) tags = %+v, %v", shown1, err)
	}

	// --- BatchCreatePublicipTags --------------------------------------
	batchCreate := eip.GetBatchCreatePublicipTagsRequestBodyActionEnum().CREATE
	if _, err := c.BatchCreatePublicipTags(&eip.BatchCreatePublicipTagsRequest{
		PublicipId: id1,
		Body: &eip.BatchCreatePublicipTagsRequestBody{
			Action: batchCreate,
			Tags: []eip.ResourceTagOption{
				{Key: "team", Value: "network"},
				{Key: "tier", Value: "edge"},
			},
		},
	}); err != nil {
		t.Fatalf("BatchCreatePublicipTags(1): %v", err)
	}
	if _, err := c.BatchCreatePublicipTags(&eip.BatchCreatePublicipTagsRequest{
		PublicipId: id2,
		Body: &eip.BatchCreatePublicipTagsRequestBody{
			Action: batchCreate,
			Tags: []eip.ResourceTagOption{
				{Key: "env", Value: "staging"},
				{Key: "team", Value: "network"},
			},
		},
	}); err != nil {
		t.Fatalf("BatchCreatePublicipTags(2): %v", err)
	}

	// --- ListPublicipTags ---------------------------------------------
	allTags, err := c.ListPublicipTags(&eip.ListPublicipTagsRequest{})
	if err != nil || allTags.Tags == nil || len(*allTags.Tags) < 3 {
		t.Fatalf("ListPublicipTags = %+v, %v", allTags, err)
	}

	// --- ListPublicipsByTags (count and filter) -----------------------
	countAct := eip.GetListPublicipsByTagsRequestBodyActionEnum().COUNT
	filterAct := eip.GetListPublicipsByTagsRequestBodyActionEnum().FILTER

	counted, err := c.ListPublicipsByTags(&eip.ListPublicipsByTagsRequest{Body: &eip.ListPublicipsByTagsRequestBody{
		Action: countAct,
		Tags:   &[]eip.TagReq{{Key: "team", Values: []string{"network"}}},
	}})
	if err != nil || counted.TotalCount == nil || *counted.TotalCount != 2 {
		t.Fatalf("ListPublicipsByTags(count) = %+v, %v", counted, err)
	}

	filtered, err := c.ListPublicipsByTags(&eip.ListPublicipsByTagsRequest{Body: &eip.ListPublicipsByTagsRequestBody{
		Action: filterAct,
		Tags:   &[]eip.TagReq{{Key: "env", Values: []string{"prod"}}},
		Limit:  ptr(int32(10)),
		Offset: ptr(int32(0)),
	}})
	if err != nil || filtered.TotalCount == nil || *filtered.TotalCount != 1 ||
		filtered.Resources == nil || len(*filtered.Resources) != 1 ||
		*(*filtered.Resources)[0].ResourceId != id1 ||
		*(*filtered.Resources)[0].ResourceName != "sdk-tag-eip-1" {
		t.Fatalf("ListPublicipsByTags(filter env=prod) = %+v, %v", filtered, err)
	}

	// Invalid limit -> VPC.0501.
	_, err = c.ListPublicipsByTags(&eip.ListPublicipsByTagsRequest{Body: &eip.ListPublicipsByTagsRequestBody{
		Action: filterAct,
		Limit:  ptr(int32(1001)),
	}})
	wantError(t, err, 400, "VPC.0501")

	// --- DeletePublicipTag and BatchDeletePublicipTags ----------------
	if _, err := c.DeletePublicipTag(&eip.DeletePublicipTagRequest{PublicipId: id1, Key: "tier"}); err != nil {
		t.Fatalf("DeletePublicipTag(tier): %v", err)
	}
	// Deleting a key the EIP does not have is a 204 no-op (§3.3).
	if _, err := c.DeletePublicipTag(&eip.DeletePublicipTagRequest{PublicipId: id1, Key: "nonexistent"}); err != nil {
		t.Fatalf("DeletePublicipTag(nonexistent): %v", err)
	}
	_, err = c.DeletePublicipTag(&eip.DeletePublicipTagRequest{PublicipId: unknownID, Key: "env"})
	wantError(t, err, 404, "VPC.0504")

	batchDelete := eip.GetBatchDeletePublicipTagsRequestBodyActionEnum().DELETE
	if _, err := c.BatchDeletePublicipTags(&eip.BatchDeletePublicipTagsRequest{
		PublicipId: id1,
		Body: &eip.BatchDeletePublicipTagsRequestBody{
			Action: batchDelete,
			Tags: []eip.ResourceTagOption{
				{Key: "env", Value: "prod"},
				{Key: "nonexistent", Value: "x"},
			},
		},
	}); err != nil {
		t.Fatalf("BatchDeletePublicipTags: %v", err)
	}

	tagsAfter, err := c.ShowPublicipTags(&eip.ShowPublicipTagsRequest{PublicipId: id1})
	if err != nil || tagsAfter.Tags == nil || len(*tagsAfter.Tags) != 1 || *(*tagsAfter.Tags)[0].Key != "team" {
		t.Fatalf("ShowPublicipTags after delete = %+v, %v", tagsAfter, err)
	}
}

// TestEIPPermissions runs only with WEISTACK_SDK_IAM=enforce (§8):
// a user granted only the classic alias vpc:publicIps:list can list EIPs,
// and is refused CreatePublicip with the VPC v1 denial.
func TestEIPPermissions(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()
	admin, admin5 := iamClientsAs(t, adminAK, adminSK)

	u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-eip-limited", Enabled: true}})
	if err != nil {
		t.Fatalf("CreateUserV5: %v", err)
	}
	uid := u.User.UserId
	defer func() {
		if _, err := admin5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: uid}); err != nil {
			t.Errorf("DeleteUserV5: %v", err)
		}
	}()

	key, err := admin.CreatePermanentAccessKey(&iam.CreatePermanentAccessKeyRequest{Body: &iam.CreatePermanentAccessKeyRequestBody{
		Credential: &iam.CreateCredentialOption{UserId: uid},
	}})
	if err != nil {
		t.Fatalf("CreatePermanentAccessKey: %v", err)
	}
	ak, sk := key.Credential.Access, key.Credential.Secret

	role, err := admin.CreateCloudServiceCustomPolicy(&iam.CreateCloudServiceCustomPolicyRequest{
		Body: &iam.CreateCloudServiceCustomPolicyRequestBody{Role: &iam.ServicePolicyRoleOption{
			DisplayName: "sdk-eip-list-only",
			Type:        "AX",
			Description: "classic alias vpc:publicIps:list only",
			Policy: &iam.ServicePolicy{
				Version: "1.1",
				Statement: []iam.ServiceStatement{{
					Action: []string{"vpc:publicIps:list"},
					Effect: iam.GetServiceStatementEffectEnum().ALLOW,
				}},
			},
		}},
	})
	if err != nil || role.Role == nil {
		t.Fatalf("CreateCloudServiceCustomPolicy: %+v, %v", role, err)
	}
	roleID := role.Role.Id
	defer func() {
		if _, err := admin.DeleteCustomPolicy(&iam.DeleteCustomPolicyRequest{RoleId: roleID}); err != nil {
			t.Errorf("DeleteCustomPolicy: %v", err)
		}
	}()

	g, err := admin.KeystoneCreateGroup(&iam.KeystoneCreateGroupRequest{Body: &iam.KeystoneCreateGroupRequestBody{
		Group: &iam.KeystoneCreateGroupOption{Name: "sdk-eip-readers"},
	}})
	if err != nil {
		t.Fatalf("KeystoneCreateGroup: %v", err)
	}
	gid := g.Group.Id
	defer func() {
		if _, err := admin.KeystoneDeleteGroup(&iam.KeystoneDeleteGroupRequest{GroupId: gid}); err != nil {
			t.Errorf("KeystoneDeleteGroup: %v", err)
		}
	}()
	if _, err := admin.KeystoneAddUserToGroup(&iam.KeystoneAddUserToGroupRequest{GroupId: gid, UserId: uid}); err != nil {
		t.Fatalf("KeystoneAddUserToGroup: %v", err)
	}
	if _, err := admin.KeystoneAssociateGroupWithProjectPermission(&iam.KeystoneAssociateGroupWithProjectPermissionRequest{
		ProjectId: projectID, GroupId: gid, RoleId: roleID,
	}); err != nil {
		t.Fatalf("KeystoneAssociateGroupWithProjectPermission: %v", err)
	}

	userEIP := eipAs(t, ak, sk)
	if _, err := userEIP.ListPublicips(&eip.ListPublicipsRequest{}); err != nil {
		t.Fatalf("ListPublicips with vpc:publicIps:list: %v", err)
	}

	perShare := eip.GetCreatePublicipBandwidthOptionShareTypeEnum().PER
	_, err = userEIP.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp"},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("denied-bw"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	denialOf(t, err, "WeiStack.0403")
}
