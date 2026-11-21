package sdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	eipv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2/model"
	eipv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v3/model"
	elbv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3"
	elb "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3/model"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	ims "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ims/v2/model"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

const elbEndpoint = "http://elb." + region + ".myhuaweicloud.com"

func newELB(t *testing.T) *elbv3.ElbClient {
	t.Helper()
	return elbAs(t, signingAK("AKELBSDKEXAMPLE00000"), signingSK())
}

func elbAs(t *testing.T, ak, sk string) *elbv3.ElbClient {
	t.Helper()
	cred, err := basic.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		WithProjectId(projectID).
		SafeBuild()
	if err != nil {
		t.Fatalf("building credentials: %v", err)
	}
	hc, err := elbv3.ElbClientBuilder().
		WithEndpoints([]string{elbEndpoint}).
		WithCredential(cred).
		WithHttpConfig(httpConfigAt(emulatorAddr)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building ELB client: %v", err)
	}
	return elbv3.NewElbClient(hc)
}

// elbSeededFlavors fetches the seeded L4/L7 small and medium flavor IDs.
func elbSeededFlavors(t *testing.T, c *elbv3.ElbClient) (l4Small, l4Med, l7Small, l7Med string) {
	t.Helper()
	res, err := c.ListFlavors(&elb.ListFlavorsRequest{})
	if err != nil || res.Flavors == nil {
		t.Fatalf("ListFlavors: %+v, %v", res, err)
	}
	for _, f := range *res.Flavors {
		switch f.Name {
		case "L4_flavor.elb.s2.small":
			l4Small = f.Id
		case "L4_flavor.elb.s1.medium":
			l4Med = f.Id
		case "L7_flavor.elb.s1.small":
			l7Small = f.Id
		case "L7_flavor.elb.s1.medium":
			l7Med = f.Id
		}
	}
	if l4Small == "" || l4Med == "" || l7Small == "" || l7Med == "" {
		t.Fatalf("missing seeded flavors: l4Small=%q l4Med=%q l7Small=%q l7Med=%q", l4Small, l4Med, l7Small, l7Med)
	}
	return l4Small, l4Med, l7Small, l7Med
}

func TestELBFlavorsAndAvailabilityZones(t *testing.T) {
	c := newELB(t)

	// ListFlavors: all 4 seeded flavors.
	all, err := c.ListFlavors(&elb.ListFlavorsRequest{})
	if err != nil || all.Flavors == nil || len(*all.Flavors) != 4 {
		t.Fatalf("ListFlavors = %+v, %v (want 4 flavors)", all, err)
	}

	// Filter by type=L4.
	l4Only, err := c.ListFlavors(&elb.ListFlavorsRequest{Type: &[]string{"L4"}})
	if err != nil || l4Only.Flavors == nil || len(*l4Only.Flavors) != 2 {
		t.Fatalf("ListFlavors(L4) = %+v, %v", l4Only, err)
	}
	for _, f := range *l4Only.Flavors {
		if f.Type != "L4" {
			t.Errorf("flavor %s has type %q, want L4", f.Name, f.Type)
		}
	}

	// Marker + limit paging.
	page1, err := c.ListFlavors(&elb.ListFlavorsRequest{Limit: ptr(int32(2))})
	if err != nil || page1.Flavors == nil || len(*page1.Flavors) != 2 || page1.PageInfo == nil || page1.PageInfo.NextMarker == nil {
		t.Fatalf("ListFlavors page 1 = %+v, %v", page1, err)
	}
	page2, err := c.ListFlavors(&elb.ListFlavorsRequest{Limit: ptr(int32(2)), Marker: page1.PageInfo.NextMarker})
	if err != nil || page2.Flavors == nil || len(*page2.Flavors) != 2 {
		t.Fatalf("ListFlavors page 2 = %+v, %v", page2, err)
	}

	// ShowFlavor: found and not found.
	fid := (*all.Flavors)[0].Id
	shown, err := c.ShowFlavor(&elb.ShowFlavorRequest{FlavorId: fid})
	if err != nil || shown.Flavor == nil || shown.Flavor.Id != fid {
		t.Fatalf("ShowFlavor = %+v, %v", shown, err)
	}
	_, err = c.ShowFlavor(&elb.ShowFlavorRequest{FlavorId: unknownID})
	wantError(t, err, 404, "ELB.8904")

	// ListAvailabilityZones: single inner slice with region's AZs.
	azRes, err := c.ListAvailabilityZones(&elb.ListAvailabilityZonesRequest{})
	if err != nil || azRes.AvailabilityZones == nil || len(*azRes.AvailabilityZones) != 1 || len((*azRes.AvailabilityZones)[0]) < 2 {
		t.Fatalf("ListAvailabilityZones = %+v, %v", azRes, err)
	}
	for _, az := range (*azRes.AvailabilityZones)[0] {
		if az.State != "ACTIVE" || !strings.HasPrefix(az.Code, region) {
			t.Errorf("unexpected AZ: %+v", az)
		}
	}
}

func TestELBLoadBalancerAndEIPHook(t *testing.T) {
	c := newELB(t)
	net2 := newV2(t, realEndpoint)
	eip2 := newEIP(t)
	eip3 := newEIPv3(t)

	l4Small, l4Med, l7Small, l7Med := elbSeededFlavors(t, c)
	az1, az2 := region+"a", region+"b"

	// Create VPC and subnet.
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("elb-sdk-vpc"), Cidr: ptr("10.80.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "elb vpc deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
			return err == nil
		})
	})
	eventually(t, "elb vpc OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "elb-sdk-subnet", Cidr: "10.80.1.0/24", GatewayIp: "10.80.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	neutronSubnetID := sc.Subnet.NeutronSubnetId
	t.Cleanup(func() {
		eventually(t, "elb subnet deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
			return err == nil
		})
	})
	eventually(t, "elb subnet ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	// Create an EIP to bind via publicip_ids.
	eipCreated, err := eip2.CreatePublicip(&eipv2.CreatePublicipRequest{Body: &eipv2.CreatePublicipRequestBody{
		Publicip: &eipv2.CreatePublicipOption{Type: "5_bgp"},
		Bandwidth: &eipv2.CreatePublicipBandwidthOption{
			Name:      ptr("elb-sdk-bw"),
			Size:      ptr(int32(5)),
			ShareType: eipv2.GetCreatePublicipBandwidthOptionShareTypeEnum().PER,
		},
	}})
	if err != nil || eipCreated.Publicip == nil {
		t.Fatalf("CreatePublicip: %+v, %v", eipCreated, err)
	}
	eipID := *eipCreated.Publicip.Id
	t.Cleanup(func() {
		_, _ = eip2.DeletePublicip(&eipv2.DeletePublicipRequest{PublicipId: eipID})
	})
	eventually(t, "EIP DOWN", func() bool {
		s, err := eip2.ShowPublicip(&eipv2.ShowPublicipRequest{PublicipId: eipID})
		return err == nil && s.Publicip != nil && s.Publicip.Status != nil && s.Publicip.Status.Value() == "DOWN"
	})

	// Validation: unknown AZ -> ELB.8902.
	_, err = c.CreateLoadBalancer(&elb.CreateLoadBalancerRequest{Body: &elb.CreateLoadBalancerRequestBody{
		Loadbalancer: &elb.CreateLoadBalancerOption{
			Name:                 ptr("bad-az-lb"),
			VpcId:                ptr(vpcID),
			VipSubnetCidrId:      ptr(neutronSubnetID),
			L4FlavorId:           ptr(l4Small),
			AvailabilityZoneList: []string{"no-such-az"},
		},
	}})
	wantError(t, err, 400, "ELB.8902")

	// Create LB with existing EIP bound via publicip_ids.
	created, err := c.CreateLoadBalancer(&elb.CreateLoadBalancerRequest{Body: &elb.CreateLoadBalancerRequestBody{
		Loadbalancer: &elb.CreateLoadBalancerOption{
			Name:                     ptr("sdk-elb-main"),
			Description:              ptr("sdk dedicated elb"),
			VpcId:                    ptr(vpcID),
			VipSubnetCidrId:          ptr(neutronSubnetID),
			ElbVirsubnetIds:          &[]string{subnetID},
			L4FlavorId:               ptr(l4Small),
			L7FlavorId:               ptr(l7Small),
			AvailabilityZoneList:     []string{az1},
			PublicipIds:              &[]string{eipID},
			DeletionProtectionEnable: ptr(true),
		},
	}})
	if err != nil || created.Loadbalancer == nil {
		t.Fatalf("CreateLoadBalancer: %+v, %v", created, err)
	}
	lb := created.Loadbalancer
	lbID := lb.Id
	if lb.ProvisioningStatus != "ACTIVE" || lb.OperatingStatus != "ONLINE" {
		t.Fatalf("LB status = %s/%s, want ACTIVE/ONLINE", lb.ProvisioningStatus, lb.OperatingStatus)
	}
	if !strings.HasPrefix(lb.VipAddress, "10.80.1.") || lb.VipPortId == "" {
		t.Fatalf("unexpected VIP: addr=%q port=%q", lb.VipAddress, lb.VipPortId)
	}
	if len(lb.Eips) != 1 || lb.Eips[0].EipId == nil || *lb.Eips[0].EipId != eipID {
		t.Fatalf("LB eips = %+v, want %s", lb.Eips, eipID)
	}
	if len(lb.Publicips) != 1 || lb.Publicips[0].PublicipId != eipID {
		t.Fatalf("LB publicips = %+v, want %s", lb.Publicips, eipID)
	}

	// Verify EIP hook effects (§4.2): v2 ACTIVE with port_id, v3 associate_instance_type=ELB, delete refused VPC.0517.
	shownEIP2, err := eip2.ShowPublicip(&eipv2.ShowPublicipRequest{PublicipId: eipID})
	if err != nil || shownEIP2.Publicip == nil || shownEIP2.Publicip.Status.Value() != "ACTIVE" || shownEIP2.Publicip.PortId == nil || *shownEIP2.Publicip.PortId != lb.VipPortId {
		t.Fatalf("EIP v2 while bound to ELB = %+v, %v", shownEIP2, err)
	}
	shownEIP3, err := eip3.ShowPublicip(&eipv3.ShowPublicipRequest{PublicipId: eipID})
	if err != nil || shownEIP3.Publicip == nil || shownEIP3.Publicip.AssociateInstanceType == nil || shownEIP3.Publicip.AssociateInstanceType.Value() != "ELB" || shownEIP3.Publicip.AssociateInstanceId == nil || *shownEIP3.Publicip.AssociateInstanceId != lbID {
		t.Fatalf("EIP v3 while bound to ELB = %+v, %v", shownEIP3, err)
	}
	_, err = eip2.DeletePublicip(&eipv2.DeletePublicipRequest{PublicipId: eipID})
	wantError(t, err, 409, "VPC.0517")

	// Show & List load balancers.
	shownLB, err := c.ShowLoadBalancer(&elb.ShowLoadBalancerRequest{LoadbalancerId: lbID})
	if err != nil || shownLB.Loadbalancer == nil || shownLB.Loadbalancer.Name != "sdk-elb-main" {
		t.Fatalf("ShowLoadBalancer = %+v, %v", shownLB, err)
	}
	listedLB, err := c.ListLoadBalancers(&elb.ListLoadBalancersRequest{Name: &[]string{"sdk-elb-main"}})
	if err != nil || listedLB.Loadbalancers == nil || len(*listedLB.Loadbalancers) != 1 {
		t.Fatalf("ListLoadBalancers = %+v, %v", listedLB, err)
	}

	// UpdateLoadBalancer: flavor upgrade works; cross-type flavor change -> ELB.8959.
	_, err = c.UpdateLoadBalancer(&elb.UpdateLoadBalancerRequest{
		LoadbalancerId: lbID,
		Body: &elb.UpdateLoadBalancerRequestBody{Loadbalancer: &elb.UpdateLoadBalancerOption{
			L4FlavorId: ptr(l7Med),
		}},
	})
	wantError(t, err, 400, "ELB.8959")

	updatedLB, err := c.UpdateLoadBalancer(&elb.UpdateLoadBalancerRequest{
		LoadbalancerId: lbID,
		Body: &elb.UpdateLoadBalancerRequestBody{Loadbalancer: &elb.UpdateLoadBalancerOption{
			Name:       ptr("sdk-elb-renamed"),
			L4FlavorId: ptr(l4Med),
			L7FlavorId: ptr(l7Med),
		}},
	})
	if err != nil || updatedLB.Loadbalancer == nil || updatedLB.Loadbalancer.Name != "sdk-elb-renamed" || updatedLB.Loadbalancer.L4FlavorId != l4Med {
		t.Fatalf("UpdateLoadBalancer = %+v, %v", updatedLB, err)
	}

	// BatchAddAvailableZones and BatchRemoveAvailableZones.
	addedAZ, err := c.BatchAddAvailableZones(&elb.BatchAddAvailableZonesRequest{
		LoadbalancerId: lbID,
		Body:           &elb.BatchAddAvailableZonesRequestBody{AvailabilityZoneList: []string{az2}},
	})
	if err != nil || addedAZ.Loadbalancer == nil || len(addedAZ.Loadbalancer.AvailabilityZoneList) != 2 {
		t.Fatalf("BatchAddAvailableZones = %+v, %v", addedAZ, err)
	}
	removedAZ, err := c.BatchRemoveAvailableZones(&elb.BatchRemoveAvailableZonesRequest{
		LoadbalancerId: lbID,
		Body:           &elb.BatchRemoveAvailableZonesRequestBody{AvailabilityZoneList: []string{az2}},
	})
	if err != nil || removedAZ.Loadbalancer == nil || len(removedAZ.Loadbalancer.AvailabilityZoneList) != 1 {
		t.Fatalf("BatchRemoveAvailableZones = %+v, %v", removedAZ, err)
	}
	// Cannot remove last remaining AZ -> ELB.8902.
	_, err = c.BatchRemoveAvailableZones(&elb.BatchRemoveAvailableZonesRequest{
		LoadbalancerId: lbID,
		Body:           &elb.BatchRemoveAvailableZonesRequestBody{AvailabilityZoneList: []string{az1}},
	})
	wantError(t, err, 400, "ELB.8902")

	// Delete refused while deletion_protection_enable is true -> ELB.8907.
	_, err = c.DeleteLoadBalancer(&elb.DeleteLoadBalancerRequest{LoadbalancerId: lbID})
	wantError(t, err, 409, "ELB.8907")

	// Disable deletion protection and delete.
	if _, err := c.UpdateLoadBalancer(&elb.UpdateLoadBalancerRequest{
		LoadbalancerId: lbID,
		Body:           &elb.UpdateLoadBalancerRequestBody{Loadbalancer: &elb.UpdateLoadBalancerOption{DeletionProtectionEnable: ptr(false)}},
	}); err != nil {
		t.Fatalf("disable deletion protection: %v", err)
	}
	if _, err := c.DeleteLoadBalancer(&elb.DeleteLoadBalancerRequest{LoadbalancerId: lbID}); err != nil {
		t.Fatalf("DeleteLoadBalancer: %v", err)
	}

	// EIP must now be DOWN and deletable.
	shownEIP2, err = eip2.ShowPublicip(&eipv2.ShowPublicipRequest{PublicipId: eipID})
	if err != nil || shownEIP2.Publicip == nil || shownEIP2.Publicip.Status.Value() != "DOWN" {
		t.Fatalf("EIP after LB delete = %+v, %v", shownEIP2, err)
	}

	// Create LB with inline publicip (CreateForELB) and test DeleteLoadBalancerForce with child resources.
	perShare := elb.GetCreateLoadBalancerBandwidthOptionShareTypeEnum().PER
	bwCharge := elb.GetCreateLoadBalancerBandwidthOptionChargeModeEnum().BANDWIDTH
	lb2Res, err := c.CreateLoadBalancer(&elb.CreateLoadBalancerRequest{Body: &elb.CreateLoadBalancerRequestBody{
		Loadbalancer: &elb.CreateLoadBalancerOption{
			Name:                 ptr("sdk-elb-force"),
			VpcId:                ptr(vpcID),
			VipSubnetCidrId:      ptr(neutronSubnetID),
			L7FlavorId:           ptr(l7Small),
			AvailabilityZoneList: []string{az1},
			Publicip: &elb.CreateLoadBalancerPublicIpOption{
				NetworkType: "5_bgp",
				Bandwidth: &elb.CreateLoadBalancerBandwidthOption{
					Name:       ptr("sdk-elb-inline-bw"),
					Size:       ptr(int32(5)),
					ShareType:  &perShare,
					ChargeMode: &bwCharge,
				},
			},
		},
	}})
	if err != nil || lb2Res.Loadbalancer == nil || len(lb2Res.Loadbalancer.Eips) != 1 {
		t.Fatalf("CreateLoadBalancer(inline publicip) = %+v, %v", lb2Res, err)
	}
	lb2ID := lb2Res.Loadbalancer.Id
	inlineEIPID := *lb2Res.Loadbalancer.Eips[0].EipId
	t.Cleanup(func() {
		_, _ = eip2.DeletePublicip(&eipv2.DeletePublicipRequest{PublicipId: inlineEIPID})
	})

	lsnRes, err := c.CreateListener(&elb.CreateListenerRequest{Body: &elb.CreateListenerRequestBody{
		Listener: &elb.CreateListenerOption{
			LoadbalancerId: lb2ID,
			Name:           ptr("force-http"),
			Protocol:       "HTTP",
			ProtocolPort:   ptr(int32(80)),
		},
	}})
	if err != nil || lsnRes.Listener == nil {
		t.Fatalf("CreateListener: %+v, %v", lsnRes, err)
	}
	// Normal delete fails while listener exists -> ELB.8907.
	_, err = c.DeleteLoadBalancer(&elb.DeleteLoadBalancerRequest{LoadbalancerId: lb2ID})
	wantError(t, err, 409, "ELB.8907")

	// Force delete removes LB and listener cleanly.
	if _, err := c.DeleteLoadBalancerForce(&elb.DeleteLoadBalancerForceRequest{LoadbalancerId: lb2ID}); err != nil {
		t.Fatalf("DeleteLoadBalancerForce: %v", err)
	}
	_, err = c.ShowListener(&elb.ShowListenerRequest{ListenerId: lsnRes.Listener.Id})
	wantError(t, err, 404, "ELB.8904")
}

func TestELBListenersPoolsHealthMonitorsAndMemberHealth(t *testing.T) {
	c := newELB(t)
	net2 := newV2(t, realEndpoint)
	compute := newECS(t)
	images := newIMS(t)

	l4Small, _, l7Small, _ := elbSeededFlavors(t, c)
	az1 := region + "a"

	// Create VPC and subnet.
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("elb-health-vpc"), Cidr: ptr("10.81.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "health vpc deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
			return err == nil
		})
	})
	eventually(t, "health vpc OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "elb-health-subnet", Cidr: "10.81.1.0/24", GatewayIp: "10.81.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	neutronSubnetID := sc.Subnet.NeutronSubnetId
	t.Cleanup(func() {
		eventually(t, "health subnet deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
			return err == nil
		})
	})
	eventually(t, "health subnet ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	// Pick a seeded public image and create a real ECS server in the subnet.
	imgList, err := images.ListImages(&ims.ListImagesRequest{})
	if err != nil || imgList.Images == nil || len(*imgList.Images) == 0 {
		t.Fatalf("ListImages: %+v, %v", imgList, err)
	}
	imageID := (*imgList.Images)[0].Id

	srvCreate, err := compute.CreateServers(&ecs.CreateServersRequest{Body: &ecs.CreateServersRequestBody{
		Server: &ecs.PrePaidServer{
			Name:       "elb-backend-ecs",
			ImageRef:   imageID,
			FlavorRef:  "s6.small.1",
			Vpcid:      vpcID,
			Nics:       []ecs.PrePaidServerNic{{SubnetId: ptr(subnetID)}},
			RootVolume: &ecs.PrePaidServerRootVolume{Volumetype: ecs.GetPrePaidServerRootVolumeVolumetypeEnum().SSD},
		},
	}})
	if err != nil || srvCreate.ServerIds == nil || len(*srvCreate.ServerIds) != 1 {
		t.Fatalf("CreateServers: %+v, %v", srvCreate, err)
	}
	serverID := (*srvCreate.ServerIds)[0]
	t.Cleanup(func() {
		_, _ = compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{
			Servers: []ecs.ServerId{{Id: serverID}},
		}})
		eventually(t, "backend server deleted", func() bool {
			_, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
			return err != nil
		})
	})

	var serverIP string
	eventually(t, "backend ECS ACTIVE", func() bool {
		s, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
		if err != nil || s.Server == nil || s.Server.Status != "ACTIVE" {
			return false
		}
		for _, addrs := range s.Server.Addresses {
			for _, a := range addrs {
				if a.Addr != "" {
					serverIP = a.Addr
					return true
				}
			}
		}
		return false
	})

	// Create dedicated ELB with L4 + L7 flavors and ip_target_enable=true.
	lbRes, err := c.CreateLoadBalancer(&elb.CreateLoadBalancerRequest{Body: &elb.CreateLoadBalancerRequestBody{
		Loadbalancer: &elb.CreateLoadBalancerOption{
			Name:                 ptr("sdk-elb-full"),
			VpcId:                ptr(vpcID),
			VipSubnetCidrId:      ptr(neutronSubnetID),
			L4FlavorId:           ptr(l4Small),
			L7FlavorId:           ptr(l7Small),
			AvailabilityZoneList: []string{az1},
			IpTargetEnable:       ptr(true),
		},
	}})
	if err != nil || lbRes.Loadbalancer == nil {
		t.Fatalf("CreateLoadBalancer: %+v, %v", lbRes, err)
	}
	lbID := lbRes.Loadbalancer.Id
	t.Cleanup(func() {
		_, _ = c.DeleteLoadBalancerForce(&elb.DeleteLoadBalancerForceRequest{LoadbalancerId: lbID})
	})

	// Listeners: HTTP:80, TCP:80 conflicts (same family -> ELB.8907), UDP:80 succeeds (different family).
	httpLsnRes, err := c.CreateListener(&elb.CreateListenerRequest{Body: &elb.CreateListenerRequestBody{
		Listener: &elb.CreateListenerOption{
			LoadbalancerId: lbID,
			Name:           ptr("http-80"),
			Protocol:       "HTTP",
			ProtocolPort:   ptr(int32(80)),
		},
	}})
	if err != nil || httpLsnRes.Listener == nil {
		t.Fatalf("CreateListener(HTTP:80): %+v, %v", httpLsnRes, err)
	}
	httpLsnID := httpLsnRes.Listener.Id

	_, err = c.CreateListener(&elb.CreateListenerRequest{Body: &elb.CreateListenerRequestBody{
		Listener: &elb.CreateListenerOption{
			LoadbalancerId: lbID,
			Name:           ptr("tcp-80-conflict"),
			Protocol:       "TCP",
			ProtocolPort:   ptr(int32(80)),
		},
	}})
	wantError(t, err, 409, "ELB.8907")

	udpLsnRes, err := c.CreateListener(&elb.CreateListenerRequest{Body: &elb.CreateListenerRequestBody{
		Listener: &elb.CreateListenerOption{
			LoadbalancerId: lbID,
			Name:           ptr("udp-80"),
			Protocol:       "UDP",
			ProtocolPort:   ptr(int32(80)),
		},
	}})
	if err != nil || udpLsnRes.Listener == nil {
		t.Fatalf("CreateListener(UDP:80): %+v, %v", udpLsnRes, err)
	}
	udpLsnID := udpLsnRes.Listener.Id

	if _, err := c.UpdateListener(&elb.UpdateListenerRequest{
		ListenerId: httpLsnID,
		Body:       &elb.UpdateListenerRequestBody{Listener: &elb.UpdateListenerOption{Name: ptr("http-80-v2")}},
	}); err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	lsnList, err := c.ListListeners(&elb.ListListenersRequest{LoadbalancerId: &[]string{lbID}})
	if err != nil || lsnList.Listeners == nil || len(*lsnList.Listeners) != 2 {
		t.Fatalf("ListListeners = %+v, %v", lsnList, err)
	}

	// Create HTTP pool attached to HTTP listener.
	poolRes, err := c.CreatePool(&elb.CreatePoolRequest{Body: &elb.CreatePoolRequestBody{
		Pool: &elb.CreatePoolOption{
			Name:        ptr("http-pool"),
			Protocol:    "HTTP",
			LbAlgorithm: "ROUND_ROBIN",
			ListenerId:  ptr(httpLsnID),
		},
	}})
	if err != nil || poolRes.Pool == nil {
		t.Fatalf("CreatePool: %+v, %v", poolRes, err)
	}
	poolID := poolRes.Pool.Id

	if _, err := c.UpdatePool(&elb.UpdatePoolRequest{
		PoolId: poolID,
		Body: &elb.UpdatePoolRequestBody{Pool: &elb.UpdatePoolOption{
			Name:        ptr("http-pool-v2"),
			LbAlgorithm: ptr("LEAST_CONNECTIONS"),
			SessionPersistence: &elb.UpdatePoolSessionPersistenceOption{
				Type:               ptr(elb.GetUpdatePoolSessionPersistenceOptionTypeEnum().HTTP_COOKIE),
				PersistenceTimeout: ptr(int32(60)),
			},
		}},
	}); err != nil {
		t.Fatalf("UpdatePool: %v", err)
	}
	poolsList, err := c.ListPools(&elb.ListPoolsRequest{LoadbalancerId: &[]string{lbID}})
	if err != nil || poolsList.Pools == nil || len(*poolsList.Pools) != 1 {
		t.Fatalf("ListPools = %+v, %v", poolsList, err)
	}
	shownPool, err := c.ShowPool(&elb.ShowPoolRequest{PoolId: poolID})
	if err != nil || shownPool.Pool == nil || shownPool.Pool.LbAlgorithm != "LEAST_CONNECTIONS" {
		t.Fatalf("ShowPool = %+v, %v", shownPool, err)
	}

	// Listener cannot be deleted normally while default_pool_id is set -> ELB.8907.
	_, err = c.DeleteListener(&elb.DeleteListenerRequest{ListenerId: httpLsnID})
	wantError(t, err, 409, "ELB.8907")

	// Add instance member pointing at the real ECS server, plus an IP member.
	instMemRes, err := c.CreateMember(&elb.CreateMemberRequest{
		PoolId: poolID,
		Body: &elb.CreateMemberRequestBody{Member: &elb.CreateMemberOption{
			Name:         ptr("ecs-backend"),
			Address:      serverIP,
			ProtocolPort: ptr(int32(8080)),
			SubnetCidrId: ptr(neutronSubnetID),
			Weight:       ptr(int32(10)),
		}},
	})
	if err != nil || instMemRes.Member == nil {
		t.Fatalf("CreateMember(instance): %+v, %v", instMemRes, err)
	}
	instMemID := instMemRes.Member.Id
	if instMemRes.Member.OperatingStatus != "NO_MONITOR" {
		t.Fatalf("member without monitor = %q, want NO_MONITOR", instMemRes.Member.OperatingStatus)
	}

	ipMemRes, err := c.CreateMember(&elb.CreateMemberRequest{
		PoolId: poolID,
		Body: &elb.CreateMemberRequestBody{Member: &elb.CreateMemberOption{
			Name:         ptr("ip-backend"),
			Address:      serverIP,
			ProtocolPort: ptr(int32(8081)),
		}},
	})
	if err != nil || ipMemRes.Member == nil || ipMemRes.Member.MemberType == nil || *ipMemRes.Member.MemberType != "ip" {
		t.Fatalf("CreateMember(ip): %+v, %v", ipMemRes, err)
	}
	ipMemID := ipMemRes.Member.Id

	// ListMembers & ListAllMembers & UpdateMember.
	memList, err := c.ListMembers(&elb.ListMembersRequest{PoolId: poolID})
	if err != nil || memList.Members == nil || len(*memList.Members) != 2 {
		t.Fatalf("ListMembers = %+v, %v", memList, err)
	}
	allMemList, err := c.ListAllMembers(&elb.ListAllMembersRequest{PoolId: &[]string{poolID}})
	if err != nil || allMemList.Members == nil || len(*allMemList.Members) != 2 {
		t.Fatalf("ListAllMembers = %+v, %v", allMemList, err)
	}
	if _, err := c.UpdateMember(&elb.UpdateMemberRequest{
		PoolId:   poolID,
		MemberId: instMemID,
		Body:     &elb.UpdateMemberRequestBody{Member: &elb.UpdateMemberOption{Weight: ptr(int32(25))}},
	}); err != nil {
		t.Fatalf("UpdateMember: %v", err)
	}

	// Attach HTTP health monitor -> both members become ONLINE because ECS server is ACTIVE (§3.5).
	hmRes, err := c.CreateHealthMonitor(&elb.CreateHealthMonitorRequest{Body: &elb.CreateHealthMonitorRequestBody{
		Healthmonitor: &elb.CreateHealthMonitorOption{
			Name:          ptr("http-hm"),
			PoolId:        poolID,
			Type:          "HTTP",
			Delay:         5,
			Timeout:       3,
			MaxRetries:    3,
			HttpMethod:    ptr("GET"),
			UrlPath:       ptr("/health"),
			ExpectedCodes: ptr("200"),
		},
	}})
	if err != nil || hmRes.Healthmonitor == nil {
		t.Fatalf("CreateHealthMonitor: %+v, %v", hmRes, err)
	}
	hmID := hmRes.Healthmonitor.Id

	hmList, err := c.ListHealthMonitors(&elb.ListHealthMonitorsRequest{Id: &[]string{hmID}})
	if err != nil || hmList.Healthmonitors == nil || len(*hmList.Healthmonitors) != 1 {
		t.Fatalf("ListHealthMonitors = %+v, %v", hmList, err)
	}
	hmShown, err := c.ShowHealthMonitor(&elb.ShowHealthMonitorRequest{HealthmonitorId: hmID})
	if err != nil || hmShown.Healthmonitor == nil || hmShown.Healthmonitor.Type != "HTTP" {
		t.Fatalf("ShowHealthMonitor = %+v, %v", hmShown, err)
	}

	// Verify ONLINE in ShowMember and ShowLoadBalancerStatus.
	shownMem, err := c.ShowMember(&elb.ShowMemberRequest{PoolId: poolID, MemberId: instMemID})
	if err != nil || shownMem.Member == nil || shownMem.Member.OperatingStatus != "ONLINE" {
		t.Fatalf("ShowMember with active ECS + monitor = %+v, %v", shownMem, err)
	}
	stRes, err := c.ShowLoadBalancerStatus(&elb.ShowLoadBalancerStatusRequest{LoadbalancerId: lbID})
	if err != nil || stRes.Statuses == nil || stRes.Statuses.Loadbalancer == nil {
		t.Fatalf("ShowLoadBalancerStatus = %+v, %v", stRes, err)
	}

	// Stop the ECS server -> member immediately reports OFFLINE (§3.5).
	if _, err := compute.BatchStopServers(&ecs.BatchStopServersRequest{Body: &ecs.BatchStopServersRequestBody{
		OsStop: &ecs.BatchStopServersOption{
			Servers: []ecs.ServerId{{Id: serverID}},
		},
	}}); err != nil {
		t.Fatalf("BatchStopServers: %v", err)
	}
	eventually(t, "backend ECS SHUTOFF", func() bool {
		s, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
		return err == nil && s.Server != nil && s.Server.Status == "SHUTOFF"
	})

	shownMem, err = c.ShowMember(&elb.ShowMemberRequest{PoolId: poolID, MemberId: instMemID})
	if err != nil || shownMem.Member == nil || shownMem.Member.OperatingStatus != "OFFLINE" {
		t.Fatalf("ShowMember with SHUTOFF ECS = %+v, %v (want OFFLINE)", shownMem, err)
	}
	shownIPMem, err := c.ShowMember(&elb.ShowMemberRequest{PoolId: poolID, MemberId: ipMemID})
	if err != nil || shownIPMem.Member == nil || shownIPMem.Member.OperatingStatus != "OFFLINE" {
		t.Fatalf("ShowMember(ip) with SHUTOFF ECS = %+v, %v (want OFFLINE)", shownIPMem, err)
	}

	// Start the ECS server -> member returns to ONLINE.
	if _, err := compute.BatchStartServers(&ecs.BatchStartServersRequest{Body: &ecs.BatchStartServersRequestBody{
		OsStart: &ecs.BatchStartServersOption{
			Servers: []ecs.ServerId{{Id: serverID}},
		},
	}}); err != nil {
		t.Fatalf("BatchStartServers: %v", err)
	}
	eventually(t, "backend ECS ACTIVE again", func() bool {
		s, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
		return err == nil && s.Server != nil && s.Server.Status == "ACTIVE"
	})
	shownMem, err = c.ShowMember(&elb.ShowMemberRequest{PoolId: poolID, MemberId: instMemID})
	if err != nil || shownMem.Member == nil || shownMem.Member.OperatingStatus != "ONLINE" {
		t.Fatalf("ShowMember after ECS restart = %+v, %v (want ONLINE)", shownMem, err)
	}

	// UpdateHealthMonitor admin_state_up=false -> OFFLINE; DeleteHealthMonitor -> NO_MONITOR.
	if _, err := c.UpdateHealthMonitor(&elb.UpdateHealthMonitorRequest{
		HealthmonitorId: hmID,
		Body:            &elb.UpdateHealthMonitorRequestBody{Healthmonitor: &elb.UpdateHealthMonitorOption{AdminStateUp: ptr(false)}},
	}); err != nil {
		t.Fatalf("UpdateHealthMonitor: %v", err)
	}
	shownMem, err = c.ShowMember(&elb.ShowMemberRequest{PoolId: poolID, MemberId: instMemID})
	if err != nil || shownMem.Member == nil || shownMem.Member.OperatingStatus != "OFFLINE" {
		t.Fatalf("ShowMember with disabled HM = %+v, %v (want OFFLINE)", shownMem, err)
	}
	if _, err := c.DeleteHealthMonitor(&elb.DeleteHealthMonitorRequest{HealthmonitorId: hmID}); err != nil {
		t.Fatalf("DeleteHealthMonitor: %v", err)
	}
	shownMem, err = c.ShowMember(&elb.ShowMemberRequest{PoolId: poolID, MemberId: instMemID})
	if err != nil || shownMem.Member == nil || shownMem.Member.OperatingStatus != "NO_MONITOR" {
		t.Fatalf("ShowMember after DeleteHealthMonitor = %+v, %v (want NO_MONITOR)", shownMem, err)
	}

	// DeleteMember, DeletePool refused while member/listener exists, DeletePoolCascade, DeleteListenerForce.
	if _, err := c.DeleteMember(&elb.DeleteMemberRequest{PoolId: poolID, MemberId: ipMemID}); err != nil {
		t.Fatalf("DeleteMember: %v", err)
	}
	_, err = c.DeletePool(&elb.DeletePoolRequest{PoolId: poolID})
	wantError(t, err, 409, "ELB.8907")
	if _, err := c.DeletePoolCascade(&elb.DeletePoolCascadeRequest{PoolId: poolID}); err != nil {
		t.Fatalf("DeletePoolCascade: %v", err)
	}
	if _, err := c.DeleteListenerForce(&elb.DeleteListenerForceRequest{ListenerId: httpLsnID}); err != nil {
		t.Fatalf("DeleteListenerForce: %v", err)
	}
	if _, err := c.DeleteListener(&elb.DeleteListenerRequest{ListenerId: udpLsnID}); err != nil {
		t.Fatalf("DeleteListener(UDP): %v", err)
	}
}

// TestELBPermissions runs only with WEISTACK_SDK_IAM=enforce (§7): a user
// holding only elb:loadbalancers:list can list load balancers and is refused
// CreateLoadBalancer with 403 WeiStack.0403.
func TestELBPermissions(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()
	admin, admin5 := iamClientsAs(t, adminAK, adminSK)

	u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-elb-limited", Enabled: true}})
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
			DisplayName: "sdk-elb-list-only",
			Type:        "AX",
			Description: "elb:loadbalancers:list only",
			Policy: &iam.ServicePolicy{
				Version: "1.1",
				Statement: []iam.ServiceStatement{{
					Action: []string{"elb:loadbalancers:list"},
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
		Group: &iam.KeystoneCreateGroupOption{Name: "sdk-elb-readers"},
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

	userELB := elbAs(t, ak, sk)
	if _, err := userELB.ListLoadBalancers(&elb.ListLoadBalancersRequest{}); err != nil {
		t.Fatalf("ListLoadBalancers with elb:loadbalancers:list: %v", err)
	}

	_, err = userELB.CreateLoadBalancer(&elb.CreateLoadBalancerRequest{Body: &elb.CreateLoadBalancerRequestBody{
		Loadbalancer: &elb.CreateLoadBalancerOption{
			Name:                 ptr("denied-elb"),
			AvailabilityZoneList: []string{region + "a"},
		},
	}})
	denialOf(t, err, "WeiStack.0403")
}

func elbGenerateCertPEM(t *testing.T, cn string, isCA bool) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	now := time.Now().UTC().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	cPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(cPEM), string(kPEM)
}

func TestELBCertificatesL7IPGroupsSecurityPoliciesAndTags(t *testing.T) {
	c := newELB(t)
	net2 := newV2(t, realEndpoint)

	_, _, _, l7Med := elbSeededFlavors(t, c)
	az1 := region + "a"

	// Create VPC and subnet.
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("elb-l7-sdk-vpc"), Cidr: ptr("10.82.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "l7 vpc deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
			return err == nil
		})
	})
	eventually(t, "l7 vpc OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "elb-l7-sdk-subnet", Cidr: "10.82.1.0/24", GatewayIp: "10.82.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	neutronSubnetID := sc.Subnet.NeutronSubnetId
	t.Cleanup(func() {
		eventually(t, "l7 subnet deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
			return err == nil
		})
	})
	eventually(t, "l7 subnet ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	// --- Certificates (§3.7) ---
	srvCertPEM, srvKeyPEM := elbGenerateCertPEM(t, "sdk.example.com", false)
	otherCertPEM, otherKeyPEM := elbGenerateCertPEM(t, "other.example.com", false)
	caCertPEM, _ := elbGenerateCertPEM(t, "sdk-ca", true)

	// Mismatched key -> ELB.1011.
	_, err = c.CreateCertificate(&elb.CreateCertificateRequest{Body: &elb.CreateCertificateRequestBody{
		Certificate: &elb.CreateCertificateOption{
			Name:        ptr("bad-pair"),
			Certificate: ptr(srvCertPEM),
			PrivateKey:  ptr(otherKeyPEM),
		},
	}})
	wantError(t, err, 400, "ELB.1011")

	// Non-CA as client cert -> ELB.5051.
	clientType := elb.GetCreateCertificateOptionTypeEnum().CLIENT
	_, err = c.CreateCertificate(&elb.CreateCertificateRequest{Body: &elb.CreateCertificateRequestBody{
		Certificate: &elb.CreateCertificateOption{
			Name:        ptr("bad-ca"),
			Type:        &clientType,
			Certificate: ptr(otherCertPEM),
		},
	}})
	wantError(t, err, 400, "ELB.5051")

	srvCertRes, err := c.CreateCertificate(&elb.CreateCertificateRequest{Body: &elb.CreateCertificateRequestBody{
		Certificate: &elb.CreateCertificateOption{
			Name:        ptr("sdk-server-cert"),
			Certificate: ptr(srvCertPEM),
			PrivateKey:  ptr(srvKeyPEM),
		},
	}})
	if err != nil || srvCertRes.Certificate == nil {
		t.Fatalf("CreateCertificate(server): %+v, %v", srvCertRes, err)
	}
	srvCertID := srvCertRes.Certificate.Id
	if srvCertRes.Certificate.PrivateKey != "" {
		t.Fatalf("CreateCertificate returned non-empty private_key")
	}
	if srvCertRes.Certificate.Domain != "sdk.example.com" || srvCertRes.Certificate.Fingerprint == nil || len(*srvCertRes.Certificate.Fingerprint) != 40 {
		t.Fatalf("unexpected derived cert fields: %+v", srvCertRes.Certificate)
	}
	t.Cleanup(func() {
		_, _ = c.DeleteCertificate(&elb.DeleteCertificateRequest{CertificateId: srvCertID})
	})

	caCertRes, err := c.CreateCertificate(&elb.CreateCertificateRequest{Body: &elb.CreateCertificateRequestBody{
		Certificate: &elb.CreateCertificateOption{
			Name:        ptr("sdk-ca-cert"),
			Type:        &clientType,
			Certificate: ptr(caCertPEM),
		},
	}})
	if err != nil || caCertRes.Certificate == nil {
		t.Fatalf("CreateCertificate(client): %+v, %v", caCertRes, err)
	}
	caCertID := caCertRes.Certificate.Id
	t.Cleanup(func() {
		_, _ = c.DeleteCertificate(&elb.DeleteCertificateRequest{CertificateId: caCertID})
	})

	certList, err := c.ListCertificates(&elb.ListCertificatesRequest{Name: &[]string{"sdk-server-cert"}})
	if err != nil || certList.Certificates == nil || len(*certList.Certificates) != 1 {
		t.Fatalf("ListCertificates = %+v, %v", certList, err)
	}
	if _, err := c.UpdateCertificate(&elb.UpdateCertificateRequest{
		CertificateId: srvCertID,
		Body:          &elb.UpdateCertificateRequestBody{Certificate: &elb.UpdateCertificateOption{Description: ptr("updated cert")}},
	}); err != nil {
		t.Fatalf("UpdateCertificate: %v", err)
	}
	shownCert, err := c.ShowCertificate(&elb.ShowCertificateRequest{CertificateId: srvCertID})
	if err != nil || shownCert.Certificate == nil || shownCert.Certificate.PrivateKey != "" || shownCert.Certificate.Description != "updated cert" {
		t.Fatalf("ShowCertificate = %+v, %v", shownCert, err)
	}

	// --- IP Groups & Security Policies (§3.9) ---
	ipgRes, err := c.CreateIpGroup(&elb.CreateIpGroupRequest{Body: &elb.CreateIpGroupRequestBody{
		Ipgroup: &elb.CreateIpGroupOption{
			Name:        ptr("sdk-ipg"),
			Description: ptr("allowlist"),
			IpList:      []elb.CreateIpGroupIpOption{{Ip: "10.0.0.1", Description: ptr("one")}, {Ip: "192.168.10.0/24"}},
		},
	}})
	if err != nil || ipgRes.Ipgroup == nil {
		t.Fatalf("CreateIpGroup: %+v, %v", ipgRes, err)
	}
	ipgID := ipgRes.Ipgroup.Id
	t.Cleanup(func() {
		_, _ = c.DeleteIpGroup(&elb.DeleteIpGroupRequest{IpgroupId: ipgID})
	})

	sysPolicies, err := c.ListSystemSecurityPolicies(&elb.ListSystemSecurityPoliciesRequest{})
	if err != nil || sysPolicies.SystemSecurityPolicies == nil || len(*sysPolicies.SystemSecurityPolicies) < 5 {
		t.Fatalf("ListSystemSecurityPolicies = %+v, %v", sysPolicies, err)
	}

	cipher1 := elb.GetCreateSecurityPolicyOptionCiphersEnum().ECDHE_RSA_AES128_GCM_SHA256
	spRes, err := c.CreateSecurityPolicy(&elb.CreateSecurityPolicyRequest{Body: &elb.CreateSecurityPolicyRequestBody{
		SecurityPolicy: &elb.CreateSecurityPolicyOption{
			Name:      ptr("sdk-secpol"),
			Protocols: []string{"TLSv1.2", "TLSv1.3"},
			Ciphers:   []elb.CreateSecurityPolicyOptionCiphers{cipher1},
		},
	}})
	if err != nil || spRes.SecurityPolicy == nil {
		t.Fatalf("CreateSecurityPolicy: %+v, %v", spRes, err)
	}
	spID := spRes.SecurityPolicy.Id
	t.Cleanup(func() {
		_, _ = c.DeleteSecurityPolicy(&elb.DeleteSecurityPolicyRequest{SecurityPolicyId: spID})
	})

	// Create L7 load balancer, HTTP & HTTPS listeners (using cert, CA cert, security policy, and IP group).
	lbRes, err := c.CreateLoadBalancer(&elb.CreateLoadBalancerRequest{Body: &elb.CreateLoadBalancerRequestBody{
		Loadbalancer: &elb.CreateLoadBalancerOption{
			Name:                 ptr("sdk-elb-l7"),
			VpcId:                ptr(vpcID),
			VipSubnetCidrId:      ptr(neutronSubnetID),
			L7FlavorId:           ptr(l7Med),
			AvailabilityZoneList: []string{az1},
		},
	}})
	if err != nil || lbRes.Loadbalancer == nil {
		t.Fatalf("CreateLoadBalancer: %+v, %v", lbRes, err)
	}
	lbID := lbRes.Loadbalancer.Id
	t.Cleanup(func() {
		_, _ = c.DeleteLoadBalancerForce(&elb.DeleteLoadBalancerForceRequest{LoadbalancerId: lbID})
	})

	httpLsn, err := c.CreateListener(&elb.CreateListenerRequest{Body: &elb.CreateListenerRequestBody{
		Listener: &elb.CreateListenerOption{
			LoadbalancerId:        lbID,
			Name:                  ptr("l7-http"),
			Protocol:              "HTTP",
			ProtocolPort:          ptr(int32(80)),
			EnhanceL7policyEnable: ptr(true),
		},
	}})
	if err != nil || httpLsn.Listener == nil {
		t.Fatalf("CreateListener(HTTP): %+v, %v", httpLsn, err)
	}
	httpLsnID := httpLsn.Listener.Id

	httpsLsn, err := c.CreateListener(&elb.CreateListenerRequest{Body: &elb.CreateListenerRequestBody{
		Listener: &elb.CreateListenerOption{
			LoadbalancerId:          lbID,
			Name:                    ptr("l7-https"),
			Protocol:                "HTTPS",
			ProtocolPort:            ptr(int32(443)),
			DefaultTlsContainerRef:  ptr(srvCertID),
			ClientCaTlsContainerRef: ptr(caCertID),
			SecurityPolicyId:        ptr(spID),
			Ipgroup: &elb.CreateListenerIpGroupOption{
				IpgroupId:     ipgID,
				EnableIpgroup: ptr(true),
				Type:          ptr(elb.GetCreateListenerIpGroupOptionTypeEnum().WHITE),
			},
		},
	}})
	if err != nil || httpsLsn.Listener == nil {
		t.Fatalf("CreateListener(HTTPS): %+v, %v", httpsLsn, err)
	}
	httpsLsnID := httpsLsn.Listener.Id

	// Delete guards while bound to HTTPS listener -> ELB.8907.
	_, err = c.DeleteCertificate(&elb.DeleteCertificateRequest{CertificateId: srvCertID})
	wantError(t, err, 409, "ELB.8907")
	_, err = c.DeleteIpGroup(&elb.DeleteIpGroupRequest{IpgroupId: ipgID})
	wantError(t, err, 409, "ELB.8907")
	_, err = c.DeleteSecurityPolicy(&elb.DeleteSecurityPolicyRequest{SecurityPolicyId: spID})
	wantError(t, err, 409, "ELB.8907")

	// IP group and security policy show the bound listener.
	shownIPG, err := c.ShowIpGroup(&elb.ShowIpGroupRequest{IpgroupId: ipgID})
	if err != nil || shownIPG.Ipgroup == nil || len(shownIPG.Ipgroup.Listeners) != 1 || shownIPG.Ipgroup.Listeners[0].Id != httpsLsnID {
		t.Fatalf("ShowIpGroup = %+v, %v", shownIPG, err)
	}
	shownSP, err := c.ShowSecurityPolicy(&elb.ShowSecurityPolicyRequest{SecurityPolicyId: spID})
	if err != nil || shownSP.SecurityPolicy == nil || len(shownSP.SecurityPolicy.Listeners) != 1 || shownSP.SecurityPolicy.Listeners[0].Id != httpsLsnID {
		t.Fatalf("ShowSecurityPolicy = %+v, %v", shownSP, err)
	}

	// --- L7 Policies and Rules (§3.8) ---
	httpPool, err := c.CreatePool(&elb.CreatePoolRequest{Body: &elb.CreatePoolRequestBody{
		Pool: &elb.CreatePoolOption{
			Name:           ptr("l7-pool"),
			Protocol:       "HTTP",
			LbAlgorithm:    "ROUND_ROBIN",
			LoadbalancerId: ptr(lbID),
		},
	}})
	if err != nil || httpPool.Pool == nil {
		t.Fatalf("CreatePool: %+v, %v", httpPool, err)
	}
	poolID := httpPool.Pool.Id

	// Policy 1: REDIRECT_TO_POOL with inline rule and priority 10.
	pol1, err := c.CreateL7Policy(&elb.CreateL7PolicyRequest{Body: &elb.CreateL7PolicyRequestBody{
		L7policy: &elb.CreateL7PolicyOption{
			Name:           ptr("sdk-pol-pool"),
			ListenerId:     httpLsnID,
			Action:         "REDIRECT_TO_POOL",
			RedirectPoolId: ptr(poolID),
			Priority:       ptr(int32(10)),
			Rules: &[]elb.CreateL7PolicyRuleOption{{
				Type:        "PATH",
				CompareType: "STARTS_WITH",
				Value:       "/api",
			}},
		},
	}})
	if err != nil || pol1.L7policy == nil || len(pol1.L7policy.Rules) != 1 {
		t.Fatalf("CreateL7Policy(pool): %+v, %v", pol1, err)
	}
	pol1ID := pol1.L7policy.Id

	// Add a second rule (HOST_NAME) to pol1, then test duplicate type -> ELB.8907.
	rule2, err := c.CreateL7Rule(&elb.CreateL7RuleRequest{
		L7policyId: pol1ID,
		Body: &elb.CreateL7RuleRequestBody{Rule: &elb.CreateRuleOption{
			Type:        "HOST_NAME",
			CompareType: "EQUAL_TO",
			Value:       "api.example.com",
		}},
	})
	if err != nil || rule2.Rule == nil {
		t.Fatalf("CreateL7Rule(HOST_NAME): %+v, %v", rule2, err)
	}
	rule2ID := rule2.Rule.Id

	_, err = c.CreateL7Rule(&elb.CreateL7RuleRequest{
		L7policyId: pol1ID,
		Body: &elb.CreateL7RuleRequestBody{Rule: &elb.CreateRuleOption{
			Type:        "HOST_NAME",
			CompareType: "EQUAL_TO",
			Value:       "dup.example.com",
		}},
	})
	wantError(t, err, 409, "ELB.8907")

	// ListL7Rules, ListAllL7Rules, ShowL7Rule, UpdateL7Rule.
	rulesList, err := c.ListL7Rules(&elb.ListL7RulesRequest{L7policyId: pol1ID})
	if err != nil || rulesList.Rules == nil || len(*rulesList.Rules) != 2 {
		t.Fatalf("ListL7Rules = %+v, %v", rulesList, err)
	}
	allRules, err := c.ListAllL7Rules(&elb.ListAllL7RulesRequest{L7policyId: &[]string{pol1ID}})
	if err != nil || allRules.Rules == nil || len(*allRules.Rules) != 2 {
		t.Fatalf("ListAllL7Rules = %+v, %v", allRules, err)
	}
	if _, err := c.UpdateL7Rule(&elb.UpdateL7RuleRequest{
		L7policyId: pol1ID,
		L7ruleId:   rule2ID,
		Body:       &elb.UpdateL7RuleRequestBody{Rule: &elb.UpdateL7RuleOption{Value: ptr("v2.example.com")}},
	}); err != nil {
		t.Fatalf("UpdateL7Rule: %v", err)
	}

	// Policy 2: REDIRECT_TO_LISTENER (HTTP -> HTTPS), Policy 3: FIXED_RESPONSE.
	pol2, err := c.CreateL7Policy(&elb.CreateL7PolicyRequest{Body: &elb.CreateL7PolicyRequestBody{
		L7policy: &elb.CreateL7PolicyOption{
			Name:               ptr("sdk-pol-lsn"),
			ListenerId:         httpLsnID,
			Action:             "REDIRECT_TO_LISTENER",
			RedirectListenerId: ptr(httpsLsnID),
			Priority:           ptr(int32(20)),
		},
	}})
	if err != nil || pol2.L7policy == nil {
		t.Fatalf("CreateL7Policy(listener): %+v, %v", pol2, err)
	}
	ctJSON := elb.GetFixtedResponseConfigContentTypeEnum().APPLICATION_JSON
	pol3, err := c.CreateL7Policy(&elb.CreateL7PolicyRequest{Body: &elb.CreateL7PolicyRequestBody{
		L7policy: &elb.CreateL7PolicyOption{
			Name:       ptr("sdk-pol-fixed"),
			ListenerId: httpsLsnID,
			Action:     "FIXED_RESPONSE",
			FixedResponseConfig: &elb.CreateFixtedResponseConfig{
				StatusCode:  "200",
				ContentType: ptr(elb.GetCreateFixtedResponseConfigContentTypeEnum().APPLICATION_JSON),
				MessageBody: ptr(`{"ok":true}`),
			},
		},
	}})
	if err != nil || pol3.L7policy == nil || pol3.L7policy.FixedResponseConfig == nil || pol3.L7policy.FixedResponseConfig.ContentType != ctJSON {
		t.Fatalf("CreateL7Policy(fixed): %+v, %v", pol3, err)
	}

	polsList, err := c.ListL7Policies(&elb.ListL7PoliciesRequest{ListenerId: &[]string{httpLsnID}})
	if err != nil || polsList.L7policies == nil || len(*polsList.L7policies) != 2 {
		t.Fatalf("ListL7Policies = %+v, %v", polsList, err)
	}
	if _, err := c.DeleteL7Rule(&elb.DeleteL7RuleRequest{L7policyId: pol1ID, L7ruleId: rule2ID}); err != nil {
		t.Fatalf("DeleteL7Rule: %v", err)
	}
	if _, err := c.DeleteL7Policy(&elb.DeleteL7PolicyRequest{L7policyId: pol1ID}); err != nil {
		t.Fatalf("DeleteL7Policy: %v", err)
	}

	// --- Load Balancer & Listener Tags (§3.11) on /v3 and /v2.0 ---
	addAction := elb.GetChangeLoadbalancerTagsRequestBodyActionEnum().CREATE
	delAction := elb.GetChangeLoadbalancerTagsRequestBodyActionEnum().DELETE
	if _, err := c.ChangeLoadbalancerTags(&elb.ChangeLoadbalancerTagsRequest{
		LoadbalancerId: lbID,
		Body: &elb.ChangeLoadbalancerTagsRequestBody{
			Action: addAction,
			Tags:   []elb.ChangeResourceTagOption{{Key: "env", Value: "sdk"}},
		},
	}); err != nil {
		t.Fatalf("ChangeLoadbalancerTags(create): %v", err)
	}
	lbTags, err := c.ShowLoadbalancerTags(&elb.ShowLoadbalancerTagsRequest{LoadbalancerId: lbID})
	if err != nil || lbTags.Tags == nil || len(*lbTags.Tags) != 1 || (*lbTags.Tags)[0].Key != "env" {
		t.Fatalf("ShowLoadbalancerTags = %+v, %v", lbTags, err)
	}
	allLBTags, err := c.ListLoadbalancerTags(&elb.ListLoadbalancerTagsRequest{})
	if err != nil || allLBTags.Tags == nil || len(*allLBTags.Tags) == 0 {
		t.Fatalf("ListLoadbalancerTags = %+v, %v", allLBTags, err)
	}
	if _, err := c.ChangeLoadbalancerTags(&elb.ChangeLoadbalancerTagsRequest{
		LoadbalancerId: lbID,
		Body: &elb.ChangeLoadbalancerTagsRequestBody{
			Action: delAction,
			Tags:   []elb.ChangeResourceTagOption{{Key: "env"}},
		},
	}); err != nil {
		t.Fatalf("ChangeLoadbalancerTags(delete): %v", err)
	}

	// Listener tags via /v2.0 prefix (as Terraform calls them).
	lsnAdd := elb.GetChangeListenerTagsRequestBodyActionEnum().CREATE
	reqDef := elbv3.GenReqDefForChangeListenerTags()
	v20Def := *reqDef
	v20Def.Path = strings.Replace(v20Def.Path, "/v3/", "/v2.0/", 1)
	if _, err := c.HcClient.Sync(
		&elb.ChangeListenerTagsRequest{
			ListenerId: httpLsnID,
			Body: &elb.ChangeListenerTagsRequestBody{
				Action: lsnAdd,
				Tags:   []elb.ChangeResourceTagOption{{Key: "tier", Value: "web"}},
			},
		},
		&v20Def,
	); err != nil {
		t.Fatalf("ChangeListenerTags(/v2.0): %v", err)
	}
	lsnTags, err := c.ShowListenerTags(&elb.ShowListenerTagsRequest{ListenerId: httpLsnID})
	if err != nil || lsnTags.Tags == nil || len(*lsnTags.Tags) != 1 || (*lsnTags.Tags)[0].Key != "tier" {
		t.Fatalf("ShowListenerTags = %+v, %v", lsnTags, err)
	}
}
