package sdk

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/def"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	eipv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2/model"
	eipv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v3/model"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	ims "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ims/v2/model"
	natv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nat/v2"
	nat "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nat/v2/model"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

const natEndpoint = "http://nat." + region + ".myhuaweicloud.com"

func newNAT(t *testing.T) *natv2.NatClient {
	t.Helper()
	return natAs(t, signingAK("AKNATSDKEXAMPLE00000"), signingSK())
}

// natAs builds a NAT v2 client that signs with ak and sk against Huawei
// Cloud's regional NAT endpoint while dialling the emulator.
func natAs(t *testing.T, ak, sk string) *natv2.NatClient {
	t.Helper()
	cred, err := basic.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		WithProjectId(projectID).
		SafeBuild()
	if err != nil {
		t.Fatalf("building credentials: %v", err)
	}
	hc, err := natv2.NatClientBuilder().
		WithEndpoints([]string{natEndpoint}).
		WithCredential(cred).
		WithHttpConfig(httpConfigAt(emulatorAddr)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building NAT client: %v", err)
	}
	return natv2.NewNatClient(hc)
}

// v20TagDef clones an SDK /v3/{project_id}/nat_gateways/... request
// definition onto the /v2.0/{project_id}/nat_gateways/... prefix that
// the Terraform provider calls (§3.4).
func v20TagDef(d *def.HttpRequestDef) *def.HttpRequestDef {
	cp := *d
	cp.Path = strings.Replace(d.Path, "/v3/", "/v2.0/", 1)
	return &cp
}

// TestPublicNatGatewayLifecycle drives §3.1 through the official NAT v2
// SDK: ListNatGatewaySpecs, creating public NAT gateways in a real VPC
// and subnet (with automatic and explicit ngport_ip_address allocation,
// session_conf, tags, and spec limits), PENDING_CREATE -> ACTIVE
// transitions, Show, List with filters and marker/limit pagination,
// Update (name, description, spec, session_conf), Delete (including
// subnet IP release), and all §3.1 validation error cases.
func TestPublicNatGatewayLifecycle(t *testing.T) {
	c := newNAT(t)
	net2 := newV2(t, realEndpoint)

	// --- ListNatGatewaySpecs (§3.1) -----------------------------------
	specsRes, err := c.ListNatGatewaySpecs(&nat.ListNatGatewaySpecsRequest{})
	if err != nil || specsRes.Specs == nil {
		t.Fatalf("ListNatGatewaySpecs: %+v, %v", specsRes, err)
	}
	wantSpecs := []string{"1", "2", "3", "4"}
	if len(*specsRes.Specs) != len(wantSpecs) {
		t.Fatalf("ListNatGatewaySpecs = %+v, want %v", *specsRes.Specs, wantSpecs)
	}
	for i, w := range wantSpecs {
		if got := (*specsRes.Specs)[i].Value(); got != w {
			t.Errorf("ListNatGatewaySpecs[%d] = %q, want %q", i, got, w)
		}
	}

	// --- Set up two VPCs and subnets to test cross-VPC and IP allocation ---
	vc1, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("nat-gw-sdk-vpc-1"), Cidr: ptr("10.70.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc(1): %v", err)
	}
	vpc1ID := vc1.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "VPC 1 to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpc1ID})
			return err == nil
		})
	})
	eventually(t, "VPC 1 to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpc1ID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc1, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "nat-gw-sdk-subnet-1", Cidr: "10.70.1.0/24", GatewayIp: "10.70.1.1", VpcId: vpc1ID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet(1): %v", err)
	}
	subnet1ID := sc1.Subnet.Id
	t.Cleanup(func() {
		eventually(t, "subnet 1 to be deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpc1ID, SubnetId: subnet1ID})
			return err == nil
		})
	})
	eventually(t, "subnet 1 to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnet1ID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	vc2, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("nat-gw-sdk-vpc-2"), Cidr: ptr("10.71.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc(2): %v", err)
	}
	vpc2ID := vc2.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "VPC 2 to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpc2ID})
			return err == nil
		})
	})
	eventually(t, "VPC 2 to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpc2ID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc2, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "nat-gw-sdk-subnet-2", Cidr: "10.71.1.0/24", GatewayIp: "10.71.1.1", VpcId: vpc2ID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet(2): %v", err)
	}
	subnet2ID := sc2.Subnet.Id
	t.Cleanup(func() {
		eventually(t, "subnet 2 to be deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpc2ID, SubnetId: subnet2ID})
			return err == nil
		})
	})
	eventually(t, "subnet 2 to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnet2ID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	spec1 := nat.GetCreateNatGatewayOptionSpecEnum().E_1
	spec2 := nat.GetCreateNatGatewayOptionSpecEnum().E_2
	var badSpec nat.CreateNatGatewayOptionSpec
	_ = badSpec.UnmarshalJSON([]byte(`"9"`))

	// --- CreateNatGateway validation errors (§3.1) --------------------
	// Unknown router_id -> NAT.0004 (404).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "nat-bad-router",
			RouterId:          unknownID,
			InternalNetworkId: subnet1ID,
			Spec:              spec1,
		},
	}})
	wantError(t, err, 404, "NAT.0004")

	// Unknown internal_network_id -> NAT.0005 (404).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "nat-bad-subnet",
			RouterId:          vpc1ID,
			InternalNetworkId: unknownID,
			Spec:              spec1,
		},
	}})
	wantError(t, err, 404, "NAT.0005")

	// Subnet in another VPC -> NAT.0008 (400).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "nat-cross-vpc-subnet",
			RouterId:          vpc1ID,
			InternalNetworkId: subnet2ID,
			Spec:              spec1,
		},
	}})
	wantError(t, err, 400, "NAT.0008")

	// Invalid spec -> NAT.0016 (400).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "nat-bad-spec",
			RouterId:          vpc1ID,
			InternalNetworkId: subnet1ID,
			Spec:              badSpec,
		},
	}})
	wantError(t, err, 400, "NAT.0016")

	// Invalid name -> NAT.0002 (400).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "bad name!",
			RouterId:          vpc1ID,
			InternalNetworkId: subnet1ID,
			Spec:              spec1,
		},
	}})
	wantError(t, err, 400, "NAT.0002")

	// Invalid description (< or >) -> NAT.0014 (400).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "nat-bad-desc",
			RouterId:          vpc1ID,
			InternalNetworkId: subnet1ID,
			Spec:              spec1,
			Description:       ptr("invalid <desc>"),
		},
	}})
	wantError(t, err, 400, "NAT.0014")

	// Negative session_conf value -> NAT.0002 (400).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "nat-bad-sess",
			RouterId:          vpc1ID,
			InternalNetworkId: subnet1ID,
			Spec:              spec1,
			SessionConf:       &nat.SessionConfiguration{TcpSessionExpireTime: ptr(int32(-1))},
		},
	}})
	wantError(t, err, 400, "NAT.0002")

	// Unusable ngport_ip_address (outside subnet) -> NAT.0002 (400).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "nat-bad-ip",
			RouterId:          vpc1ID,
			InternalNetworkId: subnet1ID,
			Spec:              spec1,
			NgportIpAddress:   ptr("10.70.99.5"),
		},
	}})
	wantError(t, err, 400, "NAT.0002")

	// Invalid enterprise_project_id -> VPC.0011 (400).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:                "nat-bad-ep",
			RouterId:            vpc1ID,
			InternalNetworkId:   subnet1ID,
			Spec:                spec1,
			EnterpriseProjectId: ptr("not-a-uuid"),
		},
	}})
	wantError(t, err, 400, "VPC.0011")

	// prepaid_options present -> WeiStack.0501 (501).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "nat-prepaid",
			RouterId:          vpc1ID,
			InternalNetworkId: subnet1ID,
			Spec:              spec1,
			PrepaidOptions: &nat.PrepaidOptions{
				PeriodType: nat.GetPrepaidOptionsPeriodTypeEnum().MONTH,
				PeriodNum:  1,
			},
		},
	}})
	wantError(t, err, 501, "WeiStack.0501")

	// --- Create first NAT gateway (default session_conf, auto IP) -----
	beforeSub, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnet1ID})
	if err != nil {
		t.Fatalf("ShowSubnet before create: %v", err)
	}
	availBefore := beforeSub.Subnet.AvailableIpAddressCount

	created1, err := c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "sdk-nat-gw-1",
			Description:       ptr("first public gateway"),
			RouterId:          vpc1ID,
			InternalNetworkId: subnet1ID,
			Spec:              spec1,
			Tags:              &[]string{"env*dev", "team*network"},
		},
	}})
	if err != nil || created1.NatGateway == nil || created1.NatGateway.Id == nil {
		t.Fatalf("CreateNatGateway(1): %+v, %v", created1, err)
	}
	gw1 := created1.NatGateway
	gw1ID := *gw1.Id
	t.Cleanup(func() {
		_, _ = c.DeleteNatGateway(&nat.DeleteNatGatewayRequest{NatGatewayId: gw1ID})
	})

	if gw1.Status == nil || gw1.Status.Value() != "PENDING_CREATE" {
		t.Errorf("new gateway status = %v, want PENDING_CREATE", gw1.Status)
	}
	if gw1.Name == nil || *gw1.Name != "sdk-nat-gw-1" ||
		gw1.Description == nil || *gw1.Description != "first public gateway" ||
		gw1.RouterId == nil || *gw1.RouterId != vpc1ID ||
		gw1.InternalNetworkId == nil || *gw1.InternalNetworkId != subnet1ID ||
		gw1.Spec == nil || gw1.Spec.Value() != "1" ||
		gw1.TenantId == nil || *gw1.TenantId != projectID ||
		gw1.EnterpriseProjectId == nil || *gw1.EnterpriseProjectId != "0" ||
		gw1.AdminStateUp == nil || !*gw1.AdminStateUp ||
		gw1.BillingInfo == nil || *gw1.BillingInfo != "" ||
		gw1.DnatRulesLimit == nil || *gw1.DnatRulesLimit != 200 ||
		gw1.SnatRulePublicIpLimit == nil || *gw1.SnatRulePublicIpLimit != 20 ||
		gw1.PpsMax != nil || gw1.BpsMax != nil ||
		gw1.NgportIpAddress == nil || !strings.HasPrefix(*gw1.NgportIpAddress, "10.70.1.") {
		t.Errorf("created gateway 1 = %+v", gw1)
	}
	if gw1.SessionConf == nil ||
		gw1.SessionConf.TcpSessionExpireTime == nil || *gw1.SessionConf.TcpSessionExpireTime != 900 ||
		gw1.SessionConf.UdpSessionExpireTime == nil || *gw1.SessionConf.UdpSessionExpireTime != 300 ||
		gw1.SessionConf.IcmpSessionExpireTime == nil || *gw1.SessionConf.IcmpSessionExpireTime != 10 ||
		gw1.SessionConf.TcpTimeWaitTime == nil || *gw1.SessionConf.TcpTimeWaitTime != 5 {
		t.Errorf("gateway 1 default session_conf = %+v", gw1.SessionConf)
	}
	if gw1.CreatedAt == nil || time.Since(time.Time(*gw1.CreatedAt)) > time.Hour {
		t.Errorf("gateway 1 created_at not decoded as recent time: %v", gw1.CreatedAt)
	}
	gw1IP := *gw1.NgportIpAddress

	// Subnet available IP count decreased by 1.
	duringSub, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnet1ID})
	if err != nil {
		t.Fatalf("ShowSubnet after gw1 create: %v", err)
	}
	if duringSub.Subnet.AvailableIpAddressCount != availBefore-1 {
		t.Errorf("subnet available IPs = %d, want %d", duringSub.Subnet.AvailableIpAddressCount, availBefore-1)
	}

	eventually(t, "gateway 1 to become ACTIVE", func() bool {
		s, err := c.ShowNatGateway(&nat.ShowNatGatewayRequest{NatGatewayId: gw1ID})
		if err != nil {
			t.Fatalf("ShowNatGateway(1): %v", err)
		}
		return s.NatGateway.Status != nil && s.NatGateway.Status.Value() == "ACTIVE"
	})

	// Requesting an ngport_ip_address already in use by gateway 1 -> NAT.0002 (400).
	_, err = c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "nat-dup-ip",
			RouterId:          vpc1ID,
			InternalNetworkId: subnet1ID,
			Spec:              spec1,
			NgportIpAddress:   &gw1IP,
		},
	}})
	wantError(t, err, 400, "NAT.0002")

	// --- Create second NAT gateway (explicit IP and custom session_conf) ---
	const explicitNgportIP = "10.70.1.200"
	created2, err := c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "sdk-nat-gw-2",
			Description:       ptr("second public gateway"),
			RouterId:          vpc1ID,
			InternalNetworkId: subnet1ID,
			Spec:              spec2,
			NgportIpAddress:   ptr(explicitNgportIP),
			SessionConf: &nat.SessionConfiguration{
				TcpSessionExpireTime:  ptr(int32(1200)),
				UdpSessionExpireTime:  ptr(int32(600)),
				IcmpSessionExpireTime: ptr(int32(20)),
				TcpTimeWaitTime:       ptr(int32(10)),
			},
		},
	}})
	if err != nil || created2.NatGateway == nil || created2.NatGateway.Id == nil {
		t.Fatalf("CreateNatGateway(2): %+v, %v", created2, err)
	}
	gw2ID := *created2.NatGateway.Id
	t.Cleanup(func() {
		_, _ = c.DeleteNatGateway(&nat.DeleteNatGatewayRequest{NatGatewayId: gw2ID})
	})
	if created2.NatGateway.NgportIpAddress == nil || *created2.NatGateway.NgportIpAddress != explicitNgportIP {
		t.Errorf("gateway 2 ngport_ip_address = %v, want %s", created2.NatGateway.NgportIpAddress, explicitNgportIP)
	}
	if created2.NatGateway.SessionConf == nil ||
		*created2.NatGateway.SessionConf.TcpSessionExpireTime != 1200 ||
		*created2.NatGateway.SessionConf.UdpSessionExpireTime != 600 ||
		*created2.NatGateway.SessionConf.IcmpSessionExpireTime != 20 ||
		*created2.NatGateway.SessionConf.TcpTimeWaitTime != 10 {
		t.Errorf("gateway 2 custom session_conf = %+v", created2.NatGateway.SessionConf)
	}
	eventually(t, "gateway 2 to become ACTIVE", func() bool {
		s, err := c.ShowNatGateway(&nat.ShowNatGatewayRequest{NatGatewayId: gw2ID})
		return err == nil && s.NatGateway.Status != nil && s.NatGateway.Status.Value() == "ACTIVE"
	})

	// --- ShowNatGateway and UpdateNatGateway --------------------------
	_, err = c.ShowNatGateway(&nat.ShowNatGatewayRequest{NatGatewayId: unknownID})
	wantError(t, err, 404, "NAT.0105")

	_, err = c.UpdateNatGateway(&nat.UpdateNatGatewayRequest{
		NatGatewayId: unknownID,
		Body: &nat.UpdateNatGatewayRequestBody{
			NatGateway: &nat.UpdateNatGatewayOption{Name: ptr("ghost")},
		},
	})
	wantError(t, err, 404, "NAT.0105")

	var badUpdSpec nat.UpdateNatGatewayOptionSpec
	_ = badUpdSpec.UnmarshalJSON([]byte(`"9"`))
	_, err = c.UpdateNatGateway(&nat.UpdateNatGatewayRequest{
		NatGatewayId: gw1ID,
		Body: &nat.UpdateNatGatewayRequestBody{
			NatGateway: &nat.UpdateNatGatewayOption{Spec: &badUpdSpec},
		},
	})
	wantError(t, err, 400, "NAT.0016")

	_, err = c.UpdateNatGateway(&nat.UpdateNatGatewayRequest{
		NatGatewayId: gw1ID,
		Body: &nat.UpdateNatGatewayRequestBody{
			NatGateway: &nat.UpdateNatGatewayOption{
				PrepaidOptions: &nat.UpdateNatGatewayOptionPrepaidOptions{IsAutoPay: ptr(true)},
			},
		},
	})
	wantError(t, err, 501, "WeiStack.0501")

	updSpec3 := nat.GetUpdateNatGatewayOptionSpecEnum().E_3
	updated1, err := c.UpdateNatGateway(&nat.UpdateNatGatewayRequest{
		NatGatewayId: gw1ID,
		Body: &nat.UpdateNatGatewayRequestBody{
			NatGateway: &nat.UpdateNatGatewayOption{
				Name:        ptr("sdk-nat-gw-1-updated"),
				Description: ptr("updated description"),
				Spec:        &updSpec3,
				SessionConf: &nat.SessionConfiguration{
					TcpSessionExpireTime: ptr(int32(1800)),
					TcpTimeWaitTime:      ptr(int32(15)),
				},
			},
		},
	})
	if err != nil || updated1.NatGateway == nil {
		t.Fatalf("UpdateNatGateway(1): %+v, %v", updated1, err)
	}
	u1 := updated1.NatGateway
	if u1.Name == nil || *u1.Name != "sdk-nat-gw-1-updated" ||
		u1.Description == nil || *u1.Description != "updated description" ||
		u1.Spec == nil || u1.Spec.Value() != "3" ||
		u1.SessionConf == nil ||
		*u1.SessionConf.TcpSessionExpireTime != 1800 ||
		*u1.SessionConf.UdpSessionExpireTime != 300 ||
		*u1.SessionConf.IcmpSessionExpireTime != 10 ||
		*u1.SessionConf.TcpTimeWaitTime != 15 {
		t.Errorf("UpdateNatGateway(1) = %+v", u1)
	}

	// --- ListNatGateways (filters and pagination) ---------------------
	listActive := nat.GetListNatGatewaysRequestStatusEnum().ACTIVE
	listSpec3 := nat.GetListNatGatewaysRequestSpecEnum().E_3
	sortKey := nat.GetListNatGatewaysRequestSortKeyEnum().NAME
	sortDir := nat.GetListNatGatewaysRequestSortDirEnum().ASC

	filtered, err := c.ListNatGateways(&nat.ListNatGatewaysRequest{
		Id:                  &gw1ID,
		TenantId:            &projectID,
		Name:                ptr("sdk-nat-gw-1-updated"),
		Description:         ptr("updated description"),
		Spec:                &[]nat.ListNatGatewaysRequestSpec{listSpec3},
		Status:              &[]nat.ListNatGatewaysRequestStatus{listActive},
		RouterId:            &vpc1ID,
		InternalNetworkId:   &subnet1ID,
		AdminStateUp:        ptr(true),
		EnterpriseProjectId: ptr("all_granted_eps"),
		CreatedAt:           u1.CreatedAt,
		SortKey:             &sortKey,
		SortDir:             &sortDir,
	})
	if err != nil || filtered.NatGateways == nil || len(*filtered.NatGateways) != 1 ||
		*(*filtered.NatGateways)[0].Id != gw1ID {
		t.Fatalf("ListNatGateways(filters) = %+v, %v", filtered, err)
	}

	// Paginate across the gateways in vpc1ID with limit=1.
	seen := map[string]int{}
	var marker *string
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("ListNatGateways paging did not terminate")
		}
		res, err := c.ListNatGateways(&nat.ListNatGatewaysRequest{
			RouterId: &vpc1ID,
			Limit:    ptr(int32(1)),
			Marker:   marker,
		})
		if err != nil {
			t.Fatalf("ListNatGateways(page %d): %v", pages, err)
		}
		if res.NatGateways == nil || len(*res.NatGateways) == 0 {
			break
		}
		for _, g := range *res.NatGateways {
			seen[*g.Id]++
		}
		last := *(*res.NatGateways)[len(*res.NatGateways)-1].Id
		marker = &last
	}
	if seen[gw1ID] != 1 || seen[gw2ID] != 1 {
		t.Errorf("ListNatGateways paging seen = %v, want 1 each for %s and %s", seen, gw1ID, gw2ID)
	}

	_, err = c.ListNatGateways(&nat.ListNatGatewaysRequest{Marker: ptr(unknownID)})
	wantError(t, err, 400, "NAT.0002")
	_, err = c.ListNatGateways(&nat.ListNatGatewaysRequest{Limit: ptr(int32(-1))})
	wantError(t, err, 400, "NAT.0002")

	// --- DeleteNatGateway and verify subnet IP release ----------------
	if _, err := c.DeleteNatGateway(&nat.DeleteNatGatewayRequest{NatGatewayId: gw2ID}); err != nil {
		t.Fatalf("DeleteNatGateway(2): %v", err)
	}
	if _, err := c.DeleteNatGateway(&nat.DeleteNatGatewayRequest{NatGatewayId: gw1ID}); err != nil {
		t.Fatalf("DeleteNatGateway(1): %v", err)
	}
	_, err = c.ShowNatGateway(&nat.ShowNatGatewayRequest{NatGatewayId: gw1ID})
	wantError(t, err, 404, "NAT.0105")
	_, err = c.DeleteNatGateway(&nat.DeleteNatGatewayRequest{NatGatewayId: gw1ID})
	wantError(t, err, 404, "NAT.0105")

	afterSub, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnet1ID})
	if err != nil {
		t.Fatalf("ShowSubnet after gateway deletes: %v", err)
	}
	if afterSub.Subnet.AvailableIpAddressCount != availBefore {
		t.Errorf("subnet available IPs after delete = %d, want %d (restored)", afterSub.Subnet.AvailableIpAddressCount, availBefore)
	}
}

// TestPublicSnatAndDnatRulesAndEIPHook drives §3.2, §3.3 and §4.2
// through the official NAT v2, EIP v2, EIP v3, VPC v2 and ECS v2 SDKs:
//   - SNAT rule creation (network_id and cidr with source_type 0 & 1,
//     single and comma-separated multiple EIPs), Show, List, Update
//     (swapping EIPs by public_ip_address and updating description),
//     Delete, and validation/conflict errors;
//   - EIP hook semantics in EIP v2 and v3 (ACTIVE status, NATGW
//     associate_instance_type/associate_instance_id, vnic nil, port
//     bind refusal VPC.0510, delete refusal VPC.0517, cross-gateway
//     hold refusal NAT.0404, reference counting across multiple rules on
//     the same gateway, and return to DOWN/unbound on last release);
//   - DNAT rule creation (real ECS NIC port_id and private_ip, single
//     ports, port ranges, and "any" protocol), all-or-nothing
//     BatchCreateNatGatewayDnatRules, Show, List, Update, Delete, and
//     conflict cases (NAT.0304, NAT.0305, NAT.0306, NAT.0307, NAT.0308,
//     NAT.0408, NAT.0409);
//   - DeleteNatGateway refusal (NAT.0006) while rules remain.
func TestPublicSnatAndDnatRulesAndEIPHook(t *testing.T) {
	c := newNAT(t)
	eip2 := newEIP(t)
	eip3 := newEIPv3(t)
	net2 := newV2(t, realEndpoint)
	compute := newECS(t)
	images := newIMS(t)

	// --- Set up primary VPC with two subnets + ECS server, and a second VPC ---
	vc1, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("nat-rules-vpc-1"), Cidr: ptr("10.72.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc(1): %v", err)
	}
	vpc1ID := vc1.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "VPC 1 to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpc1ID})
			return err == nil
		})
	})
	eventually(t, "VPC 1 to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpc1ID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	makeSubnet := func(name, cidr, gw, vpcID string) string {
		t.Helper()
		sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
			Name: name, Cidr: cidr, GatewayIp: gw, VpcId: vpcID,
		}}})
		if err != nil {
			t.Fatalf("CreateSubnet(%s): %v", name, err)
		}
		id := sc.Subnet.Id
		t.Cleanup(func() {
			eventually(t, name+" to be deletable", func() bool {
				_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: id})
				return err == nil
			})
		})
		eventually(t, name+" to become ACTIVE", func() bool {
			s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: id})
			return err == nil && s.Subnet.Status.Value() == "ACTIVE"
		})
		return id
	}
	sub1aID := makeSubnet("nat-rules-sub-1a", "10.72.1.0/24", "10.72.1.1", vpc1ID)
	sub1bID := makeSubnet("nat-rules-sub-1b", "10.72.2.0/24", "10.72.2.1", vpc1ID)

	vc2, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("nat-rules-vpc-2"), Cidr: ptr("10.73.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc(2): %v", err)
	}
	vpc2ID := vc2.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "VPC 2 to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpc2ID})
			return err == nil
		})
	})
	eventually(t, "VPC 2 to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpc2ID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})
	sub2ID := makeSubnet("nat-rules-sub-2", "10.73.1.0/24", "10.73.1.1", vpc2ID)

	// Create an ECS server in vpc1/sub1a and another in vpc2/sub2.
	imgList, err := images.ListImages(&ims.ListImagesRequest{Name: ptr("Ubuntu 22.04 server 64bit")})
	if err != nil || imgList.Images == nil || len(*imgList.Images) != 1 {
		t.Fatalf("ListImages: %+v, %v", imgList, err)
	}
	imageID := (*imgList.Images)[0].Id

	makeServerPort := func(name, vpcID, subnetID string) string {
		t.Helper()
		srv, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
			Server: &ecs.PostPaidServer{
				Name:       name,
				ImageRef:   imageID,
				FlavorRef:  "s6.large.2",
				Vpcid:      vpcID,
				Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
				RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
			},
		}})
		if err != nil || srv.JobId == nil || srv.ServerIds == nil || len(*srv.ServerIds) != 1 {
			t.Fatalf("CreatePostPaidServers(%s): %+v, %v", name, srv, err)
		}
		srvID := (*srv.ServerIds)[0]
		t.Cleanup(func() {
			del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{
				Servers: []ecs.ServerId{{Id: srvID}},
			}})
			if err == nil && del.JobId != nil {
				eventually(t, "delete server "+name+" job to finish", func() bool {
					job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *del.JobId})
					return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
				})
			}
		})
		eventually(t, "create server "+name+" job to finish", func() bool {
			job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *srv.JobId})
			return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
		})
		ports, err := net2.ListPorts(&v2.ListPortsRequest{DeviceId: &srvID})
		if err != nil || ports.Ports == nil || len(*ports.Ports) != 1 {
			t.Fatalf("ListPorts(%s): %+v, %v", name, ports, err)
		}
		return (*ports.Ports)[0].Id
	}
	port1ID := makeServerPort("nat-rules-srv-1", vpc1ID, sub1aID)
	port2OtherVPCID := makeServerPort("nat-rules-srv-2", vpc2ID, sub2ID)

	// Create two public NAT gateways: gw1 in vpc1/sub1a, gw2 in vpc2/sub2.
	spec1 := nat.GetCreateNatGatewayOptionSpecEnum().E_1
	makeGateway := func(name, vpcID, subnetID string) string {
		t.Helper()
		res, err := c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
			NatGateway: &nat.CreateNatGatewayOption{
				Name:              name,
				RouterId:          vpcID,
				InternalNetworkId: subnetID,
				Spec:              spec1,
			},
		}})
		if err != nil || res.NatGateway == nil || res.NatGateway.Id == nil {
			t.Fatalf("CreateNatGateway(%s): %+v, %v", name, res, err)
		}
		id := *res.NatGateway.Id
		t.Cleanup(func() {
			_, _ = c.DeleteNatGateway(&nat.DeleteNatGatewayRequest{NatGatewayId: id})
		})
		eventually(t, name+" to become ACTIVE", func() bool {
			s, err := c.ShowNatGateway(&nat.ShowNatGatewayRequest{NatGatewayId: id})
			return err == nil && s.NatGateway.Status != nil && s.NatGateway.Status.Value() == "ACTIVE"
		})
		return id
	}
	gw1ID := makeGateway("nat-rules-gw-1", vpc1ID, sub1aID)
	gw2ID := makeGateway("nat-rules-gw-2", vpc2ID, sub2ID)

	// Create 4 EIPs.
	perShare := eipv2.GetCreatePublicipBandwidthOptionShareTypeEnum().PER
	makeEIP := func(alias string) (id, addr string) {
		t.Helper()
		res, err := eip2.CreatePublicip(&eipv2.CreatePublicipRequest{Body: &eipv2.CreatePublicipRequestBody{
			Publicip:  &eipv2.CreatePublicipOption{Type: "5_bgp", Alias: ptr(alias)},
			Bandwidth: &eipv2.CreatePublicipBandwidthOption{Name: ptr(alias + "-bw"), ShareType: perShare, Size: ptr(int32(5))},
		}})
		if err != nil || res.Publicip == nil || res.Publicip.Id == nil || res.Publicip.PublicIpAddress == nil {
			t.Fatalf("CreatePublicip(%s): %+v, %v", alias, res, err)
		}
		id = *res.Publicip.Id
		addr = *res.Publicip.PublicIpAddress
		t.Cleanup(func() {
			_, _ = eip2.UpdatePublicip(&eipv2.UpdatePublicipRequest{PublicipId: id, Body: &eipv2.UpdatePublicipsRequestBody{Publicip: &eipv2.UpdatePublicipOption{}}})
			_, _ = eip2.DeletePublicip(&eipv2.DeletePublicipRequest{PublicipId: id})
		})
		eventually(t, alias+" to become DOWN", func() bool {
			s, err := eip2.ShowPublicip(&eipv2.ShowPublicipRequest{PublicipId: id})
			return err == nil && s.Publicip.Status.Value() == "DOWN"
		})
		return id, addr
	}
	eip1ID, eip1Addr := makeEIP("nat-sdk-eip-1")
	eip2ID, eip2Addr := makeEIP("nat-sdk-eip-2")
	eip3ID, eip3Addr := makeEIP("nat-sdk-eip-3")
	eip4ID, _ := makeEIP("nat-sdk-eip-4")

	// Bind eip4 to port2OtherVPCID to test NAT.0402 (EIP already bound to a port).
	if _, err := eip2.UpdatePublicip(&eipv2.UpdatePublicipRequest{
		PublicipId: eip4ID,
		Body:       &eipv2.UpdatePublicipsRequestBody{Publicip: &eipv2.UpdatePublicipOption{PortId: &port2OtherVPCID}},
	}); err != nil {
		t.Fatalf("binding eip4 to port: %v", err)
	}

	// =================================================================
	// 1. Public SNAT rules (§3.2) and EIP hook (§4.2)
	// =================================================================

	// --- SNAT validation errors ---------------------------------------
	// Unknown gateway -> NAT.0105 (404).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: unknownID,
			NetworkId:    &sub1aID,
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 404, "NAT.0105")

	// Both network_id and cidr -> NAT.0202 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1aID,
			Cidr:         ptr("10.72.1.0/25"),
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0202")

	// Neither network_id nor cidr -> NAT.0202 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0202")

	// network_id with source_type=1 -> NAT.0204 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1aID,
			SourceType:   ptr(int32(1)),
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0204")

	// Unknown network_id -> NAT.0019 (404).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    ptr(unknownID),
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 404, "NAT.0019")

	// network_id in another VPC -> NAT.0008 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub2ID,
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0008")

	// Non-canonical or invalid CIDR -> NAT.0203 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			Cidr:         ptr("10.72.1.5/24"),
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0203")

	// source_type=0 CIDR outside VPC subnets -> NAT.0205 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			Cidr:         ptr("192.168.100.0/24"),
			SourceType:   ptr(int32(0)),
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0205")

	// Non-UUID floating_ip_id -> NAT.0210 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1aID,
			FloatingIpId: "not-a-uuid",
		},
	}})
	wantError(t, err, 400, "NAT.0210")

	// Duplicate EIP in floating_ip_id -> NAT.0403 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1aID,
			FloatingIpId: eip1ID + "," + eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0403")

	// Unknown EIP -> NAT.0026 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1aID,
			FloatingIpId: unknownID,
		},
	}})
	wantError(t, err, 400, "NAT.0026")

	// EIP bound to an ECS port -> NAT.0402 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1aID,
			FloatingIpId: eip4ID,
		},
	}})
	wantError(t, err, 400, "NAT.0402")

	// global_eip_id present -> WeiStack.0501 (501).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1aID,
			FloatingIpId: eip1ID,
			GlobalEipId:  ptr(unknownID),
		},
	}})
	wantError(t, err, 501, "WeiStack.0501")

	// --- Create SNAT rule 1 (network_id, comma-separated multiple EIPs) ---
	snat1Created, err := c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1aID,
			FloatingIpId: eip1ID + "," + eip2ID,
			Description:  ptr("subnet 1a snat"),
		},
	}})
	if err != nil || snat1Created.SnatRule == nil {
		t.Fatalf("CreateNatGatewaySnatRule(1): %+v, %v", snat1Created, err)
	}
	sr1 := snat1Created.SnatRule
	snat1ID := sr1.Id
	t.Cleanup(func() {
		_, _ = c.DeleteNatGatewaySnatRule(&nat.DeleteNatGatewaySnatRuleRequest{NatGatewayId: gw1ID, SnatRuleId: snat1ID})
	})

	if sr1.Status.Value() != "PENDING_CREATE" {
		t.Errorf("new SNAT rule status = %s, want PENDING_CREATE", sr1.Status.Value())
	}
	wantJoinedIDs := eip1ID + "," + eip2ID
	wantJoinedAddrs := eip1Addr + "," + eip2Addr
	if sr1.NatGatewayId != gw1ID || sr1.TenantId != projectID || sr1.NetworkId != sub1aID ||
		sr1.Cidr != "" || sr1.SourceType != 0 ||
		sr1.FloatingIpId != wantJoinedIDs || sr1.FloatingIpAddress != wantJoinedAddrs ||
		sr1.Description != "subnet 1a snat" || !sr1.AdminStateUp ||
		sr1.GlobalEipId != "" || sr1.GlobalEipAddress != "" {
		t.Errorf("created SNAT rule 1 = %+v", sr1)
	}

	eventually(t, "SNAT rule 1 to become ACTIVE", func() bool {
		s, err := c.ShowNatGatewaySnatRule(&nat.ShowNatGatewaySnatRuleRequest{SnatRuleId: snat1ID})
		if err != nil {
			t.Fatalf("ShowNatGatewaySnatRule(1): %v", err)
		}
		return s.SnatRule.Status.Value() == "ACTIVE"
	})

	// Duplicate subnet on the same gateway -> NAT.0208 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1aID,
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0208")

	// CIDR overlapping sub1a (10.72.1.0/24) on the same gateway -> NAT.0207 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			Cidr:         ptr("10.72.1.0/25"),
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0207")

	// Deleting gateway 1 while rules exist -> NAT.0006 (400).
	_, err = c.DeleteNatGateway(&nat.DeleteNatGatewayRequest{NatGatewayId: gw1ID})
	wantError(t, err, 400, "NAT.0006")

	// --- Verify EIP hook (§4.2) via EIP v2 and v3 SDKs ----------------
	// 1. EIP v2 shows ACTIVE with no port_id.
	eip1V2, err := eip2.ShowPublicip(&eipv2.ShowPublicipRequest{PublicipId: eip1ID})
	if err != nil || eip1V2.Publicip == nil ||
		eip1V2.Publicip.Status.Value() != "ACTIVE" || eip1V2.Publicip.PortId != nil {
		t.Fatalf("EIP v2 ShowPublicip(held by NAT) = %+v, %v", eip1V2, err)
	}

	// 2. EIP v3 ShowPublicip and ListPublicips show associate_instance_type=NATGW, associate_instance_id=gw1ID, vnic=nil.
	eip1V3, err := eip3.ShowPublicip(&eipv3.ShowPublicipRequest{PublicipId: eip1ID})
	if err != nil || eip1V3.Publicip == nil ||
		eip1V3.Publicip.Status == nil || eip1V3.Publicip.Status.Value() != "ACTIVE" ||
		eip1V3.Publicip.AssociateInstanceType == nil || eip1V3.Publicip.AssociateInstanceType.Value() != "NATGW" ||
		eip1V3.Publicip.AssociateInstanceId == nil || *eip1V3.Publicip.AssociateInstanceId != gw1ID ||
		eip1V3.Publicip.Vnic != nil {
		t.Fatalf("EIP v3 ShowPublicip(held by NAT) = %+v, %v", eip1V3, err)
	}

	natgwFilter := eipv3.GetListPublicipsRequestAssociateInstanceTypeEnum().NATGW
	listedHeldV3, err := eip3.ListPublicips(&eipv3.ListPublicipsRequest{
		AssociateInstanceType: &[]eipv3.ListPublicipsRequestAssociateInstanceType{natgwFilter},
		AssociateInstanceId:   &[]string{gw1ID},
	})
	if err != nil || listedHeldV3.Publicips == nil || len(*listedHeldV3.Publicips) != 2 {
		t.Fatalf("EIP v3 ListPublicips(NATGW, %s) = %+v, %v; want 2 held EIPs", gw1ID, listedHeldV3, err)
	}

	// 3. Held EIP cannot be bound to a port via v2 or v3 -> VPC.0510 (409).
	_, err = eip2.UpdatePublicip(&eipv2.UpdatePublicipRequest{
		PublicipId: eip1ID,
		Body:       &eipv2.UpdatePublicipsRequestBody{Publicip: &eipv2.UpdatePublicipOption{PortId: &port1ID}},
	})
	wantError(t, err, 409, "VPC.0510")

	assocPort := eipv3.GetAssociatePublicipsOptionAssociateInstanceTypeEnum().PORT
	_, err = eip3.AssociatePublicips(&eipv3.AssociatePublicipsRequest{
		PublicipId: eip1ID,
		Body: &eipv3.AssociatePublicipsRequestBody{
			Publicip: &eipv3.AssociatePublicipsOption{
				AssociateInstanceType: assocPort,
				AssociateInstanceId:   port1ID,
			},
		},
	})
	wantError(t, err, 409, "VPC.0510")

	// 4. Held EIP cannot be deleted -> VPC.0517 (409).
	_, err = eip2.DeletePublicip(&eipv2.DeletePublicipRequest{PublicipId: eip1ID})
	wantError(t, err, 409, "VPC.0517")

	// 5. Another NAT gateway (gw2) cannot hold eip1 -> NAT.0404 (400).
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw2ID,
			NetworkId:    &sub2ID,
			FloatingIpId: eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0404")

	// --- Create SNAT rule 2 (cidr with source_type=0 inside sub1b, sharing eip1) ---
	snat2Created, err := c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			Cidr:         ptr("10.72.2.0/25"),
			SourceType:   ptr(int32(0)),
			FloatingIpId: eip1ID,
			Description:  ptr("cidr source_type 0 snat"),
		},
	}})
	if err != nil || snat2Created.SnatRule == nil {
		t.Fatalf("CreateNatGatewaySnatRule(2, cidr source_type=0): %+v, %v", snat2Created, err)
	}
	snat2ID := snat2Created.SnatRule.Id
	t.Cleanup(func() {
		_, _ = c.DeleteNatGatewaySnatRule(&nat.DeleteNatGatewaySnatRuleRequest{NatGatewayId: gw1ID, SnatRuleId: snat2ID})
	})
	eventually(t, "SNAT rule 2 to become ACTIVE", func() bool {
		s, err := c.ShowNatGatewaySnatRule(&nat.ShowNatGatewaySnatRuleRequest{SnatRuleId: snat2ID})
		return err == nil && s.SnatRule.Status.Value() == "ACTIVE"
	})

	// --- Create SNAT rule 3 (cidr with source_type=1 Direct Connect, sharing eip1) ---
	snat3Created, err := c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			Cidr:         ptr("172.31.100.0/24"),
			SourceType:   ptr(int32(1)),
			FloatingIpId: eip1ID,
			Description:  ptr("direct connect snat"),
		},
	}})
	if err != nil || snat3Created.SnatRule == nil || snat3Created.SnatRule.SourceType != 1 {
		t.Fatalf("CreateNatGatewaySnatRule(3, cidr source_type=1): %+v, %v", snat3Created, err)
	}
	snat3ID := snat3Created.SnatRule.Id
	t.Cleanup(func() {
		_, _ = c.DeleteNatGatewaySnatRule(&nat.DeleteNatGatewaySnatRuleRequest{NatGatewayId: gw1ID, SnatRuleId: snat3ID})
	})
	eventually(t, "SNAT rule 3 to become ACTIVE", func() bool {
		s, err := c.ShowNatGatewaySnatRule(&nat.ShowNatGatewaySnatRuleRequest{SnatRuleId: snat3ID})
		return err == nil && s.SnatRule.Status.Value() == "ACTIVE"
	})

	// --- ListNatGatewaySnatRules (filters and pagination) -------------
	snatActive := nat.GetListNatGatewaySnatRulesRequestStatusEnum().ACTIVE
	listedSnat1, err := c.ListNatGatewaySnatRules(&nat.ListNatGatewaySnatRulesRequest{
		Id:                &snat1ID,
		NatGatewayId:      &[]string{gw1ID},
		NetworkId:         &sub1aID,
		SourceType:        ptr(int32(0)),
		FloatingIpId:      &eip2ID,
		FloatingIpAddress: &wantJoinedAddrs,
		Description:       ptr("subnet 1a snat"),
		Status:            &snatActive,
		AdminStateUp:      ptr(true),
	})
	if err != nil || listedSnat1.SnatRules == nil || len(*listedSnat1.SnatRules) != 1 ||
		(*listedSnat1.SnatRules)[0].Id != snat1ID {
		t.Fatalf("ListNatGatewaySnatRules(filters) = %+v, %v", listedSnat1, err)
	}

	// Paginate across SNAT rules on gw1 with limit=1.
	seenSnat := map[string]int{}
	var snatMarker *string
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("ListNatGatewaySnatRules paging did not terminate")
		}
		res, err := c.ListNatGatewaySnatRules(&nat.ListNatGatewaySnatRulesRequest{
			NatGatewayId: &[]string{gw1ID},
			Limit:        ptr(int32(1)),
			Marker:       snatMarker,
		})
		if err != nil {
			t.Fatalf("ListNatGatewaySnatRules(page %d): %v", pages, err)
		}
		if res.SnatRules == nil || len(*res.SnatRules) == 0 {
			break
		}
		for _, r := range *res.SnatRules {
			seenSnat[r.Id]++
		}
		last := (*res.SnatRules)[len(*res.SnatRules)-1].Id
		snatMarker = &last
	}
	if seenSnat[snat1ID] != 1 || seenSnat[snat2ID] != 1 || seenSnat[snat3ID] != 1 {
		t.Errorf("ListNatGatewaySnatRules paging seen = %v", seenSnat)
	}

	// --- UpdateNatGatewaySnatRule (swap EIPs by public_ip_address) ----
	// Wrong gateway ID -> NAT.0002 (400).
	_, err = c.UpdateNatGatewaySnatRule(&nat.UpdateNatGatewaySnatRuleRequest{
		SnatRuleId: snat1ID,
		Body: &nat.UpdateNatGatewaySnatRuleRequestOption{
			SnatRule: &nat.UpdateNatGatewaySnatRuleOption{
				NatGatewayId:    gw2ID,
				PublicIpAddress: &eip3Addr,
			},
		},
	})
	wantError(t, err, 400, "NAT.0002")

	// Unknown public_ip_address -> NAT.0026 (400).
	_, err = c.UpdateNatGatewaySnatRule(&nat.UpdateNatGatewaySnatRuleRequest{
		SnatRuleId: snat1ID,
		Body: &nat.UpdateNatGatewaySnatRuleRequestOption{
			SnatRule: &nat.UpdateNatGatewaySnatRuleOption{
				NatGatewayId:    gw1ID,
				PublicIpAddress: ptr("203.0.113.254"),
			},
		},
	})
	wantError(t, err, 400, "NAT.0026")

	// Swap snat1 from (eip1, eip2) to (eip1, eip3): eip2 should be released, eip3 held, eip1 still held.
	updSnatAddrs := eip1Addr + "," + eip3Addr
	updSnat1, err := c.UpdateNatGatewaySnatRule(&nat.UpdateNatGatewaySnatRuleRequest{
		SnatRuleId: snat1ID,
		Body: &nat.UpdateNatGatewaySnatRuleRequestOption{
			SnatRule: &nat.UpdateNatGatewaySnatRuleOption{
				NatGatewayId:    gw1ID,
				PublicIpAddress: &updSnatAddrs,
				Description:     ptr("subnet 1a snat updated"),
			},
		},
	})
	if err != nil || updSnat1.SnatRule == nil {
		t.Fatalf("UpdateNatGatewaySnatRule(1): %+v, %v", updSnat1, err)
	}
	if updSnat1.SnatRule.FloatingIpId != eip1ID+","+eip3ID ||
		updSnat1.SnatRule.FloatingIpAddress != updSnatAddrs ||
		updSnat1.SnatRule.PublicIpAddress != updSnatAddrs ||
		updSnat1.SnatRule.Description != "subnet 1a snat updated" {
		t.Errorf("UpdateNatGatewaySnatRule(1) = %+v", updSnat1.SnatRule)
	}

	// Verify eip2 is now released (DOWN in v2, unbound in v3) while eip3 is held (NATGW).
	eip2AfterDrop, err := eip3.ShowPublicip(&eipv3.ShowPublicipRequest{PublicipId: eip2ID})
	if err != nil || eip2AfterDrop.Publicip.Status.Value() != "DOWN" ||
		eip2AfterDrop.Publicip.AssociateInstanceType != nil || eip2AfterDrop.Publicip.AssociateInstanceId != nil {
		t.Fatalf("eip2 after drop from SNAT rule = %+v, %v; want DOWN and unbound", eip2AfterDrop, err)
	}
	eip3AfterHold, err := eip3.ShowPublicip(&eipv3.ShowPublicipRequest{PublicipId: eip3ID})
	if err != nil || eip3AfterHold.Publicip.Status.Value() != "ACTIVE" ||
		eip3AfterHold.Publicip.AssociateInstanceType == nil || eip3AfterHold.Publicip.AssociateInstanceType.Value() != "NATGW" ||
		eip3AfterHold.Publicip.AssociateInstanceId == nil || *eip3AfterHold.Publicip.AssociateInstanceId != gw1ID {
		t.Fatalf("eip3 after add to SNAT rule = %+v, %v; want ACTIVE/NATGW", eip3AfterHold, err)
	}

	// Delete snat2 and snat3; eip1 is still used by snat1 so it remains held.
	if _, err := c.DeleteNatGatewaySnatRule(&nat.DeleteNatGatewaySnatRuleRequest{NatGatewayId: gw1ID, SnatRuleId: snat2ID}); err != nil {
		t.Fatalf("DeleteNatGatewaySnatRule(2): %v", err)
	}
	if _, err := c.DeleteNatGatewaySnatRule(&nat.DeleteNatGatewaySnatRuleRequest{NatGatewayId: gw1ID, SnatRuleId: snat3ID}); err != nil {
		t.Fatalf("DeleteNatGatewaySnatRule(3): %v", err)
	}
	eip1StillHeld, err := eip3.ShowPublicip(&eipv3.ShowPublicipRequest{PublicipId: eip1ID})
	if err != nil || eip1StillHeld.Publicip.Status.Value() != "ACTIVE" ||
		eip1StillHeld.Publicip.AssociateInstanceType == nil || eip1StillHeld.Publicip.AssociateInstanceType.Value() != "NATGW" {
		t.Fatalf("eip1 while still used by snat1 = %+v, %v; want ACTIVE/NATGW", eip1StillHeld, err)
	}

	// =================================================================
	// 2. Public DNAT rules (§3.3)
	// =================================================================

	// --- DNAT validation errors ---------------------------------------
	// Both port_id and private_ip -> NAT.0317 (400).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PortId:              &port1ID,
			PrivateIp:           ptr("10.72.1.50"),
			Protocol:            "tcp",
			InternalServicePort: 80,
			ExternalServicePort: 8080,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0317")

	// Neither port_id nor private_ip -> NAT.0310 (400).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			Protocol:            "tcp",
			InternalServicePort: 80,
			ExternalServicePort: 8080,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0310")

	// Unknown port_id -> NAT.0023 (404).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PortId:              ptr(unknownID),
			Protocol:            "tcp",
			InternalServicePort: 80,
			ExternalServicePort: 8080,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 404, "NAT.0023")

	// port_id in another VPC -> NAT.0315 (400).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PortId:              &port2OtherVPCID,
			Protocol:            "tcp",
			InternalServicePort: 80,
			ExternalServicePort: 8080,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0315")

	// Invalid private_ip -> NAT.0311 (400).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PrivateIp:           ptr("999.999.999.999"),
			Protocol:            "tcp",
			InternalServicePort: 80,
			ExternalServicePort: 8080,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0311")

	// Invalid protocol -> NAT.0302 (400).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PortId:              &port1ID,
			Protocol:            "icmp",
			InternalServicePort: 80,
			ExternalServicePort: 8080,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0302")

	// Mismatched port ranges -> NAT.0303 (400).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:             gw1ID,
			PortId:                   &port1ID,
			Protocol:                 "tcp",
			InternalServicePortRange: ptr("1000-1010"),
			ExternalServicePortRange: ptr("2000-2020"),
			FloatingIpId:             eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0303")

	// "any" protocol with non-zero ports -> NAT.0306 (400).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PortId:              &port1ID,
			Protocol:            "any",
			InternalServicePort: 80,
			ExternalServicePort: 80,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0306")

	// "tcp" protocol with port 0 -> NAT.0306 (400).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PortId:              &port1ID,
			Protocol:            "tcp",
			InternalServicePort: 0,
			ExternalServicePort: 0,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0306")

	// "any" DNAT rule on eip1 (which is currently used by snat1) -> NAT.0409 (400).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PrivateIp:           ptr("10.250.0.99"),
			Protocol:            "any",
			InternalServicePort: 0,
			ExternalServicePort: 0,
			FloatingIpId:        eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0409")

	// --- Create DNAT rule 1 (port_id, single ports, TCP 8080 -> 80 on eip1) ---
	dnat1Created, err := c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PortId:              &port1ID,
			Protocol:            "tcp",
			InternalServicePort: 80,
			ExternalServicePort: 8080,
			FloatingIpId:        eip1ID,
			Description:         ptr("web port dnat"),
		},
	}})
	if err != nil || dnat1Created.DnatRule == nil {
		t.Fatalf("CreateNatGatewayDnatRule(1): %+v, %v", dnat1Created, err)
	}
	dr1 := dnat1Created.DnatRule
	dnat1ID := dr1.Id
	t.Cleanup(func() {
		_, _ = c.DeleteNatGatewayDnatRule(&nat.DeleteNatGatewayDnatRuleRequest{NatGatewayId: gw1ID, DnatRuleId: dnat1ID})
	})
	if dr1.Status.Value() != "PENDING_CREATE" {
		t.Errorf("new DNAT rule status = %s, want PENDING_CREATE", dr1.Status.Value())
	}
	if dr1.NatGatewayId != gw1ID || dr1.TenantId != projectID ||
		dr1.PortId == nil || *dr1.PortId != port1ID ||
		dr1.Protocol.Value() != "tcp" ||
		dr1.InternalServicePort != 80 || dr1.ExternalServicePort != 8080 ||
		dr1.FloatingIpId != eip1ID || dr1.FloatingIpAddress != eip1Addr ||
		!dr1.AdminStateUp || dr1.Description != "web port dnat" {
		t.Errorf("created DNAT rule 1 = %+v", dr1)
	}
	eventually(t, "DNAT rule 1 to become ACTIVE", func() bool {
		s, err := c.ShowNatGatewayDnatRule(&nat.ShowNatGatewayDnatRuleRequest{DnatRuleId: dnat1ID})
		return err == nil && s.DnatRule.Status.Value() == "ACTIVE"
	})

	// --- Create DNAT rule 2 (private_ip, port ranges, UDP 2000-2010 -> 1000-1010 on eip1) ---
	dnat2Created, err := c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:             gw1ID,
			PrivateIp:                ptr("10.250.0.10"),
			Protocol:                 "udp",
			InternalServicePort:      999,
			ExternalServicePort:      999,
			InternalServicePortRange: ptr("1000-1010"),
			ExternalServicePortRange: ptr("2000-2010"),
			FloatingIpId:             eip1ID,
			Description:              ptr("udp range dnat"),
		},
	}})
	if err != nil || dnat2Created.DnatRule == nil {
		t.Fatalf("CreateNatGatewayDnatRule(2, range): %+v, %v", dnat2Created, err)
	}
	dr2 := dnat2Created.DnatRule
	dnat2ID := dr2.Id
	t.Cleanup(func() {
		_, _ = c.DeleteNatGatewayDnatRule(&nat.DeleteNatGatewayDnatRuleRequest{NatGatewayId: gw1ID, DnatRuleId: dnat2ID})
	})
	if dr2.InternalServicePort != 0 || dr2.ExternalServicePort != 0 ||
		dr2.InternalServicePortRange == nil || *dr2.InternalServicePortRange != "1000-1010" ||
		dr2.ExternalServicePortRange == nil || *dr2.ExternalServicePortRange != "2000-2010" ||
		dr2.PrivateIp == nil || *dr2.PrivateIp != "10.250.0.10" {
		t.Errorf("created DNAT rule 2 (ranges) = %+v", dr2)
	}
	eventually(t, "DNAT rule 2 to become ACTIVE", func() bool {
		s, err := c.ShowNatGatewayDnatRule(&nat.ShowNatGatewayDnatRuleRequest{DnatRuleId: dnat2ID})
		return err == nil && s.DnatRule.Status.Value() == "ACTIVE"
	})

	// --- DNAT conflict errors (§3.3) ----------------------------------
	// NAT.0305: same EIP (eip1), external port (8080) and protocol (tcp).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PrivateIp:           ptr("10.250.0.99"),
			Protocol:            "tcp",
			InternalServicePort: 90,
			ExternalServicePort: 8080,
			FloatingIpId:        eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0305")

	// NAT.0305: external port inside dnat2's range (2005 in 2000-2010, udp, eip1).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PrivateIp:           ptr("10.250.0.99"),
			Protocol:            "udp",
			InternalServicePort: 90,
			ExternalServicePort: 2005,
			FloatingIpId:        eip1ID,
		},
	}})
	wantError(t, err, 400, "NAT.0305")

	// NAT.0304: same port_id (port1ID), internal port (80) and protocol (tcp) on a different EIP (eip2).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PortId:              &port1ID,
			Protocol:            "tcp",
			InternalServicePort: 80,
			ExternalServicePort: 9090,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0304")

	// NAT.0304: same private_ip (10.250.0.10), internal port inside range (1005 in 1000-1010) and protocol (udp).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PrivateIp:           ptr("10.250.0.10"),
			Protocol:            "udp",
			InternalServicePort: 1005,
			ExternalServicePort: 9090,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0304")

	// NAT.0307: "any" rule on port1ID (which already has dnat1).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PortId:              &port1ID,
			Protocol:            "any",
			InternalServicePort: 0,
			ExternalServicePort: 0,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0307")

	// NAT.0308: "any" rule on private_ip 10.250.0.10 (which already has dnat2).
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PrivateIp:           ptr("10.250.0.10"),
			Protocol:            "any",
			InternalServicePort: 0,
			ExternalServicePort: 0,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0308")

	// NAT.0408: "any" rule on eip3 after eip3 gets a normal DNAT rule (and not in SNAT).
	// First create an "any" DNAT rule on eip2 (which is currently unused) and a fresh private_ip 10.250.0.20.
	dnat3Any, err := c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PrivateIp:           ptr("10.250.0.20"),
			Protocol:            "any",
			InternalServicePort: 0,
			ExternalServicePort: 0,
			FloatingIpId:        eip2ID,
			Description:         ptr("all-port dnat on eip2"),
		},
	}})
	if err != nil || dnat3Any.DnatRule == nil || dnat3Any.DnatRule.Protocol.Value() != "any" {
		t.Fatalf("CreateNatGatewayDnatRule(3, any): %+v, %v", dnat3Any, err)
	}
	dnat3ID := dnat3Any.DnatRule.Id
	t.Cleanup(func() {
		_, _ = c.DeleteNatGatewayDnatRule(&nat.DeleteNatGatewayDnatRuleRequest{NatGatewayId: gw1ID, DnatRuleId: dnat3ID})
	})
	eventually(t, "DNAT rule 3 to become ACTIVE", func() bool {
		s, err := c.ShowNatGatewayDnatRule(&nat.ShowNatGatewayDnatRuleRequest{DnatRuleId: dnat3ID})
		return err == nil && s.DnatRule.Status.Value() == "ACTIVE"
	})

	// NAT.0408: adding a normal DNAT rule on eip2 (which has an "any" rule) is refused.
	_, err = c.CreateNatGatewayDnatRule(&nat.CreateNatGatewayDnatRuleRequest{Body: &nat.CreateNatGatewayDnatRuleOption{
		DnatRule: &nat.CreateNatGatewayDnatOption{
			NatGatewayId:        gw1ID,
			PrivateIp:           ptr("10.250.0.30"),
			Protocol:            "tcp",
			InternalServicePort: 443,
			ExternalServicePort: 443,
			FloatingIpId:        eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0408")

	// NAT.0409: creating an SNAT rule using eip2 (which has an "any" DNAT rule) is refused.
	_, err = c.CreateNatGatewaySnatRule(&nat.CreateNatGatewaySnatRuleRequest{Body: &nat.CreateNatGatewaySnatRuleRequestOption{
		SnatRule: &nat.CreateNatGatewaySnatRuleOption{
			NatGatewayId: gw1ID,
			NetworkId:    &sub1bID,
			FloatingIpId: eip2ID,
		},
	}})
	wantError(t, err, 400, "NAT.0409")

	// Delete dnat3 ("any" rule on eip2) so eip2 is free again.
	if _, err := c.DeleteNatGatewayDnatRule(&nat.DeleteNatGatewayDnatRuleRequest{NatGatewayId: gw1ID, DnatRuleId: dnat3ID}); err != nil {
		t.Fatalf("DeleteNatGatewayDnatRule(3): %v", err)
	}

	// --- BatchCreateNatGatewayDnatRules (all-or-nothing) --------------
	// Empty batch -> NAT.0002 (400).
	_, err = c.BatchCreateNatGatewayDnatRules(&nat.BatchCreateNatGatewayDnatRulesRequest{
		Body: &nat.BatchCreateNatGatewayDnatRulesRequestBody{DnatRules: []nat.CreateNatGatewayDnatOption{}},
	})
	wantError(t, err, 400, "NAT.0002")

	// Intra-batch conflict (two rules with the same external port 8443 on eip2) -> NAT.0305, creates 0 rules and leaves eip2 DOWN.
	_, err = c.BatchCreateNatGatewayDnatRules(&nat.BatchCreateNatGatewayDnatRulesRequest{
		Body: &nat.BatchCreateNatGatewayDnatRulesRequestBody{
			DnatRules: []nat.CreateNatGatewayDnatOption{
				{
					NatGatewayId:        gw1ID,
					PortId:              &port1ID,
					Protocol:            "tcp",
					InternalServicePort: 443,
					ExternalServicePort: 8443,
					FloatingIpId:        eip2ID,
				},
				{
					NatGatewayId:        gw1ID,
					PrivateIp:           ptr("10.250.0.40"),
					Protocol:            "tcp",
					InternalServicePort: 443,
					ExternalServicePort: 8443,
					FloatingIpId:        eip2ID,
				},
			},
		},
	})
	wantError(t, err, 400, "NAT.0305")
	eip2AfterFailedBatch, err := eip2.ShowPublicip(&eipv2.ShowPublicipRequest{PublicipId: eip2ID})
	if err != nil || eip2AfterFailedBatch.Publicip.Status.Value() != "DOWN" {
		t.Fatalf("eip2 after failed batch = %+v, %v; want DOWN", eip2AfterFailedBatch, err)
	}

	// Valid batch of 2 rules on eip2.
	batchCreated, err := c.BatchCreateNatGatewayDnatRules(&nat.BatchCreateNatGatewayDnatRulesRequest{
		Body: &nat.BatchCreateNatGatewayDnatRulesRequestBody{
			DnatRules: []nat.CreateNatGatewayDnatOption{
				{
					NatGatewayId:        gw1ID,
					PortId:              &port1ID,
					Protocol:            "tcp",
					InternalServicePort: 443,
					ExternalServicePort: 8443,
					FloatingIpId:        eip2ID,
					Description:         ptr("batch rule 1"),
				},
				{
					NatGatewayId:        gw1ID,
					PrivateIp:           ptr("10.250.0.40"),
					Protocol:            "6",
					InternalServicePort: 8081,
					ExternalServicePort: 8081,
					FloatingIpId:        eip2ID,
					Description:         ptr("batch rule 2"),
				},
			},
		},
	})
	if err != nil || batchCreated.DnatRules == nil || len(*batchCreated.DnatRules) != 2 {
		t.Fatalf("BatchCreateNatGatewayDnatRules: %+v, %v", batchCreated, err)
	}
	batchID1 := (*batchCreated.DnatRules)[0].Id
	batchID2 := (*batchCreated.DnatRules)[1].Id
	t.Cleanup(func() {
		_, _ = c.DeleteNatGatewayDnatRule(&nat.DeleteNatGatewayDnatRuleRequest{NatGatewayId: gw1ID, DnatRuleId: batchID1})
		_, _ = c.DeleteNatGatewayDnatRule(&nat.DeleteNatGatewayDnatRuleRequest{NatGatewayId: gw1ID, DnatRuleId: batchID2})
	})
	if (*batchCreated.DnatRules)[1].Protocol.Value() != "tcp" {
		t.Errorf("protocol '6' normalized to %q, want 'tcp'", (*batchCreated.DnatRules)[1].Protocol.Value())
	}
	for _, bID := range []string{batchID1, batchID2} {
		eventually(t, "batch DNAT rule "+bID+" to become ACTIVE", func() bool {
			s, err := c.ShowNatGatewayDnatRule(&nat.ShowNatGatewayDnatRuleRequest{DnatRuleId: bID})
			return err == nil && s.DnatRule.Status.Value() == "ACTIVE"
		})
	}

	// --- ListNatGatewayDnatRules (filters and pagination) -------------
	dnatActive := nat.GetListNatGatewayDnatRulesRequestStatusEnum().ACTIVE
	filteredDnat, err := c.ListNatGatewayDnatRules(&nat.ListNatGatewayDnatRulesRequest{
		Id:                  &dnat1ID,
		NatGatewayId:        &[]string{gw1ID},
		PortId:              &port1ID,
		Protocol:            &[]string{"tcp"},
		InternalServicePort: ptr(int32(80)),
		ExternalServicePort: ptr(int32(8080)),
		FloatingIpId:        &eip1ID,
		FloatingIpAddress:   &eip1Addr,
		Status:              &[]nat.ListNatGatewayDnatRulesRequestStatus{dnatActive},
		Description:         ptr("web port dnat"),
		AdminStateUp:        ptr(true),
	})
	if err != nil || filteredDnat.DnatRules == nil || len(*filteredDnat.DnatRules) != 1 ||
		(*filteredDnat.DnatRules)[0].Id != dnat1ID {
		t.Fatalf("ListNatGatewayDnatRules(filters) = %+v, %v", filteredDnat, err)
	}

	seenDnat := map[string]int{}
	var dnatMarker *string
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("ListNatGatewayDnatRules paging did not terminate")
		}
		res, err := c.ListNatGatewayDnatRules(&nat.ListNatGatewayDnatRulesRequest{
			NatGatewayId: &[]string{gw1ID},
			Limit:        ptr(int32(1)),
			Marker:       dnatMarker,
		})
		if err != nil {
			t.Fatalf("ListNatGatewayDnatRules(page %d): %v", pages, err)
		}
		if res.DnatRules == nil || len(*res.DnatRules) == 0 {
			break
		}
		for _, r := range *res.DnatRules {
			seenDnat[r.Id]++
		}
		last := (*res.DnatRules)[len(*res.DnatRules)-1].Id
		dnatMarker = &last
	}
	for _, wantID := range []string{dnat1ID, dnat2ID, batchID1, batchID2} {
		if seenDnat[wantID] != 1 {
			t.Errorf("DNAT rule %s seen %d times in paging, want 1", wantID, seenDnat[wantID])
		}
	}

	// --- UpdateNatGatewayDnatRule -------------------------------------
	updUDP := nat.GetUpdateNatGatewayDnatRuleOptionProtocolEnum().UDP
	updDnat1, err := c.UpdateNatGatewayDnatRule(&nat.UpdateNatGatewayDnatRuleRequest{
		DnatRuleId: dnat1ID,
		Body: &nat.UpdateNatGatewayDnatRuleRequestBody{
			DnatRule: &nat.UpdateNatGatewayDnatRuleOption{
				NatGatewayId:        gw1ID,
				Description:         ptr("web port dnat updated"),
				Protocol:            &updUDP,
				InternalServicePort: ptr(int32(8088)),
				ExternalServicePort: ptr(int32(8089)),
				FloatingIpId:        &eip3ID,
			},
		},
	})
	if err != nil || updDnat1.DnatRule == nil {
		t.Fatalf("UpdateNatGatewayDnatRule(1): %+v, %v", updDnat1, err)
	}
	if updDnat1.DnatRule.Description != "web port dnat updated" ||
		updDnat1.DnatRule.Protocol.Value() != "udp" ||
		updDnat1.DnatRule.InternalServicePort != 8088 ||
		updDnat1.DnatRule.ExternalServicePort != 8089 ||
		updDnat1.DnatRule.FloatingIpId != eip3ID ||
		updDnat1.DnatRule.FloatingIpAddress != eip3Addr {
		t.Errorf("UpdateNatGatewayDnatRule(1) = %+v", updDnat1.DnatRule)
	}

	// --- Delete rules and verify EIPs return to DOWN/unbound ----------
	_, err = c.DeleteNatGatewayDnatRule(&nat.DeleteNatGatewayDnatRuleRequest{NatGatewayId: gw2ID, DnatRuleId: dnat1ID})
	wantError(t, err, 404, "NAT.0319")
	_, err = c.DeleteNatGatewaySnatRule(&nat.DeleteNatGatewaySnatRuleRequest{NatGatewayId: gw2ID, SnatRuleId: snat1ID})
	wantError(t, err, 404, "NAT.0209")

	for _, id := range []string{dnat1ID, dnat2ID, batchID1, batchID2} {
		if _, err := c.DeleteNatGatewayDnatRule(&nat.DeleteNatGatewayDnatRuleRequest{NatGatewayId: gw1ID, DnatRuleId: id}); err != nil {
			t.Fatalf("DeleteNatGatewayDnatRule(%s): %v", id, err)
		}
	}
	if _, err := c.DeleteNatGatewaySnatRule(&nat.DeleteNatGatewaySnatRuleRequest{NatGatewayId: gw1ID, SnatRuleId: snat1ID}); err != nil {
		t.Fatalf("DeleteNatGatewaySnatRule(1): %v", err)
	}

	_, err = c.ShowNatGatewayDnatRule(&nat.ShowNatGatewayDnatRuleRequest{DnatRuleId: dnat1ID})
	wantError(t, err, 404, "NAT.0319")
	_, err = c.ShowNatGatewaySnatRule(&nat.ShowNatGatewaySnatRuleRequest{SnatRuleId: snat1ID})
	wantError(t, err, 404, "NAT.0209")

	// All 3 EIPs used by gw1 must now be DOWN and unbound in both v2 and v3.
	for _, id := range []string{eip1ID, eip2ID, eip3ID} {
		s2, err := eip2.ShowPublicip(&eipv2.ShowPublicipRequest{PublicipId: id})
		if err != nil || s2.Publicip.Status.Value() != "DOWN" {
			t.Errorf("EIP v2 %s after all NAT rules deleted = %+v, %v; want DOWN", id, s2, err)
		}
		s3, err := eip3.ShowPublicip(&eipv3.ShowPublicipRequest{PublicipId: id})
		if err != nil || s3.Publicip.Status.Value() != "DOWN" ||
			s3.Publicip.AssociateInstanceType != nil || s3.Publicip.AssociateInstanceId != nil {
			t.Errorf("EIP v3 %s after all NAT rules deleted = %+v, %v; want DOWN/unbound", id, s3, err)
		}
	}

	// Gateway 1 now has no rules and can be deleted.
	if _, err := c.DeleteNatGateway(&nat.DeleteNatGatewayRequest{NatGatewayId: gw1ID}); err != nil {
		t.Fatalf("DeleteNatGateway(1) after rules deleted: %v", err)
	}
}

// TestPublicNatGatewayTags drives §3.4 through the official NAT v2 SDK
// against both the /v3/{project_id}/nat_gateways/... routes (built into
// the Go SDK) and the /v2.0/{project_id}/nat_gateways/... routes (called
// by the Terraform provider).
func TestPublicNatGatewayTags(t *testing.T) {
	c := newNAT(t)
	net2 := newV2(t, realEndpoint)

	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("nat-tags-sdk-vpc"), Cidr: ptr("10.74.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "tags VPC to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
			return err == nil
		})
	})
	eventually(t, "tags VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "nat-tags-sdk-subnet", Cidr: "10.74.1.0/24", GatewayIp: "10.74.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	t.Cleanup(func() {
		eventually(t, "tags subnet to be deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
			return err == nil
		})
	})
	eventually(t, "tags subnet to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	spec1 := nat.GetCreateNatGatewayOptionSpecEnum().E_1
	makeGateway := func(name string, initTags *[]string) string {
		t.Helper()
		res, err := c.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
			NatGateway: &nat.CreateNatGatewayOption{
				Name:              name,
				RouterId:          vpcID,
				InternalNetworkId: subnetID,
				Spec:              spec1,
				Tags:              initTags,
			},
		}})
		if err != nil || res.NatGateway == nil || res.NatGateway.Id == nil {
			t.Fatalf("CreateNatGateway(%s): %+v, %v", name, res, err)
		}
		id := *res.NatGateway.Id
		t.Cleanup(func() {
			_, _ = c.DeleteNatGateway(&nat.DeleteNatGatewayRequest{NatGatewayId: id})
		})
		eventually(t, name+" to become ACTIVE", func() bool {
			s, err := c.ShowNatGateway(&nat.ShowNatGatewayRequest{NatGatewayId: id})
			return err == nil && s.NatGateway.Status != nil && s.NatGateway.Status.Value() == "ACTIVE"
		})
		return id
	}

	gw1ID := makeGateway("sdk-tag-nat-1", &[]string{"init*one"})
	gw2ID := makeGateway("sdk-tag-nat-2", nil)

	// --- 1. /v3 tag operations via NatClient methods ------------------
	// Show initial tag created via "key*value" on CreateNatGateway.
	initShown, err := c.ShowNatGatewayTag(&nat.ShowNatGatewayTagRequest{NatGatewayId: gw1ID})
	if err != nil || initShown.Tags == nil || len(*initShown.Tags) != 1 ||
		(*initShown.Tags)[0].Key != "init" || (*initShown.Tags)[0].Value != "one" {
		t.Fatalf("ShowNatGatewayTag(initial) = %+v, %v", initShown, err)
	}

	// Error cases on CreateNatGatewayTag.
	_, err = c.CreateNatGatewayTag(&nat.CreateNatGatewayTagRequest{
		NatGatewayId: unknownID,
		Body:         &nat.CreateNatTagRequestBody{Tag: &nat.TagBody{Key: "env", Value: "dev"}},
	})
	wantError(t, err, 404, "NAT.0105")

	_, err = c.CreateNatGatewayTag(&nat.CreateNatGatewayTagRequest{
		NatGatewayId: gw1ID,
		Body:         &nat.CreateNatTagRequestBody{Tag: &nat.TagBody{Key: "", Value: "dev"}},
	})
	wantError(t, err, 400, "NAT.1015")

	// Create and overwrite tag via /v3.
	if _, err := c.CreateNatGatewayTag(&nat.CreateNatGatewayTagRequest{
		NatGatewayId: gw1ID,
		Body:         &nat.CreateNatTagRequestBody{Tag: &nat.TagBody{Key: "env", Value: "dev"}},
	}); err != nil {
		t.Fatalf("CreateNatGatewayTag(env=dev): %v", err)
	}
	if _, err := c.CreateNatGatewayTag(&nat.CreateNatGatewayTagRequest{
		NatGatewayId: gw1ID,
		Body:         &nat.CreateNatTagRequestBody{Tag: &nat.TagBody{Key: "env", Value: "prod"}},
	}); err != nil {
		t.Fatalf("CreateNatGatewayTag(env=prod): %v", err)
	}

	// BatchCreateDeleteNatGatewayTag (create) on gw1 and gw2.
	if _, err := c.BatchCreateDeleteNatGatewayTag(&nat.BatchCreateDeleteNatGatewayTagRequest{
		NatGatewayId: gw1ID,
		Body: &nat.BatchCreateDeleteNatTagsRequestBody{
			Action: "create",
			Tags: []nat.PublicTags{
				{Key: "team", Value: "edge"},
				{Key: "tier", Value: "public"},
			},
		},
	}); err != nil {
		t.Fatalf("BatchCreateDeleteNatGatewayTag(create gw1): %v", err)
	}
	if _, err := c.BatchCreateDeleteNatGatewayTag(&nat.BatchCreateDeleteNatGatewayTagRequest{
		NatGatewayId: gw2ID,
		Body: &nat.BatchCreateDeleteNatTagsRequestBody{
			Action: "create",
			Tags: []nat.PublicTags{
				{Key: "env", Value: "staging"},
				{Key: "team", Value: "edge"},
			},
		},
	}); err != nil {
		t.Fatalf("BatchCreateDeleteNatGatewayTag(create gw2): %v", err)
	}

	// Invalid batch action -> NAT.0002 (400).
	_, err = c.BatchCreateDeleteNatGatewayTag(&nat.BatchCreateDeleteNatGatewayTagRequest{
		NatGatewayId: gw1ID,
		Body: &nat.BatchCreateDeleteNatTagsRequestBody{
			Action: "invalid",
			Tags:   []nat.PublicTags{{Key: "k", Value: "v"}},
		},
	})
	wantError(t, err, 400, "NAT.0002")

	// ListNatGatewayTag across the project.
	allTags, err := c.ListNatGatewayTag(&nat.ListNatGatewayTagRequest{})
	if err != nil || allTags.Tags == nil || len(*allTags.Tags) < 4 {
		t.Fatalf("ListNatGatewayTag = %+v, %v", allTags, err)
	}

	// ListNatGatewayByTag (count and filter with matches).
	counted, err := c.ListNatGatewayByTag(&nat.ListNatGatewayByTagRequest{
		Body: &nat.ListNatsByTagsRequestBody{
			Action: "count",
			Tags:   &[]nat.PublicTag{{Key: "team", Values: []string{"edge"}}},
		},
	})
	if err != nil || counted.TotalCount == nil || *counted.TotalCount != 2 {
		t.Fatalf("ListNatGatewayByTag(count) = %+v, %v", counted, err)
	}

	filtered, err := c.ListNatGatewayByTag(&nat.ListNatGatewayByTagRequest{
		Body: &nat.ListNatsByTagsRequestBody{
			Action:  "filter",
			Tags:    &[]nat.PublicTag{{Key: "env", Values: []string{"prod"}}},
			Matches: &[]nat.PublicMatch{{Key: "resource_name", Value: "sdk-tag-nat"}},
			Limit:   ptr("10"),
			Offset:  ptr("0"),
		},
	})
	if err != nil || filtered.TotalCount == nil || *filtered.TotalCount != 1 ||
		filtered.Resources == nil || len(*filtered.Resources) != 1 ||
		(*filtered.Resources)[0].ResourceId != gw1ID ||
		(*filtered.Resources)[0].ResourceName != "sdk-tag-nat-1" {
		t.Fatalf("ListNatGatewayByTag(filter) = %+v, %v", filtered, err)
	}

	// DeleteNatGatewayTag: deleting an existing key returns 204; deleting a missing key returns 400 NAT.0002 (§3.4).
	if _, err := c.DeleteNatGatewayTag(&nat.DeleteNatGatewayTagRequest{NatGatewayId: gw1ID, Key: "init"}); err != nil {
		t.Fatalf("DeleteNatGatewayTag(init): %v", err)
	}
	_, err = c.DeleteNatGatewayTag(&nat.DeleteNatGatewayTagRequest{NatGatewayId: gw1ID, Key: "nonexistent"})
	wantError(t, err, 400, "NAT.0002")

	// Batch delete ignores missing keys (§3.4).
	if _, err := c.BatchCreateDeleteNatGatewayTag(&nat.BatchCreateDeleteNatGatewayTagRequest{
		NatGatewayId: gw1ID,
		Body: &nat.BatchCreateDeleteNatTagsRequestBody{
			Action: "delete",
			Tags: []nat.PublicTags{
				{Key: "tier", Value: "public"},
				{Key: "nonexistent", Value: "x"},
			},
		},
	}); err != nil {
		t.Fatalf("BatchCreateDeleteNatGatewayTag(delete): %v", err)
	}

	// --- 2. /v2.0 tag routes used by the Terraform provider (§3.4) ----
	if _, err := c.HcClient.Sync(&nat.CreateNatGatewayTagRequest{
		NatGatewayId: gw2ID,
		Body:         &nat.CreateNatTagRequestBody{Tag: &nat.TagBody{Key: "tf", Value: "v20"}},
	}, v20TagDef(natv2.GenReqDefForCreateNatGatewayTag())); err != nil {
		t.Fatalf("v2.0 CreateNatGatewayTag: %v", err)
	}

	if _, err := c.HcClient.Sync(&nat.BatchCreateDeleteNatGatewayTagRequest{
		NatGatewayId: gw2ID,
		Body: &nat.BatchCreateDeleteNatTagsRequestBody{
			Action: "create",
			Tags:   []nat.PublicTags{{Key: "tf-batch", Value: "ok"}},
		},
	}, v20TagDef(natv2.GenReqDefForBatchCreateDeleteNatGatewayTag())); err != nil {
		t.Fatalf("v2.0 BatchCreateDeleteNatGatewayTag: %v", err)
	}

	v20ShownRaw, err := c.HcClient.Sync(&nat.ShowNatGatewayTagRequest{
		NatGatewayId: gw2ID,
	}, v20TagDef(natv2.GenReqDefForShowNatGatewayTag()))
	if err != nil {
		t.Fatalf("v2.0 ShowNatGatewayTag: %v", err)
	}
	v20Shown := v20ShownRaw.(*nat.ShowNatGatewayTagResponse)
	if v20Shown.Tags == nil || len(*v20Shown.Tags) != 4 {
		t.Fatalf("v2.0 ShowNatGatewayTag(gw2) = %+v, want 4 tags", v20Shown)
	}

	v20ListRaw, err := c.HcClient.Sync(&nat.ListNatGatewayTagRequest{}, v20TagDef(natv2.GenReqDefForListNatGatewayTag()))
	if err != nil {
		t.Fatalf("v2.0 ListNatGatewayTag: %v", err)
	}
	if v20List := v20ListRaw.(*nat.ListNatGatewayTagResponse); v20List.Tags == nil || len(*v20List.Tags) == 0 {
		t.Fatalf("v2.0 ListNatGatewayTag = %+v", v20List)
	}

	v20ByTagRaw, err := c.HcClient.Sync(&nat.ListNatGatewayByTagRequest{
		Body: &nat.ListNatsByTagsRequestBody{
			Action: "filter",
			Tags:   &[]nat.PublicTag{{Key: "tf", Values: []string{"v20"}}},
		},
	}, v20TagDef(natv2.GenReqDefForListNatGatewayByTag()))
	if err != nil {
		t.Fatalf("v2.0 ListNatGatewayByTag: %v", err)
	}
	v20ByTag := v20ByTagRaw.(*nat.ListNatGatewayByTagResponse)
	if v20ByTag.TotalCount == nil || *v20ByTag.TotalCount != 1 ||
		v20ByTag.Resources == nil || len(*v20ByTag.Resources) != 1 ||
		(*v20ByTag.Resources)[0].ResourceId != gw2ID {
		t.Fatalf("v2.0 ListNatGatewayByTag = %+v", v20ByTag)
	}

	if _, err := c.HcClient.Sync(&nat.DeleteNatGatewayTagRequest{
		NatGatewayId: gw2ID,
		Key:          "tf",
	}, v20TagDef(natv2.GenReqDefForDeleteNatGatewayTag())); err != nil {
		t.Fatalf("v2.0 DeleteNatGatewayTag: %v", err)
	}
}

// TestNATPermissions runs only with WEISTACK_SDK_IAM=enforce (§7):
// a user granted only nat:natGateways:list can call ListNatGateways,
// and is refused CreateNatGateway with 403 VPC.2201.
func TestNATPermissions(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()
	admin, admin5 := iamClientsAs(t, adminAK, adminSK)

	u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-nat-limited", Enabled: true}})
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
			DisplayName: "sdk-nat-list-only",
			Type:        "AX",
			Description: "nat:natGateways:list only",
			Policy: &iam.ServicePolicy{
				Version: "1.1",
				Statement: []iam.ServiceStatement{{
					Action: []string{"nat:natGateways:list"},
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
		Group: &iam.KeystoneCreateGroupOption{Name: "sdk-nat-readers"},
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

	userNAT := natAs(t, ak, sk)
	if _, err := userNAT.ListNatGateways(&nat.ListNatGatewaysRequest{}); err != nil {
		t.Fatalf("ListNatGateways with nat:natGateways:list: %v", err)
	}

	spec1 := nat.GetCreateNatGatewayOptionSpecEnum().E_1
	_, err = userNAT.CreateNatGateway(&nat.CreateNatGatewayRequest{Body: &nat.CreateNatGatewayRequestBody{
		NatGateway: &nat.CreateNatGatewayOption{
			Name:              "denied-nat-gw",
			RouterId:          unknownID,
			InternalNetworkId: unknownID,
			Spec:              spec1,
		},
	}})
	denialOf(t, err, "VPC.2201")
}

// TestPrivateNatGatewaysAndTransitSubnets drives §3.5 and §3.6 through
// the official NAT v2 SDK:
//   - ListSpecs (all 5 private specs and limits);
//   - CreatePrivateNat (real VPC + subnet, subnet IP allocation,
//     downlink_vpcs, rule_max, transit_ip_pool_size_max, status ACTIVE,
//     tags, default and explicit spec/ngport_ip_address), ShowPrivateNat,
//     ListPrivateNats (filters and page_info pagination), UpdatePrivateNat
//     (name, description, spec, same-spec NAT.1206, rule-limit NAT.1207),
//     DeletePrivateNat (NAT.1202 while rules exist, subnet IP release),
//     and error codes NAT.1201, NAT.1002, NAT.1010, NAT.1403, NAT.1405,
//     VPC.0011;
//   - CreateTransitSubnet (in a separate VPC/subnet, NAT.1101 on duplicate
//     or gateway subnet, NAT.1010 on mismatched virsubnet_project_id),
//     ShowTransitSubnet (ip_count tracking), ListTransitSubnet,
//     UpdateTransitSubnet, and DeleteTransitSubnet (NAT.1202 while transit
//     IPs exist).
func TestPrivateNatGatewaysAndTransitSubnets(t *testing.T) {
	c := newNAT(t)
	net2 := newV2(t, realEndpoint)

	// --- ListSpecs (§3.5) ---------------------------------------------
	specsRes, err := c.ListSpecs(&nat.ListSpecsRequest{})
	if err != nil || specsRes.Specs == nil {
		t.Fatalf("ListSpecs: %+v, %v", specsRes, err)
	}
	wantSpecs := []struct {
		name, code, cbcCode       string
		rule, sess, bps, pps, qps int32
	}{
		{"Small", "1", "privatenat_small", 20, 2000, 233, 20000, 6000},
		{"Medium", "2", "privatenat_medium", 50, 5000, 584, 50000, 9000},
		{"Large", "3", "privatenat_large", 200, 20000, 2336, 200000, 10000},
		{"Extra-large", "4", "privatenat_xlarge", 500, 50000, 5840, 500000, 10000},
		{"Extra-xlarge", "5", "privatenat_xxlarge", 5000, 500000, 58400, 5000000, 100000},
	}
	if len(*specsRes.Specs) != len(wantSpecs) {
		t.Fatalf("ListSpecs len = %d, want %d: %+v", len(*specsRes.Specs), len(wantSpecs), *specsRes.Specs)
	}
	for i, w := range wantSpecs {
		got := (*specsRes.Specs)[i]
		if got.Name == nil || *got.Name != w.name ||
			got.Code == nil || *got.Code != w.code ||
			got.CbcCode == nil || *got.CbcCode != w.cbcCode ||
			got.RuleMax == nil || *got.RuleMax != w.rule ||
			got.SessMax == nil || *got.SessMax != w.sess ||
			got.BpsMax == nil || *got.BpsMax != w.bps ||
			got.PpsMax == nil || *got.PpsMax != w.pps ||
			got.QpsMax == nil || *got.QpsMax != w.qps {
			t.Errorf("ListSpecs[%d] = %+v, want %+v", i, got, w)
		}
	}

	// --- Set up two VPCs and subnets ----------------------------------
	makeVPC := func(name, cidr string) string {
		t.Helper()
		vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
			Name: ptr(name), Cidr: ptr(cidr),
		}}})
		if err != nil {
			t.Fatalf("CreateVpc(%s): %v", name, err)
		}
		id := vc.Vpc.Id
		t.Cleanup(func() {
			eventually(t, name+" to be deletable", func() bool {
				_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: id})
				return err == nil
			})
		})
		eventually(t, name+" to become OK", func() bool {
			s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: id})
			return err == nil && s.Vpc.Status.Value() == "OK"
		})
		return id
	}
	makeSubnet := func(name, cidr, gw, vpcID string) string {
		t.Helper()
		sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
			Name: name, Cidr: cidr, GatewayIp: gw, VpcId: vpcID,
		}}})
		if err != nil {
			t.Fatalf("CreateSubnet(%s): %v", name, err)
		}
		id := sc.Subnet.Id
		t.Cleanup(func() {
			eventually(t, name+" to be deletable", func() bool {
				_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: id})
				return err == nil
			})
		})
		eventually(t, name+" to become ACTIVE", func() bool {
			s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: id})
			return err == nil && s.Subnet.Status.Value() == "ACTIVE"
		})
		return id
	}

	vpc1ID := makeVPC("pnat-sdk-vpc-1", "10.80.0.0/16")
	sub1ID := makeSubnet("pnat-sdk-sub-1", "10.80.1.0/24", "10.80.1.1", vpc1ID)
	vpc2ID := makeVPC("pnat-sdk-vpc-2", "10.81.0.0/16")
	sub2aID := makeSubnet("pnat-sdk-sub-2a", "10.81.1.0/24", "10.81.1.1", vpc2ID)
	sub2bID := makeSubnet("pnat-sdk-sub-2b", "10.81.2.0/24", "10.81.2.1", vpc2ID)

	specSmall := nat.GetCreatePrivateNatOptionSpecEnum().SMALL
	specMedium := nat.GetCreatePrivateNatOptionSpecEnum().MEDIUM
	var badCreateSpec nat.CreatePrivateNatOptionSpec
	_ = badCreateSpec.UnmarshalJSON([]byte(`"Giant"`))

	// --- CreatePrivateNat validation errors (§3.5) --------------------
	// Empty downlink_vpcs -> NAT.1010 (400).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "pnat-empty-vpcs",
			DownlinkVpcs: []nat.DownlinkVpcOption{},
		},
	}})
	wantError(t, err, 400, "NAT.1010")

	// More than 1 downlink_vpc -> NAT.1201 (400).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name: "pnat-two-vpcs",
			DownlinkVpcs: []nat.DownlinkVpcOption{
				{VirsubnetId: sub1ID},
				{VirsubnetId: sub2aID},
			},
		},
	}})
	wantError(t, err, 400, "NAT.1201")

	// Unknown virsubnet_id -> NAT.1002 (404).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "pnat-bad-sub",
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: unknownID}},
		},
	}})
	wantError(t, err, 404, "NAT.1002")

	// Invalid spec -> NAT.1010 (400).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "pnat-bad-spec",
			Spec:         &badCreateSpec,
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: sub1ID}},
		},
	}})
	wantError(t, err, 400, "NAT.1010")

	// Invalid name -> NAT.1010 (400).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "bad name!",
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: sub1ID}},
		},
	}})
	wantError(t, err, 400, "NAT.1010")

	// Invalid description -> NAT.1010 (400).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "pnat-bad-desc",
			Description:  ptr("bad <desc>"),
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: sub1ID}},
		},
	}})
	wantError(t, err, 400, "NAT.1010")

	// Unusable ngport_ip_address -> NAT.1405 (400).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "pnat-bad-ip",
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: sub1ID, NgportIpAddress: ptr("10.80.99.5")}},
		},
	}})
	wantError(t, err, 400, "NAT.1405")

	// Invalid enterprise_project_id -> VPC.0011 (400).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:                "pnat-bad-ep",
			DownlinkVpcs:        []nat.DownlinkVpcOption{{VirsubnetId: sub1ID}},
			EnterpriseProjectId: ptr("not-a-uuid"),
		},
	}})
	wantError(t, err, 400, "VPC.0011")

	// Invalid tag -> NAT.1015 (400).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "pnat-bad-tag",
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: sub1ID}},
			Tags:         &[]nat.Tag{{Key: "", Value: "v"}},
		},
	}})
	wantError(t, err, 400, "NAT.1015")

	// --- Create private NAT gateways ----------------------------------
	beforeSub, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: sub1ID})
	if err != nil {
		t.Fatalf("ShowSubnet(sub1) before create: %v", err)
	}
	availBefore := beforeSub.Subnet.AvailableIpAddressCount

	created1, err := c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "sdk-pnat-gw-1",
			Description:  ptr("first private gateway"),
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: sub1ID}},
			Tags:         &[]nat.Tag{{Key: "env", Value: "dev"}, {Key: "team", Value: "core"}},
		},
	}})
	if err != nil || created1.Gateway == nil {
		t.Fatalf("CreatePrivateNat(1): %+v, %v", created1, err)
	}
	gw1 := created1.Gateway
	gw1ID := gw1.Id
	t.Cleanup(func() {
		_, _ = c.DeletePrivateNat(&nat.DeletePrivateNatRequest{GatewayId: gw1ID})
	})

	if gw1.Status.Value() != "ACTIVE" ||
		gw1.Spec.Value() != "Small" ||
		gw1.Name != "sdk-pnat-gw-1" ||
		gw1.Description != "first private gateway" ||
		gw1.ProjectId != projectID ||
		gw1.EnterpriseProjectId != "0" ||
		gw1.RuleMax == nil || *gw1.RuleMax != 20 ||
		gw1.TransitIpPoolSizeMax == nil || *gw1.TransitIpPoolSizeMax != 1 ||
		len(gw1.DownlinkVpcs) != 1 ||
		gw1.DownlinkVpcs[0].VpcId != vpc1ID ||
		gw1.DownlinkVpcs[0].VirsubnetId != sub1ID ||
		gw1.DownlinkVpcs[0].NgportIpAddress == nil || !strings.HasPrefix(*gw1.DownlinkVpcs[0].NgportIpAddress, "10.80.1.") ||
		gw1.Tags == nil || len(*gw1.Tags) != 2 {
		t.Errorf("created private gateway 1 = %+v", gw1)
	}
	if gw1.CreatedAt == nil || gw1.UpdatedAt == nil || time.Since(time.Time(*gw1.CreatedAt)) > time.Hour {
		t.Errorf("private gateway 1 timestamps unexpected: created=%v updated=%v", gw1.CreatedAt, gw1.UpdatedAt)
	}
	gw1IP := *gw1.DownlinkVpcs[0].NgportIpAddress

	// Subnet available IP count decreased by 1.
	duringSub, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: sub1ID})
	if err != nil {
		t.Fatalf("ShowSubnet(sub1) after gw1 create: %v", err)
	}
	if duringSub.Subnet.AvailableIpAddressCount != availBefore-1 {
		t.Errorf("subnet available IPs = %d, want %d", duringSub.Subnet.AvailableIpAddressCount, availBefore-1)
	}

	// Duplicate ngport_ip_address -> NAT.1403 (409).
	_, err = c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "pnat-dup-ip",
			Spec:         &specSmall,
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: sub1ID, NgportIpAddress: &gw1IP}},
		},
	}})
	wantError(t, err, 409, "NAT.1403")

	// Create second private gateway with explicit spec Medium and explicit IP.
	const explicitNgportIP = "10.80.1.200"
	created2, err := c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "sdk-pnat-gw-2",
			Description:  ptr("second private gateway"),
			Spec:         &specMedium,
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: sub1ID, NgportIpAddress: ptr(explicitNgportIP)}},
		},
	}})
	if err != nil || created2.Gateway == nil {
		t.Fatalf("CreatePrivateNat(2): %+v, %v", created2, err)
	}
	gw2ID := created2.Gateway.Id
	t.Cleanup(func() {
		_, _ = c.DeletePrivateNat(&nat.DeletePrivateNatRequest{GatewayId: gw2ID})
	})
	if created2.Gateway.DownlinkVpcs[0].NgportIpAddress == nil || *created2.Gateway.DownlinkVpcs[0].NgportIpAddress != explicitNgportIP ||
		created2.Gateway.RuleMax == nil || *created2.Gateway.RuleMax != 50 {
		t.Errorf("created private gateway 2 = %+v", created2.Gateway)
	}

	// --- ShowPrivateNat and UpdatePrivateNat --------------------------
	_, err = c.ShowPrivateNat(&nat.ShowPrivateNatRequest{GatewayId: unknownID})
	wantError(t, err, 404, "NAT.1002")

	shown1, err := c.ShowPrivateNat(&nat.ShowPrivateNatRequest{GatewayId: gw1ID})
	if err != nil || shown1.Gateway == nil || shown1.Gateway.Id != gw1ID {
		t.Fatalf("ShowPrivateNat(1): %+v, %v", shown1, err)
	}

	_, err = c.UpdatePrivateNat(&nat.UpdatePrivateNatRequest{
		GatewayId: unknownID,
		Body:      &nat.UpdatePrivateNatRequestBody{Gateway: &nat.UpdatePrivateNatOption{Name: ptr("ghost")}},
	})
	wantError(t, err, 404, "NAT.1002")

	// Updating to the same spec -> NAT.1206 (400).
	updSmall := nat.GetUpdatePrivateNatOptionSpecEnum().SMALL
	updMedium := nat.GetUpdatePrivateNatOptionSpecEnum().MEDIUM
	_, err = c.UpdatePrivateNat(&nat.UpdatePrivateNatRequest{
		GatewayId: gw1ID,
		Body:      &nat.UpdatePrivateNatRequestBody{Gateway: &nat.UpdatePrivateNatOption{Spec: &updSmall}},
	})
	wantError(t, err, 400, "NAT.1206")

	// Update name, description, and spec Small -> Medium.
	updated1, err := c.UpdatePrivateNat(&nat.UpdatePrivateNatRequest{
		GatewayId: gw1ID,
		Body: &nat.UpdatePrivateNatRequestBody{Gateway: &nat.UpdatePrivateNatOption{
			Name:        ptr("sdk-pnat-gw-1-upd"),
			Description: ptr("updated private gateway"),
			Spec:        &updMedium,
		}},
	})
	if err != nil || updated1.Gateway == nil {
		t.Fatalf("UpdatePrivateNat(1): %+v, %v", updated1, err)
	}
	if updated1.Gateway.Name != "sdk-pnat-gw-1-upd" ||
		updated1.Gateway.Description != "updated private gateway" ||
		updated1.Gateway.Spec.Value() != "Medium" ||
		updated1.Gateway.RuleMax == nil || *updated1.Gateway.RuleMax != 50 {
		t.Errorf("UpdatePrivateNat(1) = %+v", updated1.Gateway)
	}

	// --- ListPrivateNats (filters and page_info pagination) -----------
	listMed := nat.GetListPrivateNatsRequestSpecEnum().MEDIUM
	listActive := nat.GetListPrivateNatsRequestStatusEnum().ACTIVE
	filtered, err := c.ListPrivateNats(&nat.ListPrivateNatsRequest{
		Id:                  &[]string{gw1ID},
		Name:                &[]string{"sdk-pnat-gw-1-upd"},
		Description:         &[]string{"updated private gateway"},
		Spec:                &[]nat.ListPrivateNatsRequestSpec{listMed},
		Status:              &[]nat.ListPrivateNatsRequestStatus{listActive},
		VpcId:               &[]string{vpc1ID},
		VirsubnetId:         &[]string{sub1ID},
		EnterpriseProjectId: &[]string{"all_granted_eps"},
	})
	if err != nil || filtered.Gateways == nil || len(*filtered.Gateways) != 1 ||
		(*filtered.Gateways)[0].Id != gw1ID || filtered.PageInfo == nil ||
		filtered.PageInfo.CurrentCount == nil || *filtered.PageInfo.CurrentCount != 1 {
		t.Fatalf("ListPrivateNats(filters) = %+v, %v", filtered, err)
	}

	seen := map[string]int{}
	var marker *string
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("ListPrivateNats paging did not terminate")
		}
		res, err := c.ListPrivateNats(&nat.ListPrivateNatsRequest{
			VpcId:  &[]string{vpc1ID},
			Limit:  ptr(int32(1)),
			Marker: marker,
		})
		if err != nil {
			t.Fatalf("ListPrivateNats(page %d): %v", pages, err)
		}
		if res.Gateways == nil || len(*res.Gateways) == 0 {
			break
		}
		for _, g := range *res.Gateways {
			seen[g.Id]++
		}
		if res.PageInfo == nil || res.PageInfo.NextMarker == nil || *res.PageInfo.NextMarker == "" {
			break
		}
		marker = res.PageInfo.NextMarker
	}
	if seen[gw1ID] != 1 || seen[gw2ID] != 1 {
		t.Errorf("ListPrivateNats paging seen = %v, want 1 each for %s and %s", seen, gw1ID, gw2ID)
	}

	_, err = c.ListPrivateNats(&nat.ListPrivateNatsRequest{Marker: ptr(unknownID)})
	wantError(t, err, 400, "NAT.1010")
	_, err = c.ListPrivateNats(&nat.ListPrivateNatsRequest{Limit: ptr(int32(-1))})
	wantError(t, err, 400, "NAT.1010")

	// --- Transit subnets (§3.6) ---------------------------------------
	// Subnet in which a private gateway works -> NAT.1101 (400).
	_, err = c.CreateTransitSubnet(&nat.CreateTransitSubnetRequest{Body: &nat.CreateTransitSubnetRequestBody{
		TransitSubnet: &nat.CreateTransitSubnetOption{
			Name:               "tsn-on-gw-sub",
			VirsubnetId:        sub1ID,
			VirsubnetProjectId: projectID,
		},
	}})
	wantError(t, err, 400, "NAT.1101")

	// Unknown virsubnet_id -> NAT.1002 (404).
	_, err = c.CreateTransitSubnet(&nat.CreateTransitSubnetRequest{Body: &nat.CreateTransitSubnetRequestBody{
		TransitSubnet: &nat.CreateTransitSubnetOption{
			Name:               "tsn-unknown-sub",
			VirsubnetId:        unknownID,
			VirsubnetProjectId: projectID,
		},
	}})
	wantError(t, err, 404, "NAT.1002")

	// Mismatched virsubnet_project_id -> NAT.1010 (400).
	_, err = c.CreateTransitSubnet(&nat.CreateTransitSubnetRequest{Body: &nat.CreateTransitSubnetRequestBody{
		TransitSubnet: &nat.CreateTransitSubnetOption{
			Name:               "tsn-bad-proj",
			VirsubnetId:        sub2aID,
			VirsubnetProjectId: unknownID,
		},
	}})
	wantError(t, err, 400, "NAT.1010")

	// Create two transit subnets in vpc2.
	tsn1Res, err := c.CreateTransitSubnet(&nat.CreateTransitSubnetRequest{Body: &nat.CreateTransitSubnetRequestBody{
		TransitSubnet: &nat.CreateTransitSubnetOption{
			Name:               "sdk-tsn-1",
			Description:        ptr("transit subnet 1"),
			VirsubnetId:        sub2aID,
			VirsubnetProjectId: projectID,
			Tags:               &[]nat.Tag{{Key: "env", Value: "test"}},
		},
	}})
	if err != nil || tsn1Res.TransitSubnet == nil {
		t.Fatalf("CreateTransitSubnet(1): %+v, %v", tsn1Res, err)
	}
	tsn1 := tsn1Res.TransitSubnet
	tsn1ID := tsn1.Id
	t.Cleanup(func() {
		_, _ = c.DeleteTransitSubnet(&nat.DeleteTransitSubnetRequest{TransitSubnetId: tsn1ID})
	})
	if tsn1.Name != "sdk-tsn-1" || tsn1.Description != "transit subnet 1" ||
		tsn1.VirsubnetId != sub2aID || tsn1.VirsubnetProjectId != projectID ||
		tsn1.ProjectId != projectID || tsn1.VpcId != vpc2ID ||
		tsn1.Cidr != "10.81.1.0/24" || tsn1.Type.Value() != "VPC" ||
		tsn1.Status.Value() != "ACTIVE" || tsn1.IpCount != 0 || len(tsn1.Tags) != 1 {
		t.Errorf("created transit subnet 1 = %+v", tsn1)
	}

	// Duplicate transit subnet on sub2a -> NAT.1101 (400).
	_, err = c.CreateTransitSubnet(&nat.CreateTransitSubnetRequest{Body: &nat.CreateTransitSubnetRequestBody{
		TransitSubnet: &nat.CreateTransitSubnetOption{
			Name:               "sdk-tsn-dup",
			VirsubnetId:        sub2aID,
			VirsubnetProjectId: projectID,
		},
	}})
	wantError(t, err, 400, "NAT.1101")

	tsn2Res, err := c.CreateTransitSubnet(&nat.CreateTransitSubnetRequest{Body: &nat.CreateTransitSubnetRequestBody{
		TransitSubnet: &nat.CreateTransitSubnetOption{
			Name:               "sdk-tsn-2",
			VirsubnetId:        sub2bID,
			VirsubnetProjectId: projectID,
		},
	}})
	if err != nil || tsn2Res.TransitSubnet == nil {
		t.Fatalf("CreateTransitSubnet(2): %+v, %v", tsn2Res, err)
	}
	tsn2ID := tsn2Res.TransitSubnet.Id
	t.Cleanup(func() {
		_, _ = c.DeleteTransitSubnet(&nat.DeleteTransitSubnetRequest{TransitSubnetId: tsn2ID})
	})

	// UpdateTransitSubnet & ShowTransitSubnet.
	_, err = c.ShowTransitSubnet(&nat.ShowTransitSubnetRequest{TransitSubnetId: unknownID})
	wantError(t, err, 404, "NAT.1002")

	updTsn, err := c.UpdateTransitSubnet(&nat.UpdateTransitSubnetRequest{
		TransitSubnetId: tsn1ID,
		Body: &nat.UpdateTransitSubnetRequestBody{TransitSubnet: &nat.UpdateTransitSubnetOption{
			Name:        ptr("sdk-tsn-1-upd"),
			Description: ptr("updated transit subnet 1"),
		}},
	})
	if err != nil || updTsn.TransitSubnet == nil ||
		updTsn.TransitSubnet.Name != "sdk-tsn-1-upd" ||
		updTsn.TransitSubnet.Description != "updated transit subnet 1" {
		t.Fatalf("UpdateTransitSubnet(1) = %+v, %v", updTsn, err)
	}

	// ListTransitSubnet (filters & pagination).
	filteredTsn, err := c.ListTransitSubnet(&nat.ListTransitSubnetRequest{
		Id:                 &[]string{tsn1ID},
		Name:               &[]string{"sdk-tsn-1-upd"},
		Description:        &[]string{"updated transit subnet 1"},
		VirsubnetProjectId: &[]string{projectID},
		VpcId:              &[]string{vpc2ID},
		VirsubnetId:        &[]string{sub2aID},
		Status:             &[]string{"ACTIVE"},
	})
	if err != nil || filteredTsn.TransitSubnets == nil || len(*filteredTsn.TransitSubnets) != 1 ||
		(*filteredTsn.TransitSubnets)[0].Id != tsn1ID {
		t.Fatalf("ListTransitSubnet(filters) = %+v, %v", filteredTsn, err)
	}

	seenTsn := map[string]int{}
	var tsnMarker *string
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("ListTransitSubnet paging did not terminate")
		}
		res, err := c.ListTransitSubnet(&nat.ListTransitSubnetRequest{
			VpcId:  &[]string{vpc2ID},
			Limit:  ptr(int32(1)),
			Marker: tsnMarker,
		})
		if err != nil {
			t.Fatalf("ListTransitSubnet(page %d): %v", pages, err)
		}
		if res.TransitSubnets == nil || len(*res.TransitSubnets) == 0 {
			break
		}
		for _, s := range *res.TransitSubnets {
			seenTsn[s.Id]++
		}
		if res.PageInfo == nil || res.PageInfo.NextMarker == nil || *res.PageInfo.NextMarker == "" {
			break
		}
		tsnMarker = res.PageInfo.NextMarker
	}
	if seenTsn[tsn1ID] != 1 || seenTsn[tsn2ID] != 1 {
		t.Errorf("ListTransitSubnet paging seen = %v", seenTsn)
	}

	// --- Transit subnet ip_count tracking & DeleteTransitSubnet NAT.1202 ---
	tipA, err := c.CreateTransitIp(&nat.CreateTransitIpRequest{Body: &nat.CreateTransitIpRequestBody{
		TransitIp: &nat.CreatTransitIpOption{VirsubnetId: sub2aID},
	}})
	if err != nil || tipA.TransitIp == nil {
		t.Fatalf("CreateTransitIp(A): %+v, %v", tipA, err)
	}
	tipAID := tipA.TransitIp.Id
	t.Cleanup(func() {
		_, _ = c.DeleteTransitIp(&nat.DeleteTransitIpRequest{TransitIpId: tipAID})
	})

	tipB, err := c.CreateTransitIp(&nat.CreateTransitIpRequest{Body: &nat.CreateTransitIpRequestBody{
		TransitIp: &nat.CreatTransitIpOption{VirsubnetId: sub2aID},
	}})
	if err != nil || tipB.TransitIp == nil {
		t.Fatalf("CreateTransitIp(B): %+v, %v", tipB, err)
	}
	tipBID := tipB.TransitIp.Id
	t.Cleanup(func() {
		_, _ = c.DeleteTransitIp(&nat.DeleteTransitIpRequest{TransitIpId: tipBID})
	})

	shownTsn, err := c.ShowTransitSubnet(&nat.ShowTransitSubnetRequest{TransitSubnetId: tsn1ID})
	if err != nil || shownTsn.TransitSubnet.IpCount != 2 {
		t.Fatalf("ShowTransitSubnet ip_count = %+v, %v; want 2", shownTsn, err)
	}

	// DeleteTransitSubnet while transit IPs exist -> NAT.1202 (400).
	_, err = c.DeleteTransitSubnet(&nat.DeleteTransitSubnetRequest{TransitSubnetId: tsn1ID})
	wantError(t, err, 400, "NAT.1202")

	// --- Rule-limit downgrade NAT.1207 & delete-with-rules NAT.1202 ---
	// gw1 is Medium (rule_max=50). Create 21 private DNAT rules on gw1 using tipA,
	// then verify DeletePrivateNat -> NAT.1202 and downgrading Medium -> Small -> NAT.1207.
	var ruleIDs []string
	tcpProto := nat.GetCreatePrivateDnatOptionProtocolEnum().TCP
	for i := 1; i <= 21; i++ {
		r, err := c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
			DnatRule: &nat.CreatePrivateDnatOption{
				GatewayId:           gw1ID,
				TransitIpId:         tipAID,
				Protocol:            &tcpProto,
				PrivateIpAddress:    ptr(fmt.Sprintf("10.250.1.%d", i)),
				InternalServicePort: ptr("80"),
				TransitServicePort:  ptr(strconv.Itoa(10000 + i)),
			},
		}})
		if err != nil || r.DnatRule == nil || r.DnatRule.Id == nil {
			t.Fatalf("CreatePrivateDnat(%d): %+v, %v", i, r, err)
		}
		ruleIDs = append(ruleIDs, *r.DnatRule.Id)
	}
	t.Cleanup(func() {
		for _, rid := range ruleIDs {
			_, _ = c.DeletePrivateDnat(&nat.DeletePrivateDnatRequest{DnatRuleId: rid})
		}
	})

	_, err = c.DeletePrivateNat(&nat.DeletePrivateNatRequest{GatewayId: gw1ID})
	wantError(t, err, 400, "NAT.1202")

	_, err = c.UpdatePrivateNat(&nat.UpdatePrivateNatRequest{
		GatewayId: gw1ID,
		Body:      &nat.UpdatePrivateNatRequestBody{Gateway: &nat.UpdatePrivateNatOption{Spec: &updSmall}},
	})
	wantError(t, err, 400, "NAT.1207")

	for _, rid := range ruleIDs {
		if _, err := c.DeletePrivateDnat(&nat.DeletePrivateDnatRequest{DnatRuleId: rid}); err != nil {
			t.Fatalf("DeletePrivateDnat(%s): %v", rid, err)
		}
	}

	// Clean up transit IPs and verify ip_count decrements to 1 then 0.
	if _, err := c.DeleteTransitIp(&nat.DeleteTransitIpRequest{TransitIpId: tipBID}); err != nil {
		t.Fatalf("DeleteTransitIp(B): %v", err)
	}
	shownTsn, err = c.ShowTransitSubnet(&nat.ShowTransitSubnetRequest{TransitSubnetId: tsn1ID})
	if err != nil || shownTsn.TransitSubnet.IpCount != 1 {
		t.Fatalf("ShowTransitSubnet ip_count after deleting tipB = %+v, %v; want 1", shownTsn, err)
	}
	if _, err := c.DeleteTransitIp(&nat.DeleteTransitIpRequest{TransitIpId: tipAID}); err != nil {
		t.Fatalf("DeleteTransitIp(A): %v", err)
	}
	shownTsn, err = c.ShowTransitSubnet(&nat.ShowTransitSubnetRequest{TransitSubnetId: tsn1ID})
	if err != nil || shownTsn.TransitSubnet.IpCount != 0 {
		t.Fatalf("ShowTransitSubnet ip_count after deleting tipA = %+v, %v; want 0", shownTsn, err)
	}

	if _, err := c.DeleteTransitSubnet(&nat.DeleteTransitSubnetRequest{TransitSubnetId: tsn1ID}); err != nil {
		t.Fatalf("DeleteTransitSubnet(1): %v", err)
	}
	if _, err := c.DeleteTransitSubnet(&nat.DeleteTransitSubnetRequest{TransitSubnetId: tsn2ID}); err != nil {
		t.Fatalf("DeleteTransitSubnet(2): %v", err)
	}
	_, err = c.ShowTransitSubnet(&nat.ShowTransitSubnetRequest{TransitSubnetId: tsn1ID})
	wantError(t, err, 404, "NAT.1002")

	// Delete both private NAT gateways and verify subnet IPs are released.
	if _, err := c.DeletePrivateNat(&nat.DeletePrivateNatRequest{GatewayId: gw2ID}); err != nil {
		t.Fatalf("DeletePrivateNat(2): %v", err)
	}
	if _, err := c.DeletePrivateNat(&nat.DeletePrivateNatRequest{GatewayId: gw1ID}); err != nil {
		t.Fatalf("DeletePrivateNat(1): %v", err)
	}
	_, err = c.ShowPrivateNat(&nat.ShowPrivateNatRequest{GatewayId: gw1ID})
	wantError(t, err, 404, "NAT.1002")
	_, err = c.DeletePrivateNat(&nat.DeletePrivateNatRequest{GatewayId: gw1ID})
	wantError(t, err, 404, "NAT.1002")

	afterSub, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: sub1ID})
	if err != nil {
		t.Fatalf("ShowSubnet(sub1) after gateway deletes: %v", err)
	}
	if afterSub.Subnet.AvailableIpAddressCount != availBefore {
		t.Errorf("subnet available IPs after delete = %d, want %d", afterSub.Subnet.AvailableIpAddressCount, availBefore)
	}
}

// TestPrivateTransitIpsAndSnatDnatRules drives §3.7, §3.8, and §3.9
// through the official NAT v2, VPC v2, ECS v2, and IMS v2 SDKs:
//   - Transit IPs: CreateTransitIp (auto and explicit ip_address,
//     NAT.1101 on non-transit subnet, NAT.1002 on unknown subnet,
//     NAT.1403/NAT.1405), ShowTransitIp, ListTransitIps (filtering by
//     transit_subnet_id and gateway_id, page_info paging), DeleteTransitIp
//     (NAT.1409 while used by rules), and gateway_id linking/unlinking;
//   - Private SNAT rules: CreatePrivateSnat (virsubnet_id and cidr,
//     transit_ip_associations, NAT.1501, NAT.1502, NAT.1003, NAT.1503,
//     NAT.1505, NAT.1303, NAT.1305, NAT.1406), ShowPrivateSnat,
//     ListPrivateSnats, UpdatePrivateSnat (swapping transit IPs and
//     unlinking old ones), DeletePrivateSnat;
//   - Private DNAT rules: CreatePrivateDnat (ECS NIC network_interface_id
//     -> type COMPUTE and private_ip_address -> type CUSTOMIZE, tcp/udp/any,
//     NAT.1311, NAT.1009, NAT.1304, NAT.1308, NAT.1306, NAT.1310,
//     NAT.1307, NAT.1410, NAT.1309), ShowPrivateDnat, ListPrivateDnats,
//     UpdatePrivateDnat, DeletePrivateDnat.
func TestPrivateTransitIpsAndSnatDnatRules(t *testing.T) {
	c := newNAT(t)
	net2 := newV2(t, realEndpoint)
	compute := newECS(t)
	images := newIMS(t)

	makeVPC := func(name, cidr string) string {
		t.Helper()
		vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
			Name: ptr(name), Cidr: ptr(cidr),
		}}})
		if err != nil {
			t.Fatalf("CreateVpc(%s): %v", name, err)
		}
		id := vc.Vpc.Id
		t.Cleanup(func() {
			eventually(t, name+" to be deletable", func() bool {
				_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: id})
				return err == nil
			})
		})
		eventually(t, name+" to become OK", func() bool {
			s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: id})
			return err == nil && s.Vpc.Status.Value() == "OK"
		})
		return id
	}
	makeSubnet := func(name, cidr, gw, vpcID string) string {
		t.Helper()
		sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
			Name: name, Cidr: cidr, GatewayIp: gw, VpcId: vpcID,
		}}})
		if err != nil {
			t.Fatalf("CreateSubnet(%s): %v", name, err)
		}
		id := sc.Subnet.Id
		t.Cleanup(func() {
			eventually(t, name+" to be deletable", func() bool {
				_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: id})
				return err == nil
			})
		})
		eventually(t, name+" to become ACTIVE", func() bool {
			s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: id})
			return err == nil && s.Subnet.Status.Value() == "ACTIVE"
		})
		return id
	}

	// vpc1 holds gw1 (sub1a), gw2 (sub1b), and a transit subnet (sub1c) to test NAT.1303.
	// vpc2 holds transit subnet tsn2 (sub2a) and a plain subnet (sub2b) for NAT.1101 + NAT.1304.
	vpc1ID := makeVPC("pnat-rules-vpc-1", "10.82.0.0/16")
	sub1aID := makeSubnet("pnat-rules-sub-1a", "10.82.1.0/24", "10.82.1.1", vpc1ID)
	sub1bID := makeSubnet("pnat-rules-sub-1b", "10.82.2.0/24", "10.82.2.1", vpc1ID)
	sub1cID := makeSubnet("pnat-rules-sub-1c", "10.82.3.0/24", "10.82.3.1", vpc1ID)

	vpc2ID := makeVPC("pnat-rules-vpc-2", "10.83.0.0/16")
	sub2aID := makeSubnet("pnat-rules-sub-2a", "10.83.1.0/24", "10.83.1.1", vpc2ID)
	sub2bID := makeSubnet("pnat-rules-sub-2b", "10.83.2.0/24", "10.83.2.1", vpc2ID)

	imgList, err := images.ListImages(&ims.ListImagesRequest{Name: ptr("Ubuntu 22.04 server 64bit")})
	if err != nil || imgList.Images == nil || len(*imgList.Images) != 1 {
		t.Fatalf("ListImages: %+v, %v", imgList, err)
	}
	imageID := (*imgList.Images)[0].Id

	makeServerPort := func(name, vpcID, subnetID string) (portID, portIP string) {
		t.Helper()
		srv, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
			Server: &ecs.PostPaidServer{
				Name:       name,
				ImageRef:   imageID,
				FlavorRef:  "s6.large.2",
				Vpcid:      vpcID,
				Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
				RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
			},
		}})
		if err != nil || srv.JobId == nil || srv.ServerIds == nil || len(*srv.ServerIds) != 1 {
			t.Fatalf("CreatePostPaidServers(%s): %+v, %v", name, srv, err)
		}
		srvID := (*srv.ServerIds)[0]
		t.Cleanup(func() {
			del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{
				Servers: []ecs.ServerId{{Id: srvID}},
			}})
			if err == nil && del.JobId != nil {
				eventually(t, "delete server "+name+" job to finish", func() bool {
					job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *del.JobId})
					return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
				})
			}
		})
		eventually(t, "create server "+name+" job to finish", func() bool {
			job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *srv.JobId})
			return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
		})
		ports, err := net2.ListPorts(&v2.ListPortsRequest{DeviceId: &srvID})
		if err != nil || ports.Ports == nil || len(*ports.Ports) != 1 ||
			len((*ports.Ports)[0].FixedIps) != 1 || (*ports.Ports)[0].FixedIps[0].IpAddress == nil {
			t.Fatalf("ListPorts(%s): %+v, %v", name, ports, err)
		}
		return (*ports.Ports)[0].Id, *(*ports.Ports)[0].FixedIps[0].IpAddress
	}
	port1ID, port1IP := makeServerPort("pnat-rules-srv-1", vpc1ID, sub1aID)
	port2OtherVPCID, _ := makeServerPort("pnat-rules-srv-2", vpc2ID, sub2bID)

	makePrivateGW := func(name, subnetID string) string {
		t.Helper()
		res, err := c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
			Gateway: &nat.CreatePrivateNatOption{
				Name:         name,
				DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: subnetID}},
			},
		}})
		if err != nil || res.Gateway == nil {
			t.Fatalf("CreatePrivateNat(%s): %+v, %v", name, res, err)
		}
		id := res.Gateway.Id
		t.Cleanup(func() {
			_, _ = c.DeletePrivateNat(&nat.DeletePrivateNatRequest{GatewayId: id})
		})
		return id
	}
	gw1ID := makePrivateGW("pnat-rules-gw-1", sub1aID)
	gw2ID := makePrivateGW("pnat-rules-gw-2", sub1bID)

	makeTransitSubnet := func(name, subnetID string) string {
		t.Helper()
		res, err := c.CreateTransitSubnet(&nat.CreateTransitSubnetRequest{Body: &nat.CreateTransitSubnetRequestBody{
			TransitSubnet: &nat.CreateTransitSubnetOption{
				Name:               name,
				VirsubnetId:        subnetID,
				VirsubnetProjectId: projectID,
			},
		}})
		if err != nil || res.TransitSubnet == nil {
			t.Fatalf("CreateTransitSubnet(%s): %+v, %v", name, res, err)
		}
		id := res.TransitSubnet.Id
		t.Cleanup(func() {
			_, _ = c.DeleteTransitSubnet(&nat.DeleteTransitSubnetRequest{TransitSubnetId: id})
		})
		return id
	}
	tsnSameVPCID := makeTransitSubnet("pnat-tsn-same-vpc", sub1cID)
	tsn2ID := makeTransitSubnet("pnat-tsn-vpc2", sub2aID)
	_ = tsnSameVPCID

	// =================================================================
	// 1. Transit IPs (§3.7)
	// =================================================================
	// Non-transit subnet -> NAT.1101 (400).
	_, err = c.CreateTransitIp(&nat.CreateTransitIpRequest{Body: &nat.CreateTransitIpRequestBody{
		TransitIp: &nat.CreatTransitIpOption{VirsubnetId: sub2bID},
	}})
	wantError(t, err, 400, "NAT.1101")

	// Unknown subnet -> NAT.1002 (404).
	_, err = c.CreateTransitIp(&nat.CreateTransitIpRequest{Body: &nat.CreateTransitIpRequestBody{
		TransitIp: &nat.CreatTransitIpOption{VirsubnetId: unknownID},
	}})
	wantError(t, err, 404, "NAT.1002")

	// Invalid ip_address -> NAT.1405 (400).
	_, err = c.CreateTransitIp(&nat.CreateTransitIpRequest{Body: &nat.CreateTransitIpRequestBody{
		TransitIp: &nat.CreatTransitIpOption{VirsubnetId: sub2aID, IpAddress: ptr("10.83.99.5")},
	}})
	wantError(t, err, 400, "NAT.1405")

	// Invalid enterprise_project_id -> VPC.0011 (400).
	_, err = c.CreateTransitIp(&nat.CreateTransitIpRequest{Body: &nat.CreateTransitIpRequestBody{
		TransitIp: &nat.CreatTransitIpOption{VirsubnetId: sub2aID, EnterpriseProjectId: ptr("not-a-uuid")},
	}})
	wantError(t, err, 400, "VPC.0011")

	beforeSub2a, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: sub2aID})
	if err != nil {
		t.Fatalf("ShowSubnet(sub2a) before transit IPs: %v", err)
	}
	availSub2a := beforeSub2a.Subnet.AvailableIpAddressCount

	makeTransitIP := func(subnetID string, ip *string, tags *[]nat.PrivateTag) (id, addr string) {
		t.Helper()
		res, err := c.CreateTransitIp(&nat.CreateTransitIpRequest{Body: &nat.CreateTransitIpRequestBody{
			TransitIp: &nat.CreatTransitIpOption{
				VirsubnetId: subnetID,
				IpAddress:   ip,
				Tags:        tags,
			},
		}})
		if err != nil || res.TransitIp == nil {
			t.Fatalf("CreateTransitIp(%s): %+v, %v", subnetID, res, err)
		}
		tip := res.TransitIp
		t.Cleanup(func() {
			_, _ = c.DeleteTransitIp(&nat.DeleteTransitIpRequest{TransitIpId: tip.Id})
		})
		if tip.GatewayId != "" || tip.NetworkInterfaceId == "" ||
			tip.Status == nil || tip.Status.Value() != "ACTIVE" ||
			tip.EnterpriseProjectId != "0" {
			t.Errorf("created transit IP = %+v", tip)
		}
		return tip.Id, tip.IpAddress
	}

	tip1ID, tip1Addr := makeTransitIP(sub2aID, nil, &[]nat.PrivateTag{{Key: "role", Value: "snat"}})
	tip2ID, tip2Addr := makeTransitIP(sub2aID, ptr("10.83.1.200"), nil)
	tip3ID, tip3Addr := makeTransitIP(sub2aID, nil, nil)
	tipSameVPCID, _ := makeTransitIP(sub1cID, nil, nil)
	if tip2Addr != "10.83.1.200" {
		t.Errorf("explicit transit IP address = %q, want 10.83.1.200", tip2Addr)
	}

	// Duplicate ip_address in transit subnet -> NAT.1403 (409).
	_, err = c.CreateTransitIp(&nat.CreateTransitIpRequest{Body: &nat.CreateTransitIpRequestBody{
		TransitIp: &nat.CreatTransitIpOption{VirsubnetId: sub2aID, IpAddress: ptr("10.83.1.200")},
	}})
	wantError(t, err, 409, "NAT.1403")

	// ShowTransitIp & ListTransitIps (before gateway link).
	_, err = c.ShowTransitIp(&nat.ShowTransitIpRequest{TransitIpId: unknownID})
	wantError(t, err, 404, "NAT.1002")

	shownTip1, err := c.ShowTransitIp(&nat.ShowTransitIpRequest{TransitIpId: tip1ID})
	if err != nil || shownTip1.TransitIp == nil || shownTip1.TransitIp.Id != tip1ID {
		t.Fatalf("ShowTransitIp(1): %+v, %v", shownTip1, err)
	}

	listedTips, err := c.ListTransitIps(&nat.ListTransitIpsRequest{
		TransitSubnetId: &[]string{tsn2ID},
		VirsubnetId:     &[]string{sub2aID},
	})
	if err != nil || listedTips.TransitIps == nil || len(*listedTips.TransitIps) != 3 {
		t.Fatalf("ListTransitIps(transit_subnet_id) = %+v, %v; want 3", listedTips, err)
	}

	// =================================================================
	// 2. Private SNAT rules (§3.8)
	// =================================================================
	// Unknown gateway -> NAT.1002 (404).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    unknownID,
			VirsubnetId:  &sub1aID,
			TransitIpIds: []string{tip1ID},
		},
	}})
	wantError(t, err, 404, "NAT.1002")

	// Both virsubnet_id and cidr -> NAT.1501 (400).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			VirsubnetId:  &sub1aID,
			Cidr:         ptr("10.82.1.0/25"),
			TransitIpIds: []string{tip1ID},
		},
	}})
	wantError(t, err, 400, "NAT.1501")

	// Neither virsubnet_id nor cidr -> NAT.1501 (400).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			TransitIpIds: []string{tip1ID},
		},
	}})
	wantError(t, err, 400, "NAT.1501")

	// Non-canonical CIDR -> NAT.1502 (400).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			Cidr:         ptr("10.82.1.5/24"),
			TransitIpIds: []string{tip1ID},
		},
	}})
	wantError(t, err, 400, "NAT.1502")

	// virsubnet_id not in gateway's VPC -> NAT.1003 (404).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			VirsubnetId:  &sub2bID,
			TransitIpIds: []string{tip1ID},
		},
	}})
	wantError(t, err, 404, "NAT.1003")

	// Unknown transit_ip_id -> NAT.1002 (404).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			VirsubnetId:  &sub1aID,
			TransitIpIds: []string{unknownID},
		},
	}})
	wantError(t, err, 404, "NAT.1002")

	// Transit IP in gateway's own VPC -> NAT.1303 (409).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			VirsubnetId:  &sub1aID,
			TransitIpIds: []string{tipSameVPCID},
		},
	}})
	wantError(t, err, 409, "NAT.1303")

	// Create private SNAT rule 1 (virsubnet_id, tip1).
	psnat1Res, err := c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			VirsubnetId:  &sub1aID,
			Description:  ptr("private snat subnet 1a"),
			TransitIpIds: []string{tip1ID},
		},
	}})
	if err != nil || psnat1Res.SnatRule == nil || psnat1Res.SnatRule.Id == nil {
		t.Fatalf("CreatePrivateSnat(1): %+v, %v", psnat1Res, err)
	}
	psnat1 := psnat1Res.SnatRule
	psnat1ID := *psnat1.Id
	t.Cleanup(func() {
		_, _ = c.DeletePrivateSnat(&nat.DeletePrivateSnatRequest{SnatRuleId: psnat1ID})
	})
	if psnat1.Status == nil || psnat1.Status.Value() != "ACTIVE" ||
		psnat1.GatewayId == nil || *psnat1.GatewayId != gw1ID ||
		psnat1.VirsubnetId == nil || *psnat1.VirsubnetId != sub1aID ||
		psnat1.TransitIpAssociations == nil || len(*psnat1.TransitIpAssociations) != 1 ||
		*(*psnat1.TransitIpAssociations)[0].TransitIpId != tip1ID ||
		*(*psnat1.TransitIpAssociations)[0].TransitIpAddress != tip1Addr {
		t.Errorf("created private SNAT 1 = %+v", psnat1)
	}

	// tip1 is now linked to gw1ID, cannot be deleted (NAT.1409) or used by gw2 (NAT.1406).
	shownTip1After, err := c.ShowTransitIp(&nat.ShowTransitIpRequest{TransitIpId: tip1ID})
	if err != nil || shownTip1After.TransitIp.GatewayId != gw1ID {
		t.Fatalf("tip1 gateway_id after SNAT create = %+v, %v; want %s", shownTip1After, err, gw1ID)
	}
	byGW1, err := c.ListTransitIps(&nat.ListTransitIpsRequest{GatewayId: &[]string{gw1ID}})
	if err != nil || byGW1.TransitIps == nil || len(*byGW1.TransitIps) != 1 || (*byGW1.TransitIps)[0].Id != tip1ID {
		t.Fatalf("ListTransitIps(gateway_id=%s) = %+v, %v", gw1ID, byGW1, err)
	}

	_, err = c.DeleteTransitIp(&nat.DeleteTransitIpRequest{TransitIpId: tip1ID})
	wantError(t, err, 409, "NAT.1409")

	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw2ID,
			VirsubnetId:  &sub1bID,
			TransitIpIds: []string{tip1ID},
		},
	}})
	wantError(t, err, 409, "NAT.1406")

	// Duplicate subnet on gw1 -> NAT.1503 (409).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			VirsubnetId:  &sub1aID,
			TransitIpIds: []string{tip1ID},
		},
	}})
	wantError(t, err, 409, "NAT.1503")

	// Create private SNAT rule 2 (cidr, sharing tip1 on gw1).
	psnat2Res, err := c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			Cidr:         ptr("10.82.2.0/25"),
			Description:  ptr("private snat cidr"),
			TransitIpIds: []string{tip1ID},
		},
	}})
	if err != nil || psnat2Res.SnatRule == nil || psnat2Res.SnatRule.Id == nil {
		t.Fatalf("CreatePrivateSnat(2, cidr): %+v, %v", psnat2Res, err)
	}
	psnat2ID := *psnat2Res.SnatRule.Id
	t.Cleanup(func() {
		_, _ = c.DeletePrivateSnat(&nat.DeletePrivateSnatRequest{SnatRuleId: psnat2ID})
	})

	// Duplicate CIDR on gw1 -> NAT.1505 (409).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			Cidr:         ptr("10.82.2.0/25"),
			TransitIpIds: []string{tip1ID},
		},
	}})
	wantError(t, err, 409, "NAT.1505")

	// ShowPrivateSnat & ListPrivateSnats (filters + page_info).
	_, err = c.ShowPrivateSnat(&nat.ShowPrivateSnatRequest{SnatRuleId: unknownID})
	wantError(t, err, 404, "NAT.1002")

	shownPsnat1, err := c.ShowPrivateSnat(&nat.ShowPrivateSnatRequest{SnatRuleId: psnat1ID})
	if err != nil || shownPsnat1.SnatRule == nil || *shownPsnat1.SnatRule.Id != psnat1ID {
		t.Fatalf("ShowPrivateSnat(1): %+v, %v", shownPsnat1, err)
	}

	filteredPsnat, err := c.ListPrivateSnats(&nat.ListPrivateSnatsRequest{
		Id:                  &[]string{psnat1ID},
		GatewayId:           &[]string{gw1ID},
		VirsubnetId:         &[]string{sub1aID},
		Description:         &[]string{"private snat subnet 1a"},
		TransitIpId:         &[]string{tip1ID},
		TransitIpAddress:    &[]string{tip1Addr},
		EnterpriseProjectId: &[]string{"0"},
	})
	if err != nil || filteredPsnat.SnatRules == nil || len(*filteredPsnat.SnatRules) != 1 ||
		*(*filteredPsnat.SnatRules)[0].Id != psnat1ID {
		t.Fatalf("ListPrivateSnats(filters) = %+v, %v", filteredPsnat, err)
	}

	// Delete psnat2 so only psnat1 uses tip1, then UpdatePrivateSnat psnat1 to swap tip1 -> tip2
	// and verify tip1 unlinks while tip2 links.
	if _, err := c.DeletePrivateSnat(&nat.DeletePrivateSnatRequest{SnatRuleId: psnat2ID}); err != nil {
		t.Fatalf("DeletePrivateSnat(2): %v", err)
	}
	updPsnat1, err := c.UpdatePrivateSnat(&nat.UpdatePrivateSnatRequest{
		SnatRuleId: psnat1ID,
		Body: &nat.UpdatePrivateSnatOptionBody{SnatRule: &nat.UpdatePrivateSnatOption{
			TransitIpIds: &[]string{tip2ID},
			Description:  ptr("private snat swapped"),
		}},
	})
	if err != nil || updPsnat1.SnatRule == nil ||
		*updPsnat1.SnatRule.Description != "private snat swapped" ||
		len(*updPsnat1.SnatRule.TransitIpAssociations) != 1 ||
		*(*updPsnat1.SnatRule.TransitIpAssociations)[0].TransitIpId != tip2ID ||
		*(*updPsnat1.SnatRule.TransitIpAssociations)[0].TransitIpAddress != tip2Addr {
		t.Fatalf("UpdatePrivateSnat(1) = %+v, %v", updPsnat1, err)
	}

	tip1AfterSwap, err := c.ShowTransitIp(&nat.ShowTransitIpRequest{TransitIpId: tip1ID})
	if err != nil || tip1AfterSwap.TransitIp.GatewayId != "" {
		t.Errorf("tip1 gateway_id after swap = %+v, %v; want empty", tip1AfterSwap, err)
	}
	tip2AfterSwap, err := c.ShowTransitIp(&nat.ShowTransitIpRequest{TransitIpId: tip2ID})
	if err != nil || tip2AfterSwap.TransitIp.GatewayId != gw1ID {
		t.Errorf("tip2 gateway_id after swap = %+v, %v; want %s", tip2AfterSwap, err, gw1ID)
	}

	// Swap back to tip1 so tip2 is free for DNAT testing below.
	if _, err := c.UpdatePrivateSnat(&nat.UpdatePrivateSnatRequest{
		SnatRuleId: psnat1ID,
		Body:       &nat.UpdatePrivateSnatOptionBody{SnatRule: &nat.UpdatePrivateSnatOption{TransitIpIds: &[]string{tip1ID}}},
	}); err != nil {
		t.Fatalf("UpdatePrivateSnat(1 back to tip1): %v", err)
	}

	// =================================================================
	// 3. Private DNAT rules (§3.9)
	// =================================================================
	dnatTCP := nat.GetCreatePrivateDnatOptionProtocolEnum().TCP
	dnatUDP := nat.GetCreatePrivateDnatOptionProtocolEnum().UDP
	dnatANY := nat.GetCreatePrivateDnatOptionProtocolEnum().ANY

	// Both network_interface_id and private_ip_address -> NAT.1311 (400).
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip2ID,
			NetworkInterfaceId:  &port1ID,
			PrivateIpAddress:    ptr("10.82.1.50"),
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("8080"),
		},
	}})
	wantError(t, err, 400, "NAT.1311")

	// Neither network_interface_id nor private_ip_address -> NAT.1311 (400).
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip2ID,
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("8080"),
		},
	}})
	wantError(t, err, 400, "NAT.1311")

	// Unknown network_interface_id -> NAT.1009 (404).
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip2ID,
			NetworkInterfaceId:  ptr(unknownID),
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("8080"),
		},
	}})
	wantError(t, err, 404, "NAT.1009")

	// Port in another VPC -> NAT.1304 (409).
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip2ID,
			NetworkInterfaceId:  &port2OtherVPCID,
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("8080"),
		},
	}})
	wantError(t, err, 409, "NAT.1304")

	// Transit IP in gateway's own VPC -> NAT.1303 (409).
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tipSameVPCID,
			NetworkInterfaceId:  &port1ID,
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("8080"),
		},
	}})
	wantError(t, err, 409, "NAT.1303")

	// Transit IP used by an SNAT rule (tip1) -> NAT.1308 (409).
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip1ID,
			NetworkInterfaceId:  &port1ID,
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("8080"),
		},
	}})
	wantError(t, err, 409, "NAT.1308")

	// "any" with non-zero ports -> NAT.1306 (400).
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip2ID,
			NetworkInterfaceId:  &port1ID,
			Protocol:            &dnatANY,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("80"),
		},
	}})
	wantError(t, err, 400, "NAT.1306")

	// Create private DNAT rule 1 (ECS port -> type COMPUTE, TCP 8080 -> 80 on tip2).
	pdnat1Res, err := c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip2ID,
			NetworkInterfaceId:  &port1ID,
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("8080"),
			Description:         ptr("compute dnat"),
		},
	}})
	if err != nil || pdnat1Res.DnatRule == nil || pdnat1Res.DnatRule.Id == nil {
		t.Fatalf("CreatePrivateDnat(1, COMPUTE): %+v, %v", pdnat1Res, err)
	}
	pd1 := pdnat1Res.DnatRule
	pdnat1ID := *pd1.Id
	t.Cleanup(func() {
		_, _ = c.DeletePrivateDnat(&nat.DeletePrivateDnatRequest{DnatRuleId: pdnat1ID})
	})
	if pd1.Type == nil || *pd1.Type != "COMPUTE" ||
		pd1.PrivateIpAddress == nil || *pd1.PrivateIpAddress != port1IP ||
		pd1.NetworkInterfaceId == nil || *pd1.NetworkInterfaceId != port1ID ||
		pd1.Protocol == nil || pd1.Protocol.Value() != "tcp" ||
		pd1.InternalServicePort == nil || *pd1.InternalServicePort != "80" ||
		pd1.TransitServicePort == nil || *pd1.TransitServicePort != "8080" ||
		pd1.Status == nil || pd1.Status.Value() != "ACTIVE" {
		t.Errorf("created private DNAT 1 = %+v", pd1)
	}

	// tip2 is now used by DNAT -> SNAT with tip2 gives NAT.1305 (409), gw2 DNAT gives NAT.1406 (409).
	_, err = c.CreatePrivateSnat(&nat.CreatePrivateSnatRequest{Body: &nat.CreatePrivateSnatOptionBody{
		SnatRule: &nat.CreatePrivateSnatOption{
			GatewayId:    gw1ID,
			Cidr:         ptr("10.82.2.0/25"),
			TransitIpIds: []string{tip2ID},
		},
	}})
	wantError(t, err, 409, "NAT.1305")

	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw2ID,
			TransitIpId:         tip2ID,
			PrivateIpAddress:    ptr("10.250.0.10"),
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("8080"),
		},
	}})
	wantError(t, err, 409, "NAT.1406")

	// Create private DNAT rule 2 (private_ip_address -> type CUSTOMIZE, UDP 9090 -> 90 on tip2).
	pdnat2Res, err := c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip2ID,
			PrivateIpAddress:    ptr("10.250.0.10"),
			Protocol:            &dnatUDP,
			InternalServicePort: ptr("90"),
			TransitServicePort:  ptr("9090"),
			Description:         ptr("customize dnat"),
		},
	}})
	if err != nil || pdnat2Res.DnatRule == nil || pdnat2Res.DnatRule.Id == nil {
		t.Fatalf("CreatePrivateDnat(2, CUSTOMIZE): %+v, %v", pdnat2Res, err)
	}
	pdnat2ID := *pdnat2Res.DnatRule.Id
	t.Cleanup(func() {
		_, _ = c.DeletePrivateDnat(&nat.DeletePrivateDnatRequest{DnatRuleId: pdnat2ID})
	})
	if pdnat2Res.DnatRule.Type == nil || *pdnat2Res.DnatRule.Type != "CUSTOMIZE" {
		t.Errorf("created private DNAT 2 type = %v, want CUSTOMIZE", pdnat2Res.DnatRule.Type)
	}

	// --- Conflict cases (§3.9) ----------------------------------------
	// NAT.1310: same transit IP (tip2), transit port (8080), protocol (tcp).
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip2ID,
			PrivateIpAddress:    ptr("10.250.0.99"),
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("81"),
			TransitServicePort:  ptr("8080"),
		},
	}})
	wantError(t, err, 409, "NAT.1310")

	// NAT.1307: same backend (port1ID), internal port (80), protocol (tcp) on tip3.
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip3ID,
			NetworkInterfaceId:  &port1ID,
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("80"),
			TransitServicePort:  ptr("8081"),
		},
	}})
	wantError(t, err, 409, "NAT.1307")

	// NAT.1410: "any" rule on tip2 (which already has pdnat1/pdnat2).
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip2ID,
			PrivateIpAddress:    ptr("10.250.0.20"),
			Protocol:            &dnatANY,
			InternalServicePort: ptr("0"),
			TransitServicePort:  ptr("0"),
		},
	}})
	wantError(t, err, 409, "NAT.1410")

	// NAT.1309: "any" rule on port1ID (which already has pdnat1) using tip3.
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip3ID,
			NetworkInterfaceId:  &port1ID,
			Protocol:            &dnatANY,
			InternalServicePort: ptr("0"),
			TransitServicePort:  ptr("0"),
		},
	}})
	wantError(t, err, 409, "NAT.1309")

	// Create private DNAT rule 3 (any protocol on tip3 and 10.250.0.30).
	pdnat3Res, err := c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip3ID,
			PrivateIpAddress:    ptr("10.250.0.30"),
			Protocol:            &dnatANY,
			InternalServicePort: ptr("0"),
			TransitServicePort:  ptr("0"),
			Description:         ptr("any dnat"),
		},
	}})
	if err != nil || pdnat3Res.DnatRule == nil || pdnat3Res.DnatRule.Id == nil {
		t.Fatalf("CreatePrivateDnat(3, any): %+v, %v", pdnat3Res, err)
	}
	pdnat3ID := *pdnat3Res.DnatRule.Id
	t.Cleanup(func() {
		_, _ = c.DeletePrivateDnat(&nat.DeletePrivateDnatRequest{DnatRuleId: pdnat3ID})
	})

	// Reverse NAT.1410 and NAT.1309: adding tcp rule on tip3 or 10.250.0.30.
	_, err = c.CreatePrivateDnat(&nat.CreatePrivateDnatRequest{Body: &nat.CreatePrivateDnatOptionBody{
		DnatRule: &nat.CreatePrivateDnatOption{
			GatewayId:           gw1ID,
			TransitIpId:         tip3ID,
			PrivateIpAddress:    ptr("10.250.0.40"),
			Protocol:            &dnatTCP,
			InternalServicePort: ptr("443"),
			TransitServicePort:  ptr("443"),
		},
	}})
	wantError(t, err, 409, "NAT.1410")

	// ShowPrivateDnat & ListPrivateDnats (filters + pagination).
	_, err = c.ShowPrivateDnat(&nat.ShowPrivateDnatRequest{DnatRuleId: unknownID})
	wantError(t, err, 404, "NAT.1002")

	shownPd1, err := c.ShowPrivateDnat(&nat.ShowPrivateDnatRequest{DnatRuleId: pdnat1ID})
	if err != nil || shownPd1.DnatRule == nil || *shownPd1.DnatRule.Id != pdnat1ID {
		t.Fatalf("ShowPrivateDnat(1): %+v, %v", shownPd1, err)
	}

	filteredPd, err := c.ListPrivateDnats(&nat.ListPrivateDnatsRequest{
		Id:                  &[]string{pdnat1ID},
		GatewayId:           &[]string{gw1ID},
		TransitIpId:         &[]string{tip2ID},
		NetworkInterfaceId:  &[]string{port1ID},
		Type:                &[]string{"COMPUTE"},
		PrivateIpAddress:    &[]string{port1IP},
		Protocol:            &[]string{"tcp"},
		InternalServicePort: &[]string{"80"},
		TransitServicePort:  &[]string{"8080"},
		Description:         &[]string{"compute dnat"},
		EnterpriseProjectId: &[]string{"0"},
	})
	if err != nil || filteredPd.DnatRules == nil || len(*filteredPd.DnatRules) != 1 ||
		*(*filteredPd.DnatRules)[0].Id != pdnat1ID {
		t.Fatalf("ListPrivateDnats(filters) = %+v, %v", filteredPd, err)
	}

	seenPd := map[string]int{}
	var pdMarker *string
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("ListPrivateDnats paging did not terminate")
		}
		res, err := c.ListPrivateDnats(&nat.ListPrivateDnatsRequest{
			GatewayId: &[]string{gw1ID},
			Limit:     ptr(int32(1)),
			Marker:    pdMarker,
		})
		if err != nil {
			t.Fatalf("ListPrivateDnats(page %d): %v", pages, err)
		}
		if res.DnatRules == nil || len(*res.DnatRules) == 0 {
			break
		}
		for _, r := range *res.DnatRules {
			seenPd[*r.Id]++
		}
		if res.PageInfo == nil || res.PageInfo.NextMarker == nil || *res.PageInfo.NextMarker == "" {
			break
		}
		pdMarker = res.PageInfo.NextMarker
	}
	if seenPd[pdnat1ID] != 1 || seenPd[pdnat2ID] != 1 || seenPd[pdnat3ID] != 1 {
		t.Errorf("ListPrivateDnats paging seen = %v", seenPd)
	}

	// Delete pdnat3 to free tip3, then UpdatePrivateDnat pdnat1 to use tip3 + udp 8089 -> 8088.
	if _, err := c.DeletePrivateDnat(&nat.DeletePrivateDnatRequest{DnatRuleId: pdnat3ID}); err != nil {
		t.Fatalf("DeletePrivateDnat(3): %v", err)
	}
	updProtoUDP := nat.GetUpdatePrivateDnatOptionProtocolEnum().UDP
	updPd1, err := c.UpdatePrivateDnat(&nat.UpdatePrivateDnatRequest{
		DnatRuleId: pdnat1ID,
		Body: &nat.UpdatePrivateDnatRequestBody{DnatRule: &nat.UpdatePrivateDnatOption{
			Description:         ptr("compute dnat updated"),
			TransitIpId:         &tip3ID,
			Protocol:            &updProtoUDP,
			InternalServicePort: ptr("8088"),
			TransitServicePort:  ptr("8089"),
		}},
	})
	if err != nil || updPd1.DnatRule == nil ||
		*updPd1.DnatRule.Description != "compute dnat updated" ||
		*updPd1.DnatRule.TransitIpId != tip3ID ||
		updPd1.DnatRule.Protocol.Value() != "udp" ||
		*updPd1.DnatRule.InternalServicePort != "8088" ||
		*updPd1.DnatRule.TransitServicePort != "8089" {
		t.Fatalf("UpdatePrivateDnat(1) = %+v, %v", updPd1, err)
	}

	// Delete remaining rules and verify all transit IPs unlink and delete cleanly.
	for _, rid := range []string{pdnat1ID, pdnat2ID} {
		if _, err := c.DeletePrivateDnat(&nat.DeletePrivateDnatRequest{DnatRuleId: rid}); err != nil {
			t.Fatalf("DeletePrivateDnat(%s): %v", rid, err)
		}
	}
	if _, err := c.DeletePrivateSnat(&nat.DeletePrivateSnatRequest{SnatRuleId: psnat1ID}); err != nil {
		t.Fatalf("DeletePrivateSnat(1): %v", err)
	}

	_, err = c.ShowPrivateDnat(&nat.ShowPrivateDnatRequest{DnatRuleId: pdnat1ID})
	wantError(t, err, 404, "NAT.1002")
	_, err = c.ShowPrivateSnat(&nat.ShowPrivateSnatRequest{SnatRuleId: psnat1ID})
	wantError(t, err, 404, "NAT.1002")

	for _, tid := range []string{tip1ID, tip2ID, tip3ID} {
		s, err := c.ShowTransitIp(&nat.ShowTransitIpRequest{TransitIpId: tid})
		if err != nil || s.TransitIp.GatewayId != "" {
			t.Errorf("transit IP %s after rules deleted = %+v, %v; want gateway_id empty", tid, s, err)
		}
		if _, err := c.DeleteTransitIp(&nat.DeleteTransitIpRequest{TransitIpId: tid}); err != nil {
			t.Fatalf("DeleteTransitIp(%s): %v", tid, err)
		}
	}
	_, err = c.ShowTransitIp(&nat.ShowTransitIpRequest{TransitIpId: tip1ID})
	wantError(t, err, 404, "NAT.1002")

	afterSub2a, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: sub2aID})
	if err != nil {
		t.Fatalf("ShowSubnet(sub2a) after transit IP deletes: %v", err)
	}
	if afterSub2a.Subnet.AvailableIpAddressCount != availSub2a {
		t.Errorf("sub2a available IPs after transit IP deletes = %d, want %d", afterSub2a.Subnet.AvailableIpAddressCount, availSub2a)
	}
	_ = tip3Addr
}

// TestPrivateNatTags drives §3.10 through the official NAT v2 SDK across
// all 3 private NAT resource types (private-nat-gateways, transit-ips,
// transit-subnets) and all 6 tag operations per resource type, including
// filter/count and NAT.1002, NAT.1010, NAT.1015 error cases.
func TestPrivateNatTags(t *testing.T) {
	c := newNAT(t)
	net2 := newV2(t, realEndpoint)

	makeVPC := func(name, cidr string) string {
		t.Helper()
		vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
			Name: ptr(name), Cidr: ptr(cidr),
		}}})
		if err != nil {
			t.Fatalf("CreateVpc(%s): %v", name, err)
		}
		id := vc.Vpc.Id
		t.Cleanup(func() {
			eventually(t, name+" to be deletable", func() bool {
				_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: id})
				return err == nil
			})
		})
		eventually(t, name+" to become OK", func() bool {
			s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: id})
			return err == nil && s.Vpc.Status.Value() == "OK"
		})
		return id
	}
	makeSubnet := func(name, cidr, gw, vpcID string) string {
		t.Helper()
		sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
			Name: name, Cidr: cidr, GatewayIp: gw, VpcId: vpcID,
		}}})
		if err != nil {
			t.Fatalf("CreateSubnet(%s): %v", name, err)
		}
		id := sc.Subnet.Id
		t.Cleanup(func() {
			eventually(t, name+" to be deletable", func() bool {
				_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: id})
				return err == nil
			})
		})
		eventually(t, name+" to become ACTIVE", func() bool {
			s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: id})
			return err == nil && s.Subnet.Status.Value() == "ACTIVE"
		})
		return id
	}

	vpc1ID := makeVPC("pnat-tags-vpc-1", "10.84.0.0/16")
	sub1ID := makeSubnet("pnat-tags-sub-1", "10.84.1.0/24", "10.84.1.1", vpc1ID)
	vpc2ID := makeVPC("pnat-tags-vpc-2", "10.85.0.0/16")
	sub2aID := makeSubnet("pnat-tags-sub-2a", "10.85.1.0/24", "10.85.1.1", vpc2ID)
	sub2bID := makeSubnet("pnat-tags-sub-2b", "10.85.2.0/24", "10.85.2.1", vpc2ID)

	gwRes, err := c.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "sdk-tag-pnat-gw",
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: sub1ID}},
			Tags:         &[]nat.Tag{{Key: "init", Value: "one"}},
		},
	}})
	if err != nil || gwRes.Gateway == nil {
		t.Fatalf("CreatePrivateNat: %+v, %v", gwRes, err)
	}
	gwID := gwRes.Gateway.Id
	t.Cleanup(func() {
		_, _ = c.DeletePrivateNat(&nat.DeletePrivateNatRequest{GatewayId: gwID})
	})

	tsnRes, err := c.CreateTransitSubnet(&nat.CreateTransitSubnetRequest{Body: &nat.CreateTransitSubnetRequestBody{
		TransitSubnet: &nat.CreateTransitSubnetOption{
			Name:               "sdk-tag-tsn",
			VirsubnetId:        sub2aID,
			VirsubnetProjectId: projectID,
			Tags:               &[]nat.Tag{{Key: "init", Value: "tsn"}},
		},
	}})
	if err != nil || tsnRes.TransitSubnet == nil {
		t.Fatalf("CreateTransitSubnet: %+v, %v", tsnRes, err)
	}
	tsnID := tsnRes.TransitSubnet.Id
	t.Cleanup(func() {
		_, _ = c.DeleteTransitSubnet(&nat.DeleteTransitSubnetRequest{TransitSubnetId: tsnID})
	})

	// Second transit subnet without tags to test filter selectivity.
	tsn2Res, err := c.CreateTransitSubnet(&nat.CreateTransitSubnetRequest{Body: &nat.CreateTransitSubnetRequestBody{
		TransitSubnet: &nat.CreateTransitSubnetOption{
			Name:               "sdk-tag-tsn-other",
			VirsubnetId:        sub2bID,
			VirsubnetProjectId: projectID,
		},
	}})
	if err != nil || tsn2Res.TransitSubnet == nil {
		t.Fatalf("CreateTransitSubnet(2): %+v, %v", tsn2Res, err)
	}
	tsn2ID := tsn2Res.TransitSubnet.Id
	t.Cleanup(func() {
		_, _ = c.DeleteTransitSubnet(&nat.DeleteTransitSubnetRequest{TransitSubnetId: tsn2ID})
	})

	tipRes, err := c.CreateTransitIp(&nat.CreateTransitIpRequest{Body: &nat.CreateTransitIpRequestBody{
		TransitIp: &nat.CreatTransitIpOption{
			VirsubnetId: sub2aID,
			Tags:        &[]nat.PrivateTag{{Key: "init", Value: "tip"}},
		},
	}})
	if err != nil || tipRes.TransitIp == nil {
		t.Fatalf("CreateTransitIp: %+v, %v", tipRes, err)
	}
	tipID := tipRes.TransitIp.Id
	t.Cleanup(func() {
		_, _ = c.DeleteTransitIp(&nat.DeleteTransitIpRequest{TransitIpId: tipID})
	})

	batchCreate := nat.GetBatchOperateResourceTagsRequestBodyActionEnum().CREATE
	batchDelete := nat.GetBatchOperateResourceTagsRequestBodyActionEnum().DELETE
	var badBatchAction nat.BatchOperateResourceTagsRequestBodyAction
	_ = badBatchAction.UnmarshalJSON([]byte(`"bogus"`))
	actCount := nat.GetListTagResourceInstancesRequestBodyActionEnum().COUNT
	actFilter := nat.GetListTagResourceInstancesRequestBodyActionEnum().FILTER

	// --- 1. private-nat-gateways tags ---------------------------------
	gwTags, err := c.ShowPrivateNatTags(&nat.ShowPrivateNatTagsRequest{ResourceId: gwID})
	if err != nil || gwTags.Tags == nil || len(*gwTags.Tags) != 1 || (*gwTags.Tags)[0].Key != "init" {
		t.Fatalf("ShowPrivateNatTags(initial) = %+v, %v", gwTags, err)
	}
	_, err = c.ShowPrivateNatTags(&nat.ShowPrivateNatTagsRequest{ResourceId: unknownID})
	wantError(t, err, 404, "NAT.1002")

	_, err = c.CreatePrivateNatTag(&nat.CreatePrivateNatTagRequest{
		ResourceId: gwID,
		Body:       &nat.CreateResourceTagRequestBody{Tag: &nat.Tag{Key: "", Value: "v"}},
	})
	wantError(t, err, 400, "NAT.1015")

	if _, err := c.CreatePrivateNatTag(&nat.CreatePrivateNatTagRequest{
		ResourceId: gwID,
		Body:       &nat.CreateResourceTagRequestBody{Tag: &nat.Tag{Key: "env", Value: "prod"}},
	}); err != nil {
		t.Fatalf("CreatePrivateNatTag: %v", err)
	}
	_, err = c.BatchCreateDeletePrivateNatTags(&nat.BatchCreateDeletePrivateNatTagsRequest{
		ResourceId: gwID,
		Body:       &nat.BatchOperateResourceTagsRequestBody{Action: badBatchAction, Tags: []nat.Tag{{Key: "k", Value: "v"}}},
	})
	wantError(t, err, 400, "NAT.1010")

	if _, err := c.BatchCreateDeletePrivateNatTags(&nat.BatchCreateDeletePrivateNatTagsRequest{
		ResourceId: gwID,
		Body: &nat.BatchOperateResourceTagsRequestBody{
			Action: batchCreate,
			Tags:   []nat.Tag{{Key: "team", Value: "net"}, {Key: "tier", Value: "priv"}},
		},
	}); err != nil {
		t.Fatalf("BatchCreateDeletePrivateNatTags(create): %v", err)
	}
	allGwTags, err := c.ListPrivateNatTags(&nat.ListPrivateNatTagsRequest{})
	if err != nil || allGwTags.Tags == nil || len(*allGwTags.Tags) < 3 {
		t.Fatalf("ListPrivateNatTags = %+v, %v", allGwTags, err)
	}
	gwCount, err := c.ListPrivateNatsByTags(&nat.ListPrivateNatsByTagsRequest{
		Body: &nat.ListTagResourceInstancesRequestBody{
			Action: actCount,
			Tags:   &[]nat.Tags{{Key: "env", Values: []string{"prod"}}},
		},
	})
	if err != nil || gwCount.TotalCount == nil || *gwCount.TotalCount != 1 {
		t.Fatalf("ListPrivateNatsByTags(count) = %+v, %v", gwCount, err)
	}
	gwFilter, err := c.ListPrivateNatsByTags(&nat.ListPrivateNatsByTagsRequest{
		Body: &nat.ListTagResourceInstancesRequestBody{
			Action:  actFilter,
			Tags:    &[]nat.Tags{{Key: "team", Values: []string{"net"}}},
			Matches: &[]nat.Match{{Key: "resource_name", Value: "sdk-tag-pnat"}},
		},
	})
	if err != nil || gwFilter.Resources == nil || len(*gwFilter.Resources) != 1 ||
		(*gwFilter.Resources)[0].ResourceId != gwID || (*gwFilter.Resources)[0].ResourceName != "sdk-tag-pnat-gw" {
		t.Fatalf("ListPrivateNatsByTags(filter) = %+v, %v", gwFilter, err)
	}
	if _, err := c.DeletePrivateNatTag(&nat.DeletePrivateNatTagRequest{ResourceId: gwID, Key: "init"}); err != nil {
		t.Fatalf("DeletePrivateNatTag: %v", err)
	}
	_, err = c.DeletePrivateNatTag(&nat.DeletePrivateNatTagRequest{ResourceId: gwID, Key: "missing"})
	wantError(t, err, 400, "NAT.1010")
	if _, err := c.BatchCreateDeletePrivateNatTags(&nat.BatchCreateDeletePrivateNatTagsRequest{
		ResourceId: gwID,
		Body: &nat.BatchOperateResourceTagsRequestBody{
			Action: batchDelete,
			Tags:   []nat.Tag{{Key: "tier", Value: "priv"}, {Key: "missing", Value: "x"}},
		},
	}); err != nil {
		t.Fatalf("BatchCreateDeletePrivateNatTags(delete): %v", err)
	}

	// --- 2. transit-subnets tags --------------------------------------
	tsnTags, err := c.ShowTransitSubnetTags(&nat.ShowTransitSubnetTagsRequest{ResourceId: tsnID})
	if err != nil || tsnTags.Tags == nil || len(*tsnTags.Tags) != 1 || (*tsnTags.Tags)[0].Key != "init" {
		t.Fatalf("ShowTransitSubnetTags(initial) = %+v, %v", tsnTags, err)
	}
	_, err = c.CreateTransitSubnetTag(&nat.CreateTransitSubnetTagRequest{
		ResourceId: unknownID,
		Body:       &nat.CreateResourceTagRequestBody{Tag: &nat.Tag{Key: "k", Value: "v"}},
	})
	wantError(t, err, 404, "NAT.1002")
	_, err = c.CreateTransitSubnetTag(&nat.CreateTransitSubnetTagRequest{
		ResourceId: tsnID,
		Body:       &nat.CreateResourceTagRequestBody{Tag: &nat.Tag{Key: "", Value: "v"}},
	})
	wantError(t, err, 400, "NAT.1015")

	if _, err := c.CreateTransitSubnetTag(&nat.CreateTransitSubnetTagRequest{
		ResourceId: tsnID,
		Body:       &nat.CreateResourceTagRequestBody{Tag: &nat.Tag{Key: "env", Value: "prod"}},
	}); err != nil {
		t.Fatalf("CreateTransitSubnetTag: %v", err)
	}
	if _, err := c.BatchCreateDeleteTransitSubnetTags(&nat.BatchCreateDeleteTransitSubnetTagsRequest{
		ResourceId: tsnID,
		Body: &nat.BatchOperateResourceTagsRequestBody{
			Action: batchCreate,
			Tags:   []nat.Tag{{Key: "team", Value: "net"}},
		},
	}); err != nil {
		t.Fatalf("BatchCreateDeleteTransitSubnetTags(create): %v", err)
	}
	allTsnTags, err := c.ListTransitSubnetTags(&nat.ListTransitSubnetTagsRequest{})
	if err != nil || allTsnTags.Tags == nil || len(*allTsnTags.Tags) < 3 {
		t.Fatalf("ListTransitSubnetTags = %+v, %v", allTsnTags, err)
	}
	tsnCount, err := c.ListTransitSubnetsByTags(&nat.ListTransitSubnetsByTagsRequest{
		Body: &nat.ListTagResourceInstancesRequestBody{
			Action: actCount,
			Tags:   &[]nat.Tags{{Key: "env", Values: []string{"prod"}}},
		},
	})
	if err != nil || tsnCount.TotalCount == nil || *tsnCount.TotalCount != 1 {
		t.Fatalf("ListTransitSubnetsByTags(count) = %+v, %v", tsnCount, err)
	}
	tsnFilter, err := c.ListTransitSubnetsByTags(&nat.ListTransitSubnetsByTagsRequest{
		Body: &nat.ListTagResourceInstancesRequestBody{
			Action:  actFilter,
			Tags:    &[]nat.Tags{{Key: "team", Values: []string{"net"}}},
			Matches: &[]nat.Match{{Key: "resource_name", Value: "sdk-tag-tsn"}},
		},
	})
	if err != nil || tsnFilter.Resources == nil || len(*tsnFilter.Resources) != 1 ||
		(*tsnFilter.Resources)[0].ResourceId != tsnID {
		t.Fatalf("ListTransitSubnetsByTags(filter) = %+v, %v", tsnFilter, err)
	}
	if _, err := c.DeleteTransitSubnetTag(&nat.DeleteTransitSubnetTagRequest{ResourceId: tsnID, Key: "init"}); err != nil {
		t.Fatalf("DeleteTransitSubnetTag: %v", err)
	}
	_, err = c.DeleteTransitSubnetTag(&nat.DeleteTransitSubnetTagRequest{ResourceId: tsnID, Key: "missing"})
	wantError(t, err, 400, "NAT.1010")
	if _, err := c.BatchCreateDeleteTransitSubnetTags(&nat.BatchCreateDeleteTransitSubnetTagsRequest{
		ResourceId: tsnID,
		Body: &nat.BatchOperateResourceTagsRequestBody{
			Action: batchDelete,
			Tags:   []nat.Tag{{Key: "team", Value: "net"}},
		},
	}); err != nil {
		t.Fatalf("BatchCreateDeleteTransitSubnetTags(delete): %v", err)
	}

	// --- 3. transit-ips tags ------------------------------------------
	tipTags, err := c.ShowTransitIpTags(&nat.ShowTransitIpTagsRequest{ResourceId: tipID})
	if err != nil || tipTags.Tags == nil || len(*tipTags.Tags) != 1 || (*tipTags.Tags)[0].Key != "init" {
		t.Fatalf("ShowTransitIpTags(initial) = %+v, %v", tipTags, err)
	}
	_, err = c.CreateTransitIpTag(&nat.CreateTransitIpTagRequest{
		ResourceId: unknownID,
		Body:       &nat.CreateResourceTagRequestBody{Tag: &nat.Tag{Key: "k", Value: "v"}},
	})
	wantError(t, err, 404, "NAT.1002")
	_, err = c.CreateTransitIpTag(&nat.CreateTransitIpTagRequest{
		ResourceId: tipID,
		Body:       &nat.CreateResourceTagRequestBody{Tag: &nat.Tag{Key: "", Value: "v"}},
	})
	wantError(t, err, 400, "NAT.1015")

	if _, err := c.CreateTransitIpTag(&nat.CreateTransitIpTagRequest{
		ResourceId: tipID,
		Body:       &nat.CreateResourceTagRequestBody{Tag: &nat.Tag{Key: "env", Value: "prod"}},
	}); err != nil {
		t.Fatalf("CreateTransitIpTag: %v", err)
	}
	if _, err := c.BatchCreateDeleteTransitIpTags(&nat.BatchCreateDeleteTransitIpTagsRequest{
		ResourceId: tipID,
		Body: &nat.BatchOperateResourceTagsRequestBody{
			Action: batchCreate,
			Tags:   []nat.Tag{{Key: "role", Value: "dnat"}},
		},
	}); err != nil {
		t.Fatalf("BatchCreateDeleteTransitIpTags(create): %v", err)
	}
	allTipTags, err := c.ListTransitIpTags(&nat.ListTransitIpTagsRequest{})
	if err != nil || allTipTags.Tags == nil || len(*allTipTags.Tags) < 3 {
		t.Fatalf("ListTransitIpTags = %+v, %v", allTipTags, err)
	}
	tipCount, err := c.ListTransitIpsByTags(&nat.ListTransitIpsByTagsRequest{
		Body: &nat.ListTagResourceInstancesRequestBody{
			Action: actCount,
			Tags:   &[]nat.Tags{{Key: "env", Values: []string{"prod"}}},
		},
	})
	if err != nil || tipCount.TotalCount == nil || *tipCount.TotalCount != 1 {
		t.Fatalf("ListTransitIpsByTags(count) = %+v, %v", tipCount, err)
	}
	tipFilter, err := c.ListTransitIpsByTags(&nat.ListTransitIpsByTagsRequest{
		Body: &nat.ListTagResourceInstancesRequestBody{
			Action: actFilter,
			Tags:   &[]nat.Tags{{Key: "role", Values: []string{"dnat"}}},
		},
	})
	if err != nil || tipFilter.Resources == nil || len(*tipFilter.Resources) != 1 ||
		(*tipFilter.Resources)[0].ResourceId != tipID {
		t.Fatalf("ListTransitIpsByTags(filter) = %+v, %v", tipFilter, err)
	}
	if _, err := c.DeleteTransitIpTag(&nat.DeleteTransitIpTagRequest{ResourceId: tipID, Key: "init"}); err != nil {
		t.Fatalf("DeleteTransitIpTag: %v", err)
	}
	_, err = c.DeleteTransitIpTag(&nat.DeleteTransitIpTagRequest{ResourceId: tipID, Key: "missing"})
	wantError(t, err, 400, "NAT.1010")
	if _, err := c.BatchCreateDeleteTransitIpTags(&nat.BatchCreateDeleteTransitIpTagsRequest{
		ResourceId: tipID,
		Body: &nat.BatchOperateResourceTagsRequestBody{
			Action: batchDelete,
			Tags:   []nat.Tag{{Key: "role", Value: "dnat"}},
		},
	}); err != nil {
		t.Fatalf("BatchCreateDeleteTransitIpTags(delete): %v", err)
	}
}

// TestPrivateNATPermissions runs only with WEISTACK_SDK_IAM=enforce (§7):
// an unprivileged user can call public ListSpecs, a user with only
// nat:privateNatGateways:list can list private gateways, and is refused
// CreatePrivateNat with 403 VPC.2201.
func TestPrivateNATPermissions(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()
	admin, admin5 := iamClientsAs(t, adminAK, adminSK)

	u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-pnat-limited", Enabled: true}})
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
			DisplayName: "sdk-pnat-list-only",
			Type:        "AX",
			Description: "nat:privateNatGateways:list only",
			Policy: &iam.ServicePolicy{
				Version: "1.1",
				Statement: []iam.ServiceStatement{{
					Action: []string{"nat:privateNatGateways:list"},
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
		Group: &iam.KeystoneCreateGroupOption{Name: "sdk-pnat-readers"},
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

	userNAT := natAs(t, ak, sk)
	if _, err := userNAT.ListSpecs(&nat.ListSpecsRequest{}); err != nil {
		t.Fatalf("ListSpecs (public) with limited user: %v", err)
	}
	if _, err := userNAT.ListPrivateNats(&nat.ListPrivateNatsRequest{}); err != nil {
		t.Fatalf("ListPrivateNats with nat:privateNatGateways:list: %v", err)
	}

	_, err = userNAT.CreatePrivateNat(&nat.CreatePrivateNatRequest{Body: &nat.CreatePrivateNatRequestBody{
		Gateway: &nat.CreatePrivateNatOption{
			Name:         "denied-pnat-gw",
			DownlinkVpcs: []nat.DownlinkVpcOption{{VirsubnetId: unknownID}},
		},
	}})
	denialOf(t, err, "VPC.2201")
}
