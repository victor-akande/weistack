package sdk

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	vpcv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	vpcv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3"
	v3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3/model"
)

// realEndpoint is Huawei Cloud's actual VPC endpoint for the region. The
// SDK is pointed at it unchanged; only the TCP connection is redirected
// to the emulator, so URL building, the Host header and request signing
// are exactly what the real service would receive.
const realEndpoint = "http://vpc." + region + ".myhuaweicloud.com"

func httpConfig() *config.HttpConfig { return httpConfigAt(emulatorAddr) }

// httpConfigAt dials addr for every connection.
func httpConfigAt(addr string) *config.HttpConfig {
	return config.DefaultHttpConfig().
		WithTimeout(10 * time.Second).
		WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		})
}

func credentials(t *testing.T) *basic.Credentials {
	t.Helper()
	cred, err := basic.NewCredentialsBuilder().
		WithAk(signingAK("AKWEISTACKEXAMPLE")).
		WithSk(signingSK()).
		WithProjectId(projectID).
		SafeBuild()
	if err != nil {
		t.Fatalf("building credentials: %v", err)
	}
	return cred
}

func newV2(t *testing.T, endpoint string) *vpcv2.VpcClient {
	t.Helper()
	return newV2At(t, emulatorAddr, endpoint)
}

func newV2At(t *testing.T, addr, endpoint string) *vpcv2.VpcClient {
	t.Helper()
	hc, err := vpcv2.VpcClientBuilder().
		WithEndpoints([]string{endpoint}).
		WithCredential(credentials(t)).
		WithHttpConfig(httpConfigAt(addr)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building v2 client: %v", err)
	}
	return vpcv2.NewVpcClient(hc)
}

func newV3(t *testing.T) *vpcv3.VpcClient {
	t.Helper()
	return newV3At(t, emulatorAddr)
}

func newV3At(t *testing.T, addr string) *vpcv3.VpcClient {
	t.Helper()
	hc, err := vpcv3.VpcClientBuilder().
		WithEndpoints([]string{realEndpoint}).
		WithCredential(credentials(t)).
		WithHttpConfig(httpConfigAt(addr)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building v3 client: %v", err)
	}
	return vpcv3.NewVpcClient(hc)
}

func ptr[T any](v T) *T { return &v }

// wantError asserts that err is a service error with the given HTTP
// status and Huawei error code, as decoded by the SDK itself.
func wantError(t *testing.T, err error, status int, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("call succeeded, want %d %s", status, code)
	}
	var byValue sdkerr.ServiceResponseError
	var byPtr *sdkerr.ServiceResponseError
	switch {
	case errors.As(err, &byPtr):
		byValue = *byPtr
	case errors.As(err, &byValue):
	default:
		t.Fatalf("error is %T (%v), want a ServiceResponseError", err, err)
	}
	if byValue.StatusCode != status || byValue.ErrorCode != code {
		t.Fatalf("got %d %s (%s), want %d %s", byValue.StatusCode, byValue.ErrorCode, byValue.ErrorMessage, status, code)
	}
	if byValue.ErrorMessage == "" {
		t.Errorf("the SDK decoded no error message from %d %s", status, code)
	}
	if byValue.RequestId == "" {
		t.Errorf("the SDK found no request ID on %d %s", status, code)
	}
}

// eventually polls until ok returns true, as a real client waits for an
// asynchronous resource.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

const unknownID = "00000000-0000-4000-8000-000000000000"

// TestNetworkLifecycle is the network half of the plan's end-to-end
// scenario 1, plus the dependency errors of scenario 5: VPC -> subnet ->
// security group and rules, then everything deleted in reverse order.
func TestNetworkLifecycle(t *testing.T) {
	c2 := newV2(t, realEndpoint)
	c3 := newV3(t)

	// --- VPC ---------------------------------------------------------
	created, err := c2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name:        ptr("sdk-vpc"),
		Description: ptr("created by the SDK suite"),
		Cidr:        ptr("192.168.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpc := created.Vpc
	if vpc == nil || vpc.Id == "" {
		t.Fatalf("CreateVpc returned no VPC: %+v", created)
	}
	if got := vpc.Status.Value(); got != "CREATING" {
		t.Errorf("new VPC status = %q, want CREATING", got)
	}
	if vpc.Name != "sdk-vpc" || vpc.Cidr != "192.168.0.0/16" || vpc.TenantId != projectID || vpc.EnterpriseProjectId != "0" {
		t.Errorf("created VPC = %+v", vpc)
	}
	if vpc.CreatedAt == nil || time.Since(time.Time(*vpc.CreatedAt)) > time.Hour {
		t.Errorf("created_at was not decoded as a recent time: %v", vpc.CreatedAt)
	}

	// Deleting while it is still being created is refused.
	_, err = c2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpc.Id})
	wantError(t, err, 409, "VPC.0103")

	eventually(t, "the VPC to become OK", func() bool {
		shown, err := c2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpc.Id})
		if err != nil {
			t.Fatalf("ShowVpc: %v", err)
		}
		return shown.Vpc.Status.Value() == "OK"
	})

	_, err = c2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{Name: ptr("sdk-vpc")}}})
	wantError(t, err, 400, "VPC.0115")
	_, err = c2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{Cidr: ptr("300.0.0.0/8")}}})
	wantError(t, err, 400, "VPC.0101")
	_, err = c2.ShowVpc(&v2.ShowVpcRequest{VpcId: unknownID})
	wantError(t, err, 404, "VPC.0105")

	updated, err := c2.UpdateVpc(&v2.UpdateVpcRequest{VpcId: vpc.Id, Body: &v2.UpdateVpcRequestBody{Vpc: &v2.UpdateVpcOption{
		Description: ptr("updated"),
	}}})
	if err != nil || updated.Vpc.Description != "updated" || updated.Vpc.Name != "sdk-vpc" {
		t.Fatalf("UpdateVpc = %+v, %v", updated, err)
	}

	listed, err := c2.ListVpcs(&v2.ListVpcsRequest{Id: &vpc.Id})
	if err != nil || listed.Vpcs == nil || len(*listed.Vpcs) != 1 || (*listed.Vpcs)[0].Id != vpc.Id {
		t.Fatalf("ListVpcs(id) = %+v, %v", listed, err)
	}

	// --- Subnet ------------------------------------------------------
	subnetReq := func(name, cidr, gateway, vpcID string) *v2.CreateSubnetRequest {
		return &v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
			Name: name, Cidr: cidr, GatewayIp: gateway, VpcId: vpcID,
			PrimaryDns: ptr("100.125.1.250"), SecondaryDns: ptr("100.125.3.250"),
		}}}
	}
	sc, err := c2.CreateSubnet(subnetReq("sdk-subnet", "192.168.1.0/24", "192.168.1.1", vpc.Id))
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnet := sc.Subnet
	if got := subnet.Status.Value(); got != "UNKNOWN" {
		t.Errorf("new subnet status = %q, want UNKNOWN", got)
	}
	if subnet.VpcId != vpc.Id || subnet.NeutronNetworkId != subnet.Id || subnet.NeutronSubnetId == "" ||
		!subnet.DhcpEnable || subnet.AvailableIpAddressCount != 251 || len(subnet.DnsList) != 2 {
		t.Errorf("created subnet = %+v", subnet)
	}

	eventually(t, "the subnet to become ACTIVE", func() bool {
		shown, err := c2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnet.Id})
		if err != nil {
			t.Fatalf("ShowSubnet: %v", err)
		}
		return shown.Subnet.Status.Value() == "ACTIVE"
	})

	_, err = c2.CreateSubnet(subnetReq("outside", "10.0.0.0/24", "10.0.0.1", vpc.Id))
	wantError(t, err, 400, "VPC.0203")
	_, err = c2.CreateSubnet(subnetReq("overlap", "192.168.1.128/25", "192.168.1.129", vpc.Id))
	wantError(t, err, 400, "VPC.0204")
	_, err = c2.CreateSubnet(subnetReq("orphan", "192.168.2.0/24", "192.168.2.1", unknownID))
	wantError(t, err, 404, "VPC.0003")
	_, err = c2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: unknownID})
	wantError(t, err, 404, "VPC.0202")

	us, err := c2.UpdateSubnet(&v2.UpdateSubnetRequest{VpcId: vpc.Id, SubnetId: subnet.Id,
		Body: &v2.UpdateSubnetRequestBody{Subnet: &v2.UpdateSubnetOption{Name: "sdk-subnet-renamed"}}})
	if err != nil || us.Subnet == nil || us.Subnet.Id != subnet.Id || us.Subnet.Status.Value() != "ACTIVE" {
		t.Fatalf("UpdateSubnet = %+v, %v", us, err)
	}
	ls, err := c2.ListSubnets(&v2.ListSubnetsRequest{VpcId: &vpc.Id})
	if err != nil || ls.Subnets == nil || len(*ls.Subnets) != 1 || (*ls.Subnets)[0].Name != "sdk-subnet-renamed" {
		t.Fatalf("ListSubnets(vpc_id) = %+v, %v", ls, err)
	}

	// Scenario 5: a VPC with subnets cannot be deleted.
	_, err = c2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpc.Id})
	wantError(t, err, 409, "VPC.0104")

	// --- Security group and rules (v3) -------------------------------
	gc, err := c3.CreateSecurityGroup(&v3.CreateSecurityGroupRequest{Body: &v3.CreateSecurityGroupRequestBody{
		SecurityGroup: &v3.CreateSecurityGroupOption{Name: "sdk-sg", Description: ptr("web servers")},
	}})
	if err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}
	if gc.HttpStatusCode != 201 {
		t.Errorf("CreateSecurityGroup status = %d, want 201", gc.HttpStatusCode)
	}
	group := gc.SecurityGroup
	if group == nil || group.Name != "sdk-sg" || group.ProjectId != projectID || len(group.SecurityGroupRules) != 4 {
		t.Fatalf("created group = %+v", group)
	}
	if gc.RequestId == nil || *gc.RequestId == "" {
		t.Error("CreateSecurityGroup returned no request_id")
	}

	dry, err := c3.CreateSecurityGroup(&v3.CreateSecurityGroupRequest{Body: &v3.CreateSecurityGroupRequestBody{
		DryRun: ptr(true), SecurityGroup: &v3.CreateSecurityGroupOption{Name: "ghost"},
	}})
	if err != nil || dry.HttpStatusCode != 202 || dry.SecurityGroup != nil {
		t.Fatalf("dry run = %+v, %v; want 202 and no group", dry, err)
	}

	ruleReq := &v3.CreateSecurityGroupRuleRequest{Body: &v3.CreateSecurityGroupRuleRequestBody{
		SecurityGroupRule: &v3.CreateSecurityGroupRuleOption{
			SecurityGroupId: group.Id, Direction: "ingress", Protocol: ptr("tcp"),
			Multiport: ptr("22,443"), RemoteIpPrefix: ptr("10.0.0.0/8"), Description: ptr("ssh and https"),
		},
	}}
	rc, err := c3.CreateSecurityGroupRule(ruleReq)
	if err != nil {
		t.Fatalf("CreateSecurityGroupRule: %v", err)
	}
	rule := rc.SecurityGroupRule
	if rule == nil || rule.SecurityGroupId != group.Id || rule.Protocol != "tcp" || rule.Multiport != "22,443" ||
		rule.RemoteIpPrefix != "10.0.0.0/8" || rule.Ethertype != "IPv4" || rule.Action != "allow" || rule.Priority != 1 || !rule.Enabled {
		t.Fatalf("created rule = %+v", rule)
	}

	_, err = c3.CreateSecurityGroupRule(ruleReq)
	wantError(t, err, 409, "VPC.9902")
	_, err = c3.CreateSecurityGroupRule(&v3.CreateSecurityGroupRuleRequest{Body: &v3.CreateSecurityGroupRuleRequestBody{
		SecurityGroupRule: &v3.CreateSecurityGroupRuleOption{SecurityGroupId: group.Id, Direction: "ingress", Ethertype: ptr("IPX")},
	}})
	wantError(t, err, 400, "VPC.9902")
	_, err = c3.ShowSecurityGroup(&v3.ShowSecurityGroupRequest{SecurityGroupId: unknownID})
	wantError(t, err, 404, "VPC.9904")

	shownRule, err := c3.ShowSecurityGroupRule(&v3.ShowSecurityGroupRuleRequest{SecurityGroupRuleId: rule.Id})
	if err != nil || shownRule.SecurityGroupRule.Id != rule.Id {
		t.Fatalf("ShowSecurityGroupRule = %+v, %v", shownRule, err)
	}
	lr, err := c3.ListSecurityGroupRules(&v3.ListSecurityGroupRulesRequest{
		SecurityGroupId: &[]string{group.Id}, Protocol: &[]string{"tcp"},
	})
	if err != nil || lr.SecurityGroupRules == nil || len(*lr.SecurityGroupRules) != 1 || lr.PageInfo == nil || lr.PageInfo.CurrentCount != 1 {
		t.Fatalf("ListSecurityGroupRules = %+v, %v", lr, err)
	}

	shownGroup, err := c3.ShowSecurityGroup(&v3.ShowSecurityGroupRequest{SecurityGroupId: group.Id})
	if err != nil || len(shownGroup.SecurityGroup.SecurityGroupRules) != 5 {
		t.Fatalf("ShowSecurityGroup = %+v, %v; want 5 rules", shownGroup, err)
	}
	ug, err := c3.UpdateSecurityGroup(&v3.UpdateSecurityGroupRequest{SecurityGroupId: group.Id,
		Body: &v3.UpdateSecurityGroupRequestBody{SecurityGroup: &v3.UpdateSecurityGroupOption{Name: ptr("sdk-sg-renamed")}}})
	if err != nil || ug.SecurityGroup.Name != "sdk-sg-renamed" {
		t.Fatalf("UpdateSecurityGroup = %+v, %v", ug, err)
	}
	lg, err := c3.ListSecurityGroups(&v3.ListSecurityGroupsRequest{Name: &[]string{"sdk-sg-renamed", "default"}})
	if err != nil || lg.SecurityGroups == nil || len(*lg.SecurityGroups) != 2 {
		t.Fatalf("ListSecurityGroups = %+v, %v; want the default group and ours", lg, err)
	}

	// --- Teardown in reverse order -----------------------------------
	if _, err := c3.DeleteSecurityGroupRule(&v3.DeleteSecurityGroupRuleRequest{SecurityGroupRuleId: rule.Id}); err != nil {
		t.Fatalf("DeleteSecurityGroupRule: %v", err)
	}
	if _, err := c3.DeleteSecurityGroup(&v3.DeleteSecurityGroupRequest{SecurityGroupId: group.Id}); err != nil {
		t.Fatalf("DeleteSecurityGroup: %v", err)
	}
	if _, err := c2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpc.Id, SubnetId: subnet.Id}); err != nil {
		t.Fatalf("DeleteSubnet: %v", err)
	}
	if _, err := c2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpc.Id}); err != nil {
		t.Fatalf("DeleteVpc: %v", err)
	}
	_, err = c2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpc.Id})
	wantError(t, err, 404, "VPC.0105")
}

// TestLocalhostEndpoint uses the endpoint a learner configures with no
// setup at all: http://{service}.localhost:{port}. Nothing is redirected
// here; the name is resolved by the operating system.
//
// (The /{service} path prefix is not an option for this SDK: it discards
// any path in the configured endpoint.)
func TestLocalhostEndpoint(t *testing.T) {
	const host = "vpc.localhost"
	addrs, err := net.LookupHost(host)
	if err != nil {
		t.Skipf("%s does not resolve on this machine: %v", host, err)
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip == nil || !ip.IsLoopback() {
			t.Skipf("%s resolves to %s, which is not a loopback address", host, a)
		}
	}
	emulatorHost, port, err := net.SplitHostPort(emulatorAddr)
	if err != nil {
		t.Fatal(err)
	}
	if ip := net.ParseIP(emulatorHost); ip == nil || !ip.IsLoopback() {
		t.Skipf("the emulator under test is at %s, not on this machine's loopback", emulatorHost)
	}

	hc, err := vpcv2.VpcClientBuilder().
		WithEndpoints([]string{"http://" + net.JoinHostPort(host, port)}).
		WithCredential(credentials(t)).
		WithHttpConfig(config.DefaultHttpConfig().WithTimeout(10 * time.Second)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building client: %v", err)
	}
	c := vpcv2.NewVpcClient(hc)

	created, err := c.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{Name: ptr("via-localhost")}}})
	if err != nil {
		t.Fatalf("CreateVpc through %s: %v", host, err)
	}
	id := created.Vpc.Id
	eventually(t, "the VPC to become OK", func() bool {
		shown, err := c.ShowVpc(&v2.ShowVpcRequest{VpcId: id})
		return err == nil && shown.Vpc.Status.Value() == "OK"
	})
	if _, err := c.DeleteVpc(&v2.DeleteVpcRequest{VpcId: id}); err != nil {
		t.Fatalf("DeleteVpc: %v", err)
	}
}

// TestPaging walks a list with marker and limit the way the SDK's users
// do, and must see every item exactly once.
func TestPaging(t *testing.T) {
	c := newV2(t, realEndpoint)

	want := map[string]bool{}
	for _, name := range []string{"page-a", "page-b", "page-c", "page-d", "page-e"} {
		created, err := c.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{Name: ptr(name)}}})
		if err != nil {
			t.Fatalf("CreateVpc(%s): %v", name, err)
		}
		want[created.Vpc.Id] = true
	}

	seen := map[string]int{}
	var marker *string
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("paging did not terminate")
		}
		res, err := c.ListVpcs(&v2.ListVpcsRequest{Limit: ptr(int32(2)), Marker: marker})
		if err != nil {
			t.Fatalf("ListVpcs: %v", err)
		}
		if res.Vpcs == nil || len(*res.Vpcs) == 0 {
			break
		}
		for _, v := range *res.Vpcs {
			seen[v.Id]++
		}
		last := (*res.Vpcs)[len(*res.Vpcs)-1].Id
		marker = &last
	}
	for id := range want {
		if seen[id] != 1 {
			t.Errorf("VPC %s seen %d times while paging, want 1", id, seen[id])
		}
	}

	for id := range want {
		eventually(t, "VPC "+id+" to be deletable", func() bool {
			_, err := c.DeleteVpc(&v2.DeleteVpcRequest{VpcId: id})
			return err == nil
		})
	}
}
