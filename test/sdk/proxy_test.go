package sdk

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	vpcv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

// TestHTTPSProxy uses the emulator the way a user does without changing
// any endpoint: the SDK keeps Huawei Cloud's real HTTPS endpoint and
// sends its traffic through WeiStack as a proxy. Verification is
// skipped, as the SDK's own option allows; trusting `weistack ca` is the
// alternative.
func TestHTTPSProxy(t *testing.T) {
	t.Parallel()
	host, port, err := net.SplitHostPort(emulatorAddr)
	if err != nil {
		t.Fatal(err)
	}
	portNum, _ := strconv.Atoi(port)
	hc := config.DefaultHttpConfig().
		WithTimeout(10 * time.Second).
		WithIgnoreSSLVerification(true).
		WithProxy(config.NewProxy().WithSchema("http").WithHost(host).WithPort(portNum))

	built, err := vpcv2.VpcClientBuilder().
		WithEndpoints([]string{"https://vpc." + region + ".myhuaweicloud.com"}).
		WithCredential(credentials(t)).
		WithHttpConfig(hc).
		SafeBuild()
	if err != nil {
		t.Fatalf("building client: %v", err)
	}
	c := vpcv2.NewVpcClient(built)

	created, err := c.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("sdk-proxy-vpc"), Cidr: ptr("10.42.0.0/16"),
	}}})
	if err != nil || created.Vpc == nil {
		t.Fatalf("CreateVpc through the proxy = %+v, %v", created, err)
	}
	eventually(t, "the VPC to become active", func() bool {
		shown, err := c.ShowVpc(&v2.ShowVpcRequest{VpcId: created.Vpc.Id})
		if err != nil || shown.Vpc == nil || shown.Vpc.Name != "sdk-proxy-vpc" {
			t.Fatalf("ShowVpc through the proxy = %+v, %v", shown, err)
		}
		return shown.Vpc.Status.Value() == "OK"
	})
	if _, err := c.DeleteVpc(&v2.DeleteVpcRequest{VpcId: created.Vpc.Id}); err != nil {
		t.Fatalf("DeleteVpc through the proxy: %v", err)
	}
}
