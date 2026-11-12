package sdk

import (
	"testing"

	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	v3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3/model"
)

// TestListVpcsV3 is the call KooCLI makes for "hcloud VPC ListVpcs".
func TestListVpcsV3(t *testing.T) {
	t.Parallel()
	net2, net3 := newV2(t, realEndpoint), newV3(t)
	created, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("sdk-v3-list"), Cidr: ptr("10.80.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	id := created.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "the VPC to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: id})
			return err == nil
		})
	})

	eventually(t, "the VPC to be listed as ACTIVE", func() bool {
		res, err := net3.ListVpcs(&v3.ListVpcsRequest{Id: &[]string{id}})
		if err != nil {
			t.Fatalf("ListVpcs (v3): %v", err)
		}
		return res.Vpcs != nil && len(*res.Vpcs) == 1 && (*res.Vpcs)[0].Status == "ACTIVE"
	})
	res, err := net3.ListVpcs(&v3.ListVpcsRequest{Name: &[]string{"sdk-v3-list"}, Limit: ptr(int32(10))})
	if err != nil || res.Vpcs == nil || len(*res.Vpcs) != 1 || res.PageInfo == nil || res.PageInfo.CurrentCount != 1 {
		t.Fatalf("ListVpcs (v3) by name = %+v, %v", res, err)
	}
	v := (*res.Vpcs)[0]
	if v.Id != id || v.Cidr != "10.80.0.0/16" || v.ProjectId != projectID || len(v.CloudResources) != 2 {
		t.Fatalf("listed VPC = %+v", v)
	}
}
