package sdk

import (
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	vpcv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

// vpcAs builds a VPC client that signs with ak and sk.
func vpcAs(t *testing.T, ak, sk string) *vpcv2.VpcClient {
	t.Helper()
	cred, err := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithProjectId(projectID).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	hc, err := vpcv2.VpcClientBuilder().
		WithEndpoints([]string{realEndpoint}).WithCredential(cred).WithHttpConfig(httpConfigAt(emulatorAddr)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	return vpcv2.NewVpcClient(hc)
}

// TestEnforcedSignatures runs only with WEISTACK_SDK_IAM=enforce: the
// SDK's own signatures pass, and wrong ones are refused with the API
// gateway's documented errors, as the SDK decodes them.
func TestEnforcedSignatures(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()

	if _, err := vpcAs(t, adminAK, adminSK).ListVpcs(&v2.ListVpcsRequest{}); err != nil {
		t.Fatalf("the administrator's key: %v", err)
	}
	_, err := vpcAs(t, adminAK, "a-wrong-secret-key-0000000000000000000000").ListVpcs(&v2.ListVpcsRequest{})
	wantError(t, err, 401, "APIGW.0301")
	_, err = vpcAs(t, "UNKNOWNSDKKEY0000000", adminSK).ListVpcs(&v2.ListVpcsRequest{})
	wantError(t, err, 401, "APIGW.0301")
}
