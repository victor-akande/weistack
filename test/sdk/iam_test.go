package sdk

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	iamv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	stsv1 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1"
	sts "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/model"
	stsregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/region"
	vpcv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	vpcregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/region"
)

// proxyConfig sends every request, IAM's discovery calls included, to
// Huawei Cloud's real HTTPS endpoints through the emulator as a proxy.
func proxyConfig(t *testing.T) *config.HttpConfig {
	t.Helper()
	host, port, err := net.SplitHostPort(emulatorAddr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(port)
	return config.DefaultHttpConfig().
		WithTimeout(10 * time.Second).
		WithIgnoreSSLVerification(true).
		WithProxy(config.NewProxy().WithSchema("http").WithHost(host).WithPort(n))
}

// TestDiscoveryWithoutProjectID: a client configured with nothing but
// keys finds its project the way it does on Huawei Cloud, by asking IAM
// (GET /v3/projects?name=<region>).
func TestDiscoveryWithoutProjectID(t *testing.T) {
	t.Parallel()
	creds, err := basic.NewCredentialsBuilder().
		WithAk(signingAK("AKDISCOVERY000000000")). // the SDK caches discoveries by key
		WithSk(signingSK()).
		SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	// Built as users build clients: by region. That is what makes the
	// SDK discover the project; with an explicit endpoint it would not.
	hc, err := vpcv2.VpcClientBuilder().
		WithRegion(vpcregion.ValueOf(region)).
		WithCredential(creds).
		WithHttpConfig(proxyConfig(t)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building a client without a project ID: %v", err)
	}
	c := vpcv2.NewVpcClient(hc)
	created, err := c.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("discovered"), Cidr: ptr("10.90.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc with a discovered project: %v", err)
	}
	if created.Vpc.TenantId != projectID {
		t.Fatalf("the VPC landed in project %s, want %s", created.Vpc.TenantId, projectID)
	}
}

// TestIAMDiscoveryAndCallerIdentity uses the IAM and STS clients with
// global credentials and no domain ID: the SDK finds the account itself.
func TestIAMDiscoveryAndCallerIdentity(t *testing.T) {
	t.Parallel()
	creds, err := global.NewCredentialsBuilder().
		WithAk(signingAK("AKGLOBAL000000000000")).
		WithSk(signingSK()).
		SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	hc, err := iamv3.IamClientBuilder().
		WithEndpoints([]string{"https://iam.myhuaweicloud.com"}).
		WithCredential(creds).
		WithHttpConfig(proxyConfig(t)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building the IAM client: %v", err)
	}
	c := iamv3.NewIamClient(hc)
	domains, err := c.KeystoneListAuthDomains(&iam.KeystoneListAuthDomainsRequest{})
	if err != nil || domains.Domains == nil || len(*domains.Domains) != 1 || (*domains.Domains)[0].Name != "weistack" {
		t.Fatalf("KeystoneListAuthDomains = %+v, %v", domains, err)
	}
	account := (*domains.Domains)[0].Id

	projects, err := c.KeystoneListProjects(&iam.KeystoneListProjectsRequest{DomainId: &account, Name: ptr(region)})
	if err != nil || projects.Projects == nil || len(*projects.Projects) != 1 || (*projects.Projects)[0].Id != projectID {
		t.Fatalf("KeystoneListProjects = %+v, %v", projects, err)
	}

	// STS takes basic credentials; without a project ID it discovers one.
	stsCreds, err := basic.NewCredentialsBuilder().
		WithAk(signingAK("AKSTSCALLER000000000")).
		WithSk(signingSK()).
		SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	stsHC, err := stsv1.StsClientBuilder().
		WithRegion(stsregion.ValueOf(region)).
		WithCredential(stsCreds).
		WithHttpConfig(proxyConfig(t)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building the STS client: %v", err)
	}
	who, err := stsv1.NewStsClient(stsHC).GetCallerIdentity(&sts.GetCallerIdentityRequest{})
	if err != nil || who.AccountId == nil || *who.AccountId != account || who.PrincipalId == nil || *who.PrincipalId == "" {
		t.Fatalf("GetCallerIdentity = %+v, %v", who, err)
	}
}
