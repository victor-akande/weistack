package sdk

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	stsv1 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1"
	sts "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/model"
	stsregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/region"
	vpcv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	vpcregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/region"
)

// addedAccount is an account added through the admin API.
type addedAccount struct {
	ID, Name, ProjectID string
	AK, SK              string
}

// addAccount adds an account through the emulator's admin API.
func addAccount(t *testing.T, name string) addedAccount {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": name})
	res, err := http.Post("http://"+emulatorAddr+"/_weistack/accounts", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Account struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			ProjectID string `json:"project_id"`
		} `json:"account"`
		Credentials struct {
			AccessKey string `json:"access_key"`
			SecretKey string `json:"secret_key"`
		} `json:"credentials"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /_weistack/accounts = %d, %v", res.StatusCode, err)
	}
	return addedAccount{
		ID: out.Account.ID, Name: out.Account.Name, ProjectID: out.Account.ProjectID,
		AK: out.Credentials.AccessKey, SK: out.Credentials.SecretKey,
	}
}

// vpcIn builds a VPC client that signs with ak and sk in project.
func vpcIn(t *testing.T, ak, sk, project string) *vpcv2.VpcClient {
	t.Helper()
	cred, err := basic.NewCredentialsBuilder().WithAk(ak).WithSk(sk).WithProjectId(project).SafeBuild()
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

// TestAccounts uses an account added beside the emulator's own: the SDK
// discovers its account and project with its root user's keys, its
// resources are its own, and, with credentials enforced, the primary
// account's project is refused to it.
func TestAccounts(t *testing.T) {
	t.Parallel()
	partner := addAccount(t, "sdk-partner-"+strings.ToLower(rand.Text()[:6]))
	if partner.ProjectID == projectID || partner.ID == "" {
		t.Fatalf("added = %+v", partner)
	}

	// IAM and STS answer in the partner's account.
	c, _ := iamClientsAs(t, partner.AK, partner.SK)
	domains, err := c.KeystoneListAuthDomains(&iam.KeystoneListAuthDomainsRequest{})
	if err != nil || len(*domains.Domains) != 1 || (*domains.Domains)[0].Id != partner.ID {
		t.Fatalf("KeystoneListAuthDomains as the partner = %+v, %v", domains, err)
	}
	creds, err := basic.NewCredentialsBuilder().WithAk(partner.AK).WithSk(partner.SK).WithProjectId(partner.ProjectID).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	stsHC, err := stsv1.StsClientBuilder().
		WithRegion(stsregion.ValueOf(region)).WithCredential(creds).WithHttpConfig(proxyConfig(t)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	who, err := stsv1.NewStsClient(stsHC).GetCallerIdentity(&sts.GetCallerIdentityRequest{})
	if err != nil || *who.AccountId != partner.ID || *who.PrincipalUrn != "iam::"+partner.ID+":user:"+partner.Name {
		t.Fatalf("GetCallerIdentity as the partner = %+v, %v", who, err)
	}

	// The SDK discovers the partner's project, and the VPC lands there.
	discovering, err := basic.NewCredentialsBuilder().WithAk(partner.AK).WithSk(partner.SK).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	hc, err := vpcv2.VpcClientBuilder().
		WithRegion(vpcregion.ValueOf(region)).WithCredential(discovering).WithHttpConfig(proxyConfig(t)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	created, err := vpcv2.NewVpcClient(hc).CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("partner-vpc"), Cidr: ptr("10.91.0.0/16"),
	}}})
	if err != nil || created.Vpc.TenantId != partner.ProjectID {
		t.Fatalf("CreateVpc as the partner = %+v, %v", created, err)
	}
	vpcID := created.Vpc.Id
	mine := vpcIn(t, partner.AK, partner.SK, partner.ProjectID)
	eventually(t, "the VPC to become OK", func() bool {
		shown, err := mine.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && shown.Vpc.Status.Value() == "OK"
	})
	t.Cleanup(func() {
		if _, err := mine.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID}); err != nil {
			t.Errorf("DeleteVpc: %v", err)
		}
	})
	primary, err := vpcIn(t, signingAK("AKACCOUNTS0000000000"), signingSK(), projectID).ListVpcs(&v2.ListVpcsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range *primary.Vpcs {
		if v.Id == vpcID {
			t.Error("the partner's VPC is listed in the primary account's project")
		}
	}

	// Buckets are their owning account's.
	bucket := "sdk-accounts-" + strings.ToLower(rand.Text()[:8])
	owner := newOBSWithKey(t, emulatorAddr, signingAK("AKACCOUNTSOBS0000000"), signingSK(), obs.SignatureObs, false)
	if _, err := owner.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := owner.DeleteBucket(bucket); err != nil {
			t.Errorf("DeleteBucket: %v", err)
		}
	})
	_, err = newOBSWithKey(t, emulatorAddr, partner.AK, partner.SK, obs.SignatureObs, false).ListObjects(&obs.ListObjectsInput{Bucket: bucket})
	wantOBSError(t, err, 403, "AccessDenied")

	// With credentials enforced, the partner's root user may do anything
	// in its own account and nothing in another's project.
	if !enforcing {
		return
	}
	_, err = vpcIn(t, partner.AK, partner.SK, projectID).ListVpcs(&v2.ListVpcsRequest{})
	denialOf(t, err, "WeiStack.0403")
}
