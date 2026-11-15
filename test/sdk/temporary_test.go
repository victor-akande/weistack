package sdk

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	stsv1 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1"
	sts "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/model"
	stsregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/sts/v1/region"
	vpcv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

// temporary are temporary credentials as a test uses them.
type temporary struct{ ak, sk, token string }

func (c temporary) basic(t *testing.T, project string) *basic.Credentials {
	t.Helper()
	creds, err := basic.NewCredentialsBuilder().WithAk(c.ak).WithSk(c.sk).WithSecurityToken(c.token).WithProjectId(project).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	return creds
}

func (c temporary) vpc(t *testing.T, project string) *vpcv2.VpcClient {
	t.Helper()
	hc, err := vpcv2.VpcClientBuilder().
		WithEndpoints([]string{realEndpoint}).WithCredential(c.basic(t, project)).WithHttpConfig(httpConfigAt(emulatorAddr)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	return vpcv2.NewVpcClient(hc)
}

func (c temporary) sts(t *testing.T) *stsv1.StsClient {
	t.Helper()
	hc, err := stsv1.StsClientBuilder().
		WithRegion(stsregion.ValueOf(region)).WithCredential(c.basic(t, projectID)).WithHttpConfig(proxyConfig(t)).SafeBuild()
	if err != nil {
		t.Fatal(err)
	}
	return stsv1.NewStsClient(hc)
}

func (c temporary) obs(t *testing.T) *obs.ObsClient {
	t.Helper()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, emulatorAddr)
		},
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client, err := obs.New(c.ak, c.sk, obsEndpoint, obs.WithSecurityToken(c.token), obs.WithSignature(obs.SignatureObs),
		obs.WithRegion(region), obs.WithHttpTransport(transport), obs.WithMaxRetryCount(0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// TestTemporaryCredentials: a partner account assumes the emulator
// account's agencies, through classic IAM and through STS, and acts with
// what the agency was granted; a user's own temporary credentials carry
// an OBS-only session policy. With credentials enforced, the
// credentials' signatures are checked and their permissions evaluated.
func TestTemporaryCredentials(t *testing.T) {
	t.Parallel()
	suffix := strings.ToLower(rand.Text()[:6])
	partner := addAccount(t, "sdk-temp-partner-"+suffix)
	c, c5 := iamClients(t, "AKTEMPORARY000000000")
	domains, err := c.KeystoneListAuthDomains(&iam.KeystoneListAuthDomainsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	account := (*domains.Domains)[0]

	// A classic agency for the partner, allowed to read VPCs.
	created, err := c.CreateAgency(&iam.CreateAgencyRequest{Body: &iam.CreateAgencyRequestBody{Agency: &iam.CreateAgencyOption{
		Name: "sdk-temp-classic-" + suffix, DomainId: account.Id, TrustDomainId: ptr(partner.ID),
	}}})
	if err != nil {
		t.Fatalf("CreateAgency: %v", err)
	}
	t.Cleanup(func() { _, _ = c.DeleteAgency(&iam.DeleteAgencyRequest{AgencyId: created.Agency.Id}) })
	perms, err := c.KeystoneListPermissions(&iam.KeystoneListPermissionsRequest{DisplayName: ptr("VPC ReadOnlyAccess")})
	if err != nil || len(*perms.Roles) != 1 {
		t.Fatalf("KeystoneListPermissions = %+v, %v", perms, err)
	}
	if _, err := c.AssociateAgencyWithProjectPermission(&iam.AssociateAgencyWithProjectPermissionRequest{
		ProjectId: projectID, AgencyId: created.Agency.Id, RoleId: (*perms.Roles)[0].Id,
	}); err != nil {
		t.Fatalf("AssociateAgencyWithProjectPermission: %v", err)
	}

	// The partner assumes it with classic IAM.
	pc, _ := iamClientsAs(t, partner.AK, partner.SK)
	got, err := pc.CreateTemporaryAccessKeyByAgency(&iam.CreateTemporaryAccessKeyByAgencyRequest{Body: &iam.CreateTemporaryAccessKeyByAgencyRequestBody{
		Auth: &iam.AgencyAuth{Identity: &iam.AgencyAuthIdentity{
			Methods: []iam.AgencyAuthIdentityMethods{iam.GetAgencyAuthIdentityMethodsEnum().ASSUME_ROLE},
			AssumeRole: &iam.IdentityAssumerole{
				AgencyName: created.Agency.Name, DomainName: ptr(account.Name), DurationSeconds: ptr(int32(1800)),
				SessionUser: &iam.AssumeroleSessionuser{Name: ptr("alice")},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("CreateTemporaryAccessKeyByAgency: %v", err)
	}
	classic := temporary{got.Credential.Access, got.Credential.Secret, got.Credential.Securitytoken}
	who, err := classic.sts(t).GetCallerIdentity(&sts.GetCallerIdentityRequest{})
	if err != nil || who.AccountId == nil || *who.AccountId != account.Id ||
		*who.PrincipalUrn != "sts::"+account.Id+":assumed-agency:"+created.Agency.Name+"/alice" {
		t.Fatalf("GetCallerIdentity as the agency = %+v, %v", who, err)
	}
	// It reads the emulator account's VPCs; enforced, it may not create one.
	if _, err := classic.vpc(t, projectID).ListVpcs(&vpc.ListVpcsRequest{}); err != nil {
		t.Fatalf("ListVpcs as the agency: %v", err)
	}
	if enforcing {
		_, err = classic.vpc(t, projectID).CreateVpc(&vpc.CreateVpcRequest{Body: &vpc.CreateVpcRequestBody{Vpc: &vpc.CreateVpcOption{Name: ptr("nope")}}})
		denialOf(t, err, "WeiStack.0403")
		// A tampered security token makes the key unknown.
		bad := classic
		bad.token = strings.ToUpper(bad.token[:8]) + bad.token[8:]
		if bad.token == classic.token {
			bad.token = "x" + bad.token[1:]
		}
		_, err = bad.vpc(t, projectID).ListVpcs(&vpc.ListVpcsRequest{})
		wantError(t, err, 401, "APIGW.0301")
	}

	// An IAM 5.0 trust agency, assumed with STS, limited by a session policy.
	trust := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["sts:agencies:assume"],"Principal":{"IAM":["` + partner.ID + `"]}}]}`
	made, err := c5.CreateAgencyV5(&v5.CreateAgencyV5Request{Body: &v5.CreateAgencyReqBody{AgencyName: "sdk-temp-trust-" + suffix, TrustPolicy: trust}})
	if err != nil {
		t.Fatalf("CreateAgencyV5: %v", err)
	}
	t.Cleanup(func() { _, _ = c5.DeleteAgencyV5(&v5.DeleteAgencyV5Request{AgencyId: made.Agency.AgencyId}) })
	pol, err := c5.CreatePolicyV5(&v5.CreatePolicyV5Request{Body: &v5.CreatePolicyReqBody{
		PolicyName: "sdk-temp-vpc-" + suffix, PolicyDocument: `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:*:*"]}]}`,
	}})
	if err != nil {
		t.Fatalf("CreatePolicyV5: %v", err)
	}
	if _, err := c5.AttachAgencyPolicyV5(&v5.AttachAgencyPolicyV5Request{PolicyId: pol.Policy.PolicyId, Body: &v5.AttachAgencyPolicyReqBody{AgencyId: made.Agency.AgencyId}}); err != nil {
		t.Fatalf("AttachAgencyPolicyV5: %v", err)
	}
	t.Cleanup(func() {
		_, _ = c5.DetachAgencyPolicyV5(&v5.DetachAgencyPolicyV5Request{PolicyId: pol.Policy.PolicyId, Body: &v5.DetachAgencyPolicyReqBody{AgencyId: made.Agency.AgencyId}})
		_, _ = c5.DeletePolicyV5(&v5.DeletePolicyV5Request{PolicyId: pol.Policy.PolicyId})
	})
	assumed, err := stsAs(t, partner.AK, partner.SK).AssumeAgency(&sts.AssumeAgencyRequest{Body: &sts.AssumeAgencyReqBody{
		AgencyUrn: made.Agency.Urn, AgencySessionName: "ci-run",
		Policy: ptr(`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:*:list*"]}]}`),
	}})
	if err != nil {
		t.Fatalf("AssumeAgency: %v", err)
	}
	if assumed.AssumedAgency.Urn != "sts::"+account.Id+":assumed-agency:"+made.Agency.AgencyName+"/ci-run" ||
		assumed.AssumedAgency.Id != made.Agency.AgencyId+":ci-run" || assumed.Credentials.Expiration == nil {
		t.Fatalf("AssumeAgency = %+v", assumed)
	}
	viaSTS := temporary{assumed.Credentials.AccessKeyId, assumed.Credentials.SecretAccessKey, assumed.Credentials.SecurityToken}
	if _, err := viaSTS.vpc(t, projectID).ListVpcs(&vpc.ListVpcsRequest{}); err != nil {
		t.Fatalf("ListVpcs as the trust agency: %v", err)
	}
	if enforcing {
		// The agency may create VPCs; the session may not.
		_, err = viaSTS.vpc(t, projectID).CreateVpc(&vpc.CreateVpcRequest{Body: &vpc.CreateVpcRequestBody{Vpc: &vpc.CreateVpcOption{Name: ptr("nope")}}})
		denialOf(t, err, "WeiStack.0403")
		// The emulator account does not trust itself.
		_, err = stsAs(t, adminAK, adminSK).AssumeAgency(&sts.AssumeAgencyRequest{Body: &sts.AssumeAgencyReqBody{AgencyUrn: made.Agency.Urn, AgencySessionName: "self"}})
		denialOf(t, err, "STS5.1001")
	}
	_, err = stsAs(t, partner.AK, partner.SK).AssumeAgency(&sts.AssumeAgencyRequest{Body: &sts.AssumeAgencyReqBody{
		AgencyUrn: made.Agency.Urn, AgencySessionName: "long", DurationSeconds: ptr(int32(7200)),
	}})
	wantError(t, err, 400, "STS5.1102")

	// The partner's own temporary credentials, which may only read OBS.
	own, err := pc.CreateTemporaryAccessKeyByToken(&iam.CreateTemporaryAccessKeyByTokenRequest{Body: &iam.CreateTemporaryAccessKeyByTokenRequestBody{
		Auth: &iam.TokenAuth{Identity: &iam.TokenAuthIdentity{
			Methods: []iam.TokenAuthIdentityMethods{iam.GetTokenAuthIdentityMethodsEnum().TOKEN},
			Policy: &iam.ServicePolicy{Version: "1.1", Statement: []iam.ServiceStatement{{
				Action: []string{"obs:object:getObject", "obs:bucket:*"}, Effect: iam.GetServiceStatementEffectEnum().ALLOW,
			}}},
		}},
	}})
	if err != nil {
		t.Fatalf("CreateTemporaryAccessKeyByToken: %v", err)
	}
	mine := temporary{own.Credential.Access, own.Credential.Secret, own.Credential.Securitytoken}
	bucket := "sdk-temp-" + suffix
	oc := mine.obs(t)
	if _, err := oc.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
		t.Fatalf("CreateBucket with temporary credentials: %v", err)
	}
	t.Cleanup(func() { _, _ = newOBSWithKey(t, emulatorAddr, partner.AK, partner.SK, obs.SignatureObs, false).DeleteBucket(bucket) })
	if _, err := mine.vpc(t, partner.ProjectID).ListVpcs(&vpc.ListVpcsRequest{}); err != nil {
		t.Fatalf("ListVpcs with an OBS-only session policy: %v", err)
	}
	if enforcing {
		_, err = oc.PutObject(&obs.PutObjectInput{PutObjectBasicInput: obs.PutObjectBasicInput{ObjectOperationInput: obs.ObjectOperationInput{Bucket: bucket, Key: "k"}}})
		wantOBSError(t, err, 403, "AccessDenied")
	}
}
