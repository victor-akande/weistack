package sdk

import (
	"testing"

	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
)

// TestIAMAgencies drives agencies of both generations through the SDK's
// own models: a classic agency for another account, granted a role in
// the project, and an IAM 5.0 trust agency with a policy attached, plus a
// service-linked agency.
func TestIAMAgencies(t *testing.T) {
	t.Parallel()
	c, c5 := iamClients(t, "AKAGENCIES0000000000")
	domains, err := c.KeystoneListAuthDomains(&iam.KeystoneListAuthDomainsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	account := (*domains.Domains)[0].Id
	partner := addAccount(t, "sdk-agency-partner-"+account[:6])

	// Classic.
	var days interface{} = 2
	created, err := c.CreateAgency(&iam.CreateAgencyRequest{Body: &iam.CreateAgencyRequestBody{Agency: &iam.CreateAgencyOption{
		Name: "sdk-classic", DomainId: account, TrustDomainName: ptr(partner.Name), Description: ptr("for the partner"), Duration: &days,
	}}})
	if err != nil || created.Agency.Duration != "48" || *created.Agency.TrustDomainId != partner.ID {
		t.Fatalf("CreateAgency = %+v, %v", created, err)
	}
	id := created.Agency.Id
	shown, err := c.ShowAgency(&iam.ShowAgencyRequest{AgencyId: id})
	if err != nil || *shown.Agency.TrustDomainName != partner.Name || *shown.Agency.AgencyUrn != "iam::"+account+":agency:sdk-classic" {
		t.Fatalf("ShowAgency = %+v, %v", shown, err)
	}
	var forever interface{} = "FOREVER"
	if _, err := c.UpdateAgency(&iam.UpdateAgencyRequest{AgencyId: id, Body: &iam.UpdateAgencyRequestBody{Agency: &iam.UpdateAgencyOption{Duration: &forever}}}); err != nil {
		t.Fatalf("UpdateAgency: %v", err)
	}
	perms, err := c.KeystoneListPermissions(&iam.KeystoneListPermissionsRequest{DisplayName: ptr("VPC ReadOnlyAccess")})
	if err != nil || len(*perms.Roles) != 1 {
		t.Fatalf("KeystoneListPermissions = %+v, %v", perms, err)
	}
	role := (*perms.Roles)[0].Id
	if _, err := c.AssociateAgencyWithProjectPermission(&iam.AssociateAgencyWithProjectPermissionRequest{ProjectId: projectID, AgencyId: id, RoleId: role}); err != nil {
		t.Fatalf("AssociateAgencyWithProjectPermission: %v", err)
	}
	roles, err := c.ListProjectPermissionsForAgency(&iam.ListProjectPermissionsForAgencyRequest{ProjectId: projectID, AgencyId: id})
	if err != nil || len(*roles.Roles) != 1 || (*roles.Roles)[0].Id != role {
		t.Fatalf("ListProjectPermissionsForAgency = %+v, %v", roles, err)
	}
	listed, err := c.ListAgencies(&iam.ListAgenciesRequest{DomainId: account, Name: ptr("sdk-classic")})
	if err != nil || len(*listed.Agencies) != 1 || (*listed.Agencies)[0].Duration != "FOREVER" {
		t.Fatalf("ListAgencies = %+v, %v", listed, err)
	}
	if _, err := c.DeleteAgency(&iam.DeleteAgencyRequest{AgencyId: id}); err != nil {
		t.Fatalf("DeleteAgency: %v", err)
	}

	// IAM 5.0.
	trust := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["sts:agencies:assume"],"Principal":{"IAM":["` + partner.ID + `"]}}]}`
	made, err := c5.CreateAgencyV5(&v5.CreateAgencyV5Request{Body: &v5.CreateAgencyReqBody{
		AgencyName: "sdk-trust", TrustPolicy: trust, MaxSessionDuration: ptr(int32(7200)),
	}})
	if err != nil || made.Agency.Urn != "iam::"+account+":agency:sdk-trust" || made.Agency.MaxSessionDuration != 7200 || made.Agency.CreatedAt == nil {
		t.Fatalf("CreateAgencyV5 = %+v, %v", made, err)
	}
	aid := made.Agency.AgencyId
	pol, err := c5.CreatePolicyV5(&v5.CreatePolicyV5Request{Body: &v5.CreatePolicyReqBody{
		PolicyName: "sdk-agency-reader", PolicyDocument: `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:*:list*"]}]}`,
	}})
	if err != nil {
		t.Fatalf("CreatePolicyV5: %v", err)
	}
	pid := pol.Policy.PolicyId
	if _, err := c5.AttachAgencyPolicyV5(&v5.AttachAgencyPolicyV5Request{PolicyId: pid, Body: &v5.AttachAgencyPolicyReqBody{AgencyId: aid}}); err != nil {
		t.Fatalf("AttachAgencyPolicyV5: %v", err)
	}
	held, err := c5.ListAttachedAgencyPoliciesV5(&v5.ListAttachedAgencyPoliciesV5Request{AgencyId: aid})
	if err != nil || len(*held.AttachedPolicies) != 1 || (*held.AttachedPolicies)[0].PolicyId != pid {
		t.Fatalf("ListAttachedAgencyPoliciesV5 = %+v, %v", held, err)
	}
	got, err := c5.GetAgencyV5(&v5.GetAgencyV5Request{AgencyId: aid})
	if err != nil || *got.Agency.TrustPolicy != trust {
		t.Fatalf("GetAgencyV5 = %+v, %v", got, err)
	}
	if _, err := c5.DetachAgencyPolicyV5(&v5.DetachAgencyPolicyV5Request{PolicyId: pid, Body: &v5.DetachAgencyPolicyReqBody{AgencyId: aid}}); err != nil {
		t.Fatalf("DetachAgencyPolicyV5: %v", err)
	}
	if _, err := c5.DeleteAgencyV5(&v5.DeleteAgencyV5Request{AgencyId: aid}); err != nil {
		t.Fatalf("DeleteAgencyV5: %v", err)
	}
	if _, err := c5.DeletePolicyV5(&v5.DeletePolicyV5Request{PolicyId: pid}); err != nil {
		t.Fatalf("DeletePolicyV5: %v", err)
	}

	// Service-linked.
	linked, err := c5.CreateServiceLinkedAgencyV5(&v5.CreateServiceLinkedAgencyV5Request{Body: &v5.CreateServiceLinkedAgencyReqBody{ServicePrincipal: "service.SDKTEST"}})
	if err != nil {
		t.Fatalf("CreateServiceLinkedAgencyV5: %v", err)
	}
	task, err := c5.DeleteServiceLinkedAgencyV5(&v5.DeleteServiceLinkedAgencyV5Request{AgencyId: linked.Agency.AgencyId})
	if err != nil || task.DeletionTaskId == nil {
		t.Fatalf("DeleteServiceLinkedAgencyV5 = %+v, %v", task, err)
	}
	status, err := c5.GetServiceLinkedAgencyDeletionStatusV5(&v5.GetServiceLinkedAgencyDeletionStatusV5Request{DeletionTaskId: *task.DeletionTaskId})
	if err != nil || status.Status == nil || status.Status.Value() != "succeeded" {
		t.Fatalf("GetServiceLinkedAgencyDeletionStatusV5 = %+v, %v", status, err)
	}
}
