package vpc

import (
	"net/http"
	"testing"
)

func TestTagReads(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	v, err := e.svc.CreateVPC(ctx, testTenant, CreateVPCOption{CIDR: ptr("10.0.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	sn, err := e.svc.CreateSubnet(ctx, testTenant, CreateSubnetOption{Name: "sn", CIDR: "10.0.1.0/24", GatewayIP: "10.0.1.1", VPCID: v.ID})
	if err != nil {
		t.Fatal(err)
	}
	g, err := e.svc.CreateSecurityGroup(ctx, testTenant, CreateSecurityGroupOption{Name: "web", Tags: &[]Tag{{Key: "env", Value: "dev"}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := e.svc.CreateSecurityGroup(ctx, testTenant, CreateSecurityGroupOption{Name: "bare"}, false)
	if err != nil {
		t.Fatal(err)
	}

	tags := func(path string) []Tag {
		t.Helper()
		status, out := e.send(t, http.MethodGet, "/v2.0/"+testProject+path, nil)
		if status != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, status, out)
		}
		got := decodeInto[tagsResponse](t, out).Tags
		if got == nil {
			t.Fatalf("GET %s: tags is null, want a list: %s", path, out)
		}
		return got
	}
	if got := tags("/vpcs/" + v.ID + "/tags"); len(got) != 0 {
		t.Errorf("VPC tags = %v", got)
	}
	if got := tags("/subnets/" + sn.ID + "/tags"); len(got) != 0 {
		t.Errorf("subnet tags = %v", got)
	}
	if got := tags("/security-groups/" + g.ID + "/tags"); len(got) != 1 || got[0] != (Tag{Key: "env", Value: "dev"}) {
		t.Errorf("security group tags = %v", got)
	}
	if got := tags("/security-groups/" + bare.ID + "/tags"); len(got) != 0 {
		t.Errorf("untagged group tags = %v", got)
	}

	for _, path := range []string{"/vpcs/", "/subnets/", "/security-groups/"} {
		if status, out := e.send(t, http.MethodGet, "/v2.0/"+testProject+path+"00000000-0000-4000-8000-000000000000/tags", nil); status != http.StatusNotFound {
			t.Errorf("GET %s of a missing resource: %d %s", path, status, out)
		}
	}
	if status, _ := e.send(t, http.MethodPost, "/v2.0/"+testProject+"/vpcs/"+v.ID+"/tags/action", nil); status != http.StatusNotImplemented {
		t.Errorf("changing tags: %d", status)
	}
}
