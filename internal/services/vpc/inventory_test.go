package vpc

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
)

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	vpc := e.mustCreateVPC(t, "web", "10.0.0.0/16")
	subnet := e.mustCreateSubnet(t, vpc.ID, "app", "10.0.1.0/24", "10.0.1.1")
	status, out := e.call3(t, http.MethodPost, "/security-groups",
		`{"security_group": {"name": "sg", "enterprise_project_id": "0", "tags": [{"key": "env", "value": "dev"}]}}`)
	if status != http.StatusCreated {
		t.Fatalf("creating a security group: %d %s", status, out)
	}
	sg := decodeInto[securityGroupResponse](t, out).SecurityGroup
	status, out = e.call3(t, http.MethodPost, "/security-group-rules",
		fmt.Sprintf(`{"security_group_rule": {"security_group_id": %q, "direction": "ingress", "protocol": "tcp", "multiport": "22"}}`, sg.ID))
	if status != http.StatusCreated {
		t.Fatalf("creating a rule: %d %s", status, out)
	}
	rule := decodeInto[struct {
		Rule SecurityGroupRule `json:"security_group_rule"`
	}](t, out).Rule
	// A VPC in another project, still being created.
	const other = "fedcba9876543210fedcba9876543210"
	status, out = e.callAs(t, other, http.MethodPost, "/vpcs", `{"vpc": {"name": "pending", "cidr": "192.168.0.0/16"}}`)
	if status != http.StatusOK {
		t.Fatalf("creating a VPC: %d %s", status, out)
	}
	pending := decodeInto[vpcResponse](t, out).VPC

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := make(map[string]inventory.Resource)
	for _, r := range snap.Resources {
		got[r.Type.String()+"/"+r.ProjectID+"/"+r.ID] = r
	}
	at := func(typ inventory.Type, project, id string) inventory.Resource {
		t.Helper()
		r, ok := got[typ.String()+"/"+project+"/"+id]
		if !ok {
			t.Fatalf("%s %s is not reported; got %v", typ, id, snap.Resources)
		}
		return r
	}

	v := at(inventory.VPCs, testProject, vpc.ID)
	if v.Name != "web" || v.RegionID != testRegion || v.State != inventory.Succeeded ||
		v.EnterpriseProjectID != "0" || v.Created.IsZero() || !v.Created.Equal(time.Time(vpc.CreatedAt)) || len(v.Relations) != 0 {
		t.Errorf("VPC = %+v", v)
	}
	if p := at(inventory.VPCs, other, pending.ID); p.State != inventory.Processing || p.Name != "pending" {
		t.Errorf("the VPC being created = %+v, want Processing", p)
	}
	if s := at(inventory.VPCSubnets, testProject, subnet.ID); s.Name != "app" || s.State != inventory.Succeeded || s.Created.IsZero() {
		t.Errorf("subnet = %+v", s)
	}
	if g := at(inventory.VPCSecurityGroups, testProject, sg.ID); g.Name != "sg" || g.Tags["env"] != "dev" || len(g.Tags) != 1 || g.Created.IsZero() {
		t.Errorf("security group = %+v", g)
	}
	if r := at(inventory.VPCSecurityGroupRules, testProject, rule.ID); r.Name != "" || r.Created.IsZero() {
		t.Errorf("rule = %+v", r)
	}

	// The project's default security group, made on first use, is the
	// account's, so it is reported too. Every group starts with four
	// rules: 4 + 4, and the one added.
	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.VPCs:                  2,
		inventory.VPCSubnets:            1,
		inventory.VPCSecurityGroups:     2,
		inventory.VPCSecurityGroupRules: 9,
	}
	if fmt.Sprint(count) != fmt.Sprint(want) {
		t.Errorf("reported %v, want %v", count, want)
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	for status, want := range map[string]inventory.State{
		VPCStatusCreating: inventory.Processing, VPCStatusOK: inventory.Succeeded, VPCStatusError: inventory.Failed,
	} {
		if got := vpcState(status); got != want {
			t.Errorf("vpcState(%s) = %s, want %s", status, got, want)
		}
	}
	for status, want := range map[string]inventory.State{
		SubnetStatusUnknown: inventory.Processing, SubnetStatusActive: inventory.Succeeded, SubnetStatusError: inventory.Failed,
	} {
		if got := subnetState(status); got != want {
			t.Errorf("subnetState(%s) = %s, want %s", status, got, want)
		}
	}
}
