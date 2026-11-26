package ecs

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

type staticReporter []inventory.Resource

func (r staticReporter) ReportResources(_ context.Context, emit func(inventory.Resource) error) error {
	for _, res := range r {
		if err := emit(res); err != nil {
			return err
		}
	}
	return nil
}

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	extraGroup, err := e.network.CreateSecurityGroup(t.Context(), testTenant.vpc(), vpc.CreateSecurityGroupOption{Name: "db"}, false)
	if err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}

	const (
		epID       = "11111111-1111-4111-8111-111111111111"
		secretText = "cloud-init-secret-payload"
		testAcct   = "acct-main"
		otherAcct  = "acct-other"
	)
	encodedSecret := base64.StdEncoding.EncodeToString([]byte(secretText))

	createdAt := e.clock.Now()
	_, webIDs := e.mustCreate(t, n.serverBody(
		"name", `"web"`,
		"security_groups", fmt.Sprintf(`[{"id": %q}, {"id": %q}]`, n.groupID, extraGroup.ID),
		"server_tags", `[{"key": "env", "value": "prod"}, {"key": "bare", "value": ""}]`,
		"user_data", fmt.Sprintf("%q", encodedSecret),
		"extendparam", fmt.Sprintf(`{"enterprise_project_id": %q}`, epID),
	))
	e.settle(t)
	updatedAt := e.clock.Now()

	// A second server in another project, still in BUILD.
	otherTenant := Tenant{Region: testRegion, ProjectID: otherProject}
	on := e.mustNetwork(t, otherTenant, "192.168.2.0/24")
	status, out := e.call(t, http.MethodPost, "/v1/"+otherProject+"/cloudservers", on.serverBody("name", `"pending"`))
	if status != http.StatusOK {
		t.Fatalf("creating server in second project: %d %s", status, out)
	}
	pendingID := decodeInto[createServersResponse](t, out).ServerIDs[0]

	peers := staticReporter{
		{Type: inventory.VPCs, ID: n.vpcID, RegionID: testRegion, ProjectID: testProject},
		{Type: inventory.VPCSecurityGroups, ID: n.groupID, RegionID: testRegion, ProjectID: testProject},
		{Type: inventory.VPCSecurityGroups, ID: extraGroup.ID, RegionID: testRegion, ProjectID: testProject},
		{Type: inventory.IMSImages, ID: ubuntuImage, RegionID: testRegion, ProjectID: testProject},
		{Type: inventory.VPCs, ID: on.vpcID, RegionID: testRegion, ProjectID: otherProject},
	}
	owners := map[string]string{
		testProject:  testAcct,
		otherProject: otherAcct,
	}
	snap, err := inventory.New(inventory.Options{
		Reporters: []inventory.Reporter{e.svc, peers},
		Owner: func(projectID, _ string) (string, bool) {
			acct, ok := owners[projectID]
			return acct, ok
		},
	}).Collect(t.Context())
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
			t.Fatalf("%s %s in %s is not reported; got %v", typ, id, project, snap.Resources)
		}
		return r
	}

	web := at(inventory.ECSServers, testProject, webIDs[0])
	wantTags := map[string]string{"env": "prod", "bare": ""}
	if web.Name != "web" ||
		web.RegionID != testRegion ||
		web.ProjectID != testProject ||
		web.AccountID != testAcct ||
		web.EnterpriseProjectID != epID ||
		!web.Created.Equal(createdAt) ||
		!web.Updated.Equal(updatedAt) ||
		web.State != inventory.Succeeded ||
		!maps.Equal(web.Tags, wantTags) {
		t.Errorf("web server = %+v", web)
	}

	sgIDs := []string{n.groupID, extraGroup.ID}
	slices.Sort(sgIDs)
	wantWebRelations := []inventory.Ref{
		{Relation: inventory.IsAssociatedWith, Type: inventory.IMSImages, ID: ubuntuImage},
		{Relation: inventory.IsAssociatedWith, Type: inventory.VPCSecurityGroups, ID: sgIDs[0]},
		{Relation: inventory.IsAssociatedWith, Type: inventory.VPCSecurityGroups, ID: sgIDs[1]},
		{Relation: inventory.IsContainedIn, Type: inventory.VPCs, ID: n.vpcID},
	}
	if !reflect.DeepEqual(web.Relations, wantWebRelations) {
		t.Errorf("web.Relations = %+v, want %+v", web.Relations, wantWebRelations)
	}

	pending := at(inventory.ECSServers, otherProject, pendingID)
	if pending.Name != "pending" ||
		pending.RegionID != testRegion ||
		pending.ProjectID != otherProject ||
		pending.AccountID != otherAcct ||
		pending.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		pending.Created.IsZero() ||
		pending.State != inventory.Processing ||
		len(pending.Tags) != 0 {
		t.Errorf("pending server = %+v", pending)
	}
	wantPendingRelations := []inventory.Ref{
		{Relation: inventory.IsContainedIn, Type: inventory.VPCs, ID: on.vpcID},
	}
	if !reflect.DeepEqual(pending.Relations, wantPendingRelations) {
		t.Errorf("pending.Relations = %+v, want %+v", pending.Relations, wantPendingRelations)
	}

	// User data must never appear in the inventory report.
	dumped := fmt.Sprintf("%+v", snap)
	if strings.Contains(dumped, secretText) || strings.Contains(dumped, encodedSecret) {
		t.Errorf("user_data leaked into inventory snapshot: %s", dumped)
	}

	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	wantCount := map[inventory.Type]int{
		inventory.ECSServers:        2,
		inventory.VPCs:              2,
		inventory.VPCSecurityGroups: 2,
		inventory.IMSImages:         1,
	}
	if !maps.Equal(count, wantCount) {
		t.Errorf("reported %v, want %v", count, wantCount)
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	pending := &PendingOp{Kind: taskServerStop}
	cases := []struct {
		name    string
		status  string
		pending *PendingOp
		want    inventory.State
	}{
		{name: StatusBuild, status: StatusBuild, want: inventory.Processing},
		{name: StatusReboot, status: StatusReboot, want: inventory.Processing},
		{name: StatusHardReboot, status: StatusHardReboot, want: inventory.Processing},
		{name: StatusResize, status: StatusResize, want: inventory.Processing},
		{name: StatusError, status: StatusError, want: inventory.Failed},
		{name: StatusActive, status: StatusActive, want: inventory.Succeeded},
		{name: StatusShutoff, status: StatusShutoff, want: inventory.Succeeded},
		{name: "ACTIVE with Pending", status: StatusActive, pending: pending, want: inventory.Processing},
		{name: "SHUTOFF with Pending", status: StatusShutoff, pending: pending, want: inventory.Processing},
	}
	for _, tc := range cases {
		if got := serverState(tc.status, tc.pending); got != tc.want {
			t.Errorf("%s: serverState(%q, %v) = %s, want %s", tc.name, tc.status, tc.pending, got, tc.want)
		}
	}
}
