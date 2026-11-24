package inventory

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type reporterFunc func(ctx context.Context, emit func(Resource) error) error

func (f reporterFunc) ReportResources(ctx context.Context, emit func(Resource) error) error {
	return f(ctx, emit)
}

// reports is a reporter of fixed resources.
func reports(rs ...Resource) Reporter {
	return reporterFunc(func(_ context.Context, emit func(Resource) error) error {
		for _, r := range rs {
			if err := emit(r); err != nil {
				return err
			}
		}
		return nil
	})
}

const (
	region  = "ap-southeast-1"
	project = "0123456789abcdef0123456789abcdef"
	account = "acc1"
)

func inProject(t Type, id string, refs ...Ref) Resource {
	return Resource{Type: t, ID: id, RegionID: region, ProjectID: project, Relations: refs}
}

func collect(t *testing.T, o Options) Snapshot {
	t.Helper()
	snap, err := New(o).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return snap
}

func find(t *testing.T, s Snapshot, typ Type, id string) Resource {
	t.Helper()
	for _, r := range s.Resources {
		if r.Type == typ && r.ID == id {
			return r
		}
	}
	t.Fatalf("%s %q is not in the snapshot", typ, id)
	return Resource{}
}

func TestCatalogue(t *testing.T) {
	t.Parallel()
	all := Types()
	if len(all) != len(catalogue) {
		t.Fatalf("Types() has %d types, the catalogue %d", len(all), len(catalogue))
	}
	var documented []string
	for i, info := range all {
		typ := info.Type
		if typ.Provider == "" || typ.Name == "" || strings.Contains(typ.Provider, ".") || strings.Contains(typ.Name, ".") {
			t.Errorf("type %q: a provider and a name without dots are needed", typ)
		}
		if i > 0 && all[i-1].Type.String() >= typ.String() {
			t.Errorf("Types() is not sorted at %s", typ)
		}
		if info.Placement < InProject || info.Placement > Global {
			t.Errorf("%s has no placement", typ)
		}
		if got, ok := ParseType(typ.String()); !ok || got != typ {
			t.Errorf("ParseType(%q) = %v, %v", typ, got, ok)
		}
		if info.Documented {
			documented = append(documented, typ.String())
		}
	}
	// The names Huawei documents for Config: changing this list needs a
	// source (see the catalogue's comment).
	want := []string{
		"ecs.cloudservers", "elb.listeners", "elb.loadbalancers", "elb.members", "evs.volumes",
		"iam.agencies", "iam.groups", "iam.policies", "iam.roles", "iam.users",
		"ims.images", "kms.keys", "nat.natGateways", "nat.privateNatGateways",
		"obs.buckets", "rds.instances",
		"vpc.bandwidths", "vpc.networks", "vpc.publicips", "vpc.securityGroups", "vpc.vpcs",
	}
	if !reflect.DeepEqual(documented, want) {
		t.Errorf("documented types = %v\nwant %v", documented, want)
	}
	for _, s := range []string{"", "ecs", "ecs.", ".cloudservers", "ecs.servers", "ecs.cloudservers.x"} {
		if typ, ok := ParseType(s); ok {
			t.Errorf("ParseType(%q) = %v, true; want false", s, typ)
		}
	}
	if info, _ := Lookup(OBSBuckets); info.Placement != InRegion {
		t.Errorf("obs.buckets placement = %v, want InRegion", info.Placement)
	}
	if info, _ := Lookup(IAMUsers); info.Placement != Global {
		t.Errorf("iam.users placement = %v, want Global", info.Placement)
	}
}

func TestRelationTypes(t *testing.T) {
	t.Parallel()
	for _, r := range []RelationType{Contains, IsContainedIn, IsAttachedTo, IsAssociatedWith} {
		if !r.valid() {
			t.Errorf("%s is not valid", r)
		}
		if r.Inverse().Inverse() != r {
			t.Errorf("%s: the inverse of the inverse is %s", r, r.Inverse().Inverse())
		}
	}
	if Contains.Inverse() != IsContainedIn || IsAttachedTo.Inverse() != IsAttachedTo || IsAssociatedWith.Inverse() != IsAssociatedWith {
		t.Error("Inverse does not follow Config's table")
	}
	if RelationType("Contains").valid() || RelationType("").valid() {
		t.Error("a relationship type outside the four is valid")
	}
}

func TestDocumentedRelations(t *testing.T) {
	t.Parallel()
	for _, p := range documented {
		for _, typ := range []Type{p.from, p.to} {
			if _, ok := Lookup(typ); !ok {
				t.Errorf("%s %s %s: %s is not catalogued", p.from, p.relation, p.to, typ)
			}
		}
		// Collect looks for the other resource in the same region and
		// project: a relationship across placements would need more.
		if a, b := catalogue[p.from].Placement, catalogue[p.to].Placement; a != b {
			t.Errorf("%s %s %s: the types are placed differently", p.from, p.relation, p.to)
		}
		if !Allowed(p.from, p.relation, p.to) || !Allowed(p.to, p.relation.Inverse(), p.from) {
			t.Errorf("%s %s %s is not allowed from both ends", p.from, p.relation, p.to)
		}
	}
	if len(allowed) != 2*len(documented) {
		t.Errorf("%d allowed pairs from %d documented: one is listed twice, or from both ends", len(allowed), len(documented))
	}
	for p := range allowed {
		if !allowed[pair{p.to, p.relation.Inverse(), p.from}] {
			t.Errorf("%s %s %s is allowed only one way", p.from, p.relation, p.to)
		}
	}
	// Examples from Config's table, and relationships it does not have.
	cases := []struct {
		from     Type
		relation RelationType
		to       Type
		want     bool
	}{
		{ECSServers, IsAttachedTo, EVSVolumes, true},
		{EVSVolumes, IsAttachedTo, ECSServers, true},
		{VPCs, Contains, ECSServers, true},
		{EIPPublicIPs, IsContainedIn, EIPBandwidths, true},
		{NATGateways, IsAttachedTo, EIPPublicIPs, true},
		{IAMUsers, IsContainedIn, IAMGroups, true},
		{ELBMembers, IsContainedIn, ELBPools, true},
		{VPCs, Contains, VPCSubnets, false},
		{ECSServers, Contains, VPCs, false},
		{ECSServers, Contains, EIPPublicIPs, false},
		{KPSKeypairs, IsAssociatedWith, ECSServers, false},
	}
	for _, c := range cases {
		if got := Allowed(c.from, c.relation, c.to); got != c.want {
			t.Errorf("Allowed(%s, %s, %s) = %v, want %v", c.from, c.relation, c.to, got, c.want)
		}
	}
}

func TestCollectCompletesResources(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	tags := map[string]string{"env": "dev"}
	owners := map[string]string{project + "@" + region: account}
	snap := collect(t, Options{
		Reporters: []Reporter{reports(
			Resource{Type: VPCs, ID: "vpc1", Name: "web", RegionID: region, ProjectID: project, Created: created, Tags: tags},
			Resource{Type: VPCs, ID: "vpc2", RegionID: region, ProjectID: "elsewhere"},
			Resource{Type: VPCs, ID: "vpc3", RegionID: region, ProjectID: project, AccountID: "kept",
				EnterpriseProjectID: "ep1", Created: created, Updated: created.Add(time.Hour), State: Processing},
			Resource{Type: IAMUsers, ID: "u1", AccountID: account},
			Resource{Type: OBSBuckets, ID: "bucket", RegionID: region, AccountID: account},
		)},
		Owner: func(p, r string) (string, bool) {
			a, ok := owners[p+"@"+r]
			return a, ok
		},
	})
	tags["env"] = "changed"

	vpc1 := find(t, snap, VPCs, "vpc1")
	want := Resource{Type: VPCs, ID: "vpc1", Name: "web", AccountID: account, RegionID: region, ProjectID: project,
		EnterpriseProjectID: DefaultEnterpriseProject, Created: created, Updated: created, State: Succeeded,
		Tags: map[string]string{"env": "dev"}}
	if !reflect.DeepEqual(vpc1, want) {
		t.Errorf("vpc1 = %+v\nwant %+v", vpc1, want)
	}
	if vpc2 := find(t, snap, VPCs, "vpc2"); vpc2.AccountID != "" || vpc2.Tags == nil || len(vpc2.Tags) != 0 || !vpc2.Updated.IsZero() {
		t.Errorf("vpc2 (no owner, no tags, no times) = %+v", vpc2)
	}
	vpc3 := find(t, snap, VPCs, "vpc3")
	if vpc3.AccountID != "kept" || vpc3.EnterpriseProjectID != "ep1" || !vpc3.Updated.Equal(created.Add(time.Hour)) || vpc3.State != Processing {
		t.Errorf("vpc3 (all set) = %+v", vpc3)
	}
	if u := find(t, snap, IAMUsers, "u1"); u.RegionID != GlobalRegion || u.ProjectID != "" || u.AccountID != account {
		t.Errorf("u1 (global) = %+v", u)
	}
	if b := find(t, snap, OBSBuckets, "bucket"); b.RegionID != region || b.AccountID != account {
		t.Errorf("bucket (in a region) = %+v", b)
	}
}

func TestCollectOrder(t *testing.T) {
	t.Parallel()
	snap := collect(t, Options{Reporters: []Reporter{
		reports(
			inProject(VPCs, "b"),
			Resource{Type: VPCs, ID: "a", RegionID: "z-region", ProjectID: "p"},
			inProject(VPCs, "a"),
			inProject(ECSServers, "z"),
		),
		reports(Resource{Type: IAMUsers, ID: "u"}),
	}})
	var got []string
	for _, r := range snap.Resources {
		got = append(got, r.Type.String()+"/"+r.RegionID+"/"+r.ID)
	}
	want := []string{
		"ecs.cloudservers/" + region + "/z",
		"iam.users/global/u",
		"vpc.vpcs/" + region + "/a",
		"vpc.vpcs/" + region + "/b",
		"vpc.vpcs/z-region/a",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v\nwant %v", got, want)
	}
}

func TestCollectJoinsRelations(t *testing.T) {
	t.Parallel()
	snap := collect(t, Options{Reporters: []Reporter{
		// The server reports its VPC, two volumes, its security group and
		// a public image, which is not in the inventory.
		reports(inProject(ECSServers, "srv",
			Ref{IsContainedIn, VPCs, "vpc"},
			Ref{IsAttachedTo, EVSVolumes, "vol2"},
			Ref{IsAttachedTo, EVSVolumes, "vol1"},
			Ref{IsAssociatedWith, VPCSecurityGroups, "sg"},
			Ref{IsAssociatedWith, IMSImages, "public-image"},
		)),
		// The volume reports its server too: the same relationship, once.
		reports(inProject(EVSVolumes, "vol1", Ref{IsAttachedTo, ECSServers, "srv"}), inProject(EVSVolumes, "vol2")),
		reports(inProject(VPCs, "vpc"), inProject(VPCSecurityGroups, "sg")),
	}})

	srv := find(t, snap, ECSServers, "srv")
	wantSrv := []Ref{
		{IsAssociatedWith, VPCSecurityGroups, "sg"},
		{IsAttachedTo, EVSVolumes, "vol1"},
		{IsAttachedTo, EVSVolumes, "vol2"},
		{IsContainedIn, VPCs, "vpc"},
	}
	if !reflect.DeepEqual(srv.Relations, wantSrv) {
		t.Errorf("server relations = %v\nwant %v", srv.Relations, wantSrv)
	}
	if got := find(t, snap, VPCs, "vpc").Relations; !reflect.DeepEqual(got, []Ref{{Contains, ECSServers, "srv"}}) {
		t.Errorf("VPC relations = %v", got)
	}
	if got := find(t, snap, EVSVolumes, "vol1").Relations; !reflect.DeepEqual(got, []Ref{{IsAttachedTo, ECSServers, "srv"}}) {
		t.Errorf("vol1 relations = %v", got)
	}
	if got := find(t, snap, VPCSecurityGroups, "sg").Relations; !reflect.DeepEqual(got, []Ref{{IsAssociatedWith, ECSServers, "srv"}}) {
		t.Errorf("security group relations = %v", got)
	}
}

func TestCollectRelationsStayInTheirProject(t *testing.T) {
	t.Parallel()
	// The same IDs in two projects (KPS numbers key pairs per project):
	// each server relates only to the VPC in its own project.
	other := "fedcba9876543210fedcba9876543210"
	snap := collect(t, Options{Reporters: []Reporter{reports(
		inProject(ECSServers, "1", Ref{IsContainedIn, VPCs, "1"}),
		inProject(VPCs, "1"),
		Resource{Type: VPCs, ID: "1", RegionID: region, ProjectID: other},
		Resource{Type: IAMGroups, ID: "g", Relations: []Ref{{Contains, IAMUsers, "u"}}},
		Resource{Type: IAMUsers, ID: "u"},
		// Relations of one type sort by the other's type, then ID.
		inProject(ELBLoadBalancers, "lb",
			Ref{IsAttachedTo, ELBPools, "p2"}, Ref{IsAttachedTo, EIPPublicIPs, "ip"}, Ref{IsAttachedTo, ELBPools, "p1"}),
		inProject(ELBPools, "p1"), inProject(ELBPools, "p2"), inProject(EIPPublicIPs, "ip"),
	)}})
	if len(snap.Resources) != 9 {
		t.Fatalf("%d resources, want 9", len(snap.Resources))
	}
	wantLB := []Ref{{IsAttachedTo, ELBPools, "p1"}, {IsAttachedTo, ELBPools, "p2"}, {IsAttachedTo, EIPPublicIPs, "ip"}}
	if got := find(t, snap, ELBLoadBalancers, "lb").Relations; !reflect.DeepEqual(got, wantLB) {
		t.Errorf("load balancer relations = %v\nwant %v", got, wantLB)
	}
	for _, r := range snap.Resources {
		if r.Type == VPCs && r.ProjectID == other && len(r.Relations) != 0 {
			t.Errorf("the other project's VPC has relations %v", r.Relations)
		}
	}
	if got := find(t, snap, IAMUsers, "u").Relations; !reflect.DeepEqual(got, []Ref{{IsContainedIn, IAMGroups, "g"}}) {
		t.Errorf("user relations = %v", got)
	}
}

func TestCollectRejectsInvalidReports(t *testing.T) {
	t.Parallel()
	cases := map[string]Resource{
		"unknown type":              {Type: Type{"ecs", "servers"}, ID: "x", RegionID: region, ProjectID: project},
		"no ID":                     {Type: VPCs, RegionID: region, ProjectID: project},
		"project type, no region":   {Type: VPCs, ID: "x", ProjectID: project},
		"project type, global":      {Type: VPCs, ID: "x", RegionID: GlobalRegion, ProjectID: project},
		"project type, no project":  {Type: VPCs, ID: "x", RegionID: region},
		"region type, a project":    {Type: OBSBuckets, ID: "x", RegionID: region, ProjectID: project},
		"region type, no region":    {Type: OBSBuckets, ID: "x"},
		"region type, global":       {Type: OBSBuckets, ID: "x", RegionID: GlobalRegion},
		"global type, a region":     {Type: IAMUsers, ID: "x", RegionID: region},
		"global type, a project":    {Type: IAMUsers, ID: "x", ProjectID: project},
		"unknown state":             {Type: VPCs, ID: "x", RegionID: region, ProjectID: project, State: "ACTIVE"},
		"unknown relationship":      inProject(ECSServers, "x", Ref{"uses", VPCs, "v"}),
		"undocumented relationship": inProject(VPCs, "x", Ref{Contains, VPCSubnets, "s"}),
		"relationship, wrong way":   inProject(ECSServers, "x", Ref{Contains, VPCs, "v"}),
		"relationship without ID":   inProject(ECSServers, "x", Ref{IsContainedIn, VPCs, ""}),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := New(Options{Reporters: []Reporter{reports(r)}}).Collect(t.Context())
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Collect: err = %v, want ErrInvalid", err)
			}
		})
	}

	t.Run("reported twice", func(t *testing.T) {
		t.Parallel()
		_, err := New(Options{Reporters: []Reporter{reports(inProject(VPCs, "x")), reports(inProject(VPCs, "x"))}}).Collect(t.Context())
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("Collect: err = %v, want ErrInvalid", err)
		}
	})
}

func TestCollectErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	failing := reporterFunc(func(context.Context, func(Resource) error) error { return boom })
	if _, err := New(Options{Reporters: []Reporter{reports(inProject(VPCs, "x")), failing}}).Collect(t.Context()); !errors.Is(err, boom) {
		t.Errorf("a reporter's error: Collect err = %v, want boom", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := New(Options{Reporters: []Reporter{reports(inProject(VPCs, "x"))}}).Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: Collect err = %v, want context.Canceled", err)
	}
	if _, err := New(Options{}).Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled, no reporters: Collect err = %v, want context.Canceled", err)
	}

	// A reporter that stops at emit's error returns it.
	var after int
	stops := reporterFunc(func(_ context.Context, emit func(Resource) error) error {
		if err := emit(Resource{Type: VPCs}); err != nil {
			return err
		}
		after++
		return nil
	})
	if _, err := New(Options{Reporters: []Reporter{stops}}).Collect(t.Context()); !errors.Is(err, ErrInvalid) || after != 0 {
		t.Errorf("Collect err = %v, emits after the error = %d; want ErrInvalid and 0", err, after)
	}
}

func TestCollectEmpty(t *testing.T) {
	t.Parallel()
	snap := collect(t, Options{})
	if len(snap.Resources) != 0 {
		t.Errorf("Resources = %v, want none", snap.Resources)
	}
	if got := snap.Select(Filter{}); got == nil || len(got) != 0 {
		t.Errorf("Select = %#v, want an empty, non-nil slice", got)
	}
}

func TestSelect(t *testing.T) {
	t.Parallel()
	snap := collect(t, Options{
		Reporters: []Reporter{reports(
			inProject(VPCs, "a"),
			Resource{Type: VPCs, ID: "b", RegionID: "r2", ProjectID: "p2", EnterpriseProjectID: "ep"},
			inProject(ECSServers, "c"),
			Resource{Type: IAMUsers, ID: "u", AccountID: account},
		)},
		Owner: func(p, _ string) (string, bool) { return account, p == project },
	})
	ids := func(rs []Resource) string {
		var out []string
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		f    Filter
		want string
	}{
		{Filter{}, "c,u,a,b"},
		{Filter{Type: VPCs}, "a,b"},
		{Filter{AccountID: account}, "c,u,a"},
		{Filter{RegionID: "r2"}, "b"},
		{Filter{RegionID: GlobalRegion}, "u"},
		{Filter{ProjectID: project}, "c,a"},
		{Filter{EnterpriseProjectID: "ep"}, "b"},
		{Filter{EnterpriseProjectID: DefaultEnterpriseProject, Type: VPCs}, "a"},
		{Filter{ID: "c"}, "c"},
		{Filter{ID: "c", Type: VPCs}, ""},
	}
	for _, c := range cases {
		if got := ids(snap.Select(c.f)); got != c.want {
			t.Errorf("Select(%+v) = %q, want %q", c.f, got, c.want)
		}
	}
}
