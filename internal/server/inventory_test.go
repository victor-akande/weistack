package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/inventory"
)

// reportingService is a service that holds fixed resources.
type reportingService struct {
	*fakeService
	resources []inventory.Resource
}

func (s reportingService) ReportResources(_ context.Context, emit func(inventory.Resource) error) error {
	for _, r := range s.resources {
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}

func inventoryHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()
	created := time.Date(2026, 11, 24, 9, 30, 15, 500, time.FixedZone("UTC+8", 8*3600))
	vpc := reportingService{&fakeService{name: "vpc"}, []inventory.Resource{
		{Type: inventory.VPCs, ID: "vpc-1", Name: "prod", RegionID: "ap-southeast-1", ProjectID: testProject,
			Created: created, Tags: map[string]string{"env": "prod"}},
		{Type: inventory.VPCs, ID: "vpc-2", RegionID: "eu-west-101", ProjectID: "other"},
	}}
	ecs := reportingService{&fakeService{name: "ecs"}, []inventory.Resource{
		{Type: inventory.ECSServers, ID: "srv-1", Name: "web", RegionID: "ap-southeast-1", ProjectID: testProject,
			State:     inventory.Processing,
			Relations: []inventory.Ref{{Relation: inventory.IsContainedIn, Type: inventory.VPCs, ID: "vpc-1"}}},
	}}
	// A service that reports nothing is no different from one that holds
	// nothing.
	return newHarness(t, mutate, vpc, ecs, &fakeService{name: "ims"})
}

func TestInventory(t *testing.T) {
	t.Parallel()
	h := inventoryHarness(t, nil)
	res := h.do(t, http.MethodGet, "/_weistack/inventory", nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	want := `{"resources":[` +
		`{"id":"srv-1","name":"web","provider":"ecs","type":"cloudservers","account_id":"","region_id":"ap-southeast-1",` +
		`"project_id":"` + testProject + `","ep_id":"0","provisioning_state":"Processing","tags":{},"relations":[` +
		`{"relation_type":"isContainedIn","from_resource_type":"ecs.cloudservers","to_resource_type":"vpc.vpcs",` +
		`"from_resource_id":"srv-1","to_resource_id":"vpc-1"}]},` +
		`{"id":"vpc-1","name":"prod","provider":"vpc","type":"vpcs","account_id":"","region_id":"ap-southeast-1",` +
		`"project_id":"` + testProject + `","ep_id":"0","created":"2026-11-24T01:30:15Z","updated":"2026-11-24T01:30:15Z",` +
		`"provisioning_state":"Succeeded","tags":{"env":"prod"},"relations":[` +
		`{"relation_type":"contains","from_resource_type":"vpc.vpcs","to_resource_type":"ecs.cloudservers",` +
		`"from_resource_id":"vpc-1","to_resource_id":"srv-1"}]},` +
		`{"id":"vpc-2","name":"","provider":"vpc","type":"vpcs","account_id":"","region_id":"eu-west-101",` +
		`"project_id":"other","ep_id":"0","provisioning_state":"Succeeded","tags":{},"relations":[]}` +
		`],"count":3}`
	if got := readBody(t, res); got != want {
		t.Fatalf("inventory = %s\nwant %s", got, want)
	}
}

func TestInventoryFilters(t *testing.T) {
	t.Parallel()
	h := inventoryHarness(t, nil)
	for query, want := range map[string][]string{
		"":                                {"srv-1", "vpc-1", "vpc-2"},
		"?type=vpc.vpcs":                  {"vpc-1", "vpc-2"},
		"?region_id=eu-west-101":          {"vpc-2"},
		"?project_id=" + testProject:      {"srv-1", "vpc-1"},
		"?type=vpc.vpcs&id=vpc-1":         {"vpc-1"},
		"?ep_id=0&type=ecs.cloudservers":  {"srv-1"},
		"?account_id=nobody":              {},
		"?type=evs.volumes":               {},
		"?id=vpc-1&region_id=eu-west-101": {},
	} {
		res := h.do(t, http.MethodGet, "/_weistack/inventory"+query, nil, nil)
		var body struct {
			Resources []struct {
				ID string `json:"id"`
			} `json:"resources"`
			Count *int `json:"count"`
		}
		readJSON(t, res, &body)
		var got []string
		for _, r := range body.Resources {
			got = append(got, r.ID)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") || body.Count == nil || *body.Count != len(want) || body.Resources == nil {
			t.Errorf("GET inventory%s = %v (count %v), want %v", query, got, body.Count, want)
		}
	}

	for _, typ := range []string{"vpc", "ecs.servers", "VPC.vpcs"} {
		res := h.do(t, http.MethodGet, "/_weistack/inventory?type="+typ, nil, nil)
		body := readBody(t, res)
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "WeiStack.0400") || res.Header.Get("X-WeiStack-Hint") == "" {
			t.Errorf("type=%s: %d %s (hint %q), want 400 WeiStack.0400 with a hint", typ, res.StatusCode, body, res.Header.Get("X-WeiStack-Hint"))
		}
	}
}

func TestInventoryLeavesOutDisabledServices(t *testing.T) {
	t.Parallel()
	h := inventoryHarness(t, func(c *config.Config) { c.Services = []string{"vpc"} })
	res := h.do(t, http.MethodGet, "/_weistack/inventory", nil, nil)
	body := readBody(t, res)
	if strings.Contains(body, "srv-1") || !strings.Contains(body, `"count":2`) {
		t.Fatalf("inventory with ecs disabled = %s", body)
	}
	// Without the server, the VPC has no relationship left.
	if strings.Contains(body, "isContainedIn") || strings.Contains(body, `"contains"`) {
		t.Fatalf("a relationship to a disabled service's resource: %s", body)
	}
}

func TestInventoryInvalidReport(t *testing.T) {
	t.Parallel()
	bad := reportingService{&fakeService{name: "vpc"}, []inventory.Resource{
		{Type: inventory.VPCs, ID: "vpc-secret-cause", RegionID: "ap-southeast-1"},
	}}
	h := newHarness(t, nil, bad)
	res := h.do(t, http.MethodGet, "/_weistack/inventory", nil, nil)
	body := readBody(t, res)
	if res.StatusCode != http.StatusInternalServerError || strings.Contains(body, "vpc-secret-cause") {
		t.Fatalf("an invalid report: %d %s; want 500 without the cause", res.StatusCode, body)
	}
	if !strings.Contains(h.logs.String(), "vpc-secret-cause") {
		t.Fatal("the cause was not logged")
	}
}

func TestInventoryEmpty(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	res := h.do(t, http.MethodGet, "/_weistack/inventory", nil, nil)
	if got, want := readBody(t, res), `{"resources":[],"count":0}`; got != want {
		t.Fatalf("inventory = %s, want %s", got, want)
	}
}

// ownerAccounts says which account owns each project; its other methods
// are not called.
type ownerAccounts struct {
	accountsAPI
	owners map[string]string // project ID@region: account ID
}

type accountsAPI = Accounts

func (a ownerAccounts) ProjectOwner(projectID, region string) (string, bool) {
	id, ok := a.owners[projectID+"@"+region]
	return id, ok
}

func TestInventoryAccounts(t *testing.T) {
	t.Parallel()
	h := inventoryHarness(t, nil)
	// The same services, with the accounts of IAM.
	var err error
	h.srv, err = New(Options{
		Config: h.srv.cfg, ProjectID: testProject, Logger: h.srv.log, Store: h.store, Engine: h.engine,
		IDs: h.srv.ids, Services: servicesOf(h.srv),
		Accounts: ownerAccounts{owners: map[string]string{testProject + "@ap-southeast-1": "acct-1"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := h.do(t, http.MethodGet, "/_weistack/inventory?account_id=acct-1", nil, nil)
	body := readBody(t, res)
	if !strings.Contains(body, `"count":2`) || !strings.Contains(body, `"id":"srv-1"`) || !strings.Contains(body, `"id":"vpc-1"`) {
		t.Fatalf("inventory of acct-1 = %s, want srv-1 and vpc-1", body)
	}
	res = h.do(t, http.MethodGet, "/_weistack/inventory?id=vpc-2", nil, nil)
	if body := readBody(t, res); !strings.Contains(body, `"account_id":""`) {
		t.Fatalf("a project no account owns = %s, want no account", body)
	}
}

func servicesOf(s *Server) []Service {
	var out []Service
	for _, name := range s.names {
		out = append(out, s.services[name].svc)
	}
	return out
}

// eipReporter stands for a service hosted on VPC's host: it reports an
// EIP attached to the harness's server.
var eipReporter = reportingService{&fakeService{name: "eip"}, []inventory.Resource{
	{Type: inventory.EIPPublicIPs, ID: "eip-1", RegionID: "ap-southeast-1", ProjectID: testProject,
		Relations: []inventory.Ref{{Relation: inventory.IsAttachedTo, Type: inventory.ECSServers, ID: "srv-1"}}},
}}

// withHosted rebuilds h's server with hosted reporters.
func withHosted(t *testing.T, h *harness, hosted map[string][]inventory.Reporter, mutate func(*config.Config)) error {
	t.Helper()
	cfg := h.srv.cfg
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(Options{
		Config: cfg, ProjectID: testProject, Logger: h.srv.log, Store: h.store, Engine: h.engine,
		IDs: h.srv.ids, Services: servicesOf(h.srv), HostedReporters: hosted,
	})
	if err == nil {
		h.srv = srv
	}
	return err
}

func TestInventoryHostedReporters(t *testing.T) {
	t.Parallel()
	h := inventoryHarness(t, nil)
	if err := withHosted(t, h, map[string][]inventory.Reporter{"vpc": {eipReporter}}, nil); err != nil {
		t.Fatalf("New: %v", err)
	}
	res := h.do(t, http.MethodGet, "/_weistack/inventory?type=ecs.cloudservers", nil, nil)
	body := readBody(t, res)
	// The server, mounted, relates to the EIP, hosted.
	if !strings.Contains(body, `"to_resource_type":"vpc.publicips","from_resource_id":"srv-1","to_resource_id":"eip-1"`) {
		t.Fatalf("the server lacks its hosted EIP: %s", body)
	}
	res = h.do(t, http.MethodGet, "/_weistack/inventory", nil, nil)
	if body := readBody(t, res); !strings.Contains(body, `"count":4`) {
		t.Fatalf("inventory = %s, want the 3 mounted resources and the hosted EIP", body)
	}
}

func TestInventoryHostedOnADisabledService(t *testing.T) {
	t.Parallel()
	h := inventoryHarness(t, nil)
	err := withHosted(t, h, map[string][]inventory.Reporter{"vpc": {eipReporter}},
		func(c *config.Config) { c.Services = []string{"ecs"} })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := h.do(t, http.MethodGet, "/_weistack/inventory", nil, nil)
	if body := readBody(t, res); strings.Contains(body, "eip-1") || !strings.Contains(body, `"count":1`) {
		t.Fatalf("with VPC disabled, inventory = %s; want only the server", body)
	}
}

func TestInventoryHostedOnAServiceWithoutReports(t *testing.T) {
	t.Parallel()
	// The host itself need not report anything (ims reports nothing here).
	h := inventoryHarness(t, nil)
	if err := withHosted(t, h, map[string][]inventory.Reporter{"ims": {eipReporter}}, nil); err != nil {
		t.Fatalf("New: %v", err)
	}
	res := h.do(t, http.MethodGet, "/_weistack/inventory?type=vpc.publicips", nil, nil)
	if body := readBody(t, res); !strings.Contains(body, `"id":"eip-1"`) {
		t.Fatalf("inventory = %s, want the EIP", body)
	}
}

func TestInventoryHostedErrors(t *testing.T) {
	t.Parallel()
	h := inventoryHarness(t, nil)
	if err := withHosted(t, h, map[string][]inventory.Reporter{"nosuch": {eipReporter}}, nil); err == nil || !strings.Contains(err.Error(), "nosuch") {
		t.Fatalf("a reporter hosted on an unknown service: err = %v", err)
	}

	// A mounted service listed as hosted too reports everything twice,
	// which the inventory refuses.
	h = inventoryHarness(t, nil)
	vpc := servicesOf(h.srv)[2] // ecs, ims, vpc
	rep, ok := vpc.(inventory.Reporter)
	if !ok || vpc.Name() != "vpc" {
		t.Fatalf("services = %v", servicesOf(h.srv))
	}
	if err := withHosted(t, h, map[string][]inventory.Reporter{"vpc": {rep}}, nil); err != nil {
		t.Fatalf("New: %v", err)
	}
	res := h.do(t, http.MethodGet, "/_weistack/inventory", nil, nil)
	if res.StatusCode != http.StatusInternalServerError || !strings.Contains(h.logs.String(), "reported twice") {
		t.Fatalf("a service reported twice: %d; logs %s", res.StatusCode, h.logs.String())
	}
}
