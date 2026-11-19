package faults

import (
	"errors"
	"testing"
)

func TestCheck(t *testing.T) {
	t.Parallel()
	for _, r := range []Rule{
		{Type: "chaos"},
		{Type: TypeLifecycle},
		{Type: TypeLifecycle, Transition: "Ecs.Server"},
		{Type: TypeLifecycle, Transition: "ecs.server.build", Status: 500},
		{Type: TypeLifecycle, Transition: "ecs.server.build", Times: -1},
		{Type: TypeRequest},
		{Type: TypeRequest, Service: "vpc"},
		{Type: TypeRequest, Service: "vpc", Status: 200},
		{Type: TypeRequest, Service: "vpc", Status: 503, Path: "v1/x"},
		{Type: TypeRequest, Service: "vpc", Status: 503, Path: "/[x"},
		{Type: TypeRequest, Service: "vpc", DelayMS: MaxDelayMS + 1},
		{Type: TypeRequest, Service: "vpc", DelayMS: 10, Code: "X"},
		{Type: TypeRequest, Service: "vpc", Status: 503, Transition: "x"},
	} {
		if err := Check(r); !errors.Is(err, ErrInvalid) {
			t.Errorf("Check(%+v) = %v", r, err)
		}
	}
	for _, r := range []Rule{
		{Type: TypeLifecycle, Transition: "ecs.server.*"},
		{Type: TypeLifecycle, Transition: "*", Resource: "abc", Times: 0},
		{Type: TypeRequest, Service: "vpc", Status: 429, Path: "/v1/*/vpcs", Method: "post"},
		{Type: TypeRequest, Service: "vpc", DelayMS: 50},
	} {
		if err := Check(r); err != nil {
			t.Errorf("Check(%+v) = %v", r, err)
		}
	}
}

func TestLifecycleFaults(t *testing.T) {
	t.Parallel()
	g := New(nil)
	if _, err := g.Add(Rule{Type: TypeLifecycle, Transition: "ecs.server.*", Resource: "srv-1", Times: 2}); err != nil {
		t.Fatal(err)
	}
	if g.Fault("ecs.server.build", "srv-2") != nil || g.Fault("rds.instance.create", "srv-1") != nil {
		t.Error("a fault applied to another resource or kind")
	}
	if g.Fault("ecs.server.build", "srv-1") == nil || g.Fault("ecs.server.reboot", "srv-1") == nil {
		t.Error("the fault did not apply twice")
	}
	if g.Fault("ecs.server.build", "srv-1") != nil || len(g.List()) != 0 {
		t.Error("a spent fault applied again or stayed listed")
	}
	// Until removed.
	r, _ := g.Add(Rule{Type: TypeLifecycle, Transition: "*", Times: 0})
	for range 5 {
		if g.Fault("vpc.vpc.create", "x") == nil {
			t.Fatal("a standing fault stopped")
		}
	}
	if l := g.List(); len(l) != 1 || l[0].Hits != 5 || l[0].Remaining != -1 {
		t.Errorf("list = %+v", l)
	}
	if !g.Remove(r.ID) || g.Remove(r.ID) || g.Fault("vpc.vpc.create", "x") != nil {
		t.Error("Remove")
	}
}

func TestRequestFaults(t *testing.T) {
	t.Parallel()
	g := New(nil)
	if _, err := g.Add(Rule{Type: TypeRequest, Service: "vpc", Method: "post", Path: "/v1/*/vpcs", Status: 429, Times: 1}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ svc, method, path string }{
		{"ecs", "POST", "/v1/p/vpcs"}, {"vpc", "GET", "/v1/p/vpcs"}, {"vpc", "POST", "/v1/p/subnets"}, {"vpc", "POST", "/v1/p/vpcs/x"},
	} {
		if _, ok := g.Request(c.svc, c.method, c.path); ok {
			t.Errorf("matched %+v", c)
		}
	}
	if r, ok := g.Request("vpc", "POST", "/v1/p/vpcs"); !ok || r.Status != 429 || r.Remaining != 0 {
		t.Errorf("Request = %+v, %v", r, ok)
	}
	if _, ok := g.Request("vpc", "POST", "/v1/p/vpcs"); ok {
		t.Error("a spent fault applied again")
	}
	mustAdd(t, g, Rule{Type: TypeRequest, Service: "obs", Status: 503, Times: 3})
	g.Clear()
	if len(g.List()) != 0 {
		t.Error("Clear")
	}
	for range MaxRules {
		if _, err := g.Add(Rule{Type: TypeRequest, Service: "obs", Status: 503}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.Add(Rule{Type: TypeRequest, Service: "obs", Status: 503}); !errors.Is(err, ErrInvalid) {
		t.Errorf("rule %d = %v", MaxRules+1, err)
	}
}

func mustAdd(t *testing.T, g *Registry, r Rule) Rule {
	t.Helper()
	added, err := g.Add(r)
	if err != nil {
		t.Fatalf("Add(%+v) = %v", r, err)
	}
	return added
}
