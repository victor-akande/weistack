package actions

import (
	"regexp"
	"testing"
)

// actionRE is the documented form, service:resourceType:operation; IAM's
// own access-key actions leave the resource type empty (iam::createAccessKey).
var actionRE = regexp.MustCompile(`^[a-z]+:[a-zA-Z]*:[a-zA-Z0-9]+$`)

func TestCatalogue(t *testing.T) {
	t.Parallel()
	for _, a := range All() {
		if !actionRE.MatchString(a.Name) {
			t.Errorf("malformed action %q", a.Name)
		}
		for _, al := range a.Aliases {
			if !actionRE.MatchString(al) {
				t.Errorf("%s: malformed alias %q", a.Name, al)
			}
		}
		if a.Level < List || a.Level > PermissionManagement {
			t.Errorf("%s: no access level", a.Name)
		}
		if got := MustLookup(a.Name); got.Name != a.Name {
			t.Errorf("Lookup(%q) = %q", a.Name, got.Name)
		}
	}
	if _, ok := Lookup("vpc:vpcs:fly"); ok {
		t.Error("Lookup found an unknown action")
	}
	// Spot checks against the documented tables.
	a := MustLookup("ecs:cloudServers:createServers")
	if len(a.Aliases) != 1 || a.Aliases[0] != "ecs:cloudServers:create" || a.Level != Write {
		t.Errorf("createServers = %+v", a)
	}
	if a := MustLookup("ecs:cloudServers:batchCreateServerTags"); len(a.Aliases) != 2 {
		t.Errorf("batchCreateServerTags aliases = %v", a.Aliases)
	}
	if a := MustLookup("obs:object:getObject"); a.Resource != "object" || a.Level != Read {
		t.Errorf("getObject = %+v", a)
	}
}

func TestMustLookupPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	MustLookup("vpc:vpcs:fly")
}
