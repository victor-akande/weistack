package iam

import (
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/actions"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
)

// systemAllows reports whether the named system permission allows an
// action, with its catalogued aliases.
func systemAllows(t *testing.T, display, action string) bool {
	t.Helper()
	var doc []byte
	for _, ro := range catalogue {
		if ro.DisplayName == display {
			doc = ro.Policy
		}
	}
	if doc == nil {
		t.Fatalf("no system permission %q", display)
	}
	p, err := policydoc.Parse(doc)
	if err != nil {
		t.Fatalf("%s: %v", display, err)
	}
	a := actions.MustLookup(action)
	return policydoc.Evaluate(policydoc.Request{Action: a.Name, Aliases: a.Aliases}, []policydoc.Source{{Name: display, Policy: p}}).Allowed
}

// checkMatrix checks permissions against a documented "supported
// operations" table: each row is an action and, per permission, whether
// Huawei lists it as supported.
func checkMatrix(t *testing.T, perms []string, rows map[string][]bool) {
	t.Helper()
	for action, want := range rows {
		for i, perm := range perms {
			if got := systemAllows(t, perm, action); got != want[i] {
				t.Errorf("%s allows %s = %v, documented %v", perm, action, got, want[i])
			}
		}
	}
}

// The ECS table (productdesc-ecs ecs_01_0059): creating, querying,
// modifying, starting, stopping, restarting and deleting ECSs, querying
// their disks and NICs, and adding tags.
func TestSystemRolesECSMatrix(t *testing.T) {
	t.Parallel()
	checkMatrix(t, []string{"ECS FullAccess", "ECS CommonOperations", "ECS ReadOnlyAccess", "Server Administrator"}, map[string][]bool{
		"ecs:cloudServers:createServers":               {true, false, false, true},
		"ecs:cloudServers:listServersDetails":          {true, true, true, true},
		"ecs:cloudServers:showServer":                  {true, true, true, true},
		"ecs:cloudServers:updateServer":                {true, false, false, true},
		"ecs:cloudServers:start":                       {true, true, false, true},
		"ecs:cloudServers:stop":                        {true, true, false, true},
		"ecs:cloudServers:reboot":                      {true, true, false, true},
		"ecs:cloudServers:deleteServers":               {true, false, false, true},
		"ecs:cloudServers:listServerVolumeAttachments": {true, true, true, true},
		"ecs:cloudServers:batchCreateServerTags":       {true, true, false, true},
		"ecs:cloudServers:resize":                      {true, false, false, true},
	})
}

// The KPS table (DEW's permissions, Table 5): read-only may read key
// pairs and tasks, and nothing else.
func TestSystemRolesKPSMatrix(t *testing.T) {
	t.Parallel()
	checkMatrix(t, []string{"DEW KeypairFullAccess", "DEW KeypairReadOnlyAccess"}, map[string][]bool{
		"kps:SSHKeyPair:create":           {true, false},
		"kps:SSHKeyPair:list":             {true, true},
		"kps:SSHKeyPair:get":              {true, true},
		"kps:SSHKeyPair:update":           {true, false},
		"kps:SSHKeyPair:delete":           {true, false},
		"kps:SSHKeyPair:importPrivateKey": {true, false},
		"kps:SSHKeyPair:exportPrivateKey": {true, false},
		"kps:SSHKeyPair:clearPrivateKey":  {true, false},
		"kps:SSHKeyPair:bind":             {true, false},
		"kps:SSHKeyPair:unbind":           {true, false},
		"kps::getTask":                    {true, true},
		"kps::getRunningTask":             {true, true},
		"kps::getFailedTask":              {true, true},
		"kps::deleteFailedTask":           {true, false},
	})
	// Every KPS action is in the table, and neither policy grants another
	// service's.
	for _, a := range actions.All() {
		kps := ofService(a, "kps")
		if got := systemAllows(t, "DEW KeypairFullAccess", a.Name); got != kps {
			t.Errorf("DEW KeypairFullAccess allows %s = %v", a.Name, got)
		}
		read := a.Level == actions.List || a.Level == actions.Read
		if got := systemAllows(t, "DEW KeypairReadOnlyAccess", a.Name); got != (kps && read) {
			t.Errorf("DEW KeypairReadOnlyAccess allows %s (%s) = %v", a.Name, a.Level, got)
		}
	}
}

// The VPC table (productdesc-vpc overview_permission): VPC Administrator
// has everything but security groups and their rules.
func TestSystemRolesVPCMatrix(t *testing.T) {
	t.Parallel()
	checkMatrix(t, []string{"VPC ReadOnlyAccess", "VPC Administrator", "VPC FullAccess"}, map[string][]bool{
		"vpc:vpcs:create":               {false, true, true},
		"vpc:vpcs:update":               {false, true, true},
		"vpc:vpcs:delete":               {false, true, true},
		"vpc:vpcs:get":                  {true, true, true},
		"vpc:vpcs:list":                 {true, true, true},
		"vpc:subnets:create":            {false, true, true},
		"vpc:subnets:list":              {true, true, true},
		"vpc:subnets:update":            {false, true, true},
		"vpc:subnets:delete":            {false, true, true},
		"vpc:securityGroups:create":     {false, false, true},
		"vpc:securityGroups:get":        {true, false, true},
		"vpc:securityGroups:update":     {false, false, true},
		"vpc:securityGroups:delete":     {false, false, true},
		"vpc:securityGroupRules:create": {false, false, true},
		"vpc:securityGroupRules:get":    {true, false, true},
		"vpc:securityGroupRules:delete": {false, false, true},
	})
}

// The OBS permissions (usermanual-permissions iam_01_0001): Buckets
// Viewer lists buckets and reads their metadata and location;
// ReadOnlyAccess also lists objects; OperateAccess also uploads,
// downloads and deletes objects and reads object ACLs.
func TestSystemRolesOBSMatrix(t *testing.T) {
	t.Parallel()
	checkMatrix(t, []string{"OBS Buckets Viewer", "OBS ReadOnlyAccess", "OBS OperateAccess", "OBS Administrator"}, map[string][]bool{
		"obs:bucket:listAllMyBuckets":  {true, true, true, true},
		"obs:bucket:headBucket":        {true, true, true, true},
		"obs:bucket:getBucketLocation": {true, true, true, true},
		"obs:bucket:listBucket":        {false, true, true, true},
		"obs:object:getObject":         {false, false, true, true},
		"obs:object:putObject":         {false, false, true, true},
		"obs:object:deleteObject":      {false, false, true, true},
		"obs:bucket:createBucket":      {false, false, false, true},
		"obs:bucket:deleteBucket":      {false, false, false, true},
		"obs:bucket:getBucketAcl":      {false, false, false, true},
	})
}

// ofService reports whether a classic permission of svc covers an action:
// its name is the service's, or one of its classic aliases is. EIP's
// actions (eip:publicIps:*) keep the classic names vpc:publicIps:*, so
// VPC's system permissions grant them, as on Huawei Cloud.
func ofService(a actions.Action, svc string) bool {
	if strings.HasPrefix(a.Name, svc+":") {
		return true
	}
	for _, alias := range a.Aliases {
		if strings.HasPrefix(alias, svc+":") {
			return true
		}
	}
	return false
}

// ReadOnlyAccess permissions allow exactly the documented list and read
// actions of their service; FullAccess allows every action of it and no
// other service's. An action of another service whose classic alias is
// this service's counts as this service's.
func TestSystemRolesByAccessLevel(t *testing.T) {
	t.Parallel()
	for svc, names := range map[string][2]string{
		"ecs": {"ECS ReadOnlyAccess", "ECS FullAccess"},
		"evs": {"EVS ReadOnlyAccess", "EVS FullAccess"},
		"ims": {"IMS ReadOnlyAccess", "IMS FullAccess"},
		"vpc": {"VPC ReadOnlyAccess", "VPC FullAccess"},
		"rds": {"RDS ReadOnlyAccess", "RDS FullAccess"},
	} {
		for _, a := range actions.All() {
			inService := ofService(a, svc)
			read := a.Level == actions.List || a.Level == actions.Read
			if got := systemAllows(t, names[0], a.Name); got != (inService && read) {
				t.Errorf("%s allows %s (%s) = %v", names[0], a.Name, a.Level, got)
			}
			if got := systemAllows(t, names[1], a.Name); got != inService {
				t.Errorf("%s allows %s = %v", names[1], a.Name, got)
			}
		}
	}
}

// The account-wide roles: Tenant Administrator has every service but
// IAM, Tenant Guest reads every service but IAM, Security Administrator
// has IAM, and FullAccess has everything.
func TestSystemRolesAccountWide(t *testing.T) {
	t.Parallel()
	for _, a := range actions.All() {
		iam := a.Name[:4] == "iam:"
		read := a.Level == actions.List || a.Level == actions.Read
		if got := systemAllows(t, "Tenant Administrator", a.Name); got == iam {
			t.Errorf("Tenant Administrator allows %s = %v", a.Name, got)
		}
		if got := systemAllows(t, "Security Administrator", a.Name); got != iam {
			t.Errorf("Security Administrator allows %s = %v", a.Name, got)
		}
		if !systemAllows(t, "FullAccess", a.Name) {
			t.Errorf("FullAccess denies %s", a.Name)
		}
		// Tenant Guest covers the services it names; STS's one action
		// is a write.
		if a.Name[:4] == "sts:" {
			continue
		}
		if got := systemAllows(t, "Tenant Guest", a.Name); got != (!iam && read) {
			t.Errorf("Tenant Guest allows %s (%s) = %v", a.Name, a.Level, got)
		}
	}
}
