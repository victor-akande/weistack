package vpc

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const docsSecGroupBody = `{"security_group": {"name": "security_group_1", "description": "security group description"}}`

func docsRuleBody(groupID string) string {
	return fmt.Sprintf(`{"security_group_rule": {
		"security_group_id": %q, "direction": "ingress", "protocol": "tcp",
		"description": "security group rule description", "action": "allow", "priority": 1,
		"multiport": "33", "remote_ip_prefix": "10.10.0.0/16"}}`, groupID)
}

func (e *env) mustCreateSecGroup(t *testing.T, name string) SecurityGroupInfo {
	t.Helper()
	status, out := e.call3(t, http.MethodPost, "/security-groups", fmt.Sprintf(`{"security_group": {"name": %q}}`, name))
	if status != http.StatusCreated {
		t.Fatalf("creating security group %q: %d %s", name, status, out)
	}
	return decodeInto[securityGroupResponse](t, out).SecurityGroup
}

func TestSecurityGroupLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	out := e.expect3(t, "create_security_group", http.MethodPost, "/security-groups", docsSecGroupBody)
	g := decodeInto[securityGroupResponse](t, out).SecurityGroup

	// The two ingress rules refer to the group itself.
	for _, r := range g.SecurityGroupRules {
		self := r.RemoteGroupID != nil && *r.RemoteGroupID == g.ID
		if (r.Direction == "ingress") != self {
			t.Errorf("default %s %s rule: remote_group_id = %v", r.Direction, r.Ethertype, r.RemoteGroupID)
		}
		if r.SecurityGroupID != g.ID {
			t.Errorf("default rule belongs to %s, want %s", r.SecurityGroupID, g.ID)
		}
	}

	e.expect3(t, "show_security_group", http.MethodGet, "/security-groups/"+g.ID, "")
	// Every project also owns a "default" group.
	e.expect3(t, "list_security_groups", http.MethodGet, "/security-groups", "")
	e.expect3(t, "list_security_groups_page", http.MethodGet, "/security-groups?limit=1", "")
	e.expect3(t, "update_security_group", http.MethodPut, "/security-groups/"+g.ID,
		`{"security_group": {"name": "security_group_2"}}`)

	e.expect3(t, "delete_security_group", http.MethodDelete, "/security-groups/"+g.ID, "")
	e.expect3(t, "error_secgroup_not_found", http.MethodGet, "/security-groups/"+g.ID, "")
	e.expect3(t, "error_secgroup_not_found", http.MethodDelete, "/security-groups/"+g.ID, "")
	e.expect3(t, "error_secgroup_not_found", http.MethodPut, "/security-groups/"+g.ID, `{"security_group": {"name": "x"}}`)

	// Its rules went with it.
	rules, err := e.svc.ListSecurityGroupRules(t.Context(), testTenant, ListSecurityGroupRulesFilter{SecurityGroupIDs: []string{g.ID}})
	if err != nil || len(rules) != 0 {
		t.Fatalf("%d rules of a deleted group remain (err %v)", len(rules), err)
	}
}

func TestSecurityGroupRuleLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	g := e.mustCreateSecGroup(t, "web")

	out := e.expect3(t, "create_security_group_rule", http.MethodPost, "/security-group-rules", docsRuleBody(g.ID))
	rule := decodeInto[securityGroupRuleResponse](t, out).SecurityGroupRule

	e.expect3(t, "show_security_group_rule", http.MethodGet, "/security-group-rules/"+rule.ID, "")
	e.expect3(t, "list_security_group_rules", http.MethodGet, "/security-group-rules?protocol=tcp", "")
	e.expect3(t, "list_security_group_rules_empty", http.MethodGet, "/security-group-rules?protocol=udp", "")

	// The same rule again is a conflict.
	e.expect3(t, "error_secgroup_conflict", http.MethodPost, "/security-group-rules", docsRuleBody(g.ID))

	// The group now shows five rules.
	info, err := e.svc.GetSecurityGroup(t.Context(), testTenant, g.ID)
	if err != nil || len(info.SecurityGroupRules) != 5 {
		t.Fatalf("group has %d rules (err %v), want 5", len(info.SecurityGroupRules), err)
	}

	e.expect3(t, "delete_security_group", http.MethodDelete, "/security-group-rules/"+rule.ID, "")
	e.expect3(t, "error_secgroup_not_found", http.MethodGet, "/security-group-rules/"+rule.ID, "")
	e.expect3(t, "error_secgroup_not_found", http.MethodDelete, "/security-group-rules/"+rule.ID, "")
}

func TestDryRunValidatesWithoutCreating(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	g := e.mustCreateSecGroup(t, "web")

	e.expect3(t, "dry_run", http.MethodPost, "/security-groups", `{"dry_run": true, "security_group": {"name": "ghost"}}`)
	e.expect3(t, "error_secgroup_invalid", http.MethodPost, "/security-groups", `{"dry_run": true, "security_group": {"name": "a b"}}`)
	e.expect3(t, "dry_run", http.MethodPut, "/security-groups/"+g.ID, `{"dry_run": true, "security_group": {"name": "ghost"}}`)
	e.expect3(t, "error_secgroup_not_found", http.MethodPut, "/security-groups/"+testUnknownID, `{"dry_run": true, "security_group": {"name": "ghost"}}`)

	ruleBody := strings.Replace(docsRuleBody(g.ID), `{"security_group_rule"`, `{"dry_run": true, "security_group_rule"`, 1)
	e.expect3(t, "dry_run", http.MethodPost, "/security-group-rules", ruleBody)

	groups, _ := e.svc.ListSecurityGroups(t.Context(), testTenant, ListSecurityGroupsFilter{})
	if len(groups) != 2 || groups[1].Name != "web" {
		t.Fatalf("dry runs changed the groups: %+v", groups)
	}
	rules, _ := e.svc.ListSecurityGroupRules(t.Context(), testTenant, ListSecurityGroupRulesFilter{SecurityGroupIDs: []string{g.ID}})
	if len(rules) != 4 {
		t.Fatalf("dry run created a rule: %d rules, want 4", len(rules))
	}
}

func TestCreateSecurityGroupValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	tags := make([]string, 21)
	for i := range tags {
		tags[i] = fmt.Sprintf(`{"key": "k%d", "value": "v"}`, i)
	}
	for name, body := range map[string]string{
		"empty body":         ``,
		"missing object":     `{}`,
		"missing name":       `{"security_group": {}}`,
		"bad name":           `{"security_group": {"name": "a/b"}}`,
		"name too long":      `{"security_group": {"name": "` + strings.Repeat("n", 65) + `"}}`,
		"bad description":    `{"security_group": {"name": "a", "description": "<x>"}}`,
		"bad enterprise id":  `{"security_group": {"name": "a", "enterprise_project_id": "x"}}`,
		"too many tags":      `{"security_group": {"name": "a", "tags": [` + strings.Join(tags, ",") + `]}}`,
		"duplicate tag keys": `{"security_group": {"name": "a", "tags": [{"key": "k", "value": "1"}, {"key": "k", "value": "2"}]}}`,
		"empty tag key":      `{"security_group": {"name": "a", "tags": [{"key": "", "value": "1"}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			e.expect3(t, "error_secgroup_invalid", http.MethodPost, "/security-groups", body)
		})
	}

	status, out := e.call3(t, http.MethodPost, "/security-groups", `{"security_group": {
		"name": "tagged", "enterprise_project_id": "0aad99bc-f5f6-4f78-8404-c598d76b0ed2",
		"tags": [{"key": "env", "value": "prod"}]}}`)
	if status != http.StatusCreated {
		t.Fatalf("create with tags: %d %s", status, out)
	}
	g := decodeInto[securityGroupResponse](t, out).SecurityGroup
	if len(g.Tags) != 1 || g.Tags[0] != (Tag{Key: "env", Value: "prod"}) || g.EnterpriseProjectID == "0" {
		t.Fatalf("created = %+v", g)
	}

	// Group names need not be unique.
	e.mustCreateSecGroup(t, "tagged")

	for name, body := range map[string]string{
		"missing object":  `{}`,
		"bad name":        `{"security_group": {"name": ""}}`,
		"bad description": `{"security_group": {"description": ">"}}`,
		"malformed":       `{`,
	} {
		t.Run("update "+name, func(t *testing.T) {
			e.expect3(t, "error_secgroup_invalid", http.MethodPut, "/security-groups/"+g.ID, body)
		})
	}
	if status, out := e.call3(t, http.MethodPut, "/security-groups/"+g.ID, `{"security_group": {"description": "new"}}`); status != http.StatusOK {
		t.Fatalf("description-only update: %d %s", status, out)
	}
	if got, _ := e.svc.GetSecurityGroup(t.Context(), testTenant, g.ID); got.Description != "new" || got.Name != "tagged" {
		t.Fatalf("after update: %+v", got.SecurityGroup)
	}
}

func TestDefaultSecurityGroup(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	groups, err := e.svc.ListSecurityGroups(t.Context(), testTenant, ListSecurityGroupsFilter{})
	if err != nil || len(groups) != 1 || groups[0].Name != "default" {
		t.Fatalf("a fresh project lists %+v (err %v), want only the default group", groups, err)
	}
	// It is created once, not on every call.
	groups, _ = e.svc.ListSecurityGroups(t.Context(), testTenant, ListSecurityGroupsFilter{})
	if len(groups) != 1 {
		t.Fatalf("default group duplicated: %d groups", len(groups))
	}
	info, _ := e.svc.GetSecurityGroup(t.Context(), testTenant, groups[0].ID)
	if len(info.SecurityGroupRules) != 4 {
		t.Fatalf("default group has %d rules, want 4", len(info.SecurityGroupRules))
	}
	e.expect3(t, "error_secgroup_conflict", http.MethodDelete, "/security-groups/"+groups[0].ID, "")
}

func TestCreateRuleValidationAndNormalisation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	g := e.mustCreateSecGroup(t, "web")
	other := e.mustCreateSecGroup(t, "db")

	rule := func(fields string) string {
		return fmt.Sprintf(`{"security_group_rule": {"security_group_id": %q, %s}}`, g.ID, fields)
	}

	invalid := map[string]string{
		"missing object":             `{}`,
		"missing group":              `{"security_group_rule": {"direction": "ingress"}}`,
		"missing direction":          rule(`"protocol": "tcp"`),
		"bad direction":              rule(`"direction": "sideways"`),
		"bad ethertype":              rule(`"direction": "ingress", "ethertype": "IPX"`),
		"bad protocol":               rule(`"direction": "ingress", "protocol": "smtp"`),
		"protocol number too large":  rule(`"direction": "ingress", "protocol": "256"`),
		"icmp over ipv6":             rule(`"direction": "ingress", "protocol": "icmp", "ethertype": "IPv6"`),
		"icmpv6 over ipv4":           rule(`"direction": "ingress", "protocol": "icmpv6"`),
		"multiport without protocol": rule(`"direction": "ingress", "multiport": "80"`),
		"multiport with icmp":        rule(`"direction": "ingress", "protocol": "icmp", "multiport": "80"`),
		"port zero":                  rule(`"direction": "ingress", "protocol": "tcp", "multiport": "0"`),
		"port too large":             rule(`"direction": "ingress", "protocol": "tcp", "multiport": "65536"`),
		"reversed range":             rule(`"direction": "ingress", "protocol": "tcp", "multiport": "30-1"`),
		"port not a number":          rule(`"direction": "ingress", "protocol": "tcp", "multiport": "http"`),
		"empty list item":            rule(`"direction": "ingress", "protocol": "tcp", "multiport": "22,,80"`),
		"bad prefix":                 rule(`"direction": "ingress", "remote_ip_prefix": "ten.zero"`),
		"prefix family mismatch":     rule(`"direction": "ingress", "remote_ip_prefix": "2001:db8::/32"`),
		"two remotes":                rule(`"direction": "ingress", "remote_ip_prefix": "10.0.0.0/8", "remote_group_id": "` + other.ID + `"`),
		"bad action":                 rule(`"direction": "ingress", "action": "log"`),
		"priority zero":              rule(`"direction": "ingress", "priority": 0`),
		"priority too large":         rule(`"direction": "ingress", "priority": 101`),
		"bad description":            rule(`"direction": "ingress", "description": "<"`),
	}
	for name, body := range invalid {
		t.Run(name, func(t *testing.T) {
			e.expect3(t, "error_secgroup_invalid", http.MethodPost, "/security-group-rules", body)
		})
	}

	notFound := map[string]string{
		"unknown group":         `{"security_group_rule": {"security_group_id": "` + testUnknownID + `", "direction": "ingress"}}`,
		"unknown remote group":  rule(`"direction": "ingress", "remote_group_id": "` + testUnknownID + `"`),
		"unknown address group": rule(`"direction": "ingress", "remote_address_group_id": "` + testUnknownID + `"`),
	}
	for name, body := range notFound {
		t.Run(name, func(t *testing.T) {
			e.expect3(t, "error_secgroup_not_found", http.MethodPost, "/security-group-rules", body)
		})
	}

	create := func(fields string) SecurityGroupRule {
		t.Helper()
		status, out := e.call3(t, http.MethodPost, "/security-group-rules", rule(fields))
		if status != http.StatusCreated {
			t.Fatalf("create rule {%s}: %d %s", fields, status, out)
		}
		return decodeInto[securityGroupRuleResponse](t, out).SecurityGroupRule
	}
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}

	// Defaults.
	r := create(`"direction": "egress", "remote_ip_prefix": "8.8.8.8"`)
	if r.Ethertype != "IPv4" || r.Action != "allow" || r.Priority != 1 || !r.Enabled || r.Protocol != nil || r.Multiport != nil {
		t.Errorf("defaults: %+v", r)
	}
	// A bare address gains a full mask; host bits are cleared.
	if got := str(r.RemoteIPPrefix); got != "8.8.8.8/32" {
		t.Errorf("bare address normalised to %q, want 8.8.8.8/32", got)
	}
	r = create(`"direction": "ingress", "protocol": "TCP", "multiport": "22,80,8000-8100", "remote_ip_prefix": "10.1.2.3/16", "ethertype": "ipv4", "action": "DENY", "priority": 50, "enabled": false`)
	if str(r.Protocol) != "tcp" || str(r.RemoteIPPrefix) != "10.1.0.0/16" || r.Ethertype != "IPv4" || r.Action != "deny" || r.Priority != 50 || r.Enabled {
		t.Errorf("normalisation: %+v", r)
	}
	r = create(`"direction": "ingress", "ethertype": "IPv6", "protocol": "icmpv6", "remote_ip_prefix": "2001:db8::1"`)
	if str(r.RemoteIPPrefix) != "2001:db8::1/128" {
		t.Errorf("IPv6 bare address normalised to %q", str(r.RemoteIPPrefix))
	}
	create(`"direction": "ingress", "protocol": "47"`)
	r = create(`"direction": "ingress", "protocol": "udp", "multiport": "53", "remote_group_id": "` + other.ID + `"`)
	if str(r.RemoteGroupID) != other.ID {
		t.Errorf("remote group: %+v", r)
	}

	// Same traffic at a different priority is a different rule.
	create(`"direction": "ingress", "protocol": "47", "priority": 2`)
	e.expect3(t, "error_secgroup_conflict", http.MethodPost, "/security-group-rules", rule(`"direction": "ingress", "protocol": "47"`))

	// Deleting the remote group removes the rule that points at it.
	e.expect3(t, "delete_security_group", http.MethodDelete, "/security-groups/"+other.ID, "")
	e.expect3(t, "error_secgroup_not_found", http.MethodGet, "/security-group-rules/"+r.ID, "")
}

func TestListSecurityGroupFiltersAndPaging(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	web := e.mustCreateSecGroup(t, "web")
	db := e.mustCreateSecGroup(t, "db")
	e.mustCreateSecGroup(t, "web")

	names := func(query string) string {
		t.Helper()
		status, out := e.call3(t, http.MethodGet, "/security-groups"+query, "")
		if status != http.StatusOK {
			t.Fatalf("list %s: %d %s", query, status, out)
		}
		res := decodeInto[listSecurityGroupsResponse](t, out)
		if res.PageInfo.CurrentCount != len(res.SecurityGroups) {
			t.Errorf("list %s: current_count %d for %d groups", query, res.PageInfo.CurrentCount, len(res.SecurityGroups))
		}
		var ns []string
		for _, g := range res.SecurityGroups {
			ns = append(ns, g.Name)
		}
		next := ""
		if res.PageInfo.NextMarker != nil {
			next = " next"
		}
		return strings.Join(ns, ",") + next
	}

	tests := []struct{ query, want string }{
		{"", "default,web,db,web"},
		{"?name=web", "web,web"},
		{"?name=web&name=db", "web,db,web"},
		{"?id=" + db.ID, "db"},
		{"?id=" + db.ID + "&id=" + web.ID, "web,db"},
		{"?description=Default+security+group", "default"},
		{"?enterprise_project_id=0", "default,web,db,web"},
		{"?enterprise_project_id=0aad99bc-f5f6-4f78-8404-c598d76b0ed2", ""},
		{"?limit=2", "default,web next"},
		{"?limit=2&marker=" + web.ID, "db,web"},
		{"?limit=1&marker=" + web.ID, "db next"},
		{"?limit=0", ""},
	}
	for _, tt := range tests {
		if got := names(tt.query); got != tt.want {
			t.Errorf("list %q = %q, want %q", tt.query, got, tt.want)
		}
	}
	e.expect3(t, "error_secgroup_invalid", http.MethodGet, "/security-groups?limit=2001", "")
	e.expect3(t, "error_secgroup_invalid", http.MethodGet, "/security-groups?marker="+testUnknownID, "")
}

func TestListSecurityGroupRuleFilters(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	g := e.mustCreateSecGroup(t, "web")
	mk := func(fields string) {
		t.Helper()
		body := fmt.Sprintf(`{"security_group_rule": {"security_group_id": %q, %s}}`, g.ID, fields)
		if status, out := e.call3(t, http.MethodPost, "/security-group-rules", body); status != http.StatusCreated {
			t.Fatalf("create: %d %s", status, out)
		}
	}
	mk(`"direction": "ingress", "protocol": "tcp", "multiport": "22", "remote_ip_prefix": "10.0.0.0/8", "description": "ssh"`)
	mk(`"direction": "ingress", "protocol": "udp", "multiport": "53", "priority": 7, "action": "deny"`)
	mk(`"direction": "egress", "protocol": "tcp", "multiport": "443", "enabled": false`)

	count := func(query string) int {
		t.Helper()
		status, out := e.call3(t, http.MethodGet, "/security-group-rules?security_group_id="+g.ID+query, "")
		if status != http.StatusOK {
			t.Fatalf("list %s: %d %s", query, status, out)
		}
		return len(decodeInto[listSecurityGroupRulesResponse](t, out).SecurityGroupRules)
	}
	tests := []struct {
		query string
		want  int
	}{
		{"", 7}, // 4 default + 3
		{"&protocol=tcp", 2},
		{"&protocol=tcp&protocol=udp", 3},
		{"&direction=egress", 3},
		{"&direction=egress&protocol=tcp", 1},
		{"&action=deny", 1},
		{"&priority=7", 1},
		{"&priority=7&priority=100", 5},
		{"&ethertype=IPv6", 2},
		{"&description=ssh", 1},
		{"&remote_ip_prefix=10.0.0.0/8", 1},
		{"&remote_group_id=" + g.ID, 2},
		{"&remote_address_group_id=" + testUnknownID, 0},
		{"&enabled=false", 1},
		{"&enabled=true", 6},
		{"&limit=3", 3},
	}
	for _, tt := range tests {
		if got := count(tt.query); got != tt.want {
			t.Errorf("list %q returned %d rules, want %d", tt.query, got, tt.want)
		}
	}
	// Filtering on another group's ID returns nothing from this one.
	if status, out := e.call3(t, http.MethodGet, "/security-group-rules?security_group_id="+testUnknownID, ""); status != 200 ||
		len(decodeInto[listSecurityGroupRulesResponse](t, out).SecurityGroupRules) != 0 {
		t.Errorf("unknown group filter: %d %s", status, out)
	}
	e.expect3(t, "error_secgroup_invalid", http.MethodGet, "/security-group-rules?priority=high", "")
	e.expect3(t, "error_secgroup_invalid", http.MethodGet, "/security-group-rules?enabled=perhaps", "")
	e.expect3(t, "error_secgroup_invalid", http.MethodGet, "/security-group-rules?limit=-1", "")
}

// Many clients touching security groups in a brand-new project at once
// must still end up with exactly one default group.
func TestDefaultGroupIsCreatedOnceUnderConcurrency(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()

	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				if _, err := e.svc.ListSecurityGroups(ctx, testTenant, ListSecurityGroupsFilter{}); err != nil {
					t.Errorf("list: %v", err)
				}
				return
			}
			if _, err := e.svc.CreateSecurityGroup(ctx, testTenant, CreateSecurityGroupOption{Name: "g"}, false); err != nil {
				t.Errorf("create: %v", err)
			}
		}()
	}
	wg.Wait()

	defaults, err := e.svc.ListSecurityGroups(ctx, testTenant, ListSecurityGroupsFilter{Names: []string{"default"}})
	if err != nil || len(defaults) != 1 {
		t.Fatalf("%d default groups (err %v), want 1", len(defaults), err)
	}
	all, _ := e.svc.ListSecurityGroups(ctx, testTenant, ListSecurityGroupsFilter{})
	if len(all) != 21 {
		t.Fatalf("%d groups, want 21", len(all))
	}
}

func TestTimeZJSON(t *testing.T) {
	t.Parallel()
	var tz TimeZ
	if err := tz.UnmarshalJSON([]byte(`"2020-07-09T05:56:27Z"`)); err != nil {
		t.Fatal(err)
	}
	if b, _ := tz.MarshalJSON(); string(b) != `"2020-07-09T05:56:27Z"` {
		t.Fatalf("round trip = %s", b)
	}
	for _, bad := range []string{`7`, `"2020-07-09T05:56:27"`, `"x"`} {
		if err := tz.UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("UnmarshalJSON(%s) succeeded", bad)
		}
	}
}
