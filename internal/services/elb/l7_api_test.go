package elb

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestL7PolicyHTTPLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)

	// Empty list.
	e.expect(t, "l7policies", "list_l7policies_empty", http.MethodGet, "/l7policies", "")

	// Create REDIRECT_TO_POOL policy with inline PATH rule and priority.
	outPool := e.expect(t, "l7policies", "create_l7policy_pool", http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "policy-pool-1",
			"description": "route api traffic",
			"listener_id": %q,
			"action": "REDIRECT_TO_POOL",
			"redirect_pool_id": %q,
			"priority": 10,
			"position": 5,
			"rules": [
				{
					"type": "PATH",
					"compare_type": "STARTS_WITH",
					"value": "/api"
				}
			]
		}
	}`, e.enhLsnID, e.httpPoolID))
	poolPolID := l7DecodeInto[l7PolicyEnvelope](t, outPool).L7Policy.ID

	// Show and list.
	e.expect(t, "l7policies", "show_l7policy", http.MethodGet, "/l7policies/"+poolPolID, "")
	e.expect(t, "l7policies", "list_l7policies", http.MethodGet, "/l7policies?id="+poolPolID, "")

	// Update policy (name, description, priority, redirect_pools_config with string weight).
	e.expect(t, "l7policies", "update_l7policy", http.MethodPut, "/l7policies/"+poolPolID, fmt.Sprintf(`{
		"l7policy": {
			"name": "policy-pool-updated",
			"description": "updated route",
			"priority": 20,
			"redirect_pools_config": [
				{"pool_id": %q, "weight": "75"},
				{"pool_id": %q, "weight": 25}
			]
		}
	}`, e.httpPoolID, e.grpcPoolID))

	// Create REDIRECT_TO_LISTENER policy.
	outLsn := e.expect(t, "l7policies", "create_l7policy_listener", http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "policy-https-redirect",
			"listener_id": %q,
			"action": "REDIRECT_TO_LISTENER",
			"redirect_listener_id": %q
		}
	}`, e.httpLsnID, e.httpsLsnID))
	lsnPolID := l7DecodeInto[l7PolicyEnvelope](t, outLsn).L7Policy.ID

	// Create REDIRECT_TO_URL policy.
	outURL := e.expect(t, "l7policies", "create_l7policy_url", http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "policy-url-redirect",
			"listener_id": %q,
			"action": "REDIRECT_TO_URL",
			"redirect_url_config": {
				"protocol": "HTTPS",
				"host": "new.example.com",
				"port": "443",
				"path": "/moved",
				"query": "${query}&from=elb",
				"status_code": "301"
			}
		}
	}`, e.enhLsnID))
	urlPolID := l7DecodeInto[l7PolicyEnvelope](t, outURL).L7Policy.ID

	// Create FIXED_RESPONSE policy.
	outFixed := e.expect(t, "l7policies", "create_l7policy_fixed", http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "policy-fixed-resp",
			"listener_id": %q,
			"action": "FIXED_RESPONSE",
			"fixed_response_config": {
				"status_code": "200",
				"content_type": "application/json",
				"message_body": "{\"ok\":true}"
			}
		}
	}`, e.enhLsnID))
	fixedPolID := l7DecodeInto[l7PolicyEnvelope](t, outFixed).L7Policy.ID

	// Delete policies (204).
	e.expect(t, "l7policies", "delete_l7policy", http.MethodDelete, "/l7policies/"+poolPolID, "")
	e.expect(t, "l7policies", "delete_l7policy", http.MethodDelete, "/l7policies/"+lsnPolID, "")
	e.expect(t, "l7policies", "delete_l7policy", http.MethodDelete, "/l7policies/"+urlPolID, "")
	e.expect(t, "l7policies", "delete_l7policy", http.MethodDelete, "/l7policies/"+fixedPolID, "")

	// Deleted policy returns ELB.8904 on show, update, delete.
	e.expect(t, "l7policies", "error_not_found", http.MethodGet, "/l7policies/"+poolPolID, "")
	e.expect(t, "l7policies", "error_not_found", http.MethodPut, "/l7policies/"+poolPolID, `{"l7policy": {"name": "gone"}}`)
	e.expect(t, "l7policies", "error_not_found", http.MethodDelete, "/l7policies/"+poolPolID, "")
}

func TestL7PolicyHTTPErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)

	// Seed a policy with priority 1 on enhanced listener to trigger ELB.8907.
	st, raw := e.call(t, http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "prio-seed",
			"listener_id": %q,
			"action": "REDIRECT_TO_POOL",
			"redirect_pool_id": %q,
			"priority": 1
		}
	}`, e.enhLsnID, e.httpPoolID))
	if st != http.StatusCreated {
		t.Fatalf("seed policy: %d %s", st, raw)
	}
	seedID := l7DecodeInto[l7PolicyEnvelope](t, raw).L7Policy.ID

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		golden string
	}{
		{"malformed json", http.MethodPost, "/l7policies", `{`, "error_invalid_input"},
		{"missing l7policy wrapper", http.MethodPost, "/l7policies", `{}`, "error_invalid_input"},
		{"invalid action", http.MethodPost, "/l7policies", fmt.Sprintf(`{"l7policy": {"listener_id": %q, "action": "BAD"}}`, e.httpLsnID), "error_invalid_input"},
		{"tcp listener rejected", http.MethodPost, "/l7policies", fmt.Sprintf(`{"l7policy": {"listener_id": %q, "action": "REDIRECT_TO_POOL", "redirect_pool_id": %q}}`, e.tcpLsnID, e.httpPoolID), "error_invalid_input"},
		{"priority on non-enhanced listener", http.MethodPost, "/l7policies", fmt.Sprintf(`{"l7policy": {"listener_id": %q, "action": "REDIRECT_TO_POOL", "redirect_pool_id": %q, "priority": 1}}`, e.httpLsnID, e.httpPoolID), "error_invalid_input"},
		{"unknown listener", http.MethodPost, "/l7policies", fmt.Sprintf(`{"l7policy": {"listener_id": %q, "action": "REDIRECT_TO_POOL", "redirect_pool_id": %q}}`, l7TestUnknownUUID, e.httpPoolID), "error_not_found"},
		{"unknown pool", http.MethodPost, "/l7policies", fmt.Sprintf(`{"l7policy": {"listener_id": %q, "action": "REDIRECT_TO_POOL", "redirect_pool_id": %q}}`, e.httpLsnID, l7TestUnknownUUID), "error_not_found"},
		{"duplicate priority conflict", http.MethodPost, "/l7policies", fmt.Sprintf(`{"l7policy": {"listener_id": %q, "action": "REDIRECT_TO_POOL", "redirect_pool_id": %q, "priority": 1}}`, e.enhLsnID, e.httpPoolID), "error_conflict"},
		{"duplicate inline rule type conflict", http.MethodPost, "/l7policies", fmt.Sprintf(`{"l7policy": {"listener_id": %q, "action": "REDIRECT_TO_POOL", "redirect_pool_id": %q, "rules": [{"type": "PATH", "compare_type": "EQUAL_TO", "value": "/a"}, {"type": "PATH", "compare_type": "EQUAL_TO", "value": "/b"}]}}`, e.enhLsnID, e.httpPoolID), "error_conflict"},
		{"update malformed json", http.MethodPut, "/l7policies/" + seedID, `{`, "error_invalid_input"},
		{"update missing wrapper", http.MethodPut, "/l7policies/" + seedID, `{}`, "error_invalid_input"},
		{"update null redirect_pool_id", http.MethodPut, "/l7policies/" + seedID, `{"l7policy": {"redirect_pool_id": null}}`, "error_invalid_input"},
		{"list invalid limit", http.MethodGet, "/l7policies?limit=0", "", "error_invalid_input"},
		{"list invalid marker", http.MethodGet, "/l7policies?marker=" + l7TestUnknownUUID, "", "error_invalid_input"},
		{"list invalid priority", http.MethodGet, "/l7policies?priority=abc", "", "error_invalid_input"},
		{"list invalid admin_state_up", http.MethodGet, "/l7policies?admin_state_up=maybe", "", "error_invalid_input"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "l7policies", tc.golden, tc.method, tc.path, tc.body)
		})
	}
}

func TestL7PolicyHTTPListFilters(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)

	// Create a policy on lb2's HTTPS listener (custom EP).
	st, raw := e.call(t, http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "pol-filter",
			"description": "filter desc",
			"listener_id": %q,
			"action": "REDIRECT_TO_POOL",
			"redirect_pool_id": %q,
			"priority": 7
		}
	}`, e.lb2HttpsID, e.lb2PoolID))
	if st != http.StatusCreated {
		t.Fatalf("create policy: %d %s", st, raw)
	}
	pol := l7DecodeInto[l7PolicyEnvelope](t, raw).L7Policy

	q := url.Values{}
	q.Set("id", pol.ID)
	q.Set("name", "pol-filter")
	q.Set("description", "filter desc")
	q.Set("admin_state_up", "true")
	q.Set("listener_id", e.lb2HttpsID)
	q.Set("position", "100")
	q.Set("action", "REDIRECT_TO_POOL")
	q.Set("redirect_pool_id", e.lb2PoolID)
	q.Set("provisioning_status", StatusActive)
	q.Set("priority", "7")
	q.Set("display_all_rules", "true")
	q.Set("enterprise_project_id", l7TestCustomEP)

	st, out := e.call(t, http.MethodGet, "/l7policies?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("list policies: %d %s", st, out)
	}
	listed := l7DecodeInto[l7ListPoliciesResponse](t, out)
	if len(listed.L7Policies) != 1 || listed.L7Policies[0].ID != pol.ID {
		t.Fatalf("filtered policies = %+v, want [%s]", listed.L7Policies, pol.ID)
	}

	// all_granted_eps also matches.
	st, out = e.call(t, http.MethodGet, "/l7policies?enterprise_project_id="+allGrantedEPs, "")
	if st != http.StatusOK {
		t.Fatalf("list all_granted_eps: %d %s", st, out)
	}
	if len(l7DecodeInto[l7ListPoliciesResponse](t, out).L7Policies) != 1 {
		t.Fatalf("expected 1 policy with all_granted_eps")
	}
}

func TestL7RuleHTTPLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)

	// Seed a policy to attach rules to.
	st, raw := e.call(t, http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "rules-host-policy",
			"listener_id": %q,
			"action": "REDIRECT_TO_POOL",
			"redirect_pool_id": %q
		}
	}`, e.enhLsnID, e.httpPoolID))
	if st != http.StatusCreated {
		t.Fatalf("seed policy: %d %s", st, raw)
	}
	polID := l7DecodeInto[l7PolicyEnvelope](t, raw).L7Policy.ID

	// Empty lists (per-policy and project-wide /l7policies/rules).
	e.expect(t, "l7rules", "list_l7rules_empty", http.MethodGet, "/l7policies/"+polID+"/rules", "")
	e.expect(t, "l7rules", "list_all_l7rules_empty", http.MethodGet, "/l7policies/rules", "")

	// Create PATH rule (201).
	rawPath := e.expect(t, "l7rules", "create_l7rule_path", http.MethodPost, "/l7policies/"+polID+"/rules", `{
		"rule": {
			"type": "PATH",
			"compare_type": "EQUAL_TO",
			"value": "/v1/orders"
		}
	}`)
	pathRuleID := l7DecodeInto[l7RuleEnvelope](t, rawPath).Rule.ID

	// Create HEADER rule with conditions (201).
	rawHdr := e.expect(t, "l7rules", "create_l7rule_header_conditions", http.MethodPost, "/l7policies/"+polID+"/rules", `{
		"rule": {
			"type": "HEADER",
			"compare_type": "EQUAL_TO",
			"conditions": [
				{"key": "X-Env", "value": "canary"},
				{"key": "X-Env", "value": "staging"}
			]
		}
	}`)
	hdrRuleID := l7DecodeInto[l7RuleEnvelope](t, rawHdr).Rule.ID

	// Show PATH rule (200).
	e.expect(t, "l7rules", "show_l7rule", http.MethodGet, "/l7policies/"+polID+"/rules/"+pathRuleID, "")

	// Update PATH rule (200).
	e.expect(t, "l7rules", "update_l7rule", http.MethodPut, "/l7policies/"+polID+"/rules/"+pathRuleID, `{
		"rule": {
			"compare_type": "STARTS_WITH",
			"value": "/v2/orders"
		}
	}`)

	// List rules on policy (200) — filter by id for deterministic order.
	e.expect(t, "l7rules", "list_l7rules", http.MethodGet, "/l7policies/"+polID+"/rules?id="+pathRuleID, "")

	// List all rules across project (200) — verifies /l7policies/rules route precedence.
	e.expect(t, "l7rules", "list_all_l7rules", http.MethodGet, "/l7policies/rules?id="+pathRuleID, "")

	// Delete rules (204).
	e.expect(t, "l7rules", "delete_l7rule", http.MethodDelete, "/l7policies/"+polID+"/rules/"+hdrRuleID, "")
	e.expect(t, "l7rules", "delete_l7rule", http.MethodDelete, "/l7policies/"+polID+"/rules/"+pathRuleID, "")

	// Deleted rule returns ELB.8904 on show, update, delete.
	e.expect(t, "l7rules", "error_not_found", http.MethodGet, "/l7policies/"+polID+"/rules/"+pathRuleID, "")
	e.expect(t, "l7rules", "error_not_found", http.MethodPut, "/l7policies/"+polID+"/rules/"+pathRuleID, `{"rule": {"value": "/v3"}}`)
	e.expect(t, "l7rules", "error_not_found", http.MethodDelete, "/l7policies/"+polID+"/rules/"+pathRuleID, "")
}

func TestL7RuleHTTPErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)

	st, raw := e.call(t, http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "rules-err-policy",
			"listener_id": %q,
			"action": "REDIRECT_TO_POOL",
			"redirect_pool_id": %q
		}
	}`, e.enhLsnID, e.httpPoolID))
	if st != http.StatusCreated {
		t.Fatalf("seed policy: %d %s", st, raw)
	}
	polID := l7DecodeInto[l7PolicyEnvelope](t, raw).L7Policy.ID

	st, raw = e.call(t, http.MethodPost, "/l7policies/"+polID+"/rules", `{
		"rule": {"type": "HOST_NAME", "compare_type": "EQUAL_TO", "value": "example.com"}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("seed rule: %d %s", st, raw)
	}
	ruleID := l7DecodeInto[l7RuleEnvelope](t, raw).Rule.ID

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		golden string
	}{
		{"malformed json", http.MethodPost, "/l7policies/" + polID + "/rules", `{`, "error_invalid_input"},
		{"missing rule wrapper", http.MethodPost, "/l7policies/" + polID + "/rules", `{}`, "error_invalid_input"},
		{"bad type", http.MethodPost, "/l7policies/" + polID + "/rules", `{"rule": {"type": "COOKIE", "compare_type": "EQUAL_TO", "value": "x"}}`, "error_invalid_input"},
		{"bad compare_type for METHOD", http.MethodPost, "/l7policies/" + polID + "/rules", `{"rule": {"type": "METHOD", "compare_type": "REGEX", "value": "GET"}}`, "error_invalid_input"},
		{"key forbidden on PATH", http.MethodPost, "/l7policies/" + polID + "/rules", `{"rule": {"type": "PATH", "compare_type": "EQUAL_TO", "key": "k", "value": "/a"}}`, "error_invalid_input"},
		{"key required on HEADER", http.MethodPost, "/l7policies/" + polID + "/rules", `{"rule": {"type": "HEADER", "compare_type": "EQUAL_TO", "value": "v"}}`, "error_invalid_input"},
		{"unknown policy on create", http.MethodPost, "/l7policies/" + l7TestUnknownUUID + "/rules", `{"rule": {"type": "PATH", "compare_type": "EQUAL_TO", "value": "/a"}}`, "error_not_found"},
		{"unknown policy on list", http.MethodGet, "/l7policies/" + l7TestUnknownUUID + "/rules", "", "error_not_found"},
		{"duplicate rule type conflict", http.MethodPost, "/l7policies/" + polID + "/rules", `{"rule": {"type": "HOST_NAME", "compare_type": "EQUAL_TO", "value": "other.com"}}`, "error_conflict"},
		{"update malformed json", http.MethodPut, "/l7policies/" + polID + "/rules/" + ruleID, `{`, "error_invalid_input"},
		{"update missing wrapper", http.MethodPut, "/l7policies/" + polID + "/rules/" + ruleID, `{}`, "error_invalid_input"},
		{"update invalid compare_type for HOST_NAME", http.MethodPut, "/l7policies/" + polID + "/rules/" + ruleID, `{"rule": {"compare_type": "REGEX"}}`, "error_invalid_input"},
		{"list invalid limit", http.MethodGet, "/l7policies/" + polID + "/rules?limit=0", "", "error_invalid_input"},
		{"list invalid marker", http.MethodGet, "/l7policies/" + polID + "/rules?marker=" + l7TestUnknownUUID, "", "error_invalid_input"},
		{"list all invalid limit", http.MethodGet, "/l7policies/rules?limit=2001", "", "error_invalid_input"},
		{"list all invalid invert", http.MethodGet, "/l7policies/rules?invert=maybe", "", "error_invalid_input"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "l7rules", tc.golden, tc.method, tc.path, tc.body)
		})
	}
}

func TestL7RuleHTTPListFilters(t *testing.T) {
	t.Parallel()
	e := l7NewTestEnv(t)

	st, raw := e.call(t, http.MethodPost, "/l7policies", fmt.Sprintf(`{
		"l7policy": {
			"name": "rule-filter-pol",
			"listener_id": %q,
			"action": "REDIRECT_TO_POOL",
			"redirect_pool_id": %q
		}
	}`, e.lb2HttpsID, e.lb2PoolID))
	if st != http.StatusCreated {
		t.Fatalf("create policy: %d %s", st, raw)
	}
	polID := l7DecodeInto[l7PolicyEnvelope](t, raw).L7Policy.ID

	st, raw = e.call(t, http.MethodPost, "/l7policies/"+polID+"/rules", `{
		"rule": {
			"type": "QUERY_STRING",
			"compare_type": "EQUAL_TO",
			"key": "region",
			"value": "sg*"
		}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("create rule: %d %s", st, raw)
	}
	rule := l7DecodeInto[l7RuleEnvelope](t, raw).Rule

	q := url.Values{}
	q.Set("id", rule.ID)
	q.Set("type", "QUERY_STRING")
	q.Set("compare_type", "EQUAL_TO")
	q.Set("provisioning_status", StatusActive)
	q.Set("invert", "false")
	q.Set("admin_state_up", "true")
	q.Set("key", "region")
	q.Set("value", "sg*")
	q.Set("enterprise_project_id", l7TestCustomEP)

	st, out := e.call(t, http.MethodGet, "/l7policies/"+polID+"/rules?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("list rules: %d %s", st, out)
	}
	resp := l7DecodeInto[l7ListRulesResponse](t, out)
	if len(resp.Rules) != 1 || resp.Rules[0].ID != rule.ID {
		t.Fatalf("list rules = %+v, want [%s]", resp.Rules, rule.ID)
	}

	q.Set("l7policy_id", polID)
	q.Set("enterprise_project_id", allGrantedEPs)
	st, out = e.call(t, http.MethodGet, "/l7policies/rules?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("list all rules: %d %s", st, out)
	}
	allResp := l7DecodeInto[l7ListRulesResponse](t, out)
	if len(allResp.Rules) != 1 || allResp.Rules[0].ID != rule.ID {
		t.Fatalf("list all rules = %+v, want [%s]", allResp.Rules, rule.ID)
	}
}
