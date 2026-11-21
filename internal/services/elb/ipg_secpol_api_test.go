package elb

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestIPGroupLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	e.expect(t, "ipgroups", "list_ipgroups_empty", http.MethodGet, "/ipgroups", "")

	out := e.expect(t, "ipgroups", "create_ipgroup", http.MethodPost, "/ipgroups", `{
		"ipgroup": {
			"name": "office-allowlist",
			"description": "corporate ingress",
			"ip_list": [
				{"ip": "192.168.1.123"},
				{"ip": "192.168.3.0/24", "description": "office subnet"}
			]
		}
	}`)
	id := ipgspDecodeInto[ipgEnvelope](t, out).IPGroup.ID

	e.expect(t, "ipgroups", "show_ipgroup", http.MethodGet, "/ipgroups/"+id, "")
	e.expect(t, "ipgroups", "list_ipgroups", http.MethodGet, "/ipgroups", "")

	e.expect(t, "ipgroups", "update_ipgroup", http.MethodPut, "/ipgroups/"+id, `{
		"ipgroup": {
			"name": "office-allowlist-updated",
			"description": "updated corporate ingress",
			"ip_list": [
				{"ip": "10.0.0.0/16", "description": "vpn range"}
			]
		}
	}`)

	// Bind an HTTP listener to the IP group and confirm listeners ref + delete guard (ELB.8907).
	st, rawLsn := e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "http-guarded",
			"protocol": "HTTP",
			"protocol_port": 80,
			"loadbalancer_id": %q,
			"ipgroup": {
				"ipgroup_id": %q,
				"type": "white",
				"enable_ipgroup": true
			}
		}
	}`, e.lbID, id))
	if st != http.StatusCreated {
		t.Fatalf("create listener: %d %s", st, rawLsn)
	}
	lsnID := ipgspDecodeInto[listenerEnvelope](t, rawLsn).Listener.ID

	e.expect(t, "ipgroups", "show_ipgroup_with_listener", http.MethodGet, "/ipgroups/"+id, "")
	e.expect(t, "ipgroups", "error_conflict", http.MethodDelete, "/ipgroups/"+id, "")

	// Delete the listener, then delete the IP group cleanly (204).
	if st, raw := e.call(t, http.MethodDelete, "/listeners/"+lsnID, ""); st != http.StatusNoContent {
		t.Fatalf("delete listener: %d %s", st, raw)
	}
	e.expect(t, "ipgroups", "delete_ipgroup", http.MethodDelete, "/ipgroups/"+id, "")

	// Deleted IP group returns ELB.8904 on show, update, delete.
	e.expect(t, "ipgroups", "error_not_found", http.MethodGet, "/ipgroups/"+id, "")
	e.expect(t, "ipgroups", "error_not_found", http.MethodPut, "/ipgroups/"+id, `{"ipgroup": {"name": "x"}}`)
	e.expect(t, "ipgroups", "error_not_found", http.MethodDelete, "/ipgroups/"+id, "")
}

func TestIPGroupErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	// Seed one IP group so we can also test update validation errors.
	st, raw := e.call(t, http.MethodPost, "/ipgroups", `{"ipgroup": {"name": "seed", "ip_list": [{"ip": "10.0.0.1"}]}}`)
	if st != http.StatusCreated {
		t.Fatalf("seed ipgroup: %d %s", st, raw)
	}
	seedID := ipgspDecodeInto[ipgEnvelope](t, raw).IPGroup.ID

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		golden string
	}{
		{"empty body", http.MethodPost, "/ipgroups", ``, "error_invalid_input"},
		{"malformed json", http.MethodPost, "/ipgroups", `{"ipgroup": `, "error_invalid_input"},
		{"missing wrapper", http.MethodPost, "/ipgroups", `{}`, "error_invalid_input"},
		{"missing ip_list", http.MethodPost, "/ipgroups", `{"ipgroup": {"name": "no-list"}}`, "error_invalid_input"},
		{"invalid ipv4", http.MethodPost, "/ipgroups", `{"ipgroup": {"ip_list": [{"ip": "999.1.1.1"}]}}`, "error_invalid_input"},
		{"non-canonical cidr", http.MethodPost, "/ipgroups", `{"ipgroup": {"ip_list": [{"ip": "192.168.1.5/24"}]}}`, "error_invalid_input"},
		{"ipv6 rejected", http.MethodPost, "/ipgroups", `{"ipgroup": {"ip_list": [{"ip": "2001:db8::1"}]}}`, "error_invalid_input"},
		{"duplicate ip", http.MethodPost, "/ipgroups", `{"ipgroup": {"ip_list": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.1"}]}}`, "error_invalid_input"},
		{"duplicate ip and /32", http.MethodPost, "/ipgroups", `{"ipgroup": {"ip_list": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.1/32"}]}}`, "error_invalid_input"},
		{"invalid enterprise_project_id", http.MethodPost, "/ipgroups", `{"ipgroup": {"ip_list": [], "enterprise_project_id": ""}}`, "error_invalid_input"},
		{"update missing wrapper", http.MethodPut, "/ipgroups/" + seedID, `{}`, "error_invalid_input"},
		{"update invalid ip_list", http.MethodPut, "/ipgroups/" + seedID, `{"ipgroup": {"ip_list": [{"ip": "bad"}]}}`, "error_invalid_input"},
		{"list invalid limit 0", http.MethodGet, "/ipgroups?limit=0", "", "error_invalid_input"},
		{"list invalid limit 2001", http.MethodGet, "/ipgroups?limit=2001", "", "error_invalid_input"},
		{"list unknown marker", http.MethodGet, "/ipgroups?marker=" + ipgspUnknownUUID, "", "error_invalid_input"},
		{"list invalid page_reverse", http.MethodGet, "/ipgroups?page_reverse=maybe", "", "error_invalid_input"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "ipgroups", tc.golden, tc.method, tc.path, tc.body)
		})
	}
}

func TestIPGroupListHTTPFilters(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	st, raw1 := e.call(t, http.MethodPost, "/ipgroups", fmt.Sprintf(`{
		"ipgroup": {
			"name": "ipg-alpha",
			"description": "alpha desc",
			"enterprise_project_id": %q,
			"ip_list": [
				{"ip": "192.168.10.1"},
				{"ip": "10.20.0.0/16"}
			]
		}
	}`, ipgspCustomEP))
	if st != http.StatusCreated {
		t.Fatalf("create ipg1: %d %s", st, raw1)
	}
	g1 := ipgspDecodeInto[ipgEnvelope](t, raw1).IPGroup

	st, raw2 := e.call(t, http.MethodPost, "/ipgroups", `{
		"ipgroup": {
			"name": "ipg-beta",
			"description": "beta desc",
			"ip_list": [{"ip": "172.16.0.0/12"}]
		}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("create ipg2: %d %s", st, raw2)
	}

	q := url.Values{}
	q.Add("id", g1.ID)
	q.Add("name", "ipg-alpha")
	q.Add("description", "alpha desc")
	q.Add("ip_list", "10.20.0.0/16")
	q.Add("enterprise_project_id", ipgspCustomEP)
	q.Set("page_reverse", "false")

	st, out := e.call(t, http.MethodGet, "/ipgroups?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("filtered list: %d %s", st, out)
	}
	listed := ipgspDecodeInto[ipgListResponse](t, out)
	if len(listed.IPGroups) != 1 || listed.IPGroups[0].ID != g1.ID || listed.PageInfo.CurrentCount != 1 {
		t.Fatalf("filtered list = %+v, want [%s]", listed, g1.ID)
	}

	// enterprise_project_id=all_granted_eps returns both IP groups.
	st, out = e.call(t, http.MethodGet, "/ipgroups?enterprise_project_id="+allGrantedEPs, "")
	if st != http.StatusOK {
		t.Fatalf("all_granted_eps list: %d %s", st, out)
	}
	listed = ipgspDecodeInto[ipgListResponse](t, out)
	if len(listed.IPGroups) != 2 || listed.PageInfo.CurrentCount != 2 {
		t.Fatalf("all_granted_eps count = %d, want 2", len(listed.IPGroups))
	}
}

func TestSecurityPolicyLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	e.expect(t, "security_policies", "list_security_policies_empty", http.MethodGet, "/security-policies", "")
	e.expect(t, "security_policies", "list_system_security_policies", http.MethodGet, "/system-security-policies", "")

	out := e.expect(t, "security_policies", "create_security_policy", http.MethodPost, "/security-policies", `{
		"security_policy": {
			"name": "strict-tls-policy",
			"description": "tls 1.2 and 1.3 only",
			"protocols": ["TLSv1.2", "TLSv1.3"],
			"ciphers": [
				"ECDHE-RSA-AES128-GCM-SHA256",
				"TLS_AES_128_GCM_SHA256",
				"TLS_AES_256_GCM_SHA384"
			]
		}
	}`)
	id := ipgspDecodeInto[secpolEnvelope](t, out).SecurityPolicy.ID

	e.expect(t, "security_policies", "show_security_policy", http.MethodGet, "/security-policies/"+id, "")
	e.expect(t, "security_policies", "list_security_policies", http.MethodGet, "/security-policies", "")

	e.expect(t, "security_policies", "update_security_policy", http.MethodPut, "/security-policies/"+id, `{
		"security_policy": {
			"name": "strict-tls-policy-v2",
			"description": "updated tls 1.3 policy",
			"protocols": ["TLSv1.3"],
			"ciphers": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
		}
	}`)

	// Bind an HTTPS listener to the custom security policy and confirm listeners ref + delete guard (ELB.8907).
	st, rawLsn := e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "https-guarded",
			"protocol": "HTTPS",
			"protocol_port": 443,
			"loadbalancer_id": %q,
			"default_tls_container_ref": %q,
			"security_policy_id": %q
		}
	}`, e.lbID, e.serverCertID, id))
	if st != http.StatusCreated {
		t.Fatalf("create https listener: %d %s", st, rawLsn)
	}
	lsnID := ipgspDecodeInto[listenerEnvelope](t, rawLsn).Listener.ID

	e.expect(t, "security_policies", "show_security_policy_with_listener", http.MethodGet, "/security-policies/"+id, "")
	e.expect(t, "security_policies", "error_conflict", http.MethodDelete, "/security-policies/"+id, "")

	// Delete the listener, then delete the security policy cleanly (204).
	if st, raw := e.call(t, http.MethodDelete, "/listeners/"+lsnID, ""); st != http.StatusNoContent {
		t.Fatalf("delete listener: %d %s", st, raw)
	}
	e.expect(t, "security_policies", "delete_security_policy", http.MethodDelete, "/security-policies/"+id, "")

	// Deleted security policy returns ELB.8904 on show, update, delete.
	e.expect(t, "security_policies", "error_not_found", http.MethodGet, "/security-policies/"+id, "")
	e.expect(t, "security_policies", "error_not_found", http.MethodPut, "/security-policies/"+id, `{"security_policy": {"name": "x"}}`)
	e.expect(t, "security_policies", "error_not_found", http.MethodDelete, "/security-policies/"+id, "")
}

func TestSecurityPolicyErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	st, raw := e.call(t, http.MethodPost, "/security-policies", `{
		"security_policy": {
			"name": "seed-sp",
			"protocols": ["TLSv1.2"],
			"ciphers": ["AES128-SHA"]
		}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("seed security policy: %d %s", st, raw)
	}
	seedID := ipgspDecodeInto[secpolEnvelope](t, raw).SecurityPolicy.ID

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		golden string
	}{
		{"empty body", http.MethodPost, "/security-policies", ``, "error_invalid_input"},
		{"malformed json", http.MethodPost, "/security-policies", `{"security_policy": `, "error_invalid_input"},
		{"missing wrapper", http.MethodPost, "/security-policies", `{}`, "error_invalid_input"},
		{"missing protocols", http.MethodPost, "/security-policies", `{"security_policy": {"ciphers": ["AES128-SHA"]}}`, "error_invalid_input"},
		{"empty protocols", http.MethodPost, "/security-policies", `{"security_policy": {"protocols": [], "ciphers": ["AES128-SHA"]}}`, "error_invalid_input"},
		{"invalid protocol", http.MethodPost, "/security-policies", `{"security_policy": {"protocols": ["SSLv3"], "ciphers": ["AES128-SHA"]}}`, "error_invalid_input"},
		{"duplicate protocol", http.MethodPost, "/security-policies", `{"security_policy": {"protocols": ["TLSv1.2", "TLSv1.2"], "ciphers": ["AES128-SHA"]}}`, "error_invalid_input"},
		{"missing ciphers", http.MethodPost, "/security-policies", `{"security_policy": {"protocols": ["TLSv1.2"]}}`, "error_invalid_input"},
		{"empty ciphers", http.MethodPost, "/security-policies", `{"security_policy": {"protocols": ["TLSv1.2"], "ciphers": []}}`, "error_invalid_input"},
		{"unknown cipher", http.MethodPost, "/security-policies", `{"security_policy": {"protocols": ["TLSv1.2"], "ciphers": ["FAKE-CIPHER"]}}`, "error_invalid_input"},
		{"duplicate cipher", http.MethodPost, "/security-policies", `{"security_policy": {"protocols": ["TLSv1.2"], "ciphers": ["AES128-SHA", "AES128-SHA"]}}`, "error_invalid_input"},
		{"invalid enterprise_project_id", http.MethodPost, "/security-policies", `{"security_policy": {"protocols": ["TLSv1.2"], "ciphers": ["AES128-SHA"], "enterprise_project_id": ""}}`, "error_invalid_input"},
		{"update missing wrapper", http.MethodPut, "/security-policies/" + seedID, `{}`, "error_invalid_input"},
		{"update empty protocols", http.MethodPut, "/security-policies/" + seedID, `{"security_policy": {"protocols": []}}`, "error_invalid_input"},
		{"update invalid cipher", http.MethodPut, "/security-policies/" + seedID, `{"security_policy": {"ciphers": ["NOPE"]}}`, "error_invalid_input"},
		{"list invalid limit 0", http.MethodGet, "/security-policies?limit=0", "", "error_invalid_input"},
		{"list invalid limit 2001", http.MethodGet, "/security-policies?limit=2001", "", "error_invalid_input"},
		{"list unknown marker", http.MethodGet, "/security-policies?marker=" + ipgspUnknownUUID, "", "error_invalid_input"},
		{"list invalid page_reverse", http.MethodGet, "/security-policies?page_reverse=maybe", "", "error_invalid_input"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "security_policies", tc.golden, tc.method, tc.path, tc.body)
		})
	}
}

func TestSecurityPolicyListHTTPFilters(t *testing.T) {
	t.Parallel()
	e := newIPGSPEnv(t)

	st, raw1 := e.call(t, http.MethodPost, "/security-policies", fmt.Sprintf(`{
		"security_policy": {
			"name": "sp-alpha",
			"description": "alpha policy",
			"enterprise_project_id": %q,
			"protocols": ["TLSv1.2", "TLSv1.3"],
			"ciphers": ["AES128-SHA", "TLS_AES_128_GCM_SHA256"]
		}
	}`, ipgspCustomEP))
	if st != http.StatusCreated {
		t.Fatalf("create sp1: %d %s", st, raw1)
	}
	sp1 := ipgspDecodeInto[secpolEnvelope](t, raw1).SecurityPolicy

	st, raw2 := e.call(t, http.MethodPost, "/security-policies", `{
		"security_policy": {
			"name": "sp-beta",
			"description": "beta policy",
			"protocols": ["TLSv1.2"],
			"ciphers": ["AES256-SHA"]
		}
	}`)
	if st != http.StatusCreated {
		t.Fatalf("create sp2: %d %s", st, raw2)
	}

	// Multi-filter query including space-separated protocols and colon-separated ciphers.
	q := url.Values{}
	q.Add("id", sp1.ID)
	q.Add("name", "sp-alpha")
	q.Add("description", "alpha policy")
	q.Add("protocols", "TLSv1.2 TLSv1.3")
	q.Add("ciphers", "AES128-SHA:TLS_AES_128_GCM_SHA256")
	q.Add("enterprise_project_id", ipgspCustomEP)
	q.Set("page_reverse", "false")

	st, out := e.call(t, http.MethodGet, "/security-policies?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("filtered list: %d %s", st, out)
	}
	listed := ipgspDecodeInto[secpolListResponse](t, out)
	if len(listed.SecurityPolicies) != 1 || listed.SecurityPolicies[0].ID != sp1.ID || listed.PageInfo.CurrentCount != 1 {
		t.Fatalf("filtered list = %+v, want [%s]", listed, sp1.ID)
	}

	// enterprise_project_id=all_granted_eps returns both custom security policies.
	st, out = e.call(t, http.MethodGet, "/security-policies?enterprise_project_id="+allGrantedEPs, "")
	if st != http.StatusOK {
		t.Fatalf("all_granted_eps list: %d %s", st, out)
	}
	listed = ipgspDecodeInto[secpolListResponse](t, out)
	if len(listed.SecurityPolicies) != 2 || listed.PageInfo.CurrentCount != 2 {
		t.Fatalf("all_granted_eps count = %d, want 2", len(listed.SecurityPolicies))
	}
}
