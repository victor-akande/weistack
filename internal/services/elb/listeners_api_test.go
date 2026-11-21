package elb

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestListenerLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newLsnEnv(t)
	poolID := e.seedPool(t, lsnTestTenant, e.lbBothID, "HTTP")

	e.expect(t, "list_listeners_empty", http.MethodGet, "/listeners", "")

	out := e.expect(t, "create_listener", http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "http-listener-1",
			"description": "primary http listener",
			"protocol": "HTTP",
			"protocol_port": 80,
			"loadbalancer_id": %q,
			"admin_state_up": true,
			"http2_enable": false,
			"insert_headers": {
				"X-Forwarded-ELB-IP": true,
				"X-Forwarded-Host": true
			},
			"enable_member_retry": true,
			"keepalive_timeout": 120,
			"client_timeout": 45,
			"member_timeout": 90,
			"ipgroup": {
				"ipgroup_id": %q,
				"type": "white",
				"enable_ipgroup": true
			},
			"transparent_client_ip_enable": true,
			"enhance_l7policy_enable": true,
			"protection_status": "nonProtection",
			"gzip_enable": true,
			"cps": 1000,
			"connection": 5000,
			"tags": [{"key": "env", "value": "prod"}]
		}
	}`, e.lbBothID, e.ipGroupID))
	id := lsnDecodeInto[listenerEnvelope](t, out).Listener.ID

	e.expect(t, "show_listener", http.MethodGet, "/listeners/"+id, "")
	e.expect(t, "list_listeners", http.MethodGet, "/listeners", "")

	e.expect(t, "update_listener", http.MethodPut, "/listeners/"+id, fmt.Sprintf(`{
		"listener": {
			"name": "http-listener-updated",
			"description": "updated description",
			"default_pool_id": %q,
			"keepalive_timeout": 180,
			"ipgroup": {
				"enable_ipgroup": false,
				"type": "black"
			},
			"protection_status": "consoleProtection",
			"protection_reason": "locked by ops"
		}
	}`, poolID))

	// Normal delete refused while default_pool_id is bound (ELB.8907).
	e.expect(t, "error_conflict", http.MethodDelete, "/listeners/"+id, "")

	// Force delete unbinds default_pool_id and deletes the listener (204).
	e.expect(t, "delete_listener_force", http.MethodDelete, "/listeners/"+id+"/force", "")

	// Deleted listener returns ELB.8904 on show, update, delete, force delete.
	e.expect(t, "error_not_found", http.MethodGet, "/listeners/"+id, "")
	e.expect(t, "error_not_found", http.MethodPut, "/listeners/"+id, `{"listener": {"name": "x"}}`)
	e.expect(t, "error_not_found", http.MethodDelete, "/listeners/"+id, "")
	e.expect(t, "error_not_found", http.MethodDelete, "/listeners/"+id+"/force", "")

	// Create a second listener with port_ranges and delete it cleanly via standard DELETE.
	out2 := e.expect(t, "create_listener_port_ranges", http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "tcp-range-listener",
			"protocol": "TCP",
			"loadbalancer_id": %q,
			"port_ranges": [
				{"start_port": 1000, "end_port": 1010},
				{"start_port": 2000, "end_port": 2010}
			]
		}
	}`, e.lbL4ID))
	id2 := lsnDecodeInto[listenerEnvelope](t, out2).Listener.ID
	e.expect(t, "delete_listener", http.MethodDelete, "/listeners/"+id2, "")
}

func TestListenerCreateErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newLsnEnv(t)

	// Seed one HTTP listener on port 8080 so we can test port conflict (ELB.8907).
	st, raw := e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "seed-http",
			"protocol": "HTTP",
			"protocol_port": 8080,
			"loadbalancer_id": %q
		}
	}`, e.lbBothID))
	if st != http.StatusCreated {
		t.Fatalf("seed create: %d %s", st, raw)
	}

	tests := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_invalid_input"},
		{"malformed json", `{"listener": `, "error_invalid_input"},
		{"missing wrapper", `{}`, "error_invalid_input"},
		{"missing loadbalancer_id", `{"listener": {"protocol": "HTTP", "protocol_port": 80}}`, "error_invalid_input"},
		{"unknown loadbalancer_id", fmt.Sprintf(`{"listener": {"protocol": "HTTP", "protocol_port": 80, "loadbalancer_id": %q}}`, lsnUnknownUUID), "error_not_found"},
		{"unsupported protocol IP", fmt.Sprintf(`{"listener": {"protocol": "IP", "protocol_port": 80, "loadbalancer_id": %q}}`, e.lbBothID), "error_invalid_input"},
		{"missing L7 flavor for HTTP", fmt.Sprintf(`{"listener": {"protocol": "HTTP", "protocol_port": 80, "loadbalancer_id": %q}}`, e.lbL4ID), "error_invalid_input"},
		{"missing L4 flavor for TCP", fmt.Sprintf(`{"listener": {"protocol": "TCP", "protocol_port": 80, "loadbalancer_id": %q}}`, e.lbL7ID), "error_invalid_input"},
		{"port out of range", fmt.Sprintf(`{"listener": {"protocol": "TCP", "protocol_port": 70000, "loadbalancer_id": %q}}`, e.lbBothID), "error_invalid_input"},
		{"overlapping port_ranges", fmt.Sprintf(`{"listener": {"protocol": "TCP", "loadbalancer_id": %q, "port_ranges": [{"start_port": 100, "end_port": 200}, {"start_port": 150, "end_port": 250}]}}`, e.lbBothID), "error_invalid_input"},
		{"port conflict in TCP/HTTP family", fmt.Sprintf(`{"listener": {"protocol": "TCP", "protocol_port": 8080, "loadbalancer_id": %q}}`, e.lbBothID), "error_conflict"},
		{"HTTPS missing server cert", fmt.Sprintf(`{"listener": {"protocol": "HTTPS", "protocol_port": 443, "loadbalancer_id": %q}}`, e.lbBothID), "error_invalid_input"},
		{"HTTPS unknown cert", fmt.Sprintf(`{"listener": {"protocol": "HTTPS", "protocol_port": 443, "loadbalancer_id": %q, "default_tls_container_ref": %q}}`, e.lbBothID, lsnUnknownUUID), "error_not_found"},
		{"HTTPS unknown security policy", fmt.Sprintf(`{"listener": {"protocol": "HTTPS", "protocol_port": 443, "loadbalancer_id": %q, "default_tls_container_ref": %q, "security_policy_id": %q}}`, e.lbBothID, e.serverCertID, lsnUnknownUUID), "error_not_found"},
		{"unknown ipgroup", fmt.Sprintf(`{"listener": {"protocol": "HTTP", "protocol_port": 8090, "loadbalancer_id": %q, "ipgroup": {"ipgroup_id": %q, "type": "white"}}}`, e.lbBothID, lsnUnknownUUID), "error_not_found"},
		{"invalid ipgroup type", fmt.Sprintf(`{"listener": {"protocol": "HTTP", "protocol_port": 8091, "loadbalancer_id": %q, "ipgroup": {"ipgroup_id": %q, "type": "gray"}}}`, e.lbBothID, e.ipGroupID), "error_invalid_input"},
		{"unknown default_pool_id", fmt.Sprintf(`{"listener": {"protocol": "HTTP", "protocol_port": 8092, "loadbalancer_id": %q, "default_pool_id": %q}}`, e.lbBothID, lsnUnknownUUID), "error_not_found"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, tc.golden, http.MethodPost, "/listeners", tc.body)
		})
	}
}

func TestListenerUpdateHTTPSPoliciesAndNullClearing(t *testing.T) {
	t.Parallel()
	e := newLsnEnv(t)

	// Create TERMINATED_HTTPS -> stored as HTTPS with default tls-1-2.
	st, raw := e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "https-1",
			"protocol": "TERMINATED_HTTPS",
			"protocol_port": 443,
			"loadbalancer_id": %q,
			"default_tls_container_ref": %q,
			"ipgroup": {"ipgroup_id": %q, "type": "white"}
		}
	}`, e.lbBothID, e.serverCertID, e.ipGroupID))
	if st != http.StatusCreated {
		t.Fatalf("create https: %d %s", st, raw)
	}
	env := lsnDecodeInto[listenerEnvelope](t, raw)
	if env.Listener.Protocol != "HTTPS" || env.Listener.TLSCiphersPolicy != "tls-1-2" {
		t.Fatalf("unexpected created https listener: %+v", env.Listener)
	}
	id := env.Listener.ID

	// Switch to custom security_policy_id (clears tls_ciphers_policy).
	st, raw = e.call(t, http.MethodPut, "/listeners/"+id, fmt.Sprintf(`{
		"listener": {
			"security_policy_id": %q,
			"sni_container_refs": [%q],
			"client_ca_tls_container_ref": %q,
			"ipgroup": null
		}
	}`, e.secPolID, e.serverCert2, e.clientCertID))
	if st != http.StatusOK {
		t.Fatalf("update to custom sp: %d %s", st, raw)
	}
	env = lsnDecodeInto[listenerEnvelope](t, raw)
	if env.Listener.SecurityPolicyID != e.secPolID || env.Listener.TLSCiphersPolicy != "" {
		t.Fatalf("policy switch failed: sp=%q ciphers=%q", env.Listener.SecurityPolicyID, env.Listener.TLSCiphersPolicy)
	}
	if env.Listener.IPGroup != nil {
		t.Fatalf("expected ipgroup cleared, got %+v", env.Listener.IPGroup)
	}

	// Switch back to system tls_ciphers_policy (clears security_policy_id) and clear client CA.
	st, raw = e.call(t, http.MethodPut, "/listeners/"+id, `{
		"listener": {
			"tls_ciphers_policy": "tls-1-2-strict",
			"client_ca_tls_container_ref": null
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("update back to system policy: %d %s", st, raw)
	}
	env = lsnDecodeInto[listenerEnvelope](t, raw)
	if env.Listener.TLSCiphersPolicy != "tls-1-2-strict" || env.Listener.SecurityPolicyID != "" || env.Listener.ClientCATLSContainerRef != "" {
		t.Fatalf("unexpected after switch back: %+v", env.Listener)
	}

	// Sending both policies together fails with ELB.8902.
	e.expect(t, "error_invalid_input", http.MethodPut, "/listeners/"+id, fmt.Sprintf(`{
		"listener": {
			"tls_ciphers_policy": "tls-1-2",
			"security_policy_id": %q
		}
	}`, e.secPolID))
}

func TestListenerListHTTPFiltersAndErrors(t *testing.T) {
	t.Parallel()
	e := newLsnEnv(t)

	// Create two listeners on different LBs / enterprise projects.
	st, raw1 := e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "lsn-l7-http",
			"description": "custom ep listener",
			"protocol": "HTTP",
			"protocol_port": 8080,
			"loadbalancer_id": %q,
			"keepalive_timeout": 75,
			"client_timeout": 35,
			"member_timeout": 45,
			"enhance_l7policy_enable": true,
			"protection_status": "consoleProtection"
		}
	}`, e.lbL7ID))
	if st != http.StatusCreated {
		t.Fatalf("create l1: %d %s", st, raw1)
	}
	l1 := lsnDecodeInto[listenerEnvelope](t, raw1).Listener

	st, raw2 := e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "lsn-l4-tcp",
			"protocol": "TCP",
			"protocol_port": 9000,
			"loadbalancer_id": %q
		}
	}`, e.lbL4ID))
	if st != http.StatusCreated {
		t.Fatalf("create l2: %d %s", st, raw2)
	}

	// Query parameter validation errors -> ELB.8902.
	e.expect(t, "error_invalid_input", http.MethodGet, "/listeners?limit=0", "")
	e.expect(t, "error_invalid_input", http.MethodGet, "/listeners?limit=2001", "")
	e.expect(t, "error_invalid_input", http.MethodGet, "/listeners?limit=abc", "")
	e.expect(t, "error_invalid_input", http.MethodGet, "/listeners?marker="+lsnUnknownUUID, "")
	e.expect(t, "error_invalid_input", http.MethodGet, "/listeners?page_reverse=maybe", "")
	e.expect(t, "error_invalid_input", http.MethodGet, "/listeners?admin_state_up=nope", "")
	e.expect(t, "error_invalid_input", http.MethodGet, "/listeners?keepalive_timeout=notanint", "")

	// Combined filters matching l1.
	q := url.Values{}
	q.Add("id", l1.ID)
	q.Add("name", "lsn-l7-http")
	q.Add("description", "custom ep listener")
	q.Add("protocol", "TCP")
	q.Add("protocol", "HTTP")
	q.Add("protocol_port", "8080")
	q.Add("loadbalancer_id", e.lbL7ID)
	q.Add("enterprise_project_id", lsnCustomEP)
	q.Add("protection_status", "consoleProtection")
	q.Add("keepalive_timeout", "75")
	q.Add("client_timeout", "35")
	q.Add("member_timeout", "45")
	q.Add("connection_limit", "-1")
	q.Set("admin_state_up", "true")
	q.Set("enhance_l7policy_enable", "true")
	q.Set("page_reverse", "false")
	st, out := e.call(t, http.MethodGet, "/listeners?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("filtered list: %d %s", st, out)
	}
	listed := lsnDecodeInto[listListenersResponse](t, out)
	if len(listed.Listeners) != 1 || listed.Listeners[0].ID != l1.ID || listed.PageInfo.CurrentCount != 1 {
		t.Fatalf("filtered list = %+v, want [%s]", listed, l1.ID)
	}

	// enterprise_project_id=all_granted_eps returns both listeners.
	st, out = e.call(t, http.MethodGet, "/listeners?enterprise_project_id=all_granted_eps", "")
	if st != http.StatusOK {
		t.Fatalf("all_granted_eps list: %d %s", st, out)
	}
	listed = lsnDecodeInto[listListenersResponse](t, out)
	if len(listed.Listeners) != 2 || listed.PageInfo.CurrentCount != 2 {
		t.Fatalf("all_granted_eps count = %d, want 2", len(listed.Listeners))
	}
}
