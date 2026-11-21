package elb

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestPoolLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)

	e.expect(t, "pools", "list_pools_empty", http.MethodGet, "/pools", "")

	out := e.expect(t, "pools", "create_pool", http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {
			"name": "pool-http-1",
			"description": "primary http pool",
			"protocol": "HTTP",
			"lb_algorithm": "ROUND_ROBIN",
			"loadbalancer_id": %q,
			"session_persistence": {
				"type": "HTTP_COOKIE",
				"persistence_timeout": 60
			},
			"slow_start": {
				"enable": false,
				"duration": 60
			}
		}
	}`, e.lbID))
	id := poolDecodeInto[poolEnvelope](t, out).Pool.ID

	e.expect(t, "pools", "show_pool", http.MethodGet, "/pools/"+id, "")
	e.expect(t, "pools", "list_pools", http.MethodGet, "/pools", "")

	e.expect(t, "pools", "update_pool", http.MethodPut, "/pools/"+id, `{
		"pool": {
			"name": "pool-http-updated",
			"description": "updated pool",
			"lb_algorithm": "LEAST_CONNECTIONS",
			"session_persistence": null,
			"slow_start": {
				"enable": true,
				"duration": 120
			},
			"pool_health": {
				"minimum_healthy_member_count": 1
			}
		}
	}`)

	e.expect(t, "pools", "delete_pool", http.MethodDelete, "/pools/"+id, "")

	// Deleted pool returns ELB.8904 on show, update, delete, and cascade delete.
	e.expect(t, "pools", "error_not_found", http.MethodGet, "/pools/"+id, "")
	e.expect(t, "pools", "error_not_found", http.MethodPut, "/pools/"+id, `{"pool": {"name": "x"}}`)
	e.expect(t, "pools", "error_not_found", http.MethodDelete, "/pools/"+id, "")
	e.expect(t, "pools", "error_not_found", http.MethodDelete, "/pools/"+id+"/delete-cascade", "")

	// Pool created with listener_id + cascade delete.
	lsnID := e.seedListener(t, e.lbID, "HTTP", 80)
	outLsn := e.expect(t, "pools", "create_pool_with_listener", http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {
			"name": "pool-on-listener",
			"protocol": "HTTP",
			"lb_algorithm": "LEAST_CONNECTIONS",
			"listener_id": %q
		}
	}`, lsnID))
	lsnPoolID := poolDecodeInto[poolEnvelope](t, outLsn).Pool.ID
	e.seedMember(t, lsnPoolID, "10.0.0.15", 8080)

	// Regular delete refused with ELB.8907 while listener & member exist.
	e.expect(t, "pools", "error_conflict", http.MethodDelete, "/pools/"+lsnPoolID, "")
	// Cascade delete succeeds with 204.
	e.expect(t, "pools", "delete_pool_cascade", http.MethodDelete, "/pools/"+lsnPoolID+"/delete-cascade", "")

	// Unbound IP pool with vpc_id.
	e.expect(t, "pools", "create_pool_ip_unbound", http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {
			"name": "pool-ip-unbound",
			"protocol": "TCP",
			"lb_algorithm": "SOURCE_IP",
			"type": "ip",
			"vpc_id": %q
		}
	}`, e.vpcID))
}

func TestPoolErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)

	lsnHTTP := e.seedListener(t, e.lbID, "HTTP", 80)
	lsnBusy := e.seedListener(t, e.lbID, "TCP", 81)
	if st, raw := e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {"protocol": "TCP", "lb_algorithm": "ROUND_ROBIN", "listener_id": %q}
	}`, lsnBusy)); st != http.StatusCreated {
		t.Fatalf("seed busy listener pool: %d %s", st, raw)
	}

	tests := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_invalid_input"},
		{"malformed json", `{"pool": `, "error_invalid_input"},
		{"missing pool wrapper", `{}`, "error_invalid_input"},
		{"bad protocol", fmt.Sprintf(`{"pool": {"protocol": "SCTP", "lb_algorithm": "ROUND_ROBIN", "loadbalancer_id": %q}}`, e.lbID), "error_invalid_input"},
		{"QUIC_CID on TCP", fmt.Sprintf(`{"pool": {"protocol": "TCP", "lb_algorithm": "QUIC_CID", "loadbalancer_id": %q}}`, e.lbID), "error_invalid_input"},
		{"protocol mismatch with listener", fmt.Sprintf(`{"pool": {"protocol": "TCP", "lb_algorithm": "ROUND_ROBIN", "listener_id": %q}}`, lsnHTTP), "error_invalid_input"},
		{"no placement", `{"pool": {"protocol": "TCP", "lb_algorithm": "ROUND_ROBIN"}}`, "error_invalid_input"},
		{"bad session persistence", fmt.Sprintf(`{"pool": {"protocol": "TCP", "lb_algorithm": "ROUND_ROBIN", "loadbalancer_id": %q, "session_persistence": {"type": "SOURCE_IP", "cookie_name": "bad"}}}`, e.lbID), "error_invalid_input"},
		{"unknown loadbalancer", fmt.Sprintf(`{"pool": {"protocol": "TCP", "lb_algorithm": "ROUND_ROBIN", "loadbalancer_id": %q}}`, poolTestUnknownUUID), "error_not_found"},
		{"unknown listener", fmt.Sprintf(`{"pool": {"protocol": "TCP", "lb_algorithm": "ROUND_ROBIN", "listener_id": %q}}`, poolTestUnknownUUID), "error_not_found"},
		{"unknown vpc", fmt.Sprintf(`{"pool": {"protocol": "TCP", "lb_algorithm": "ROUND_ROBIN", "type": "ip", "vpc_id": %q}}`, poolTestUnknownUUID), "error_not_found"},
		{"listener already has pool", fmt.Sprintf(`{"pool": {"protocol": "TCP", "lb_algorithm": "ROUND_ROBIN", "listener_id": %q}}`, lsnBusy), "error_conflict"},
		{"ipv6 not implemented", fmt.Sprintf(`{"pool": {"protocol": "TCP", "lb_algorithm": "ROUND_ROBIN", "loadbalancer_id": %q, "ip_version": "v6"}}`, e.lbID), "error_not_implemented"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "pools", tc.golden, http.MethodPost, "/pools", tc.body)
		})
	}

	// List query errors -> ELB.8902.
	e.expect(t, "pools", "error_invalid_input", http.MethodGet, "/pools?limit=0", "")
	e.expect(t, "pools", "error_invalid_input", http.MethodGet, "/pools?limit=2001", "")
	e.expect(t, "pools", "error_invalid_input", http.MethodGet, "/pools?marker="+poolTestUnknownUUID, "")
	e.expect(t, "pools", "error_invalid_input", http.MethodGet, "/pools?admin_state_up=nope", "")
	e.expect(t, "pools", "error_invalid_input", http.MethodGet, "/pools?quic_cid_len=abc", "")
}

func TestPoolListHTTPFilters(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)

	lsnID := e.seedListener(t, e.lbID, "QUIC", 443)
	st, raw := e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {
			"name": "pool-quic-filter",
			"description": "quic desc",
			"protocol": "QUIC",
			"lb_algorithm": "QUIC_CID",
			"listener_id": %q,
			"enterprise_project_id": %q,
			"any_port_enable": true,
			"connection_drain": {"enable": true, "timeout": 300},
			"pool_health": {"minimum_healthy_member_count": 1},
			"quic_cid_hash_strategy": {"len": 5, "offset": 2},
			"az_affinity": {"enable": true, "az_minimum_healthy_member_percentage": 50}
		}
	}`, lsnID, poolTestCustomEP))
	if st != http.StatusCreated {
		t.Fatalf("create pool: %d %s", st, raw)
	}
	p := poolDecodeInto[poolEnvelope](t, raw).Pool
	memID := e.seedMember(t, p.ID, "10.0.0.99", 0)

	q := url.Values{}
	q.Set("id", p.ID)
	q.Set("name", "pool-quic-filter")
	q.Set("description", "quic desc")
	q.Set("admin_state_up", "true")
	q.Set("loadbalancer_id", e.lbID)
	q.Set("listener_id", lsnID)
	q.Add("protocol", "TCP")
	q.Add("protocol", "QUIC")
	q.Set("lb_algorithm", "QUIC_CID")
	q.Set("enterprise_project_id", allGrantedEPs)
	q.Set("ip_version", "v4")
	q.Set("member_address", "10.0.0.99")
	q.Set("member_instance_id", memID)
	q.Set("member_deletion_protection_enable", "false")
	q.Set("vpc_id", e.vpcID)
	q.Set("protection_status", "nonProtection")
	q.Set("connection_drain", "true")
	q.Set("pool_health", "minimum_healthy_member_count=1")
	q.Set("any_port_enable", "true")
	q.Set("public_border_group", "center")
	q.Set("quic_cid_len", "5")
	q.Set("quic_cid_offset", "2")
	q.Set("az_affinity", "enable=true")

	st, out := e.call(t, http.MethodGet, "/pools?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("list pools: %d %s", st, out)
	}
	listed := poolDecodeInto[listPoolsResponse](t, out)
	if len(listed.Pools) != 1 || listed.Pools[0].ID != p.ID || listed.PageInfo.CurrentCount != 1 {
		t.Fatalf("filtered list = %+v, want [%s]", listed, p.ID)
	}
}

func TestHealthMonitorLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)

	e.expect(t, "healthmonitors", "list_healthmonitors_empty", http.MethodGet, "/healthmonitors", "")

	// Seed HTTP and TCP pools.
	st, raw := e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {"name": "hm-http-pool", "protocol": "HTTP", "lb_algorithm": "ROUND_ROBIN", "loadbalancer_id": %q}
	}`, e.lbID))
	if st != http.StatusCreated {
		t.Fatalf("create http pool: %d %s", st, raw)
	}
	httpPoolID := poolDecodeInto[poolEnvelope](t, raw).Pool.ID

	st, raw = e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {"name": "hm-tcp-pool", "protocol": "TCP", "lb_algorithm": "ROUND_ROBIN", "loadbalancer_id": %q}
	}`, e.lbID))
	if st != http.StatusCreated {
		t.Fatalf("create tcp pool: %d %s", st, raw)
	}
	tcpPoolID := poolDecodeInto[poolEnvelope](t, raw).Pool.ID

	// Create HTTP monitor.
	out := e.expect(t, "healthmonitors", "create_healthmonitor_http", http.MethodPost, "/healthmonitors", fmt.Sprintf(`{
		"healthmonitor": {
			"name": "hm-http-1",
			"pool_id": %q,
			"type": "HTTP",
			"delay": 10,
			"timeout": 3,
			"max_retries": 3
		}
	}`, httpPoolID))
	hmID := poolDecodeInto[healthMonitorEnvelope](t, out).HealthMonitor.ID

	// Show and list.
	e.expect(t, "healthmonitors", "show_healthmonitor", http.MethodGet, "/healthmonitors/"+hmID, "")
	e.expect(t, "healthmonitors", "list_healthmonitors", http.MethodGet, "/healthmonitors", "")

	// Update.
	e.expect(t, "healthmonitors", "update_healthmonitor", http.MethodPut, "/healthmonitors/"+hmID, `{
		"healthmonitor": {
			"name": "hm-http-updated",
			"delay": 15,
			"timeout": 5,
			"max_retries": 5,
			"max_retries_down": 4,
			"monitor_port": 8443,
			"http_method": "HEAD",
			"url_path": "/healthz",
			"expected_codes": "200-204",
			"domain_name": "app.example.com",
			"admin_state_up": false
		}
	}`)

	// Delete.
	e.expect(t, "healthmonitors", "delete_healthmonitor", http.MethodDelete, "/healthmonitors/"+hmID, "")

	// Not found after delete.
	e.expect(t, "healthmonitors", "error_not_found", http.MethodGet, "/healthmonitors/"+hmID, "")
	e.expect(t, "healthmonitors", "error_not_found", http.MethodPut, "/healthmonitors/"+hmID, `{"healthmonitor": {"name": "x"}}`)
	e.expect(t, "healthmonitors", "error_not_found", http.MethodDelete, "/healthmonitors/"+hmID, "")

	// Create TCP monitor with monitor_port.
	e.expect(t, "healthmonitors", "create_healthmonitor_tcp", http.MethodPost, "/healthmonitors", fmt.Sprintf(`{
		"healthmonitor": {
			"name": "hm-tcp-1",
			"pool_id": %q,
			"type": "TCP",
			"delay": 5,
			"timeout": 2,
			"max_retries": 2,
			"max_retries_down": 4,
			"monitor_port": 8080
		}
	}`, tcpPoolID))
}

func TestHealthMonitorErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)

	// Seed HTTP pool (already monitored) and UDP pool.
	st, raw := e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {"protocol": "HTTP", "lb_algorithm": "ROUND_ROBIN", "loadbalancer_id": %q}
	}`, e.lbID))
	if st != http.StatusCreated {
		t.Fatalf("create http pool: %d %s", st, raw)
	}
	busyPoolID := poolDecodeInto[poolEnvelope](t, raw).Pool.ID
	if st, raw := e.call(t, http.MethodPost, "/healthmonitors", fmt.Sprintf(`{
		"healthmonitor": {"pool_id": %q, "type": "HTTP", "delay": 5, "timeout": 3, "max_retries": 3}
	}`, busyPoolID)); st != http.StatusCreated {
		t.Fatalf("seed hm: %d %s", st, raw)
	}

	st, raw = e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {"protocol": "UDP", "lb_algorithm": "ROUND_ROBIN", "loadbalancer_id": %q}
	}`, e.lbID))
	if st != http.StatusCreated {
		t.Fatalf("create udp pool: %d %s", st, raw)
	}
	udpPoolID := poolDecodeInto[poolEnvelope](t, raw).Pool.ID

	tests := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_invalid_input"},
		{"malformed json", `{"healthmonitor": `, "error_invalid_input"},
		{"missing wrapper", `{}`, "error_invalid_input"},
		{"unknown pool", fmt.Sprintf(`{"healthmonitor": {"pool_id": %q, "type": "HTTP", "delay": 5, "timeout": 3, "max_retries": 3}}`, poolTestUnknownUUID), "error_not_found"},
		{"pool already has monitor", fmt.Sprintf(`{"healthmonitor": {"pool_id": %q, "type": "HTTP", "delay": 5, "timeout": 3, "max_retries": 3}}`, busyPoolID), "error_conflict"},
		{"UDP pool rejects HTTP monitor", fmt.Sprintf(`{"healthmonitor": {"pool_id": %q, "type": "HTTP", "delay": 5, "timeout": 3, "max_retries": 3}}`, udpPoolID), "error_invalid_input"},
		{"UDP_CONNECT rejects url_path", fmt.Sprintf(`{"healthmonitor": {"pool_id": %q, "type": "UDP_CONNECT", "delay": 5, "timeout": 3, "max_retries": 3, "url_path": "/"}}`, udpPoolID), "error_invalid_input"},
		{"delay out of range", fmt.Sprintf(`{"healthmonitor": {"pool_id": %q, "type": "UDP_CONNECT", "delay": 51, "timeout": 3, "max_retries": 3}}`, udpPoolID), "error_invalid_input"},
		{"timeout 0", fmt.Sprintf(`{"healthmonitor": {"pool_id": %q, "type": "UDP_CONNECT", "delay": 5, "timeout": 0, "max_retries": 3}}`, udpPoolID), "error_invalid_input"},
		{"max_retries out of range", fmt.Sprintf(`{"healthmonitor": {"pool_id": %q, "type": "UDP_CONNECT", "delay": 5, "timeout": 3, "max_retries": 11}}`, udpPoolID), "error_invalid_input"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, "healthmonitors", tc.golden, http.MethodPost, "/healthmonitors", tc.body)
		})
	}

	// List query errors -> ELB.8902.
	e.expect(t, "healthmonitors", "error_invalid_input", http.MethodGet, "/healthmonitors?limit=0", "")
	e.expect(t, "healthmonitors", "error_invalid_input", http.MethodGet, "/healthmonitors?marker="+poolTestUnknownUUID, "")
	e.expect(t, "healthmonitors", "error_invalid_input", http.MethodGet, "/healthmonitors?delay=notanint", "")
	e.expect(t, "healthmonitors", "error_invalid_input", http.MethodGet, "/healthmonitors?admin_state_up=maybe", "")
}

func TestHealthMonitorListHTTPFilters(t *testing.T) {
	t.Parallel()
	e := newPoolTestEnv(t)

	st, raw := e.call(t, http.MethodPost, "/pools", fmt.Sprintf(`{
		"pool": {"protocol": "HTTP", "lb_algorithm": "ROUND_ROBIN", "loadbalancer_id": %q, "enterprise_project_id": %q}
	}`, e.lbID, poolTestCustomEP))
	if st != http.StatusCreated {
		t.Fatalf("create pool: %d %s", st, raw)
	}
	poolID := poolDecodeInto[poolEnvelope](t, raw).Pool.ID

	st, raw = e.call(t, http.MethodPost, "/healthmonitors", fmt.Sprintf(`{
		"healthmonitor": {
			"name": "hm-filter-1",
			"pool_id": %q,
			"type": "HTTP",
			"delay": 12,
			"timeout": 4,
			"max_retries": 6,
			"max_retries_down": 5,
			"monitor_port": 8081,
			"http_method": "POST",
			"url_path": "/ready",
			"expected_codes": "200,204",
			"domain_name": "svc.internal",
			"admin_state_up": true
		}
	}`, poolID))
	if st != http.StatusCreated {
		t.Fatalf("create hm: %d %s", st, raw)
	}
	hm := poolDecodeInto[healthMonitorEnvelope](t, raw).HealthMonitor

	q := url.Values{}
	q.Set("id", hm.ID)
	q.Set("name", "hm-filter-1")
	q.Add("type", "TCP")
	q.Add("type", "HTTP")
	q.Set("monitor_port", "8081")
	q.Set("domain_name", "svc.internal")
	q.Set("delay", "12")
	q.Set("timeout", "4")
	q.Set("max_retries", "6")
	q.Set("max_retries_down", "5")
	q.Set("admin_state_up", "true")
	q.Set("expected_codes", "200,204")
	q.Set("url_path", "/ready")
	q.Set("http_method", "POST")
	q.Set("enterprise_project_id", poolTestCustomEP)

	st, out := e.call(t, http.MethodGet, "/healthmonitors?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("list hms: %d %s", st, out)
	}
	listed := poolDecodeInto[listHealthMonitorsResponse](t, out)
	if len(listed.HealthMonitors) != 1 || listed.HealthMonitors[0].ID != hm.ID {
		t.Fatalf("filtered list = %+v, want [%s]", listed, hm.ID)
	}

	// all_granted_eps also matches.
	st, out = e.call(t, http.MethodGet, "/healthmonitors?enterprise_project_id="+allGrantedEPs, "")
	if st != http.StatusOK {
		t.Fatalf("list all_granted_eps: %d %s", st, out)
	}
	if len(poolDecodeInto[listHealthMonitorsResponse](t, out).HealthMonitors) != 1 {
		t.Fatalf("expected 1 hm with all_granted_eps")
	}
}
