package elb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func certMustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

func TestCertLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := certNewEnv(t)

	rsaPair := certGenRSA(t, "www.example.com", []string{"www.example.com", "api.example.com"}, nil, false, certTestEpoch.AddDate(1, 0, 0))
	ecRotated := certGenECDSA(t, "rotated.example.com", []string{"rotated.example.com"}, false, certTestEpoch.AddDate(2, 0, 0))
	caPair := certGenECDSA(t, "Example Root CA", nil, true, certTestEpoch.AddDate(2, 0, 0))

	// 1. Empty list.
	e.expect(t, "list_certificates_empty", http.MethodGet, "/certificates", "")

	// 2. Create server certificate.
	createServerBody := certMustJSON(t, map[string]any{
		"certificate": map[string]any{
			"name":        "server-cert-1",
			"description": "primary rsa server cert",
			"type":        "server",
			"certificate": rsaPair.certPEM,
			"private_key": rsaPair.keyPKCS1PEM,
		},
	})
	out := e.expect(t, "create_certificate_server", http.MethodPost, "/certificates", createServerBody)
	if strings.Contains(string(out), certKeyBodySnippet(rsaPair.keyPKCS1PEM)) {
		t.Fatalf("private key leaked in create response")
	}
	created := certDecodeInto[certEnvelope](t, out).Certificate
	if created.Fingerprint != rsaPair.fingerprint {
		t.Fatalf("fingerprint = %q, want %q", created.Fingerprint, rsaPair.fingerprint)
	}
	if created.PrivateKey != "" {
		t.Fatalf("private_key = %q, want empty", created.PrivateKey)
	}

	// 3. Show certificate.
	showOut := e.expect(t, "show_certificate", http.MethodGet, "/certificates/"+created.ID, "")
	if strings.Contains(string(showOut), certKeyBodySnippet(rsaPair.keyPKCS1PEM)) {
		t.Fatalf("private key leaked in show response")
	}

	// 4. Create client CA certificate.
	createClientBody := certMustJSON(t, map[string]any{
		"certificate": map[string]any{
			"name":        "client-ca-1",
			"description": "client ca certificate",
			"type":        "client",
			"certificate": caPair.certPEM,
		},
	})
	caOut := e.expect(t, "create_certificate_client", http.MethodPost, "/certificates", createClientBody)
	caCreated := certDecodeInto[certEnvelope](t, caOut).Certificate
	if caCreated.Fingerprint != caPair.fingerprint {
		t.Fatalf("ca fingerprint = %q, want %q", caCreated.Fingerprint, caPair.fingerprint)
	}

	// 5. List certificates (2 items).
	listOut := e.expect(t, "list_certificates", http.MethodGet, "/certificates", "")
	if strings.Contains(string(listOut), certKeyBodySnippet(rsaPair.keyPKCS1PEM)) {
		t.Fatalf("private key leaked in list response")
	}

	// 6. Update certificate (metadata + rotate to ECDSA pair).
	e.clock.Advance(5 * time.Minute)
	updateBody := certMustJSON(t, map[string]any{
		"certificate": map[string]any{
			"name":              "server-cert-rotated",
			"description":       "rotated to ecdsa",
			"domain":            "*.example.com,app.example.com",
			"admin_state_up":    false,
			"certificate":       ecRotated.certPEM,
			"private_key":       ecRotated.keySEC1PEM,
			"protection_status": "consoleProtection",
			"protection_reason": "managed by terraform",
		},
	})
	updOut := e.expect(t, "update_certificate", http.MethodPut, "/certificates/"+created.ID, updateBody)
	if strings.Contains(string(updOut), certKeyBodySnippet(ecRotated.keySEC1PEM)) {
		t.Fatalf("private key leaked in update response")
	}
	updated := certDecodeInto[certEnvelope](t, updOut).Certificate
	if updated.Fingerprint != ecRotated.fingerprint {
		t.Fatalf("rotated fingerprint = %q, want %q", updated.Fingerprint, ecRotated.fingerprint)
	}
	certAssertNoPlaintextKeyInStore(t, e.store, rsaPair.keyPKCS1PEM, ecRotated.keySEC1PEM)

	// 7. Attach server cert to an HTTPS listener -> DELETE returns 409 ELB.8907.
	st, lsnOut := e.call(t, http.MethodPost, "/listeners", fmt.Sprintf(`{
		"listener": {
			"name": "https-cert-guard",
			"protocol": "HTTPS",
			"protocol_port": 443,
			"loadbalancer_id": %q,
			"default_tls_container_ref": %q,
			"client_ca_tls_container_ref": %q
		}
	}`, e.lbID, created.ID, caCreated.ID))
	if st != http.StatusCreated {
		t.Fatalf("create HTTPS listener: %d %s", st, lsnOut)
	}
	lsnID := certDecodeInto[listenerEnvelope](t, lsnOut).Listener.ID

	e.expect(t, "error_conflict", http.MethodDelete, "/certificates/"+created.ID, "")
	e.expect(t, "error_conflict", http.MethodDelete, "/certificates/"+caCreated.ID, "")

	// 8. Delete listener -> DELETE certificates succeeds (204).
	if st, body := e.call(t, http.MethodDelete, "/listeners/"+lsnID, ""); st != http.StatusNoContent {
		t.Fatalf("delete listener: %d %s", st, body)
	}
	e.expect(t, "delete_certificate", http.MethodDelete, "/certificates/"+created.ID, "")
	e.expect(t, "delete_certificate", http.MethodDelete, "/certificates/"+caCreated.ID, "")

	// 9. Deleted certificate returns 404 ELB.8904 on show, update, delete.
	e.expect(t, "error_not_found", http.MethodGet, "/certificates/"+created.ID, "")
	e.expect(t, "error_not_found", http.MethodPut, "/certificates/"+created.ID, `{"certificate":{"name":"x"}}`)
	e.expect(t, "error_not_found", http.MethodDelete, "/certificates/"+created.ID, "")
}

func TestCertErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := certNewEnv(t)

	notAfter := certTestEpoch.AddDate(1, 0, 0)
	rsaGood := certGenRSA(t, "ok.example.com", nil, nil, false, notAfter)
	rsaOther := certGenRSA(t, "other.example.com", nil, nil, false, notAfter)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		golden string
	}{
		{"empty body", http.MethodPost, "/certificates", ``, "error_invalid_input"},
		{"malformed json", http.MethodPost, "/certificates", `{"certificate":`, "error_invalid_input"},
		{"missing wrapper", http.MethodPost, "/certificates", `{}`, "error_invalid_input"},
		{"missing cert and key", http.MethodPost, "/certificates", `{"certificate":{"name":"empty"}}`, "error_invalid_input"},
		{"invalid type", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "bogus", "certificate": rsaGood.certPEM, "private_key": rsaGood.keyPKCS1PEM},
		}), "error_invalid_input"},
		{"invalid domain", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "server", "domain": "-bad.example.com", "certificate": rsaGood.certPEM, "private_key": rsaGood.keyPKCS1PEM},
		}), "error_invalid_input"},
		{"bad server PEM", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "server", "certificate": "bad pem", "private_key": rsaGood.keyPKCS1PEM},
		}), "error_invalid_certificate"},
		{"mismatched server key", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "server", "certificate": rsaGood.certPEM, "private_key": rsaOther.keyPKCS1PEM},
		}), "error_invalid_certificate"},
		{"non-CA as client", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "client", "certificate": rsaGood.certPEM},
		}), "error_invalid_ca_certificate"},
		{"bad client PEM", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "client", "certificate": "not a ca"},
		}), "error_invalid_ca_certificate"},
		{"server_sm not implemented", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "server_sm", "certificate": rsaGood.certPEM, "private_key": rsaGood.keyPKCS1PEM},
		}), "error_not_implemented"},
		{"enc_certificate not implemented", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "server", "certificate": rsaGood.certPEM, "private_key": rsaGood.keyPKCS1PEM, "enc_certificate": rsaGood.certPEM},
		}), "error_not_implemented"},
		{"scm_certificate_id not implemented", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "server", "certificate": rsaGood.certPEM, "private_key": rsaGood.keyPKCS1PEM, "scm_certificate_id": "scm-1"},
		}), "error_not_implemented"},
		{"source scm not implemented", http.MethodPost, "/certificates", certMustJSON(t, map[string]any{
			"certificate": map[string]any{"type": "server", "certificate": rsaGood.certPEM, "private_key": rsaGood.keyPKCS1PEM, "source": "scm"},
		}), "error_not_implemented"},
		{"show unknown id", http.MethodGet, "/certificates/" + certUnknownUUID, "", "error_not_found"},
		{"update unknown id", http.MethodPut, "/certificates/" + certUnknownUUID, `{"certificate":{"name":"x"}}`, "error_not_found"},
		{"update missing wrapper", http.MethodPut, "/certificates/" + certUnknownUUID, `{}`, "error_invalid_input"},
		{"delete unknown id", http.MethodDelete, "/certificates/" + certUnknownUUID, "", "error_not_found"},
		{"list limit=0", http.MethodGet, "/certificates?limit=0", "", "error_invalid_input"},
		{"list limit=2001", http.MethodGet, "/certificates?limit=2001", "", "error_invalid_input"},
		{"list bad page_reverse", http.MethodGet, "/certificates?page_reverse=maybe", "", "error_invalid_input"},
		{"list bad admin_state_up", http.MethodGet, "/certificates?admin_state_up=nope", "", "error_invalid_input"},
		{"list unknown marker", http.MethodGet, "/certificates?marker=" + certUnknownUUID, "", "error_invalid_input"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, tc.golden, tc.method, tc.path, tc.body)
		})
	}
}

func TestCertHTTPListFiltersAndTLSListenersFlow(t *testing.T) {
	t.Parallel()
	e := certNewEnv(t)

	notAfter := certTestEpoch.AddDate(1, 0, 0)
	srv1 := certGenRSA(t, "edge1.example.com", []string{"edge1.example.com"}, nil, false, notAfter)
	srv2 := certGenECDSA(t, "edge2.example.com", []string{"edge2.example.com"}, false, notAfter)
	ca := certGenECDSA(t, "Mutual TLS CA", nil, true, notAfter)

	createCert := func(payload map[string]any) certWire {
		t.Helper()
		st, raw := e.call(t, http.MethodPost, "/certificates", certMustJSON(t, map[string]any{"certificate": payload}))
		if st != http.StatusCreated {
			t.Fatalf("create cert: %d %s", st, raw)
		}
		return certDecodeInto[certEnvelope](t, raw).Certificate
	}

	c1 := createCert(map[string]any{
		"name":                  "edge-1",
		"description":           "custom ep server cert",
		"type":                  "server",
		"domain":                "edge1.example.com,*.edge1.example.com",
		"certificate":           srv1.certPEM,
		"private_key":           srv1.keyPKCS8PEM,
		"enterprise_project_id": certCustomEP,
		"protection_status":     "consoleProtection",
		"protection_reason":     "prod",
	})
	c2 := createCert(map[string]any{
		"name":        "edge-2-sni",
		"type":        "server",
		"certificate": srv2.certPEM,
		"private_key": srv2.keySEC1PEM,
	})
	cCA := createCert(map[string]any{
		"name":        "mtls-ca",
		"type":        "client",
		"certificate": ca.certPEM,
	})

	// Combined HTTP query filters match c1.
	q := url.Values{}
	q.Add("id", c1.ID)
	q.Add("name", "edge-1")
	q.Add("description", "custom ep server cert")
	q.Add("domain", "edge1.example.com,*.edge1.example.com")
	q.Add("type", "server")
	q.Add("common_name", "edge1.example.com")
	q.Add("fingerprint", srv1.fingerprint)
	q.Add("protection_status", "consoleProtection")
	q.Add("protection_reason", "prod")
	q.Add("enterprise_project_id", certCustomEP)
	q.Set("admin_state_up", "true")
	q.Set("page_reverse", "false")
	st, out := e.call(t, http.MethodGet, "/certificates?"+q.Encode(), "")
	if st != http.StatusOK {
		t.Fatalf("filtered list: %d %s", st, out)
	}
	listed := certDecodeInto[certListResponse](t, out)
	if len(listed.Certificates) != 1 || listed.Certificates[0].ID != c1.ID || listed.PageInfo.CurrentCount != 1 {
		t.Fatalf("filtered list = %+v, want [%s]", listed, c1.ID)
	}

	// enterprise_project_id=all_granted_eps returns all 3 certs.
	st, out = e.call(t, http.MethodGet, "/certificates?enterprise_project_id=all_granted_eps", "")
	if st != http.StatusOK {
		t.Fatalf("all_granted_eps: %d %s", st, out)
	}
	listed = certDecodeInto[certListResponse](t, out)
	if len(listed.Certificates) != 3 || listed.PageInfo.CurrentCount != 3 {
		t.Fatalf("all_granted_eps count = %d, want 3", len(listed.Certificates))
	}

	// Create HTTPS, TLS, and QUIC listeners with these real certificates via HTTP.
	createLsn := func(body string) listenerWire {
		t.Helper()
		st, raw := e.call(t, http.MethodPost, "/listeners", body)
		if st != http.StatusCreated {
			t.Fatalf("create listener: %d %s", st, raw)
		}
		return certDecodeInto[listenerEnvelope](t, raw).Listener
	}
	httpsLsn := createLsn(fmt.Sprintf(`{
		"listener": {
			"name": "https-real",
			"protocol": "HTTPS",
			"protocol_port": 443,
			"loadbalancer_id": %q,
			"default_tls_container_ref": %q,
			"sni_container_refs": [%q],
			"client_ca_tls_container_ref": %q
		}
	}`, e.lbID, c1.ID, c2.ID, cCA.ID))
	tlsLsn := createLsn(fmt.Sprintf(`{
		"listener": {
			"name": "tls-real",
			"protocol": "TLS",
			"protocol_port": 8443,
			"loadbalancer_id": %q,
			"default_tls_container_ref": %q
		}
	}`, e.lbID, c2.ID))
	quicLsn := createLsn(fmt.Sprintf(`{
		"listener": {
			"name": "quic-real",
			"protocol": "QUIC",
			"protocol_port": 443,
			"loadbalancer_id": %q,
			"default_tls_container_ref": %q
		}
	}`, e.lbID, c1.ID))

	// Update HTTPS listener to drop SNI and client CA refs.
	st, raw := e.call(t, http.MethodPut, "/listeners/"+httpsLsn.ID, `{
		"listener": {
			"sni_container_refs": [],
			"client_ca_tls_container_ref": null
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("update HTTPS listener: %d %s", st, raw)
	}

	// CA cert is now free to delete; c2 is still used by TLS listener -> 409.
	if st, body := e.call(t, http.MethodDelete, "/certificates/"+cCA.ID, ""); st != http.StatusNoContent {
		t.Fatalf("delete unbound CA: %d %s", st, body)
	}
	e.expect(t, "error_conflict", http.MethodDelete, "/certificates/"+c2.ID, "")

	// Clean up listeners, then delete c1 and c2.
	for _, id := range []string{httpsLsn.ID, tlsLsn.ID, quicLsn.ID} {
		if st, body := e.call(t, http.MethodDelete, "/listeners/"+id, ""); st != http.StatusNoContent {
			t.Fatalf("delete listener %s: %d %s", id, st, body)
		}
	}
	if st, body := e.call(t, http.MethodDelete, "/certificates/"+c1.ID, ""); st != http.StatusNoContent {
		t.Fatalf("delete c1: %d %s", st, body)
	}
	if st, body := e.call(t, http.MethodDelete, "/certificates/"+c2.ID, ""); st != http.StatusNoContent {
		t.Fatalf("delete c2: %d %s", st, body)
	}
}
