package elb

import (
	"net/http"
	"testing"
)

func TestErrorConstructors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"invalid input", errInvalidInput("name"), http.StatusBadRequest, "ELB.8902"},
		{"not found", errNotFound("loadbalancer", "id1"), http.StatusNotFound, "ELB.8904"},
		{"conflict", errConflict("in use"), http.StatusConflict, "ELB.8907"},
		{"flavor type change", errFlavorTypeChange("l4_flavor_id", "L4", "L7"), http.StatusBadRequest, "ELB.8959"},
		{"ip member protocol", errIPMemberProtocol("TCP"), http.StatusBadRequest, "ELB.8938"},
		{"ip target disabled", errIPTargetDisabled(), http.StatusBadRequest, "ELB.8939"},
		{"invalid cert", errInvalidCertificate(), http.StatusBadRequest, "ELB.1011"},
		{"invalid ca cert", errInvalidCACertificate(), http.StatusBadRequest, "ELB.5051"},
		{"multiple domains", errMultipleDomainsNotSupported(), http.StatusBadRequest, "ELB.8909"},
		{"subnet full", errSubnetFull(), http.StatusBadRequest, "ELB.8934"},
		{"not implemented", errNotImplemented("op"), http.StatusNotImplemented, "WeiStack.0501"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.err == nil {
				t.Fatal("nil error")
			}
			if got := tc.err.Error(); got == "" {
				t.Fatal("empty error string")
			}
		})
	}
}

func TestSeededData(t *testing.T) {
	t.Parallel()
	flavors := seededFlavors("ap-southeast-1", "proj1")
	if len(flavors) != 4 {
		t.Fatalf("len(seededFlavors) = %d, want 4", len(flavors))
	}
	// Deterministic across calls.
	again := seededFlavors("ap-southeast-1", "proj1")
	for i := range flavors {
		if flavors[i].ID != again[i].ID {
			t.Fatalf("flavor %d ID not deterministic: %s vs %s", i, flavors[i].ID, again[i].ID)
		}
	}

	azs := seededAvailabilityZones("ap-southeast-1")
	if len(azs) != 1 || len(azs[0]) == 0 {
		t.Fatalf("seededAvailabilityZones = %+v", azs)
	}

	policies := seededSystemSecurityPolicies("proj1")
	if len(policies) != 10 {
		t.Fatalf("len(seededSystemSecurityPolicies) = %d, want 10", len(policies))
	}
	if !isSystemSecurityPolicy("tls-1-2") || isSystemSecurityPolicy("nonexistent") {
		t.Fatal("isSystemSecurityPolicy mismatch")
	}
	ciphers := allowedSecurityPolicyCiphers()
	if _, ok := ciphers["TLS_AES_128_GCM_SHA256"]; !ok {
		t.Fatal("expected TLS 1.3 cipher in allowedSecurityPolicyCiphers")
	}
}
