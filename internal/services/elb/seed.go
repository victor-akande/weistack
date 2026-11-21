package elb

import (
	"crypto/sha1" //nolint:gosec // name-based UUIDs (RFC 4122 version 5) are defined on SHA-1
	"fmt"
	"sort"
	"strings"

	"github.com/victor-akande/weistack/internal/core/zones"
)

// nameUUID returns the RFC 4122 version 5 UUID of name, so seeded flavor IDs
// are deterministic per region and stable across restarts.
func nameUUID(name string) string {
	sum := sha1.Sum([]byte(name)) //nolint:gosec // see import
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func intPtr(v int) *int { return &v }

// seededFlavors returns the four read-only ELB flavors for region (§2, ListFlavors.txt),
// sorted by ascending ID.
func seededFlavors(region, projectID string) []flavorWire {
	flavors := []flavorWire{
		{
			ID:        nameUUID("weistack:elb:flavor:" + region + ":L7_flavor.elb.s1.small"),
			Name:      "L7_flavor.elb.s1.small",
			Type:      "L7",
			Shared:    true,
			ProjectID: projectID,
			Info: flavorInfo{
				Bandwidth:  intPtr(50000),
				Connection: 200000,
				CPS:        2000,
				HTTPSCPS:   intPtr(200),
				LCU:        intPtr(10),
				QPS:        intPtr(4000),
			},
			FlavorSoldOut:     false,
			PublicBorderGroup: "center",
			Category:          0,
		},
		{
			ID:        nameUUID("weistack:elb:flavor:" + region + ":L4_flavor.elb.s2.small"),
			Name:      "L4_flavor.elb.s2.small",
			Type:      "L4",
			Shared:    true,
			ProjectID: projectID,
			Info: flavorInfo{
				Bandwidth:  intPtr(100000),
				Connection: 1000000,
				CPS:        20000,
				LCU:        intPtr(20),
			},
			FlavorSoldOut:     false,
			PublicBorderGroup: "center",
			Category:          0,
		},
		{
			ID:        nameUUID("weistack:elb:flavor:" + region + ":L7_flavor.elb.s1.medium"),
			Name:      "L7_flavor.elb.s1.medium",
			Type:      "L7",
			Shared:    true,
			ProjectID: projectID,
			Info: flavorInfo{
				Bandwidth:  intPtr(100000),
				Connection: 400000,
				CPS:        4000,
				HTTPSCPS:   intPtr(400),
				LCU:        intPtr(20),
				QPS:        intPtr(8000),
			},
			FlavorSoldOut:     false,
			PublicBorderGroup: "center",
			Category:          0,
		},
		{
			ID:        nameUUID("weistack:elb:flavor:" + region + ":L4_flavor.elb.s1.medium"),
			Name:      "L4_flavor.elb.s1.medium",
			Type:      "L4",
			Shared:    true,
			ProjectID: projectID,
			Info: flavorInfo{
				Bandwidth:  intPtr(200000),
				Connection: 2000000,
				CPS:        40000,
				LCU:        intPtr(40),
			},
			FlavorSoldOut:     false,
			PublicBorderGroup: "center",
			Category:          0,
		},
	}
	sort.Slice(flavors, func(i, j int) bool { return flavors[i].ID < flavors[j].ID })
	return flavors
}

func findSeededFlavor(region, projectID, id string) (flavorWire, bool) {
	for _, f := range seededFlavors(region, projectID) {
		if f.ID == id {
			return f, true
		}
	}
	return flavorWire{}, false
}

// seededAvailabilityZones returns the region's availability zones in the
// array-of-arrays shape of ListAvailabilityZones (§2).
func seededAvailabilityZones(region string) [][]availabilityZoneWire {
	azs := zones.Of(region)
	group := make([]availabilityZoneWire, len(azs))
	for i, az := range azs {
		group[i] = availabilityZoneWire{
			Code:              az,
			State:             StatusActive,
			Protocol:          []string{"L4", "L7"},
			PublicBorderGroup: "center",
			Category:          0,
		}
	}
	return [][]availabilityZoneWire{group}
}

type systemSecurityPolicySpec struct {
	name      string
	protocols string
	ciphers   string
}

// systemSecurityPolicyTable is the verbatim list from ListSystemSecurityPolicies.txt (§2).
var systemSecurityPolicyTable = []systemSecurityPolicySpec{
	{
		name:      "tls-1-0",
		protocols: "TLSv1.2 TLSv1.1 TLSv1",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-SHA256:AES256-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA",
	},
	{
		name:      "tls-1-0-inherit",
		protocols: "TLSv1.2 TLSv1.1 TLSv1",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-SHA256:AES256-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DHE-DSS-AES128-SHA:CAMELLIA128-SHA:EDH-RSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:CAMELLIA256-SHA:EDH-DSS-DES-CBC3-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA",
	},
	{
		name:      "tls-1-1",
		protocols: "TLSv1.2 TLSv1.1",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-SHA256:AES256-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA",
	},
	{
		name:      "tls-1-2",
		protocols: "TLSv1.2",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-SHA256:AES256-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA",
	},
	{
		name:      "tls-1-2-strict",
		protocols: "TLSv1.2",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-SHA256:AES256-SHA256:ECDHE-RSA-AES256-SHA384",
	},
	{
		name:      "tls-1-2-fs",
		protocols: "TLSv1.2",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384",
	},
	{
		name:      "tls-1-0-with-1-3",
		protocols: "TLSv1.3 TLSv1.2 TLSv1.1 TLSv1",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-SHA256:AES256-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256",
	},
	{
		name:      "tls-1-2-fs-with-1-3",
		protocols: "TLSv1.3 TLSv1.2",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256",
	},
	{
		name:      "hybrid-policy-1-0",
		protocols: "TLSv1.2 TLSv1.1",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:AES128-SHA256:AES256-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA",
	},
	{
		name:      "tls-1-2-strict-no-cbc",
		protocols: "TLSv1.2",
		ciphers:   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
	},
}

func seededSystemSecurityPolicies(projectID string) []systemSecurityPolicyWire {
	out := make([]systemSecurityPolicyWire, len(systemSecurityPolicyTable))
	for i, spec := range systemSecurityPolicyTable {
		out[i] = systemSecurityPolicyWire{
			Name:      spec.name,
			Protocols: spec.protocols,
			Ciphers:   spec.ciphers,
			ProjectID: projectID,
		}
	}
	return out
}

func isSystemSecurityPolicy(name string) bool {
	for _, spec := range systemSecurityPolicyTable {
		if spec.name == name {
			return true
		}
	}
	return false
}

// allowedSecurityPolicyCiphers builds the set of every cipher named in the
// system security policies (§3.9).
func allowedSecurityPolicyCiphers() map[string]struct{} {
	set := make(map[string]struct{})
	for _, spec := range systemSecurityPolicyTable {
		for c := range strings.SplitSeq(spec.ciphers, ":") {
			if c != "" {
				set[c] = struct{}{}
			}
		}
	}
	return set
}
