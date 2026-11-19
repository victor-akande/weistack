package eip

import (
	"net/http"
	"strings"
	"testing"
)

func TestPublicIPLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)

	e.expect(t, "list_publicips_empty", http.MethodGet, "/publicips", "")

	out := e.expect(t, "create_publicip", http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "alias": "eip-1"},
		"bandwidth": {"name": "bw-1", "size": 10, "share_type": "PER"}
	}`)
	id := pipDecodeInto[createPublicIPResponse](t, out).PublicIP.ID

	// Still PENDING_CREATE before lifecycle delay settles: binding, unbinding, and deleting return VPC.0512.
	e.expect(t, "error_publicip_busy", http.MethodPut, "/publicips/"+id,
		`{"publicip": {"port_id": "`+pipPortID1+`"}}`)
	e.expect(t, "error_publicip_busy", http.MethodPut, "/publicips/"+id,
		`{"publicip": {}}`)
	e.expect(t, "error_publicip_busy", http.MethodDelete, "/publicips/"+id, "")

	e.settle(t)

	e.expect(t, "show_publicip", http.MethodGet, "/publicips/"+id, "")
	e.expect(t, "list_publicips", http.MethodGet, "/publicips", "")

	e.expect(t, "update_publicip_bind", http.MethodPut, "/publicips/"+id,
		`{"publicip": {"port_id": "`+pipPortID1+`"}}`)
	e.expect(t, "show_publicip_bound", http.MethodGet, "/publicips/"+id, "")

	// Deleting a bound EIP returns VPC.0517.
	e.expect(t, "error_publicip_bound", http.MethodDelete, "/publicips/"+id, "")

	// Unbind with empty object {} as Terraform does.
	e.expect(t, "update_publicip_unbind", http.MethodPut, "/publicips/"+id,
		`{"publicip": {}}`)

	e.expect(t, "delete_publicip", http.MethodDelete, "/publicips/"+id, "")
	e.expect(t, "error_publicip_not_found", http.MethodGet, "/publicips/"+id, "")
	e.expect(t, "error_publicip_not_found", http.MethodPut, "/publicips/"+id, `{"publicip": {}}`)
	e.expect(t, "error_publicip_not_found", http.MethodDelete, "/publicips/"+id, "")
}

func TestCreatePublicIPValidationAndErrorCodes(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)

	// Seed one EIP bound to pipPortID1 so we have an in-use IP (192.0.2.1), a bound port, and a PER bandwidth.
	status, raw := e.call(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "port_id": "`+pipPortID1+`"},
		"bandwidth": {"name": "bw-seed", "size": 5, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("seed create: %d %s", status, raw)
	}
	e.settle(t)
	seedID := pipDecodeInto[createPublicIPResponse](t, raw).PublicIP.ID
	seedRec, err := e.svc.publicips(pipTestTenant).Get(t.Context(), seedID)
	if err != nil {
		t.Fatalf("get seed EIP: %v", err)
	}
	perBWID := seedRec.BandwidthID

	tests := []struct {
		name   string
		body   string
		golden string
	}{
		{
			name:   "empty body",
			body:   ``,
			golden: "error_publicip_invalid",
		},
		{
			name:   "malformed json",
			body:   `{"publicip": `,
			golden: "error_publicip_invalid",
		},
		{
			name:   "missing publicip object",
			body:   `{"bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_publicip_invalid",
		},
		{
			name:   "empty publicip object",
			body:   `{"publicip": {}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_publicip_invalid",
		},
		{
			name:   "unsupported type in region",
			body:   `{"publicip": {"type": "5_sbgp"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_publicip_invalid",
		},
		{
			name:   "ipv6 not implemented",
			body:   `{"publicip": {"type": "5_bgp", "ip_version": 6}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_ipv6_not_implemented",
		},
		{
			name:   "invalid ip_version",
			body:   `{"publicip": {"type": "5_bgp", "ip_version": 5}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_publicip_invalid",
		},
		{
			name:   "invalid alias with space",
			body:   `{"publicip": {"type": "5_bgp", "alias": "bad name"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_publicip_invalid",
		},
		{
			name:   "alias too long",
			body:   `{"publicip": {"type": "5_bgp", "alias": "` + strings.Repeat("a", 65) + `"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_publicip_invalid",
		},
		{
			name:   "ip_address outside range",
			body:   `{"publicip": {"type": "5_bgp", "ip_address": "10.0.0.1"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_ip_address_in_use",
		},
		{
			name:   "ip_address already in use",
			body:   `{"publicip": {"type": "5_bgp", "ip_address": "192.0.2.1"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_ip_address_in_use",
		},
		{
			name:   "port_id unknown",
			body:   `{"publicip": {"type": "5_bgp", "port_id": "` + pipUnknownID + `"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_port_invalid",
		},
		{
			name:   "port_id already bound",
			body:   `{"publicip": {"type": "5_bgp", "port_id": "` + pipPortID1 + `"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}}`,
			golden: "error_port_already_bound",
		},
		{
			name:   "missing bandwidth object",
			body:   `{"publicip": {"type": "5_bgp"}}`,
			golden: "error_publicip_invalid",
		},
		{
			name:   "invalid bandwidth share_type",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "BAD"}}`,
			golden: "error_publicip_invalid",
		},
		{
			name:   "PER missing name",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"size": 5, "share_type": "PER"}}`,
			golden: "error_bandwidth_invalid",
		},
		{
			name:   "PER invalid name",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"name": "bad name", "size": 5, "share_type": "PER"}}`,
			golden: "error_bandwidth_invalid",
		},
		{
			name:   "PER size 0",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"name": "bw", "size": 0, "share_type": "PER"}}`,
			golden: "error_bandwidth_invalid",
		},
		{
			name:   "PER size 301",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"name": "bw", "size": 301, "share_type": "PER"}}`,
			golden: "error_bandwidth_invalid",
		},
		{
			name:   "PER invalid charge_mode",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER", "charge_mode": "packets"}}`,
			golden: "error_bandwidth_invalid",
		},
		{
			name:   "WHOLE missing id",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"share_type": "WHOLE"}}`,
			golden: "error_bandwidth_invalid",
		},
		{
			name:   "WHOLE unknown bandwidth id",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"share_type": "WHOLE", "id": "` + pipUnknownID + `"}}`,
			golden: "error_bandwidth_not_found",
		},
		{
			name:   "WHOLE pointing at PER bandwidth",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"share_type": "WHOLE", "id": "` + perBWID + `"}}`,
			golden: "error_bandwidth_not_found",
		},
		{
			name:   "invalid enterprise_project_id",
			body:   `{"publicip": {"type": "5_bgp"}, "bandwidth": {"name": "bw", "size": 5, "share_type": "PER"}, "enterprise_project_id": "not-a-uuid"}`,
			golden: "error_enterprise_project_invalid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.expect(t, tc.golden, http.MethodPost, "/publicips", tc.body)
		})
	}
}

func TestCreatePublicIPQuotaAndPoolExhaustionGolden(t *testing.T) {
	t.Parallel()

	// Quota exceeded (VPC.0521).
	eQuota := newPIPEnvWithOptions(t, 0, 1)
	status, out := eQuota.call(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp"},
		"bandwidth": {"name": "bw-1", "size": 5, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("first create: %d %s", status, out)
	}
	eQuota.expect(t, "error_publicip_quota", http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp"},
		"bandwidth": {"name": "bw-2", "size": 5, "share_type": "PER"}
	}`)

	// Address pool exhausted (VPC.0532).
	ePool := newPIPEnv(t)
	ePool.svc.pool = []string{"192.0.2.1"}
	status, out = ePool.call(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp"},
		"bandwidth": {"name": "bw-1", "size": 5, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("first pool create: %d %s", status, out)
	}
	ePool.expect(t, "error_address_pool_exhausted", http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp"},
		"bandwidth": {"name": "bw-2", "size": 5, "share_type": "PER"}
	}`)
}

func TestCreateAndDeletePublicIPWithWholeBandwidth(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)
	ctx := t.Context()

	// Seed a WHOLE bandwidth directly in the bandwidth collection.
	shared := bandwidth{
		ID:                  pipSharedBWID,
		Name:                "shared-bw",
		Size:                50,
		ShareType:           ShareTypeWhole,
		ChargeMode:          ChargeModeBandwidth,
		EnterpriseProjectID: "0",
		PublicIPIDs:         []string{},
		CreatedAt:           pipTestEpoch,
		UpdatedAt:           pipTestEpoch,
	}
	if err := e.svc.bandwidths(pipTestTenant).Create(ctx, shared.ID, shared); err != nil {
		t.Fatalf("seed WHOLE bandwidth: %v", err)
	}

	status, out := e.call(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "alias": "shared-eip"},
		"bandwidth": {"share_type": "WHOLE", "id": "`+pipSharedBWID+`"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("create with WHOLE bandwidth: %d %s", status, out)
	}
	pipID := pipDecodeInto[createPublicIPResponse](t, out).PublicIP.ID
	e.settle(t)

	// Show reflects the WHOLE bandwidth's metadata.
	status, out = e.call(t, http.MethodGet, "/publicips/"+pipID, "")
	if status != http.StatusOK {
		t.Fatalf("show: %d %s", status, out)
	}
	shown := pipDecodeInto[showPublicIPResponse](t, out).PublicIP
	if shown.BandwidthID != pipSharedBWID || shown.BandwidthShareType != ShareTypeWhole || shown.BandwidthSize != 50 || shown.BandwidthName != "shared-bw" {
		t.Fatalf("shown bandwidth = %+v", shown)
	}

	bwAfterCreate, err := e.svc.bandwidths(pipTestTenant).Get(ctx, pipSharedBWID)
	if err != nil || len(bwAfterCreate.PublicIPIDs) != 1 || bwAfterCreate.PublicIPIDs[0] != pipID {
		t.Fatalf("WHOLE bandwidth PublicIPIDs after create = %+v, %v", bwAfterCreate.PublicIPIDs, err)
	}

	// Deleting the EIP removes it from PublicIPIDs but keeps the WHOLE bandwidth.
	e.expect(t, "delete_publicip", http.MethodDelete, "/publicips/"+pipID, "")
	bwAfterDelete, err := e.svc.bandwidths(pipTestTenant).Get(ctx, pipSharedBWID)
	if err != nil || len(bwAfterDelete.PublicIPIDs) != 0 {
		t.Fatalf("WHOLE bandwidth after EIP delete = %+v, %v", bwAfterDelete, err)
	}
}

func TestUpdatePublicIPErrorCodesGolden(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)

	// Create EIP 1 bound to pipPortID1, and EIP 2 unbound.
	status, raw1 := e.call(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp", "port_id": "`+pipPortID1+`"},
		"bandwidth": {"name": "bw-1", "size": 5, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("create 1: %d %s", status, raw1)
	}
	id1 := pipDecodeInto[createPublicIPResponse](t, raw1).PublicIP.ID

	status, raw2 := e.call(t, http.MethodPost, "/publicips", `{
		"publicip": {"type": "5_bgp"},
		"bandwidth": {"name": "bw-2", "size": 5, "share_type": "PER"}
	}`)
	if status != http.StatusOK {
		t.Fatalf("create 2: %d %s", status, raw2)
	}
	id2 := pipDecodeInto[createPublicIPResponse](t, raw2).PublicIP.ID
	e.settle(t)

	// Port already has a different EIP -> VPC.0511.
	e.expect(t, "error_port_already_bound", http.MethodPut, "/publicips/"+id2,
		`{"publicip": {"port_id": "`+pipPortID1+`"}}`)

	// EIP 1 is already bound to pipPortID1; binding it to pipPortID2 -> VPC.0510.
	e.expect(t, "error_publicip_already_bound", http.MethodPut, "/publicips/"+id1,
		`{"publicip": {"port_id": "`+pipPortID2+`"}}`)

	// Invalid update payloads -> VPC.0501.
	invalidPayloads := map[string]string{
		"unknown port":                `{"publicip": {"port_id": "` + pipUnknownID + `"}}`,
		"port_id and ip_version both": `{"publicip": {"port_id": "` + pipPortID2 + `", "ip_version": 4}}`,
		"ip_version not 4":            `{"publicip": {"ip_version": 6}}`,
		"invalid alias":               `{"publicip": {"alias": "bad alias"}}`,
		"missing publicip object":     `{}`,
		"malformed json":              `{"publicip": `,
	}
	for name, body := range invalidPayloads {
		t.Run(name, func(t *testing.T) {
			e.expect(t, "error_publicip_invalid", http.MethodPut, "/publicips/"+id2, body)
		})
	}
}

func TestListPublicIPsFiltersOrderingAndPaging(t *testing.T) {
	t.Parallel()
	e := newPIPEnv(t)

	const epCustom = "0aad99bc-f5f6-4f78-8404-c598d76b0ed2"

	// Create 3 EIPs: one bound to pipPortID1, one in a custom enterprise project, one plain.
	bodies := []string{
		`{"publicip": {"type": "5_bgp", "alias": "a", "port_id": "` + pipPortID1 + `"}, "bandwidth": {"name": "bw-a", "size": 5, "share_type": "PER"}}`,
		`{"publicip": {"type": "5_bgp", "alias": "b", "ip_address": "198.51.100.5"}, "bandwidth": {"name": "bw-b", "size": 5, "share_type": "PER"}, "enterprise_project_id": "` + epCustom + `"}`,
		`{"publicip": {"type": "5_bgp", "alias": "c"}, "bandwidth": {"name": "bw-c", "size": 5, "share_type": "PER"}}`,
	}
	for _, b := range bodies {
		status, out := e.call(t, http.MethodPost, "/publicips", b)
		if status != http.StatusOK {
			t.Fatalf("create: %d %s", status, out)
		}
	}
	e.settle(t)

	// Full list is sorted by ascending ID.
	status, rawAll := e.call(t, http.MethodGet, "/publicips", "")
	if status != http.StatusOK {
		t.Fatalf("list all: %d %s", status, rawAll)
	}
	all := pipDecodeInto[listPublicIPsResponse](t, rawAll).PublicIPs
	if len(all) != 3 {
		t.Fatalf("len(all) = %d, want 3", len(all))
	}
	if all[0].ID >= all[1].ID || all[1].ID >= all[2].ID {
		t.Fatalf("IDs not sorted ascending: %q, %q, %q", all[0].ID, all[1].ID, all[2].ID)
	}

	listIDs := func(query string) []string {
		t.Helper()
		st, out := e.call(t, http.MethodGet, "/publicips"+query, "")
		if st != http.StatusOK {
			t.Fatalf("list %s: %d %s", query, st, out)
		}
		var ids []string
		for _, p := range pipDecodeInto[listPublicIPsResponse](t, out).PublicIPs {
			ids = append(ids, p.ID)
		}
		return ids
	}

	// Repeatable id filter.
	gotByID := listIDs("?id=" + all[0].ID + "&id=" + all[2].ID)
	if len(gotByID) != 2 || gotByID[0] != all[0].ID || gotByID[1] != all[2].ID {
		t.Fatalf("repeatable id filter = %v, want [%s %s]", gotByID, all[0].ID, all[2].ID)
	}

	// port_id and private_ip_address filters.
	if got := listIDs("?port_id=" + pipPortID1); len(got) != 1 {
		t.Fatalf("port_id filter = %v, want 1 match", got)
	}
	if got := listIDs("?private_ip_address=192.168.0.10"); len(got) != 1 {
		t.Fatalf("private_ip_address filter = %v, want 1 match", got)
	}

	// public_ip_address and ip_version filters.
	if got := listIDs("?public_ip_address=198.51.100.5"); len(got) != 1 {
		t.Fatalf("public_ip_address filter = %v, want 1 match", got)
	}
	if got := listIDs("?ip_version=4"); len(got) != 3 {
		t.Fatalf("ip_version=4 filter = %v, want 3 matches", got)
	}
	if got := listIDs("?ip_version=6"); len(got) != 0 {
		t.Fatalf("ip_version=6 filter = %v, want 0 matches", got)
	}

	// enterprise_project_id filter including all_granted_eps.
	if got := listIDs("?enterprise_project_id=0"); len(got) != 2 {
		t.Fatalf("enterprise_project_id=0 = %v, want 2", got)
	}
	if got := listIDs("?enterprise_project_id=" + epCustom); len(got) != 1 {
		t.Fatalf("enterprise_project_id=custom = %v, want 1", got)
	}
	if got := listIDs("?enterprise_project_id=all_granted_eps"); len(got) != 3 {
		t.Fatalf("enterprise_project_id=all_granted_eps = %v, want 3", got)
	}

	// Paging with limit and marker.
	page1 := listIDs("?limit=2")
	if len(page1) != 2 || page1[0] != all[0].ID || page1[1] != all[1].ID {
		t.Fatalf("page1 = %v", page1)
	}
	page2 := listIDs("?limit=2&marker=" + all[1].ID)
	if len(page2) != 1 || page2[0] != all[2].ID {
		t.Fatalf("page2 = %v", page2)
	}

	// Error cases on list: bad limit -> VPC.0501, unknown marker -> VPC.0504.
	e.expect(t, "error_publicip_invalid", http.MethodGet, "/publicips?limit=-1", "")
	e.expect(t, "error_publicip_invalid", http.MethodGet, "/publicips?limit=abc", "")
	e.expect(t, "error_publicip_not_found", http.MethodGet, "/publicips?marker="+pipUnknownID, "")
}
