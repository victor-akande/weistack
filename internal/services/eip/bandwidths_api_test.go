package eip

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/quota"
)

func TestBandwidthLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newBWEnv(t)

	// 1. Empty list.
	e.expectV1(t, "list_bandwidths_empty", http.MethodGet, "/bandwidths", "")

	// 2. Seed one EIP with a PER bandwidth, and create one shared (WHOLE) bandwidth via v2.0 POST.
	pip, perBW := e.bwSeedPublicIPWithPER(t, "bw-per", 5, "192.0.2.1")

	out := e.expectV20(t, "create_shared_bandwidth", http.MethodPost, "/bandwidths",
		`{"bandwidth": {"name": "bw-shared", "size": 10}}`)
	sharedBW := bwDecodeInto[bandwidthResponse](t, out).Bandwidth

	// 3. Show PER and WHOLE bandwidths.
	e.expectV1(t, "show_bandwidth_per", http.MethodGet, "/bandwidths/"+perBW.ID, "")
	e.expectV1(t, "show_bandwidth_whole", http.MethodGet, "/bandwidths/"+sharedBW.ID, "")

	// 4. List bandwidths (ordered by ascending ID; seed order with seed 7 puts perBW.ID before sharedBW.ID).
	e.expectV1(t, "list_bandwidths", http.MethodGet, "/bandwidths", "")

	// 5. Update PER bandwidth via v1 PUT.
	e.expectV1(t, "update_bandwidth", http.MethodPut, "/bandwidths/"+perBW.ID,
		`{"bandwidth": {"name": "bw-per-updated", "size": 20, "charge_mode": "traffic"}}`)

	// 6. Update WHOLE bandwidth via v2.0 PUT (with extendParam ignored).
	e.expectV20(t, "update_prepaid_bandwidth", http.MethodPut, "/bandwidths/"+sharedBW.ID,
		`{"bandwidth": {"name": "bw-shared-updated", "size": 50}, "extendParam": {"is_auto_pay": "false"}}`)

	// 7. Insert EIP into shared bandwidth via v2.0 POST .../insert.
	e.expectV20(t, "insert_shared_bandwidth", http.MethodPost, "/bandwidths/"+sharedBW.ID+"/insert",
		fmt.Sprintf(`{"bandwidth": {"publicip_info": [{"publicip_id": %q, "publicip_type": "5_bgp"}]}}`, pip.ID))

	// Old PER bandwidth was deleted on insert -> 404 VPC.0306.
	e.expectV1(t, "error_bandwidth_not_found", http.MethodGet, "/bandwidths/"+perBW.ID, "")

	// Deleting shared bandwidth while it still has an EIP -> 409 VPC.0304.
	e.expectV20(t, "error_bandwidth_in_use", http.MethodDelete, "/bandwidths/"+sharedBW.ID, "")

	// 8. Remove EIP from shared bandwidth via v2.0 POST .../remove -> 204.
	e.expectV20(t, "remove_shared_bandwidth", http.MethodPost, "/bandwidths/"+sharedBW.ID+"/remove",
		fmt.Sprintf(`{"bandwidth": {"charge_mode": "bandwidth", "size": 5, "publicip_info": [{"publicip_id": %q}]}}`, pip.ID))

	// 9. Delete now-empty shared bandwidth -> 204.
	e.expectV20(t, "delete_shared_bandwidth", http.MethodDelete, "/bandwidths/"+sharedBW.ID, "")
	e.expectV1(t, "error_bandwidth_not_found", http.MethodGet, "/bandwidths/"+sharedBW.ID, "")
}

func TestBandwidthErrorGoldenFilesPerOperation(t *testing.T) {
	t.Parallel()
	e := newBWEnv(t)

	const unknownID = "00000000-0000-4000-8000-000000000000"
	pip1, perBW1 := e.bwSeedPublicIPWithPER(t, "per-1", 5, "192.0.2.1")
	pip2, _ := e.bwSeedPublicIPWithPER(t, "per-2", 5, "192.0.2.2")

	// ListBandwidths errors: VPC.0301 (bad limit) and VPC.0306 (unknown marker).
	e.expectV1(t, "error_bandwidth_invalid", http.MethodGet, "/bandwidths?limit=-1", "")
	e.expectV1(t, "error_bandwidth_invalid", http.MethodGet, "/bandwidths?limit=abc", "")
	e.expectV1(t, "error_bandwidth_not_found", http.MethodGet, "/bandwidths?marker="+unknownID, "")

	// ShowBandwidth error: VPC.0306.
	e.expectV1(t, "error_bandwidth_not_found", http.MethodGet, "/bandwidths/"+unknownID, "")

	// UpdateBandwidth (v1) and UpdatePrePaidBandwidth (v2.0) errors: VPC.0306 and VPC.0301.
	e.expectV1(t, "error_bandwidth_not_found", http.MethodPut, "/bandwidths/"+unknownID, `{"bandwidth": {"name": "x"}}`)
	e.expectV20(t, "error_bandwidth_not_found", http.MethodPut, "/bandwidths/"+unknownID, `{"bandwidth": {"name": "x"}}`)

	for name, body := range map[string]string{
		"empty body":       ``,
		"malformed json":   `{"bandwidth":`,
		"missing object":   `{}`,
		"bad name":         `{"bandwidth": {"name": "bad name"}}`,
		"per size too big": `{"bandwidth": {"size": 301}}`,
		"bad charge_mode":  `{"bandwidth": {"charge_mode": "invalid"}}`,
	} {
		t.Run("update/"+name, func(t *testing.T) {
			e.expectV1(t, "error_bandwidth_invalid", http.MethodPut, "/bandwidths/"+perBW1.ID, body)
			e.expectV20(t, "error_bandwidth_invalid", http.MethodPut, "/bandwidths/"+perBW1.ID, body)
		})
	}

	// CreateSharedBandwidth errors: VPC.0301 and VPC.0310.
	for name, body := range map[string]string{
		"empty body":      ``,
		"missing object":  `{}`,
		"missing name":    `{"bandwidth": {"size": 10}}`,
		"name too long":   `{"bandwidth": {"name": "` + strings.Repeat("x", 65) + `", "size": 10}}`,
		"size below 5":    `{"bandwidth": {"name": "bw", "size": 4}}`,
		"size above 2000": `{"bandwidth": {"name": "bw", "size": 2001}}`,
		"bad charge_mode": `{"bandwidth": {"name": "bw", "size": 10, "charge_mode": "bad"}}`,
		"bad ep id":       `{"bandwidth": {"name": "bw", "size": 10, "enterprise_project_id": "bad"}}`,
	} {
		t.Run("create_shared/"+name, func(t *testing.T) {
			e.expectV20(t, "error_bandwidth_invalid", http.MethodPost, "/bandwidths", body)
		})
	}

	var sharedIDs []string
	for i := 1; i <= (quota.Limits{}).Get(quota.VPCShareBandwidth); i++ {
		status, out := e.callV20(t, http.MethodPost, "/bandwidths",
			fmt.Sprintf(`{"bandwidth": {"name": "shared-%d", "size": 10}}`, i))
		if status != http.StatusOK {
			t.Fatalf("create shared #%d: %d %s", i, status, out)
		}
		sharedIDs = append(sharedIDs, bwDecodeInto[bandwidthResponse](t, out).Bandwidth.ID)
	}
	e.expectV20(t, "error_shared_bandwidth_quota", http.MethodPost, "/bandwidths",
		`{"bandwidth": {"name": "shared-overflow", "size": 10}}`)

	shared1 := sharedIDs[0]
	shared2 := sharedIDs[1]

	// DeleteSharedBandwidth errors: VPC.0306 (not found), VPC.0323 (PER bandwidth).
	e.expectV20(t, "error_bandwidth_not_found", http.MethodDelete, "/bandwidths/"+unknownID, "")
	e.expectV20(t, "error_shared_bandwidth_modify", http.MethodDelete, "/bandwidths/"+perBW1.ID, "")

	// AddPublicipsIntoSharedBandwidth errors: VPC.0306, VPC.0301, VPC.0323.
	e.expectV20(t, "error_bandwidth_not_found", http.MethodPost, "/bandwidths/"+unknownID+"/insert",
		fmt.Sprintf(`{"bandwidth": {"publicip_info": [{"publicip_id": %q}]}}`, pip1.ID))
	e.expectV20(t, "error_bandwidth_invalid", http.MethodPost, "/bandwidths/"+shared1+"/insert", `{}`)
	e.expectV20(t, "error_bandwidth_invalid", http.MethodPost, "/bandwidths/"+shared1+"/insert",
		`{"bandwidth": {"publicip_info": []}}`)
	e.expectV20(t, "error_bandwidth_invalid", http.MethodPost, "/bandwidths/"+shared1+"/insert",
		fmt.Sprintf(`{"bandwidth": {"publicip_info": [{"publicip_id": %q}]}}`, unknownID))
	e.expectV20(t, "error_shared_bandwidth_modify", http.MethodPost, "/bandwidths/"+perBW1.ID+"/insert",
		fmt.Sprintf(`{"bandwidth": {"publicip_info": [{"publicip_id": %q}]}}`, pip2.ID))

	// Insert pip1 into shared1, then try inserting pip1 into shared2 (already on WHOLE -> VPC.0323).
	status, out := e.callV20(t, http.MethodPost, "/bandwidths/"+shared1+"/insert",
		fmt.Sprintf(`{"bandwidth": {"publicip_info": [{"publicip_id": %q}]}}`, pip1.ID))
	if status != http.StatusOK {
		t.Fatalf("insert pip1: %d %s", status, out)
	}
	e.expectV20(t, "error_shared_bandwidth_modify", http.MethodPost, "/bandwidths/"+shared2+"/insert",
		fmt.Sprintf(`{"bandwidth": {"publicip_info": [{"publicip_id": %q}]}}`, pip1.ID))

	// DeleteSharedBandwidth error when EIPs still in it -> VPC.0304.
	e.expectV20(t, "error_bandwidth_in_use", http.MethodDelete, "/bandwidths/"+shared1, "")

	// RemovePublicipsFromSharedBandwidth errors: VPC.0306, VPC.0301, VPC.0323.
	e.expectV20(t, "error_bandwidth_not_found", http.MethodPost, "/bandwidths/"+unknownID+"/remove",
		fmt.Sprintf(`{"bandwidth": {"charge_mode": "bandwidth", "size": 5, "publicip_info": [{"publicip_id": %q}]}}`, pip1.ID))
	e.expectV20(t, "error_bandwidth_invalid", http.MethodPost, "/bandwidths/"+shared1+"/remove", `{}`)
	e.expectV20(t, "error_bandwidth_invalid", http.MethodPost, "/bandwidths/"+shared1+"/remove",
		fmt.Sprintf(`{"bandwidth": {"charge_mode": "bad", "size": 5, "publicip_info": [{"publicip_id": %q}]}}`, pip1.ID))
	e.expectV20(t, "error_bandwidth_invalid", http.MethodPost, "/bandwidths/"+shared1+"/remove",
		fmt.Sprintf(`{"bandwidth": {"charge_mode": "bandwidth", "size": 301, "publicip_info": [{"publicip_id": %q}]}}`, pip1.ID))
	e.expectV20(t, "error_shared_bandwidth_modify", http.MethodPost, "/bandwidths/"+shared1+"/remove",
		fmt.Sprintf(`{"bandwidth": {"charge_mode": "bandwidth", "size": 5, "publicip_info": [{"publicip_id": %q}]}}`, pip2.ID))
}

func TestListBandwidthsFiltersAndPagingHTTP(t *testing.T) {
	t.Parallel()
	e := newBWEnv(t)

	const customEP = "0aad99bc-f5f6-4f78-8404-c598d76b0ed2"
	_, perBW := e.bwSeedPublicIPWithPERInEP(t, "per-ep", 5, "192.0.2.1", customEP)

	status, out := e.callV20(t, http.MethodPost, "/bandwidths",
		`{"bandwidth": {"name": "whole-default", "size": 10}}`)
	if status != http.StatusOK {
		t.Fatalf("create whole-default: %d %s", status, out)
	}
	wholeDefault := bwDecodeInto[bandwidthResponse](t, out).Bandwidth

	status, out = e.callV20(t, http.MethodPost, "/bandwidths",
		fmt.Sprintf(`{"bandwidth": {"name": "whole-ep", "size": 15, "enterprise_project_id": %q}}`, customEP))
	if status != http.StatusOK {
		t.Fatalf("create whole-ep: %d %s", status, out)
	}
	wholeEP := bwDecodeInto[bandwidthResponse](t, out).Bandwidth

	listIDs := func(query string) []string {
		t.Helper()
		st, raw := e.callV1(t, http.MethodGet, "/bandwidths"+query, "")
		if st != http.StatusOK {
			t.Fatalf("GET /bandwidths%s: %d %s", query, st, raw)
		}
		var ids []string
		for _, bw := range bwDecodeInto[listBandwidthsResponse](t, raw).Bandwidths {
			ids = append(ids, bw.ID)
		}
		return ids
	}

	// Filter by share_type=PER and share_type=WHOLE.
	if got := listIDs("?share_type=PER"); len(got) != 1 || got[0] != perBW.ID {
		t.Fatalf("share_type=PER: got %v, want [%s]", got, perBW.ID)
	}
	if got := listIDs("?share_type=WHOLE"); len(got) != 2 {
		t.Fatalf("share_type=WHOLE: got %v, want 2 items", got)
	}

	// Filter by enterprise_project_id and all_granted_eps.
	if got := listIDs("?enterprise_project_id=0"); len(got) != 1 || got[0] != wholeDefault.ID {
		t.Fatalf("enterprise_project_id=0: got %v, want [%s]", got, wholeDefault.ID)
	}
	if got := listIDs("?enterprise_project_id=" + customEP); len(got) != 2 {
		t.Fatalf("enterprise_project_id=custom: got %v, want 2 items (%s, %s)", got, perBW.ID, wholeEP.ID)
	}
	all := listIDs("?enterprise_project_id=all_granted_eps")
	if len(all) != 3 {
		t.Fatalf("all_granted_eps: got %v, want 3 items", all)
	}

	// Paging with limit=1 and marker.
	page1 := listIDs("?limit=1")
	if len(page1) != 1 || page1[0] != all[0] {
		t.Fatalf("page1 = %v, want [%s]", page1, all[0])
	}
	page2 := listIDs("?limit=1&marker=" + page1[0])
	if len(page2) != 1 || page2[0] != all[1] {
		t.Fatalf("page2 = %v, want [%s]", page2, all[1])
	}
	page3 := listIDs("?limit=1&marker=" + page2[0])
	if len(page3) != 1 || page3[0] != all[2] {
		t.Fatalf("page3 = %v, want [%s]", page3, all[2])
	}
	page4 := listIDs("?limit=1&marker=" + page3[0])
	if len(page4) != 0 {
		t.Fatalf("page4 = %v, want empty", page4)
	}
}
