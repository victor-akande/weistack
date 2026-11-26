package kms

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/inventory"
)

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	createdAt := e.now

	const customEP = "11111111-2222-3333-4444-555555555555"
	activeID := e.newKey(t, fmt.Sprintf(`{"key_alias":"app-key","enterprise_project_id":%q}`, customEP))
	if code, out := e.call(t, http.MethodPost, activeID+"/tags/action",
		`{"action":"create","tags":[{"key":"env","value":"prod"},{"key":"team","value":"sec"}]}`); code != http.StatusNoContent {
		t.Fatalf("creating tags: %d %v", code, out)
	}

	disabledID := e.newKey(t, `{"key_alias":"disabled-key"}`)
	e.ok(t, "disable-key", ref(disabledID))

	pendingID := e.newKey(t, `{"key_alias":"pending-key"}`)
	e.ok(t, "schedule-key-deletion", fmt.Sprintf(`{"key_id":%q,"pending_days":%q}`, pendingID, strconv.Itoa(maxPendingDays)))

	expiredID := e.newKey(t, `{"key_alias":"expired-key"}`)
	e.ok(t, "schedule-key-deletion", fmt.Sprintf(`{"key_id":%q,"pending_days":%q}`, expiredID, strconv.Itoa(minPendingDays)))

	// A key in a second project of the primary account, and a key in a
	// second account's project.
	const otherProject = "abcdef0123456789abcdef0123456789"
	code, out := e.callAs(t, "", otherProject, http.MethodPost, "create-key", `{"key_alias":"other-project-key"}`)
	if code != http.StatusOK {
		t.Fatalf("creating key in second project: %d %v", code, out)
	}
	otherProjectKeyID := out["key_info"].(map[string]any)["key_id"].(string)

	partner := identity.Account{ID: "9876543210fedcba9876543210fedcba", Name: "partner"}
	const partnerAK = "PARTNERKEY0000000000"
	if err := e.dir.AddAccount(partner, identity.Credentials{AccessKey: partnerAK, SecretKey: "PartnerSecret0000000"}); err != nil {
		t.Fatal(err)
	}
	partnerProject := partner.DerivedProjectID(testRegion)
	code, out = e.callAs(t, partnerAK, partnerProject, http.MethodPost, "create-key", `{"key_alias":"partner-key"}`)
	if code != http.StatusOK {
		t.Fatalf("creating key in partner account: %d %v", code, out)
	}
	partnerKeyID := out["key_info"].(map[string]any)["key_id"].(string)

	// A service default key (obs/default), created through cmk.Keys.
	dk, err := e.svc.NewDataKey(t.Context(), testRegion, "", "obs")
	if err != nil {
		t.Fatalf("NewDataKey: %v", err)
	}

	// A grant on activeID: kms.grant must not be reported.
	grantID := e.ok(t, "create-grant",
		fmt.Sprintf(`{"key_id":%q,"grantee_principal":%q,"grantee_principal_type":"domain","operations":["decrypt-data","describe-key"],"name":"partner-grant"}`,
			activeID, partner.ID))["grant_id"].(string)

	// Advance past expiredID's scheduled deletion without touching the API,
	// so expiredID stays unpurged in the store while pendingID remains pending.
	e.now = e.now.AddDate(0, 0, minPendingDays)

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := make(map[string]inventory.Resource, len(snap.Resources))
	for _, r := range snap.Resources {
		got[r.Type.String()+"/"+r.ProjectID+"/"+r.ID] = r
	}
	at := func(project, id string) inventory.Resource {
		t.Helper()
		r, ok := got[inventory.KMSKeys.String()+"/"+project+"/"+id]
		if !ok {
			t.Fatalf("%s %s in %s is not reported; got %+v", inventory.KMSKeys, id, project, snap.Resources)
		}
		return r
	}

	wantTags := map[string]string{"env": "prod", "team": "sec"}
	if k := at(testProject, activeID); k.Name != "app-key" || k.RegionID != testRegion ||
		k.ProjectID != testProject || k.AccountID != testAccount.ID || k.EnterpriseProjectID != customEP ||
		!k.Created.Equal(createdAt) || !k.Updated.Equal(createdAt) || k.State != inventory.Succeeded ||
		!reflect.DeepEqual(k.Tags, wantTags) || len(k.Relations) != 0 {
		t.Errorf("active key = %+v", k)
	}
	if k := at(testProject, disabledID); k.Name != "disabled-key" || k.RegionID != testRegion ||
		k.ProjectID != testProject || k.AccountID != testAccount.ID || k.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!k.Created.Equal(createdAt) || k.State != inventory.Succeeded || len(k.Tags) != 0 || len(k.Relations) != 0 {
		t.Errorf("disabled key = %+v", k)
	}
	if k := at(testProject, pendingID); k.Name != "pending-key" || k.RegionID != testRegion ||
		k.ProjectID != testProject || k.AccountID != testAccount.ID || k.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!k.Created.Equal(createdAt) || k.State != inventory.Succeeded || len(k.Tags) != 0 || len(k.Relations) != 0 {
		t.Errorf("pending-deletion key = %+v", k)
	}
	if k := at(otherProject, otherProjectKeyID); k.Name != "other-project-key" || k.RegionID != testRegion ||
		k.ProjectID != otherProject || k.AccountID != testAccount.ID || k.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!k.Created.Equal(createdAt) || k.State != inventory.Succeeded || len(k.Tags) != 0 || len(k.Relations) != 0 {
		t.Errorf("second-project key = %+v", k)
	}
	if k := at(partnerProject, partnerKeyID); k.Name != "partner-key" || k.RegionID != testRegion ||
		k.ProjectID != partnerProject || k.AccountID != partner.ID || k.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!k.Created.Equal(createdAt) || k.State != inventory.Succeeded || len(k.Tags) != 0 || len(k.Relations) != 0 {
		t.Errorf("partner key = %+v", k)
	}
	if k := at(testProject, dk.KeyID); k.Name != "obs/default" || k.RegionID != testRegion ||
		k.ProjectID != testProject || k.AccountID != testAccount.ID || k.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!k.Created.Equal(createdAt) || k.State != inventory.Succeeded || len(k.Tags) != 0 || len(k.Relations) != 0 {
		t.Errorf("default key = %+v", k)
	}

	if _, ok := got[inventory.KMSKeys.String()+"/"+testProject+"/"+expiredID]; ok {
		t.Errorf("expired key %s should not be reported", expiredID)
	}

	reportedKeys := []string{activeID, disabledID, pendingID, otherProjectKeyID, partnerKeyID, dk.KeyID}
	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.KMSKeys: len(reportedKeys),
	}
	if !reflect.DeepEqual(count, want) {
		t.Errorf("reported %v, want %v", count, want)
	}

	// Verify neither grants nor any key material (plain or sealed) appear in the snapshot.
	stored, err := e.svc.keys(testRegion).Get(t.Context(), activeID)
	if err != nil {
		t.Fatalf("loading stored key: %v", err)
	}
	rawMat, err := e.svc.material(stored, 0)
	if err != nil {
		t.Fatalf("opening stored material: %v", err)
	}
	sealedMat := stored.Materials[0].Sealed

	dump := fmt.Sprintf("%+v", snap)
	for label, secret := range map[string]string{
		"grant ID":              grantID,
		"grant name":            "partner-grant",
		"CMK raw hex":           hex.EncodeToString(rawMat),
		"CMK raw base64":        base64.StdEncoding.EncodeToString(rawMat),
		"CMK sealed raw":        string(sealedMat),
		"CMK sealed hex":        hex.EncodeToString(sealedMat),
		"CMK sealed base64":     base64.StdEncoding.EncodeToString(sealedMat),
		"datakey plain hex":     hex.EncodeToString(dk.Plain),
		"datakey plain base64":  base64.StdEncoding.EncodeToString(dk.Plain),
		"datakey sealed hex":    hex.EncodeToString(dk.Sealed),
		"datakey sealed base64": base64.StdEncoding.EncodeToString(dk.Sealed),
	} {
		if strings.Contains(dump, secret) || strings.Contains(dump, strings.ToUpper(secret)) {
			t.Errorf("%s leaked into inventory snapshot", label)
		}
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	for state, want := range map[string]inventory.State{
		stateEnabled:         inventory.Succeeded,
		stateDisabled:        inventory.Succeeded,
		statePendingDeletion: inventory.Succeeded,
	} {
		if got := resourceOf(key{State: state}).State; got != want {
			t.Errorf("resourceOf(State: %s).State = %s, want %s", state, got, want)
		}
	}
}
