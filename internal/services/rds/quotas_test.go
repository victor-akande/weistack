package rds

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
)

func (e *env) getQuotas(t *testing.T, project string) ([]QuotaResource, map[string]any) {
	t.Helper()
	status, raw := e.callAs(t, project, http.MethodGet, "/quotas", "")
	if status != http.StatusOK {
		t.Fatalf("GET /quotas: status %d, body %s", status, raw)
	}
	res := decodeInto[showQuotasResponse](t, raw)
	rawMap := decodeInto[map[string]any](t, raw)
	return res.Quotas.Resources, rawMap
}

func TestShowQuotasDefaultsAndUsage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	resources, raw := e.getQuotas(t, testProject)

	// Verify exact JSON shape matches rds/v3 ShowQuotasResponse.
	if len(raw) != 1 {
		t.Fatalf("top-level keys = %v, want only quotas", raw)
	}
	quotasObj, ok := raw["quotas"].(map[string]any)
	if !ok || len(quotasObj) != 1 {
		t.Fatalf("quotas = %v, want object with only resources", raw["quotas"])
	}
	resSlice, ok := quotasObj["resources"].([]any)
	if !ok || len(resSlice) != 1 {
		t.Fatalf("resources = %v, want 1 item", quotasObj["resources"])
	}
	itemMap, ok := resSlice[0].(map[string]any)
	if !ok || len(itemMap) != 3 {
		t.Fatalf("resource item = %v, want 3 fields (type, used, quota)", resSlice[0])
	}
	for _, k := range []string{"type", "used", "quota"} {
		if _, exists := itemMap[k]; !exists {
			t.Errorf("missing JSON field %q in resource item", k)
		}
	}

	var defaults quota.Limits
	wantQuota := defaults.Get(quota.RDSInstance)
	if len(resources) != 1 || resources[0] != (QuotaResource{Type: "instance", Used: 0, Quota: wantQuota}) {
		t.Fatalf("initial quotas = %+v, want instance used=0 quota=%d", resources, wantQuota)
	}

	// Create two instances; usage counts them immediately (BUILD) and after settling (ACTIVE).
	id1, _ := e.mustCreate(t, e.body("name", `"db-one"`))
	e.mustCreate(t, e.body("name", `"db-two"`))

	resources, _ = e.getQuotas(t, testProject)
	if resources[0].Used != 2 || resources[0].Quota != wantQuota {
		t.Fatalf("during BUILD quotas = %+v, want used=2 quota=%d", resources, wantQuota)
	}
	e.settle(t)

	resources, _ = e.getQuotas(t, testProject)
	if resources[0].Used != 2 {
		t.Fatalf("after settle quotas = %+v, want used=2", resources)
	}

	// Another project has isolated usage.
	other, _ := e.getQuotas(t, otherProject)
	if len(other) != 1 || other[0].Used != 0 || other[0].Quota != wantQuota {
		t.Errorf("other project quotas = %+v, want used=0 quota=%d", other, wantQuota)
	}

	// Deleting one instance and settling decrements used.
	if status, out := e.call(t, http.MethodDelete, "/instances/"+id1, ""); status != http.StatusAccepted {
		t.Fatalf("delete instance: %d %s", status, out)
	}
	e.settle(t)

	resources, _ = e.getQuotas(t, testProject)
	if resources[0].Used != 1 {
		t.Errorf("after delete quotas = %+v, want used=1", resources)
	}
}

func TestShowQuotasCustomAndUnlimited(t *testing.T) {
	t.Parallel()

	t.Run("custom", func(t *testing.T) {
		t.Parallel()
		limit := 7
		e := newEnvWith(t, options{quota: limit})

		resources, _ := e.getQuotas(t, testProject)
		if len(resources) != 1 || resources[0] != (QuotaResource{Type: "instance", Used: 0, Quota: limit}) {
			t.Fatalf("custom quotas = %+v, want instance used=0 quota=%d", resources, limit)
		}
	})

	t.Run("unlimited", func(t *testing.T) {
		t.Parallel()
		e := newEnvWith(t, options{quota: quota.Unlimited})
		e.mustCreate(t, e.body("name", `"db-unlim"`))

		resources, _ := e.getQuotas(t, testProject)
		if len(resources) != 1 || resources[0] != (QuotaResource{Type: "instance", Used: 1, Quota: quota.Unlimited}) {
			t.Fatalf("unlimited quotas = %+v, want instance used=1 quota=%d", resources, quota.Unlimited)
		}
	})
}

func TestShowQuotasSeededOverLimit(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	limit := 2
	seededCount := limit + 2

	coll := store.Of[Instance](st, store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindInstance})
	for i := range seededCount {
		id := fmt.Sprintf("0000000000000000000000000000000%din01", i+1)
		if err := coll.Create(t.Context(), id, Instance{
			ID:     id,
			Name:   fmt.Sprintf("seeded-%d", i+1),
			Status: StatusActive,
			Engine: "MySQL",
		}); err != nil {
			t.Fatalf("seed instance %d: %v", i, err)
		}
	}

	e := newEnvWith(t, options{store: st, quota: limit})

	resources, _ := e.getQuotas(t, testProject)
	if len(resources) != 1 || resources[0] != (QuotaResource{Type: "instance", Used: seededCount, Quota: limit}) {
		t.Fatalf("seeded quotas = %+v, want instance used=%d quota=%d", resources, seededCount, limit)
	}

	// Creating one more instance is refused with DBS.200046.
	status, raw := e.call(t, http.MethodPost, "/instances", e.body("name", `"db-over"`))
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("create over limit: status = %d, want %d; body = %s", status, http.StatusRequestEntityTooLarge, raw)
	}
	errBody := decodeInto[map[string]string](t, raw)
	if errBody["error_code"] != "DBS.200046" {
		t.Errorf("error_code = %q, want DBS.200046", errBody["error_code"])
	}
}
