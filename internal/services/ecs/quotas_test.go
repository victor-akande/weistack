package ecs

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
)

func (e *env) getLimits(t *testing.T, project string) (ServerLimits, map[string]any) {
	t.Helper()
	path := "/v1/" + project + "/cloudservers/limits"
	status, raw := e.call(t, http.MethodGet, path, "")
	if status != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", path, status, raw)
	}
	res := decodeInto[showServerLimitsResponse](t, raw)
	rawMap := decodeInto[map[string]any](t, raw)
	return res.Absolute, rawMap
}

func TestShowServerLimitsDefaultsAndUsage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	got, raw := e.getLimits(t, testProject)

	// Verify exact top-level and absolute JSON keys match ecs/v2 ServerLimits.
	if len(raw) != 1 {
		t.Fatalf("top-level keys = %v, want only absolute", raw)
	}
	absMap, ok := raw["absolute"].(map[string]any)
	if !ok {
		t.Fatalf("absolute is not a JSON object: %T", raw["absolute"])
	}
	wantKeys := []string{
		"maxImageMeta",
		"maxPersonality",
		"maxPersonalitySize",
		"maxSecurityGroupRules",
		"maxSecurityGroups",
		"maxServerGroupMembers",
		"maxServerGroups",
		"maxServerMeta",
		"maxTotalCores",
		"maxTotalFloatingIps",
		"maxTotalInstances",
		"maxTotalKeypairs",
		"maxTotalRAMSize",
		"totalCoresUsed",
		"totalFloatingIpsUsed",
		"totalInstancesUsed",
		"totalRAMUsed",
		"totalSecurityGroupsUsed",
		"totalServerGroupsUsed",
	}
	if len(absMap) != len(wantKeys) {
		t.Fatalf("absolute has %d keys, want %d: %v", len(absMap), len(wantKeys), absMap)
	}
	for _, k := range wantKeys {
		if _, exists := absMap[k]; !exists {
			t.Errorf("missing JSON field %q in absolute", k)
		}
	}

	var defaults quota.Limits
	wantInitial := ServerLimits{
		MaxImageMeta:            limitMaxImageMeta,
		MaxPersonality:          limitMaxPersonality,
		MaxPersonalitySize:      limitMaxPersonalitySize,
		MaxSecurityGroupRules:   limitMaxSecurityGroupRules,
		MaxSecurityGroups:       defaults.Get(quota.VPCSecurityGroup),
		MaxServerGroupMembers:   limitMaxServerGroupMembers,
		MaxServerGroups:         limitMaxServerGroups,
		MaxServerMeta:           limitMaxServerMeta,
		MaxTotalCores:           defaults.Get(quota.ECSCores),
		MaxTotalFloatingIps:     defaults.Get(quota.VPCPublicIP),
		MaxTotalInstances:       defaults.Get(quota.ECSInstances),
		MaxTotalKeypairs:        quota.Unlimited,
		MaxTotalRAMSize:         quota.Unlimited,
		TotalCoresUsed:          0,
		TotalFloatingIpsUsed:    0,
		TotalInstancesUsed:      0,
		TotalRAMUsed:            0,
		TotalSecurityGroupsUsed: 1, // VPC default security group
		TotalServerGroupsUsed:   0,
	}
	if got != wantInitial {
		t.Fatalf("initial limits = %+v, want %+v", got, wantInitial)
	}

	// Create network (adds one custom security group "web" on top of "default").
	net := e.mustNetwork(t, testTenant, "192.168.10.0/24")

	f1, ok := e.svc.FlavorByName("s6.large.2")
	if !ok {
		t.Fatal("missing flavor s6.large.2")
	}
	f2, ok := e.svc.FlavorByName("s6.xlarge.4")
	if !ok {
		t.Fatal("missing flavor s6.xlarge.4")
	}

	// Server 1 with a newly created EIP.
	_, ids1 := e.mustCreate(t, net.serverBody(
		"name", `"srv-one"`,
		"flavorRef", fmt.Sprintf("%q", f1.Name),
		"publicip", `{"eip":{"iptype":"5_bgp","bandwidth":{"size":5,"sharetype":"PER"}},"delete_on_termination":true}`,
	))
	// Server 2 without an EIP.
	_, _ = e.mustCreate(t, net.serverBody(
		"name", `"srv-two"`,
		"flavorRef", fmt.Sprintf("%q", f2.Name),
	))
	e.settle(t)

	got, _ = e.getLimits(t, testProject)
	if got.TotalInstancesUsed != 2 {
		t.Errorf("totalInstancesUsed = %d, want 2", got.TotalInstancesUsed)
	}
	if wantCores := f1.VCPUs + f2.VCPUs; got.TotalCoresUsed != wantCores {
		t.Errorf("totalCoresUsed = %d, want %d", got.TotalCoresUsed, wantCores)
	}
	if wantRAM := int64(f1.RAM + f2.RAM); got.TotalRAMUsed != wantRAM {
		t.Errorf("totalRAMUsed = %d, want %d", got.TotalRAMUsed, wantRAM)
	}
	if got.TotalFloatingIpsUsed != 1 {
		t.Errorf("totalFloatingIpsUsed = %d, want 1", got.TotalFloatingIpsUsed)
	}
	if got.TotalSecurityGroupsUsed != 2 {
		t.Errorf("totalSecurityGroupsUsed = %d, want 2", got.TotalSecurityGroupsUsed)
	}

	// Another project has isolated usage.
	other, _ := e.getLimits(t, otherProject)
	if other.TotalInstancesUsed != 0 || other.TotalCoresUsed != 0 || other.TotalRAMUsed != 0 || other.TotalFloatingIpsUsed != 0 || other.TotalSecurityGroupsUsed != 1 {
		t.Errorf("other project limits = %+v, want zero server/EIP usage and 1 default SG", other)
	}

	// Deleting server 1 with delete_publicip=true frees its instances, cores, RAM and EIP.
	delBody := fmt.Sprintf(`{"servers":[{"id":%q}],"delete_publicip":true,"delete_volume":true}`, ids1[0])
	if status, out := e.call(t, http.MethodPost, "/v1/{project}/cloudservers/delete", delBody); status != http.StatusOK {
		t.Fatalf("delete server: %d %s", status, out)
	}
	e.settle(t)

	got, _ = e.getLimits(t, testProject)
	if got.TotalInstancesUsed != 1 {
		t.Errorf("after delete totalInstancesUsed = %d, want 1", got.TotalInstancesUsed)
	}
	if got.TotalCoresUsed != f2.VCPUs {
		t.Errorf("after delete totalCoresUsed = %d, want %d", got.TotalCoresUsed, f2.VCPUs)
	}
	if got.TotalRAMUsed != int64(f2.RAM) {
		t.Errorf("after delete totalRAMUsed = %d, want %d", got.TotalRAMUsed, f2.RAM)
	}
	if got.TotalFloatingIpsUsed != 0 {
		t.Errorf("after delete totalFloatingIpsUsed = %d, want 0", got.TotalFloatingIpsUsed)
	}
}

func TestShowServerLimitsCustomAndUnlimited(t *testing.T) {
	t.Parallel()

	t.Run("custom", func(t *testing.T) {
		t.Parallel()
		maxInstances := 7
		maxCores := 24
		maxEIPs := 3
		maxSGs := 6
		limits := quota.For(map[quota.Key]int{
			quota.ECSInstances:     maxInstances,
			quota.ECSCores:         maxCores,
			quota.VPCPublicIP:      maxEIPs,
			quota.VPCSecurityGroup: maxSGs,
		})
		e := newEnvLimits(t, store.NewMemory(), "", limits, nil)

		got, _ := e.getLimits(t, testProject)
		if got.MaxTotalInstances != maxInstances {
			t.Errorf("maxTotalInstances = %d, want %d", got.MaxTotalInstances, maxInstances)
		}
		if got.MaxTotalCores != maxCores {
			t.Errorf("maxTotalCores = %d, want %d", got.MaxTotalCores, maxCores)
		}
		if got.MaxTotalFloatingIps != maxEIPs {
			t.Errorf("maxTotalFloatingIps = %d, want %d", got.MaxTotalFloatingIps, maxEIPs)
		}
		if got.MaxSecurityGroups != maxSGs {
			t.Errorf("maxSecurityGroups = %d, want %d", got.MaxSecurityGroups, maxSGs)
		}
	})

	t.Run("unlimited", func(t *testing.T) {
		t.Parallel()
		limits := quota.For(map[quota.Key]int{
			quota.ECSInstances:     quota.Unlimited,
			quota.ECSCores:         quota.Unlimited,
			quota.VPCPublicIP:      quota.Unlimited,
			quota.VPCSecurityGroup: quota.Unlimited,
		})
		e := newEnvLimits(t, store.NewMemory(), "", limits, nil)

		got, _ := e.getLimits(t, testProject)
		if got.MaxTotalInstances != quota.Unlimited ||
			got.MaxTotalCores != quota.Unlimited ||
			got.MaxTotalFloatingIps != quota.Unlimited ||
			got.MaxSecurityGroups != quota.Unlimited {
			t.Errorf("unlimited limits = %+v, want %d for all configured keys", got, quota.Unlimited)
		}
	})
}

func TestShowServerLimitsNilEIPs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := New(Deps{
		Store:   e.store,
		Engine:  e.engine,
		IDs:     ids.NewSeeded(21),
		Logger:  log,
		Network: e.network,
		EIPs:    nil,
		Images:  e.images,
		Volumes: e.volumes,
		Now:     e.clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := svc.ShowLimits(t.Context(), testTenant)
	if err != nil {
		t.Fatalf("ShowLimits: %v", err)
	}
	if got.TotalFloatingIpsUsed != 0 {
		t.Errorf("totalFloatingIpsUsed = %d, want 0 when EIPs is nil", got.TotalFloatingIpsUsed)
	}
}

func TestShowServerLimitsSeededOverQuota(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	instLimit := 2
	seededCount := instLimit + 2

	flavorName := "s6.large.2"
	coll := store.Of[Server](st, store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindServer})
	for i := range seededCount {
		id := fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", i+1)
		if err := coll.Create(t.Context(), id, Server{
			ID:     id,
			Name:   fmt.Sprintf("seeded-%d", i+1),
			Status: StatusActive,
			Flavor: flavorName,
		}); err != nil {
			t.Fatalf("seed server %d: %v", i, err)
		}
	}

	// Configure limits below the seeded server and vCPU totals.
	coreLimit := 2
	limits := quota.For(map[quota.Key]int{
		quota.ECSInstances: instLimit,
		quota.ECSCores:     coreLimit,
	})
	e := newEnvLimits(t, st, "", limits, nil)
	f, ok := e.svc.FlavorByName(flavorName)
	if !ok {
		t.Fatalf("missing flavor %s", flavorName)
	}

	got, _ := e.getLimits(t, testProject)
	if got.MaxTotalInstances != instLimit {
		t.Errorf("maxTotalInstances = %d, want %d", got.MaxTotalInstances, instLimit)
	}
	if got.TotalInstancesUsed != seededCount {
		t.Errorf("totalInstancesUsed = %d, want %d (> limit %d)", got.TotalInstancesUsed, seededCount, instLimit)
	}
	if wantCores := seededCount * f.VCPUs; got.TotalCoresUsed != wantCores {
		t.Errorf("totalCoresUsed = %d, want %d (> limit %d)", got.TotalCoresUsed, wantCores, coreLimit)
	}
	if wantRAM := int64(seededCount * f.RAM); got.TotalRAMUsed != wantRAM {
		t.Errorf("totalRAMUsed = %d, want %d", got.TotalRAMUsed, wantRAM)
	}

	// Creating one more server is refused with Ecs.0001.
	net := e.mustNetwork(t, testTenant, "192.168.20.0/24")
	status, raw := e.call(t, http.MethodPost, serversPath, net.serverBody("name", `"over-limit"`))
	if status != http.StatusBadRequest {
		t.Fatalf("create over limit: status = %d, want %d; body = %s", status, http.StatusBadRequest, raw)
	}
	errBody := decodeInto[map[string]map[string]string](t, raw)
	if errBody["error"]["code"] != "Ecs.0001" {
		t.Errorf("error code = %q, want Ecs.0001", errBody["error"]["code"])
	}
}
