package sdk

import (
	"testing"

	ecsv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
)

func newECS(t *testing.T) *ecsv2.EcsClient {
	t.Helper()
	hc, err := ecsv2.EcsClientBuilder().
		WithEndpoints([]string{"http://ecs." + region + ".myhuaweicloud.com"}).
		WithCredential(credentials(t)).
		WithHttpConfig(httpConfig()).
		SafeBuild()
	if err != nil {
		t.Fatalf("building ECS client: %v", err)
	}
	return ecsv2.NewEcsClient(hc)
}

// TestFlavorsAndZones is what a script does before creating a server:
// pick an availability zone, then a flavor sold there.
func TestFlavorsAndZones(t *testing.T) {
	c := newECS(t)

	zones, err := c.NovaListAvailabilityZones(&ecs.NovaListAvailabilityZonesRequest{})
	if err != nil {
		t.Fatalf("NovaListAvailabilityZones: %v", err)
	}
	if zones.AvailabilityZoneInfo == nil || len(*zones.AvailabilityZoneInfo) != 3 {
		t.Fatalf("zones = %+v, want 3", zones.AvailabilityZoneInfo)
	}
	az := (*zones.AvailabilityZoneInfo)[0]
	if az.ZoneName != region+"a" || az.ZoneState == nil || !az.ZoneState.Available {
		t.Errorf("first zone = %+v", az)
	}

	listed, err := c.ListFlavors(&ecs.ListFlavorsRequest{AvailabilityZone: &az.ZoneName})
	if err != nil {
		t.Fatalf("ListFlavors: %v", err)
	}
	if listed.Flavors == nil || len(*listed.Flavors) < 20 {
		t.Fatalf("ListFlavors returned %d flavors, want at least the 20 built-in ones", len(*listed.Flavors))
	}
	var found *ecs.Flavor
	for i, f := range *listed.Flavors {
		if f.Id == "s6.large.2" {
			found = &(*listed.Flavors)[i]
		}
	}
	if found == nil {
		t.Fatal("s6.large.2 is not in the flavor list")
	}
	if found.Vcpus != "2" || found.Ram != 4096 || found.Name != "s6.large.2" || !found.OsFlavorAccessisPublic || len(found.Links) != 2 {
		t.Errorf("s6.large.2 = %+v", found)
	}
	spec := found.OsExtraSpecs
	if spec == nil || spec.Ecsgeneration == nil || *spec.Ecsgeneration != "s6" ||
		spec.Ecsperformancetype == nil || *spec.Ecsperformancetype != "normal" ||
		spec.Condoperationstatus == nil || *spec.Condoperationstatus != "normal" {
		t.Errorf("s6.large.2 extra specs = %+v", spec)
	}

	one, err := c.ListFlavors(&ecs.ListFlavorsRequest{FlavorId: ptr("m7.large.8")})
	if err != nil || one.Flavors == nil || len(*one.Flavors) != 1 || (*one.Flavors)[0].Ram != 16384 {
		t.Fatalf("ListFlavors(flavor_id) = %+v, %v", one, err)
	}

	_, err = c.ListFlavors(&ecs.ListFlavorsRequest{Marker: ptr("no.such.flavor")})
	wantError(t, err, 400, "Ecs.0005")
}
