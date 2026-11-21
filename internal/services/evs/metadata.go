package evs

import (
	"net/http"
	"strings"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/zones"
)

type volumeTypeSpec struct {
	Name string
	ID   string
}

var supportedVolumeTypes = []volumeTypeSpec{
	{Name: "SATA", ID: "f3454cbe-d625-4edd-8de0-7bd3784ec143"},
	{Name: "SAS", ID: "27f8d1f1-52fa-4d6c-976a-0881849963f5"},
	{Name: "GPSSD", ID: "fdfb39b6-1af9-44a3-b379-63d157efbb0c"},
	{Name: "SSD", ID: "e2a523ff-35ef-4cf6-ac9f-cedb3183f858"},
	{Name: "ESSD", ID: "e97c0dde-1a56-4bd4-b8a6-ff86ae28518e"},
	{Name: "GPSSD2", ID: "2ce7f24b-c4b0-4d64-a67e-7af8da40cde8"},
	{Name: "ESSD2", ID: "a96564af-93a9-4c82-8400-6ccd551cb30a"},
}

// volumeTypeExtraSpecs mirrors the SDK model evs/v2 VolumeTypeExtraSpecs.
type volumeTypeExtraSpecs struct {
	RESKEYAvailabilityZones                  string `json:"RESKEY:availability_zones"`
	AvailabilityZone                         string `json:"availability-zone"`
	OsVendorExtendedSoldOutAvailabilityZones string `json:"os-vendor-extended:sold_out_availability_zones"`
	VolumeBackendName                        string `json:"volume_backend_name"`
}

// volumeTypeWire mirrors the SDK model evs/v2 VolumeType.
type volumeTypeWire struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	ExtraSpecs volumeTypeExtraSpecs `json:"extra_specs"`
	IsPublic   bool                 `json:"is_public"`
}

type listVolumeTypesResponse struct {
	VolumeTypes []volumeTypeWire `json:"volume_types"`
}

// zoneStateWire mirrors the SDK model evs/v2 ZoneState.
type zoneStateWire struct {
	Available bool `json:"available"`
}

// azInfoWire mirrors the SDK model evs/v2 AzInfo.
type azInfoWire struct {
	ZoneName  string        `json:"zoneName"`
	ZoneState zoneStateWire `json:"zoneState"`
}

type listAvailabilityZonesResponse struct {
	AvailabilityZoneInfo []azInfoWire `json:"availabilityZoneInfo"`
}

func (s *Service) handleListVolumeTypes(w http.ResponseWriter, _ *http.Request, t Tenant) error {
	azs := zones.Of(t.Region)
	joined := strings.Join(azs, ",")
	first := ""
	if len(azs) > 0 {
		first = azs[0]
	}

	out := make([]volumeTypeWire, 0, len(supportedVolumeTypes))
	for _, spec := range supportedVolumeTypes {
		out = append(out, volumeTypeWire{
			ID:       spec.ID,
			Name:     spec.Name,
			IsPublic: true,
			ExtraSpecs: volumeTypeExtraSpecs{
				VolumeBackendName:                        spec.Name,
				AvailabilityZone:                         first,
				RESKEYAvailabilityZones:                  joined,
				OsVendorExtendedSoldOutAvailabilityZones: "",
			},
		})
	}
	return httpx.WriteJSON(w, http.StatusOK, listVolumeTypesResponse{VolumeTypes: out})
}

func (s *Service) handleListAvailabilityZones(w http.ResponseWriter, _ *http.Request, t Tenant) error {
	azs := zones.Of(t.Region)
	out := make([]azInfoWire, 0, len(azs))
	for _, az := range azs {
		out = append(out, azInfoWire{
			ZoneName:  az,
			ZoneState: zoneStateWire{Available: true},
		})
	}
	return httpx.WriteJSON(w, http.StatusOK, listAvailabilityZonesResponse{AvailabilityZoneInfo: out})
}
