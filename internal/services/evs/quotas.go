package evs

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/quota"
)

// quotaDetail mirrors the SDK model evs/v2 QuotaDetail.
type quotaDetail struct {
	InUse    int `json:"in_use"`
	Limit    int `json:"limit"`
	Reserved int `json:"reserved"`
}

// quotaSet mirrors the SDK model evs/v2 QuotaList plus per-type items
// for all volume types supported by WeiStack (M18 §3.4).
type quotaSet struct {
	ID              string      `json:"id"`
	Volumes         quotaDetail `json:"volumes"`
	Gigabytes       quotaDetail `json:"gigabytes"`
	Snapshots       quotaDetail `json:"snapshots"`
	VolumesSATA     quotaDetail `json:"volumes_SATA"`
	GigabytesSATA   quotaDetail `json:"gigabytes_SATA"`
	SnapshotsSATA   quotaDetail `json:"snapshots_SATA"`
	VolumesSAS      quotaDetail `json:"volumes_SAS"`
	GigabytesSAS    quotaDetail `json:"gigabytes_SAS"`
	SnapshotsSAS    quotaDetail `json:"snapshots_SAS"`
	VolumesGPSSD    quotaDetail `json:"volumes_GPSSD"`
	GigabytesGPSSD  quotaDetail `json:"gigabytes_GPSSD"`
	SnapshotsGPSSD  quotaDetail `json:"snapshots_GPSSD"`
	VolumesSSD      quotaDetail `json:"volumes_SSD"`
	GigabytesSSD    quotaDetail `json:"gigabytes_SSD"`
	SnapshotsSSD    quotaDetail `json:"snapshots_SSD"`
	VolumesESSD     quotaDetail `json:"volumes_ESSD"`
	GigabytesESSD   quotaDetail `json:"gigabytes_ESSD"`
	SnapshotsESSD   quotaDetail `json:"snapshots_ESSD"`
	VolumesGPSSD2   quotaDetail `json:"volumes_GPSSD2"`
	GigabytesGPSSD2 quotaDetail `json:"gigabytes_GPSSD2"`
	SnapshotsGPSSD2 quotaDetail `json:"snapshots_GPSSD2"`
	VolumesESSD2    quotaDetail `json:"volumes_ESSD2"`
	GigabytesESSD2  quotaDetail `json:"gigabytes_ESSD2"`
	SnapshotsESSD2  quotaDetail `json:"snapshots_ESSD2"`
}

type listQuotasResponse struct {
	QuotaSet quotaSet `json:"quota_set"`
}

func (s *Service) handleListQuotas(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if chi.URLParam(r, "target_project_id") != t.ProjectID {
		return errVolumeNotFound
	}

	vols, err := s.volumes(t).List(r.Context(), nil)
	if err != nil {
		return err
	}
	snaps, err := s.snapshots(t).List(r.Context(), nil)
	if err != nil {
		return err
	}

	type typeUsage struct {
		volumes   int
		gigabytes int
		snapshots int
	}
	byType := make(map[string]*typeUsage, len(supportedVolumeTypes))
	for _, spec := range supportedVolumeTypes {
		byType[spec.Name] = &typeUsage{}
	}

	var totalGB int
	for _, v := range vols {
		totalGB += v.SizeGB
		if u, ok := byType[v.VolumeType]; ok {
			u.volumes++
			u.gigabytes += v.SizeGB
		}
	}
	for _, sn := range snaps {
		if u, ok := byType[sn.VolumeType]; ok {
			u.snapshots++
		}
	}

	perType := func(name string) (volumes, gigabytes, snapshots quotaDetail) {
		u := byType[name]
		return quotaDetail{InUse: u.volumes, Limit: quota.Unlimited},
			quotaDetail{InUse: u.gigabytes, Limit: quota.Unlimited},
			quotaDetail{InUse: u.snapshots, Limit: quota.Unlimited}
	}

	qs := quotaSet{
		ID:        t.ProjectID,
		Volumes:   quotaDetail{InUse: len(vols), Limit: s.quotas.Get(quota.EVSVolumes)},
		Gigabytes: quotaDetail{InUse: totalGB, Limit: s.quotas.Get(quota.EVSGigabytes)},
		Snapshots: quotaDetail{InUse: len(snaps), Limit: s.quotas.Get(quota.EVSSnapshots)},
	}
	qs.VolumesSATA, qs.GigabytesSATA, qs.SnapshotsSATA = perType("SATA")
	qs.VolumesSAS, qs.GigabytesSAS, qs.SnapshotsSAS = perType("SAS")
	qs.VolumesGPSSD, qs.GigabytesGPSSD, qs.SnapshotsGPSSD = perType("GPSSD")
	qs.VolumesSSD, qs.GigabytesSSD, qs.SnapshotsSSD = perType("SSD")
	qs.VolumesESSD, qs.GigabytesESSD, qs.SnapshotsESSD = perType("ESSD")
	qs.VolumesGPSSD2, qs.GigabytesGPSSD2, qs.SnapshotsGPSSD2 = perType("GPSSD2")
	qs.VolumesESSD2, qs.GigabytesESSD2, qs.SnapshotsESSD2 = perType("ESSD2")

	return httpx.WriteJSON(w, http.StatusOK, listQuotasResponse{QuotaSet: qs})
}
