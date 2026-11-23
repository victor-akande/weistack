package ims

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/quota"
)

const (
	imageQuotaMin = 1
	imageQuotaMax = 1000
)

// quotaInfo mirrors the SDK model ims/v2 QuotaInfo.
type quotaInfo struct {
	Type  string `json:"type"`
	Used  int    `json:"used"`
	Quota int    `json:"quota"`
	Min   int    `json:"min"`
	Max   int    `json:"max"`
}

// quotaResources mirrors the SDK model ims/v2 Quota.
type quotaResources struct {
	Resources []quotaInfo `json:"resources"`
}

// showImageQuotaResponse mirrors the SDK model ims/v2 ShowImageQuotaResponse.
type showImageQuotaResponse struct {
	Quotas quotaResources `json:"quotas"`
}

func (s *Service) handleShowImageQuota(w http.ResponseWriter, r *http.Request, t Tenant) error {
	existing, err := s.privateImages(t).List(r.Context(), nil)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, showImageQuotaResponse{
		Quotas: quotaResources{
			Resources: []quotaInfo{
				{
					Type:  "image",
					Used:  len(existing),
					Quota: s.quotas.Get(quota.IMSImage),
					Min:   imageQuotaMin,
					Max:   imageQuotaMax,
				},
			},
		},
	})
}
