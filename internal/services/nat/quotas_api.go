package nat

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/quota"
)

type quotaResourceWire struct {
	Type  string `json:"type"`
	Used  int    `json:"used"`
	Quota int    `json:"quota"`
	Min   int    `json:"min"`
}

type quotaSetWire struct {
	Resources []quotaResourceWire `json:"resources"`
}

type listQuotasResponse struct {
	Quotas quotaSetWire `json:"quotas"`
}

func (s *Service) handleListQuotas(w http.ResponseWriter, r *http.Request, t Tenant) error {
	typ := r.URL.Query().Get("type")
	resources := make([]quotaResourceWire, 0, 1)
	if typ == "" || typ == "nat_gateway" {
		gws, err := s.gateways(t).List(r.Context(), nil)
		if err != nil {
			return err
		}
		resources = append(resources, quotaResourceWire{
			Type:  "nat_gateway",
			Used:  len(gws),
			Quota: s.quotas.Get(quota.NATGateway),
			Min:   0,
		})
	}
	return httpx.WriteJSON(w, http.StatusOK, listQuotasResponse{
		Quotas: quotaSetWire{Resources: resources},
	})
}
