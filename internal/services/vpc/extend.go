package vpc

import (
	"context"

	"github.com/go-chi/chi/v5"
)

// QuotaResource is one quota item reported through GET /v1/{project_id}/quotas
// by a service sharing the VPC endpoint (EIP, ELB).
type QuotaResource struct {
	Type  string `json:"type"`
	Used  int    `json:"used"`
	Quota int    `json:"quota"`
	Min   int    `json:"min"`
}

// Extension adds the routes and quota entries of a service that shares the VPC
// endpoint (EIP, NAT, ELB).
type Extension interface {
	RoutesV1(r chi.Router)  // mounted inside /v1/{project_id}
	RoutesV20(r chi.Router) // mounted inside /v2.0/{project_id}
	Routes(r chi.Router)    // mounted at the root, for its own prefixes (/v3/{project_id}/eip)
	Quotas(ctx context.Context, t Tenant) ([]QuotaResource, error)
}

// Extend adds e's routes and quota entries. Call it before the server registers routes.
func (s *Service) Extend(e Extension) {
	if e != nil {
		s.exts = append(s.exts, e)
	}
}
