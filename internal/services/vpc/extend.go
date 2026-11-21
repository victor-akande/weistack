package vpc

import "github.com/go-chi/chi/v5"

// Extension adds the routes of a service that shares the VPC endpoint
// (EIP: SDKs and Terraform send it to vpc.{region}.myhuaweicloud.com).
type Extension interface {
	RoutesV1(r chi.Router)  // mounted inside /v1/{project_id}
	RoutesV20(r chi.Router) // mounted inside /v2.0/{project_id}
	Routes(r chi.Router)    // mounted at the root, for its own prefixes (/v3/{project_id}/eip)
}

// Extend adds e's routes. Call it before the server registers routes.
func (s *Service) Extend(e Extension) {
	if e != nil {
		s.exts = append(s.exts, e)
	}
}
