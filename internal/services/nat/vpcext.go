package nat

import (
	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

// VPCExtension returns a vpc.Extension that mounts NAT's /v2.0 public
// gateway tag routes on the VPC endpoint, where Terraform's NetworkingV2Client
// sends them.
func (s *Service) VPCExtension() vpc.Extension {
	return vpcExtension{s: s}
}

type vpcExtension struct {
	s *Service
}

func (vpcExtension) RoutesV1(chi.Router) {}

func (e vpcExtension) RoutesV20(r chi.Router) {
	act := authz.Action
	gw := authz.Param("gateway", "nat_gateway_id")

	r.Group(func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{
			Name:  "nat",
			Style: apierr.StyleFlatRequestID,
			Deny:  denied,
		}))
		e.s.mountPublicTagRoutes(r, act, gw)
	})
}

func (vpcExtension) Routes(chi.Router) {}
