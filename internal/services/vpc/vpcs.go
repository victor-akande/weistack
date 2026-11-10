package vpc

import (
	"context"
	"errors"

	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Defaults of a new VPC, from the API reference's example response.
const (
	defaultEnterpriseProjectID = "0"
	defaultBlockServiceStates  = "off"
)

// CreateVPC creates a VPC in status CREATING; it becomes OK after the
// lifecycle delay.
func (s *Service) CreateVPC(ctx context.Context, t Tenant, opt CreateVPCOption) (VPC, error) {
	v := VPC{
		ID:                         s.ids.UUID(),
		Status:                     VPCStatusCreating,
		BlockServiceEndpointStates: defaultBlockServiceStates,
		EnterpriseProjectID:        defaultEnterpriseProjectID,
		Routes:                     []Route{},
		TenantID:                   t.ProjectID,
	}
	if opt.Name != nil {
		v.Name = *opt.Name
	}
	if opt.Description != nil {
		v.Description = *opt.Description
	}
	if opt.CIDR != nil {
		v.CIDR = *opt.CIDR
	}
	if opt.EnterpriseProjectID != nil && *opt.EnterpriseProjectID != "" {
		v.EnterpriseProjectID = *opt.EnterpriseProjectID
	}
	if opt.BlockServiceEndpointStates != nil && *opt.BlockServiceEndpointStates != "" {
		v.BlockServiceEndpointStates = *opt.BlockServiceEndpointStates
	}
	if opt.EnableNetworkAddressUsageMetrics != nil {
		v.EnableNetworkAddressUsageMetrics = *opt.EnableNetworkAddressUsageMetrics
	}

	if err := checkName(v.Name, true); err != nil {
		return VPC{}, errInvalidVPC("%s", err)
	}
	if err := checkDescription(v.Description); err != nil {
		return VPC{}, errInvalidVPC("%s", err)
	}
	if v.CIDR != "" {
		if err := checkVPCCIDR(v.CIDR); err != nil {
			return VPC{}, errInvalidVPC("cidr %s", err)
		}
	}
	if v.EnterpriseProjectID != defaultEnterpriseProjectID && !isUUID(v.EnterpriseProjectID) {
		return VPC{}, errInvalidVPC("enterprise_project_id %q is invalid", v.EnterpriseProjectID)
	}
	if s := v.BlockServiceEndpointStates; s != "on" && s != "off" {
		return VPC{}, errInvalidVPC("block_service_endpoint_states must be on or off")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkVPCNameFree(ctx, t, v.Name, ""); err != nil {
		return VPC{}, err
	}
	v.CreatedAt = s.timestamp()
	v.UpdatedAt = v.CreatedAt
	if err := s.vpcs(t).Create(ctx, v.ID, v); err != nil {
		return VPC{}, err
	}
	s.scheduleVPCActivation(t, v.ID)
	return v, nil
}

// checkVPCNameFree enforces that a non-empty VPC name is unique in the
// project. exceptID is the VPC being renamed, if any. The caller must
// hold s.mu.
func (s *Service) checkVPCNameFree(ctx context.Context, t Tenant, name, exceptID string) error {
	if name == "" {
		return nil
	}
	clash, err := s.vpcs(t).List(ctx, func(v VPC) bool { return v.Name == name && v.ID != exceptID })
	if err != nil {
		return err
	}
	if len(clash) > 0 {
		return errVPCNameExists(name)
	}
	return nil
}

func (s *Service) scheduleVPCActivation(t Tenant, id string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  id,
		Kind: taskVPCCreate,
		Run: func(ctx context.Context, fault error) {
			status := VPCStatusOK
			if fault != nil {
				status = VPCStatusError
			}
			_, err := s.vpcs(t).Update(ctx, id, func(v *VPC) error {
				v.Status = status
				return nil
			})
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				s.log.ErrorContext(ctx, "vpc activation failed", "vpc_id", id, "error", err)
			}
		},
	})
}

// GetVPC returns one VPC.
func (s *Service) GetVPC(ctx context.Context, t Tenant, id string) (VPC, error) {
	if !isUUID(id) {
		return VPC{}, errInvalidVPC("vpcId %q is invalid", id)
	}
	v, err := s.vpcs(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return VPC{}, errVPCNotFound(id)
	}
	return v, err
}

// ListVPCs returns the project's VPCs in creation order.
func (s *Service) ListVPCs(ctx context.Context, t Tenant, f ListVPCsFilter) ([]VPC, error) {
	return s.vpcs(t).List(ctx, func(v VPC) bool {
		return (f.ID == "" || v.ID == f.ID) &&
			(f.EnterpriseProjectID == "" || v.EnterpriseProjectID == f.EnterpriseProjectID)
	})
}

// UpdateVPC changes the fields set in opt.
func (s *Service) UpdateVPC(ctx context.Context, t Tenant, id string, opt UpdateVPCOption) (VPC, error) {
	if !isUUID(id) {
		return VPC{}, errInvalidVPC("vpcId %q is invalid", id)
	}
	if opt.Name != nil {
		if err := checkName(*opt.Name, true); err != nil {
			return VPC{}, errInvalidVPC("%s", err)
		}
	}
	if opt.Description != nil {
		if err := checkDescription(*opt.Description); err != nil {
			return VPC{}, errInvalidVPC("%s", err)
		}
	}
	if opt.CIDR != nil {
		if err := checkVPCCIDR(*opt.CIDR); err != nil {
			return VPC{}, errInvalidVPC("cidr %s", err)
		}
	}
	if opt.Routes != nil {
		for _, route := range *opt.Routes {
			if _, err := parseIPv4CIDR(route.Destination); err != nil {
				return VPC{}, errInvalidVPC("route destination %s", err)
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if opt.Name != nil {
		if err := s.checkVPCNameFree(ctx, t, *opt.Name, id); err != nil {
			return VPC{}, err
		}
	}
	now := s.timestamp()
	v, err := s.vpcs(t).Update(ctx, id, func(v *VPC) error {
		if opt.Name != nil {
			v.Name = *opt.Name
		}
		if opt.Description != nil {
			v.Description = *opt.Description
		}
		if opt.CIDR != nil {
			v.CIDR = *opt.CIDR
		}
		if opt.Routes != nil {
			v.Routes = append([]Route{}, *opt.Routes...)
		}
		if opt.EnableNetworkAddressUsageMetrics != nil {
			v.EnableNetworkAddressUsageMetrics = *opt.EnableNetworkAddressUsageMetrics
		}
		v.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return VPC{}, errVPCNotFound(id)
	}
	return v, err
}

// DeleteVPC removes a VPC.
func (s *Service) DeleteVPC(ctx context.Context, t Tenant, id string) error {
	if !isUUID(id) {
		return errInvalidVPC("vpcId %q is invalid", id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := s.vpcs(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errVPCNotFound(id)
	}
	if err != nil {
		return err
	}
	if v.Status == VPCStatusCreating {
		return errVPCBusy(id)
	}
	if err := s.vpcs(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s.engine.Cancel(id)
	return nil
}
