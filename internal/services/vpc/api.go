package vpc

import (
	"errors"
	"math"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Routes implements server.Service. Paths are those of the real API.
// Each route names the IAM action it needs (usermanual-permissions
// iam_11_0017, checked against each operation's API page); a route's
// resource is the one its path names.
func (s *Service) Routes(r chi.Router) {
	act, vpc, subnet, group, rule, port := authz.Action, authz.Param("vpc", "vpc_id"), authz.Param("subnet", "subnet_id"),
		authz.Param("securityGroup", "security_group_id"), authz.Param("securityGroupRule", "security_group_rule_id"),
		authz.Param("port", "port_id")
	r.Route("/v2.0/{project_id}", func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "vpc", Style: apierr.StyleCodeMessage}))
		r.With(act("vpc:vpcs:listTags", authz.Param("vpc", "id"))).Get("/vpcs/{id}/tags", s.v1("ShowVpcTags", s.handleShowVPCTags))
		r.With(act("vpc:subnets:listTags", authz.Param("subnet", "id"))).Get("/subnets/{id}/tags", s.v1("ShowSubnetTags", s.handleShowSubnetTags))
		r.With(act("vpc:securityGroups:listTags", authz.Param("securityGroup", "id"))).Get("/security-groups/{id}/tags", s.v1("ShowSecurityGroupTags", s.handleShowSecurityGroupTags))
		for _, ext := range s.exts {
			ext.RoutesV20(r)
		}
	})
	r.Route("/v1/{project_id}", func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "vpc", Style: apierr.StyleCodeMessage}))
		r.With(act("vpc:vpcs:create")).Post("/vpcs", s.v1("CreateVpc", s.handleCreateVPC))
		r.With(act("vpc:vpcs:list")).Get("/vpcs", s.v1("ListVpcs", s.handleListVPCs))
		r.With(act("vpc:vpcs:get", vpc)).Get("/vpcs/{vpc_id}", s.v1("ShowVpc", s.handleShowVPC))
		r.With(act("vpc:vpcs:update", vpc)).Put("/vpcs/{vpc_id}", s.v1("UpdateVpc", s.handleUpdateVPC))
		r.With(act("vpc:vpcs:delete", vpc)).Delete("/vpcs/{vpc_id}", s.v1("DeleteVpc", s.handleDeleteVPC))

		r.With(act("vpc:subnets:create")).Post("/subnets", s.v1("CreateSubnet", s.handleCreateSubnet))
		r.With(act("vpc:subnets:list")).Get("/subnets", s.v1("ListSubnets", s.handleListSubnets))
		r.With(act("vpc:subnets:get", subnet)).Get("/subnets/{subnet_id}", s.v1("ShowSubnet", s.handleShowSubnet))
		r.With(act("vpc:subnets:update", subnet)).Put("/vpcs/{vpc_id}/subnets/{subnet_id}", s.v1("UpdateSubnet", s.handleUpdateSubnet))
		r.With(act("vpc:subnets:delete", subnet)).Delete("/vpcs/{vpc_id}/subnets/{subnet_id}", s.v1("DeleteSubnet", s.handleDeleteSubnet))

		// Ports, the NICs of ECS servers, read only.
		r.With(act("vpc:ports:list")).Get("/ports", s.v1("ListPorts", s.handleListPorts))
		r.With(act("vpc:ports:get", port)).Get("/ports/{port_id}", s.v1("ShowPort", s.handleShowPort))

		// The v1 security group API, a view of the v3 records.
		r.With(act("vpc:securityGroups:create")).Post("/security-groups", s.v1("CreateSecurityGroupV1", s.handleCreateGroupV1))
		r.With(act("vpc:securityGroups:list")).Get("/security-groups", s.v1("ListSecurityGroupsV1", s.handleListGroupsV1))
		r.With(act("vpc:securityGroups:get", group)).Get("/security-groups/{security_group_id}", s.v1("ShowSecurityGroupV1", s.handleShowGroupV1))
		r.With(act("vpc:securityGroups:delete", group)).Delete("/security-groups/{security_group_id}", s.v1("DeleteSecurityGroupV1", s.handleDeleteGroupV1))
		r.With(act("vpc:securityGroupRules:create")).Post("/security-group-rules", s.v1("CreateSecurityGroupRuleV1", s.handleCreateRuleV1))
		r.With(act("vpc:securityGroupRules:list")).Get("/security-group-rules", s.v1("ListSecurityGroupRulesV1", s.handleListRulesV1))
		r.With(act("vpc:securityGroupRules:get", rule)).Get("/security-group-rules/{security_group_rule_id}", s.v1("ShowSecurityGroupRuleV1", s.handleShowRuleV1))
		r.With(act("vpc:securityGroupRules:delete", rule)).Delete("/security-group-rules/{security_group_rule_id}", s.v1("DeleteSecurityGroupRuleV1", s.handleDeleteRuleV1))

		r.With(act("vpc:quotas:list")).Get("/quotas", s.v1("ShowQuota", s.handleShowQuotaV1))
		for _, ext := range s.exts {
			ext.RoutesV1(r)
		}
	})
	r.Route("/v3/{project_id}/vpc", func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "vpc", Style: apierr.StyleFlatRequestID}))
		r.With(act("vpc:securityGroups:create")).Post("/security-groups", s.v3("CreateSecurityGroup", s.handleCreateSecurityGroup))
		r.With(act("vpc:securityGroups:list")).Get("/security-groups", s.v3("ListSecurityGroups", s.handleListSecurityGroups))
		r.With(act("vpc:securityGroups:get", group)).Get("/security-groups/{security_group_id}", s.v3("ShowSecurityGroup", s.handleShowSecurityGroup))
		r.With(act("vpc:securityGroups:update", group)).Put("/security-groups/{security_group_id}", s.v3("UpdateSecurityGroup", s.handleUpdateSecurityGroup))
		r.With(act("vpc:securityGroups:delete", group)).Delete("/security-groups/{security_group_id}", s.v3("DeleteSecurityGroup", s.handleDeleteSecurityGroup))

		r.With(act("vpc:securityGroupRules:create")).Post("/security-group-rules", s.v3("CreateSecurityGroupRule", s.handleCreateSecurityGroupRule))
		r.With(act("vpc:securityGroupRules:list")).Get("/security-group-rules", s.v3("ListSecurityGroupRules", s.handleListSecurityGroupRules))
		r.With(act("vpc:securityGroupRules:get", rule)).Get("/security-group-rules/{security_group_rule_id}", s.v3("ShowSecurityGroupRule", s.handleShowSecurityGroupRule))
		r.With(act("vpc:securityGroupRules:delete", rule)).Delete("/security-group-rules/{security_group_rule_id}", s.v3("DeleteSecurityGroupRule", s.handleDeleteSecurityGroupRule))

		r.With(act("vpc:vpcs:list")).Get("/vpcs", s.v3("ListVpcsV3", s.handleListVPCsV3))
		r.With(act("vpc:vpcs:get", vpc)).Get("/vpcs/{vpc_id}", s.v3("ShowVpcV3", s.handleShowVPCv3))

		r.With(act("vpc:quotas:list")).Get("/quotas", s.v3("ShowQuotaV3", s.handleShowQuotaV3))
	})
	for _, ext := range s.exts {
		ext.Routes(r)
	}
}

// v1ListLimits bounds "limit" on v1 list operations: 0 to the maximum
// 32-bit integer, 2000 when omitted.
var v1ListLimits = pagination.Limits{Default: 2000, Min: 0, Max: math.MaxInt32}

type handler func(w http.ResponseWriter, r *http.Request, t Tenant) error

// v1 adapts a handler of the v1 API: it names the operation for logs,
// resolves the tenant and renders errors in the v1 envelope.
func (s *Service) v1(op string, fn handler) http.HandlerFunc {
	return s.adapt(op, apierr.StyleCodeMessage, fn)
}

// v3 adapts a handler of the v3 API.
func (s *Service) v3(op string, fn handler) http.HandlerFunc {
	return s.adapt(op, apierr.StyleFlatRequestID, fn)
}

func (s *Service) adapt(op string, style apierr.Style, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := reqctx.From(r.Context())
		info.SetOperation(op)
		t := Tenant{Region: info.Region, ProjectID: chi.URLParam(r, "project_id")}

		err := fn(w, r, t)
		if err == nil {
			return
		}
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(r.Context(), "vpc operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, style, err)
	}
}

// decode reads a JSON body, mapping every failure to an invalid-parameter
// error built by invalid.
func decode(r *http.Request, dst any, invalid func(string, ...any) *apierr.Error) error {
	if err := httpx.DecodeJSON(r, dst); err != nil {
		return invalid("%s", err)
	}
	return nil
}

func (s *Service) handleCreateVPC(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createVPCRequest
	if err := decode(r, &req, errInvalidVPC); err != nil {
		return err
	}
	if req.VPC == nil {
		return errInvalidVPC("the request body must contain a vpc object")
	}
	v, err := s.CreateVPC(r.Context(), t, *req.VPC)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, vpcResponse{VPC: v})
}

func (s *Service) handleShowVPC(w http.ResponseWriter, r *http.Request, t Tenant) error {
	v, err := s.GetVPC(r.Context(), t, chi.URLParam(r, "vpc_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, vpcResponse{VPC: v})
}

func (s *Service) handleListVPCs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, v1ListLimits)
	if err != nil {
		return errInvalidVPC("%s", err)
	}
	all, err := s.ListVPCs(r.Context(), t, ListVPCsFilter{
		ID:                  q.Get("id"),
		EnterpriseProjectID: q.Get("enterprise_project_id"),
	})
	if err != nil {
		return err
	}
	out, err := pagination.ByMarker(all, func(v VPC) string { return v.ID }, page)
	if err != nil {
		return errInvalidVPC("%s", err)
	}
	return httpx.WriteJSON(w, http.StatusOK, listVPCsResponse{VPCs: out})
}

func (s *Service) handleUpdateVPC(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateVPCRequest
	if err := decode(r, &req, errInvalidVPC); err != nil {
		return err
	}
	if req.VPC == nil {
		return errInvalidVPC("the request body must contain a vpc object")
	}
	v, err := s.UpdateVPC(r.Context(), t, chi.URLParam(r, "vpc_id"), *req.VPC)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, vpcResponse{VPC: v})
}

func (s *Service) handleDeleteVPC(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if err := s.DeleteVPC(r.Context(), t, chi.URLParam(r, "vpc_id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleCreateSubnet(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createSubnetRequest
	if err := decode(r, &req, errInvalidSubnet); err != nil {
		return err
	}
	if req.Subnet == nil {
		return errInvalidSubnet("the request body must contain a subnet object")
	}
	sn, err := s.CreateSubnet(r.Context(), t, *req.Subnet)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, subnetResponse{Subnet: sn})
}

func (s *Service) handleShowSubnet(w http.ResponseWriter, r *http.Request, t Tenant) error {
	sn, err := s.GetSubnet(r.Context(), t, chi.URLParam(r, "subnet_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, subnetResponse{Subnet: sn})
}

func (s *Service) handleListSubnets(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, v1ListLimits)
	if err != nil {
		return errInvalidSubnet("%s", err)
	}
	all, err := s.ListSubnets(r.Context(), t, ListSubnetsFilter{VPCID: q.Get("vpc_id")})
	if err != nil {
		return err
	}
	out, err := pagination.ByMarker(all, func(sn Subnet) string { return sn.ID }, page)
	if err != nil {
		return errInvalidSubnet("%s", err)
	}
	return httpx.WriteJSON(w, http.StatusOK, listSubnetsResponse{Subnets: out})
}

func (s *Service) handleUpdateSubnet(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateSubnetRequest
	if err := decode(r, &req, errInvalidSubnet); err != nil {
		return err
	}
	if req.Subnet == nil {
		return errInvalidSubnet("the request body must contain a subnet object")
	}
	sn, err := s.UpdateSubnet(r.Context(), t, chi.URLParam(r, "vpc_id"), chi.URLParam(r, "subnet_id"), *req.Subnet)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, updateSubnetResponse{Subnet: subnetResult{ID: sn.ID, Status: sn.Status}})
}

func (s *Service) handleDeleteSubnet(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if err := s.DeleteSubnet(r.Context(), t, chi.URLParam(r, "vpc_id"), chi.URLParam(r, "subnet_id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
