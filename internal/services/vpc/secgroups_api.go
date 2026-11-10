package vpc

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// v3ListLimits bounds "limit" on v3 list operations.
var v3ListLimits = pagination.Limits{Default: 2000, Min: 0, Max: 2000}

// dryRunCode is the code of the 202 response to a passed dry run.
const dryRunCode = "SYS.0202"

func requestID(r *http.Request) string { return reqctx.From(r.Context()).RequestID }

func writeDryRun(w http.ResponseWriter, r *http.Request) error {
	return httpx.WriteJSON(w, http.StatusAccepted, dryRunResponse{
		RequestID: requestID(r),
		ErrorMsg:  "Request validation has been passed with dry run...",
		ErrorCode: dryRunCode,
	})
}

// paginate applies marker/limit paging and builds the v3 page_info.
func paginate[T any](q url.Values, all []T, id func(T) string) ([]T, pageInfo, error) {
	page, err := pagination.ParseMarker(q, v3ListLimits)
	if err != nil {
		return nil, pageInfo{}, errInvalidSecGroup("%s", err)
	}
	out, err := pagination.ByMarker(all, id, page)
	if err != nil {
		return nil, pageInfo{}, errInvalidSecGroup("%s", err)
	}
	info := pageInfo{CurrentCount: len(out)}
	if len(out) > 0 {
		info.PreviousMarker = id(out[0])
		// A next marker is only present when more items follow.
		if last := id(out[len(out)-1]); last != id(all[len(all)-1]) {
			info.NextMarker = &last
		}
	}
	return out, info, nil
}

func (s *Service) handleCreateSecurityGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createSecurityGroupRequest
	if err := decode(r, &req, errInvalidSecGroup); err != nil {
		return err
	}
	if req.SecurityGroup == nil {
		return errInvalidSecGroup("the request body must contain a security_group object")
	}
	g, err := s.CreateSecurityGroup(r.Context(), t, *req.SecurityGroup, req.DryRun)
	if err != nil {
		return err
	}
	if req.DryRun {
		return writeDryRun(w, r)
	}
	return httpx.WriteJSON(w, http.StatusCreated, securityGroupResponse{RequestID: requestID(r), SecurityGroup: g})
}

func (s *Service) handleShowSecurityGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	g, err := s.GetSecurityGroup(r.Context(), t, chi.URLParam(r, "security_group_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, securityGroupResponse{RequestID: requestID(r), SecurityGroup: g})
}

func (s *Service) handleListSecurityGroups(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	all, err := s.ListSecurityGroups(r.Context(), t, ListSecurityGroupsFilter{
		IDs:                 q["id"],
		Names:               q["name"],
		Descriptions:        q["description"],
		EnterpriseProjectID: q.Get("enterprise_project_id"),
	})
	if err != nil {
		return err
	}
	out, info, err := paginate(q, all, func(g SecurityGroup) string { return g.ID })
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, listSecurityGroupsResponse{
		RequestID: requestID(r), SecurityGroups: out, PageInfo: info,
	})
}

func (s *Service) handleUpdateSecurityGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateSecurityGroupRequest
	if err := decode(r, &req, errInvalidSecGroup); err != nil {
		return err
	}
	if req.SecurityGroup == nil {
		return errInvalidSecGroup("the request body must contain a security_group object")
	}
	g, err := s.UpdateSecurityGroup(r.Context(), t, chi.URLParam(r, "security_group_id"), *req.SecurityGroup, req.DryRun)
	if err != nil {
		return err
	}
	if req.DryRun {
		return writeDryRun(w, r)
	}
	return httpx.WriteJSON(w, http.StatusOK, securityGroupResponse{RequestID: requestID(r), SecurityGroup: g})
}

func (s *Service) handleDeleteSecurityGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if err := s.DeleteSecurityGroup(r.Context(), t, chi.URLParam(r, "security_group_id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleCreateSecurityGroupRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createSecurityGroupRuleRequest
	if err := decode(r, &req, errInvalidSecGroup); err != nil {
		return err
	}
	if req.SecurityGroupRule == nil {
		return errInvalidSecGroup("the request body must contain a security_group_rule object")
	}
	rule, err := s.CreateSecurityGroupRule(r.Context(), t, *req.SecurityGroupRule, req.DryRun)
	if err != nil {
		return err
	}
	if req.DryRun {
		return writeDryRun(w, r)
	}
	return httpx.WriteJSON(w, http.StatusCreated, securityGroupRuleResponse{RequestID: requestID(r), SecurityGroupRule: rule})
}

func (s *Service) handleShowSecurityGroupRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	rule, err := s.GetSecurityGroupRule(r.Context(), t, chi.URLParam(r, "security_group_rule_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, securityGroupRuleResponse{RequestID: requestID(r), SecurityGroupRule: rule})
}

func (s *Service) handleListSecurityGroupRules(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	f := ListSecurityGroupRulesFilter{
		IDs:                   q["id"],
		SecurityGroupIDs:      q["security_group_id"],
		Protocols:             q["protocol"],
		Descriptions:          q["description"],
		RemoteGroupIDs:        q["remote_group_id"],
		Ethertypes:            q["ethertype"],
		RemoteAddressGroupIDs: q["remote_address_group_id"],
		Direction:             q.Get("direction"),
		Action:                q.Get("action"),
		RemoteIPPrefix:        q.Get("remote_ip_prefix"),
	}
	for _, raw := range q["priority"] {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return errInvalidSecGroup("priority %q is not an integer", raw)
		}
		f.Priorities = append(f.Priorities, n)
	}
	if raw := q.Get("enabled"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return errInvalidSecGroup("enabled %q is not a boolean", raw)
		}
		f.Enabled = &b
	}

	all, err := s.ListSecurityGroupRules(r.Context(), t, f)
	if err != nil {
		return err
	}
	out, info, err := paginate(q, all, func(rule SecurityGroupRule) string { return rule.ID })
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, listSecurityGroupRulesResponse{
		RequestID: requestID(r), SecurityGroupRules: out, PageInfo: info,
	})
}

func (s *Service) handleDeleteSecurityGroupRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if err := s.DeleteSecurityGroupRule(r.Context(), t, chi.URLParam(r, "security_group_rule_id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
