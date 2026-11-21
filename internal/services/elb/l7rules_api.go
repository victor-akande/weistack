package elb

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

type l7RuleConditionReq struct {
	Key   *string `json:"key"`
	Value *string `json:"value"`
}

func l7ConvertConditionsReq(items []l7RuleConditionReq) []ruleCondition {
	if len(items) == 0 {
		return nil
	}
	out := make([]ruleCondition, len(items))
	for i, item := range items {
		out[i] = ruleCondition{
			Key:   l7DerefString(item.Key),
			Value: l7DerefString(item.Value),
		}
	}
	return out
}

type l7CreateRuleRequest struct {
	Rule *l7CreateRuleOptionReq `json:"rule"`
}

// l7CreateRuleOptionReq mirrors SDK models CreateRuleOption and CreateL7PolicyRuleOption.
type l7CreateRuleOptionReq struct {
	AdminStateUp *bool                `json:"admin_state_up"`
	CompareType  string               `json:"compare_type"`
	Key          *string              `json:"key"`
	Value        string               `json:"value"`
	ProjectID    *string              `json:"project_id"`
	Type         string               `json:"type"`
	Invert       *bool                `json:"invert"`
	Conditions   []l7RuleConditionReq `json:"conditions"`
}

func (r l7CreateRuleOptionReq) toInput() l7CreateRuleInput {
	return l7CreateRuleInput{
		Type:         r.Type,
		CompareType:  r.CompareType,
		Key:          l7DerefString(r.Key),
		Value:        r.Value,
		AdminStateUp: r.AdminStateUp,
		Invert:       r.Invert,
		Conditions:   l7ConvertConditionsReq(r.Conditions),
	}
}

type l7UpdateRuleRequest struct {
	Rule *l7UpdateRuleOptionReq `json:"rule"`
}

// l7UpdateRuleOptionReq mirrors SDK model UpdateL7RuleOption.
type l7UpdateRuleOptionReq struct {
	AdminStateUp *bool                            `json:"admin_state_up"`
	CompareType  *string                          `json:"compare_type"`
	Invert       *bool                            `json:"invert"`
	Key          *string                          `json:"key"`
	Value        *string                          `json:"value"`
	Conditions   l7Optional[[]l7RuleConditionReq] `json:"conditions"`
}

// l7RuleWire mirrors SDK model L7Rule.
type l7RuleWire struct {
	ID                 string          `json:"id"`
	Type               string          `json:"type"`
	CompareType        string          `json:"compare_type"`
	Key                string          `json:"key"`
	Value              string          `json:"value"`
	AdminStateUp       bool            `json:"admin_state_up"`
	Invert             bool            `json:"invert"`
	ProvisioningStatus string          `json:"provisioning_status"`
	ProjectID          string          `json:"project_id"`
	Conditions         []ruleCondition `json:"conditions"`
	CreatedAt          string          `json:"created_at"`
	UpdatedAt          string          `json:"updated_at"`
}

type l7RuleEnvelope struct {
	RequestID string     `json:"request_id"`
	Rule      l7RuleWire `json:"rule"`
}

type l7ListRulesResponse struct {
	RequestID string       `json:"request_id"`
	PageInfo  pageInfo     `json:"page_info"`
	Rules     []l7RuleWire `json:"rules"`
}

func l7ToRuleWire(t Tenant, r l7Rule) l7RuleWire {
	conds := make([]ruleCondition, len(r.Conditions))
	copy(conds, r.Conditions)
	return l7RuleWire{
		ID:                 r.ID,
		Type:               r.Type,
		CompareType:        r.CompareType,
		Key:                r.Key,
		Value:              r.Value,
		AdminStateUp:       r.AdminStateUp,
		Invert:             false,
		ProvisioningStatus: StatusActive,
		ProjectID:          t.ProjectID,
		Conditions:         conds,
		CreatedAt:          formatTime(r.CreatedAt),
		UpdatedAt:          formatTime(r.UpdatedAt),
	}
}

func l7ParseRulesListQuery(r *http.Request) (l7ListRulesFilter, error) {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return l7ListRulesFilter{}, errInvalidInput("limit")
	}
	pageReverse, err := parseBoolQuery(q, "page_reverse")
	if err != nil {
		return l7ListRulesFilter{}, err
	}
	invert, err := parseBoolQuery(q, "invert")
	if err != nil {
		return l7ListRulesFilter{}, err
	}
	adminUp, err := parseBoolQuery(q, "admin_state_up")
	if err != nil {
		return l7ListRulesFilter{}, err
	}
	return l7ListRulesFilter{
		IDs:                  l7NonEmpty(q["id"]),
		CompareTypes:         l7NonEmpty(q["compare_type"]),
		ProvisioningStatuses: l7NonEmpty(q["provisioning_status"]),
		Invert:               invert,
		AdminStateUp:         adminUp,
		Values:               l7NonEmpty(q["value"]),
		Keys:                 l7NonEmpty(q["key"]),
		Types:                l7NonEmpty(q["type"]),
		EnterpriseProjectIDs: l7NonEmpty(q["enterprise_project_id"]),
		L7PolicyIDs:          l7NonEmpty(q["l7policy_id"]),
		Page:                 page,
		PageReverse:          pageReverse != nil && *pageReverse,
	}, nil
}

func (s *Service) handleCreateL7Rule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req l7CreateRuleRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Rule == nil {
		return errInvalidInput("rule")
	}
	policyID := chi.URLParam(r, "l7policy_id")
	rec, err := s.l7CreateRule(r.Context(), t, policyID, req.Rule.toInput())
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, l7RuleEnvelope{
		RequestID: requestID(r),
		Rule:      l7ToRuleWire(t, rec),
	})
}

func (s *Service) handleListL7Rules(w http.ResponseWriter, r *http.Request, t Tenant) error {
	f, err := l7ParseRulesListQuery(r)
	if err != nil {
		return err
	}
	policyID := chi.URLParam(r, "l7policy_id")
	items, pi, err := s.l7ListRules(r.Context(), t, policyID, f)
	if err != nil {
		return err
	}
	out := make([]l7RuleWire, len(items))
	for i, item := range items {
		out[i] = l7ToRuleWire(t, item)
	}
	return httpx.WriteJSON(w, http.StatusOK, l7ListRulesResponse{
		RequestID: requestID(r),
		PageInfo:  pi,
		Rules:     out,
	})
}

func (s *Service) handleShowL7Rule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	policyID := chi.URLParam(r, "l7policy_id")
	ruleID := chi.URLParam(r, "l7rule_id")
	rec, err := s.l7GetRule(r.Context(), t, policyID, ruleID)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, l7RuleEnvelope{
		RequestID: requestID(r),
		Rule:      l7ToRuleWire(t, rec),
	})
}

func (s *Service) handleUpdateL7Rule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req l7UpdateRuleRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Rule == nil {
		return errInvalidInput("rule")
	}
	policyID := chi.URLParam(r, "l7policy_id")
	ruleID := chi.URLParam(r, "l7rule_id")
	opt := req.Rule

	var condsOpt l7Optional[[]ruleCondition]
	if opt.Conditions.Set {
		condsOpt.Set = true
		if opt.Conditions.Value != nil {
			converted := l7ConvertConditionsReq(*opt.Conditions.Value)
			if converted == nil {
				converted = []ruleCondition{}
			}
			condsOpt.Value = &converted
		}
	}

	rec, err := s.l7UpdateRule(r.Context(), t, policyID, ruleID, l7UpdateRuleInput{
		CompareType:  opt.CompareType,
		Key:          opt.Key,
		Value:        opt.Value,
		AdminStateUp: opt.AdminStateUp,
		Invert:       opt.Invert,
		Conditions:   condsOpt,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, l7RuleEnvelope{
		RequestID: requestID(r),
		Rule:      l7ToRuleWire(t, rec),
	})
}

func (s *Service) handleDeleteL7Rule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	policyID := chi.URLParam(r, "l7policy_id")
	ruleID := chi.URLParam(r, "l7rule_id")
	if err := s.l7DeleteRule(r.Context(), t, policyID, ruleID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListAllL7Rules(w http.ResponseWriter, r *http.Request, t Tenant) error {
	f, err := l7ParseRulesListQuery(r)
	if err != nil {
		return err
	}
	items, pi, err := s.l7ListAllRules(r.Context(), t, f)
	if err != nil {
		return err
	}
	out := make([]l7RuleWire, len(items))
	for i, item := range items {
		out[i] = l7ToRuleWire(t, item)
	}
	return httpx.WriteJSON(w, http.StatusOK, l7ListRulesResponse{
		RequestID: requestID(r),
		PageInfo:  pi,
		Rules:     out,
	})
}
