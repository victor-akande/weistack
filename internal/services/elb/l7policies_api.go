package elb

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

// l7FlexInt unmarshals either a JSON integer or a quoted decimal string (the
// ELB v3 SDK sends redirect_pools_config[].weight as *string while clients may
// also send an integer).
type l7FlexInt struct {
	Set   bool
	Value int
}

func (f *l7FlexInt) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	f.Set = true
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		f.Value = n
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	f.Value = n
	return nil
}

type l7RedirectPoolConfigReq struct {
	PoolID string    `json:"pool_id"`
	Weight l7FlexInt `json:"weight"`
}

func (r l7RedirectPoolConfigReq) toInput() l7RedirectPoolConfigInput {
	var w *int
	if r.Weight.Set {
		v := r.Weight.Value
		w = &v
	}
	return l7RedirectPoolConfigInput{
		PoolID: r.PoolID,
		Weight: w,
	}
}

type l7RedirectURLConfigReq struct {
	Protocol   *string `json:"protocol"`
	Host       *string `json:"host"`
	Port       *string `json:"port"`
	Path       *string `json:"path"`
	Query      *string `json:"query"`
	StatusCode *string `json:"status_code"`
}

func (r *l7RedirectURLConfigReq) toInput() *l7RedirectURLConfigInput {
	if r == nil {
		return nil
	}
	return &l7RedirectURLConfigInput{
		Protocol:   r.Protocol,
		Host:       r.Host,
		Port:       r.Port,
		Path:       r.Path,
		Query:      r.Query,
		StatusCode: r.StatusCode,
	}
}

type l7FixedResponseConfigReq struct {
	StatusCode  *string `json:"status_code"`
	ContentType *string `json:"content_type"`
	MessageBody *string `json:"message_body"`
}

func (r *l7FixedResponseConfigReq) toInput() *l7FixedResponseConfigInput {
	if r == nil {
		return nil
	}
	return &l7FixedResponseConfigInput{
		StatusCode:  r.StatusCode,
		ContentType: r.ContentType,
		MessageBody: r.MessageBody,
	}
}

type l7CreatePolicyRequest struct {
	L7Policy *l7CreatePolicyOptionReq `json:"l7policy"`
}

// l7CreatePolicyOptionReq mirrors SDK model CreateL7PolicyOption.
type l7CreatePolicyOptionReq struct {
	Action              string                    `json:"action"`
	AdminStateUp        *bool                     `json:"admin_state_up"`
	Description         *string                   `json:"description"`
	ListenerID          string                    `json:"listener_id"`
	Name                *string                   `json:"name"`
	Position            *int                      `json:"position"`
	Priority            *int                      `json:"priority"`
	ProjectID           *string                   `json:"project_id"`
	RedirectListenerID  *string                   `json:"redirect_listener_id"`
	RedirectPoolID      *string                   `json:"redirect_pool_id"`
	RedirectURL         *string                   `json:"redirect_url"`
	RedirectURLConfig   *l7RedirectURLConfigReq   `json:"redirect_url_config"`
	RedirectPoolsConfig []l7RedirectPoolConfigReq `json:"redirect_pools_config"`
	FixedResponseConfig *l7FixedResponseConfigReq `json:"fixed_response_config"`
	Rules               []l7CreateRuleOptionReq   `json:"rules"`
}

type l7UpdatePolicyRequest struct {
	L7Policy *l7UpdatePolicyOptionReq `json:"l7policy"`
}

// l7UpdatePolicyOptionReq mirrors SDK model UpdateL7PolicyOption.
type l7UpdatePolicyOptionReq struct {
	AdminStateUp        *bool                                 `json:"admin_state_up"`
	Description         *string                               `json:"description"`
	Name                *string                               `json:"name"`
	Priority            *int                                  `json:"priority"`
	RedirectListenerID  l7Optional[string]                    `json:"redirect_listener_id"`
	RedirectPoolID      l7Optional[string]                    `json:"redirect_pool_id"`
	RedirectPoolsConfig l7Optional[[]l7RedirectPoolConfigReq] `json:"redirect_pools_config"`
	RedirectURLConfig   l7Optional[l7RedirectURLConfigReq]    `json:"redirect_url_config"`
	FixedResponseConfig l7Optional[l7FixedResponseConfigReq]  `json:"fixed_response_config"`
	Rules               l7Optional[[]l7CreateRuleOptionReq]   `json:"rules"`
}

// l7PolicyWire mirrors SDK model L7Policy.
type l7PolicyWire struct {
	ID                  string                `json:"id"`
	Name                string                `json:"name"`
	Description         string                `json:"description"`
	Action              string                `json:"action"`
	AdminStateUp        bool                  `json:"admin_state_up"`
	ListenerID          string                `json:"listener_id"`
	Position            int                   `json:"position"`
	Priority            *int                  `json:"priority,omitempty"`
	ProjectID           string                `json:"project_id"`
	ProvisioningStatus  string                `json:"provisioning_status"`
	RedirectPoolID      string                `json:"redirect_pool_id"`
	RedirectListenerID  string                `json:"redirect_listener_id"`
	RedirectURL         string                `json:"redirect_url"`
	Rules               []idRef               `json:"rules"`
	RedirectURLConfig   *redirectURLConfig    `json:"redirect_url_config"`
	RedirectPoolsConfig []redirectPoolsConfig `json:"redirect_pools_config"`
	FixedResponseConfig *fixedResponseConfig  `json:"fixed_response_config"`
	EnterpriseProjectID string                `json:"enterprise_project_id"`
	CreatedAt           string                `json:"created_at"`
	UpdatedAt           string                `json:"updated_at"`
}

type l7PolicyEnvelope struct {
	RequestID string       `json:"request_id"`
	L7Policy  l7PolicyWire `json:"l7policy"`
}

type l7ListPoliciesResponse struct {
	RequestID  string         `json:"request_id"`
	PageInfo   pageInfo       `json:"page_info"`
	L7Policies []l7PolicyWire `json:"l7policies"`
}

func l7DerefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func l7NonEmpty(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func l7ToPolicyWire(t Tenant, d l7PolicyDetail) l7PolicyWire {
	p := d.Policy
	rules := make([]idRef, len(d.RuleIDs))
	for i, id := range d.RuleIDs {
		rules[i] = idRef{ID: id}
	}
	poolsCfg := make([]redirectPoolsConfig, len(p.RedirectPoolsConfig))
	copy(poolsCfg, p.RedirectPoolsConfig)

	pos := p.Position
	if pos == 0 {
		pos = l7DefaultPosition
	}
	ep := p.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}
	var prio *int
	if p.Priority != nil {
		v := *p.Priority
		prio = &v
	}

	return l7PolicyWire{
		ID:                  p.ID,
		Name:                p.Name,
		Description:         p.Description,
		Action:              p.Action,
		AdminStateUp:        p.AdminStateUp,
		ListenerID:          p.ListenerID,
		Position:            pos,
		Priority:            prio,
		ProjectID:           t.ProjectID,
		ProvisioningStatus:  StatusActive,
		RedirectPoolID:      p.RedirectPoolID,
		RedirectListenerID:  p.RedirectListenerID,
		RedirectURL:         p.RedirectURL,
		Rules:               rules,
		RedirectURLConfig:   l7CloneRedirectURLConfig(p.RedirectURLConfig),
		RedirectPoolsConfig: poolsCfg,
		FixedResponseConfig: l7CloneFixedResponseConfig(p.FixedResponseConfig),
		EnterpriseProjectID: ep,
		CreatedAt:           formatTime(p.CreatedAt),
		UpdatedAt:           formatTime(p.UpdatedAt),
	}
}

func l7ConvertRedirectPoolsReq(items []l7RedirectPoolConfigReq) []l7RedirectPoolConfigInput {
	if len(items) == 0 {
		return nil
	}
	out := make([]l7RedirectPoolConfigInput, len(items))
	for i, item := range items {
		out[i] = item.toInput()
	}
	return out
}

func l7ConvertInlineRulesReq(items []l7CreateRuleOptionReq) []l7CreateRuleInput {
	if len(items) == 0 {
		return nil
	}
	out := make([]l7CreateRuleInput, len(items))
	for i, item := range items {
		out[i] = item.toInput()
	}
	return out
}

func (s *Service) handleCreateL7Policy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req l7CreatePolicyRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.L7Policy == nil {
		return errInvalidInput("l7policy")
	}
	opt := req.L7Policy
	detail, err := s.l7CreatePolicy(r.Context(), t, l7CreatePolicyInput{
		ListenerID:          opt.ListenerID,
		Name:                l7DerefString(opt.Name),
		Description:         l7DerefString(opt.Description),
		Action:              opt.Action,
		AdminStateUp:        opt.AdminStateUp,
		Position:            opt.Position,
		Priority:            opt.Priority,
		RedirectPoolID:      l7DerefString(opt.RedirectPoolID),
		RedirectListenerID:  l7DerefString(opt.RedirectListenerID),
		RedirectURL:         l7DerefString(opt.RedirectURL),
		RedirectURLConfig:   opt.RedirectURLConfig.toInput(),
		RedirectPoolsConfig: l7ConvertRedirectPoolsReq(opt.RedirectPoolsConfig),
		FixedResponseConfig: opt.FixedResponseConfig.toInput(),
		Rules:               l7ConvertInlineRulesReq(opt.Rules),
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, l7PolicyEnvelope{
		RequestID: requestID(r),
		L7Policy:  l7ToPolicyWire(t, detail),
	})
}

func (s *Service) handleListL7Policies(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	pageReverse, err := parseBoolQuery(q, "page_reverse")
	if err != nil {
		return err
	}
	adminUp, err := parseBoolQuery(q, "admin_state_up")
	if err != nil {
		return err
	}
	displayAllRules, err := parseBoolQuery(q, "display_all_rules")
	if err != nil {
		return err
	}
	positions, err := parseIntQueryValues(q, "position")
	if err != nil {
		return err
	}
	priorities, err := parseIntQueryValues(q, "priority")
	if err != nil {
		return err
	}

	items, pi, err := s.l7ListPolicies(r.Context(), t, l7ListPoliciesFilter{
		IDs:                  l7NonEmpty(q["id"]),
		Names:                l7NonEmpty(q["name"]),
		Descriptions:         l7NonEmpty(q["description"]),
		AdminStateUp:         adminUp,
		ListenerIDs:          l7NonEmpty(q["listener_id"]),
		Positions:            positions,
		Actions:              l7NonEmpty(q["action"]),
		RedirectURLs:         l7NonEmpty(q["redirect_url"]),
		RedirectPoolIDs:      l7NonEmpty(q["redirect_pool_id"]),
		RedirectListenerIDs:  l7NonEmpty(q["redirect_listener_id"]),
		ProvisioningStatuses: l7NonEmpty(q["provisioning_status"]),
		EnterpriseProjectIDs: l7NonEmpty(q["enterprise_project_id"]),
		Priorities:           priorities,
		DisplayAllRules:      displayAllRules,
		Page:                 page,
		PageReverse:          pageReverse != nil && *pageReverse,
	})
	if err != nil {
		return err
	}

	out := make([]l7PolicyWire, len(items))
	for i, item := range items {
		out[i] = l7ToPolicyWire(t, item)
	}
	return httpx.WriteJSON(w, http.StatusOK, l7ListPoliciesResponse{
		RequestID:  requestID(r),
		PageInfo:   pi,
		L7Policies: out,
	})
}

func (s *Service) handleShowL7Policy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "l7policy_id")
	detail, err := s.l7GetPolicy(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, l7PolicyEnvelope{
		RequestID: requestID(r),
		L7Policy:  l7ToPolicyWire(t, detail),
	})
}

func (s *Service) handleUpdateL7Policy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req l7UpdatePolicyRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.L7Policy == nil {
		return errInvalidInput("l7policy")
	}
	id := chi.URLParam(r, "l7policy_id")
	opt := req.L7Policy

	var urlOpt l7Optional[l7RedirectURLConfigInput]
	if opt.RedirectURLConfig.Set {
		urlOpt.Set = true
		if opt.RedirectURLConfig.Value != nil {
			urlOpt.Value = opt.RedirectURLConfig.Value.toInput()
		}
	}

	var fixedOpt l7Optional[l7FixedResponseConfigInput]
	if opt.FixedResponseConfig.Set {
		fixedOpt.Set = true
		if opt.FixedResponseConfig.Value != nil {
			fixedOpt.Value = opt.FixedResponseConfig.Value.toInput()
		}
	}

	var poolsOpt l7Optional[[]l7RedirectPoolConfigInput]
	if opt.RedirectPoolsConfig.Set {
		poolsOpt.Set = true
		if opt.RedirectPoolsConfig.Value != nil {
			converted := l7ConvertRedirectPoolsReq(*opt.RedirectPoolsConfig.Value)
			if converted == nil {
				converted = []l7RedirectPoolConfigInput{}
			}
			poolsOpt.Value = &converted
		}
	}

	var rulesOpt l7Optional[[]l7CreateRuleInput]
	if opt.Rules.Set {
		rulesOpt.Set = true
		if opt.Rules.Value != nil {
			converted := l7ConvertInlineRulesReq(*opt.Rules.Value)
			if converted == nil {
				converted = []l7CreateRuleInput{}
			}
			rulesOpt.Value = &converted
		}
	}

	detail, err := s.l7UpdatePolicy(r.Context(), t, id, l7UpdatePolicyInput{
		Name:                opt.Name,
		Description:         opt.Description,
		AdminStateUp:        opt.AdminStateUp,
		Priority:            opt.Priority,
		RedirectPoolID:      opt.RedirectPoolID,
		RedirectListenerID:  opt.RedirectListenerID,
		RedirectURLConfig:   urlOpt,
		RedirectPoolsConfig: poolsOpt,
		FixedResponseConfig: fixedOpt,
		Rules:               rulesOpt,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, l7PolicyEnvelope{
		RequestID: requestID(r),
		L7Policy:  l7ToPolicyWire(t, detail),
	})
}

func (s *Service) handleDeleteL7Policy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "l7policy_id")
	if err := s.l7DeletePolicy(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
