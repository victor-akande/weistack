package elb

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	l7ActionRedirectToPool     = "REDIRECT_TO_POOL"
	l7ActionRedirectToListener = "REDIRECT_TO_LISTENER"
	l7ActionRedirectToURL      = "REDIRECT_TO_URL"
	l7ActionFixedResponse      = "FIXED_RESPONSE"

	l7DefaultPosition  = 100
	l7MaxRedirectPools = 5
	l7MaxRules         = 10
)

// l7Optional distinguishes absent, explicit null, and present JSON values.
type l7Optional[T any] struct {
	Set   bool
	Value *T
}

func (o *l7Optional[T]) UnmarshalJSON(data []byte) error {
	o.Set = true
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "null" {
		o.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	o.Value = &v
	return nil
}

// l7RedirectPoolConfigInput carries a single redirect_pools_config entry.
type l7RedirectPoolConfigInput struct {
	PoolID string
	Weight *int
}

// l7RedirectURLConfigInput carries create/update fields for redirect_url_config.
type l7RedirectURLConfigInput struct {
	Protocol   *string
	Host       *string
	Port       *string
	Path       *string
	Query      *string
	StatusCode *string
}

// l7FixedResponseConfigInput carries create/update fields for fixed_response_config.
type l7FixedResponseConfigInput struct {
	StatusCode  *string
	ContentType *string
	MessageBody *string
}

// l7CreatePolicyInput is the validated domain input for CreateL7Policy.
type l7CreatePolicyInput struct {
	ListenerID          string
	Name                string
	Description         string
	Action              string
	AdminStateUp        *bool
	Position            *int
	Priority            *int
	RedirectPoolID      string
	RedirectListenerID  string
	RedirectURL         string
	RedirectURLConfig   *l7RedirectURLConfigInput
	RedirectPoolsConfig []l7RedirectPoolConfigInput
	FixedResponseConfig *l7FixedResponseConfigInput
	Rules               []l7CreateRuleInput
}

// l7UpdatePolicyInput is the domain input for UpdateL7Policy.
type l7UpdatePolicyInput struct {
	Name                *string
	Description         *string
	AdminStateUp        *bool
	Priority            *int
	RedirectPoolID      l7Optional[string]
	RedirectListenerID  l7Optional[string]
	RedirectURLConfig   l7Optional[l7RedirectURLConfigInput]
	RedirectPoolsConfig l7Optional[[]l7RedirectPoolConfigInput]
	FixedResponseConfig l7Optional[l7FixedResponseConfigInput]
	Rules               l7Optional[[]l7CreateRuleInput]
}

// l7ListPoliciesFilter mirrors SDK model ListL7PoliciesRequest.
type l7ListPoliciesFilter struct {
	IDs                  []string
	Names                []string
	Descriptions         []string
	AdminStateUp         *bool
	ListenerIDs          []string
	Positions            []int
	Actions              []string
	RedirectURLs         []string
	RedirectPoolIDs      []string
	RedirectListenerIDs  []string
	ProvisioningStatuses []string
	EnterpriseProjectIDs []string
	Priorities           []int
	DisplayAllRules      *bool
	Page                 pagination.Marker
	PageReverse          bool
}

// l7PolicyDetail bundles a policy record with its sorted rule IDs.
type l7PolicyDetail struct {
	Policy  l7Policy
	RuleIDs []string
}

func l7ValidAction(action string) bool {
	switch action {
	case l7ActionRedirectToPool, l7ActionRedirectToListener, l7ActionRedirectToURL, l7ActionFixedResponse:
		return true
	default:
		return false
	}
}

func l7IsHTTPFamilyPoolProtocol(proto string) bool {
	switch proto {
	case "HTTP", "HTTPS", "GRPC":
		return true
	default:
		return false
	}
}

func l7CloneRedirectURLConfig(cfg *redirectURLConfig) *redirectURLConfig {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	return &cp
}

func l7CloneFixedResponseConfig(cfg *fixedResponseConfig) *fixedResponseConfig {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	return &cp
}

func l7CloneRedirectPoolsConfig(cfgs []redirectPoolsConfig) []redirectPoolsConfig {
	if len(cfgs) == 0 {
		return nil
	}
	out := make([]redirectPoolsConfig, len(cfgs))
	copy(out, cfgs)
	return out
}

func l7ValidRedirectHost(h string) bool {
	if h == "${host}" {
		return true
	}
	if len(h) == 0 || len(h) > 128 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isAlpha && !isDigit {
			return false
		}
		if !isAlpha && !isDigit && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func l7ValidRedirectPort(p string) bool {
	if p == "${port}" {
		return true
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	return strconv.Itoa(n) == p
}

func l7ValidRedirectPath(p string) bool {
	if p == "${path}" {
		return true
	}
	if len(p) == 0 || len(p) > 128 || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		if !l7IsAllowedPathByte(p[i]) {
			return false
		}
	}
	return true
}

func l7ValidRedirectQuery(q string) bool {
	if q == "" || q == "${query}" {
		return true
	}
	if len(q) > 128 {
		return false
	}
	// Strip valid ${query} placeholder occurrences before checking allowed chars.
	cleaned := strings.ReplaceAll(q, "${query}", "")
	for i := 0; i < len(cleaned); i++ {
		c := cleaned[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if isAlpha || isDigit || strings.IndexByte("!$&'()*+,-./:;=?@^_`", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

func l7ValidateRedirectURLConfig(in *l7RedirectURLConfigInput, base *redirectURLConfig) (*redirectURLConfig, error) {
	if in == nil {
		return nil, errInvalidInput("redirect_url_config")
	}
	cfg := redirectURLConfig{
		Protocol: "${protocol}",
		Host:     "${host}",
		Port:     "${port}",
		Path:     "${path}",
		Query:    "${query}",
	}
	if base != nil {
		cfg = *base
	}
	if in.Protocol != nil && *in.Protocol != "" {
		cfg.Protocol = *in.Protocol
	}
	if in.Host != nil && *in.Host != "" {
		cfg.Host = *in.Host
	}
	if in.Port != nil && *in.Port != "" {
		cfg.Port = *in.Port
	}
	if in.Path != nil && *in.Path != "" {
		cfg.Path = *in.Path
	}
	if in.Query != nil {
		cfg.Query = *in.Query
	}
	if in.StatusCode != nil {
		cfg.StatusCode = *in.StatusCode
	}

	switch cfg.Protocol {
	case "HTTP", "HTTPS", "${protocol}":
	default:
		return nil, errInvalidInput("redirect_url_config.protocol")
	}
	switch cfg.StatusCode {
	case "301", "302", "303", "307", "308":
	default:
		return nil, errInvalidInput("redirect_url_config.status_code")
	}
	if !l7ValidRedirectHost(cfg.Host) {
		return nil, errInvalidInput("redirect_url_config.host")
	}
	if !l7ValidRedirectPort(cfg.Port) {
		return nil, errInvalidInput("redirect_url_config.port")
	}
	if !l7ValidRedirectPath(cfg.Path) {
		return nil, errInvalidInput("redirect_url_config.path")
	}
	if !l7ValidRedirectQuery(cfg.Query) {
		return nil, errInvalidInput("redirect_url_config.query")
	}
	return &cfg, nil
}

func l7ValidFixedStatusCode(code string) bool {
	if len(code) != 3 {
		return false
	}
	n, err := strconv.Atoi(code)
	if err != nil {
		return false
	}
	return (n >= 200 && n <= 299) || (n >= 400 && n <= 499) || (n >= 500 && n <= 599)
}

func l7ValidateFixedResponseConfig(in *l7FixedResponseConfigInput, base *fixedResponseConfig) (*fixedResponseConfig, error) {
	if in == nil {
		return nil, errInvalidInput("fixed_response_config")
	}
	cfg := fixedResponseConfig{
		ContentType: "text/plain",
	}
	if base != nil {
		cfg = *base
	}
	if in.StatusCode != nil {
		cfg.StatusCode = *in.StatusCode
	}
	if in.ContentType != nil && *in.ContentType != "" {
		cfg.ContentType = *in.ContentType
	}
	if in.MessageBody != nil {
		cfg.MessageBody = *in.MessageBody
	}

	if !l7ValidFixedStatusCode(cfg.StatusCode) {
		return nil, errInvalidInput("fixed_response_config.status_code")
	}
	switch cfg.ContentType {
	case "text/plain", "text/css", "text/html", "application/javascript", "application/json":
	default:
		return nil, errInvalidInput("fixed_response_config.content_type")
	}
	if utf8.RuneCountInString(cfg.MessageBody) > 1024 {
		return nil, errInvalidInput("fixed_response_config.message_body")
	}
	return &cfg, nil
}

func (s *Service) l7ValidatePoolTarget(ctx context.Context, t Tenant, lb loadBalancer, poolID, field string) error {
	if poolID == "" {
		return errInvalidInput(field)
	}
	p, err := s.pools(t).Get(ctx, poolID)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("pool", poolID)
	}
	if err != nil {
		return err
	}
	if p.LoadBalancerID != "" {
		if p.LoadBalancerID != lb.ID {
			return errInvalidInput(field)
		}
	} else if p.VPCID != "" && lb.VPCID != "" && p.VPCID != lb.VPCID {
		return errInvalidInput(field)
	}
	if !l7IsHTTPFamilyPoolProtocol(p.Protocol) {
		return errInvalidInput(field)
	}
	return nil
}

func (s *Service) l7ValidateRedirectPoolsConfig(ctx context.Context, t Tenant, lb loadBalancer, items []l7RedirectPoolConfigInput) ([]redirectPoolsConfig, error) {
	if len(items) == 0 || len(items) > l7MaxRedirectPools {
		return nil, errInvalidInput("redirect_pools_config")
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]redirectPoolsConfig, 0, len(items))
	for _, item := range items {
		if item.PoolID == "" {
			return nil, errInvalidInput("redirect_pools_config")
		}
		if _, dup := seen[item.PoolID]; dup {
			return nil, errInvalidInput("redirect_pools_config")
		}
		seen[item.PoolID] = struct{}{}
		weight := 1
		if item.Weight != nil {
			if *item.Weight < 0 || *item.Weight > 100 {
				return nil, errInvalidInput("redirect_pools_config")
			}
			weight = *item.Weight
		}
		if err := s.l7ValidatePoolTarget(ctx, t, lb, item.PoolID, "redirect_pools_config"); err != nil {
			return nil, err
		}
		out = append(out, redirectPoolsConfig{
			PoolID: item.PoolID,
			Weight: weight,
		})
	}
	return out, nil
}

func (s *Service) l7ValidateRedirectListener(ctx context.Context, t Tenant, owner listener, targetID string) error {
	if targetID == "" {
		return errInvalidInput("redirect_listener_id")
	}
	target, err := s.listeners(t).Get(ctx, targetID)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("listener", targetID)
	}
	if err != nil {
		return err
	}
	if target.LoadBalancerID != owner.LoadBalancerID {
		return errInvalidInput("redirect_listener_id")
	}
	if target.Protocol != "HTTPS" {
		return errInvalidInput("redirect_listener_id")
	}
	return nil
}

func (s *Service) l7CheckPriorityUnique(ctx context.Context, t Tenant, listenerID, ignorePolicyID string, priority int) error {
	peers, err := s.l7Policies(t).List(ctx, func(p l7Policy) bool {
		return p.ListenerID == listenerID && p.ID != ignorePolicyID
	})
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if peer.Priority != nil && *peer.Priority == priority {
			return errConflict("The priority is already used by another L7 policy on this listener.")
		}
	}
	return nil
}

func (s *Service) l7LookupLBForListener(ctx context.Context, t Tenant, lsn listener) (loadBalancer, error) {
	if lsn.LoadBalancerID == "" {
		return loadBalancer{}, nil
	}
	lb, err := s.loadBalancers(t).Get(ctx, lsn.LoadBalancerID)
	if errors.Is(err, store.ErrNotFound) {
		return loadBalancer{ID: lsn.LoadBalancerID}, nil
	}
	if err != nil {
		return loadBalancer{}, err
	}
	return lb, nil
}

// l7Paginate applies forward or reverse marker/limit pagination to a slice sorted by ascending ID.
func l7Paginate[T any](all []T, idOf func(T) string, page pagination.Marker, reverse bool) ([]T, pageInfo, error) {
	if !reverse {
		return paginateSlice(all, idOf, page)
	}
	end := len(all)
	if page.ID != "" {
		found := false
		for i, item := range all {
			if idOf(item) == page.ID {
				end = i
				found = true
				break
			}
		}
		if !found {
			return nil, pageInfo{}, errInvalidInput("marker")
		}
	}
	start := 0
	hasMore := false
	if page.Limit > 0 && end > page.Limit {
		start = end - page.Limit
		hasMore = true
	}
	out := make([]T, end-start)
	copy(out, all[start:end])
	return out, makePageInfo(out, idOf, hasMore), nil
}

// l7CreatePolicy creates a forwarding policy and any inline rules (§3.8).
func (s *Service) l7CreatePolicy(ctx context.Context, t Tenant, in l7CreatePolicyInput) (l7PolicyDetail, error) {
	if !validName(in.Name) {
		return l7PolicyDetail{}, errInvalidInput("name")
	}
	if !validDescription(in.Description) {
		return l7PolicyDetail{}, errInvalidInput("description")
	}
	if in.ListenerID == "" {
		return l7PolicyDetail{}, errInvalidInput("listener_id")
	}
	if !l7ValidAction(in.Action) {
		return l7PolicyDetail{}, errInvalidInput("action")
	}
	if in.AdminStateUp != nil && !*in.AdminStateUp {
		return l7PolicyDetail{}, errInvalidInput("admin_state_up")
	}
	if in.Priority != nil && *in.Priority < 0 {
		return l7PolicyDetail{}, errInvalidInput("priority")
	}

	// Pre-validate inline rules (including duplicate types) before locking/storing.
	validatedRules, err := l7ValidateInlineRules(in.Action, in.Rules)
	if err != nil {
		return l7PolicyDetail{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lsn, err := s.listeners(t).Get(ctx, in.ListenerID)
	if errors.Is(err, store.ErrNotFound) {
		return l7PolicyDetail{}, errNotFound("listener", in.ListenerID)
	}
	if err != nil {
		return l7PolicyDetail{}, err
	}
	if !isL7ListenerProtocol(lsn.Protocol) {
		return l7PolicyDetail{}, errInvalidInput("listener_id")
	}

	var priority *int
	if in.Priority != nil {
		if !lsn.EnhanceL7PolicyEnable {
			return l7PolicyDetail{}, errInvalidInput("priority")
		}
		if err := s.l7CheckPriorityUnique(ctx, t, lsn.ID, "", *in.Priority); err != nil {
			return l7PolicyDetail{}, err
		}
		p := *in.Priority
		priority = &p
	}

	lb, err := s.l7LookupLBForListener(ctx, t, lsn)
	if err != nil {
		return l7PolicyDetail{}, err
	}

	var (
		redirectPoolID     string
		redirectPools      []redirectPoolsConfig
		redirectListenerID string
		redirectURLCfg     *redirectURLConfig
		fixedResponseCfg   *fixedResponseConfig
	)

	switch in.Action {
	case l7ActionRedirectToPool:
		if in.RedirectListenerID != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_listener_id")
		}
		if in.RedirectURLConfig != nil {
			return l7PolicyDetail{}, errInvalidInput("redirect_url_config")
		}
		if in.FixedResponseConfig != nil {
			return l7PolicyDetail{}, errInvalidInput("fixed_response_config")
		}
		if in.RedirectPoolID == "" && len(in.RedirectPoolsConfig) == 0 {
			return l7PolicyDetail{}, errInvalidInput("redirect_pool_id")
		}
		if len(in.RedirectPoolsConfig) > 0 {
			if in.RedirectPoolID != "" {
				if err := s.l7ValidatePoolTarget(ctx, t, lb, in.RedirectPoolID, "redirect_pool_id"); err != nil {
					return l7PolicyDetail{}, err
				}
			}
			redirectPools, err = s.l7ValidateRedirectPoolsConfig(ctx, t, lb, in.RedirectPoolsConfig)
			if err != nil {
				return l7PolicyDetail{}, err
			}
		} else {
			if err := s.l7ValidatePoolTarget(ctx, t, lb, in.RedirectPoolID, "redirect_pool_id"); err != nil {
				return l7PolicyDetail{}, err
			}
			redirectPoolID = in.RedirectPoolID
		}

	case l7ActionRedirectToListener:
		if lsn.Protocol != "HTTP" {
			return l7PolicyDetail{}, errInvalidInput("listener_id")
		}
		if in.RedirectPoolID != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_pool_id")
		}
		if len(in.RedirectPoolsConfig) > 0 {
			return l7PolicyDetail{}, errInvalidInput("redirect_pools_config")
		}
		if in.RedirectURLConfig != nil {
			return l7PolicyDetail{}, errInvalidInput("redirect_url_config")
		}
		if in.FixedResponseConfig != nil {
			return l7PolicyDetail{}, errInvalidInput("fixed_response_config")
		}
		if err := s.l7ValidateRedirectListener(ctx, t, lsn, in.RedirectListenerID); err != nil {
			return l7PolicyDetail{}, err
		}
		redirectListenerID = in.RedirectListenerID

	case l7ActionRedirectToURL:
		if in.RedirectPoolID != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_pool_id")
		}
		if len(in.RedirectPoolsConfig) > 0 {
			return l7PolicyDetail{}, errInvalidInput("redirect_pools_config")
		}
		if in.RedirectListenerID != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_listener_id")
		}
		if in.FixedResponseConfig != nil {
			return l7PolicyDetail{}, errInvalidInput("fixed_response_config")
		}
		redirectURLCfg, err = l7ValidateRedirectURLConfig(in.RedirectURLConfig, nil)
		if err != nil {
			return l7PolicyDetail{}, err
		}

	case l7ActionFixedResponse:
		if in.RedirectPoolID != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_pool_id")
		}
		if len(in.RedirectPoolsConfig) > 0 {
			return l7PolicyDetail{}, errInvalidInput("redirect_pools_config")
		}
		if in.RedirectListenerID != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_listener_id")
		}
		if in.RedirectURLConfig != nil {
			return l7PolicyDetail{}, errInvalidInput("redirect_url_config")
		}
		fixedResponseCfg, err = l7ValidateFixedResponseConfig(in.FixedResponseConfig, nil)
		if err != nil {
			return l7PolicyDetail{}, err
		}
	}

	ep := lsn.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}

	now := s.nowUTC()
	pol := l7Policy{
		ID:                  s.ids.UUID(),
		ListenerID:          lsn.ID,
		Name:                in.Name,
		Description:         in.Description,
		Action:              in.Action,
		AdminStateUp:        true,
		Position:            l7DefaultPosition,
		Priority:            priority,
		RedirectPoolID:      redirectPoolID,
		RedirectListenerID:  redirectListenerID,
		RedirectURL:         in.RedirectURL,
		RedirectURLConfig:   l7CloneRedirectURLConfig(redirectURLCfg),
		RedirectPoolsConfig: l7CloneRedirectPoolsConfig(redirectPools),
		FixedResponseConfig: l7CloneFixedResponseConfig(fixedResponseCfg),
		EnterpriseProjectID: ep,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	if err := s.l7Policies(t).Create(ctx, pol.ID, pol); err != nil {
		return l7PolicyDetail{}, err
	}

	ruleIDs := make([]string, 0, len(validatedRules))
	for _, vr := range validatedRules {
		r := l7Rule{
			ID:           s.ids.UUID(),
			PolicyID:     pol.ID,
			Type:         vr.Type,
			CompareType:  vr.CompareType,
			Key:          vr.Key,
			Value:        vr.Value,
			AdminStateUp: true,
			Invert:       false,
			Conditions:   l7CloneRuleConditions(vr.Conditions),
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if err := s.l7Rules(t).Create(ctx, r.ID, r); err != nil {
			for _, createdID := range ruleIDs {
				_ = s.l7Rules(t).Delete(ctx, createdID)
			}
			_ = s.l7Policies(t).Delete(ctx, pol.ID)
			return l7PolicyDetail{}, err
		}
		ruleIDs = append(ruleIDs, r.ID)
	}
	sort.Strings(ruleIDs)

	return l7PolicyDetail{
		Policy:  pol,
		RuleIDs: ruleIDs,
	}, nil
}

// l7GetPolicy returns a single forwarding policy with its rule IDs (§3.8).
func (s *Service) l7GetPolicy(ctx context.Context, t Tenant, id string) (l7PolicyDetail, error) {
	pol, err := s.l7Policies(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return l7PolicyDetail{}, errNotFound("l7policy", id)
	}
	if err != nil {
		return l7PolicyDetail{}, err
	}
	return s.l7BuildPolicyDetail(ctx, t, pol)
}

func (s *Service) l7BuildPolicyDetail(ctx context.Context, t Tenant, pol l7Policy) (l7PolicyDetail, error) {
	rules, err := s.l7Rules(t).List(ctx, func(r l7Rule) bool { return r.PolicyID == pol.ID })
	if err != nil {
		return l7PolicyDetail{}, err
	}
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	sort.Strings(ids)
	return l7PolicyDetail{
		Policy:  pol,
		RuleIDs: ids,
	}, nil
}

// l7ListPolicies lists forwarding policies matching f in ascending ID order (§3.8).
func (s *Service) l7ListPolicies(ctx context.Context, t Tenant, f l7ListPoliciesFilter) ([]l7PolicyDetail, pageInfo, error) {
	allPolicies, err := s.l7Policies(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}
	allRules, err := s.l7Rules(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}

	rulesByPolicy := make(map[string][]string)
	for _, r := range allRules {
		rulesByPolicy[r.PolicyID] = append(rulesByPolicy[r.PolicyID], r.ID)
	}

	filtered := make([]l7PolicyDetail, 0, len(allPolicies))
	for _, p := range allPolicies {
		pos := p.Position
		if pos == 0 {
			pos = l7DefaultPosition
		}
		ep := p.EnterpriseProjectID
		if ep == "" {
			ep = defaultEnterpriseProjectID
		}
		if !matchesAny(f.IDs, p.ID) ||
			!matchesAny(f.Names, p.Name) ||
			!matchesAny(f.Descriptions, p.Description) ||
			!matchesAny(f.ListenerIDs, p.ListenerID) ||
			!matchesAny(f.Actions, p.Action) ||
			!matchesAny(f.RedirectURLs, p.RedirectURL) ||
			!matchesAny(f.RedirectPoolIDs, p.RedirectPoolID) ||
			!matchesAny(f.RedirectListenerIDs, p.RedirectListenerID) ||
			!matchesAny(f.ProvisioningStatuses, StatusActive) ||
			!inEPList(f.EnterpriseProjectIDs, ep) {
			continue
		}
		if f.AdminStateUp != nil && p.AdminStateUp != *f.AdminStateUp {
			continue
		}
		if len(f.Positions) > 0 && !slices.Contains(f.Positions, pos) {
			continue
		}
		if len(f.Priorities) > 0 {
			if p.Priority == nil || !slices.Contains(f.Priorities, *p.Priority) {
				continue
			}
		}

		rIDs := rulesByPolicy[p.ID]
		sort.Strings(rIDs)
		filtered = append(filtered, l7PolicyDetail{
			Policy:  p,
			RuleIDs: rIDs,
		})
	}

	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Policy.ID < filtered[j].Policy.ID })
	return l7Paginate(filtered, func(d l7PolicyDetail) string { return d.Policy.ID }, f.Page, f.PageReverse)
}

// l7UpdatePolicy modifies mutable fields of an existing forwarding policy (§3.8).
func (s *Service) l7UpdatePolicy(ctx context.Context, t Tenant, id string, in l7UpdatePolicyInput) (l7PolicyDetail, error) {
	if in.Name != nil && !validName(*in.Name) {
		return l7PolicyDetail{}, errInvalidInput("name")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return l7PolicyDetail{}, errInvalidInput("description")
	}
	if in.AdminStateUp != nil && !*in.AdminStateUp {
		return l7PolicyDetail{}, errInvalidInput("admin_state_up")
	}
	if in.Priority != nil && *in.Priority < 0 {
		return l7PolicyDetail{}, errInvalidInput("priority")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pol, err := s.l7Policies(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return l7PolicyDetail{}, errNotFound("l7policy", id)
	}
	if err != nil {
		return l7PolicyDetail{}, err
	}

	lsn, err := s.listeners(t).Get(ctx, pol.ListenerID)
	if errors.Is(err, store.ErrNotFound) {
		return l7PolicyDetail{}, errNotFound("listener", pol.ListenerID)
	}
	if err != nil {
		return l7PolicyDetail{}, err
	}

	if in.Priority != nil {
		if !lsn.EnhanceL7PolicyEnable {
			return l7PolicyDetail{}, errInvalidInput("priority")
		}
		if err := s.l7CheckPriorityUnique(ctx, t, lsn.ID, pol.ID, *in.Priority); err != nil {
			return l7PolicyDetail{}, err
		}
	}

	var replacementRules []l7ValidatedRule
	replaceRules := false
	if in.Rules.Set {
		if in.Rules.Value == nil {
			return l7PolicyDetail{}, errInvalidInput("rules")
		}
		validated, err := l7ValidateInlineRules(pol.Action, *in.Rules.Value)
		if err != nil {
			return l7PolicyDetail{}, err
		}
		replacementRules = validated
		replaceRules = true
	}

	lb, err := s.l7LookupLBForListener(ctx, t, lsn)
	if err != nil {
		return l7PolicyDetail{}, err
	}

	switch pol.Action {
	case l7ActionRedirectToPool:
		if in.RedirectListenerID.Set && in.RedirectListenerID.Value != nil && *in.RedirectListenerID.Value != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_listener_id")
		}
		if in.RedirectURLConfig.Set && in.RedirectURLConfig.Value != nil {
			return l7PolicyDetail{}, errInvalidInput("redirect_url_config")
		}
		if in.FixedResponseConfig.Set && in.FixedResponseConfig.Value != nil {
			return l7PolicyDetail{}, errInvalidInput("fixed_response_config")
		}
		if in.RedirectPoolsConfig.Set {
			if in.RedirectPoolsConfig.Value == nil || len(*in.RedirectPoolsConfig.Value) == 0 {
				return l7PolicyDetail{}, errInvalidInput("redirect_pools_config")
			}
			validatedPools, err := s.l7ValidateRedirectPoolsConfig(ctx, t, lb, *in.RedirectPoolsConfig.Value)
			if err != nil {
				return l7PolicyDetail{}, err
			}
			if in.RedirectPoolID.Set && in.RedirectPoolID.Value != nil && *in.RedirectPoolID.Value != "" {
				if err := s.l7ValidatePoolTarget(ctx, t, lb, *in.RedirectPoolID.Value, "redirect_pool_id"); err != nil {
					return l7PolicyDetail{}, err
				}
			}
			pol.RedirectPoolsConfig = validatedPools
			pol.RedirectPoolID = ""
		} else if in.RedirectPoolID.Set {
			if in.RedirectPoolID.Value == nil || *in.RedirectPoolID.Value == "" {
				return l7PolicyDetail{}, errInvalidInput("redirect_pool_id")
			}
			if err := s.l7ValidatePoolTarget(ctx, t, lb, *in.RedirectPoolID.Value, "redirect_pool_id"); err != nil {
				return l7PolicyDetail{}, err
			}
			pol.RedirectPoolID = *in.RedirectPoolID.Value
			pol.RedirectPoolsConfig = nil
		}

	case l7ActionRedirectToListener:
		if in.RedirectPoolID.Set && in.RedirectPoolID.Value != nil && *in.RedirectPoolID.Value != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_pool_id")
		}
		if in.RedirectPoolsConfig.Set && in.RedirectPoolsConfig.Value != nil && len(*in.RedirectPoolsConfig.Value) > 0 {
			return l7PolicyDetail{}, errInvalidInput("redirect_pools_config")
		}
		if in.RedirectURLConfig.Set && in.RedirectURLConfig.Value != nil {
			return l7PolicyDetail{}, errInvalidInput("redirect_url_config")
		}
		if in.FixedResponseConfig.Set && in.FixedResponseConfig.Value != nil {
			return l7PolicyDetail{}, errInvalidInput("fixed_response_config")
		}
		if in.RedirectListenerID.Set {
			if in.RedirectListenerID.Value == nil || *in.RedirectListenerID.Value == "" {
				return l7PolicyDetail{}, errInvalidInput("redirect_listener_id")
			}
			if err := s.l7ValidateRedirectListener(ctx, t, lsn, *in.RedirectListenerID.Value); err != nil {
				return l7PolicyDetail{}, err
			}
			pol.RedirectListenerID = *in.RedirectListenerID.Value
		}

	case l7ActionRedirectToURL:
		if in.RedirectPoolID.Set && in.RedirectPoolID.Value != nil && *in.RedirectPoolID.Value != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_pool_id")
		}
		if in.RedirectPoolsConfig.Set && in.RedirectPoolsConfig.Value != nil && len(*in.RedirectPoolsConfig.Value) > 0 {
			return l7PolicyDetail{}, errInvalidInput("redirect_pools_config")
		}
		if in.RedirectListenerID.Set && in.RedirectListenerID.Value != nil && *in.RedirectListenerID.Value != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_listener_id")
		}
		if in.FixedResponseConfig.Set && in.FixedResponseConfig.Value != nil {
			return l7PolicyDetail{}, errInvalidInput("fixed_response_config")
		}
		if in.RedirectURLConfig.Set {
			if in.RedirectURLConfig.Value == nil {
				return l7PolicyDetail{}, errInvalidInput("redirect_url_config")
			}
			validatedCfg, err := l7ValidateRedirectURLConfig(in.RedirectURLConfig.Value, pol.RedirectURLConfig)
			if err != nil {
				return l7PolicyDetail{}, err
			}
			pol.RedirectURLConfig = validatedCfg
		}

	case l7ActionFixedResponse:
		if in.RedirectPoolID.Set && in.RedirectPoolID.Value != nil && *in.RedirectPoolID.Value != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_pool_id")
		}
		if in.RedirectPoolsConfig.Set && in.RedirectPoolsConfig.Value != nil && len(*in.RedirectPoolsConfig.Value) > 0 {
			return l7PolicyDetail{}, errInvalidInput("redirect_pools_config")
		}
		if in.RedirectListenerID.Set && in.RedirectListenerID.Value != nil && *in.RedirectListenerID.Value != "" {
			return l7PolicyDetail{}, errInvalidInput("redirect_listener_id")
		}
		if in.RedirectURLConfig.Set && in.RedirectURLConfig.Value != nil {
			return l7PolicyDetail{}, errInvalidInput("redirect_url_config")
		}
		if in.FixedResponseConfig.Set {
			if in.FixedResponseConfig.Value == nil {
				return l7PolicyDetail{}, errInvalidInput("fixed_response_config")
			}
			validatedCfg, err := l7ValidateFixedResponseConfig(in.FixedResponseConfig.Value, pol.FixedResponseConfig)
			if err != nil {
				return l7PolicyDetail{}, err
			}
			pol.FixedResponseConfig = validatedCfg
		}
	}

	if in.Name != nil {
		pol.Name = *in.Name
	}
	if in.Description != nil {
		pol.Description = *in.Description
	}
	if in.Priority != nil {
		p := *in.Priority
		pol.Priority = &p
	}

	now := s.nowUTC()
	pol.UpdatedAt = now
	if err := s.l7Policies(t).Put(ctx, pol.ID, pol); err != nil {
		return l7PolicyDetail{}, err
	}

	if replaceRules {
		existingRules, err := s.l7Rules(t).List(ctx, func(r l7Rule) bool { return r.PolicyID == pol.ID })
		if err != nil {
			return l7PolicyDetail{}, err
		}
		for _, old := range existingRules {
			if err := s.l7Rules(t).Delete(ctx, old.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return l7PolicyDetail{}, err
			}
		}
		newIDs := make([]string, 0, len(replacementRules))
		for _, vr := range replacementRules {
			r := l7Rule{
				ID:           s.ids.UUID(),
				PolicyID:     pol.ID,
				Type:         vr.Type,
				CompareType:  vr.CompareType,
				Key:          vr.Key,
				Value:        vr.Value,
				AdminStateUp: true,
				Invert:       false,
				Conditions:   l7CloneRuleConditions(vr.Conditions),
				CreatedAt:    now,
				UpdatedAt:    now,
			}
			if err := s.l7Rules(t).Create(ctx, r.ID, r); err != nil {
				return l7PolicyDetail{}, err
			}
			newIDs = append(newIDs, r.ID)
		}
		sort.Strings(newIDs)
		return l7PolicyDetail{
			Policy:  pol,
			RuleIDs: newIDs,
		}, nil
	}

	return s.l7BuildPolicyDetail(ctx, t, pol)
}

// l7DeletePolicy deletes a forwarding policy and every rule belonging to it (§3.8).
func (s *Service) l7DeletePolicy(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.l7Policies(t).Get(ctx, id); errors.Is(err, store.ErrNotFound) {
		return errNotFound("l7policy", id)
	} else if err != nil {
		return err
	}

	rules, err := s.l7Rules(t).List(ctx, func(r l7Rule) bool { return r.PolicyID == id })
	if err != nil {
		return err
	}
	for _, r := range rules {
		if err := s.l7Rules(t).Delete(ctx, r.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	if err := s.l7Policies(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
