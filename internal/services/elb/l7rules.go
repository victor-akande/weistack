package elb

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	l7RuleTypeHostName    = "HOST_NAME"
	l7RuleTypePath        = "PATH"
	l7RuleTypeMethod      = "METHOD"
	l7RuleTypeHeader      = "HEADER"
	l7RuleTypeQueryString = "QUERY_STRING"
	l7RuleTypeSourceIP    = "SOURCE_IP"

	l7CompareEqualTo    = "EQUAL_TO"
	l7CompareRegex      = "REGEX"
	l7CompareStartsWith = "STARTS_WITH"
)

var (
	l7HeaderKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)
)

// l7CreateRuleInput is the domain input for CreateL7Rule and inline policy rules.
type l7CreateRuleInput struct {
	Type         string
	CompareType  string
	Key          string
	Value        string
	AdminStateUp *bool
	Invert       *bool
	Conditions   []ruleCondition
}

// l7UpdateRuleInput is the domain input for UpdateL7Rule.
type l7UpdateRuleInput struct {
	CompareType  *string
	Key          *string
	Value        *string
	AdminStateUp *bool
	Invert       *bool
	Conditions   l7Optional[[]ruleCondition]
}

// l7ListRulesFilter mirrors SDK models ListL7RulesRequest and ListAllL7RulesRequest.
type l7ListRulesFilter struct {
	IDs                  []string
	CompareTypes         []string
	ProvisioningStatuses []string
	Invert               *bool
	AdminStateUp         *bool
	Values               []string
	Keys                 []string
	Types                []string
	EnterpriseProjectIDs []string
	L7PolicyIDs          []string
	Page                 pagination.Marker
	PageReverse          bool
}

// l7ValidatedRule holds normalized, validated rule fields ready for storage.
type l7ValidatedRule struct {
	Type        string
	CompareType string
	Key         string
	Value       string
	Conditions  []ruleCondition
}

func l7CloneRuleConditions(conds []ruleCondition) []ruleCondition {
	if len(conds) == 0 {
		return nil
	}
	out := make([]ruleCondition, len(conds))
	copy(out, conds)
	return out
}

func l7ValidRuleType(typ string) bool {
	switch typ {
	case l7RuleTypeHostName, l7RuleTypePath, l7RuleTypeMethod, l7RuleTypeHeader, l7RuleTypeQueryString, l7RuleTypeSourceIP:
		return true
	default:
		return false
	}
}

func l7RuleTypeUsesKey(typ string) bool {
	return typ == l7RuleTypeHeader || typ == l7RuleTypeQueryString
}

func l7ValidCompareType(typ, compareType string) bool {
	switch compareType {
	case l7CompareEqualTo:
		return l7ValidRuleType(typ)
	case l7CompareRegex, l7CompareStartsWith:
		return typ == l7RuleTypePath
	default:
		return false
	}
}

func l7IsAllowedPathByte(c byte) bool {
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
		return true
	}
	return strings.IndexByte(`_~';@^-%#&$.*+?,=!:|\/()[]{}`, c) >= 0
}

func l7ValidHostNameValue(v string) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isAlpha && !isDigit && c != '*' {
			return false
		}
		if !isAlpha && !isDigit && c != '-' && c != '.' && c != '*' {
			return false
		}
	}
	if strings.Contains(v, "*") {
		// Wildcard asterisk is allowed only as the leftmost label ("*.example.com").
		if !strings.HasPrefix(v, "*.") || len(v) <= 2 || strings.Contains(v[2:], "*") {
			return false
		}
	}
	return true
}

func l7ValidPathValue(compareType, v string) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	if compareType == l7CompareRegex {
		_, err := regexp.Compile(v)
		return err == nil
	}
	if v[0] != '/' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !l7IsAllowedPathByte(v[i]) {
			return false
		}
	}
	return true
}

func l7ValidMethodValue(v string) bool {
	switch v {
	case "GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func l7ValidSourceIPValue(v string) bool {
	if v == "" {
		return false
	}
	_, err := netip.ParsePrefix(v)
	return err == nil
}

func l7ValidHeaderKey(k string) bool {
	return l7HeaderKeyRE.MatchString(k)
}

func l7ValidHeaderValue(v string) bool {
	n := utf8.RuneCountInString(v)
	if n == 0 || n > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' || c == '"' || c < 32 || c == 127 {
			return false
		}
	}
	return true
}

const l7QueryForbiddenChars = " []{}<>\\\"#&|%~"

func l7ValidQueryToken(s string) bool {
	n := utf8.RuneCountInString(s)
	if n == 0 || n > 128 {
		return false
	}
	return !strings.ContainsAny(s, l7QueryForbiddenChars)
}

func l7ValidateKeyForType(typ, key, field string) error {
	if !l7RuleTypeUsesKey(typ) {
		if key != "" {
			return errInvalidInput(field)
		}
		return nil
	}
	switch typ {
	case l7RuleTypeHeader:
		if !l7ValidHeaderKey(key) {
			return errInvalidInput(field)
		}
	case l7RuleTypeQueryString:
		if !l7ValidQueryToken(key) {
			return errInvalidInput(field)
		}
	}
	return nil
}

func l7ValidateValueForType(typ, compareType, value, field string) error {
	switch typ {
	case l7RuleTypeHostName:
		if !l7ValidHostNameValue(value) {
			return errInvalidInput(field)
		}
	case l7RuleTypePath:
		if !l7ValidPathValue(compareType, value) {
			return errInvalidInput(field)
		}
	case l7RuleTypeMethod:
		if !l7ValidMethodValue(value) {
			return errInvalidInput(field)
		}
	case l7RuleTypeSourceIP:
		if !l7ValidSourceIPValue(value) {
			return errInvalidInput(field)
		}
	case l7RuleTypeHeader:
		if !l7ValidHeaderValue(value) {
			return errInvalidInput(field)
		}
	case l7RuleTypeQueryString:
		if !l7ValidQueryToken(value) {
			return errInvalidInput(field)
		}
	default:
		return errInvalidInput("type")
	}
	return nil
}

func l7ValidateRuleSpec(typ, compareType, key, value string, conditions []ruleCondition, adminStateUp *bool) (l7ValidatedRule, error) {
	if !l7ValidRuleType(typ) {
		return l7ValidatedRule{}, errInvalidInput("type")
	}
	if !l7ValidCompareType(typ, compareType) {
		return l7ValidatedRule{}, errInvalidInput("compare_type")
	}
	if adminStateUp != nil && !*adminStateUp {
		return l7ValidatedRule{}, errInvalidInput("admin_state_up")
	}

	if len(conditions) > 0 {
		if len(conditions) > l7MaxRules {
			return l7ValidatedRule{}, errInvalidInput("conditions")
		}
		firstKey := conditions[0].Key
		seenValues := make(map[string]struct{}, len(conditions))
		outConds := make([]ruleCondition, 0, len(conditions))
		for _, c := range conditions {
			if c.Key != firstKey {
				return l7ValidatedRule{}, errInvalidInput("conditions")
			}
			if err := l7ValidateKeyForType(typ, c.Key, "conditions"); err != nil {
				return l7ValidatedRule{}, err
			}
			if err := l7ValidateValueForType(typ, compareType, c.Value, "conditions"); err != nil {
				return l7ValidatedRule{}, err
			}
			if _, dup := seenValues[c.Value]; dup {
				return l7ValidatedRule{}, errInvalidInput("conditions")
			}
			seenValues[c.Value] = struct{}{}
			outConds = append(outConds, ruleCondition{Key: c.Key, Value: c.Value})
		}
		return l7ValidatedRule{
			Type:        typ,
			CompareType: compareType,
			Key:         "",
			Value:       "",
			Conditions:  outConds,
		}, nil
	}

	if err := l7ValidateKeyForType(typ, key, "key"); err != nil {
		return l7ValidatedRule{}, err
	}
	if err := l7ValidateValueForType(typ, compareType, value, "value"); err != nil {
		return l7ValidatedRule{}, err
	}
	return l7ValidatedRule{
		Type:        typ,
		CompareType: compareType,
		Key:         key,
		Value:       value,
	}, nil
}

func l7ValidateInlineRules(action string, rules []l7CreateRuleInput) ([]l7ValidatedRule, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	if action == l7ActionRedirectToListener {
		return nil, errInvalidInput("rules")
	}
	totalUnits := 0
	seenTypes := make(map[string]struct{}, len(rules))
	validated := make([]l7ValidatedRule, 0, len(rules))
	for _, r := range rules {
		vr, err := l7ValidateRuleSpec(r.Type, r.CompareType, r.Key, r.Value, r.Conditions, r.AdminStateUp)
		if err != nil {
			return nil, err
		}
		if _, dup := seenTypes[vr.Type]; dup {
			return nil, errConflict("Duplicate rule type in L7 policy.")
		}
		seenTypes[vr.Type] = struct{}{}
		if len(vr.Conditions) > 0 {
			totalUnits += len(vr.Conditions)
		} else {
			totalUnits++
		}
		if totalUnits > l7MaxRules {
			return nil, errInvalidInput("rules")
		}
		validated = append(validated, vr)
	}
	return validated, nil
}

// l7CreateRule creates a forwarding rule on policyID (§3.8).
func (s *Service) l7CreateRule(ctx context.Context, t Tenant, policyID string, in l7CreateRuleInput) (l7Rule, error) {
	vr, err := l7ValidateRuleSpec(in.Type, in.CompareType, in.Key, in.Value, in.Conditions, in.AdminStateUp)
	if err != nil {
		return l7Rule{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pol, err := s.l7Policies(t).Get(ctx, policyID)
	if errors.Is(err, store.ErrNotFound) {
		return l7Rule{}, errNotFound("l7policy", policyID)
	}
	if err != nil {
		return l7Rule{}, err
	}
	if pol.Action == l7ActionRedirectToListener {
		return l7Rule{}, errInvalidInput("l7policy_id")
	}

	existing, err := s.l7Rules(t).List(ctx, func(r l7Rule) bool { return r.PolicyID == policyID })
	if err != nil {
		return l7Rule{}, err
	}
	totalUnits := 0
	for _, r := range existing {
		if r.Type == vr.Type {
			return l7Rule{}, errConflict("A rule of this type already exists on the L7 policy.")
		}
		if len(r.Conditions) > 0 {
			totalUnits += len(r.Conditions)
		} else {
			totalUnits++
		}
	}
	addUnits := 1
	if len(vr.Conditions) > 0 {
		addUnits = len(vr.Conditions)
	}
	if totalUnits+addUnits > l7MaxRules {
		return l7Rule{}, errInvalidInput("rules")
	}

	now := s.nowUTC()
	rec := l7Rule{
		ID:           s.ids.UUID(),
		PolicyID:     policyID,
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
	if err := s.l7Rules(t).Create(ctx, rec.ID, rec); err != nil {
		return l7Rule{}, err
	}
	return rec, nil
}

// l7GetRule returns a single forwarding rule belonging to policyID (§3.8).
func (s *Service) l7GetRule(ctx context.Context, t Tenant, policyID, ruleID string) (l7Rule, error) {
	if _, err := s.l7Policies(t).Get(ctx, policyID); errors.Is(err, store.ErrNotFound) {
		return l7Rule{}, errNotFound("l7policy", policyID)
	} else if err != nil {
		return l7Rule{}, err
	}
	r, err := s.l7Rules(t).Get(ctx, ruleID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && r.PolicyID != policyID) {
		return l7Rule{}, errNotFound("l7rule", ruleID)
	}
	if err != nil {
		return l7Rule{}, err
	}
	return r, nil
}

// l7UpdateRule modifies mutable fields of an existing forwarding rule (§3.8).
func (s *Service) l7UpdateRule(ctx context.Context, t Tenant, policyID, ruleID string, in l7UpdateRuleInput) (l7Rule, error) {
	if in.AdminStateUp != nil && !*in.AdminStateUp {
		return l7Rule{}, errInvalidInput("admin_state_up")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.l7Policies(t).Get(ctx, policyID); errors.Is(err, store.ErrNotFound) {
		return l7Rule{}, errNotFound("l7policy", policyID)
	} else if err != nil {
		return l7Rule{}, err
	}
	cur, err := s.l7Rules(t).Get(ctx, ruleID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && cur.PolicyID != policyID) {
		return l7Rule{}, errNotFound("l7rule", ruleID)
	}
	if err != nil {
		return l7Rule{}, err
	}

	nextCompare := cur.CompareType
	if in.CompareType != nil {
		nextCompare = *in.CompareType
	}
	nextKey := cur.Key
	if in.Key != nil {
		nextKey = *in.Key
	}
	nextValue := cur.Value
	if in.Value != nil {
		nextValue = *in.Value
	}
	nextConds := cur.Conditions
	if in.Conditions.Set {
		if in.Conditions.Value == nil {
			nextConds = nil
		} else {
			nextConds = *in.Conditions.Value
		}
	}

	vr, err := l7ValidateRuleSpec(cur.Type, nextCompare, nextKey, nextValue, nextConds, in.AdminStateUp)
	if err != nil {
		return l7Rule{}, err
	}

	cur.CompareType = vr.CompareType
	cur.Key = vr.Key
	cur.Value = vr.Value
	cur.Conditions = l7CloneRuleConditions(vr.Conditions)
	cur.AdminStateUp = true
	cur.Invert = false
	cur.UpdatedAt = s.nowUTC()

	if err := s.l7Rules(t).Put(ctx, cur.ID, cur); err != nil {
		return l7Rule{}, err
	}
	return cur, nil
}

// l7DeleteRule deletes a forwarding rule belonging to policyID (§3.8).
func (s *Service) l7DeleteRule(ctx context.Context, t Tenant, policyID, ruleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.l7Policies(t).Get(ctx, policyID); errors.Is(err, store.ErrNotFound) {
		return errNotFound("l7policy", policyID)
	} else if err != nil {
		return err
	}
	r, err := s.l7Rules(t).Get(ctx, ruleID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && r.PolicyID != policyID) {
		return errNotFound("l7rule", ruleID)
	}
	if err != nil {
		return err
	}
	if err := s.l7Rules(t).Delete(ctx, ruleID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func l7MatchesRuleFilter(r l7Rule, ep string, f l7ListRulesFilter) bool {
	if !matchesAny(f.IDs, r.ID) ||
		!matchesAny(f.CompareTypes, r.CompareType) ||
		!matchesAny(f.ProvisioningStatuses, StatusActive) ||
		!matchesAny(f.Values, r.Value) ||
		!matchesAny(f.Keys, r.Key) ||
		!matchesAny(f.Types, r.Type) ||
		!matchesAny(f.L7PolicyIDs, r.PolicyID) ||
		!inEPList(f.EnterpriseProjectIDs, ep) {
		return false
	}
	if f.Invert != nil && r.Invert != *f.Invert {
		return false
	}
	if f.AdminStateUp != nil && r.AdminStateUp != *f.AdminStateUp {
		return false
	}
	return true
}

// l7ListRules lists rules of policyID in ascending ID order (§3.8).
func (s *Service) l7ListRules(ctx context.Context, t Tenant, policyID string, f l7ListRulesFilter) ([]l7Rule, pageInfo, error) {
	pol, err := s.l7Policies(t).Get(ctx, policyID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, pageInfo{}, errNotFound("l7policy", policyID)
	}
	if err != nil {
		return nil, pageInfo{}, err
	}
	ep := pol.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}

	all, err := s.l7Rules(t).List(ctx, func(r l7Rule) bool { return r.PolicyID == policyID })
	if err != nil {
		return nil, pageInfo{}, err
	}

	filtered := make([]l7Rule, 0, len(all))
	for _, r := range all {
		if l7MatchesRuleFilter(r, ep, f) {
			filtered = append(filtered, r)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].ID < filtered[j].ID })
	return l7Paginate(filtered, func(r l7Rule) string { return r.ID }, f.Page, f.PageReverse)
}

// l7ListAllRules lists all rules across the project in ascending ID order (§3.8).
func (s *Service) l7ListAllRules(ctx context.Context, t Tenant, f l7ListRulesFilter) ([]l7Rule, pageInfo, error) {
	allRules, err := s.l7Rules(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}
	allPolicies, err := s.l7Policies(t).List(ctx, nil)
	if err != nil {
		return nil, pageInfo{}, err
	}
	epByPolicy := make(map[string]string, len(allPolicies))
	for _, p := range allPolicies {
		ep := p.EnterpriseProjectID
		if ep == "" {
			ep = defaultEnterpriseProjectID
		}
		epByPolicy[p.ID] = ep
	}

	filtered := make([]l7Rule, 0, len(allRules))
	for _, r := range allRules {
		ep := epByPolicy[r.PolicyID]
		if ep == "" {
			ep = defaultEnterpriseProjectID
		}
		if l7MatchesRuleFilter(r, ep, f) {
			filtered = append(filtered, r)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].ID < filtered[j].ID })
	return l7Paginate(filtered, func(r l7Rule) string { return r.ID }, f.Page, f.PageReverse)
}
