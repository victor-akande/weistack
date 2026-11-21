package elb

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

type secpolCreateInput struct {
	Name                string
	Description         string
	Protocols           []string
	Ciphers             []string
	EnterpriseProjectID *string
}

type secpolUpdateInput struct {
	Name        *string
	Description *string
	Protocols   *[]string
	Ciphers     *[]string
}

type secpolListFilter struct {
	IDs                  []string
	Names                []string
	Descriptions         []string
	Protocols            []string
	Ciphers              []string
	EnterpriseProjectIDs []string
	Page                 pagination.Marker
}

type secpolDetail struct {
	Policy      securityPolicy
	ListenerIDs []string
}

func secpolValidProtocol(p string) bool {
	switch p {
	case "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3":
		return true
	default:
		return false
	}
}

func secpolValidateProtocols(protocols []string) ([]string, error) {
	if len(protocols) == 0 {
		return nil, errInvalidInput("protocols")
	}
	out := make([]string, 0, len(protocols))
	seen := make(map[string]struct{}, len(protocols))
	for _, p := range protocols {
		if !secpolValidProtocol(p) {
			return nil, errInvalidInput("protocols")
		}
		if _, dup := seen[p]; dup {
			return nil, errInvalidInput("protocols")
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out, nil
}

func secpolValidateCiphers(ciphers []string) ([]string, error) {
	if len(ciphers) == 0 {
		return nil, errInvalidInput("ciphers")
	}
	allowed := allowedSecurityPolicyCiphers()
	out := make([]string, 0, len(ciphers))
	seen := make(map[string]struct{}, len(ciphers))
	for _, c := range ciphers {
		if _, ok := allowed[c]; !ok {
			return nil, errInvalidInput("ciphers")
		}
		if _, dup := seen[c]; dup {
			return nil, errInvalidInput("ciphers")
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out, nil
}

func secpolListenersForPolicy(listeners []listener, spID string) []string {
	var out []string
	for _, l := range listeners {
		if l.SecurityPolicyID == spID {
			out = append(out, l.ID)
		}
	}
	slices.Sort(out)
	return out
}

func secpolListenersByPolicy(listeners []listener) map[string][]string {
	byPolicy := make(map[string][]string)
	for _, l := range listeners {
		if l.SecurityPolicyID == "" {
			continue
		}
		byPolicy[l.SecurityPolicyID] = append(byPolicy[l.SecurityPolicyID], l.ID)
	}
	for id := range byPolicy {
		slices.Sort(byPolicy[id])
	}
	return byPolicy
}

// secpolMatchesProtocols checks whether any requested protocol filter value
// matches have. Each filter value may be a single protocol ("TLSv1.2") or a
// space-separated list ("TLSv1.2 TLSv1.3"), per ListSecurityPolicies.txt.
func secpolMatchesProtocols(wants, have []string) bool {
	if len(wants) == 0 {
		return true
	}
	for _, w := range wants {
		tokens := strings.Fields(w)
		if len(tokens) == 0 {
			continue
		}
		allPresent := true
		for _, tok := range tokens {
			if !slices.Contains(have, tok) {
				allPresent = false
				break
			}
		}
		if allPresent {
			return true
		}
	}
	return false
}

// secpolMatchesCiphers checks whether any requested cipher filter value
// matches have. Each filter value may be a single cipher or a colon-separated
// list ("AES128-SHA:AES256-SHA"), per ListSecurityPolicies.txt.
func secpolMatchesCiphers(wants, have []string) bool {
	if len(wants) == 0 {
		return true
	}
	for _, w := range wants {
		tokens := strings.Split(w, ":")
		allPresent := true
		for _, tok := range tokens {
			if tok == "" || !slices.Contains(have, tok) {
				allPresent = false
				break
			}
		}
		if allPresent {
			return true
		}
	}
	return false
}

func (s *Service) createSecurityPolicy(ctx context.Context, t Tenant, in secpolCreateInput) (secpolDetail, error) {
	if !validName(in.Name) {
		return secpolDetail{}, errInvalidInput("name")
	}
	if !validDescription(in.Description) {
		return secpolDetail{}, errInvalidInput("description")
	}
	protocols, err := secpolValidateProtocols(in.Protocols)
	if err != nil {
		return secpolDetail{}, err
	}
	ciphers, err := secpolValidateCiphers(in.Ciphers)
	if err != nil {
		return secpolDetail{}, err
	}
	ep := defaultEnterpriseProjectID
	if in.EnterpriseProjectID != nil {
		if !validEnterpriseProjectID(*in.EnterpriseProjectID) {
			return secpolDetail{}, errInvalidInput("enterprise_project_id")
		}
		ep = *in.EnterpriseProjectID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowUTC()
	rec := securityPolicy{
		ID:                  s.ids.UUID(),
		Name:                in.Name,
		Description:         in.Description,
		Protocols:           protocols,
		Ciphers:             ciphers,
		EnterpriseProjectID: ep,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.securityPolicies(t).Create(ctx, rec.ID, rec); err != nil {
		return secpolDetail{}, err
	}
	return secpolDetail{Policy: rec}, nil
}

func (s *Service) getSecurityPolicy(ctx context.Context, t Tenant, id string) (secpolDetail, error) {
	rec, err := s.securityPolicies(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return secpolDetail{}, errNotFound("security_policy", id)
	}
	if err != nil {
		return secpolDetail{}, err
	}
	listeners, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return secpolDetail{}, err
	}
	return secpolDetail{
		Policy:      rec,
		ListenerIDs: secpolListenersForPolicy(listeners, rec.ID),
	}, nil
}

func (s *Service) listSecurityPolicies(ctx context.Context, t Tenant, f secpolListFilter) ([]secpolDetail, pageInfo, error) {
	items, err := s.securityPolicies(t).List(ctx, func(sp securityPolicy) bool {
		if !matchesAny(f.IDs, sp.ID) {
			return false
		}
		if !matchesAny(f.Names, sp.Name) {
			return false
		}
		if !matchesAny(f.Descriptions, sp.Description) {
			return false
		}
		if !secpolMatchesProtocols(f.Protocols, sp.Protocols) {
			return false
		}
		if !secpolMatchesCiphers(f.Ciphers, sp.Ciphers) {
			return false
		}
		ep := sp.EnterpriseProjectID
		if ep == "" {
			ep = defaultEnterpriseProjectID
		}
		if !inEPList(f.EnterpriseProjectIDs, ep) {
			return false
		}
		return true
	})
	if err != nil {
		return nil, pageInfo{}, err
	}

	slices.SortFunc(items, func(a, b securityPolicy) int {
		return strings.Compare(a.ID, b.ID)
	})
	paged, pi, err := paginateSlice(items, func(sp securityPolicy) string { return sp.ID }, f.Page)
	if err != nil {
		return nil, pageInfo{}, err
	}

	var byPolicy map[string][]string
	if len(paged) > 0 {
		listeners, err := s.listeners(t).List(ctx, nil)
		if err != nil {
			return nil, pageInfo{}, err
		}
		byPolicy = secpolListenersByPolicy(listeners)
	}

	out := make([]secpolDetail, len(paged))
	for i, sp := range paged {
		out[i] = secpolDetail{
			Policy:      sp,
			ListenerIDs: byPolicy[sp.ID],
		}
	}
	return out, pi, nil
}

func (s *Service) updateSecurityPolicy(ctx context.Context, t Tenant, id string, in secpolUpdateInput) (secpolDetail, error) {
	if in.Name != nil && !validName(*in.Name) {
		return secpolDetail{}, errInvalidInput("name")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return secpolDetail{}, errInvalidInput("description")
	}
	var validatedProtocols []string
	if in.Protocols != nil {
		var err error
		validatedProtocols, err = secpolValidateProtocols(*in.Protocols)
		if err != nil {
			return secpolDetail{}, err
		}
	}
	var validatedCiphers []string
	if in.Ciphers != nil {
		var err error
		validatedCiphers, err = secpolValidateCiphers(*in.Ciphers)
		if err != nil {
			return secpolDetail{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	updated, err := s.securityPolicies(t).Update(ctx, id, func(sp *securityPolicy) error {
		if in.Name != nil {
			sp.Name = *in.Name
		}
		if in.Description != nil {
			sp.Description = *in.Description
		}
		if in.Protocols != nil {
			sp.Protocols = validatedProtocols
		}
		if in.Ciphers != nil {
			sp.Ciphers = validatedCiphers
		}
		sp.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return secpolDetail{}, errNotFound("security_policy", id)
	}
	if err != nil {
		return secpolDetail{}, err
	}

	listeners, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return secpolDetail{}, err
	}
	return secpolDetail{
		Policy:      updated,
		ListenerIDs: secpolListenersForPolicy(listeners, updated.ID),
	}, nil
}

func (s *Service) deleteSecurityPolicy(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.securityPolicies(t).Get(ctx, id); errors.Is(err, store.ErrNotFound) {
		return errNotFound("security_policy", id)
	} else if err != nil {
		return err
	}

	listeners, err := s.listeners(t).List(ctx, func(l listener) bool {
		return l.SecurityPolicyID == id
	})
	if err != nil {
		return err
	}
	if len(listeners) > 0 {
		return errConflict("The security policy is in use by one or more listeners.")
	}

	if err := s.securityPolicies(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
