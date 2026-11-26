package iam

import (
	"context"
	"fmt"

	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: IAM users, groups, classic
// custom policies, IAM 5.0 policies and agencies, across every account.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	err := inventory.Each(ctx, s.store, kindUser, func(sc store.Scope, u user) error {
		return emit(inventory.Resource{
			Type:      inventory.IAMUsers,
			ID:        u.ID,
			Name:      u.Name,
			AccountID: s.scopeAccount(sc),
			Created:   u.CreatedAt,
			Updated:   u.UpdatedAt,
		})
	})
	if err != nil {
		return err
	}
	err = inventory.Each(ctx, s.store, kindGroup, func(sc store.Scope, g group) error {
		var rels []inventory.Ref
		if len(g.Members) > 0 {
			rels = make([]inventory.Ref, len(g.Members))
			for i, uid := range g.Members {
				rels[i] = inventory.Ref{
					Relation: inventory.Contains,
					Type:     inventory.IAMUsers,
					ID:       uid,
				}
			}
		}
		return emit(inventory.Resource{
			Type:      inventory.IAMGroups,
			ID:        g.ID,
			Name:      g.Name,
			AccountID: s.scopeAccount(sc),
			Created:   g.CreatedAt,
			Relations: rels,
		})
	})
	if err != nil {
		return err
	}
	roleRefs := make(map[store.Scope]map[string][]inventory.Ref)
	err = inventory.Each(ctx, s.store, kindRole, func(sc store.Scope, c customRole) error {
		byRole, ok := roleRefs[sc]
		if !ok {
			var loadErr error
			byRole, loadErr = s.roleRelations(ctx, sc)
			if loadErr != nil {
				return loadErr
			}
			roleRefs[sc] = byRole
		}
		return emit(inventory.Resource{
			Type:      inventory.IAMRoles,
			ID:        c.ID,
			Name:      c.Name,
			AccountID: s.scopeAccount(sc),
			Created:   c.CreatedAt,
			Updated:   c.UpdatedAt,
			Relations: byRole[c.ID],
		})
	})
	if err != nil {
		return err
	}
	policyRefs := make(map[store.Scope]map[string][]inventory.Ref)
	err = inventory.Each(ctx, s.store, kindPolicy, func(sc store.Scope, p policy) error {
		byPolicy, ok := policyRefs[sc]
		if !ok {
			var loadErr error
			byPolicy, loadErr = s.policyRelations(ctx, sc)
			if loadErr != nil {
				return loadErr
			}
			policyRefs[sc] = byPolicy
		}
		return emit(inventory.Resource{
			Type:      inventory.IAMPolicies,
			ID:        p.ID,
			Name:      p.Name,
			AccountID: s.scopeAccount(sc),
			Created:   p.CreatedAt,
			Updated:   p.UpdatedAt,
			Relations: byPolicy[p.ID],
		})
	})
	if err != nil {
		return err
	}
	return inventory.Each(ctx, s.store, kindAgency, func(sc store.Scope, a agency) error {
		return emit(inventory.Resource{
			Type:      inventory.IAMAgencies,
			ID:        a.ID,
			Name:      a.Name,
			AccountID: s.scopeAccount(sc),
			Created:   a.CreatedAt,
		})
	})
}

func (s *Service) scopeAccount(sc store.Scope) string {
	if sc.ProjectID == store.Global {
		return s.dir.Account().ID
	}
	return sc.ProjectID
}

func (s *Service) roleRelations(ctx context.Context, sc store.Scope) (map[string][]inventory.Ref, error) {
	assignScope := store.Scope{Region: sc.Region, ProjectID: sc.ProjectID, Kind: kindAssignment}
	as, err := store.Of[assignment](s.store, assignScope).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	byRole := make(map[string][]inventory.Ref)
	for _, a := range as {
		typ, err := subjectResourceType(a.Subject)
		if err != nil {
			return nil, err
		}
		byRole[a.RoleID] = append(byRole[a.RoleID], inventory.Ref{
			Relation: inventory.IsAssociatedWith,
			Type:     typ,
			ID:       a.SubjectID,
		})
	}
	return byRole, nil
}

func (s *Service) policyRelations(ctx context.Context, sc store.Scope) (map[string][]inventory.Ref, error) {
	attachScope := store.Scope{Region: sc.Region, ProjectID: sc.ProjectID, Kind: kindPolicyAttach}
	atts, err := store.Of[policyAttachment](s.store, attachScope).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	byPolicy := make(map[string][]inventory.Ref)
	for _, a := range atts {
		typ, err := subjectResourceType(a.Subject)
		if err != nil {
			return nil, err
		}
		byPolicy[a.PolicyID] = append(byPolicy[a.PolicyID], inventory.Ref{
			Relation: inventory.IsAssociatedWith,
			Type:     typ,
			ID:       a.SubjectID,
		})
	}
	return byPolicy, nil
}

func subjectResourceType(subject string) (inventory.Type, error) {
	switch subject {
	case subjectUser:
		return inventory.IAMUsers, nil
	case subjectGroup:
		return inventory.IAMGroups, nil
	case subjectAgency:
		return inventory.IAMAgencies, nil
	default:
		return inventory.Type{}, fmt.Errorf("iam: unknown subject %q", subject)
	}
}
