package iam

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/store"
)

// What a principal may do: IAM implements authz.Provider with the roles
// and policies granted to a user's groups (classic) and attached to the
// user and its groups (IAM 5.0).
//
// Classic grants apply by scope, as Huawei describes for the console's
// "Global services", "Region-specific projects" and "All resources"
// choices: a domain grant covers global services (OBS, IAM, EPS, STS), a
// project grant that project, and an all-projects grant every project.
// A grant in the default enterprise project, the only one WeiStack has,
// covers every service that supports enterprise projects, which is every
// emulated one but IAM. IAM 5.0 policies apply everywhere.
//
// Grants are cached per user and scope; any change made through IAM
// invalidates the cache.

// permissions caches computed grants and parsed documents.
type permissions struct {
	// gen counts changes made through IAM; a cached entry of an older
	// generation is stale.
	gen atomic.Uint64

	mu     sync.Mutex
	cached map[grantsKey]authz.Grants
	at     uint64 // the generation of cached

	// parsed holds documents by a key that changes with their content.
	parsed sync.Map // string -> *policydoc.Policy
}

type grantsKey struct {
	accountID string
	userID    string
	scope     authz.Scope
}

// maxCachedGrants bounds the cache; it is cleared when full.
const maxCachedGrants = 4096

// changed records a change that may affect permissions.
func (p *permissions) changed() { p.gen.Add(1) }

func (p *permissions) get(k grantsKey) (authz.Grants, uint64, bool) {
	gen := p.gen.Load()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.at != gen {
		return authz.Grants{}, gen, false
	}
	g, ok := p.cached[k]
	return g, gen, ok
}

func (p *permissions) put(k grantsKey, g authz.Grants, gen uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case gen < p.at:
		return // computed before a change the cache already reflects
	case gen > p.at || p.cached == nil || len(p.cached) >= maxCachedGrants:
		p.cached, p.at = make(map[grantsKey]authz.Grants), gen
	}
	p.cached[k] = g
}

// parse returns the parsed document under key, parsing it once.
func (p *permissions) parse(key string, doc []byte) (*policydoc.Policy, error) {
	if v, ok := p.parsed.Load(key); ok {
		return v.(*policydoc.Policy), nil
	}
	pol, err := policydoc.Parse(doc)
	if err != nil {
		return nil, err
	}
	p.parsed.Store(key, pol)
	return pol, nil
}

// Grants implements authz.Provider.
func (s *Service) Grants(ctx context.Context, pr identity.Principal, sc authz.Scope) (authz.Grants, error) {
	acct, ok := s.dir.AccountByID(pr.AccountID)
	if !ok {
		return authz.Grants{}, nil // an account removed since the key was checked
	}
	if pr.Admin || pr.UserID == acct.RootUserID() {
		return authz.Grants{All: true}, nil
	}
	ctx = withAccount(ctx, acct)
	k := grantsKey{accountID: acct.ID, userID: pr.UserID, scope: sc}
	g, gen, ok := s.perms.get(k)
	if ok {
		return g, nil
	}
	g, err := s.computeGrants(ctx, pr.UserID, sc)
	if err != nil {
		return authz.Grants{}, err
	}
	s.perms.put(k, g, gen)
	return g, nil
}

func (s *Service) computeGrants(ctx context.Context, userID string, sc authz.Scope) (authz.Grants, error) {
	acct := s.account(ctx)
	u, err := s.users(ctx).Get(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return authz.Grants{}, nil // a user deleted since its key was checked
	}
	if err != nil {
		return authz.Grants{}, err
	}
	gs, err := s.groupsOf(ctx, userID)
	if err != nil {
		return authz.Grants{}, err
	}
	groupIDs := make([]string, 0, len(gs))
	for _, g := range gs {
		if g.ID == s.adminGroupID(ctx) {
			return authz.Grants{All: true}, nil
		}
		groupIDs = append(groupIDs, g.ID)
	}

	keys := map[string][]string{
		"g:userid": {u.ID}, "g:username": {u.Name}, "g:domainid": {acct.ID}, "g:domainname": {acct.Name},
	}
	projectID := ""
	if !sc.Global {
		projectID = sc.ProjectID
		if projectID == "" {
			region := sc.Region
			if region == "" {
				region = s.defaultRegion
			}
			projectID = s.projectID(acct, region)
		}
		keys["g:projectid"] = []string{projectID}
		if p, err := s.projects(ctx).Get(ctx, projectID); err == nil {
			keys["g:projectname"] = []string{p.Name}
		}
	}

	out := authz.Grants{Keys: keys}
	if err := s.classicSources(ctx, &out, userID, groupIDs, sc, projectID); err != nil {
		return authz.Grants{}, err
	}
	if err := s.v5Sources(ctx, &out, userID, groupIDs); err != nil {
		return authz.Grants{}, err
	}
	return out, nil
}

// applies reports whether a classic grant covers a request in sc.
func applies(a assignment, sc authz.Scope, projectID string) bool {
	switch a.Scope {
	case scopeDomain:
		return sc.Global
	case scopeProject:
		return !sc.Global && a.ScopeID == projectID
	case scopeInherited:
		return !sc.Global
	case scopeEP:
		return a.ScopeID == defaultEP && sc.Service != "iam"
	}
	return false
}

func (s *Service) classicSources(ctx context.Context, out *authz.Grants, userID string, groupIDs []string, sc authz.Scope, projectID string) error {
	as, err := s.assignmentsOf(ctx, func(a assignment) bool {
		mine := a.Subject == subjectGroup && slices.Contains(groupIDs, a.SubjectID) ||
			a.Subject == subjectUser && a.SubjectID == userID
		return mine && applies(a, sc, projectID)
	})
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(as))
	for _, a := range as {
		if seen[a.RoleID] {
			continue
		}
		seen[a.RoleID] = true
		ro, ok, err := s.findRole(ctx, a.RoleID)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		key := "role:" + ro.ID + ":" + strconv.FormatInt(ro.Updated.UnixNano(), 10)
		pol, err := s.perms.parse(key, ro.Policy)
		if err != nil {
			s.log.WarnContext(ctx, "ignoring a custom policy that cannot be evaluated", "role", ro.ID, "error", err)
			continue
		}
		out.Sources = append(out.Sources, policydoc.Source{Name: ro.DisplayName, Policy: pol})
	}
	return nil
}

func (s *Service) v5Sources(ctx context.Context, out *authz.Grants, userID string, groupIDs []string) error {
	atts, err := s.attachmentsWhere(ctx, func(a policyAttachment) bool {
		return a.Subject == subjectUser && a.SubjectID == userID ||
			a.Subject == subjectGroup && slices.Contains(groupIDs, a.SubjectID)
	})
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(atts))
	for _, a := range atts {
		if seen[a.PolicyID] {
			continue
		}
		seen[a.PolicyID] = true
		p, err := s.policies(ctx).Get(ctx, a.PolicyID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		v := p.defaultVersion()
		pol, err := s.perms.parse("v5:"+p.ID+":"+v.ID, []byte(v.Document))
		if err != nil {
			s.log.WarnContext(ctx, "ignoring an identity policy that cannot be evaluated", "policy", p.ID, "error", err)
			continue
		}
		out.Sources = append(out.Sources, policydoc.Source{Name: p.Name, Policy: pol})
	}
	return nil
}
