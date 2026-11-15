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
	agencyID  string
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
	ctx = withAccount(ctx, acct)
	g, err := s.identityGrants(ctx, acct, pr, sc)
	if err != nil {
		return authz.Grants{}, err
	}
	if pr.Session != nil {
		// Not cached: the session's policies come with each request.
		ses, err := s.sessionSources(ctx, pr.Session, sc.Service)
		if err != nil {
			return authz.Grants{}, err
		}
		g.Session = ses
	}
	return g, nil
}

// identityGrants are what the principal's user or agency holds.
func (s *Service) identityGrants(ctx context.Context, acct identity.Account, pr identity.Principal, sc authz.Scope) (authz.Grants, error) {
	if !pr.Agency() && (pr.Admin || pr.UserID == acct.RootUserID()) {
		return authz.Grants{All: true}, nil
	}
	k := grantsKey{accountID: acct.ID, userID: pr.UserID, agencyID: pr.AgencyID, scope: sc}
	g, gen, ok := s.perms.get(k)
	if ok {
		return g, nil
	}
	var err error
	if pr.Agency() {
		g, err = s.agencyGrants(ctx, pr, sc)
	} else {
		g, err = s.computeGrants(ctx, pr.UserID, sc)
	}
	if err != nil {
		return authz.Grants{}, err
	}
	s.perms.put(k, g, gen)
	return g, nil
}

// agencyGrants are what an assumed agency holds: the classic roles
// granted to it and the identity policies attached to it.
func (s *Service) agencyGrants(ctx context.Context, pr identity.Principal, sc authz.Scope) (authz.Grants, error) {
	acct := s.account(ctx)
	if _, ok := s.liveAgency(ctx, pr.AgencyID); !ok {
		return authz.Grants{}, nil // deleted since the credentials were checked
	}
	keys := map[string][]string{"g:domainid": {acct.ID}, "g:domainname": {acct.Name}}
	projectID := s.scopeProjectID(ctx, acct, sc, keys)
	out := authz.Grants{Keys: keys}
	if err := s.subjectSources(ctx, &out, func(a assignment) bool {
		return a.Subject == subjectAgency && a.SubjectID == pr.AgencyID && applies(a, sc, projectID)
	}); err != nil {
		return authz.Grants{}, err
	}
	if err := s.attachedSources(ctx, &out, func(a policyAttachment) bool {
		return a.Subject == subjectAgency && a.SubjectID == pr.AgencyID
	}); err != nil {
		return authz.Grants{}, err
	}
	return out, nil
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
	projectID := s.scopeProjectID(ctx, acct, sc, keys)
	out := authz.Grants{Keys: keys}
	if err := s.subjectSources(ctx, &out, func(a assignment) bool {
		mine := a.Subject == subjectGroup && slices.Contains(groupIDs, a.SubjectID) ||
			a.Subject == subjectUser && a.SubjectID == userID
		return mine && applies(a, sc, projectID)
	}); err != nil {
		return authz.Grants{}, err
	}
	if err := s.attachedSources(ctx, &out, func(a policyAttachment) bool {
		return a.Subject == subjectUser && a.SubjectID == userID ||
			a.Subject == subjectGroup && slices.Contains(groupIDs, a.SubjectID)
	}); err != nil {
		return authz.Grants{}, err
	}
	return out, nil
}

// scopeProjectID is the project a request in sc is in, if any, whose ID
// and name it adds to keys.
func (s *Service) scopeProjectID(ctx context.Context, acct identity.Account, sc authz.Scope, keys map[string][]string) string {
	if sc.Global {
		return ""
	}
	projectID := sc.ProjectID
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
	return projectID
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

// subjectSources adds the classic roles of the grants that match.
func (s *Service) subjectSources(ctx context.Context, out *authz.Grants, match func(assignment) bool) error {
	as, err := s.assignmentsOf(ctx, match)
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

// attachedSources adds the identity policies of the attachments that
// match.
func (s *Service) attachedSources(ctx context.Context, out *authz.Grants, match func(policyAttachment) bool) error {
	atts, err := s.attachmentsWhere(ctx, match)
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
