package policy

import "strings"

// Request is an operation to authorize.
type Request struct {
	// Action is the operation's IAM 5.0 action, such as
	// "vpc:vpcs:create".
	Action string
	// Aliases are the operation's classic action names, which Huawei
	// lists in each service's action table: a classic statement matches
	// the action or any alias; a 5.0 statement matches the action only.
	Aliases []string
	// Resources are the URNs the operation acts on. Empty means it acts
	// on no particular resource, which only a Resource of * covers. When
	// there are several (a subnet is created in a VPC), each must be
	// allowed.
	Resources []string
	// Keys are the request's condition keys, lower case, with their
	// values. An absent key is one the request does not supply.
	Keys map[string][]string
	// URIs name the agency a request for iam:tokens:assume is for
	// (/iam/agencies/<id>, and its name in the same form), which classic
	// statements with a {"uri": [...]} Resource match: any one of them
	// matching is enough.
	URIs []string
	// Caller is who makes the request, for trust policies, whose
	// statements apply only to the principals they name.
	Caller *Caller
}

// Source is a policy a principal holds, under a name that identifies it
// in decisions.
type Source struct {
	Name   string
	Policy *Policy
}

// Decision is the outcome of an evaluation.
type Decision struct {
	Allowed bool
	// Explicit reports that a Deny statement decided; otherwise a denial
	// is implicit: no statement allowed the request.
	Explicit bool
	// Policy and Sid name the deciding Deny statement's source, or for
	// an allowed request the first Allow found.
	Policy, Sid string
}

// Failure describes a denial in the words of Huawei's documented
// decode-authorization-message example, or is empty when allowed.
func (d Decision) Failure() string {
	switch {
	case d.Allowed:
		return ""
	case d.Explicit:
		return "explicit deny by identity-based policy"
	}
	return "implicit deny by identity-based policy"
}

// Evaluate decides a request against the policies a principal holds: an
// applicable Deny anywhere denies; otherwise every resource of the
// request needs an applicable Allow; otherwise the request is denied.
func Evaluate(req Request, sources []Source) Decision {
	action := strings.ToLower(req.Action)
	aliases := make([]string, len(req.Aliases))
	for i, a := range req.Aliases {
		aliases[i] = strings.ToLower(a)
	}
	uris := make([]string, len(req.URIs))
	for i, u := range req.URIs {
		uris[i] = strings.ToLower(u)
	}
	resources := make([]*urn, 0, max(1, len(req.Resources)))
	for _, r := range req.Resources {
		if u, ok := splitURN(r); ok {
			resources = append(resources, &u)
		}
	}
	if len(resources) == 0 {
		resources = append(resources, nil)
	}

	var allowedBy Decision
	allowed := make([]bool, len(resources))
	for _, src := range sources {
		if src.Policy == nil {
			continue
		}
		classic := src.Policy.classic()
		for i := range src.Policy.statements {
			st := &src.Policy.statements[i]
			if !st.matchesAction(action, aliases, classic) || !st.matchesCaller(req.Caller) || !st.conditionsHold(req.Keys) {
				continue
			}
			for j, r := range resources {
				if !st.matchesResource(r, uris, req.Keys) {
					continue
				}
				if st.deny {
					return Decision{Explicit: true, Policy: src.Name, Sid: st.sid}
				}
				if !allowed[j] && allowedBy.Policy == "" {
					allowedBy = Decision{Policy: src.Name, Sid: st.sid}
				}
				allowed[j] = true
			}
		}
	}
	for _, ok := range allowed {
		if !ok {
			return Decision{}
		}
	}
	allowedBy.Allowed = true
	return allowedBy
}

func (st *statement) matchesAction(action string, aliases []string, classic bool) bool {
	m := false
	for _, p := range st.actions {
		if glob(p, action) {
			m = true
			break
		}
		if classic {
			for _, a := range aliases {
				if glob(p, a) {
					m = true
					break
				}
			}
			if m {
				break
			}
		}
	}
	return m != st.notAct
}

func (st *statement) matchesResource(r *urn, uris []string, keys map[string][]string) bool {
	if st.anyRes {
		return true
	}
	if st.uris != nil {
		for _, p := range st.uris {
			for _, u := range uris {
				if glob(p, u) {
					return true
				}
			}
		}
		return false
	}
	m := false
	for _, p := range st.res {
		if st.vars {
			// A variable that cannot be substituted makes the statement
			// inapplicable, whichever its effect.
			s, ok := substitute(p.raw, keys)
			if !ok {
				return false
			}
			if p, ok = parseResourcePattern(s); !ok {
				return false
			}
		}
		if p.matches(r) {
			m = true
			break
		}
	}
	return m != st.notRes
}

func (st *statement) conditionsHold(keys map[string][]string) bool {
	for _, c := range st.conds {
		if !c.eval(keys) {
			return false
		}
	}
	return true
}
