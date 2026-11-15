package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Trust policies: the IAM 5.0 documents an agency (a "trust agency")
// holds to say who may assume it (usermanual-iam5 iam_01_1289, "JSON
// Element Reference": Principal and NotPrincipal). Their statements are
// identity statements that also name principals:
//
//	{"Version": "5.0", "Statement": [{"Effect": "Allow",
//	  "Action": ["sts:agencies:assume"],
//	  "Principal": {"IAM": ["<account-id>"]}}]}
//
// A principal is an account (its ID, or "*" for any), a user or agency
// URN of one (iam::<account-id>:user:<name>), a cloud service
// ("Service": ["service.OBS"]), or an identity provider. A statement
// applies to a request only if its principal matches the request's
// caller.

// Principal kinds, the keys of a Principal element.
const (
	PrincipalIAM      = "IAM"
	PrincipalService  = "Service"
	PrincipalProvider = "Identity_provider"
)

// Caller is who makes a request that a trust policy is evaluated for.
type Caller struct {
	// AccountID and URN name an IAM caller: its account, and its own
	// URN (iam::<account-id>:user:<name>, or an assumed agency's).
	AccountID, URN string
	// Service names a calling cloud service, such as "service.OBS".
	Service string
}

// principals is a parsed Principal or NotPrincipal element.
type principals map[string][]string // kind -> patterns

// ParseTrust parses a trust policy: an IAM 5.0 document whose every
// statement names a Principal or a NotPrincipal.
func ParseTrust(doc []byte) (*Policy, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil || top == nil {
		return nil, errorf(ErrJSON, "the document is not a JSON object")
	}
	var version string
	if err := json.Unmarshal(top["Version"], &version); err != nil || version != Version5 {
		return nil, errorf(ErrVersion, "a trust policy's Version must be %q", Version5)
	}
	for k := range top {
		if k != "Version" && k != "Statement" {
			return nil, errorf(ErrElement, "element %q is not allowed in a trust policy", k)
		}
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(top["Statement"], &raw); err != nil || len(raw) == 0 {
		return nil, errorf(ErrStatement, "Statement must be a non-empty list")
	}
	p := &Policy{version: Version5, trust: true, statements: make([]statement, 0, len(raw))}
	for i, r := range raw {
		var el map[string]json.RawMessage
		if err := json.Unmarshal(r, &el); err != nil || el == nil {
			return nil, errorf(ErrStatement, "statement %d: a statement must be an object", i)
		}
		prin, not, err := parsePrincipals(el)
		if err != nil {
			err.Detail = fmt.Sprintf("statement %d: %s", i, err.Detail)
			return nil, err
		}
		delete(el, "Principal")
		delete(el, "NotPrincipal")
		rest, _ := json.Marshal(el)
		st, err := parseStatement(Version5, rest)
		if err != nil {
			err.Detail = fmt.Sprintf("statement %d: %s", i, err.Detail)
			return nil, err
		}
		st.principals, st.notPrin = prin, not
		p.statements = append(p.statements, st)
	}
	return p, nil
}

func parsePrincipals(el map[string]json.RawMessage) (principals, bool, *Error) {
	rawP, okP := el["Principal"]
	rawN, okN := el["NotPrincipal"]
	switch {
	case okP && okN:
		return nil, false, errorf(ErrElement, "Principal and NotPrincipal cannot both be set")
	case !okP && !okN:
		return nil, false, errorf(ErrElement, "a trust policy statement needs a Principal or a NotPrincipal")
	}
	raw, not := rawP, false
	if okN {
		raw, not = rawN, true
	}
	var byKind map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byKind); err != nil || len(byKind) == 0 {
		return nil, false, errorf(ErrElement, "a principal must be an object of IAM, Service or Identity_provider")
	}
	out := principals{}
	for kind, v := range byKind {
		switch kind {
		case PrincipalIAM, PrincipalService, PrincipalProvider:
		default:
			return nil, false, errorf(ErrElement, "unknown principal kind %q", kind)
		}
		list, _, err := stringListElement(map[string]json.RawMessage{kind: v}, kind, "", true)
		if err != nil {
			return nil, false, errorf(ErrElement, "%s", err)
		}
		out[kind] = list
	}
	return out, not, nil
}

// matchesCaller reports whether a trust statement applies to c. Every
// statement of an identity policy applies.
func (st *statement) matchesCaller(c *Caller) bool {
	if st.principals == nil {
		return true
	}
	if c == nil {
		return false
	}
	m := false
	for kind, list := range st.principals {
		for _, p := range list {
			if principalMatches(kind, p, c) {
				m = true
			}
		}
	}
	return m != st.notPrin
}

func principalMatches(kind, pattern string, c *Caller) bool {
	switch kind {
	case PrincipalIAM:
		if c.AccountID == "" {
			return false
		}
		if pattern == "*" || pattern == c.AccountID {
			return true
		}
		return strings.Contains(pattern, ":") && c.URN != "" && glob(strings.ToLower(pattern), strings.ToLower(c.URN))
	case PrincipalService:
		return c.Service != "" && (pattern == "*" || strings.EqualFold(pattern, c.Service))
	}
	return false // identity providers: federation is not emulated
}

// TrustedAccounts returns the account IDs a trust policy's Allow
// statements name as IAM principals, sorted: the agency's delegated
// accounts, which IAM shows as trust_domain_id.
func (p *Policy) TrustedAccounts() []string {
	seen := map[string]bool{}
	for _, st := range p.statements {
		if st.deny || st.notPrin {
			continue
		}
		for _, v := range st.principals[PrincipalIAM] {
			if v != "*" && !strings.Contains(v, ":") {
				seen[v] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
