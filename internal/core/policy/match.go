package policy

import (
	"strings"
	"unicode/utf8"
)

// glob reports whether s matches pattern, in which * matches any run of
// characters (none included) and ? exactly one. It runs in O(len(s) *
// len(pattern)) at worst, with no allocation.
func glob(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == s
	}
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		if p < len(pattern) {
			switch c := pattern[p]; c {
			case '*':
				star, mark = p, i
				p++
				continue
			case '?':
				_, n := utf8.DecodeRuneInString(s[i:])
				p, i = p+1, i+n
				continue
			default:
				if c == s[i] {
					p, i = p+1, i+1
					continue
				}
			}
		}
		if star < 0 {
			return false
		}
		// Let the last * swallow one more character and retry.
		_, n := utf8.DecodeRuneInString(s[mark:])
		mark += n
		p, i = star+1, mark
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// urn is a resource name split into its five parts,
// service:region:account:type:path. Service and type are lower case:
// Huawei documents them as case-insensitive.
type urn struct {
	service, region, account, typ, path string
}

// splitURN splits a resource name; ok is false if it has fewer than five
// parts. The path may itself contain colons.
func splitURN(s string) (u urn, ok bool) {
	parts := strings.SplitN(s, ":", 5)
	if len(parts) != 5 {
		return urn{}, false
	}
	return urn{
		service: strings.ToLower(parts[0]), region: parts[1], account: parts[2],
		typ: strings.ToLower(parts[3]), path: parts[4],
	}, true
}

// resourcePattern is a Resource element entry: * or a URN with
// wildcards. raw keeps the entry as written, for variable substitution.
type resourcePattern struct {
	raw string
	any bool
	u   urn
}

func parseResourcePattern(s string) (resourcePattern, bool) {
	if s == "*" {
		return resourcePattern{raw: s, any: true}, true
	}
	u, ok := splitURN(s)
	if !ok || u.service == "" {
		return resourcePattern{}, false
	}
	return resourcePattern{raw: s, u: u}, true
}

// matches reports whether the pattern covers the resource r. A nil r is
// a request on no particular resource, which only * covers, as Huawei
// documents for actions without a resource type.
func (p resourcePattern) matches(r *urn) bool {
	if p.any {
		return true
	}
	if r == nil {
		return false
	}
	return glob(p.u.service, r.service) && glob(p.u.region, r.region) &&
		glob(p.u.account, r.account) && glob(p.u.typ, r.typ) && glob(p.u.path, r.path)
}

func hasVariables(ps []resourcePattern) bool {
	for _, p := range ps {
		if strings.Contains(p.raw, "${") {
			return true
		}
	}
	return false
}

// substitute replaces IAM 5.0 policy variables in s with request values:
// ${key}, or ${key, 'default'} when the key is absent. ${*}, ${?} and
// ${$} stand for the characters themselves. A variable whose key is
// absent with no default, or has several values, cannot be substituted:
// ok is false and the statement does not apply.
func substitute(s string, keys map[string][]string) (out string, ok bool) {
	if !strings.Contains(s, "${") {
		return s, true
	}
	var b strings.Builder
	for {
		start := strings.Index(s, "${")
		if start < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		end := strings.IndexByte(s[start:], '}')
		if end < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		b.WriteString(s[:start])
		body := s[start+2 : start+end]
		s = s[start+end+1:]
		switch body {
		case "*", "?", "$":
			b.WriteString(body)
			continue
		}
		key, def, hasDef := strings.Cut(body, ",")
		vals := keys[strings.ToLower(strings.TrimSpace(key))]
		switch {
		case len(vals) == 1:
			b.WriteString(vals[0])
		case len(vals) == 0 && hasDef:
			d, ok := quoted(strings.TrimSpace(def))
			if !ok {
				return "", false
			}
			b.WriteString(d)
		default:
			return "", false
		}
	}
}

// quoted reads a single-quoted default value, in which ” is a quote.
func quoted(s string) (string, bool) {
	if len(s) < 2 || s[0] != '\'' || s[len(s)-1] != '\'' {
		return "", false
	}
	return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), true
}
