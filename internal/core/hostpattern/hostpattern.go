// Package hostpattern matches host names against simple patterns, for
// the hosts the proxy leaves alone.
//
// A pattern is a host name in which:
//
//   - "*" stands for exactly one DNS label, for example a region in
//     "apiexplorer.*.myhuaweicloud.com";
//   - "{region}" stands for one label too, and every "{region}" in a
//     pattern must be the same label: "{region}-hwcloudcli.obs.{region}.
//     myhuaweicloud.com" matches the host of one region's bucket, but not
//     a bucket that merely ends in "-hwcloudcli".
//
// Matching ignores case and a trailing dot.
package hostpattern

import (
	"fmt"
	"regexp"
	"strings"
)

const label = `[a-z0-9]([a-z0-9-]*[a-z0-9])?`

// Pattern is a compiled host pattern.
type Pattern struct {
	source string
	re     *regexp.Regexp
	// regions are the submatch indexes of the {region} placeholders.
	regions []int
}

var validRE = regexp.MustCompile(`^([a-z0-9-]+|\*|\{region\})(\.([a-z0-9-]+|\*|\{region\}))*$`)

// Compile parses a pattern.
func Compile(pattern string) (*Pattern, error) {
	p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	// "{region}" may share a label with literal text, as in
	// "{region}-hwcloudcli", so validate with it replaced.
	if !validRE.MatchString(strings.ReplaceAll(p, "{region}", "x")) || strings.Count(p, "{") != strings.Count(p, "{region}") {
		return nil, fmt.Errorf("host pattern %q: use letters, digits, hyphens, dots, * for one label and {region}", pattern)
	}
	var b strings.Builder
	b.WriteString("^")
	var regions []int
	group := 0
	for rest := p; rest != ""; {
		switch {
		case strings.HasPrefix(rest, "{region}"):
			group++
			// Each label pattern below opens one group of its own.
			regions = append(regions, group)
			b.WriteString("(" + label + ")")
			group++
			rest = rest[len("{region}"):]
		case rest[0] == '*':
			b.WriteString(label)
			group++
			rest = rest[1:]
		default:
			b.WriteString(regexp.QuoteMeta(rest[:1]))
			rest = rest[1:]
		}
	}
	b.WriteString("$")
	return &Pattern{source: p, re: regexp.MustCompile(b.String()), regions: regions}, nil
}

// Match reports whether host matches the pattern.
func (p *Pattern) Match(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	m := p.re.FindStringSubmatch(host)
	if m == nil {
		return false
	}
	for _, i := range p.regions[min(1, len(p.regions)):] {
		if m[i] != m[p.regions[0]] {
			return false
		}
	}
	return true
}

// String returns the pattern as written, normalised.
func (p *Pattern) String() string { return p.source }
