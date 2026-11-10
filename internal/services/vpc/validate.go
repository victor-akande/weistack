package vpc

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	// Names allow letters (any script), digits, underscores, hyphens and periods.
	nameRE = regexp.MustCompile(`^[\p{L}\p{N}_.\-]*$`)
	uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

const (
	maxNameLen        = 64
	maxDescriptionLen = 255
)

func isUUID(s string) bool { return uuidRE.MatchString(s) }

// checkName validates a resource name. Whether it may be empty depends
// on the resource.
func checkName(name string, allowEmpty bool) error {
	n := utf8.RuneCountInString(name)
	switch {
	case n == 0 && !allowEmpty:
		return fmt.Errorf("name is required")
	case n > maxNameLen:
		return fmt.Errorf("name must not exceed %d characters", maxNameLen)
	case !nameRE.MatchString(name):
		return fmt.Errorf("name can contain only letters, digits, underscores (_), hyphens (-), and periods (.)")
	}
	return nil
}

func checkDescription(desc string) error {
	switch {
	case utf8.RuneCountInString(desc) > maxDescriptionLen:
		return fmt.Errorf("description must not exceed %d characters", maxDescriptionLen)
	case strings.ContainsAny(desc, "<>"):
		return fmt.Errorf("description cannot contain angle brackets (< or >)")
	}
	return nil
}

// VPC CIDR limits from the API reference: a mask of 8 to 24 bits and
// none of the ranges below, which are reserved for other purposes.
const (
	minVPCPrefix = 8
	maxVPCPrefix = 24
)

var reservedVPCRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("214.0.0.0/7"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// parseIPv4CIDR parses a canonical IPv4 CIDR: no host bits set, so
// "192.168.1.0/16" is rejected rather than silently masked.
func parseIPv4CIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not in CIDR format", s)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 CIDR block", s)
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("%q has host bits set; did you mean %s?", s, p.Masked())
	}
	return p, nil
}

// checkVPCCIDR validates a VPC CIDR block.
func checkVPCCIDR(s string) error {
	p, err := parseIPv4CIDR(s)
	if err != nil {
		return err
	}
	if p.Bits() < minVPCPrefix || p.Bits() > maxVPCPrefix {
		return fmt.Errorf("the mask of %q must be between %d and %d bits", s, minVPCPrefix, maxVPCPrefix)
	}
	for _, reserved := range reservedVPCRanges {
		if reserved.Overlaps(p) {
			return fmt.Errorf("%q overlaps the reserved range %s", s, reserved)
		}
	}
	return nil
}
