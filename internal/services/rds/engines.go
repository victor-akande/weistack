package rds

import (
	"crypto/sha1" //nolint:gosec // name-based UUIDs (RFC 4122 version 5) are defined on SHA-1
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Engine is a database engine the emulator offers.
type Engine struct {
	// Name is the datastore type as the API spells it.
	Name string
	// Code is the engine's part of a specification code ("mysql", "pg").
	Code     string
	Versions []string
	// DefaultPort and the port rules.
	DefaultPort int
	portOK      func(int) bool
	// Storage limits in GB.
	MinVolume, MaxVolume int
	// MaxKeepDays bounds backup retention.
	MaxKeepDays int
	// ReplicationModes are those an HA instance may use; the first is
	// the default.
	ReplicationModes []string
	// Name rule, and the password rule: the special characters allowed
	// and how many kinds of character (upper, lower, digit, special) a
	// password must mix.
	nameRE   *regexp.Regexp
	specials string
	minKinds int
}

var engines = []Engine{
	{
		Name: "MySQL", Code: "mysql", Versions: []string{"5.7", "8.0"},
		DefaultPort: 3306,
		portOK:      func(p int) bool { return p >= 1024 && p <= 65535 && p != 12017 && p != 33071 },
		MinVolume:   20, MaxVolume: 10000, MaxKeepDays: 732,
		ReplicationModes: []string{"semisync", "async"},
		nameRE:           regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.\-]{3,63}$`),
		specials:         "~!@#$%^*-_=+?,()&.|",
		minKinds:         4,
	},
	{
		Name: "PostgreSQL", Code: "pg", Versions: []string{"13", "14", "15", "16", "17", "18"},
		DefaultPort: 5432,
		portOK:      func(p int) bool { return p >= 2100 && p <= 9500 },
		MinVolume:   40, MaxVolume: 4000, MaxKeepDays: 3660,
		ReplicationModes: []string{"async", "sync"},
		nameRE:           regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_\-]{3,63}$`),
		specials:         "~!@#$%^*-_=+?,",
		minKinds:         3,
	},
}

// engineNamed finds an engine by its datastore type, case-insensitively.
func engineNamed(name string) (Engine, bool) {
	for _, e := range engines {
		if strings.EqualFold(e.Name, name) {
			return e, true
		}
	}
	return Engine{}, false
}

// knownButUnemulated are engines the real service has and the emulator
// does not, reported as gaps rather than as invalid input.
var knownButUnemulated = []string{"SQLServer", "MariaDB"}

func unemulated(name string) bool {
	return slices.ContainsFunc(knownButUnemulated, func(n string) bool { return strings.EqualFold(n, name) })
}

func (e Engine) checkPassword(p string) error {
	if len(p) < 8 || len(p) > 32 {
		return errPassword
	}
	var upper, lower, digit, extra int
	for _, r := range p {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = 1
		case r >= 'a' && r <= 'z':
			lower = 1
		case r >= '0' && r <= '9':
			digit = 1
		case strings.ContainsRune(e.specials, r):
			extra = 1
		default:
			return errPassword
		}
	}
	if upper+lower+digit+extra < e.minKinds {
		return errPassword
	}
	return nil
}

// Instance modes.
const (
	ModeSingle = "Single"
	ModeHA     = "Ha"
)

// FlavorSpec is a database specification.
type FlavorSpec struct {
	Code   string
	Engine Engine
	Mode   string
	VCPUs  int
	RAMGB  int
}

// sizes are the general-purpose (n1) sizes offered for every engine.
var sizes = []struct {
	name       string
	vcpus, ram int
}{
	{"large.2", 2, 4}, {"large.4", 2, 8},
	{"xlarge.2", 4, 8}, {"xlarge.4", 4, 16},
	{"2xlarge.2", 8, 16}, {"2xlarge.4", 8, 32},
}

// flavorsOf returns an engine's specifications: each size as a single
// instance and, with the ".ha" suffix, as a primary/standby pair.
func flavorsOf(e Engine) []FlavorSpec {
	out := make([]FlavorSpec, 0, 2*len(sizes))
	for _, s := range sizes {
		base := fmt.Sprintf("rds.%s.n1.%s", e.Code, s.name)
		out = append(out,
			FlavorSpec{Code: base, Engine: e, Mode: ModeSingle, VCPUs: s.vcpus, RAMGB: s.ram},
			FlavorSpec{Code: base + ".ha", Engine: e, Mode: ModeHA, VCPUs: s.vcpus, RAMGB: s.ram},
		)
	}
	return out
}

// flavorByCode finds a specification of any engine.
func flavorByCode(code string) (FlavorSpec, bool) {
	for _, e := range engines {
		for _, f := range flavorsOf(e) {
			if f.Code == code {
				return f, true
			}
		}
	}
	return FlavorSpec{}, false
}

// nameUUID returns the RFC 4122 version 5 UUID of name, so seeded items
// have the same ID everywhere.
func nameUUID(name string) string {
	sum := sha1.Sum([]byte(name)) //nolint:gosec // see import
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// parsePort reads the port of a create request, which the API sends as
// a string.
func (e Engine) parsePort(raw *string) (int, error) {
	if raw == nil || *raw == "" {
		return e.DefaultPort, nil
	}
	p, err := strconv.Atoi(*raw)
	if err != nil || !e.portOK(p) {
		return 0, errPort
	}
	return p, nil
}
