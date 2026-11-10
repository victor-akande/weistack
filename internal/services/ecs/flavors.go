package ecs

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed seed/flavors.yaml
var builtinFlavors []byte

// flavorSeedFile is the file looked for in the seed directory.
const flavorSeedFile = "flavors.yaml"

// Processor architectures of a flavor.
const (
	ArchX86 = "x86"
	ArchARM = "arm"
)

// FlavorSpec is a flavor as the emulator knows it. Flavors are static
// seed data, the same in every region and project.
type FlavorSpec struct {
	Name            string `yaml:"name"`
	VCPUs           int    `yaml:"vcpus"`
	RAM             int    `yaml:"ram"` // MiB
	PerformanceType string `yaml:"performance_type"`
	Arch            string `yaml:"arch"`
}

// Generation is the flavor family, the part of the name before the
// first period ("s6" for "s6.large.2").
func (f FlavorSpec) Generation() string {
	gen, _, _ := strings.Cut(f.Name, ".")
	return gen
}

type flavorSeed struct {
	Flavors []FlavorSpec `yaml:"flavors"`
}

var flavorNameRE = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z0-9]+)+$`)

// loadFlavors returns the built-in flavors, extended by flavors.yaml in
// seedDir when that file exists. An entry in the file replaces a
// built-in flavor of the same name.
func loadFlavors(seedDir string) ([]FlavorSpec, error) {
	flavors, err := parseFlavors(builtinFlavors, "built-in flavors.yaml")
	if err != nil {
		return nil, err
	}
	if seedDir == "" {
		return flavors, nil
	}
	path := filepath.Join(seedDir, flavorSeedFile)
	raw, err := os.ReadFile(path) //nolint:gosec // operator-chosen seed directory
	if errors.Is(err, os.ErrNotExist) {
		return flavors, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ecs: reading seed file: %w", err)
	}
	extra, err := parseFlavors(raw, path)
	if err != nil {
		return nil, err
	}
	index := map[string]int{}
	for i, f := range flavors {
		index[f.Name] = i
	}
	for _, f := range extra {
		if i, ok := index[f.Name]; ok {
			flavors[i] = f
			continue
		}
		flavors = append(flavors, f)
	}
	return flavors, nil
}

func parseFlavors(raw []byte, source string) ([]FlavorSpec, error) {
	var seed flavorSeed
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a misspelt field should fail, not be ignored
	if err := dec.Decode(&seed); err != nil {
		return nil, fmt.Errorf("ecs: parsing %s: %w", source, err)
	}
	seen := map[string]bool{}
	for i := range seed.Flavors {
		f := &seed.Flavors[i]
		if err := f.normalise(); err != nil {
			return nil, fmt.Errorf("ecs: %s: flavor %d (%q): %w", source, i+1, f.Name, err)
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("ecs: %s: flavor name %q is repeated", source, f.Name)
		}
		seen[f.Name] = true
	}
	return seed.Flavors, nil
}

// normalise validates a flavor and fills its defaults.
func (f *FlavorSpec) normalise() error {
	if !flavorNameRE.MatchString(f.Name) {
		return errors.New(`name is required and must look like "s6.large.2"`)
	}
	if f.VCPUs < 1 || f.VCPUs > 1024 {
		return errors.New("vcpus must be between 1 and 1024")
	}
	if f.RAM < 128 {
		return errors.New("ram is in MiB and must be at least 128")
	}
	if f.PerformanceType == "" {
		f.PerformanceType = "normal"
	}
	if f.Arch == "" {
		f.Arch = ArchX86
	}
	if f.Arch != ArchX86 && f.Arch != ArchARM {
		return fmt.Errorf("arch %q must be x86 or arm", f.Arch)
	}
	return nil
}

// Flavor mirrors the SDK model ecs/v2 Flavor, the response form of a
// flavor. vcpus and disk are strings in the real API.
type Flavor struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	VCPUs       string          `json:"vcpus"`
	RAM         int             `json:"ram"`
	Disk        string          `json:"disk"`
	Swap        string          `json:"swap"`
	Links       []FlavorLink    `json:"links"`
	Ephemeral   int             `json:"OS-FLV-EXT-DATA:ephemeral"`
	RxtxFactor  float64         `json:"rxtx_factor"`
	Disabled    bool            `json:"OS-FLV-DISABLED:disabled"`
	RxtxQuota   *string         `json:"rxtx_quota"`
	RxtxCap     *string         `json:"rxtx_cap"`
	IsPublic    bool            `json:"os-flavor-access:is_public"`
	OSExtraSpec FlavorExtraSpec `json:"os_extra_specs"`
}

// FlavorLink mirrors the SDK model ecs/v2 FlavorLink.
type FlavorLink struct {
	Rel  string  `json:"rel"`
	Href string  `json:"href"`
	Type *string `json:"type"`
}

// FlavorExtraSpec mirrors the SDK model ecs/v2 FlavorExtraSpec, limited
// to the keys every flavor carries.
type FlavorExtraSpec struct {
	PerformanceType       string `json:"ecs:performancetype"`
	ResourceType          string `json:"resource_type"`
	Generation            string `json:"ecs:generation"`
	VirtualizationEnvType string `json:"ecs:virtualization_env_types"`
	OperationStatus       string `json:"cond:operation:status"`
	OperationAZ           string `json:"cond:operation:az"`
	CPUArchitecture       string `json:"ecs:instance_architecture,omitempty"`
}

// view renders a flavor for one tenant: links and the per-AZ sales
// status depend on the region and project.
func (f FlavorSpec) view(t Tenant) Flavor {
	base := fmt.Sprintf("https://ecs.%s.myhuaweicloud.com/v1.0/%s/flavors/%s", t.Region, t.ProjectID, f.Name)
	azs := make([]string, 0, zonesPerRegion)
	for _, az := range Zones(t.Region) {
		azs = append(azs, az+"(normal)")
	}
	out := Flavor{
		ID:         f.Name,
		Name:       f.Name,
		VCPUs:      strconv.Itoa(f.VCPUs),
		RAM:        f.RAM,
		Disk:       "0",
		RxtxFactor: 1,
		IsPublic:   true,
		Links: []FlavorLink{
			{Rel: "self", Href: base},
			{Rel: "bookmark", Href: base},
		},
		OSExtraSpec: FlavorExtraSpec{
			PerformanceType:       f.PerformanceType,
			ResourceType:          "IOoptimized" + strings.ToUpper(f.Generation()),
			Generation:            f.Generation(),
			VirtualizationEnvType: "CloudCompute",
			OperationStatus:       "normal",
			OperationAZ:           strings.Join(azs, ","),
		},
	}
	if f.Arch == ArchARM {
		out.OSExtraSpec.CPUArchitecture = "arm64"
	}
	return out
}

// zonesPerRegion is how many availability zones each region has.
const zonesPerRegion = 3

// Zones returns the availability zones of a region, named as Huawei
// Cloud names them: the region followed by a letter.
func Zones(region string) []string {
	zones := make([]string, zonesPerRegion)
	for i := range zones {
		zones[i] = region + string(rune('a'+i))
	}
	return zones
}

// ZoneExists reports whether az is an availability zone of region.
func ZoneExists(region, az string) bool {
	for _, z := range Zones(region) {
		if z == az {
			return true
		}
	}
	return false
}
