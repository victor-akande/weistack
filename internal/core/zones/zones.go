// Package zones defines the availability zones of a region. Every
// service that places resources in zones (ECS servers, RDS nodes) uses
// it, so they agree on which zones exist.
package zones

// PerRegion is how many availability zones each region has.
const PerRegion = 3

// Of returns the availability zones of a region, named as Huawei Cloud
// names them: the region followed by a letter.
func Of(region string) []string {
	out := make([]string, PerRegion)
	for i := range out {
		out[i] = region + string(rune('a'+i))
	}
	return out
}

// Exists reports whether az is an availability zone of region.
func Exists(region, az string) bool {
	for _, z := range Of(region) {
		if z == az {
			return true
		}
	}
	return false
}
