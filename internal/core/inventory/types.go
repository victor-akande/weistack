package inventory

import (
	"sort"
	"strings"
)

// Type is a resource type as Huawei Cloud's Config service names it: a
// provider, such as "ecs", and a type within it, such as "cloudservers".
type Type struct {
	Provider string
	Name     string
}

// String is the "provider.type" form Config uses in relationships and in
// its type filter, such as "ecs.cloudservers".
func (t Type) String() string { return t.Provider + "." + t.Name }

// ParseType is the inverse of Type.String. It accepts only catalogued
// types.
func ParseType(s string) (Type, bool) {
	provider, name, ok := strings.Cut(s, ".")
	if !ok {
		return Type{}, false
	}
	t := Type{Provider: provider, Name: name}
	_, known := catalogue[t]
	return t, known
}

// Placement says where a type's resources live.
type Placement int

const (
	// InProject resources belong to a project in a region, such as
	// servers.
	InProject Placement = iota + 1
	// InRegion resources belong to an account in a region, without a
	// project, such as OBS buckets.
	InRegion
	// Global resources belong to an account, in no region, such as IAM
	// users. Config reports their region as "global".
	Global
)

// GlobalRegion is the region of Global resources, as Config reports it.
const GlobalRegion = "global"

// TypeInfo describes a catalogued type.
type TypeInfo struct {
	Type      Type
	Placement Placement
	// Documented is true when Huawei Cloud documents this name for
	// Config. Other names follow Huawei's convention (see the catalogue)
	// and may change if Huawei documents a different one.
	Documented bool
}

// The types WeiStack reports. Huawei documents a type's name in the
// Config guide's "Supported Services and Resources" appendix
// (usermanual-rms/rms_06_0900), its "Relationships with Supported
// Resources" appendix (rms_06_0200), the resource types of its built-in
// policies (rms_05_05xx) or the examples of its API reference (api-rms).
//
// An undocumented name follows the convention every documented one
// keeps: the provider is the one Config files the service under, and the
// type is the collection in the service's API path, in lower camel case
// ("security-groups" is securityGroups, "nat_gateways" natGateways).
var (
	// ECS: ecs.cloudservers is documented.
	ECSServers = Type{"ecs", "cloudservers"}

	// EVS: evs.volumes is documented.
	EVSVolumes   = Type{"evs", "volumes"}
	EVSSnapshots = Type{"evs", "snapshots"}

	// VPC: vpc.vpcs, vpc.networks (subnets), vpc.securityGroups,
	// vpc.publicips and vpc.bandwidths are documented. Config files EIPs
	// and bandwidths under VPC.
	VPCs                  = Type{"vpc", "vpcs"}
	VPCSubnets            = Type{"vpc", "networks"}
	VPCSecurityGroups     = Type{"vpc", "securityGroups"}
	VPCSecurityGroupRules = Type{"vpc", "securityGroupRules"}
	EIPPublicIPs          = Type{"vpc", "publicips"}
	EIPBandwidths         = Type{"vpc", "bandwidths"}

	// NAT: nat.natGateways and nat.privateNatGateways are documented.
	// Private NAT's rules take the "private" prefix its gateways have,
	// to stay apart from public NAT's.
	NATGateways         = Type{"nat", "natGateways"}
	NATSNATRules        = Type{"nat", "snatRules"}
	NATDNATRules        = Type{"nat", "dnatRules"}
	NATPrivateGateways  = Type{"nat", "privateNatGateways"}
	NATPrivateSNATRules = Type{"nat", "privateSnatRules"}
	NATPrivateDNATRules = Type{"nat", "privateDnatRules"}
	NATTransitSubnets   = Type{"nat", "transitSubnets"}
	NATTransitIPs       = Type{"nat", "transitIps"}

	// ELB: elb.loadbalancers, elb.listeners and elb.members are
	// documented.
	ELBLoadBalancers    = Type{"elb", "loadbalancers"}
	ELBListeners        = Type{"elb", "listeners"}
	ELBPools            = Type{"elb", "pools"}
	ELBMembers          = Type{"elb", "members"}
	ELBHealthMonitors   = Type{"elb", "healthmonitors"}
	ELBL7Policies       = Type{"elb", "l7policies"}
	ELBCertificates     = Type{"elb", "certificates"}
	ELBIPGroups         = Type{"elb", "ipgroups"}
	ELBSecurityPolicies = Type{"elb", "securityPolicies"}

	// IMS: ims.images is documented.
	IMSImages = Type{"ims", "images"}

	// IAM: all five are documented. iam.roles are the custom policies of
	// classic IAM (/v3.0/OS-ROLE/roles), and iam.policies those of IAM
	// 5.0 (/v5/policies), as each API calls them.
	IAMUsers    = Type{"iam", "users"}
	IAMGroups   = Type{"iam", "groups"}
	IAMRoles    = Type{"iam", "roles"}
	IAMPolicies = Type{"iam", "policies"}
	IAMAgencies = Type{"iam", "agencies"}

	// KMS: kms.keys is documented.
	KMSKeys = Type{"kms", "keys"}

	// CSMS: csms.secrets is documented.
	CSMSSecrets = Type{"csms", "secrets"}

	// KPS.
	KPSKeypairs = Type{"kps", "keypairs"}

	// OBS: obs.buckets is documented.
	OBSBuckets = Type{"obs", "buckets"}

	// RDS: rds.instances is documented.
	RDSInstances = Type{"rds", "instances"}
	RDSBackups   = Type{"rds", "backups"}
)

var catalogue = func() map[Type]TypeInfo {
	m := make(map[Type]TypeInfo)
	add := func(p Placement, documented bool, types ...Type) {
		for _, t := range types {
			if _, dup := m[t]; dup {
				panic("inventory: type catalogued twice: " + t.String())
			}
			m[t] = TypeInfo{Type: t, Placement: p, Documented: documented}
		}
	}
	add(InProject, true,
		ECSServers, EVSVolumes,
		VPCs, VPCSubnets, VPCSecurityGroups, EIPPublicIPs, EIPBandwidths,
		NATGateways, NATPrivateGateways,
		ELBLoadBalancers, ELBListeners, ELBMembers,
		IMSImages, KMSKeys, CSMSSecrets, RDSInstances)
	add(InProject, false,
		EVSSnapshots, VPCSecurityGroupRules,
		NATSNATRules, NATDNATRules, NATPrivateSNATRules, NATPrivateDNATRules,
		NATTransitSubnets, NATTransitIPs,
		ELBPools, ELBHealthMonitors, ELBL7Policies, ELBCertificates,
		ELBIPGroups, ELBSecurityPolicies,
		KPSKeypairs, RDSBackups)
	add(InRegion, true, OBSBuckets)
	add(Global, true, IAMUsers, IAMGroups, IAMRoles, IAMPolicies, IAMAgencies)
	return m
}()

// Lookup returns what the catalogue says about t.
func Lookup(t Type) (TypeInfo, bool) {
	info, ok := catalogue[t]
	return info, ok
}

// Types returns every catalogued type, sorted by name.
func Types() []TypeInfo {
	out := make([]TypeInfo, 0, len(catalogue))
	for _, info := range catalogue {
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type.String() < out[j].Type.String() })
	return out
}
