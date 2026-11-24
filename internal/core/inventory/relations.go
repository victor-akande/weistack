package inventory

// RelationType is how one resource relates to another, in Config's
// terms (api-rms/rms_04_0302: relation_type).
type RelationType string

// The four relationship types Config documents.
const (
	Contains         RelationType = "contains"
	IsContainedIn    RelationType = "isContainedIn"
	IsAttachedTo     RelationType = "isAttachedTo"
	IsAssociatedWith RelationType = "isAssociatedWith"
)

// Inverse is the relationship seen from the other resource. In Config's
// table of relationships (usermanual-rms/rms_06_0200), every pair is
// listed from both ends: A contains B where B isContainedIn A, and
// attachment and association hold both ways.
func (t RelationType) Inverse() RelationType {
	switch t {
	case Contains:
		return IsContainedIn
	case IsContainedIn:
		return Contains
	default:
		return t
	}
}

func (t RelationType) valid() bool {
	switch t {
	case Contains, IsContainedIn, IsAttachedTo, IsAssociatedWith:
		return true
	}
	return false
}

// pair is one relationship between two types.
type pair struct {
	from     Type
	relation RelationType
	to       Type
}

// documented are the relationships between WeiStack's types that
// Config's table lists (usermanual-rms/rms_06_0200), each from one end;
// the other end follows by Inverse. A service may report only these, so
// that WeiStack shows no relationship Huawei Cloud would not.
//
// The table relates types WeiStack does not emulate too, such as ports,
// flow logs and backup vaults: those are left out. It relates no VPC to
// its subnets.
var documented = []pair{
	// "Cloud servers": isContainedIn VPCs, isAttachedTo EIPs and disks,
	// isAssociatedWith security groups and images.
	{ECSServers, IsContainedIn, VPCs},
	{ECSServers, IsAttachedTo, EIPPublicIPs},
	{ECSServers, IsAttachedTo, EVSVolumes},
	{ECSServers, IsAssociatedWith, VPCSecurityGroups},
	{ECSServers, IsAssociatedWith, IMSImages},

	// "Load balancers": contains listeners, isAttachedTo EIPs and
	// backend server groups.
	{ELBLoadBalancers, Contains, ELBListeners},
	{ELBLoadBalancers, IsAttachedTo, EIPPublicIPs},
	{ELBLoadBalancers, IsAttachedTo, ELBPools},
	// "Listeners": contains forwarding policies, isAttachedTo backend
	// server groups.
	{ELBListeners, Contains, ELBL7Policies},
	{ELBListeners, IsAttachedTo, ELBPools},
	// "Backend server groups": contains backend servers.
	{ELBPools, Contains, ELBMembers},

	// "VPCs" contains EIPs; "Bandwidth" contains publicips; "Elastic IP"
	// isAttachedTo public NAT gateways.
	{VPCs, Contains, EIPPublicIPs},
	{EIPBandwidths, Contains, EIPPublicIPs},
	{EIPPublicIPs, IsAttachedTo, NATGateways},

	// IAM: "User groups" contains users; agencies, user groups and users
	// are associated with policies and roles.
	{IAMGroups, Contains, IAMUsers},
	{IAMAgencies, IsAssociatedWith, IAMPolicies},
	{IAMAgencies, IsAssociatedWith, IAMRoles},
	{IAMGroups, IsAssociatedWith, IAMPolicies},
	{IAMGroups, IsAssociatedWith, IAMRoles},
	{IAMUsers, IsAssociatedWith, IAMPolicies},
	{IAMUsers, IsAssociatedWith, IAMRoles},
}

// allowed holds every documented pair from both ends.
var allowed = func() map[pair]bool {
	m := make(map[pair]bool, 2*len(documented))
	for _, p := range documented {
		m[p] = true
		m[pair{p.to, p.relation.Inverse(), p.from}] = true
	}
	return m
}()

// Allowed reports whether Config documents relation from a resource of
// type from to one of type to.
func Allowed(from Type, relation RelationType, to Type) bool {
	return allowed[pair{from, relation, to}]
}
