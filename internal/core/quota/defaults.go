package quota

// The keys. Names follow the type names of each service's quota API.
const (
	VPCVPC               Key = "vpc.vpc"
	VPCSubnet            Key = "vpc.subnet"
	VPCSecurityGroup     Key = "vpc.securityGroup"
	VPCSecurityGroupRule Key = "vpc.securityGroupRule"
	VPCPublicIP          Key = "vpc.publicIp"
	VPCShareBandwidth    Key = "vpc.shareBandwidth"
	VPCShareBandwidthIP  Key = "vpc.shareBandwidthIP"

	ECSInstances Key = "ecs.instances"
	ECSCores     Key = "ecs.cores"

	EVSVolumes   Key = "evs.volumes"
	EVSGigabytes Key = "evs.gigabytes"
	EVSSnapshots Key = "evs.snapshots"

	ELBLoadBalancer          Key = "elb.loadbalancer"
	ELBListener              Key = "elb.listener"
	ELBL7Policy              Key = "elb.l7policy"
	ELBPool                  Key = "elb.pool"
	ELBMember                Key = "elb.member"
	ELBCertificate           Key = "elb.certificate"
	ELBL7PoliciesPerListener Key = "elb.l7policies_per_listener"

	NATGateway Key = "nat.nat_gateway"

	IMSImage Key = "ims.image"

	OBSBuckets Key = "obs.buckets"

	RDSInstance Key = "rds.instance"

	KMSCMK Key = "kms.CMK"

	IAMUser   Key = "iam.user"
	IAMGroup  Key = "iam.group"
	IAMAgency Key = "iam.agency"
)

type def struct {
	value  int
	source string
}

// defaults are a new Huawei Cloud account's quotas: the number Huawei
// publishes, or where it publishes none, the value in its own quota
// API's example response. The limits WeiStack had before keep their
// values, which users rely on.
var defaults = map[Key]def{
	VPCVPC:               {150, "VPC quota API example"},
	VPCSubnet:            {400, "VPC quota API example"},
	VPCSecurityGroup:     {100, "VPC quota API example"},
	VPCSecurityGroupRule: {5000, "VPC quota API example"},
	VPCPublicIP:          {50, "WeiStack before v0.3 (-eip-max-per-project)"},
	VPCShareBandwidth:    {5, "VPC quota API example"},
	VPCShareBandwidthIP:  {20, "VPC quota API example"},

	ECSInstances: {20, "WeiStack before v0.3 (-ecs-max-servers)"},
	ECSCores:     {80, "WeiStack before v0.3 (-ecs-max-vcpus)"},

	EVSVolumes:   {Unlimited, "EVS quota API example"},
	EVSGigabytes: {42790, "EVS quota API example"},
	EVSSnapshots: {10, "EVS quota API example"},

	ELBLoadBalancer:          {50, "ELB quotas and constraints"},
	ELBListener:              {100, "ELB quotas and constraints"},
	ELBL7Policy:              {500, "ELB quotas and constraints"},
	ELBPool:                  {500, "ELB quotas and constraints"},
	ELBMember:                {500, "ELB quotas and constraints"},
	ELBCertificate:           {120, "ELB quotas and constraints"},
	ELBL7PoliciesPerListener: {100, "ELB quotas and constraints"},

	NATGateway: {15, "NAT quota API: the default value is 15"},

	IMSImage: {20, "IMS quota API example"},

	OBSBuckets: {100, "OBS notes and constraints"},

	RDSInstance: {20, "WeiStack before v0.3 (-rds-max-instances)"},

	KMSCMK: {100, "KMS constraints"},

	IAMUser:   {50, "IAM: the default quota of users"},
	IAMGroup:  {20, "IAM account quota API example"},
	IAMAgency: {50, "IAM account quota API example"},
}
