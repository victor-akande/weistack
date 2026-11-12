package vpc

import (
	"fmt"
	"time"

	"github.com/victor-akande/weistack/internal/core/wiretime"
)

// Time is a timestamp in the VPC v1 wire format: UTC, second resolution,
// no zone designator ("2022-12-15T02:25:11").
type Time time.Time

// MarshalJSON implements json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	return wiretime.AppendQuoted(make([]byte, 0, 24), time.Time(t), false), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Time) UnmarshalJSON(b []byte) error {
	parsed, err := wiretime.ParseQuoted(b, false)
	if err != nil {
		return fmt.Errorf("vpc: timestamp %s: %w", b, err)
	}
	*t = Time(parsed)
	return nil
}

// VPC statuses.
const (
	VPCStatusCreating = "CREATING"
	VPCStatusOK       = "OK"
	VPCStatusError    = "ERROR"
)

// VPC mirrors the SDK model vpc/v2 Vpc. It is both the stored record and
// the response body.
type VPC struct {
	ID                               string  `json:"id"`
	Name                             string  `json:"name"`
	Description                      string  `json:"description"`
	CIDR                             string  `json:"cidr"`
	Status                           string  `json:"status"`
	BlockServiceEndpointStates       string  `json:"block_service_endpoint_states"`
	EnableNetworkAddressUsageMetrics bool    `json:"enable_network_address_usage_metrics"`
	EnterpriseProjectID              string  `json:"enterprise_project_id"`
	Routes                           []Route `json:"routes"`
	TenantID                         string  `json:"tenant_id"`
	CreatedAt                        Time    `json:"created_at"`
	UpdatedAt                        Time    `json:"updated_at"`
}

// Route mirrors the SDK model vpc/v2 Route.
type Route struct {
	Destination string `json:"destination,omitempty"`
	Nexthop     string `json:"nexthop,omitempty"`
}

// CreateVPCOption mirrors the SDK model vpc/v2 CreateVpcOption.
type CreateVPCOption struct {
	CIDR                             *string   `json:"cidr"`
	Name                             *string   `json:"name"`
	Description                      *string   `json:"description"`
	EnterpriseProjectID              *string   `json:"enterprise_project_id"`
	Tags                             *[]string `json:"tags"`
	BlockServiceEndpointStates       *string   `json:"block_service_endpoint_states"`
	EnableNetworkAddressUsageMetrics *bool     `json:"enable_network_address_usage_metrics"`
}

// UpdateVPCOption mirrors the SDK model vpc/v2 UpdateVpcOption. A nil
// field is left unchanged.
type UpdateVPCOption struct {
	Name                             *string  `json:"name"`
	Description                      *string  `json:"description"`
	CIDR                             *string  `json:"cidr"`
	Routes                           *[]Route `json:"routes"`
	EnableNetworkAddressUsageMetrics *bool    `json:"enable_network_address_usage_metrics"`
}

// ListVPCsFilter selects VPCs in ListVPCs. Empty fields match everything.
type ListVPCsFilter struct {
	ID                  string
	EnterpriseProjectID string
}

type createVPCRequest struct {
	VPC *CreateVPCOption `json:"vpc"`
}

type updateVPCRequest struct {
	VPC *UpdateVPCOption `json:"vpc"`
}

type vpcResponse struct {
	VPC VPC `json:"vpc"`
}

type listVPCsResponse struct {
	VPCs []VPC `json:"vpcs"`
}

// Subnet statuses.
const (
	// SubnetStatusUnknown is the state right after creation, before the
	// subnet is associated with its VPC.
	SubnetStatusUnknown = "UNKNOWN"
	SubnetStatusActive  = "ACTIVE"
	SubnetStatusError   = "ERROR"
)

// Subnet mirrors the SDK model vpc/v2 Subnet. The IPv6 fields are only
// returned for subnets with IPv6 enabled.
type Subnet struct {
	ID                               string            `json:"id"`
	Name                             string            `json:"name"`
	Description                      string            `json:"description"`
	CIDR                             string            `json:"cidr"`
	GatewayIP                        string            `json:"gateway_ip"`
	IPv6Enable                       bool              `json:"ipv6_enable"`
	CIDRv6                           string            `json:"cidr_v6,omitempty"`
	GatewayIPv6                      string            `json:"gateway_ip_v6,omitempty"`
	DHCPEnable                       bool              `json:"dhcp_enable"`
	PrimaryDNS                       string            `json:"primary_dns"`
	SecondaryDNS                     string            `json:"secondary_dns"`
	DNSList                          []string          `json:"dnsList"`
	AvailabilityZone                 string            `json:"availability_zone"`
	VPCID                            string            `json:"vpc_id"`
	Status                           string            `json:"status"`
	NeutronNetworkID                 string            `json:"neutron_network_id"`
	NeutronSubnetID                  string            `json:"neutron_subnet_id"`
	NeutronSubnetIDv6                string            `json:"neutron_subnet_id_v6,omitempty"`
	ExtraDHCPOpts                    []ExtraDHCPOption `json:"extra_dhcp_opts"`
	TenantID                         string            `json:"tenant_id"`
	CreatedAt                        Time              `json:"created_at"`
	UpdatedAt                        Time              `json:"updated_at"`
	EnableNetworkAddressUsageMetrics bool              `json:"enable_network_address_usage_metrics"`
	AvailableIPAddressCount          int               `json:"available_ip_address_count"`
}

// ExtraDHCPOption mirrors the SDK model vpc/v2 ExtraDhcpOption.
type ExtraDHCPOption struct {
	OptName  string  `json:"opt_name"`
	OptValue *string `json:"opt_value,omitempty"`
}

// CreateSubnetOption mirrors the SDK model vpc/v2 CreateSubnetOption.
type CreateSubnetOption struct {
	Name                             string             `json:"name"`
	Description                      *string            `json:"description"`
	CIDR                             string             `json:"cidr"`
	VPCID                            string             `json:"vpc_id"`
	GatewayIP                        string             `json:"gateway_ip"`
	IPv6Enable                       *bool              `json:"ipv6_enable"`
	DHCPEnable                       *bool              `json:"dhcp_enable"`
	PrimaryDNS                       *string            `json:"primary_dns"`
	SecondaryDNS                     *string            `json:"secondary_dns"`
	DNSList                          *[]string          `json:"dnsList"`
	AvailabilityZone                 *string            `json:"availability_zone"`
	ExtraDHCPOpts                    *[]ExtraDHCPOption `json:"extra_dhcp_opts"`
	Tags                             *[]string          `json:"tags"`
	EnableNetworkAddressUsageMetrics *bool              `json:"enable_network_address_usage_metrics"`
}

// UpdateSubnetOption mirrors the SDK model vpc/v2 UpdateSubnetOption.
// Name is required by the API; a nil pointer field is left unchanged.
type UpdateSubnetOption struct {
	Name                             string             `json:"name"`
	Description                      *string            `json:"description"`
	IPv6Enable                       *bool              `json:"ipv6_enable"`
	DHCPEnable                       *bool              `json:"dhcp_enable"`
	PrimaryDNS                       *string            `json:"primary_dns"`
	SecondaryDNS                     *string            `json:"secondary_dns"`
	DNSList                          *[]string          `json:"dnsList"`
	ExtraDHCPOpts                    *[]ExtraDHCPOption `json:"extra_dhcp_opts"`
	EnableNetworkAddressUsageMetrics *bool              `json:"enable_network_address_usage_metrics"`
}

// ListSubnetsFilter selects subnets in ListSubnets.
type ListSubnetsFilter struct {
	VPCID string
}

// subnetRecord is what is stored for a subnet: the API model plus the
// private IP allocations made from it.
type subnetRecord struct {
	Subnet
	// Allocations maps an allocated private IP to its owner, for
	// example "ecs:<server id>".
	Allocations map[string]string `json:"allocations,omitempty"`
}

type createSubnetRequest struct {
	Subnet *CreateSubnetOption `json:"subnet"`
}

type updateSubnetRequest struct {
	Subnet *UpdateSubnetOption `json:"subnet"`
}

type subnetResponse struct {
	Subnet Subnet `json:"subnet"`
}

type listSubnetsResponse struct {
	Subnets []Subnet `json:"subnets"`
}

// subnetResult mirrors the SDK model vpc/v2 SubnetResult, the body of an
// update response.
type subnetResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type updateSubnetResponse struct {
	Subnet subnetResult `json:"subnet"`
}
