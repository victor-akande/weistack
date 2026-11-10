package vpc

import (
	"fmt"
	"time"
)

// timeLayout is the timestamp format of the VPC v1 API: UTC, second
// resolution, no zone designator ("2022-12-15T02:25:11").
const timeLayout = "2006-01-02T15:04:05"

// Time is a timestamp in the VPC v1 wire format.
type Time time.Time

// MarshalJSON implements json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(t).UTC().Format(timeLayout) + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Time) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return fmt.Errorf("vpc: timestamp %s is not a string", b)
	}
	parsed, err := time.ParseInLocation(timeLayout, string(b[1:len(b)-1]), time.UTC)
	if err != nil {
		return fmt.Errorf("vpc: parsing timestamp: %w", err)
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
