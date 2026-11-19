package eip

import "time"

// EIP statuses.
const (
	StatusPendingCreate = "PENDING_CREATE"
	StatusDown          = "DOWN"
	StatusActive        = "ACTIVE"
)

// Bandwidth share types, charge modes, types and statuses.
const (
	ShareTypePer          = "PER"
	ShareTypeWhole        = "WHOLE"
	ChargeModeBandwidth   = "bandwidth"
	ChargeModeTraffic     = "traffic"
	BandwidthTypeBGP      = "bgp"
	BandwidthTypeShare    = "share"
	BandwidthStatusNormal = "NORMAL"
)

// Site and wire time formats.
const (
	PublicBorderGroupCenter = "center"
	v1TimeFormat            = "2006-01-02 15:04:05"
	v3TimeFormat            = "2006-01-02T15:04:05Z"
)

// tag is a key-value pair on an EIP.
type tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// publicIP is the stored record for an elastic IP (kind eip.publicip).
type publicIP struct {
	ID                  string    `json:"id"`
	Alias               string    `json:"alias"`
	Description         string    `json:"description"`
	Type                string    `json:"type"`
	Address             string    `json:"address"`
	Status              string    `json:"status"`
	PortID              string    `json:"port_id"`
	PrivateIP           string    `json:"private_ip"`
	BandwidthID         string    `json:"bandwidth_id"`
	EnterpriseProjectID string    `json:"enterprise_project_id"`
	Tags                []tag     `json:"tags"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	ReleaseWithPort     bool      `json:"release_with_port"`
}

// bandwidth is the stored record for a bandwidth (kind eip.bandwidth).
type bandwidth struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Size                int       `json:"size"`
	ShareType           string    `json:"share_type"`
	ChargeMode          string    `json:"charge_mode"`
	EnterpriseProjectID string    `json:"enterprise_project_id"`
	PublicIPIDs         []string  `json:"public_ip_ids"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// addressClaim records ownership of an allocated public IPv4 address in a
// region (kind eip.address, keyed by address).
type addressClaim struct {
	ProjectID  string `json:"project_id"`
	PublicIPID string `json:"public_ip_id"`
}

// --- §3.1 EIPs, v1 (/v1/{project_id}/publicips) ---

// createPublicIPRequest mirrors eip/v2 CreatePublicipRequestBody.
type createPublicIPRequest struct {
	Bandwidth           *createPublicIPBandwidthOption `json:"bandwidth"`
	EnterpriseProjectID *string                        `json:"enterprise_project_id,omitempty"`
	PublicIP            *createPublicIPOption          `json:"publicip"`
}

// createPublicIPOption mirrors eip/v2 CreatePublicipOption.
type createPublicIPOption struct {
	IPAddress *string `json:"ip_address,omitempty"`
	Type      string  `json:"type"`
	IPVersion *int    `json:"ip_version,omitempty"`
	Alias     *string `json:"alias,omitempty"`
	PortID    *string `json:"port_id,omitempty"`
}

// createPublicIPBandwidthOption mirrors eip/v2 CreatePublicipBandwidthOption.
type createPublicIPBandwidthOption struct {
	ChargeMode *string `json:"charge_mode,omitempty"`
	ID         *string `json:"id,omitempty"`
	Name       *string `json:"name,omitempty"`
	ShareType  string  `json:"share_type"`
	Size       *int    `json:"size,omitempty"`
}

// publicIPCreateResp mirrors eip/v2 PublicipCreateResp and eip_api_0001.
type publicIPCreateResp struct {
	ID                  string `json:"id"`
	Status              string `json:"status"`
	Type                string `json:"type"`
	PublicIPAddress     string `json:"public_ip_address"`
	TenantID            string `json:"tenant_id"`
	IPVersion           int    `json:"ip_version"`
	CreateTime          string `json:"create_time"`
	BandwidthSize       int    `json:"bandwidth_size"`
	EnterpriseProjectID string `json:"enterprise_project_id"`
	PublicBorderGroup   string `json:"public_border_group"`
	Alias               string `json:"alias,omitempty"`
}

type createPublicIPResponse struct {
	PublicIP publicIPCreateResp `json:"publicip"`
}

// publicIPShowResp mirrors eip/v2 PublicipShowResp (§3.1).
type publicIPShowResp struct {
	BandwidthID         string   `json:"bandwidth_id"`
	BandwidthName       string   `json:"bandwidth_name"`
	BandwidthShareType  string   `json:"bandwidth_share_type"`
	BandwidthSize       int      `json:"bandwidth_size"`
	CreateTime          string   `json:"create_time"`
	EnterpriseProjectID string   `json:"enterprise_project_id"`
	ID                  string   `json:"id"`
	PortID              string   `json:"port_id,omitempty"`
	PrivateIPAddress    string   `json:"private_ip_address,omitempty"`
	PublicIPAddress     string   `json:"public_ip_address"`
	Tags                []string `json:"tags"`
	Status              string   `json:"status"`
	TenantID            string   `json:"tenant_id"`
	Type                string   `json:"type"`
	IPVersion           int      `json:"ip_version"`
	PublicBorderGroup   string   `json:"public_border_group"`
	Alias               string   `json:"alias,omitempty"`
}

type showPublicIPResponse struct {
	PublicIP publicIPShowResp `json:"publicip"`
}

type listPublicIPsResponse struct {
	PublicIPs []publicIPShowResp `json:"publicips"`
}

// updatePublicIPOption mirrors eip/v2 UpdatePublicipOption.
type updatePublicIPOption struct {
	PortID    *string `json:"port_id"`
	IPVersion *int    `json:"ip_version,omitempty"`
	Alias     *string `json:"alias,omitempty"`
}

// publicIPUpdateResp mirrors eip/v2 PublicipUpdateResp.
type publicIPUpdateResp struct {
	BandwidthID         string `json:"bandwidth_id"`
	BandwidthName       string `json:"bandwidth_name"`
	BandwidthShareType  string `json:"bandwidth_share_type"`
	BandwidthSize       int    `json:"bandwidth_size"`
	CreateTime          string `json:"create_time"`
	EnterpriseProjectID string `json:"enterprise_project_id"`
	ID                  string `json:"id"`
	PortID              string `json:"port_id,omitempty"`
	PrivateIPAddress    string `json:"private_ip_address,omitempty"`
	PublicIPAddress     string `json:"public_ip_address"`
	Status              string `json:"status"`
	TenantID            string `json:"tenant_id"`
	Type                string `json:"type"`
	IPVersion           int    `json:"ip_version"`
	Alias               string `json:"alias,omitempty"`
}

type updatePublicIPResponse struct {
	PublicIP publicIPUpdateResp `json:"publicip"`
}

// --- §3.2 Bandwidths, v1 and v2.0 ---

// bandwidthPublicIPInfo mirrors eip/v2 PublicipInfoResp.
type bandwidthPublicIPInfo struct {
	PublicIPAddress string `json:"publicip_address"`
	PublicIPID      string `json:"publicip_id"`
	PublicIPType    string `json:"publicip_type"`
	IPVersion       int    `json:"ip_version"`
}

// bandwidthRule mirrors eip/v2 BandWidthRules.
type bandwidthRule struct {
	ID                  string                  `json:"id,omitempty"`
	Name                string                  `json:"name,omitempty"`
	AdminStateUp        bool                    `json:"admin_state_up,omitempty"`
	EgressSize          int                     `json:"egress_size,omitempty"`
	EgressGuarentedSize int                     `json:"egress_guarented_size,omitempty"`
	PublicIPInfo        []bandwidthPublicIPInfo `json:"publicip_info,omitempty"`
}

// bandwidthResp mirrors eip/v2 BandwidthResp in exact field order (§3.2).
type bandwidthResp struct {
	BandwidthType        string                  `json:"bandwidth_type"`
	BillingInfo          string                  `json:"billing_info"`
	ChargeMode           string                  `json:"charge_mode"`
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name"`
	PublicIPInfo         []bandwidthPublicIPInfo `json:"publicip_info"`
	ShareType            string                  `json:"share_type"`
	Size                 int                     `json:"size"`
	TenantID             string                  `json:"tenant_id"`
	EnterpriseProjectID  string                  `json:"enterprise_project_id"`
	Status               string                  `json:"status"`
	EnableBandwidthRules bool                    `json:"enable_bandwidth_rules"`
	RuleQuota            int                     `json:"rule_quota"`
	BandwidthRules       []bandwidthRule         `json:"bandwidth_rules"`
	CreatedAt            string                  `json:"created_at"`
	UpdatedAt            string                  `json:"updated_at"`
	PublicBorderGroup    string                  `json:"public_border_group"`
}

type bandwidthResponse struct {
	Bandwidth bandwidthResp `json:"bandwidth"`
}

type listBandwidthsResponse struct {
	Bandwidths []bandwidthResp `json:"bandwidths"`
}

// updateBandwidthOption mirrors eip/v2 UpdateBandwidthOption.
type updateBandwidthOption struct {
	Name       *string `json:"name,omitempty"`
	Size       *int    `json:"size,omitempty"`
	ChargeMode *string `json:"charge_mode,omitempty"`
}

type updateBandwidthRequest struct {
	Bandwidth   *updateBandwidthOption `json:"bandwidth"`
	ExtendParam map[string]any         `json:"extendParam,omitempty"`
}

// createSharedBandwidthOption mirrors eip/v2 CreateSharedBandwidthOption.
type createSharedBandwidthOption struct {
	EnterpriseProjectID *string `json:"enterprise_project_id,omitempty"`
	Name                string  `json:"name"`
	Size                int     `json:"size"`
	ChargeMode          *string `json:"charge_mode,omitempty"`
	PublicBorderGroup   *string `json:"public_border_group,omitempty"`
	BandwidthType       *string `json:"bandwidth_type,omitempty"`
}

type createSharedBandwidthRequest struct {
	Bandwidth *createSharedBandwidthOption `json:"bandwidth"`
}

// insertPublicIPInfo mirrors eip/v2 InsertPublicipInfo.
type insertPublicIPInfo struct {
	PublicIPType *string `json:"publicip_type,omitempty"`
	PublicIPID   string  `json:"publicip_id"`
}

// addPublicIPsIntoSharedBandwidthOption mirrors eip/v2 AddPublicipsIntoSharedBandwidthOption.
type addPublicIPsIntoSharedBandwidthOption struct {
	PublicIPInfo []insertPublicIPInfo `json:"publicip_info"`
}

type addPublicIPsIntoSharedBandwidthRequest struct {
	Bandwidth *addPublicIPsIntoSharedBandwidthOption `json:"bandwidth"`
}

// removePublicIPInfo mirrors eip/v2 RemovePublicipInfo.
type removePublicIPInfo struct {
	PublicIPType *string `json:"publicip_type,omitempty"`
	PublicIPID   string  `json:"publicip_id"`
}

// removeFromSharedBandwidthOption mirrors eip/v2 RemoveFromSharedBandwidthOption.
type removeFromSharedBandwidthOption struct {
	ChargeMode   string               `json:"charge_mode"`
	PublicIPInfo []removePublicIPInfo `json:"publicip_info"`
	Size         int                  `json:"size"`
}

type removeFromSharedBandwidthRequest struct {
	Bandwidth *removeFromSharedBandwidthOption `json:"bandwidth"`
}

// --- §3.3 EIP tags (/v2.0/{project_id}/publicips) ---

type createPublicIPTagRequest struct {
	Tag *tag `json:"tag"`
}

type showPublicIPTagsResponse struct {
	Tags []tag `json:"tags"`
}

type batchPublicIPTagsRequest struct {
	Action string `json:"action"`
	Tags   []tag  `json:"tags"`
}

type tagFilter struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

type matchFilter struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type listPublicIPsByTagsRequest struct {
	Tags    []tagFilter   `json:"tags,omitempty"`
	Limit   any           `json:"limit,omitempty"`
	Offset  any           `json:"offset,omitempty"`
	Action  string        `json:"action"`
	Matches []matchFilter `json:"matches,omitempty"`
}

type taggedResource struct {
	ResourceDetail any    `json:"resource_detail"`
	ResourceID     string `json:"resource_id"`
	ResourceName   string `json:"resource_name"`
	Tags           []tag  `json:"tags"`
}

type listPublicIPsByTagsResponse struct {
	Resources  []taggedResource `json:"resources,omitempty"`
	TotalCount int              `json:"total_count"`
}

type projectTag struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

type listPublicIPTagsResponse struct {
	Tags []projectTag `json:"tags"`
}

// --- §3.4 EIPs, v3 (/v3/{project_id}/eip/publicips) ---

// vnicInfo mirrors eip/v3 VnicInfo.
type vnicInfo struct {
	PrivateIPAddress string `json:"private_ip_address,omitempty"`
	DeviceID         string `json:"device_id,omitempty"`
	DeviceOwner      string `json:"device_owner,omitempty"`
	VPCID            string `json:"vpc_id,omitempty"`
	PortID           string `json:"port_id,omitempty"`
	MAC              string `json:"mac,omitempty"`
}

// publicIPBandwidthInfo mirrors eip/v3 PublicipBandwidthInfo.
type publicIPBandwidthInfo struct {
	ID         string `json:"id,omitempty"`
	Size       int    `json:"size,omitempty"`
	ShareType  string `json:"share_type,omitempty"`
	ChargeMode string `json:"charge_mode,omitempty"`
	Name       string `json:"name,omitempty"`
}

// publicIPSingleShowResp mirrors eip/v3 PublicipSingleShowResp (§3.4).
type publicIPSingleShowResp struct {
	ID                    string                 `json:"id"`
	ProjectID             string                 `json:"project_id"`
	IPVersion             int                    `json:"ip_version"`
	PublicIPAddress       string                 `json:"public_ip_address"`
	NetworkType           string                 `json:"network_type"`
	Status                string                 `json:"status"`
	Description           string                 `json:"description"`
	PublicBorderGroup     string                 `json:"public_border_group"`
	CreatedAt             string                 `json:"created_at"`
	UpdatedAt             string                 `json:"updated_at"`
	Type                  string                 `json:"type"`
	Vnic                  *vnicInfo              `json:"vnic"`
	Bandwidth             *publicIPBandwidthInfo `json:"bandwidth"`
	EnterpriseProjectID   string                 `json:"enterprise_project_id"`
	BillingInfo           *string                `json:"billing_info"`
	LockStatus            string                 `json:"lock_status"`
	AssociateInstanceType *string                `json:"associate_instance_type"`
	AssociateInstanceID   *string                `json:"associate_instance_id"`
	PublicIPPoolID        *string                `json:"publicip_pool_id"`
	PublicIPPoolName      string                 `json:"publicip_pool_name"`
	Alias                 string                 `json:"alias"`
	Tags                  []string               `json:"tags,omitempty"`
}
