package nat

import "time"

// tag is a key-value pair on a NAT resource.
type tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// sessionConf holds a public NAT gateway's session timeouts.
type sessionConf struct {
	TCPSessionExpireTime  int `json:"tcp_session_expire_time"`
	UDPSessionExpireTime  int `json:"udp_session_expire_time"`
	ICMPSessionExpireTime int `json:"icmp_session_expire_time"`
	TCPTimeWaitTime       int `json:"tcp_time_wait_time"`
}

// defaultSessionConf are the default timeouts documented on CreateNatGateway.
var defaultSessionConf = sessionConf{
	TCPSessionExpireTime:  900,
	UDPSessionExpireTime:  300,
	ICMPSessionExpireTime: 10,
	TCPTimeWaitTime:       5,
}

// gateway is the stored record for a public NAT gateway (kind nat.gateway).
type gateway struct {
	ID                  string      `json:"id"`
	Name                string      `json:"name"`
	Description         string      `json:"description"`
	Spec                string      `json:"spec"`
	Status              string      `json:"status"`
	RouterID            string      `json:"router_id"`
	InternalNetworkID   string      `json:"internal_network_id"`
	NgportIP            string      `json:"ngport_ip"`
	EnterpriseProjectID string      `json:"enterprise_project_id"`
	Session             sessionConf `json:"session"`
	Tags                []tag       `json:"tags"`
	CreatedAt           time.Time   `json:"created_at"`
}

// snatRule is the stored record for a public SNAT rule (kind nat.snat).
type snatRule struct {
	ID            string    `json:"id"`
	GatewayID     string    `json:"gateway_id"`
	NetworkID     string    `json:"network_id"`
	CIDR          string    `json:"cidr"`
	SourceType    int       `json:"source_type"`
	FloatingIPIDs []string  `json:"floating_ip_ids"`
	Description   string    `json:"description"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

// dnatRule is the stored record for a public DNAT rule (kind nat.dnat).
type dnatRule struct {
	ID            string    `json:"id"`
	GatewayID     string    `json:"gateway_id"`
	PortID        string    `json:"port_id"`
	PrivateIP     string    `json:"private_ip"`
	Protocol      string    `json:"protocol"`
	InternalPort  int       `json:"internal_port"`
	ExternalPort  int       `json:"external_port"`
	InternalRange string    `json:"internal_range"`
	ExternalRange string    `json:"external_range"`
	FloatingIPID  string    `json:"floating_ip_id"`
	Description   string    `json:"description"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

// privateGateway is the stored record for a private NAT gateway (kind nat.private-gateway).
type privateGateway struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	Spec                string    `json:"spec"`
	VPCID               string    `json:"vpc_id"`
	SubnetID            string    `json:"subnet_id"`
	NgportIP            string    `json:"ngport_ip"`
	EnterpriseProjectID string    `json:"enterprise_project_id"`
	Tags                []tag     `json:"tags"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// transitSubnet is the stored record for a transit subnet (kind nat.transit-subnet).
type transitSubnet struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	SubnetID    string    `json:"subnet_id"`
	VPCID       string    `json:"vpc_id"`
	CIDR        string    `json:"cidr"`
	Tags        []tag     `json:"tags"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// transitIP is the stored record for a transit IP (kind nat.transit-ip).
type transitIP struct {
	ID                  string    `json:"id"`
	SubnetID            string    `json:"subnet_id"`
	Address             string    `json:"address"`
	NetworkInterfaceID  string    `json:"network_interface_id"`
	GatewayID           string    `json:"gateway_id"`
	EnterpriseProjectID string    `json:"enterprise_project_id"`
	Tags                []tag     `json:"tags"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// privateSnat is the stored record for a private SNAT rule (kind nat.private-snat).
type privateSnat struct {
	ID           string    `json:"id"`
	GatewayID    string    `json:"gateway_id"`
	CIDR         string    `json:"cidr"`
	SubnetID     string    `json:"subnet_id"`
	TransitIPIDs []string  `json:"transit_ip_ids"`
	Description  string    `json:"description"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// privateDnat is the stored record for a private DNAT rule (kind nat.private-dnat).
type privateDnat struct {
	ID                 string    `json:"id"`
	GatewayID          string    `json:"gateway_id"`
	TransitIPID        string    `json:"transit_ip_id"`
	NetworkInterfaceID string    `json:"network_interface_id"`
	PrivateIP          string    `json:"private_ip"`
	Type               string    `json:"type"`
	Protocol           string    `json:"protocol"`
	InternalPort       string    `json:"internal_port"`
	TransitPort        string    `json:"transit_port"`
	Description        string    `json:"description"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// privateSpec defines the documented limits for each private NAT spec (§2).
type privateSpec struct {
	Name    string `json:"name"`
	Code    string `json:"code"`
	CBCCode string `json:"cbc_code"`
	RuleMax int    `json:"rule_max"`
	SessMax int    `json:"sess_max"`
	BpsMax  int    `json:"bps_max"`
	PpsMax  int    `json:"pps_max"`
	QpsMax  int    `json:"qps_max"`
}

var privateSpecs = []privateSpec{
	{Name: "Small", Code: "1", CBCCode: "privatenat_small", RuleMax: 20, SessMax: 2000, BpsMax: 233, PpsMax: 20000, QpsMax: 6000},
	{Name: "Medium", Code: "2", CBCCode: "privatenat_medium", RuleMax: 50, SessMax: 5000, BpsMax: 584, PpsMax: 50000, QpsMax: 9000},
	{Name: "Large", Code: "3", CBCCode: "privatenat_large", RuleMax: 200, SessMax: 20000, BpsMax: 2336, PpsMax: 200000, QpsMax: 10000},
	{Name: "Extra-large", Code: "4", CBCCode: "privatenat_xlarge", RuleMax: 500, SessMax: 50000, BpsMax: 5840, PpsMax: 500000, QpsMax: 10000},
	{Name: "Extra-xlarge", Code: "5", CBCCode: "privatenat_xxlarge", RuleMax: 5000, SessMax: 500000, BpsMax: 58400, PpsMax: 5000000, QpsMax: 100000},
}

// pageInfo mirrors the private NAT pagination response object (§3).
type pageInfo struct {
	NextMarker     string `json:"next_marker,omitempty"`
	PreviousMarker string `json:"previous_marker,omitempty"`
	CurrentCount   int    `json:"current_count"`
}
