package elb

import "time"

// tag is a resource key/value tag.
type tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// idRef is a single-field {"id": "..."} reference used across ELB responses.
type idRef struct {
	ID string `json:"id"`
}

// pageInfo is the ELB v3 pagination trailer.
type pageInfo struct {
	PreviousMarker string  `json:"previous_marker"`
	NextMarker     *string `json:"next_marker,omitempty"`
	CurrentCount   int     `json:"current_count"`
}

// eipInfoWire matches SDK model EipInfo.
type eipInfoWire struct {
	EIPID      string `json:"eip_id"`
	EIPAddress string `json:"eip_address"`
	IPVersion  int    `json:"ip_version"`
}

// publicIPInfoWire matches SDK model PublicIpInfo.
type publicIPInfoWire struct {
	PublicIPID      string `json:"publicip_id"`
	PublicIPAddress string `json:"publicip_address"`
	IPVersion       int    `json:"ip_version"`
}

// autoscalingRef matches SDK model AutoscalingRef.
type autoscalingRef struct {
	Enable        bool    `json:"enable"`
	MinL7FlavorID *string `json:"min_l7_flavor_id,omitempty"`
}

// loadBalancer is the stored record for kind elb.loadbalancer (§2, §3.1).
type loadBalancer struct {
	ID                       string          `json:"id"`
	Name                     string          `json:"name"`
	Description              string          `json:"description"`
	AdminStateUp             bool            `json:"admin_state_up"`
	Provider                 string          `json:"provider"`
	VPCID                    string          `json:"vpc_id"`
	VIPSubnetCIDRID          string          `json:"vip_subnet_cidr_id"`
	VIPSubnetID              string          `json:"vip_subnet_id"` // VPC subnet ID for IPAM
	VIPAddress               string          `json:"vip_address"`
	VIPPortID                string          `json:"vip_port_id"`
	ELBVirsubnetIDs          []string        `json:"elb_virsubnet_ids"`
	AvailabilityZoneList     []string        `json:"availability_zone_list"`
	L4FlavorID               string          `json:"l4_flavor_id"`
	L7FlavorID               string          `json:"l7_flavor_id"`
	Guaranteed               bool            `json:"guaranteed"`
	IPTargetEnable           bool            `json:"ip_target_enable"`
	DeletionProtectionEnable bool            `json:"deletion_protection_enable"`
	EnterpriseProjectID      string          `json:"enterprise_project_id"`
	EIPIDs                   []string        `json:"eip_ids"`
	Autoscaling              *autoscalingRef `json:"autoscaling,omitempty"`
	WafFailureAction         string          `json:"waf_failure_action,omitempty"`
	ProtectionStatus         string          `json:"protection_status,omitempty"`
	ProtectionReason         string          `json:"protection_reason,omitempty"`
	Tags                     []tag           `json:"tags"`
	CreatedAt                time.Time       `json:"created_at"`
	UpdatedAt                time.Time       `json:"updated_at"`
}

// listenerInsertHeaders matches SDK model ListenerInsertHeaders.
type listenerInsertHeaders struct {
	XForwardedELBIP            *bool   `json:"X-Forwarded-ELB-IP,omitempty"`
	XForwardedPort             *bool   `json:"X-Forwarded-Port,omitempty"`
	XForwardedForPort          *bool   `json:"X-Forwarded-For-Port,omitempty"`
	XForwardedHost             *bool   `json:"X-Forwarded-Host,omitempty"`
	XForwardedProto            *bool   `json:"X-Forwarded-Proto,omitempty"`
	XRealIP                    *bool   `json:"X-Real-IP,omitempty"`
	XForwardedELBID            *bool   `json:"X-Forwarded-ELB-ID,omitempty"`
	XForwardedTLSCertificateID *bool   `json:"X-Forwarded-TLS-Certificate-ID,omitempty"`
	XForwardedTLSProtocol      *bool   `json:"X-Forwarded-TLS-Protocol,omitempty"`
	XForwardedTLSCipher        *bool   `json:"X-Forwarded-TLS-Cipher,omitempty"`
	XForwardedTLSProtocolAlias *string `json:"X-Forwarded-TLS-Protocol-alias,omitempty"`
	XForwardedTLSCipherAlias   *string `json:"X-Forwarded-TLS-Cipher-alias,omitempty"`
}

// listenerIPGroup matches SDK model ListenerIpGroup.
type listenerIPGroup struct {
	IPGroupID     string `json:"ipgroup_id"`
	EnableIPGroup bool   `json:"enable_ipgroup"`
	Type          string `json:"type"`
}

// listenerQuicConfig matches SDK model ListenerQuicConfig.
type listenerQuicConfig struct {
	QuicListenerID    *string `json:"quic_listener_id,omitempty"`
	EnableQuicUpgrade *bool   `json:"enable_quic_upgrade,omitempty"`
}

// portRange matches SDK model PortRange.
type portRange struct {
	StartPort int `json:"start_port"`
	EndPort   int `json:"end_port"`
}

// listener is the stored record for kind elb.listener (§2, §3.2).
type listener struct {
	ID                        string                 `json:"id"`
	LoadBalancerID            string                 `json:"loadbalancer_id"`
	Name                      string                 `json:"name"`
	Description               string                 `json:"description"`
	Protocol                  string                 `json:"protocol"`
	ProtocolPort              int                    `json:"protocol_port"`
	PortRanges                []portRange            `json:"port_ranges,omitempty"`
	AdminStateUp              bool                   `json:"admin_state_up"`
	DefaultPoolID             string                 `json:"default_pool_id"`
	DefaultTLSContainerRef    string                 `json:"default_tls_container_ref"`
	ClientCATLSContainerRef   string                 `json:"client_ca_tls_container_ref"`
	SNIContainerRefs          []string               `json:"sni_container_refs"`
	SNIMatchAlgo              string                 `json:"sni_match_algo"`
	TLSCiphersPolicy          string                 `json:"tls_ciphers_policy"`
	SecurityPolicyID          string                 `json:"security_policy_id"`
	HTTP2Enable               bool                   `json:"http2_enable"`
	InsertHeaders             *listenerInsertHeaders `json:"insert_headers,omitempty"`
	EnableMemberRetry         bool                   `json:"enable_member_retry"`
	KeepaliveTimeout          int                    `json:"keepalive_timeout"`
	ClientTimeout             int                    `json:"client_timeout"`
	MemberTimeout             int                    `json:"member_timeout"`
	IPGroup                   *listenerIPGroup       `json:"ipgroup,omitempty"`
	TransparentClientIPEnable bool                   `json:"transparent_client_ip_enable"`
	ProxyProtocolEnable       bool                   `json:"proxy_protocol_enable"`
	EnhanceL7PolicyEnable     bool                   `json:"enhance_l7policy_enable"`
	QuicConfig                *listenerQuicConfig    `json:"quic_config,omitempty"`
	ProtectionStatus          string                 `json:"protection_status,omitempty"`
	ProtectionReason          string                 `json:"protection_reason,omitempty"`
	GzipEnable                bool                   `json:"gzip_enable"`
	SSLEarlyDataEnable        bool                   `json:"ssl_early_data_enable"`
	CPS                       int                    `json:"cps,omitempty"`
	Connection                int                    `json:"connection,omitempty"`
	ConnectionLimit           int                    `json:"connection_limit"`
	Nat64Enable               bool                   `json:"nat64_enable"`
	EnterpriseProjectID       string                 `json:"enterprise_project_id"`
	Tags                      []tag                  `json:"tags"`
	CreatedAt                 time.Time              `json:"created_at"`
	UpdatedAt                 time.Time              `json:"updated_at"`
}

// sessionPersistence matches SDK model SessionPersistence.
type sessionPersistence struct {
	Type               string  `json:"type"`
	CookieName         *string `json:"cookie_name,omitempty"`
	PersistenceTimeout *int    `json:"persistence_timeout,omitempty"`
}

// slowStart matches SDK model SlowStart.
type slowStart struct {
	Enable   bool `json:"enable"`
	Duration int  `json:"duration"`
}

// connectionDrain matches SDK model ConnectionDrain.
type connectionDrain struct {
	Enable  *bool `json:"enable,omitempty"`
	Timeout *int  `json:"timeout,omitempty"`
}

// poolHealth matches SDK model PoolHealth.
type poolHealth struct {
	MinimumHealthyMemberCount *int `json:"minimum_healthy_member_count,omitempty"`
}

// azAffinity matches SDK model AzAffinity.
type azAffinity struct {
	Enable            bool   `json:"enable"`
	AzMinimumHealthy  int    `json:"az_minimum_healthy_member_percentage,omitempty"`
	UnhealthyFallback string `json:"az_unhealthy_fallback_strategy,omitempty"`
}

// quicCidHashStrategy matches SDK model QuicCidHashStrategy.
type quicCidHashStrategy struct {
	Len    int `json:"len"`
	Offset int `json:"offset"`
}

// pool is the stored record for kind elb.pool (§2, §3.3).
type pool struct {
	ID                             string               `json:"id"`
	Name                           string               `json:"name"`
	Description                    string               `json:"description"`
	Protocol                       string               `json:"protocol"`
	LBAlgorithm                    string               `json:"lb_algorithm"`
	AdminStateUp                   bool                 `json:"admin_state_up"`
	LoadBalancerID                 string               `json:"loadbalancer_id"`
	VPCID                          string               `json:"vpc_id"`
	Type                           string               `json:"type"`
	IPVersion                      string               `json:"ip_version"`
	HealthMonitorID                string               `json:"healthmonitor_id"`
	SessionPersistence             *sessionPersistence  `json:"session_persistence,omitempty"`
	SlowStart                      *slowStart           `json:"slow_start,omitempty"`
	ConnectionDrain                *connectionDrain     `json:"connection_drain,omitempty"`
	PoolHealth                     *poolHealth          `json:"pool_health,omitempty"`
	AzAffinity                     *azAffinity          `json:"az_affinity,omitempty"`
	QuicCidHashStrategy            *quicCidHashStrategy `json:"quic_cid_hash_strategy,omitempty"`
	MemberDeletionProtectionEnable bool                 `json:"member_deletion_protection_enable"`
	AnyPortEnable                  bool                 `json:"any_port_enable"`
	ProtectionStatus               string               `json:"protection_status,omitempty"`
	ProtectionReason               string               `json:"protection_reason,omitempty"`
	EnterpriseProjectID            string               `json:"enterprise_project_id"`
	CreatedAt                      time.Time            `json:"created_at"`
	UpdatedAt                      time.Time            `json:"updated_at"`
}

// member is the stored record for kind elb.member (§2, §3.4).
type member struct {
	ID               string    `json:"id"`
	PoolID           string    `json:"pool_id"`
	Name             string    `json:"name"`
	Address          string    `json:"address"`
	ProtocolPort     int       `json:"protocol_port"`
	SubnetCIDRID     string    `json:"subnet_cidr_id"` // neutron_subnet_id (empty for IP members)
	SubnetID         string    `json:"subnet_id"`      // VPC subnet ID (empty for IP members)
	MemberType       string    `json:"member_type"`    // "instance" or "ip"
	Weight           int       `json:"weight"`
	AdminStateUp     bool      `json:"admin_state_up"`
	AvailabilityZone string    `json:"availability_zone"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// memberStatusWire matches SDK model MemberStatus.
type memberStatusWire struct {
	ListenerID      string `json:"listener_id"`
	OperatingStatus string `json:"operating_status"`
}

// healthMonitor is the stored record for kind elb.healthmonitor (§2, §3.6).
type healthMonitor struct {
	ID             string    `json:"id"`
	PoolID         string    `json:"pool_id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Delay          int       `json:"delay"`
	Timeout        int       `json:"timeout"`
	MaxRetries     int       `json:"max_retries"`
	MaxRetriesDown int       `json:"max_retries_down"`
	MonitorPort    int       `json:"monitor_port"`
	HTTPMethod     string    `json:"http_method"`
	URLPath        string    `json:"url_path"`
	ExpectedCodes  string    `json:"expected_codes"`
	DomainName     string    `json:"domain_name"`
	AdminStateUp   bool      `json:"admin_state_up"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// certificate is the stored record for kind elb.certificate (§2, §3.7).
type certificate struct {
	ID                      string    `json:"id"`
	Name                    string    `json:"name"`
	Description             string    `json:"description"`
	Type                    string    `json:"type"`
	Domain                  string    `json:"domain"`
	Certificate             string    `json:"certificate"`
	SealedPrivateKey        []byte    `json:"sealed_private_key,omitempty"`
	AdminStateUp            bool      `json:"admin_state_up"`
	CommonName              string    `json:"common_name"`
	Fingerprint             string    `json:"fingerprint"`
	SubjectAlternativeNames []string  `json:"subject_alternative_names"`
	ExpireTime              time.Time `json:"expire_time"`
	EnterpriseProjectID     string    `json:"enterprise_project_id"`
	ProtectionStatus        string    `json:"protection_status,omitempty"`
	ProtectionReason        string    `json:"protection_reason,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// redirectURLConfig matches SDK model RedirectUrlConfig.
type redirectURLConfig struct {
	Protocol   string `json:"protocol,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       string `json:"port,omitempty"`
	Path       string `json:"path,omitempty"`
	Query      string `json:"query,omitempty"`
	StatusCode string `json:"status_code,omitempty"`
}

// fixedResponseConfig matches SDK model FixtedResponseConfig.
type fixedResponseConfig struct {
	StatusCode  string `json:"status_code"`
	ContentType string `json:"content_type"`
	MessageBody string `json:"message_body"`
}

// redirectPoolsConfig matches SDK model RedirectPoolsConfig.
type redirectPoolsConfig struct {
	PoolID string `json:"pool_id"`
	Weight int    `json:"weight"`
}

// l7Policy is the stored record for kind elb.l7policy (§2, §3.8).
type l7Policy struct {
	ID                  string                `json:"id"`
	ListenerID          string                `json:"listener_id"`
	Name                string                `json:"name"`
	Description         string                `json:"description"`
	Action              string                `json:"action"`
	AdminStateUp        bool                  `json:"admin_state_up"`
	Position            int                   `json:"position"`
	Priority            *int                  `json:"priority,omitempty"`
	RedirectPoolID      string                `json:"redirect_pool_id"`
	RedirectListenerID  string                `json:"redirect_listener_id"`
	RedirectURL         string                `json:"redirect_url"`
	RedirectURLConfig   *redirectURLConfig    `json:"redirect_url_config,omitempty"`
	RedirectPoolsConfig []redirectPoolsConfig `json:"redirect_pools_config,omitempty"`
	FixedResponseConfig *fixedResponseConfig  `json:"fixed_response_config,omitempty"`
	EnterpriseProjectID string                `json:"enterprise_project_id"`
	CreatedAt           time.Time             `json:"created_at"`
	UpdatedAt           time.Time             `json:"updated_at"`
}

// ruleCondition matches SDK model RuleCondition.
type ruleCondition struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// l7Rule is the stored record for kind elb.l7rule (§2, §3.8).
type l7Rule struct {
	ID           string          `json:"id"`
	PolicyID     string          `json:"policy_id"`
	Type         string          `json:"type"`
	CompareType  string          `json:"compare_type"`
	Key          string          `json:"key"`
	Value        string          `json:"value"`
	AdminStateUp bool            `json:"admin_state_up"`
	Invert       bool            `json:"invert"`
	Conditions   []ruleCondition `json:"conditions"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// ipInfo matches SDK model IpInfo.
type ipInfo struct {
	IP          string `json:"ip"`
	Description string `json:"description"`
}

// ipGroup is the stored record for kind elb.ipgroup (§2, §3.9).
type ipGroup struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	IPList              []ipInfo  `json:"ip_list"`
	EnterpriseProjectID string    `json:"enterprise_project_id"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// securityPolicy is the stored record for kind elb.securitypolicy (§2, §3.9).
type securityPolicy struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	Protocols           []string  `json:"protocols"`
	Ciphers             []string  `json:"ciphers"`
	EnterpriseProjectID string    `json:"enterprise_project_id"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// flavorInfo matches SDK model FlavorInfo.
type flavorInfo struct {
	Connection int  `json:"connection"`
	CPS        int  `json:"cps"`
	QPS        *int `json:"qps,omitempty"`
	Bandwidth  *int `json:"bandwidth,omitempty"`
	LCU        *int `json:"lcu,omitempty"`
	HTTPSCPS   *int `json:"https_cps,omitempty"`
}

// flavorWire matches SDK model Flavor.
type flavorWire struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Type              string     `json:"type"`
	Shared            bool       `json:"shared"`
	ProjectID         string     `json:"project_id"`
	Info              flavorInfo `json:"info"`
	FlavorSoldOut     bool       `json:"flavor_sold_out"`
	PublicBorderGroup string     `json:"public_border_group"`
	Category          int        `json:"category"`
}

// availabilityZoneWire matches SDK model AvailabilityZone.
type availabilityZoneWire struct {
	Code              string   `json:"code"`
	State             string   `json:"state"`
	Protocol          []string `json:"protocol"`
	PublicBorderGroup string   `json:"public_border_group"`
	Category          int      `json:"category"`
	SpecCode          *string  `json:"spec_code"`
}

// systemSecurityPolicyWire matches SDK model SystemSecurityPolicy.
type systemSecurityPolicyWire struct {
	Name      string `json:"name"`
	Protocols string `json:"protocols"`
	Ciphers   string `json:"ciphers"`
	ProjectID string `json:"project_id"`
}
