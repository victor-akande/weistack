package elb

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

// lsnOptField distinguishes an absent JSON key from an explicit null or value.
type lsnOptField[T any] struct {
	set  bool
	null bool
	val  T
}

func (o *lsnOptField[T]) UnmarshalJSON(data []byte) error {
	o.set = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		o.null = true
		var zero T
		o.val = zero
		return nil
	}
	return json.Unmarshal(data, &o.val)
}

type createListenerRequest struct {
	Listener *createListenerOption `json:"listener"`
}

type listenerPortRangeOption struct {
	StartPort *int `json:"start_port"`
	EndPort   *int `json:"end_port"`
}

type listenerIPGroupOption struct {
	IPGroupID     *string `json:"ipgroup_id"`
	EnableIPGroup *bool   `json:"enable_ipgroup"`
	Type          *string `json:"type"`
}

func (o *listenerIPGroupOption) toInput() *listenerIPGroupInput {
	if o == nil {
		return nil
	}
	empty := o.IPGroupID == nil && o.EnableIPGroup == nil && o.Type == nil
	return &listenerIPGroupInput{
		IPGroupID:     o.IPGroupID,
		EnableIPGroup: o.EnableIPGroup,
		Type:          o.Type,
		Empty:         empty,
	}
}

type createListenerOption struct {
	LoadBalancerID            string                    `json:"loadbalancer_id"`
	Name                      *string                   `json:"name"`
	Description               *string                   `json:"description"`
	Protocol                  string                    `json:"protocol"`
	ProtocolPort              *int                      `json:"protocol_port"`
	PortRanges                []listenerPortRangeOption `json:"port_ranges"`
	AdminStateUp              *bool                     `json:"admin_state_up"`
	DefaultPoolID             *string                   `json:"default_pool_id"`
	DefaultTLSContainerRef    *string                   `json:"default_tls_container_ref"`
	ClientCATLSContainerRef   *string                   `json:"client_ca_tls_container_ref"`
	SNIContainerRefs          []string                  `json:"sni_container_refs"`
	SNIMatchAlgo              *string                   `json:"sni_match_algo"`
	TLSCiphersPolicy          *string                   `json:"tls_ciphers_policy"`
	SecurityPolicyID          *string                   `json:"security_policy_id"`
	HTTP2Enable               *bool                     `json:"http2_enable"`
	InsertHeaders             *listenerInsertHeaders    `json:"insert_headers"`
	EnableMemberRetry         *bool                     `json:"enable_member_retry"`
	KeepaliveTimeout          *int                      `json:"keepalive_timeout"`
	ClientTimeout             *int                      `json:"client_timeout"`
	MemberTimeout             *int                      `json:"member_timeout"`
	IPGroup                   *listenerIPGroupOption    `json:"ipgroup"`
	TransparentClientIPEnable *bool                     `json:"transparent_client_ip_enable"`
	ProxyProtocolEnable       *bool                     `json:"proxy_protocol_enable"`
	EnhanceL7PolicyEnable     *bool                     `json:"enhance_l7policy_enable"`
	QuicConfig                *listenerQuicConfig       `json:"quic_config"`
	ProtectionStatus          *string                   `json:"protection_status"`
	ProtectionReason          *string                   `json:"protection_reason"`
	GzipEnable                *bool                     `json:"gzip_enable"`
	SSLEarlyDataEnable        *bool                     `json:"ssl_early_data_enable"`
	CPS                       *int                      `json:"cps"`
	Connection                *int                      `json:"connection"`
	Nat64Enable               *bool                     `json:"nat64_enable"`
	Tags                      []tag                     `json:"tags"`
}

type updateListenerRequest struct {
	Listener *updateListenerOption `json:"listener"`
}

type updateListenerOption struct {
	Name                      *string                             `json:"name"`
	Description               *string                             `json:"description"`
	AdminStateUp              *bool                               `json:"admin_state_up"`
	DefaultPoolID             lsnOptField[string]                 `json:"default_pool_id"`
	DefaultTLSContainerRef    lsnOptField[string]                 `json:"default_tls_container_ref"`
	ClientCATLSContainerRef   lsnOptField[string]                 `json:"client_ca_tls_container_ref"`
	SNIContainerRefs          lsnOptField[[]string]               `json:"sni_container_refs"`
	SNIMatchAlgo              *string                             `json:"sni_match_algo"`
	TLSCiphersPolicy          lsnOptField[string]                 `json:"tls_ciphers_policy"`
	SecurityPolicyID          lsnOptField[string]                 `json:"security_policy_id"`
	HTTP2Enable               *bool                               `json:"http2_enable"`
	InsertHeaders             lsnOptField[*listenerInsertHeaders] `json:"insert_headers"`
	EnableMemberRetry         *bool                               `json:"enable_member_retry"`
	KeepaliveTimeout          *int                                `json:"keepalive_timeout"`
	ClientTimeout             *int                                `json:"client_timeout"`
	MemberTimeout             *int                                `json:"member_timeout"`
	IPGroup                   lsnOptField[*listenerIPGroupOption] `json:"ipgroup"`
	TransparentClientIPEnable *bool                               `json:"transparent_client_ip_enable"`
	ProxyProtocolEnable       *bool                               `json:"proxy_protocol_enable"`
	EnhanceL7PolicyEnable     *bool                               `json:"enhance_l7policy_enable"`
	QuicConfig                lsnOptField[*listenerQuicConfig]    `json:"quic_config"`
	ProtectionStatus          *string                             `json:"protection_status"`
	ProtectionReason          *string                             `json:"protection_reason"`
	GzipEnable                *bool                               `json:"gzip_enable"`
	SSLEarlyDataEnable        *bool                               `json:"ssl_early_data_enable"`
	CPS                       *int                                `json:"cps"`
	Connection                *int                                `json:"connection"`
	Nat64Enable               *bool                               `json:"nat64_enable"`
}

// listenerWire matches SDK model Listener field-for-field.
type listenerWire struct {
	ID                        string                 `json:"id"`
	Name                      string                 `json:"name"`
	Description               string                 `json:"description"`
	Protocol                  string                 `json:"protocol"`
	ProtocolPort              int                    `json:"protocol_port"`
	PortRanges                []portRange            `json:"port_ranges,omitempty"`
	AdminStateUp              bool                   `json:"admin_state_up"`
	LoadBalancers             []idRef                `json:"loadbalancers"`
	DefaultPoolID             string                 `json:"default_pool_id"`
	DefaultTLSContainerRef    string                 `json:"default_tls_container_ref"`
	ClientCATLSContainerRef   string                 `json:"client_ca_tls_container_ref"`
	SNIContainerRefs          []string               `json:"sni_container_refs"`
	SNIMatchAlgo              string                 `json:"sni_match_algo"`
	TLSCiphersPolicy          string                 `json:"tls_ciphers_policy"`
	SecurityPolicyID          string                 `json:"security_policy_id"`
	HTTP2Enable               bool                   `json:"http2_enable"`
	InsertHeaders             *listenerInsertHeaders `json:"insert_headers"`
	EnableMemberRetry         bool                   `json:"enable_member_retry"`
	KeepaliveTimeout          int                    `json:"keepalive_timeout"`
	ClientTimeout             int                    `json:"client_timeout"`
	MemberTimeout             int                    `json:"member_timeout"`
	IPGroup                   *listenerIPGroup       `json:"ipgroup"`
	TransparentClientIPEnable bool                   `json:"transparent_client_ip_enable"`
	ProxyProtocolEnable       bool                   `json:"proxy_protocol_enable"`
	EnhanceL7PolicyEnable     bool                   `json:"enhance_l7policy_enable"`
	QuicConfig                *listenerQuicConfig    `json:"quic_config,omitempty"`
	ProtectionStatus          string                 `json:"protection_status"`
	ProtectionReason          string                 `json:"protection_reason"`
	GzipEnable                bool                   `json:"gzip_enable"`
	SSLEarlyDataEnable        bool                   `json:"ssl_early_data_enable"`
	CPS                       int                    `json:"cps"`
	Connection                int                    `json:"connection"`
	ConnectionLimit           int                    `json:"connection_limit"`
	Nat64Enable               bool                   `json:"nat64_enable"`
	ProjectID                 string                 `json:"project_id"`
	EnterpriseProjectID       string                 `json:"enterprise_project_id"`
	Tags                      []tag                  `json:"tags"`
	CreatedAt                 string                 `json:"created_at"`
	UpdatedAt                 string                 `json:"updated_at"`
}

type listenerEnvelope struct {
	RequestID string       `json:"request_id"`
	Listener  listenerWire `json:"listener"`
}

type listListenersResponse struct {
	RequestID string         `json:"request_id"`
	Listeners []listenerWire `json:"listeners"`
	PageInfo  pageInfo       `json:"page_info"`
}

func lsnDerefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func lsnNonEmpty(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func toListenerWire(t Tenant, l listener) listenerWire {
	sniRefs := make([]string, len(l.SNIContainerRefs))
	copy(sniRefs, l.SNIContainerRefs)

	tags := make([]tag, len(l.Tags))
	copy(tags, l.Tags)

	var ranges []portRange
	if len(l.PortRanges) > 0 {
		ranges = make([]portRange, len(l.PortRanges))
		copy(ranges, l.PortRanges)
	}

	protStatus := l.ProtectionStatus
	if protStatus == "" {
		protStatus = listenerDefaultProtectionStatus
	}
	connLimit := l.ConnectionLimit
	if connLimit == 0 {
		connLimit = listenerDefaultConnectionLimit
	}
	ep := l.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}

	return listenerWire{
		ID:                        l.ID,
		Name:                      l.Name,
		Description:               l.Description,
		Protocol:                  l.Protocol,
		ProtocolPort:              l.ProtocolPort,
		PortRanges:                ranges,
		AdminStateUp:              l.AdminStateUp,
		LoadBalancers:             []idRef{{ID: l.LoadBalancerID}},
		DefaultPoolID:             l.DefaultPoolID,
		DefaultTLSContainerRef:    l.DefaultTLSContainerRef,
		ClientCATLSContainerRef:   l.ClientCATLSContainerRef,
		SNIContainerRefs:          sniRefs,
		SNIMatchAlgo:              l.SNIMatchAlgo,
		TLSCiphersPolicy:          l.TLSCiphersPolicy,
		SecurityPolicyID:          l.SecurityPolicyID,
		HTTP2Enable:               l.HTTP2Enable,
		InsertHeaders:             cloneInsertHeaders(l.InsertHeaders),
		EnableMemberRetry:         l.EnableMemberRetry,
		KeepaliveTimeout:          l.KeepaliveTimeout,
		ClientTimeout:             l.ClientTimeout,
		MemberTimeout:             l.MemberTimeout,
		IPGroup:                   cloneListenerIPGroup(l.IPGroup),
		TransparentClientIPEnable: l.TransparentClientIPEnable,
		ProxyProtocolEnable:       l.ProxyProtocolEnable,
		EnhanceL7PolicyEnable:     l.EnhanceL7PolicyEnable,
		QuicConfig:                cloneQuicConfig(l.QuicConfig),
		ProtectionStatus:          protStatus,
		ProtectionReason:          l.ProtectionReason,
		GzipEnable:                l.GzipEnable,
		SSLEarlyDataEnable:        l.SSLEarlyDataEnable,
		CPS:                       l.CPS,
		Connection:                l.Connection,
		ConnectionLimit:           connLimit,
		Nat64Enable:               l.Nat64Enable,
		ProjectID:                 t.ProjectID,
		EnterpriseProjectID:       ep,
		Tags:                      tags,
		CreatedAt:                 formatTime(l.CreatedAt),
		UpdatedAt:                 formatTime(l.UpdatedAt),
	}
}

func (s *Service) handleCreateListener(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createListenerRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Listener == nil {
		return errInvalidInput("listener")
	}
	opt := req.Listener

	rangesValid := true
	var ranges []portRange
	if len(opt.PortRanges) > 0 {
		ranges = make([]portRange, 0, len(opt.PortRanges))
		for _, pr := range opt.PortRanges {
			if pr.StartPort == nil || pr.EndPort == nil {
				rangesValid = false
				break
			}
			ranges = append(ranges, portRange{StartPort: *pr.StartPort, EndPort: *pr.EndPort})
		}
	}

	rec, err := s.createListener(r.Context(), t, createListenerInput{
		LoadBalancerID:            opt.LoadBalancerID,
		Name:                      lsnDerefString(opt.Name),
		Description:               lsnDerefString(opt.Description),
		Protocol:                  opt.Protocol,
		ProtocolPort:              opt.ProtocolPort,
		PortRanges:                ranges,
		PortRangesValid:           rangesValid,
		AdminStateUp:              opt.AdminStateUp,
		DefaultPoolID:             lsnDerefString(opt.DefaultPoolID),
		DefaultTLSContainerRef:    lsnDerefString(opt.DefaultTLSContainerRef),
		ClientCATLSContainerRef:   lsnDerefString(opt.ClientCATLSContainerRef),
		SNIContainerRefs:          opt.SNIContainerRefs,
		SNIMatchAlgo:              lsnDerefString(opt.SNIMatchAlgo),
		TLSCiphersPolicy:          lsnDerefString(opt.TLSCiphersPolicy),
		SecurityPolicyID:          lsnDerefString(opt.SecurityPolicyID),
		HTTP2Enable:               opt.HTTP2Enable,
		InsertHeaders:             opt.InsertHeaders,
		EnableMemberRetry:         opt.EnableMemberRetry,
		KeepaliveTimeout:          opt.KeepaliveTimeout,
		ClientTimeout:             opt.ClientTimeout,
		MemberTimeout:             opt.MemberTimeout,
		IPGroup:                   opt.IPGroup.toInput(),
		TransparentClientIPEnable: opt.TransparentClientIPEnable,
		ProxyProtocolEnable:       opt.ProxyProtocolEnable,
		EnhanceL7PolicyEnable:     opt.EnhanceL7PolicyEnable,
		QuicConfig:                opt.QuicConfig,
		ProtectionStatus:          lsnDerefString(opt.ProtectionStatus),
		ProtectionReason:          lsnDerefString(opt.ProtectionReason),
		GzipEnable:                opt.GzipEnable,
		SSLEarlyDataEnable:        opt.SSLEarlyDataEnable,
		CPS:                       opt.CPS,
		Connection:                opt.Connection,
		Nat64Enable:               opt.Nat64Enable,
		Tags:                      opt.Tags,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, listenerEnvelope{
		RequestID: requestID(r),
		Listener:  toListenerWire(t, rec),
	})
}

func (s *Service) handleListListeners(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	if _, err := parseBoolQuery(q, "page_reverse"); err != nil {
		return err
	}
	if _, err := parseBoolQuery(q, "include_recycle_bin"); err != nil {
		return err
	}

	adminStateUp, err := parseBoolQuery(q, "admin_state_up")
	if err != nil {
		return err
	}
	http2Enable, err := parseBoolQuery(q, "http2_enable")
	if err != nil {
		return err
	}
	enableMemberRetry, err := parseBoolQuery(q, "enable_member_retry")
	if err != nil {
		return err
	}
	transparentClientIP, err := parseBoolQuery(q, "transparent_client_ip_enable")
	if err != nil {
		return err
	}
	proxyProtocol, err := parseBoolQuery(q, "proxy_protocol_enable")
	if err != nil {
		return err
	}
	enhanceL7, err := parseBoolQuery(q, "enhance_l7policy_enable")
	if err != nil {
		return err
	}
	sslEarlyData, err := parseBoolQuery(q, "ssl_early_data_enable")
	if err != nil {
		return err
	}
	nat64, err := parseBoolQuery(q, "nat64_enable")
	if err != nil {
		return err
	}

	connectionLimits, err := parseIntQueryValues(q, "connection_limit")
	if err != nil {
		return err
	}
	memberTimeouts, err := parseIntQueryValues(q, "member_timeout")
	if err != nil {
		return err
	}
	clientTimeouts, err := parseIntQueryValues(q, "client_timeout")
	if err != nil {
		return err
	}
	keepaliveTimeouts, err := parseIntQueryValues(q, "keepalive_timeout")
	if err != nil {
		return err
	}

	items, pi, err := s.listListeners(r.Context(), t, listListenersFilter{
		IDs:                       lsnNonEmpty(q["id"]),
		Names:                     lsnNonEmpty(q["name"]),
		Descriptions:              lsnNonEmpty(q["description"]),
		Protocols:                 lsnNonEmpty(q["protocol"]),
		ProtocolPorts:             lsnNonEmpty(q["protocol_port"]),
		DefaultTLSContainerRefs:   lsnNonEmpty(q["default_tls_container_ref"]),
		ClientCATLSContainerRefs:  lsnNonEmpty(q["client_ca_tls_container_ref"]),
		DefaultPoolIDs:            lsnNonEmpty(q["default_pool_id"]),
		LoadBalancerIDs:           lsnNonEmpty(q["loadbalancer_id"]),
		TLSCiphersPolicies:        lsnNonEmpty(q["tls_ciphers_policy"]),
		EnterpriseProjectIDs:      lsnNonEmpty(q["enterprise_project_id"]),
		ProtectionStatuses:        lsnNonEmpty(q["protection_status"]),
		MemberAddresses:           lsnNonEmpty(q["member_address"]),
		MemberDeviceIDs:           lsnNonEmpty(q["member_device_id"]),
		MemberInstanceIDs:         lsnNonEmpty(q["member_instance_id"]),
		ConnectionLimits:          connectionLimits,
		MemberTimeouts:            memberTimeouts,
		ClientTimeouts:            clientTimeouts,
		KeepaliveTimeouts:         keepaliveTimeouts,
		AdminStateUp:              adminStateUp,
		HTTP2Enable:               http2Enable,
		EnableMemberRetry:         enableMemberRetry,
		TransparentClientIPEnable: transparentClientIP,
		ProxyProtocolEnable:       proxyProtocol,
		EnhanceL7PolicyEnable:     enhanceL7,
		SSLEarlyDataEnable:        sslEarlyData,
		Nat64Enable:               nat64,
		Page:                      page,
	})
	if err != nil {
		return err
	}
	out := make([]listenerWire, 0, len(items))
	for _, item := range items {
		out = append(out, toListenerWire(t, item))
	}
	return httpx.WriteJSON(w, http.StatusOK, listListenersResponse{
		RequestID: requestID(r),
		Listeners: out,
		PageInfo:  pi,
	})
}

func (s *Service) handleShowListener(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "listener_id")
	rec, err := s.getListener(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, listenerEnvelope{
		RequestID: requestID(r),
		Listener:  toListenerWire(t, rec),
	})
}

func (s *Service) handleUpdateListener(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateListenerRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Listener == nil {
		return errInvalidInput("listener")
	}
	opt := req.Listener
	id := chi.URLParam(r, "listener_id")

	var ipgInput *listenerIPGroupInput
	if opt.IPGroup.set && !opt.IPGroup.null {
		ipgInput = opt.IPGroup.val.toInput()
	}
	var insertHeaders *listenerInsertHeaders
	if opt.InsertHeaders.set && !opt.InsertHeaders.null {
		insertHeaders = opt.InsertHeaders.val
	}
	var quicConfig *listenerQuicConfig
	if opt.QuicConfig.set && !opt.QuicConfig.null {
		quicConfig = opt.QuicConfig.val
	}

	rec, err := s.updateListener(r.Context(), t, id, updateListenerInput{
		Name:                      opt.Name,
		Description:               opt.Description,
		AdminStateUp:              opt.AdminStateUp,
		DefaultPoolIDSet:          opt.DefaultPoolID.set,
		DefaultPoolID:             opt.DefaultPoolID.val,
		DefaultTLSRefSet:          opt.DefaultTLSContainerRef.set,
		DefaultTLSRef:             opt.DefaultTLSContainerRef.val,
		ClientCATLSRefSet:         opt.ClientCATLSContainerRef.set,
		ClientCATLSRef:            opt.ClientCATLSContainerRef.val,
		SNIContainerRefsSet:       opt.SNIContainerRefs.set,
		SNIContainerRefs:          opt.SNIContainerRefs.val,
		SNIMatchAlgo:              opt.SNIMatchAlgo,
		TLSCiphersPolicySet:       opt.TLSCiphersPolicy.set,
		TLSCiphersPolicy:          opt.TLSCiphersPolicy.val,
		SecurityPolicyIDSet:       opt.SecurityPolicyID.set,
		SecurityPolicyID:          opt.SecurityPolicyID.val,
		HTTP2Enable:               opt.HTTP2Enable,
		InsertHeadersSet:          opt.InsertHeaders.set,
		InsertHeaders:             insertHeaders,
		EnableMemberRetry:         opt.EnableMemberRetry,
		KeepaliveTimeout:          opt.KeepaliveTimeout,
		ClientTimeout:             opt.ClientTimeout,
		MemberTimeout:             opt.MemberTimeout,
		IPGroupSet:                opt.IPGroup.set,
		IPGroup:                   ipgInput,
		TransparentClientIPEnable: opt.TransparentClientIPEnable,
		ProxyProtocolEnable:       opt.ProxyProtocolEnable,
		EnhanceL7PolicyEnable:     opt.EnhanceL7PolicyEnable,
		QuicConfigSet:             opt.QuicConfig.set,
		QuicConfig:                quicConfig,
		ProtectionStatus:          opt.ProtectionStatus,
		ProtectionReason:          opt.ProtectionReason,
		GzipEnable:                opt.GzipEnable,
		SSLEarlyDataEnable:        opt.SSLEarlyDataEnable,
		CPS:                       opt.CPS,
		Connection:                opt.Connection,
		Nat64Enable:               opt.Nat64Enable,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, listenerEnvelope{
		RequestID: requestID(r),
		Listener:  toListenerWire(t, rec),
	})
}

func (s *Service) handleDeleteListener(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "listener_id")
	if err := s.deleteListener(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleDeleteListenerForce(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "listener_id")
	if err := s.deleteListenerForce(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
