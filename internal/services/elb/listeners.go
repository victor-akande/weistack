package elb

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	listenerDefaultTLSCiphersPolicy = "tls-1-2"
	listenerDefaultSNIMatchAlgo     = "wildcard"
	listenerDefaultProtectionStatus = "nonProtection"
	listenerDefaultConnectionLimit  = -1
	listenerMaxPortRanges           = 10
	listenerMaxSNICerts             = 50
	listenerMaxRateLimit            = 1000000
)

var listenerHeaderAliasRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

type createListenerInput struct {
	LoadBalancerID            string
	Name                      string
	Description               string
	Protocol                  string
	ProtocolPort              *int
	PortRanges                []portRange
	PortRangesValid           bool
	AdminStateUp              *bool
	DefaultPoolID             string
	DefaultTLSContainerRef    string
	ClientCATLSContainerRef   string
	SNIContainerRefs          []string
	SNIMatchAlgo              string
	TLSCiphersPolicy          string
	SecurityPolicyID          string
	HTTP2Enable               *bool
	InsertHeaders             *listenerInsertHeaders
	EnableMemberRetry         *bool
	KeepaliveTimeout          *int
	ClientTimeout             *int
	MemberTimeout             *int
	IPGroup                   *listenerIPGroupInput
	TransparentClientIPEnable *bool
	ProxyProtocolEnable       *bool
	EnhanceL7PolicyEnable     *bool
	QuicConfig                *listenerQuicConfig
	ProtectionStatus          string
	ProtectionReason          string
	GzipEnable                *bool
	SSLEarlyDataEnable        *bool
	CPS                       *int
	Connection                *int
	Nat64Enable               *bool
	Tags                      []tag
}

type listenerIPGroupInput struct {
	IPGroupID     *string
	EnableIPGroup *bool
	Type          *string
	Empty         bool
}

type updateListenerInput struct {
	Name                      *string
	Description               *string
	AdminStateUp              *bool
	DefaultPoolIDSet          bool
	DefaultPoolID             string
	DefaultTLSRefSet          bool
	DefaultTLSRef             string
	ClientCATLSRefSet         bool
	ClientCATLSRef            string
	SNIContainerRefsSet       bool
	SNIContainerRefs          []string
	SNIMatchAlgo              *string
	TLSCiphersPolicySet       bool
	TLSCiphersPolicy          string
	SecurityPolicyIDSet       bool
	SecurityPolicyID          string
	HTTP2Enable               *bool
	InsertHeadersSet          bool
	InsertHeaders             *listenerInsertHeaders
	EnableMemberRetry         *bool
	KeepaliveTimeout          *int
	ClientTimeout             *int
	MemberTimeout             *int
	IPGroupSet                bool
	IPGroup                   *listenerIPGroupInput
	TransparentClientIPEnable *bool
	ProxyProtocolEnable       *bool
	EnhanceL7PolicyEnable     *bool
	QuicConfigSet             bool
	QuicConfig                *listenerQuicConfig
	ProtectionStatus          *string
	ProtectionReason          *string
	GzipEnable                *bool
	SSLEarlyDataEnable        *bool
	CPS                       *int
	Connection                *int
	Nat64Enable               *bool
}

type listListenersFilter struct {
	IDs                       []string
	Names                     []string
	Descriptions              []string
	Protocols                 []string
	ProtocolPorts             []string
	DefaultTLSContainerRefs   []string
	ClientCATLSContainerRefs  []string
	DefaultPoolIDs            []string
	LoadBalancerIDs           []string
	TLSCiphersPolicies        []string
	EnterpriseProjectIDs      []string
	ProtectionStatuses        []string
	MemberAddresses           []string
	MemberDeviceIDs           []string
	MemberInstanceIDs         []string
	ConnectionLimits          []int
	MemberTimeouts            []int
	ClientTimeouts            []int
	KeepaliveTimeouts         []int
	AdminStateUp              *bool
	HTTP2Enable               *bool
	EnableMemberRetry         *bool
	TransparentClientIPEnable *bool
	ProxyProtocolEnable       *bool
	EnhanceL7PolicyEnable     *bool
	SSLEarlyDataEnable        *bool
	Nat64Enable               *bool
	Page                      pagination.Marker
}

func normalizeListenerProtocol(proto string) (string, bool) {
	if proto == "TERMINATED_HTTPS" {
		proto = "HTTPS"
	}
	switch proto {
	case "TCP", "UDP", "HTTP", "HTTPS", "QUIC", "TLS":
		return proto, true
	default:
		return "", false
	}
}

func isL4ListenerProtocol(proto string) bool {
	switch proto {
	case "TCP", "UDP", "TLS", "QUIC":
		return true
	default:
		return false
	}
}

func isL7ListenerProtocol(proto string) bool {
	return proto == "HTTP" || proto == "HTTPS"
}

func isTLSListenerProtocol(proto string) bool {
	switch proto {
	case "HTTPS", "TLS", "QUIC":
		return true
	default:
		return false
	}
}

func isHTTPFamilyListenerProtocol(proto string) bool {
	return proto == "HTTP" || proto == "HTTPS" || proto == "QUIC"
}

// listenerPortFamily groups protocols that share a port namespace on a load balancer (§3.2).
func listenerPortFamily(proto string) string {
	switch proto {
	case "UDP", "QUIC":
		return "UDP"
	default:
		return "TCP"
	}
}

func listenerOccupiedRanges(port int, ranges []portRange) []portRange {
	if len(ranges) > 0 {
		out := make([]portRange, len(ranges))
		copy(out, ranges)
		return out
	}
	if port > 0 {
		return []portRange{{StartPort: port, EndPort: port}}
	}
	return nil
}

func portRangesOverlap(a, b []portRange) bool {
	for _, ra := range a {
		for _, rb := range b {
			if ra.StartPort <= rb.EndPort && rb.StartPort <= ra.EndPort {
				return true
			}
		}
	}
	return false
}

func validateListenerPortSpec(proto string, protocolPort *int, ranges []portRange, rangesValid bool) (int, []portRange, error) {
	if !rangesValid {
		return 0, nil, errInvalidInput("port_ranges")
	}
	if len(ranges) > 0 {
		if protocolPort != nil && *protocolPort != 0 {
			return 0, nil, errInvalidInput("protocol_port")
		}
		if proto != "TCP" && proto != "UDP" && proto != "TLS" {
			return 0, nil, errInvalidInput("port_ranges")
		}
		if len(ranges) > listenerMaxPortRanges {
			return 0, nil, errInvalidInput("port_ranges")
		}
		for _, r := range ranges {
			if r.StartPort < 1 || r.StartPort > 65535 || r.EndPort < r.StartPort || r.EndPort > 65535 {
				return 0, nil, errInvalidInput("port_ranges")
			}
		}
		sorted := make([]portRange, len(ranges))
		copy(sorted, ranges)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].StartPort != sorted[j].StartPort {
				return sorted[i].StartPort < sorted[j].StartPort
			}
			return sorted[i].EndPort < sorted[j].EndPort
		})
		for i := 1; i < len(sorted); i++ {
			if sorted[i].StartPort <= sorted[i-1].EndPort {
				return 0, nil, errInvalidInput("port_ranges")
			}
		}
		out := make([]portRange, len(ranges))
		copy(out, ranges)
		return 0, out, nil
	}
	if protocolPort == nil || *protocolPort < 1 || *protocolPort > 65535 {
		return 0, nil, errInvalidInput("protocol_port")
	}
	return *protocolPort, nil, nil
}

func validateListenerKeepaliveTimeout(proto string, v int) error {
	minVal := 10
	if isHTTPFamilyListenerProtocol(proto) {
		minVal = 0
	}
	if v < minVal || v > 4000 {
		return errInvalidInput("keepalive_timeout")
	}
	return nil
}

func listenerDefaultKeepaliveTimeout(proto string) int {
	if isHTTPFamilyListenerProtocol(proto) {
		return 60
	}
	return 300
}

func validateListenerTimeout(field string, v int) error {
	if v < 1 || v > 300 {
		return errInvalidInput(field)
	}
	return nil
}

func validateListenerRateLimit(field string, v int) error {
	if v < 0 || v > listenerMaxRateLimit {
		return errInvalidInput(field)
	}
	return nil
}

func validateListenerSNIMatchAlgo(v string) error {
	if v == "" || v == "wildcard" || v == "longest_suffix" {
		return nil
	}
	return errInvalidInput("sni_match_algo")
}

func validateListenerProtectionStatus(v string) error {
	if v == "" || v == "nonProtection" || v == "consoleProtection" {
		return nil
	}
	return errInvalidInput("protection_status")
}

func validateListenerProtectionReason(v string) error {
	if utf8.RuneCountInString(v) > 255 || strings.ContainsAny(v, "<>") {
		return errInvalidInput("protection_reason")
	}
	return nil
}

func validateListenerInsertHeaders(h *listenerInsertHeaders) error {
	if h == nil {
		return nil
	}
	if h.XForwardedTLSProtocolAlias != nil && !listenerHeaderAliasRE.MatchString(*h.XForwardedTLSProtocolAlias) {
		return errInvalidInput("insert_headers.X-Forwarded-TLS-Protocol-alias")
	}
	if h.XForwardedTLSCipherAlias != nil && !listenerHeaderAliasRE.MatchString(*h.XForwardedTLSCipherAlias) {
		return errInvalidInput("insert_headers.X-Forwarded-TLS-Cipher-alias")
	}
	return nil
}

func cloneInsertHeaders(h *listenerInsertHeaders) *listenerInsertHeaders {
	if h == nil {
		return nil
	}
	cp := *h
	if h.XForwardedELBIP != nil {
		v := *h.XForwardedELBIP
		cp.XForwardedELBIP = &v
	}
	if h.XForwardedPort != nil {
		v := *h.XForwardedPort
		cp.XForwardedPort = &v
	}
	if h.XForwardedForPort != nil {
		v := *h.XForwardedForPort
		cp.XForwardedForPort = &v
	}
	if h.XForwardedHost != nil {
		v := *h.XForwardedHost
		cp.XForwardedHost = &v
	}
	if h.XForwardedProto != nil {
		v := *h.XForwardedProto
		cp.XForwardedProto = &v
	}
	if h.XRealIP != nil {
		v := *h.XRealIP
		cp.XRealIP = &v
	}
	if h.XForwardedELBID != nil {
		v := *h.XForwardedELBID
		cp.XForwardedELBID = &v
	}
	if h.XForwardedTLSCertificateID != nil {
		v := *h.XForwardedTLSCertificateID
		cp.XForwardedTLSCertificateID = &v
	}
	if h.XForwardedTLSProtocol != nil {
		v := *h.XForwardedTLSProtocol
		cp.XForwardedTLSProtocol = &v
	}
	if h.XForwardedTLSCipher != nil {
		v := *h.XForwardedTLSCipher
		cp.XForwardedTLSCipher = &v
	}
	if h.XForwardedTLSProtocolAlias != nil {
		v := *h.XForwardedTLSProtocolAlias
		cp.XForwardedTLSProtocolAlias = &v
	}
	if h.XForwardedTLSCipherAlias != nil {
		v := *h.XForwardedTLSCipherAlias
		cp.XForwardedTLSCipherAlias = &v
	}
	return &cp
}

func cloneQuicConfig(q *listenerQuicConfig) *listenerQuicConfig {
	if q == nil {
		return nil
	}
	cp := *q
	if q.QuicListenerID != nil {
		v := *q.QuicListenerID
		cp.QuicListenerID = &v
	}
	if q.EnableQuicUpgrade != nil {
		v := *q.EnableQuicUpgrade
		cp.EnableQuicUpgrade = &v
	}
	return &cp
}

func cloneListenerIPGroup(g *listenerIPGroup) *listenerIPGroup {
	if g == nil {
		return nil
	}
	cp := *g
	return &cp
}

func (s *Service) validateListenerCertificate(ctx context.Context, t Tenant, id, wantType, field string) error {
	if id == "" {
		return errInvalidInput(field)
	}
	cert, err := s.certificates(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("certificate", id)
	}
	if err != nil {
		return err
	}
	if cert.Type != wantType {
		return errInvalidInput(field)
	}
	return nil
}

func (s *Service) validateListenerIPGroupIDs(ctx context.Context, t Tenant, raw string) error {
	if raw == "" {
		return errInvalidInput("ipgroup.ipgroup_id")
	}
	for id := range strings.SplitSeq(raw, ",") {
		if id == "" {
			return errInvalidInput("ipgroup.ipgroup_id")
		}
		if _, err := s.ipGroups(t).Get(ctx, id); errors.Is(err, store.ErrNotFound) {
			return errNotFound("ipgroup", id)
		} else if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) resolveListenerIPGroupCreate(ctx context.Context, t Tenant, in *listenerIPGroupInput) (*listenerIPGroup, error) {
	if in == nil || in.Empty {
		return nil, nil
	}
	if in.IPGroupID == nil || *in.IPGroupID == "" {
		return nil, errInvalidInput("ipgroup.ipgroup_id")
	}
	if err := s.validateListenerIPGroupIDs(ctx, t, *in.IPGroupID); err != nil {
		return nil, err
	}
	typ := "white"
	if in.Type != nil && *in.Type != "" {
		typ = *in.Type
	}
	if typ != "white" && typ != "black" {
		return nil, errInvalidInput("ipgroup.type")
	}
	enable := true
	if in.EnableIPGroup != nil {
		enable = *in.EnableIPGroup
	}
	return &listenerIPGroup{
		IPGroupID:     *in.IPGroupID,
		EnableIPGroup: enable,
		Type:          typ,
	}, nil
}

func (s *Service) resolveListenerIPGroupUpdate(ctx context.Context, t Tenant, existing *listenerIPGroup, in *listenerIPGroupInput) (*listenerIPGroup, error) {
	if in == nil || in.Empty {
		return nil, nil
	}
	var ipgID string
	if in.IPGroupID != nil {
		ipgID = *in.IPGroupID
	} else if existing != nil {
		ipgID = existing.IPGroupID
	}
	if ipgID == "" {
		return nil, errInvalidInput("ipgroup.ipgroup_id")
	}
	if err := s.validateListenerIPGroupIDs(ctx, t, ipgID); err != nil {
		return nil, err
	}

	typ := "white"
	if existing != nil && existing.Type != "" {
		typ = existing.Type
	}
	if in.Type != nil {
		typ = *in.Type
	}
	if typ != "white" && typ != "black" {
		return nil, errInvalidInput("ipgroup.type")
	}

	enable := true
	if existing != nil {
		enable = existing.EnableIPGroup
	}
	if in.EnableIPGroup != nil {
		enable = *in.EnableIPGroup
	}
	return &listenerIPGroup{
		IPGroupID:     ipgID,
		EnableIPGroup: enable,
		Type:          typ,
	}, nil
}

func (s *Service) validateListenerPool(ctx context.Context, t Tenant, lbID, proto, poolID, ignoreListenerID string, existingListeners []listener) error {
	p, err := s.pools(t).Get(ctx, poolID)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("pool", poolID)
	}
	if err != nil {
		return err
	}
	if p.LoadBalancerID != lbID {
		return errInvalidInput("default_pool_id")
	}
	if !listenerPoolProtocolAllowed(proto, p.Protocol) {
		return errInvalidInput("default_pool_id")
	}
	for _, other := range existingListeners {
		if other.ID == ignoreListenerID {
			continue
		}
		if other.DefaultPoolID == poolID {
			return errConflict("The pool is already used as default_pool_id by another listener.")
		}
	}
	return nil
}

func (s *Service) createListener(ctx context.Context, t Tenant, in createListenerInput) (listener, error) {
	if in.LoadBalancerID == "" {
		return listener{}, errInvalidInput("loadbalancer_id")
	}
	proto, ok := normalizeListenerProtocol(in.Protocol)
	if !ok {
		return listener{}, errInvalidInput("protocol")
	}
	if !validName(in.Name) {
		return listener{}, errInvalidInput("name")
	}
	if !validDescription(in.Description) {
		return listener{}, errInvalidInput("description")
	}
	if err := validTags(in.Tags); err != nil {
		return listener{}, err
	}
	if err := validateListenerSNIMatchAlgo(in.SNIMatchAlgo); err != nil {
		return listener{}, err
	}
	if err := validateListenerProtectionStatus(in.ProtectionStatus); err != nil {
		return listener{}, err
	}
	if err := validateListenerProtectionReason(in.ProtectionReason); err != nil {
		return listener{}, err
	}
	if err := validateListenerInsertHeaders(in.InsertHeaders); err != nil {
		return listener{}, err
	}
	port, portRanges, err := validateListenerPortSpec(proto, in.ProtocolPort, in.PortRanges, in.PortRangesValid)
	if err != nil {
		return listener{}, err
	}

	keepalive := listenerDefaultKeepaliveTimeout(proto)
	if in.KeepaliveTimeout != nil {
		if err := validateListenerKeepaliveTimeout(proto, *in.KeepaliveTimeout); err != nil {
			return listener{}, err
		}
		keepalive = *in.KeepaliveTimeout
	}
	clientTimeout := 0
	memberTimeout := 0
	if isHTTPFamilyListenerProtocol(proto) {
		clientTimeout = 60
		memberTimeout = 60
	}
	if in.ClientTimeout != nil {
		if err := validateListenerTimeout("client_timeout", *in.ClientTimeout); err != nil {
			return listener{}, err
		}
		clientTimeout = *in.ClientTimeout
	}
	if in.MemberTimeout != nil {
		if err := validateListenerTimeout("member_timeout", *in.MemberTimeout); err != nil {
			return listener{}, err
		}
		memberTimeout = *in.MemberTimeout
	}
	cps := 0
	if in.CPS != nil {
		if err := validateListenerRateLimit("cps", *in.CPS); err != nil {
			return listener{}, err
		}
		cps = *in.CPS
	}
	conn := 0
	if in.Connection != nil {
		if err := validateListenerRateLimit("connection", *in.Connection); err != nil {
			return listener{}, err
		}
		conn = *in.Connection
	}

	// Non-TLS protocols reject all TLS fields (§3.2).
	if !isTLSListenerProtocol(proto) {
		if in.DefaultTLSContainerRef != "" {
			return listener{}, errInvalidInput("default_tls_container_ref")
		}
		if in.ClientCATLSContainerRef != "" {
			return listener{}, errInvalidInput("client_ca_tls_container_ref")
		}
		if len(in.SNIContainerRefs) > 0 {
			return listener{}, errInvalidInput("sni_container_refs")
		}
		if in.TLSCiphersPolicy != "" {
			return listener{}, errInvalidInput("tls_ciphers_policy")
		}
		if in.SecurityPolicyID != "" {
			return listener{}, errInvalidInput("security_policy_id")
		}
	} else {
		if in.DefaultTLSContainerRef == "" {
			return listener{}, errInvalidInput("default_tls_container_ref")
		}
		if len(in.SNIContainerRefs) > listenerMaxSNICerts {
			return listener{}, errInvalidInput("sni_container_refs")
		}
		if in.TLSCiphersPolicy != "" && in.SecurityPolicyID != "" {
			return listener{}, errInvalidInput("security_policy_id")
		}
		if in.TLSCiphersPolicy != "" && !isSystemSecurityPolicy(in.TLSCiphersPolicy) {
			return listener{}, errInvalidInput("tls_ciphers_policy")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lb, err := s.loadBalancers(t).Get(ctx, in.LoadBalancerID)
	if errors.Is(err, store.ErrNotFound) {
		return listener{}, errNotFound("loadbalancer", in.LoadBalancerID)
	}
	if err != nil {
		return listener{}, err
	}
	if isL4ListenerProtocol(proto) && lb.L4FlavorID == "" {
		return listener{}, errInvalidInput("protocol")
	}
	if isL7ListenerProtocol(proto) && lb.L7FlavorID == "" {
		return listener{}, errInvalidInput("protocol")
	}

	if isTLSListenerProtocol(proto) {
		if err := s.validateListenerCertificate(ctx, t, in.DefaultTLSContainerRef, "server", "default_tls_container_ref"); err != nil {
			return listener{}, err
		}
		for _, ref := range in.SNIContainerRefs {
			if err := s.validateListenerCertificate(ctx, t, ref, "server", "sni_container_refs"); err != nil {
				return listener{}, err
			}
		}
		if in.ClientCATLSContainerRef != "" {
			if err := s.validateListenerCertificate(ctx, t, in.ClientCATLSContainerRef, "client", "client_ca_tls_container_ref"); err != nil {
				return listener{}, err
			}
		}
		if in.SecurityPolicyID != "" {
			if _, err := s.securityPolicies(t).Get(ctx, in.SecurityPolicyID); errors.Is(err, store.ErrNotFound) {
				return listener{}, errNotFound("security_policy", in.SecurityPolicyID)
			} else if err != nil {
				return listener{}, err
			}
		}
	}

	ipg, err := s.resolveListenerIPGroupCreate(ctx, t, in.IPGroup)
	if err != nil {
		return listener{}, err
	}

	allListeners, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return listener{}, err
	}

	// Port conflict check per protocol family on the same LB (§3.2).
	newFamily := listenerPortFamily(proto)
	newRanges := listenerOccupiedRanges(port, portRanges)
	for _, existing := range allListeners {
		if existing.LoadBalancerID != lb.ID {
			continue
		}
		if listenerPortFamily(existing.Protocol) != newFamily {
			continue
		}
		if portRangesOverlap(newRanges, listenerOccupiedRanges(existing.ProtocolPort, existing.PortRanges)) {
			return listener{}, errConflict("The port is already in use on this load balancer.")
		}
	}

	if in.DefaultPoolID != "" {
		if err := s.validateListenerPool(ctx, t, lb.ID, proto, in.DefaultPoolID, "", allListeners); err != nil {
			return listener{}, err
		}
	}

	adminStateUp := true
	if in.AdminStateUp != nil {
		adminStateUp = *in.AdminStateUp
	}
	enableMemberRetry := true
	if in.EnableMemberRetry != nil {
		enableMemberRetry = *in.EnableMemberRetry
	}
	transparentClientIP := true
	if in.TransparentClientIPEnable != nil {
		transparentClientIP = *in.TransparentClientIPEnable
	}
	http2Enable := proto == "QUIC"
	if in.HTTP2Enable != nil {
		http2Enable = *in.HTTP2Enable
	}
	proxyProtocol := false
	if in.ProxyProtocolEnable != nil {
		proxyProtocol = *in.ProxyProtocolEnable
	}
	enhanceL7 := false
	if in.EnhanceL7PolicyEnable != nil {
		enhanceL7 = *in.EnhanceL7PolicyEnable
	}
	gzipEnable := false
	if in.GzipEnable != nil {
		gzipEnable = *in.GzipEnable
	}
	sslEarlyData := false
	if in.SSLEarlyDataEnable != nil {
		sslEarlyData = *in.SSLEarlyDataEnable
	}
	nat64 := false
	if in.Nat64Enable != nil {
		nat64 = *in.Nat64Enable
	}

	tlsCiphersPolicy := in.TLSCiphersPolicy
	if isTLSListenerProtocol(proto) && tlsCiphersPolicy == "" && in.SecurityPolicyID == "" {
		tlsCiphersPolicy = listenerDefaultTLSCiphersPolicy
	}

	sniAlgo := in.SNIMatchAlgo
	if sniAlgo == "" {
		sniAlgo = listenerDefaultSNIMatchAlgo
	}
	protStatus := in.ProtectionStatus
	if protStatus == "" {
		protStatus = listenerDefaultProtectionStatus
	}
	ep := lb.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}

	var sniRefs []string
	if len(in.SNIContainerRefs) > 0 {
		sniRefs = make([]string, len(in.SNIContainerRefs))
		copy(sniRefs, in.SNIContainerRefs)
	}
	var tags []tag
	if len(in.Tags) > 0 {
		tags = make([]tag, len(in.Tags))
		copy(tags, in.Tags)
	}

	now := s.nowUTC()
	rec := listener{
		ID:                        s.ids.UUID(),
		LoadBalancerID:            lb.ID,
		Name:                      in.Name,
		Description:               in.Description,
		Protocol:                  proto,
		ProtocolPort:              port,
		PortRanges:                portRanges,
		AdminStateUp:              adminStateUp,
		DefaultPoolID:             in.DefaultPoolID,
		DefaultTLSContainerRef:    in.DefaultTLSContainerRef,
		ClientCATLSContainerRef:   in.ClientCATLSContainerRef,
		SNIContainerRefs:          sniRefs,
		SNIMatchAlgo:              sniAlgo,
		TLSCiphersPolicy:          tlsCiphersPolicy,
		SecurityPolicyID:          in.SecurityPolicyID,
		HTTP2Enable:               http2Enable,
		InsertHeaders:             cloneInsertHeaders(in.InsertHeaders),
		EnableMemberRetry:         enableMemberRetry,
		KeepaliveTimeout:          keepalive,
		ClientTimeout:             clientTimeout,
		MemberTimeout:             memberTimeout,
		IPGroup:                   cloneListenerIPGroup(ipg),
		TransparentClientIPEnable: transparentClientIP,
		ProxyProtocolEnable:       proxyProtocol,
		EnhanceL7PolicyEnable:     enhanceL7,
		QuicConfig:                cloneQuicConfig(in.QuicConfig),
		ProtectionStatus:          protStatus,
		ProtectionReason:          in.ProtectionReason,
		GzipEnable:                gzipEnable,
		SSLEarlyDataEnable:        sslEarlyData,
		CPS:                       cps,
		Connection:                conn,
		ConnectionLimit:           listenerDefaultConnectionLimit,
		Nat64Enable:               nat64,
		EnterpriseProjectID:       ep,
		Tags:                      tags,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	if err := s.listeners(t).Create(ctx, rec.ID, rec); err != nil {
		return listener{}, err
	}
	return rec, nil
}

func (s *Service) getListener(ctx context.Context, t Tenant, id string) (listener, error) {
	rec, err := s.listeners(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return listener{}, errNotFound("listener", id)
	}
	if err != nil {
		return listener{}, err
	}
	return rec, nil
}

func (s *Service) listListeners(ctx context.Context, t Tenant, f listListenersFilter) ([]listener, pageInfo, error) {
	// Precompute listener IDs matched by member filters only when requested.
	var memberMatchedListeners map[string]struct{}
	if len(f.MemberAddresses) > 0 || len(f.MemberInstanceIDs) > 0 || len(f.MemberDeviceIDs) > 0 {
		// member_device_id is not stored on ELB member records; if specified without matching, nothing matches.
		if len(f.MemberDeviceIDs) > 0 {
			return []listener{}, makePageInfo([]listener{}, func(l listener) string { return l.ID }, false), nil
		}
		mems, err := s.members(t).List(ctx, func(m member) bool {
			if !matchesAny(f.MemberAddresses, m.Address) {
				return false
			}
			if !matchesAny(f.MemberInstanceIDs, m.ID) {
				return false
			}
			return true
		})
		if err != nil {
			return nil, pageInfo{}, err
		}
		matchedPools := make(map[string]struct{}, len(mems))
		for _, m := range mems {
			matchedPools[m.PoolID] = struct{}{}
		}
		policies, err := s.l7Policies(t).List(ctx, nil)
		if err != nil {
			return nil, pageInfo{}, err
		}
		memberMatchedListeners = make(map[string]struct{})
		for _, pol := range policies {
			if pol.RedirectPoolID != "" {
				if _, ok := matchedPools[pol.RedirectPoolID]; ok {
					memberMatchedListeners[pol.ListenerID] = struct{}{}
				}
			}
			for _, rp := range pol.RedirectPoolsConfig {
				if _, ok := matchedPools[rp.PoolID]; ok {
					memberMatchedListeners[pol.ListenerID] = struct{}{}
				}
			}
		}
		allLsn, err := s.listeners(t).List(ctx, nil)
		if err != nil {
			return nil, pageInfo{}, err
		}
		for _, l := range allLsn {
			if l.DefaultPoolID != "" {
				if _, ok := matchedPools[l.DefaultPoolID]; ok {
					memberMatchedListeners[l.ID] = struct{}{}
				}
			}
		}
	}

	items, err := s.listeners(t).List(ctx, func(l listener) bool {
		if !matchesAny(f.IDs, l.ID) {
			return false
		}
		if !matchesAny(f.Names, l.Name) {
			return false
		}
		if !matchesAny(f.Descriptions, l.Description) {
			return false
		}
		if !matchesAny(f.Protocols, l.Protocol) {
			return false
		}
		if !matchesAny(f.ProtocolPorts, strconv.Itoa(l.ProtocolPort)) {
			return false
		}
		if !matchesAny(f.DefaultTLSContainerRefs, l.DefaultTLSContainerRef) {
			return false
		}
		if !matchesAny(f.ClientCATLSContainerRefs, l.ClientCATLSContainerRef) {
			return false
		}
		if !matchesAny(f.DefaultPoolIDs, l.DefaultPoolID) {
			return false
		}
		if !matchesAny(f.LoadBalancerIDs, l.LoadBalancerID) {
			return false
		}
		if !matchesAny(f.TLSCiphersPolicies, l.TLSCiphersPolicy) {
			return false
		}
		if !inEPList(f.EnterpriseProjectIDs, l.EnterpriseProjectID) {
			return false
		}
		if !matchesAny(f.ProtectionStatuses, l.ProtectionStatus) {
			return false
		}
		if len(f.ConnectionLimits) > 0 && !slices.Contains(f.ConnectionLimits, l.ConnectionLimit) {
			return false
		}
		if len(f.MemberTimeouts) > 0 && !slices.Contains(f.MemberTimeouts, l.MemberTimeout) {
			return false
		}
		if len(f.ClientTimeouts) > 0 && !slices.Contains(f.ClientTimeouts, l.ClientTimeout) {
			return false
		}
		if len(f.KeepaliveTimeouts) > 0 && !slices.Contains(f.KeepaliveTimeouts, l.KeepaliveTimeout) {
			return false
		}
		if f.AdminStateUp != nil && l.AdminStateUp != *f.AdminStateUp {
			return false
		}
		if f.HTTP2Enable != nil && l.HTTP2Enable != *f.HTTP2Enable {
			return false
		}
		if f.EnableMemberRetry != nil && l.EnableMemberRetry != *f.EnableMemberRetry {
			return false
		}
		if f.TransparentClientIPEnable != nil && l.TransparentClientIPEnable != *f.TransparentClientIPEnable {
			return false
		}
		if f.ProxyProtocolEnable != nil && l.ProxyProtocolEnable != *f.ProxyProtocolEnable {
			return false
		}
		if f.EnhanceL7PolicyEnable != nil && l.EnhanceL7PolicyEnable != *f.EnhanceL7PolicyEnable {
			return false
		}
		if f.SSLEarlyDataEnable != nil && l.SSLEarlyDataEnable != *f.SSLEarlyDataEnable {
			return false
		}
		if f.Nat64Enable != nil && l.Nat64Enable != *f.Nat64Enable {
			return false
		}
		if memberMatchedListeners != nil {
			if _, ok := memberMatchedListeners[l.ID]; !ok {
				return false
			}
		}
		return true
	})
	if err != nil {
		return nil, pageInfo{}, err
	}
	slices.SortFunc(items, func(a, b listener) int {
		return strings.Compare(a.ID, b.ID)
	})
	return paginateSlice(items, func(l listener) string { return l.ID }, f.Page)
}

func (s *Service) updateListener(ctx context.Context, t Tenant, id string, in updateListenerInput) (listener, error) {
	if in.Name != nil && !validName(*in.Name) {
		return listener{}, errInvalidInput("name")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return listener{}, errInvalidInput("description")
	}
	if in.SNIMatchAlgo != nil && validateListenerSNIMatchAlgo(*in.SNIMatchAlgo) != nil {
		return listener{}, errInvalidInput("sni_match_algo")
	}
	if in.ProtectionStatus != nil && validateListenerProtectionStatus(*in.ProtectionStatus) != nil {
		return listener{}, errInvalidInput("protection_status")
	}
	if in.ProtectionReason != nil && validateListenerProtectionReason(*in.ProtectionReason) != nil {
		return listener{}, errInvalidInput("protection_reason")
	}
	if in.InsertHeadersSet {
		if err := validateListenerInsertHeaders(in.InsertHeaders); err != nil {
			return listener{}, err
		}
	}
	if in.ClientTimeout != nil {
		if err := validateListenerTimeout("client_timeout", *in.ClientTimeout); err != nil {
			return listener{}, err
		}
	}
	if in.MemberTimeout != nil {
		if err := validateListenerTimeout("member_timeout", *in.MemberTimeout); err != nil {
			return listener{}, err
		}
	}
	if in.CPS != nil {
		if err := validateListenerRateLimit("cps", *in.CPS); err != nil {
			return listener{}, err
		}
	}
	if in.Connection != nil {
		if err := validateListenerRateLimit("connection", *in.Connection); err != nil {
			return listener{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.listeners(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return listener{}, errNotFound("listener", id)
	}
	if err != nil {
		return listener{}, err
	}

	if in.KeepaliveTimeout != nil {
		if err := validateListenerKeepaliveTimeout(existing.Protocol, *in.KeepaliveTimeout); err != nil {
			return listener{}, err
		}
	}
	if existing.EnhanceL7PolicyEnable && in.EnhanceL7PolicyEnable != nil && !*in.EnhanceL7PolicyEnable {
		return listener{}, errInvalidInput("enhance_l7policy_enable")
	}

	// Validate TLS fields against listener protocol.
	if !isTLSListenerProtocol(existing.Protocol) {
		if in.DefaultTLSRefSet && in.DefaultTLSRef != "" {
			return listener{}, errInvalidInput("default_tls_container_ref")
		}
		if in.ClientCATLSRefSet && in.ClientCATLSRef != "" {
			return listener{}, errInvalidInput("client_ca_tls_container_ref")
		}
		if in.SNIContainerRefsSet && len(in.SNIContainerRefs) > 0 {
			return listener{}, errInvalidInput("sni_container_refs")
		}
		if in.TLSCiphersPolicySet && in.TLSCiphersPolicy != "" {
			return listener{}, errInvalidInput("tls_ciphers_policy")
		}
		if in.SecurityPolicyIDSet && in.SecurityPolicyID != "" {
			return listener{}, errInvalidInput("security_policy_id")
		}
	} else {
		if in.DefaultTLSRefSet {
			if err := s.validateListenerCertificate(ctx, t, in.DefaultTLSRef, "server", "default_tls_container_ref"); err != nil {
				return listener{}, err
			}
		}
		if in.ClientCATLSRefSet && in.ClientCATLSRef != "" {
			if err := s.validateListenerCertificate(ctx, t, in.ClientCATLSRef, "client", "client_ca_tls_container_ref"); err != nil {
				return listener{}, err
			}
		}
		if in.SNIContainerRefsSet {
			if len(in.SNIContainerRefs) > listenerMaxSNICerts {
				return listener{}, errInvalidInput("sni_container_refs")
			}
			for _, ref := range in.SNIContainerRefs {
				if err := s.validateListenerCertificate(ctx, t, ref, "server", "sni_container_refs"); err != nil {
					return listener{}, err
				}
			}
		}
		if in.TLSCiphersPolicySet && in.TLSCiphersPolicy != "" && in.SecurityPolicyIDSet && in.SecurityPolicyID != "" {
			return listener{}, errInvalidInput("security_policy_id")
		}
		if in.TLSCiphersPolicySet && in.TLSCiphersPolicy != "" && !isSystemSecurityPolicy(in.TLSCiphersPolicy) {
			return listener{}, errInvalidInput("tls_ciphers_policy")
		}
		if in.SecurityPolicyIDSet && in.SecurityPolicyID != "" {
			if _, err := s.securityPolicies(t).Get(ctx, in.SecurityPolicyID); errors.Is(err, store.ErrNotFound) {
				return listener{}, errNotFound("security_policy", in.SecurityPolicyID)
			} else if err != nil {
				return listener{}, err
			}
		}
	}

	var nextIPGroup *listenerIPGroup
	if in.IPGroupSet {
		nextIPGroup, err = s.resolveListenerIPGroupUpdate(ctx, t, existing.IPGroup, in.IPGroup)
		if err != nil {
			return listener{}, err
		}
	}

	if in.DefaultPoolIDSet && in.DefaultPoolID != "" {
		allListeners, err := s.listeners(t).List(ctx, nil)
		if err != nil {
			return listener{}, err
		}
		if err := s.validateListenerPool(ctx, t, existing.LoadBalancerID, existing.Protocol, in.DefaultPoolID, existing.ID, allListeners); err != nil {
			return listener{}, err
		}
	}

	updated, err := s.listeners(t).Update(ctx, id, func(l *listener) error {
		if in.Name != nil {
			l.Name = *in.Name
		}
		if in.Description != nil {
			l.Description = *in.Description
		}
		if in.AdminStateUp != nil {
			l.AdminStateUp = *in.AdminStateUp
		}
		if in.DefaultPoolIDSet {
			l.DefaultPoolID = in.DefaultPoolID
		}
		if in.DefaultTLSRefSet && isTLSListenerProtocol(l.Protocol) {
			l.DefaultTLSContainerRef = in.DefaultTLSRef
		}
		if in.ClientCATLSRefSet && isTLSListenerProtocol(l.Protocol) {
			l.ClientCATLSContainerRef = in.ClientCATLSRef
		}
		if in.SNIContainerRefsSet && isTLSListenerProtocol(l.Protocol) {
			if len(in.SNIContainerRefs) == 0 {
				l.SNIContainerRefs = nil
			} else {
				cp := make([]string, len(in.SNIContainerRefs))
				copy(cp, in.SNIContainerRefs)
				l.SNIContainerRefs = cp
			}
		}
		if in.SNIMatchAlgo != nil {
			if *in.SNIMatchAlgo == "" {
				l.SNIMatchAlgo = listenerDefaultSNIMatchAlgo
			} else {
				l.SNIMatchAlgo = *in.SNIMatchAlgo
			}
		}
		if isTLSListenerProtocol(l.Protocol) {
			switch {
			case in.SecurityPolicyIDSet && in.SecurityPolicyID != "":
				l.SecurityPolicyID = in.SecurityPolicyID
				l.TLSCiphersPolicy = ""
			case in.TLSCiphersPolicySet && in.TLSCiphersPolicy != "":
				l.TLSCiphersPolicy = in.TLSCiphersPolicy
				l.SecurityPolicyID = ""
			default:
				if in.SecurityPolicyIDSet {
					l.SecurityPolicyID = ""
				}
				if in.TLSCiphersPolicySet {
					l.TLSCiphersPolicy = ""
				}
				if l.SecurityPolicyID == "" && l.TLSCiphersPolicy == "" {
					l.TLSCiphersPolicy = listenerDefaultTLSCiphersPolicy
				}
			}
		}
		if in.HTTP2Enable != nil {
			l.HTTP2Enable = *in.HTTP2Enable
		}
		if in.InsertHeadersSet {
			l.InsertHeaders = cloneInsertHeaders(in.InsertHeaders)
		}
		if in.EnableMemberRetry != nil {
			l.EnableMemberRetry = *in.EnableMemberRetry
		}
		if in.KeepaliveTimeout != nil {
			l.KeepaliveTimeout = *in.KeepaliveTimeout
		}
		if in.ClientTimeout != nil {
			l.ClientTimeout = *in.ClientTimeout
		}
		if in.MemberTimeout != nil {
			l.MemberTimeout = *in.MemberTimeout
		}
		if in.IPGroupSet {
			l.IPGroup = cloneListenerIPGroup(nextIPGroup)
		}
		if in.TransparentClientIPEnable != nil {
			l.TransparentClientIPEnable = *in.TransparentClientIPEnable
		}
		if in.ProxyProtocolEnable != nil {
			l.ProxyProtocolEnable = *in.ProxyProtocolEnable
		}
		if in.EnhanceL7PolicyEnable != nil {
			l.EnhanceL7PolicyEnable = *in.EnhanceL7PolicyEnable
		}
		if in.QuicConfigSet {
			l.QuicConfig = cloneQuicConfig(in.QuicConfig)
		}
		if in.ProtectionStatus != nil {
			if *in.ProtectionStatus == "" {
				l.ProtectionStatus = listenerDefaultProtectionStatus
			} else {
				l.ProtectionStatus = *in.ProtectionStatus
			}
		}
		if in.ProtectionReason != nil {
			l.ProtectionReason = *in.ProtectionReason
		}
		if in.GzipEnable != nil {
			l.GzipEnable = *in.GzipEnable
		}
		if in.SSLEarlyDataEnable != nil {
			l.SSLEarlyDataEnable = *in.SSLEarlyDataEnable
		}
		if in.CPS != nil {
			l.CPS = *in.CPS
		}
		if in.Connection != nil {
			l.Connection = *in.Connection
		}
		if in.Nat64Enable != nil {
			l.Nat64Enable = *in.Nat64Enable
		}
		l.UpdatedAt = s.nowUTC()
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return listener{}, errNotFound("listener", id)
	}
	if err != nil {
		return listener{}, err
	}
	return updated, nil
}

func (s *Service) deleteListener(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	l, err := s.listeners(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("listener", id)
	}
	if err != nil {
		return err
	}
	if l.DefaultPoolID != "" {
		return errConflict("The listener has a default pool.")
	}
	policies, err := s.l7Policies(t).List(ctx, func(p l7Policy) bool {
		return p.ListenerID == id || p.RedirectListenerID == id
	})
	if err != nil {
		return err
	}
	if len(policies) > 0 {
		return errConflict("The listener has L7 policies.")
	}
	if err := s.listeners(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func (s *Service) deleteListenerForce(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.listeners(t).Get(ctx, id); errors.Is(err, store.ErrNotFound) {
		return errNotFound("listener", id)
	} else if err != nil {
		return err
	}

	policies, err := s.l7Policies(t).List(ctx, func(p l7Policy) bool {
		return p.ListenerID == id || p.RedirectListenerID == id
	})
	if err != nil {
		return err
	}
	if len(policies) > 0 {
		policyIDs := make(map[string]struct{}, len(policies))
		for _, p := range policies {
			policyIDs[p.ID] = struct{}{}
		}
		rules, err := s.l7Rules(t).List(ctx, func(r l7Rule) bool {
			_, ok := policyIDs[r.PolicyID]
			return ok
		})
		if err != nil {
			return err
		}
		for _, r := range rules {
			if err := s.l7Rules(t).Delete(ctx, r.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		for _, p := range policies {
			if err := s.l7Policies(t).Delete(ctx, p.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
	}

	// Unbinding default_pool_id leaves the pool intact; deleting the listener removes the link.
	if err := s.listeners(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
