package nat

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

// --- Public SNAT wire types (§3.2) ---

type createSnatRuleRequest struct {
	SnatRule *createSnatRuleOption `json:"snat_rule"`
}

type createSnatRuleOption struct {
	NatGatewayID string  `json:"nat_gateway_id"`
	CIDR         *string `json:"cidr,omitempty"`
	NetworkID    *string `json:"network_id,omitempty"`
	Description  *string `json:"description,omitempty"`
	SourceType   *int    `json:"source_type,omitempty"`
	FloatingIPID string  `json:"floating_ip_id"`
	GlobalEIPID  *string `json:"global_eip_id,omitempty"`
}

type updateSnatRuleRequest struct {
	SnatRule *updateSnatRuleOption `json:"snat_rule"`
}

type updateSnatRuleOption struct {
	NatGatewayID    string  `json:"nat_gateway_id"`
	PublicIPAddress *string `json:"public_ip_address,omitempty"`
	GlobalEIPID     *string `json:"global_eip_id,omitempty"`
	Description     *string `json:"description,omitempty"`
}

type snatRuleResponseBody struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	NatGatewayID      string `json:"nat_gateway_id"`
	CIDR              string `json:"cidr"`
	SourceType        int    `json:"source_type"`
	FloatingIPID      string `json:"floating_ip_id"`
	Description       string `json:"description"`
	Status            string `json:"status"`
	CreatedAt         string `json:"created_at"`
	NetworkID         string `json:"network_id"`
	AdminStateUp      bool   `json:"admin_state_up"`
	FloatingIPAddress string `json:"floating_ip_address"`
	FreezedIPAddress  string `json:"freezed_ip_address"`
	GlobalEIPID       string `json:"global_eip_id"`
	GlobalEIPAddress  string `json:"global_eip_address"`
}

type updateSnatRuleResponseBody struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	NatGatewayID      string `json:"nat_gateway_id"`
	SourceType        int    `json:"source_type"`
	CIDR              string `json:"cidr"`
	FloatingIPID      string `json:"floating_ip_id"`
	Description       string `json:"description"`
	Status            string `json:"status"`
	CreatedAt         string `json:"created_at"`
	NetworkID         string `json:"network_id"`
	AdminStateUp      bool   `json:"admin_state_up"`
	FloatingIPAddress string `json:"floating_ip_address"`
	PublicIPAddress   string `json:"public_ip_address"`
	GlobalEIPAddress  string `json:"global_eip_address"`
	GlobalEIPID       string `json:"global_eip_id"`
}

type snatRuleResponse struct {
	SnatRule snatRuleResponseBody `json:"snat_rule"`
}

type updateSnatRuleResponse struct {
	SnatRule updateSnatRuleResponseBody `json:"snat_rule"`
}

type listSnatRulesResponse struct {
	SnatRules []snatRuleResponseBody `json:"snat_rules"`
}

// --- Public DNAT wire types (§3.3) ---

type createDnatRuleRequest struct {
	DnatRule *createDnatRuleOption `json:"dnat_rule"`
}

type batchCreateDnatRulesRequest struct {
	DnatRules []createDnatRuleOption `json:"dnat_rules"`
}

type createDnatRuleOption struct {
	Description              *string `json:"description,omitempty"`
	PortID                   *string `json:"port_id,omitempty"`
	PrivateIP                *string `json:"private_ip,omitempty"`
	NatGatewayID             string  `json:"nat_gateway_id"`
	InternalServicePort      *int    `json:"internal_service_port"`
	FloatingIPID             string  `json:"floating_ip_id"`
	ExternalServicePort      *int    `json:"external_service_port"`
	Protocol                 string  `json:"protocol"`
	InternalServicePortRange *string `json:"internal_service_port_range,omitempty"`
	ExternalServicePortRange *string `json:"external_service_port_range,omitempty"`
	GlobalEIPID              *string `json:"global_eip_id,omitempty"`
}

type updateDnatRuleRequest struct {
	DnatRule *updateDnatRuleOption `json:"dnat_rule"`
}

type updateDnatRuleOption struct {
	NatGatewayID             string  `json:"nat_gateway_id"`
	Description              *string `json:"description,omitempty"`
	PortID                   *string `json:"port_id,omitempty"`
	PrivateIP                *string `json:"private_ip,omitempty"`
	Protocol                 *string `json:"protocol,omitempty"`
	FloatingIPID             *string `json:"floating_ip_id,omitempty"`
	InternalServicePort      *int    `json:"internal_service_port,omitempty"`
	ExternalServicePort      *int    `json:"external_service_port,omitempty"`
	InternalServicePortRange *string `json:"internal_service_port_range,omitempty"`
	ExternalServicePortRange *string `json:"external_service_port_range,omitempty"`
	GlobalEIPID              *string `json:"global_eip_id,omitempty"`
}

type dnatRuleResponseBody struct {
	ID                       string `json:"id"`
	TenantID                 string `json:"tenant_id"`
	Description              string `json:"description"`
	PortID                   string `json:"port_id"`
	PrivateIP                string `json:"private_ip"`
	InternalServicePort      int    `json:"internal_service_port"`
	NatGatewayID             string `json:"nat_gateway_id"`
	FloatingIPID             string `json:"floating_ip_id"`
	FloatingIPAddress        string `json:"floating_ip_address"`
	ExternalServicePort      int    `json:"external_service_port"`
	Status                   string `json:"status"`
	AdminStateUp             bool   `json:"admin_state_up"`
	InternalServicePortRange string `json:"internal_service_port_range,omitempty"`
	ExternalServicePortRange string `json:"external_service_port_range,omitempty"`
	Protocol                 string `json:"protocol"`
	CreatedAt                string `json:"created_at"`
	GlobalEIPID              string `json:"global_eip_id"`
	GlobalEIPAddress         string `json:"global_eip_address"`
}

type dnatRuleResponse struct {
	DnatRule dnatRuleResponseBody `json:"dnat_rule"`
}

type listDnatRulesResponse struct {
	DnatRules []dnatRuleResponseBody `json:"dnat_rules"`
}

// --- Public SNAT handlers (§3.2) ---

func (s *Service) handleCreateSnatRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createSnatRuleRequest
	if err := decodePublic(r, &req); err != nil {
		return err
	}
	if req.SnatRule == nil {
		return errInvalidParams("snat_rule is required")
	}
	rule, addrs, err := s.createSnatRule(r.Context(), t, *req.SnatRule)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, snatRuleResponse{
		SnatRule: toSnatRuleResponseBody(t, rule, addrs),
	})
}

func (s *Service) handleListSnatRules(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidParams("%s", err)
	}
	adminStateUp, err := parseRuleOptionalBool(q.Get("admin_state_up"))
	if err != nil {
		return err
	}
	sourceType, err := parseRuleOptionalInt(q.Get("source_type"))
	if err != nil {
		return err
	}

	rules, addrList, err := s.listSnatRules(r.Context(), t, listSnatRulesFilter{
		AdminStateUp:      adminStateUp,
		CIDR:              q.Get("cidr"),
		FloatingIPAddress: q.Get("floating_ip_address"),
		GlobalEIPAddress:  q.Get("global_eip_address"),
		FloatingIPID:      q.Get("floating_ip_id"),
		GlobalEIPID:       q.Get("global_eip_id"),
		ID:                q.Get("id"),
		Description:       q.Get("description"),
		CreatedAt:         q.Get("created_at"),
		NatGatewayIDs:     q["nat_gateway_id"],
		NetworkID:         q.Get("network_id"),
		SourceType:        sourceType,
		Status:            q.Get("status"),
		Page:              page,
	})
	if err != nil {
		return err
	}
	out := make([]snatRuleResponseBody, len(rules))
	for i, rule := range rules {
		out[i] = toSnatRuleResponseBody(t, rule, addrList[i])
	}
	return httpx.WriteJSON(w, http.StatusOK, listSnatRulesResponse{SnatRules: out})
}

func (s *Service) handleShowSnatRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "snat_rule_id")
	rule, addrs, err := s.getSnatRule(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, snatRuleResponse{
		SnatRule: toSnatRuleResponseBody(t, rule, addrs),
	})
}

func (s *Service) handleUpdateSnatRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateSnatRuleRequest
	if err := decodePublic(r, &req); err != nil {
		return err
	}
	if req.SnatRule == nil {
		return errInvalidParams("snat_rule is required")
	}
	id := chi.URLParam(r, "snat_rule_id")
	rule, addrs, err := s.updateSnatRule(r.Context(), t, id, *req.SnatRule)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, updateSnatRuleResponse{
		SnatRule: toUpdateSnatRuleResponseBody(t, rule, addrs),
	})
}

func (s *Service) handleDeleteSnatRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	gwID := chi.URLParam(r, "nat_gateway_id")
	ruleID := chi.URLParam(r, "snat_rule_id")
	if err := s.deleteSnatRule(r.Context(), t, gwID, ruleID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// --- Public DNAT handlers (§3.3) ---

func (s *Service) handleCreateDnatRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createDnatRuleRequest
	if err := decodePublic(r, &req); err != nil {
		return err
	}
	if req.DnatRule == nil {
		return errInvalidParams("dnat_rule is required")
	}
	rule, addr, err := s.createDnatRule(r.Context(), t, *req.DnatRule)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, dnatRuleResponse{
		DnatRule: toDnatRuleResponseBody(t, rule, addr),
	})
}

func (s *Service) handleBatchCreateDnatRules(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req batchCreateDnatRulesRequest
	if err := decodePublic(r, &req); err != nil {
		return err
	}
	rules, addrs, err := s.batchCreateDnatRules(r.Context(), t, req.DnatRules)
	if err != nil {
		return err
	}
	out := make([]dnatRuleResponseBody, len(rules))
	for i, rule := range rules {
		out[i] = toDnatRuleResponseBody(t, rule, addrs[i])
	}
	return httpx.WriteJSON(w, http.StatusCreated, listDnatRulesResponse{DnatRules: out})
}

func (s *Service) handleListDnatRules(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidParams("%s", err)
	}
	adminStateUp, err := parseRuleOptionalBool(q.Get("admin_state_up"))
	if err != nil {
		return err
	}
	intPort, err := parseRuleOptionalInt(q.Get("internal_service_port"))
	if err != nil {
		return err
	}
	extPort, err := parseRuleOptionalInt(q.Get("external_service_port"))
	if err != nil {
		return err
	}

	rules, addrs, err := s.listDnatRules(r.Context(), t, listDnatRulesFilter{
		AdminStateUp:        adminStateUp,
		ExternalServicePort: extPort,
		FloatingIPAddress:   q.Get("floating_ip_address"),
		GlobalEIPAddress:    q.Get("global_eip_address"),
		Statuses:            q["status"],
		FloatingIPID:        q.Get("floating_ip_id"),
		GlobalEIPID:         q.Get("global_eip_id"),
		InternalServicePort: intPort,
		ID:                  q.Get("id"),
		Description:         q.Get("description"),
		CreatedAt:           q.Get("created_at"),
		NatGatewayIDs:       q["nat_gateway_id"],
		PortID:              q.Get("port_id"),
		PrivateIP:           q.Get("private_ip"),
		Protocols:           q["protocol"],
		Page:                page,
	})
	if err != nil {
		return err
	}
	out := make([]dnatRuleResponseBody, len(rules))
	for i, rule := range rules {
		out[i] = toDnatRuleResponseBody(t, rule, addrs[i])
	}
	return httpx.WriteJSON(w, http.StatusOK, listDnatRulesResponse{DnatRules: out})
}

func (s *Service) handleShowDnatRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "dnat_rule_id")
	rule, addr, err := s.getDnatRule(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, dnatRuleResponse{
		DnatRule: toDnatRuleResponseBody(t, rule, addr),
	})
}

func (s *Service) handleUpdateDnatRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateDnatRuleRequest
	if err := decodePublic(r, &req); err != nil {
		return err
	}
	if req.DnatRule == nil {
		return errInvalidParams("dnat_rule is required")
	}
	id := chi.URLParam(r, "dnat_rule_id")
	rule, addr, err := s.updateDnatRule(r.Context(), t, id, *req.DnatRule)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, dnatRuleResponse{
		DnatRule: toDnatRuleResponseBody(t, rule, addr),
	})
}

func (s *Service) handleDeleteDnatRule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	gwID := chi.URLParam(r, "nat_gateway_id")
	ruleID := chi.URLParam(r, "dnat_rule_id")
	if err := s.deleteDnatRule(r.Context(), t, gwID, ruleID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// --- Response mappers & query helpers ---

func toSnatRuleResponseBody(t Tenant, r snatRule, addrs []string) snatRuleResponseBody {
	return snatRuleResponseBody{
		ID:                r.ID,
		TenantID:          t.ProjectID,
		NatGatewayID:      r.GatewayID,
		CIDR:              r.CIDR,
		SourceType:        r.SourceType,
		FloatingIPID:      strings.Join(r.FloatingIPIDs, ","),
		Description:       r.Description,
		Status:            r.Status,
		CreatedAt:         r.CreatedAt.UTC().Format(publicTimeFormat),
		NetworkID:         r.NetworkID,
		AdminStateUp:      true,
		FloatingIPAddress: strings.Join(addrs, ","),
		FreezedIPAddress:  "",
		GlobalEIPID:       "",
		GlobalEIPAddress:  "",
	}
}

func toUpdateSnatRuleResponseBody(t Tenant, r snatRule, addrs []string) updateSnatRuleResponseBody {
	joinedAddrs := strings.Join(addrs, ",")
	return updateSnatRuleResponseBody{
		ID:                r.ID,
		TenantID:          t.ProjectID,
		NatGatewayID:      r.GatewayID,
		SourceType:        r.SourceType,
		CIDR:              r.CIDR,
		FloatingIPID:      strings.Join(r.FloatingIPIDs, ","),
		Description:       r.Description,
		Status:            r.Status,
		CreatedAt:         r.CreatedAt.UTC().Format(publicTimeFormat),
		NetworkID:         r.NetworkID,
		AdminStateUp:      true,
		FloatingIPAddress: joinedAddrs,
		PublicIPAddress:   joinedAddrs,
		GlobalEIPAddress:  "",
		GlobalEIPID:       "",
	}
}

func toDnatRuleResponseBody(t Tenant, r dnatRule, addr string) dnatRuleResponseBody {
	return dnatRuleResponseBody{
		ID:                       r.ID,
		TenantID:                 t.ProjectID,
		Description:              r.Description,
		PortID:                   r.PortID,
		PrivateIP:                r.PrivateIP,
		InternalServicePort:      r.InternalPort,
		NatGatewayID:             r.GatewayID,
		FloatingIPID:             r.FloatingIPID,
		FloatingIPAddress:        addr,
		ExternalServicePort:      r.ExternalPort,
		Status:                   r.Status,
		AdminStateUp:             true,
		InternalServicePortRange: r.InternalRange,
		ExternalServicePortRange: r.ExternalRange,
		Protocol:                 r.Protocol,
		CreatedAt:                r.CreatedAt.UTC().Format(publicTimeFormat),
		GlobalEIPID:              "",
		GlobalEIPAddress:         "",
	}
}

func parseRuleOptionalBool(raw string) (*bool, error) {
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, errInvalidParams("invalid boolean %q", raw)
	}
	return &v, nil
}

func parseRuleOptionalInt(raw string) (*int, error) {
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return nil, errInvalidParams("invalid integer %q", raw)
	}
	return &v, nil
}
