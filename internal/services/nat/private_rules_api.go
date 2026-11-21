package nat

import (
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// --- Transit IP wire types (§3.7) ---

type createTransitIPRequest struct {
	TransitIP *createTransitIPOption `json:"transit_ip"`
}

type createTransitIPOption struct {
	VirsubnetID         string  `json:"virsubnet_id"`
	IPAddress           *string `json:"ip_address,omitempty"`
	EnterpriseProjectID *string `json:"enterprise_project_id,omitempty"`
	Tags                *[]tag  `json:"tags,omitempty"`
}

type transitIPResponseBody struct {
	ID                  string `json:"id"`
	ProjectID           string `json:"project_id"`
	NetworkInterfaceID  string `json:"network_interface_id"`
	IPAddress           string `json:"ip_address"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
	VirsubnetID         string `json:"virsubnet_id"`
	Tags                []tag  `json:"tags"`
	GatewayID           string `json:"gateway_id"`
	EnterpriseProjectID string `json:"enterprise_project_id"`
	Status              string `json:"status"`
}

type transitIPEnvelope struct {
	TransitIP transitIPResponseBody `json:"transit_ip"`
	RequestID string                `json:"request_id"`
}

type listTransitIPsResponse struct {
	TransitIPs []transitIPResponseBody `json:"transit_ips"`
	PageInfo   pageInfo                `json:"page_info"`
	RequestID  string                  `json:"request_id"`
}

// --- Private SNAT wire types (§3.8) ---

type createPrivateSnatRequest struct {
	SnatRule *createPrivateSnatOption `json:"snat_rule"`
}

type createPrivateSnatOption struct {
	GatewayID    string   `json:"gateway_id"`
	CIDR         *string  `json:"cidr,omitempty"`
	VirsubnetID  *string  `json:"virsubnet_id,omitempty"`
	Description  *string  `json:"description,omitempty"`
	TransitIPIDs []string `json:"transit_ip_ids"`
}

type updatePrivateSnatRequest struct {
	SnatRule *updatePrivateSnatOption `json:"snat_rule"`
}

type updatePrivateSnatOption struct {
	TransitIPIDs *[]string `json:"transit_ip_ids,omitempty"`
	Description  *string   `json:"description,omitempty"`
}

type transitIPAssociation struct {
	TransitIPID      string `json:"transit_ip_id"`
	TransitIPAddress string `json:"transit_ip_address"`
}

type privateSnatResponseBody struct {
	ID                    string                 `json:"id"`
	ProjectID             string                 `json:"project_id"`
	GatewayID             string                 `json:"gateway_id"`
	CIDR                  string                 `json:"cidr"`
	VirsubnetID           string                 `json:"virsubnet_id"`
	Description           string                 `json:"description"`
	TransitIPAssociations []transitIPAssociation `json:"transit_ip_associations"`
	CreatedAt             string                 `json:"created_at"`
	UpdatedAt             string                 `json:"updated_at"`
	EnterpriseProjectID   string                 `json:"enterprise_project_id"`
	Status                string                 `json:"status"`
}

type privateSnatEnvelope struct {
	SnatRule  privateSnatResponseBody `json:"snat_rule"`
	RequestID string                  `json:"request_id"`
}

type listPrivateSnatsResponse struct {
	SnatRules []privateSnatResponseBody `json:"snat_rules"`
	PageInfo  pageInfo                  `json:"page_info"`
	RequestID string                    `json:"request_id"`
}

// --- Private DNAT wire types (§3.9) ---

type createPrivateDnatRequest struct {
	DnatRule *createPrivateDnatOption `json:"dnat_rule"`
}

type createPrivateDnatOption struct {
	Description         *string `json:"description,omitempty"`
	TransitIPID         string  `json:"transit_ip_id"`
	NetworkInterfaceID  *string `json:"network_interface_id,omitempty"`
	GatewayID           string  `json:"gateway_id"`
	Protocol            *string `json:"protocol,omitempty"`
	PrivateIPAddress    *string `json:"private_ip_address,omitempty"`
	InternalServicePort *string `json:"internal_service_port,omitempty"`
	TransitServicePort  *string `json:"transit_service_port,omitempty"`
}

type updatePrivateDnatRequest struct {
	DnatRule *updatePrivateDnatOption `json:"dnat_rule"`
}

type updatePrivateDnatOption struct {
	Description         *string `json:"description,omitempty"`
	TransitIPID         *string `json:"transit_ip_id,omitempty"`
	NetworkInterfaceID  *string `json:"network_interface_id,omitempty"`
	PrivateIPAddress    *string `json:"private_ip_address,omitempty"`
	Protocol            *string `json:"protocol,omitempty"`
	InternalServicePort *string `json:"internal_service_port,omitempty"`
	TransitServicePort  *string `json:"transit_service_port,omitempty"`
}

type privateDnatResponseBody struct {
	ID                  string `json:"id"`
	ProjectID           string `json:"project_id"`
	Description         string `json:"description"`
	TransitIPID         string `json:"transit_ip_id"`
	GatewayID           string `json:"gateway_id"`
	NetworkInterfaceID  string `json:"network_interface_id"`
	Type                string `json:"type"`
	Protocol            string `json:"protocol"`
	PrivateIPAddress    string `json:"private_ip_address"`
	InternalServicePort string `json:"internal_service_port"`
	TransitServicePort  string `json:"transit_service_port"`
	EnterpriseProjectID string `json:"enterprise_project_id"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
	Status              string `json:"status"`
}

type privateDnatEnvelope struct {
	DnatRule  privateDnatResponseBody `json:"dnat_rule"`
	RequestID string                  `json:"request_id"`
}

type listPrivateDnatsResponse struct {
	DnatRules []privateDnatResponseBody `json:"dnat_rules"`
	PageInfo  pageInfo                  `json:"page_info"`
	RequestID string                    `json:"request_id"`
}

// --- Transit IP handlers (§3.7) ---

func (s *Service) handleCreateTransitIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createTransitIPRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.TransitIP == nil {
		return errBadJSON("transit_ip is required")
	}
	var tags []tag
	if req.TransitIP.Tags != nil {
		tags = *req.TransitIP.Tags
	}
	ti, err := s.createTransitIP(r.Context(), t, createTransitIPInput{
		VirsubnetID:         req.TransitIP.VirsubnetID,
		IPAddress:           derefString(req.TransitIP.IPAddress),
		EnterpriseProjectID: derefString(req.TransitIP.EnterpriseProjectID),
		Tags:                tags,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, transitIPEnvelope{
		TransitIP: toTransitIPResp(t, ti),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleListTransitIPs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errBadJSON("%s", err)
	}
	window, all, err := s.listTransitIPs(r.Context(), t, listTransitIPsFilter{
		IDs:                  nonEmpty(q["id"]),
		ProjectIDs:           nonEmpty(q["project_id"]),
		NetworkInterfaceIDs:  nonEmpty(q["network_interface_id"]),
		IPAddresses:          nonEmpty(q["ip_address"]),
		GatewayIDs:           nonEmpty(q["gateway_id"]),
		EnterpriseProjectIDs: nonEmpty(q["enterprise_project_id"]),
		VirsubnetIDs:         nonEmpty(q["virsubnet_id"]),
		TransitSubnetIDs:     nonEmpty(q["transit_subnet_id"]),
		Page:                 page,
	})
	if err != nil {
		return err
	}
	out := make([]transitIPResponseBody, len(window))
	for i, ti := range window {
		out[i] = toTransitIPResp(t, ti)
	}
	return httpx.WriteJSON(w, http.StatusOK, listTransitIPsResponse{
		TransitIPs: out,
		PageInfo:   buildPageInfo(window, all, func(ti transitIP) string { return ti.ID }),
		RequestID:  privateRequestID(r),
	})
}

func (s *Service) handleShowTransitIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "transit_ip_id")
	ti, err := s.getTransitIP(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, transitIPEnvelope{
		TransitIP: toTransitIPResp(t, ti),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleDeleteTransitIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "transit_ip_id")
	if err := s.deleteTransitIP(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// --- Private SNAT handlers (§3.8) ---

func (s *Service) handleCreatePrivateSnat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createPrivateSnatRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.SnatRule == nil {
		return errBadJSON("snat_rule is required")
	}
	view, err := s.createPrivateSnat(r.Context(), t, createPrivateSnatInput{
		GatewayID:    req.SnatRule.GatewayID,
		CIDR:         derefString(req.SnatRule.CIDR),
		VirsubnetID:  derefString(req.SnatRule.VirsubnetID),
		Description:  derefString(req.SnatRule.Description),
		TransitIPIDs: req.SnatRule.TransitIPIDs,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, privateSnatEnvelope{
		SnatRule:  toPrivateSnatResp(t, view),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleListPrivateSnats(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errBadJSON("%s", err)
	}
	window, all, err := s.listPrivateSnats(r.Context(), t, listPrivateSnatsFilter{
		IDs:                  nonEmpty(q["id"]),
		ProjectIDs:           nonEmpty(q["project_id"]),
		Descriptions:         nonEmpty(q["description"]),
		GatewayIDs:           nonEmpty(q["gateway_id"]),
		CIDRs:                nonEmpty(q["cidr"]),
		VirsubnetIDs:         nonEmpty(q["virsubnet_id"]),
		TransitIPIDs:         nonEmpty(q["transit_ip_id"]),
		TransitIPAddresses:   nonEmpty(q["transit_ip_address"]),
		EnterpriseProjectIDs: nonEmpty(q["enterprise_project_id"]),
		Page:                 page,
	})
	if err != nil {
		return err
	}
	out := make([]privateSnatResponseBody, len(window))
	for i, v := range window {
		out[i] = toPrivateSnatResp(t, v)
	}
	return httpx.WriteJSON(w, http.StatusOK, listPrivateSnatsResponse{
		SnatRules: out,
		PageInfo:  buildPageInfo(window, all, func(v privateSnatView) string { return v.Rule.ID }),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleShowPrivateSnat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "snat_rule_id")
	view, err := s.getPrivateSnat(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, privateSnatEnvelope{
		SnatRule:  toPrivateSnatResp(t, view),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleUpdatePrivateSnat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updatePrivateSnatRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.SnatRule == nil {
		return errBadJSON("snat_rule is required")
	}
	id := chi.URLParam(r, "snat_rule_id")
	view, err := s.updatePrivateSnat(r.Context(), t, id, updatePrivateSnatInput{
		TransitIPIDs: req.SnatRule.TransitIPIDs,
		Description:  req.SnatRule.Description,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, privateSnatEnvelope{
		SnatRule:  toPrivateSnatResp(t, view),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleDeletePrivateSnat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "snat_rule_id")
	if err := s.deletePrivateSnat(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// --- Private DNAT handlers (§3.9) ---

func (s *Service) handleCreatePrivateDnat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createPrivateDnatRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.DnatRule == nil {
		return errBadJSON("dnat_rule is required")
	}
	view, err := s.createPrivateDnat(r.Context(), t, createPrivateDnatInput{
		Description:         derefString(req.DnatRule.Description),
		TransitIPID:         req.DnatRule.TransitIPID,
		NetworkInterfaceID:  derefString(req.DnatRule.NetworkInterfaceID),
		GatewayID:           req.DnatRule.GatewayID,
		Protocol:            req.DnatRule.Protocol,
		PrivateIPAddress:    derefString(req.DnatRule.PrivateIPAddress),
		InternalServicePort: req.DnatRule.InternalServicePort,
		TransitServicePort:  req.DnatRule.TransitServicePort,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, privateDnatEnvelope{
		DnatRule:  toPrivateDnatResp(t, view),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleListPrivateDnats(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errBadJSON("%s", err)
	}
	window, all, err := s.listPrivateDnats(r.Context(), t, listPrivateDnatsFilter{
		IDs:                  nonEmpty(q["id"]),
		ProjectIDs:           nonEmpty(q["project_id"]),
		EnterpriseProjectIDs: nonEmpty(q["enterprise_project_id"]),
		Descriptions:         nonEmpty(q["description"]),
		GatewayIDs:           nonEmpty(q["gateway_id"]),
		TransitIPIDs:         nonEmpty(q["transit_ip_id"]),
		NetworkInterfaceIDs:  nonEmpty(q["network_interface_id"]),
		Types:                nonEmpty(q["type"]),
		PrivateIPAddresses:   nonEmpty(q["private_ip_address"]),
		Protocols:            nonEmpty(q["protocol"]),
		InternalServicePorts: nonEmpty(q["internal_service_port"]),
		TransitServicePorts:  nonEmpty(q["transit_service_port"]),
		TransitIPAddresses:   nonEmpty(q["transit_ip_address"]),
		Page:                 page,
	})
	if err != nil {
		return err
	}
	out := make([]privateDnatResponseBody, len(window))
	for i, v := range window {
		out[i] = toPrivateDnatResp(t, v)
	}
	return httpx.WriteJSON(w, http.StatusOK, listPrivateDnatsResponse{
		DnatRules: out,
		PageInfo:  buildPageInfo(window, all, func(v privateDnatView) string { return v.Rule.ID }),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleShowPrivateDnat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "dnat_rule_id")
	view, err := s.getPrivateDnat(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, privateDnatEnvelope{
		DnatRule:  toPrivateDnatResp(t, view),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleUpdatePrivateDnat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updatePrivateDnatRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.DnatRule == nil {
		return errBadJSON("dnat_rule is required")
	}
	id := chi.URLParam(r, "dnat_rule_id")
	view, err := s.updatePrivateDnat(r.Context(), t, id, updatePrivateDnatInput{
		Description:         req.DnatRule.Description,
		TransitIPID:         req.DnatRule.TransitIPID,
		NetworkInterfaceID:  req.DnatRule.NetworkInterfaceID,
		PrivateIPAddress:    req.DnatRule.PrivateIPAddress,
		Protocol:            req.DnatRule.Protocol,
		InternalServicePort: req.DnatRule.InternalServicePort,
		TransitServicePort:  req.DnatRule.TransitServicePort,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, privateDnatEnvelope{
		DnatRule:  toPrivateDnatResp(t, view),
		RequestID: privateRequestID(r),
	})
}

func (s *Service) handleDeletePrivateDnat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "dnat_rule_id")
	if err := s.deletePrivateDnat(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// --- Response mappers & helpers ---

func privateRequestID(r *http.Request) string {
	return reqctx.From(r.Context()).RequestID
}

func buildPageInfo[T any](window, all []T, idFn func(T) string) pageInfo {
	info := pageInfo{CurrentCount: len(window)}
	if len(window) > 0 {
		info.PreviousMarker = idFn(window[0])
		if last := idFn(window[len(window)-1]); last != idFn(all[len(all)-1]) {
			info.NextMarker = last
		}
	}
	return info
}

func toTransitIPResp(t Tenant, ti transitIP) transitIPResponseBody {
	tags := []tag{}
	if len(ti.Tags) > 0 {
		tags = slices.Clone(ti.Tags)
	}
	return transitIPResponseBody{
		ID:                  ti.ID,
		ProjectID:           t.ProjectID,
		NetworkInterfaceID:  ti.NetworkInterfaceID,
		IPAddress:           ti.Address,
		CreatedAt:           ti.CreatedAt.UTC().Format(privateTimeFormat),
		UpdatedAt:           ti.UpdatedAt.UTC().Format(privateTimeFormat),
		VirsubnetID:         ti.SubnetID,
		Tags:                tags,
		GatewayID:           ti.GatewayID,
		EnterpriseProjectID: ti.EnterpriseProjectID,
		Status:              StatusActive,
	}
}

func toPrivateSnatResp(t Tenant, v privateSnatView) privateSnatResponseBody {
	assocs := v.Associations
	if assocs == nil {
		assocs = []transitIPAssociation{}
	}
	return privateSnatResponseBody{
		ID:                    v.Rule.ID,
		ProjectID:             t.ProjectID,
		GatewayID:             v.Rule.GatewayID,
		CIDR:                  v.Rule.CIDR,
		VirsubnetID:           v.Rule.SubnetID,
		Description:           v.Rule.Description,
		TransitIPAssociations: assocs,
		CreatedAt:             v.Rule.CreatedAt.UTC().Format(privateTimeFormat),
		UpdatedAt:             v.Rule.UpdatedAt.UTC().Format(privateTimeFormat),
		EnterpriseProjectID:   v.EnterpriseProjectID,
		Status:                StatusActive,
	}
}

func toPrivateDnatResp(t Tenant, v privateDnatView) privateDnatResponseBody {
	return privateDnatResponseBody{
		ID:                  v.Rule.ID,
		ProjectID:           t.ProjectID,
		Description:         v.Rule.Description,
		TransitIPID:         v.Rule.TransitIPID,
		GatewayID:           v.Rule.GatewayID,
		NetworkInterfaceID:  v.Rule.NetworkInterfaceID,
		Type:                v.Rule.Type,
		Protocol:            v.Rule.Protocol,
		PrivateIPAddress:    v.Rule.PrivateIP,
		InternalServicePort: v.Rule.InternalPort,
		TransitServicePort:  v.Rule.TransitPort,
		EnterpriseProjectID: v.EnterpriseProjectID,
		CreatedAt:           v.Rule.CreatedAt.UTC().Format(privateTimeFormat),
		UpdatedAt:           v.Rule.UpdatedAt.UTC().Format(privateTimeFormat),
		Status:              StatusActive,
	}
}
