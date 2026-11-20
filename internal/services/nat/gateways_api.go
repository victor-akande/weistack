package nat

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

// decodePublic decodes a public NAT JSON request body: malformed JSON or an
// empty body maps to NAT.1010, whereas a JSON type mismatch maps to NAT.0002 (§3).
func decodePublic(r *http.Request, dst any) error {
	var raw json.RawMessage
	if err := decode(r, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return errInvalidParams("")
		}
		return errBadJSON("%s", err)
	}
	return nil
}

type sessionConfReq struct {
	TCPSessionExpireTime  *int `json:"tcp_session_expire_time"`
	UDPSessionExpireTime  *int `json:"udp_session_expire_time"`
	ICMPSessionExpireTime *int `json:"icmp_session_expire_time"`
	TCPTimeWaitTime       *int `json:"tcp_time_wait_time"`
}

func (r *sessionConfReq) toInput() *sessionConfInput {
	if r == nil {
		return nil
	}
	return &sessionConfInput{
		TCPSessionExpireTime:  r.TCPSessionExpireTime,
		UDPSessionExpireTime:  r.UDPSessionExpireTime,
		ICMPSessionExpireTime: r.ICMPSessionExpireTime,
		TCPTimeWaitTime:       r.TCPTimeWaitTime,
	}
}

type createNatGatewayRequest struct {
	NatGateway *createNatGatewayOption `json:"nat_gateway"`
}

type createNatGatewayOption struct {
	Name                string           `json:"name"`
	RouterID            string           `json:"router_id"`
	InternalNetworkID   string           `json:"internal_network_id"`
	NgportIPAddress     *string          `json:"ngport_ip_address"`
	Description         *string          `json:"description"`
	Tags                *[]string        `json:"tags"`
	Spec                string           `json:"spec"`
	EnterpriseProjectID *string          `json:"enterprise_project_id"`
	SessionConf         *sessionConfReq  `json:"session_conf"`
	PrepaidOptions      *json.RawMessage `json:"prepaid_options"`
}

type updateNatGatewayRequest struct {
	NatGateway *updateNatGatewayOption `json:"nat_gateway"`
}

type updateNatGatewayOption struct {
	Name           *string          `json:"name"`
	Description    *string          `json:"description"`
	Spec           *string          `json:"spec"`
	SessionConf    *sessionConfReq  `json:"session_conf"`
	PrepaidOptions *json.RawMessage `json:"prepaid_options"`
}

type natGatewayResponseBody struct {
	ID                    string      `json:"id"`
	TenantID              string      `json:"tenant_id"`
	Name                  string      `json:"name"`
	Description           string      `json:"description"`
	Spec                  string      `json:"spec"`
	Status                string      `json:"status"`
	AdminStateUp          bool        `json:"admin_state_up"`
	CreatedAt             string      `json:"created_at"`
	RouterID              string      `json:"router_id"`
	InternalNetworkID     string      `json:"internal_network_id"`
	EnterpriseProjectID   string      `json:"enterprise_project_id"`
	SessionConf           sessionConf `json:"session_conf"`
	NgportIPAddress       string      `json:"ngport_ip_address"`
	BillingInfo           string      `json:"billing_info"`
	DnatRulesLimit        int64       `json:"dnat_rules_limit"`
	SnatRulePublicIPLimit int32       `json:"snat_rule_public_ip_limit"`
}

type natGatewayEnvelope struct {
	NatGateway natGatewayResponseBody `json:"nat_gateway"`
}

type listNatGatewaysResponse struct {
	NatGateways []natGatewayResponseBody `json:"nat_gateways"`
}

func hasJSONValue(raw *json.RawMessage) bool {
	if raw == nil {
		return false
	}
	trimmed := bytes.TrimSpace(*raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func nonEmpty(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func toGatewayResp(t Tenant, g gateway) natGatewayResponseBody {
	return natGatewayResponseBody{
		ID:                    g.ID,
		TenantID:              t.ProjectID,
		Name:                  g.Name,
		Description:           g.Description,
		Spec:                  g.Spec,
		Status:                g.Status,
		AdminStateUp:          true,
		CreatedAt:             g.CreatedAt.UTC().Format(publicTimeFormat),
		RouterID:              g.RouterID,
		InternalNetworkID:     g.InternalNetworkID,
		EnterpriseProjectID:   g.EnterpriseProjectID,
		SessionConf:           g.Session,
		NgportIPAddress:       g.NgportIP,
		BillingInfo:           "",
		DnatRulesLimit:        int64(dnatRulesLimitForSpec(g.Spec)),
		SnatRulePublicIPLimit: publicSnatPublicIPLimit,
	}
}

func (s *Service) handleCreateNatGateway(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createNatGatewayRequest
	if err := decodePublic(r, &req); err != nil {
		return err
	}
	if req.NatGateway == nil {
		return errInvalidParams("")
	}
	opt := req.NatGateway
	var tags []string
	if opt.Tags != nil {
		tags = *opt.Tags
	}
	g, err := s.createGateway(r.Context(), t, createGatewayInput{
		Name:                opt.Name,
		RouterID:            opt.RouterID,
		InternalNetworkID:   opt.InternalNetworkID,
		NgportIPAddress:     derefString(opt.NgportIPAddress),
		Description:         derefString(opt.Description),
		Spec:                opt.Spec,
		EnterpriseProjectID: derefString(opt.EnterpriseProjectID),
		SessionConf:         opt.SessionConf.toInput(),
		Tags:                tags,
		PrepaidOptions:      hasJSONValue(opt.PrepaidOptions),
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, natGatewayEnvelope{
		NatGateway: toGatewayResp(t, g),
	})
}

func (s *Service) handleListNatGateways(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidParams("")
	}
	var adminStateUp *bool
	if raw := q.Get("admin_state_up"); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return errInvalidParams("")
		}
		adminStateUp = &v
	}
	items, err := s.listGateways(r.Context(), t, listGatewaysFilter{
		TenantID:            q.Get("tenant_id"),
		ID:                  q.Get("id"),
		EnterpriseProjectID: q.Get("enterprise_project_id"),
		Description:         q.Get("description"),
		CreatedAt:           q.Get("created_at"),
		Name:                q.Get("name"),
		Statuses:            nonEmpty(q["status"]),
		Specs:               nonEmpty(q["spec"]),
		AdminStateUp:        adminStateUp,
		InternalNetworkID:   q.Get("internal_network_id"),
		RouterID:            q.Get("router_id"),
		Page:                page,
	})
	if err != nil {
		return err
	}
	out := make([]natGatewayResponseBody, 0, len(items))
	for _, g := range items {
		out = append(out, toGatewayResp(t, g))
	}
	return httpx.WriteJSON(w, http.StatusOK, listNatGatewaysResponse{NatGateways: out})
}

func (s *Service) handleShowNatGateway(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "nat_gateway_id")
	g, err := s.getGateway(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, natGatewayEnvelope{
		NatGateway: toGatewayResp(t, g),
	})
}

func (s *Service) handleUpdateNatGateway(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateNatGatewayRequest
	if err := decodePublic(r, &req); err != nil {
		return err
	}
	if req.NatGateway == nil {
		return errInvalidParams("")
	}
	id := chi.URLParam(r, "nat_gateway_id")
	opt := req.NatGateway
	g, err := s.updateGateway(r.Context(), t, id, updateGatewayInput{
		Name:           opt.Name,
		Description:    opt.Description,
		Spec:           opt.Spec,
		SessionConf:    opt.SessionConf.toInput(),
		PrepaidOptions: hasJSONValue(opt.PrepaidOptions),
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, natGatewayEnvelope{
		NatGateway: toGatewayResp(t, g),
	})
}

func (s *Service) handleDeleteNatGateway(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "nat_gateway_id")
	if err := s.deleteGateway(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListNatGatewaySpecs(_ http.ResponseWriter, _ *http.Request, _ Tenant) error {
	return apierr.NotImplemented("nat", "ListNatGatewaySpecs")
}
