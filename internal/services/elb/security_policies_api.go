package elb

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

type secpolCreateRequest struct {
	SecurityPolicy *secpolCreateOption `json:"security_policy"`
}

type secpolCreateOption struct {
	Name                *string  `json:"name"`
	Description         *string  `json:"description"`
	EnterpriseProjectID *string  `json:"enterprise_project_id"`
	Protocols           []string `json:"protocols"`
	Ciphers             []string `json:"ciphers"`
}

type secpolUpdateRequest struct {
	SecurityPolicy *secpolUpdateOption `json:"security_policy"`
}

type secpolUpdateOption struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Protocols   *[]string `json:"protocols"`
	Ciphers     *[]string `json:"ciphers"`
}

// secpolWire matches SDK model SecurityPolicy field-for-field.
type secpolWire struct {
	ID                  string   `json:"id"`
	ProjectID           string   `json:"project_id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Listeners           []idRef  `json:"listeners"`
	Protocols           []string `json:"protocols"`
	Ciphers             []string `json:"ciphers"`
	EnterpriseProjectID string   `json:"enterprise_project_id"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
}

type secpolEnvelope struct {
	RequestID      string     `json:"request_id"`
	SecurityPolicy secpolWire `json:"security_policy"`
}

type secpolListResponse struct {
	RequestID        string       `json:"request_id"`
	SecurityPolicies []secpolWire `json:"security_policies"`
	PageInfo         pageInfo     `json:"page_info"`
}

type secpolSystemListResponse struct {
	RequestID              string                     `json:"request_id"`
	SystemSecurityPolicies []systemSecurityPolicyWire `json:"system_security_policies"`
}

func secpolDerefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func secpolNonEmpty(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func secpolToWire(t Tenant, d secpolDetail) secpolWire {
	sp := d.Policy
	protocols := make([]string, len(sp.Protocols))
	copy(protocols, sp.Protocols)

	ciphers := make([]string, len(sp.Ciphers))
	copy(ciphers, sp.Ciphers)

	listeners := make([]idRef, len(d.ListenerIDs))
	for i, id := range d.ListenerIDs {
		listeners[i] = idRef{ID: id}
	}

	ep := sp.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}

	return secpolWire{
		ID:                  sp.ID,
		ProjectID:           t.ProjectID,
		Name:                sp.Name,
		Description:         sp.Description,
		Listeners:           listeners,
		Protocols:           protocols,
		Ciphers:             ciphers,
		EnterpriseProjectID: ep,
		CreatedAt:           formatTime(sp.CreatedAt),
		UpdatedAt:           formatTime(sp.UpdatedAt),
	}
}

func (s *Service) handleCreateSecurityPolicy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req secpolCreateRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.SecurityPolicy == nil {
		return errInvalidInput("security_policy")
	}
	opt := req.SecurityPolicy
	detail, err := s.createSecurityPolicy(r.Context(), t, secpolCreateInput{
		Name:                secpolDerefString(opt.Name),
		Description:         secpolDerefString(opt.Description),
		Protocols:           opt.Protocols,
		Ciphers:             opt.Ciphers,
		EnterpriseProjectID: opt.EnterpriseProjectID,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, secpolEnvelope{
		RequestID:      requestID(r),
		SecurityPolicy: secpolToWire(t, detail),
	})
}

func (s *Service) handleListSecurityPolicies(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	if _, err := parseBoolQuery(q, "page_reverse"); err != nil {
		return err
	}

	items, pi, err := s.listSecurityPolicies(r.Context(), t, secpolListFilter{
		IDs:                  secpolNonEmpty(q["id"]),
		Names:                secpolNonEmpty(q["name"]),
		Descriptions:         secpolNonEmpty(q["description"]),
		Protocols:            secpolNonEmpty(q["protocols"]),
		Ciphers:              secpolNonEmpty(q["ciphers"]),
		EnterpriseProjectIDs: secpolNonEmpty(q["enterprise_project_id"]),
		Page:                 page,
	})
	if err != nil {
		return err
	}
	out := make([]secpolWire, 0, len(items))
	for _, item := range items {
		out = append(out, secpolToWire(t, item))
	}
	return httpx.WriteJSON(w, http.StatusOK, secpolListResponse{
		RequestID:        requestID(r),
		SecurityPolicies: out,
		PageInfo:         pi,
	})
}

func (s *Service) handleShowSecurityPolicy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "security_policy_id")
	detail, err := s.getSecurityPolicy(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, secpolEnvelope{
		RequestID:      requestID(r),
		SecurityPolicy: secpolToWire(t, detail),
	})
}

func (s *Service) handleUpdateSecurityPolicy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req secpolUpdateRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.SecurityPolicy == nil {
		return errInvalidInput("security_policy")
	}
	id := chi.URLParam(r, "security_policy_id")
	opt := req.SecurityPolicy
	detail, err := s.updateSecurityPolicy(r.Context(), t, id, secpolUpdateInput{
		Name:        opt.Name,
		Description: opt.Description,
		Protocols:   opt.Protocols,
		Ciphers:     opt.Ciphers,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, secpolEnvelope{
		RequestID:      requestID(r),
		SecurityPolicy: secpolToWire(t, detail),
	})
}

func (s *Service) handleDeleteSecurityPolicy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "security_policy_id")
	if err := s.deleteSecurityPolicy(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListSystemSecurityPolicies(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return httpx.WriteJSON(w, http.StatusOK, secpolSystemListResponse{
		RequestID:              requestID(r),
		SystemSecurityPolicies: seededSystemSecurityPolicies(t.ProjectID),
	})
}
