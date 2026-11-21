package elb

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

type ipgIPOption struct {
	IP          string  `json:"ip"`
	Description *string `json:"description"`
}

type ipgCreateRequest struct {
	IPGroup *ipgCreateOption `json:"ipgroup"`
}

type ipgCreateOption struct {
	ProjectID           *string        `json:"project_id"`
	Name                *string        `json:"name"`
	Description         *string        `json:"description"`
	IPList              *[]ipgIPOption `json:"ip_list"`
	EnterpriseProjectID *string        `json:"enterprise_project_id"`
}

type ipgUpdateRequest struct {
	IPGroup *ipgUpdateOption `json:"ipgroup"`
}

type ipgUpdateOption struct {
	Name        *string        `json:"name"`
	Description *string        `json:"description"`
	IPList      *[]ipgIPOption `json:"ip_list"`
}

// ipgWire matches SDK model IpGroup field-for-field.
type ipgWire struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	IPList              []ipInfo `json:"ip_list"`
	Listeners           []idRef  `json:"listeners"`
	ProjectID           string   `json:"project_id"`
	EnterpriseProjectID string   `json:"enterprise_project_id"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
}

type ipgEnvelope struct {
	RequestID string  `json:"request_id"`
	IPGroup   ipgWire `json:"ipgroup"`
}

type ipgListResponse struct {
	RequestID string    `json:"request_id"`
	IPGroups  []ipgWire `json:"ipgroups"`
	PageInfo  pageInfo  `json:"page_info"`
}

func ipgDerefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func ipgNonEmpty(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func ipgConvertIPOptions(opts []ipgIPOption) []ipInfo {
	out := make([]ipInfo, len(opts))
	for i, opt := range opts {
		out[i] = ipInfo{
			IP:          opt.IP,
			Description: ipgDerefString(opt.Description),
		}
	}
	return out
}

func ipgToWire(t Tenant, d ipgDetail) ipgWire {
	g := d.Group
	ipList := make([]ipInfo, len(g.IPList))
	copy(ipList, g.IPList)

	listeners := make([]idRef, len(d.ListenerIDs))
	for i, id := range d.ListenerIDs {
		listeners[i] = idRef{ID: id}
	}

	ep := g.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}

	return ipgWire{
		ID:                  g.ID,
		Name:                g.Name,
		Description:         g.Description,
		IPList:              ipList,
		Listeners:           listeners,
		ProjectID:           t.ProjectID,
		EnterpriseProjectID: ep,
		CreatedAt:           formatTime(g.CreatedAt),
		UpdatedAt:           formatTime(g.UpdatedAt),
	}
}

func (s *Service) handleCreateIPGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req ipgCreateRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.IPGroup == nil {
		return errInvalidInput("ipgroup")
	}
	opt := req.IPGroup

	in := ipgCreateInput{
		Name:                ipgDerefString(opt.Name),
		Description:         ipgDerefString(opt.Description),
		EnterpriseProjectID: opt.EnterpriseProjectID,
	}
	if opt.IPList != nil {
		in.IPListSet = true
		in.IPList = ipgConvertIPOptions(*opt.IPList)
	}

	detail, err := s.createIPGroup(r.Context(), t, in)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, ipgEnvelope{
		RequestID: requestID(r),
		IPGroup:   ipgToWire(t, detail),
	})
}

func (s *Service) handleListIPGroups(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	if _, err := parseBoolQuery(q, "page_reverse"); err != nil {
		return err
	}

	items, pi, err := s.listIPGroups(r.Context(), t, ipgListFilter{
		IDs:                  ipgNonEmpty(q["id"]),
		Names:                ipgNonEmpty(q["name"]),
		Descriptions:         ipgNonEmpty(q["description"]),
		IPs:                  ipgNonEmpty(q["ip_list"]),
		EnterpriseProjectIDs: ipgNonEmpty(q["enterprise_project_id"]),
		Page:                 page,
	})
	if err != nil {
		return err
	}
	out := make([]ipgWire, 0, len(items))
	for _, item := range items {
		out = append(out, ipgToWire(t, item))
	}
	return httpx.WriteJSON(w, http.StatusOK, ipgListResponse{
		RequestID: requestID(r),
		IPGroups:  out,
		PageInfo:  pi,
	})
}

func (s *Service) handleShowIPGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "ipgroup_id")
	detail, err := s.getIPGroup(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, ipgEnvelope{
		RequestID: requestID(r),
		IPGroup:   ipgToWire(t, detail),
	})
}

func (s *Service) handleUpdateIPGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req ipgUpdateRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.IPGroup == nil {
		return errInvalidInput("ipgroup")
	}
	id := chi.URLParam(r, "ipgroup_id")
	opt := req.IPGroup

	in := ipgUpdateInput{
		Name:        opt.Name,
		Description: opt.Description,
	}
	if opt.IPList != nil {
		converted := ipgConvertIPOptions(*opt.IPList)
		in.IPList = &converted
	}

	detail, err := s.updateIPGroup(r.Context(), t, id, in)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, ipgEnvelope{
		RequestID: requestID(r),
		IPGroup:   ipgToWire(t, detail),
	})
}

func (s *Service) handleDeleteIPGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "ipgroup_id")
	if err := s.deleteIPGroup(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
