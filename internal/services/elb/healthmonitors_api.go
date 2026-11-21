package elb

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

type createHealthMonitorRequest struct {
	HealthMonitor *createHealthMonitorOptionReq `json:"healthmonitor"`
}

type createHealthMonitorOptionReq struct {
	AdminStateUp   *bool   `json:"admin_state_up"`
	Delay          int     `json:"delay"`
	DomainName     *string `json:"domain_name"`
	ExpectedCodes  *string `json:"expected_codes"`
	HTTPMethod     *string `json:"http_method"`
	MaxRetries     int     `json:"max_retries"`
	MaxRetriesDown *int    `json:"max_retries_down"`
	MonitorPort    *int    `json:"monitor_port"`
	Name           *string `json:"name"`
	PoolID         string  `json:"pool_id"`
	ProjectID      *string `json:"project_id"`
	Timeout        int     `json:"timeout"`
	Type           string  `json:"type"`
	URLPath        *string `json:"url_path"`
}

type updateHealthMonitorRequest struct {
	HealthMonitor *updateHealthMonitorOptionReq `json:"healthmonitor"`
}

type updateHealthMonitorOptionReq struct {
	AdminStateUp   *bool                `json:"admin_state_up"`
	Delay          *int                 `json:"delay"`
	DomainName     poolOptional[string] `json:"domain_name"`
	ExpectedCodes  *string              `json:"expected_codes"`
	HTTPMethod     *string              `json:"http_method"`
	MaxRetries     *int                 `json:"max_retries"`
	MaxRetriesDown *int                 `json:"max_retries_down"`
	MonitorPort    poolOptional[int]    `json:"monitor_port"`
	Name           *string              `json:"name"`
	Timeout        *int                 `json:"timeout"`
	Type           *string              `json:"type"`
	URLPath        *string              `json:"url_path"`
}

type healthMonitorResponse struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	ProjectID      string  `json:"project_id"`
	Type           string  `json:"type"`
	Delay          int     `json:"delay"`
	Timeout        int     `json:"timeout"`
	MaxRetries     int     `json:"max_retries"`
	MaxRetriesDown int     `json:"max_retries_down"`
	MonitorPort    *int    `json:"monitor_port"`
	HTTPMethod     string  `json:"http_method"`
	URLPath        string  `json:"url_path"`
	ExpectedCodes  string  `json:"expected_codes"`
	DomainName     *string `json:"domain_name"`
	AdminStateUp   bool    `json:"admin_state_up"`
	Pools          []idRef `json:"pools"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

type healthMonitorEnvelope struct {
	RequestID     string                `json:"request_id"`
	HealthMonitor healthMonitorResponse `json:"healthmonitor"`
}

type listHealthMonitorsResponse struct {
	RequestID      string                  `json:"request_id"`
	HealthMonitors []healthMonitorResponse `json:"healthmonitors"`
	PageInfo       pageInfo                `json:"page_info"`
}

func toHealthMonitorResponse(t Tenant, hm healthMonitor) healthMonitorResponse {
	var port *int
	if hm.MonitorPort > 0 {
		p := hm.MonitorPort
		port = &p
	}
	var domain *string
	if hm.DomainName != "" {
		d := hm.DomainName
		domain = &d
	}
	pools := make([]idRef, 0, 1)
	if hm.PoolID != "" {
		pools = append(pools, idRef{ID: hm.PoolID})
	}
	return healthMonitorResponse{
		ID:             hm.ID,
		Name:           hm.Name,
		ProjectID:      t.ProjectID,
		Type:           hm.Type,
		Delay:          hm.Delay,
		Timeout:        hm.Timeout,
		MaxRetries:     hm.MaxRetries,
		MaxRetriesDown: hm.MaxRetriesDown,
		MonitorPort:    port,
		HTTPMethod:     hm.HTTPMethod,
		URLPath:        hm.URLPath,
		ExpectedCodes:  hm.ExpectedCodes,
		DomainName:     domain,
		AdminStateUp:   hm.AdminStateUp,
		Pools:          pools,
		CreatedAt:      formatTime(hm.CreatedAt),
		UpdatedAt:      formatTime(hm.UpdatedAt),
	}
}

func (s *Service) handleCreateHealthMonitor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createHealthMonitorRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.HealthMonitor == nil {
		return errInvalidInput("healthmonitor")
	}
	opt := req.HealthMonitor
	hm, err := s.createHealthMonitor(r.Context(), t, createHealthMonitorInput{
		PoolID:         opt.PoolID,
		Name:           poolDerefString(opt.Name),
		Type:           opt.Type,
		Delay:          opt.Delay,
		Timeout:        opt.Timeout,
		MaxRetries:     opt.MaxRetries,
		MaxRetriesDown: opt.MaxRetriesDown,
		MonitorPort:    opt.MonitorPort,
		HTTPMethod:     opt.HTTPMethod,
		URLPath:        opt.URLPath,
		ExpectedCodes:  opt.ExpectedCodes,
		DomainName:     opt.DomainName,
		AdminStateUp:   opt.AdminStateUp,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, healthMonitorEnvelope{
		RequestID:     requestID(r),
		HealthMonitor: toHealthMonitorResponse(t, hm),
	})
}

func (s *Service) handleListHealthMonitors(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	pageReverse, err := parseBoolQuery(q, "page_reverse")
	if err != nil {
		return err
	}
	adminStateUp, err := parseBoolQuery(q, "admin_state_up")
	if err != nil {
		return err
	}
	monitorPorts, err := parseIntQueryValues(q, "monitor_port")
	if err != nil {
		return err
	}
	delays, err := parseIntQueryValues(q, "delay")
	if err != nil {
		return err
	}
	timeouts, err := parseIntQueryValues(q, "timeout")
	if err != nil {
		return err
	}
	maxRetries, err := parseIntQueryValues(q, "max_retries")
	if err != nil {
		return err
	}
	maxRetriesDown, err := parseIntQueryValues(q, "max_retries_down")
	if err != nil {
		return err
	}

	items, pi, err := s.listHealthMonitors(r.Context(), t, listHealthMonitorsFilter{
		IDs:                  poolNonEmpty(q["id"]),
		Names:                poolNonEmpty(q["name"]),
		Types:                poolNonEmpty(q["type"]),
		MonitorPorts:         monitorPorts,
		DomainNames:          poolNonEmpty(q["domain_name"]),
		Delays:               delays,
		Timeouts:             timeouts,
		MaxRetries:           maxRetries,
		MaxRetriesDown:       maxRetriesDown,
		AdminStateUp:         adminStateUp,
		ExpectedCodes:        poolNonEmpty(q["expected_codes"]),
		URLPaths:             poolNonEmpty(q["url_path"]),
		HTTPMethods:          poolNonEmpty(q["http_method"]),
		EnterpriseProjectIDs: poolNonEmpty(q["enterprise_project_id"]),
		Page:                 page,
		PageReverse:          pageReverse != nil && *pageReverse,
	})
	if err != nil {
		return err
	}

	out := make([]healthMonitorResponse, 0, len(items))
	for _, item := range items {
		out = append(out, toHealthMonitorResponse(t, item))
	}
	return httpx.WriteJSON(w, http.StatusOK, listHealthMonitorsResponse{
		RequestID:      requestID(r),
		HealthMonitors: out,
		PageInfo:       pi,
	})
}

func (s *Service) handleShowHealthMonitor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "healthmonitor_id")
	hm, err := s.getHealthMonitor(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, healthMonitorEnvelope{
		RequestID:     requestID(r),
		HealthMonitor: toHealthMonitorResponse(t, hm),
	})
}

func (s *Service) handleUpdateHealthMonitor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateHealthMonitorRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.HealthMonitor == nil {
		return errInvalidInput("healthmonitor")
	}
	id := chi.URLParam(r, "healthmonitor_id")
	opt := req.HealthMonitor
	hm, err := s.updateHealthMonitor(r.Context(), t, id, updateHealthMonitorInput{
		Name:           opt.Name,
		Type:           opt.Type,
		Delay:          opt.Delay,
		Timeout:        opt.Timeout,
		MaxRetries:     opt.MaxRetries,
		MaxRetriesDown: opt.MaxRetriesDown,
		MonitorPort:    opt.MonitorPort,
		HTTPMethod:     opt.HTTPMethod,
		URLPath:        opt.URLPath,
		ExpectedCodes:  opt.ExpectedCodes,
		DomainName:     opt.DomainName,
		AdminStateUp:   opt.AdminStateUp,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, healthMonitorEnvelope{
		RequestID:     requestID(r),
		HealthMonitor: toHealthMonitorResponse(t, hm),
	})
}

func (s *Service) handleDeleteHealthMonitor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "healthmonitor_id")
	if err := s.deleteHealthMonitor(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
