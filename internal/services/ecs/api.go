package ecs

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Routes implements server.Service. Paths are those of the real API.
func (s *Service) Routes(r chi.Router) {
	r.Get("/v1/{project_id}/cloudservers/flavors", s.handle("ListFlavors", s.handleListFlavors))

	// Pay-per-use creation exists under two versions with one body.
	r.Post("/v1/{project_id}/cloudservers", s.handle("CreatePostPaidServers", s.handleCreateServers))
	r.Post("/v1.1/{project_id}/cloudservers", s.handle("CreateServers", s.handleCreateServers))
	r.Get("/v1/{project_id}/cloudservers/detail", s.handle("ListServersDetails", s.handleListServers))
	r.Post("/v1/{project_id}/cloudservers/delete", s.handle("DeleteServers", s.handleDeleteServers))
	r.Get("/v1/{project_id}/cloudservers/{server_id}", s.handle("ShowServer", s.handleShowServer))
	r.Get("/v1/{project_id}/jobs/{job_id}", s.handle("ShowJob", s.handleShowJob))
	r.Get("/v2.1/{project_id}/os-availability-zone", s.handle("NovaListAvailabilityZones", s.handleListZones))
}

type handler func(w http.ResponseWriter, r *http.Request, t Tenant) error

// handle adapts a handler: it names the operation for logs, resolves the
// tenant and renders errors in the ECS envelope.
func (s *Service) handle(op string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := reqctx.From(r.Context())
		info.SetOperation(op)
		t := Tenant{Region: info.Region, ProjectID: chi.URLParam(r, "project_id")}

		err := fn(w, r, t)
		if err == nil {
			return
		}
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(r.Context(), "ecs operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, apierr.StyleNested, err)
	}
}

// flavorLimits bounds "limit" on ListFlavors; without one every flavor
// is returned.
var flavorLimits = pagination.Limits{Default: math.MaxInt32, Min: 1, Max: math.MaxInt32}

type listFlavorsResponse struct {
	Flavors []Flavor `json:"flavors"`
}

func (s *Service) handleListFlavors(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, flavorLimits)
	if err != nil {
		return errInvalidRequest("%s", err)
	}
	all := s.ListFlavors(t, q.Get("availability_zone"))
	if id := q.Get("flavor_id"); id != "" {
		kept := all[:0]
		for _, f := range all {
			if f.ID == id {
				kept = append(kept, f)
			}
		}
		all = kept
	}
	out, err := pagination.ByMarker(all, func(f Flavor) string { return f.ID }, page)
	if err != nil {
		return errInvalidRequest("%s", err)
	}
	return httpx.WriteJSON(w, http.StatusOK, listFlavorsResponse{Flavors: out})
}

// The types below mirror the SDK models ecs/v2 NovaAvailabilityZone and
// NovaAvailabilityZoneState.
type zoneState struct {
	Available bool `json:"available"`
}

type zoneInfo struct {
	ZoneState zoneState `json:"zoneState"`
	Hosts     []string  `json:"hosts"`
	ZoneName  string    `json:"zoneName"`
}

type listZonesResponse struct {
	AvailabilityZoneInfo []zoneInfo `json:"availabilityZoneInfo"`
}

func (s *Service) handleListZones(w http.ResponseWriter, _ *http.Request, t Tenant) error {
	res := listZonesResponse{AvailabilityZoneInfo: []zoneInfo{}}
	for _, az := range Zones(t.Region) {
		res.AvailabilityZoneInfo = append(res.AvailabilityZoneInfo, zoneInfo{ZoneState: zoneState{Available: true}, ZoneName: az})
	}
	return httpx.WriteJSON(w, http.StatusOK, res)
}

// decode reads a JSON body, mapping every failure to Ecs.0005.
func decode(r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(r, dst); err != nil {
		return errInvalidRequest("request body is illegal: %s", err)
	}
	return nil
}

func (s *Service) handleCreateServers(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createServersRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Server == nil {
		return errInvalidRequest("request body is illegal: it must contain a server object")
	}
	if req.DryRun {
		return apierr.NotImplemented("ecs", "CreateServers with dry_run")
	}
	job, ids, err := s.CreateServers(r.Context(), t, *req.Server)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, createServersResponse{JobID: job.JobID, ServerIDs: ids})
}

func (s *Service) handleShowServer(w http.ResponseWriter, r *http.Request, t Tenant) error {
	srv, err := s.GetServer(r.Context(), t, chi.URLParam(r, "server_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, serverResponse{Server: s.detail(r.Context(), t, srv)})
}

// Paging of ListServersDetails: offset is a page number starting at 1,
// limit is the page size (25 when omitted, at most 1000).
const (
	defaultServerLimit = 25
	maxServerLimit     = 1000
)

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (s *Service) handleListServers(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	limit, page := defaultServerLimit, 1
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxServerLimit {
			return errInvalidRequest("limit must be an integer from 1 to %d", maxServerLimit)
		}
		limit = n
	}
	if raw := q.Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return errInvalidRequest("offset must be a non-negative integer")
		}
		if n > 1 {
			page = n
		}
	}

	all, err := s.ListServers(r.Context(), t, ListServersFilter{
		Name:                q.Get("name"),
		Status:              q.Get("status"),
		Flavor:              q.Get("flavor"),
		IP:                  q.Get("ip"),
		IPEq:                q.Get("ip_eq"),
		ServerID:            q.Get("server_id"),
		ReservationID:       q.Get("reservation_id"),
		EnterpriseProjectID: q.Get("enterprise_project_id"),
		Tags:                splitList(q.Get("tags")),
		NotTags:             splitList(q.Get("not-tags")),
	})
	if err != nil {
		return err
	}
	window := pagination.ByOffset(all, pagination.Offset{Offset: (page - 1) * limit, Limit: limit})
	res := listServersResponse{Count: len(all), Servers: make([]ServerDetail, 0, len(window))}
	for _, srv := range window {
		res.Servers = append(res.Servers, s.detail(r.Context(), t, srv))
	}
	return httpx.WriteJSON(w, http.StatusOK, res)
}

func (s *Service) handleDeleteServers(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req deleteServersRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ids := make([]string, 0, len(req.Servers))
	for _, ref := range req.Servers {
		ids = append(ids, ref.ID)
	}
	job, err := s.DeleteServers(r.Context(), t, ids)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, jobResponse{JobID: job.JobID})
}

func (s *Service) handleShowJob(w http.ResponseWriter, r *http.Request, t Tenant) error {
	job, err := s.GetJob(r.Context(), t, chi.URLParam(r, "job_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, job)
}
