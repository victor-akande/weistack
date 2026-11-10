package ecs

import (
	"errors"
	"math"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Routes implements server.Service. Paths are those of the real API.
func (s *Service) Routes(r chi.Router) {
	r.Get("/v1/{project_id}/cloudservers/flavors", s.handle("ListFlavors", s.handleListFlavors))
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
