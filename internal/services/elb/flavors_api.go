package elb

import (
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

type listFlavorsResponse struct {
	Flavors   []flavorWire `json:"flavors"`
	PageInfo  pageInfo     `json:"page_info"`
	RequestID string       `json:"request_id"`
}

type showFlavorResponse struct {
	Flavor    flavorWire `json:"flavor"`
	RequestID string     `json:"request_id"`
}

type listAvailabilityZonesResponse struct {
	AvailabilityZones [][]availabilityZoneWire `json:"availability_zones"`
	RequestID         string                   `json:"request_id"`
}

func (s *Service) handleListFlavors(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	if _, err := parseBoolQuery(q, "page_reverse"); err != nil {
		return err
	}
	shared, err := parseBoolQuery(q, "shared")
	if err != nil {
		return err
	}
	soldOut, err := parseBoolQuery(q, "flavor_sold_out")
	if err != nil {
		return err
	}
	if _, err := parseBoolQuery(q, "list_all"); err != nil {
		return err
	}
	categories, err := parseIntQueryValues(q, "category")
	if err != nil {
		return err
	}

	all := seededFlavors(t.Region, t.ProjectID)
	filtered := make([]flavorWire, 0, len(all))
	for _, f := range all {
		if !matchesAny(q["id"], f.ID) {
			continue
		}
		if !matchesAny(q["name"], f.Name) {
			continue
		}
		if !matchesAny(q["type"], f.Type) {
			continue
		}
		if shared != nil && f.Shared != *shared {
			continue
		}
		if !matchesAny(q["public_border_group"], f.PublicBorderGroup) {
			continue
		}
		if len(categories) > 0 && !slices.Contains(categories, f.Category) {
			continue
		}
		if soldOut != nil && f.FlavorSoldOut != *soldOut {
			continue
		}
		filtered = append(filtered, f)
	}

	paged, pi, err := paginateSlice(filtered, func(f flavorWire) string { return f.ID }, page)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, listFlavorsResponse{
		Flavors:   paged,
		PageInfo:  pi,
		RequestID: requestID(r),
	})
}

func (s *Service) handleShowFlavor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "flavor_id")
	f, ok := findSeededFlavor(t.Region, t.ProjectID, id)
	if !ok {
		return errNotFound("flavor", id)
	}
	return httpx.WriteJSON(w, http.StatusOK, showFlavorResponse{
		Flavor:    f,
		RequestID: requestID(r),
	})
}

func (s *Service) handleListAvailabilityZones(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	if lbID := q.Get("loadbalancer_id"); lbID != "" {
		if _, err := s.getLoadBalancer(r.Context(), t, lbID); err != nil {
			return err
		}
	}
	azs := seededAvailabilityZones(t.Region)
	if pbg := q.Get("public_border_group"); pbg != "" && pbg != lbPublicBorderGroupCenter {
		azs = [][]availabilityZoneWire{}
	}
	return httpx.WriteJSON(w, http.StatusOK, listAvailabilityZonesResponse{
		AvailabilityZones: azs,
		RequestID:         requestID(r),
	})
}
