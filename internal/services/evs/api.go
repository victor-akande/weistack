package evs

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Routes implements server.Service. Paths are those of the real API.
func (s *Service) Routes(r chi.Router) {
	r.Get("/v2/{project_id}/cloudvolumes/detail", s.handle("ListVolumes", s.handleListVolumes))
	r.Get("/v2/{project_id}/cloudvolumes/{volume_id}", s.handle("ShowVolume", s.handleShowVolume))
}

type tenant struct {
	region, projectID string
}

type handler func(w http.ResponseWriter, r *http.Request, t tenant) error

// handle names the operation for logs, resolves the tenant and renders
// errors in the EVS envelope, {"error": {"code": ..., "message": ...}}.
func (s *Service) handle(op string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := reqctx.From(r.Context())
		info.SetOperation(op)
		err := fn(w, r, tenant{region: info.Region, projectID: chi.URLParam(r, "project_id")})
		if err == nil {
			return
		}
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(r.Context(), "evs operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, apierr.StyleNested, err)
	}
}

// Error catalogue, from the "Error Codes" appendix of the EVS API
// reference.
var (
	errVolumeNotFound = apierr.New(http.StatusNotFound, "EVS.5404", "Resource(Volume, Snapshot, Backup .etc) cound not be found.")
	errInvalidLimit   = apierr.New(http.StatusBadRequest, "EVS.1023", "invalid filter limit!")
	errLimitTooLarge  = apierr.New(http.StatusBadRequest, "EVS.2142", "invalid filter limit, can not greater than 1000.")
	errInvalidRequest = apierr.New(http.StatusBadRequest, "EVS.1070", "invalid request.")
)

type showVolumeResponse struct {
	Volume volumeDetail `json:"volume"`
}

func (s *Service) handleShowVolume(w http.ResponseWriter, r *http.Request, t tenant) error {
	id := chi.URLParam(r, "volume_id")
	all, err := s.list(r.Context(), t.region, t.projectID)
	if err != nil {
		return err
	}
	for _, v := range all {
		if v.ID == id {
			return httpx.WriteJSON(w, http.StatusOK, showVolumeResponse{Volume: detail(v, t, r)})
		}
	}
	return errVolumeNotFound
}

type listVolumesResponse struct {
	Count   int            `json:"count"`
	Volumes []volumeDetail `json:"volumes"`
}

const maxLimit = 1000

func (s *Service) handleListVolumes(w http.ResponseWriter, r *http.Request, t tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseOffset(q, pagination.Limits{Default: maxLimit, Min: 1, Max: 1 << 30})
	switch {
	case errors.Is(err, pagination.ErrInvalidOffset):
		return errInvalidRequest
	case err != nil:
		return errInvalidLimit
	case page.Limit > maxLimit:
		return errLimitTooLarge
	}

	all, err := s.list(r.Context(), t.region, t.projectID)
	if err != nil {
		return err
	}
	var ids map[string]bool
	if raw := strings.Trim(q.Get("ids"), "[]"); raw != "" {
		ids = map[string]bool{}
		for _, id := range strings.Split(raw, ",") {
			ids[strings.Trim(strings.TrimSpace(id), `"'`)] = true
		}
	}
	eq := func(want, got string) bool { return want == "" || want == got }
	matched := make([]Volume, 0, len(all))
	for _, v := range all {
		if !eq(q.Get("id"), v.ID) || !eq(q.Get("server_id"), v.ServerID) ||
			!eq(q.Get("availability_zone"), v.AvailabilityZone) || !eq(q.Get("status"), statusInUse) ||
			(ids != nil && !ids[v.ID]) {
			continue
		}
		if name := q.Get("name"); name != "" && !strings.Contains(v.Name, name) {
			continue
		}
		matched = append(matched, v)
	}

	out := listVolumesResponse{Count: len(matched), Volumes: []volumeDetail{}}
	for _, v := range pagination.ByOffset(matched, page) {
		out.Volumes = append(out.Volumes, detail(v, t, r))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}
