package evs

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Routes implements server.Service. Paths are those of the real API.
func (s *Service) Routes(r chi.Router) {
	act, vol := authz.Action, authz.Param("volume", "volume_id")
	r.Use(authz.Service(authz.ServiceOptions{Name: "evs", Style: apierr.StyleNested}))

	// Volumes (§3.1)
	r.With(act("evs:volumes:create")).Post("/v2.1/{project_id}/cloudvolumes", s.handle("CreateVolume", s.handleCreateVolume))
	r.With(act("evs:volumes:list")).Get("/v2/{project_id}/cloudvolumes/detail", s.handle("ListVolumes", s.handleListVolumes))
	r.With(act("evs:volumes:get", vol)).Get("/v2/{project_id}/cloudvolumes/{volume_id}", s.handle("ShowVolume", s.handleShowVolume))
	r.With(act("evs:volumes:update", vol)).Put("/v2/{project_id}/cloudvolumes/{volume_id}", s.handle("UpdateVolume", s.handleUpdateVolume))
	r.With(act("evs:volumes:delete", vol)).Delete("/v2/{project_id}/cloudvolumes/{volume_id}", s.handle("DeleteVolume", s.handleDeleteVolume))
	r.With(act("evs:volumes:resize", vol)).Post("/v2.1/{project_id}/cloudvolumes/{volume_id}/action", s.handle("ResizeVolume", s.handleResizeVolume))

	// Snapshots (§3.2)
	r.With(act("evs:snapshots:create")).Post("/v2/{project_id}/cloudsnapshots", s.handle("CreateSnapshot", s.handleCreateSnapshot))
	r.With(act("evs:snapshots:list")).Get("/v2/{project_id}/cloudsnapshots/detail", s.handle("ListSnapshots", s.handleListSnapshots))
	r.With(act("evs:snapshots:get")).Get("/v2/{project_id}/cloudsnapshots/{snapshot_id}", s.handle("ShowSnapshot", s.handleShowSnapshot))
	r.With(act("evs:snapshots:update")).Put("/v2/{project_id}/cloudsnapshots/{snapshot_id}", s.handle("UpdateSnapshot", s.handleUpdateSnapshot))
	r.With(act("evs:snapshots:delete")).Delete("/v2/{project_id}/cloudsnapshots/{snapshot_id}", s.handle("DeleteSnapshot", s.handleDeleteSnapshot))
	r.With(act("evs:snapshots:rollback")).Post("/v2/{project_id}/cloudsnapshots/{snapshot_id}/rollback", s.handle("RollbackSnapshot", s.handleRollbackSnapshot))

	// Tags (§3.3)
	r.With(authz.Defer()).Post("/v2/{project_id}/cloudvolumes/{volume_id}/tags/action", s.handle("BatchVolumeTags", s.handleBatchVolumeTags))
	r.With(act("evs:volumes:listTagsForResource", vol)).Get("/v2/{project_id}/cloudvolumes/{volume_id}/tags", s.handle("ShowVolumeTags", s.handleShowVolumeTags))
	r.With(act("evs:volumes:listTags")).Get("/v2/{project_id}/cloudvolumes/tags", s.handle("ListVolumeTags", s.handleListVolumeTags))

	// Types, zones and jobs (§3.4)
	r.With(act("evs:types:get")).Get("/v2/{project_id}/types", s.handle("CinderListVolumeTypes", s.handleListVolumeTypes))
	r.With(authz.Public()).Get("/v2/{project_id}/os-availability-zone", s.handle("CinderListAvailabilityZones", s.handleListAvailabilityZones))
	r.With(authz.Public()).Get("/v1/{project_id}/jobs/{job_id}", s.handle("ShowJob", s.handleShowJob))

	// Quotas
	r.With(act("evs:quotas:get")).Get("/v2/{project_id}/os-quota-sets/{target_project_id}", s.handle("CinderListQuotas", s.handleListQuotas))
}

type handler func(w http.ResponseWriter, r *http.Request, t Tenant) error

// handle names the operation for logs, resolves the tenant and renders
// errors in the EVS envelope, {"error": {"code": ..., "message": ...}}.
func (s *Service) handle(op string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := reqctx.From(r.Context())
		info.SetOperation(op)
		err := fn(w, r, Tenant{Region: info.Region, ProjectID: chi.URLParam(r, "project_id")})
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

type showVolumeResponse struct {
	Volume volumeDetail `json:"volume"`
}

func (s *Service) handleShowVolume(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "volume_id")
	v, err := s.volumes(t).Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return errVolumeNotFound
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, showVolumeResponse{Volume: detail(v, t, r)})
}

type listVolumesResponse struct {
	Count   int            `json:"count"`
	Volumes []volumeDetail `json:"volumes"`
}

const maxLimit = 1000

func (s *Service) handleListVolumes(w http.ResponseWriter, r *http.Request, t Tenant) error {
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

	all, err := s.volumes(t).List(r.Context(), nil)
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
	matched := make([]volume, 0, len(all))
	for _, v := range all {
		if !eq(q.Get("id"), v.ID) ||
			!eq(q.Get("availability_zone"), v.AvailabilityZone) ||
			!eq(q.Get("status"), v.Status) ||
			(ids != nil && !ids[v.ID]) {
			continue
		}
		if srvID := q.Get("server_id"); srvID != "" && !hasServerAttachment(v, srvID) {
			continue
		}
		if name := q.Get("name"); name != "" && !strings.Contains(v.Name, name) {
			continue
		}
		if ma := q.Get("multiattach"); ma != "" {
			if want, err := strconv.ParseBool(ma); err == nil && v.Multiattach != want {
				continue
			}
		}
		if vtID := q.Get("volume_type_id"); vtID != "" {
			if vt, ok := volumeTypeByID[vtID]; !ok || v.VolumeType != vt {
				continue
			}
		}
		if ep := q.Get("enterprise_project_id"); ep != "" && ep != "all_granted_eps" {
			volEP := v.EnterpriseProjectID
			if volEP == "" {
				volEP = "0"
			}
			if volEP != ep {
				continue
			}
		}
		matched = append(matched, v)
	}

	out := listVolumesResponse{Count: len(matched), Volumes: []volumeDetail{}}
	for _, v := range pagination.ByOffset(matched, page) {
		out.Volumes = append(out.Volumes, detail(v, t, r))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}
