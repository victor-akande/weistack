package ims

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Routes implements server.Service. Paths are those of the real API.
func (s *Service) Routes(r chi.Router) {
	r.Get("/v2/cloudimages", s.handle("ListImages", s.handleListImages))
	r.Get("/v2/images/{image_id}", s.handle("GlanceShowImage", s.handleShowImage))
}

// listLimits bounds "limit" on ListImages: 1 to 1000, 1000 when omitted.
var listLimits = pagination.Limits{Default: 1000, Min: 1, Max: 1000}

type handler func(w http.ResponseWriter, r *http.Request, t Tenant) error

// handle adapts a handler: it names the operation for logs, resolves the
// tenant and renders errors in the IMS envelope.
func (s *Service) handle(op string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := reqctx.From(r.Context())
		info.SetOperation(op)

		err := fn(w, r, s.tenant(r))
		if err == nil {
			return
		}
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(r.Context(), "ims operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, apierr.StyleNested, err)
	}
}

// tenant resolves the caller's project. IMS paths carry no project ID:
// SDKs send it in the X-Project-Id header, and without one the
// emulator's default project applies.
func (s *Service) tenant(r *http.Request) Tenant {
	t := Tenant{Region: reqctx.From(r.Context()).Region, ProjectID: s.defaultProject}
	if id := auth.FromContext(r.Context()).ProjectID; projectIDRE.MatchString(id) {
		t.ProjectID = id
	}
	return t
}

func (s *Service) handleListImages(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	f := ListImagesFilter{
		ImageType:       q.Get("__imagetype"),
		Visibility:      q.Get("visibility"),
		ID:              q.Get("id"),
		Name:            q.Get("name"),
		Status:          q.Get("status"),
		Platform:        q.Get("__platform"),
		OSType:          q.Get("__os_type"),
		OSBit:           q.Get("__os_bit"),
		Owner:           q.Get("owner"),
		Tag:             q.Get("tag"),
		DiskFormat:      q.Get("disk_format"),
		ContainerFormat: q.Get("container_format"),
		VirtualEnvType:  q.Get("virtual_env_type"),
		SortKey:         q.Get("sort_key"),
		SortDir:         q.Get("sort_dir"),
	}
	if raw := q.Get("protected"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return errInvalidRequest("protected %q is not a boolean", raw)
		}
		f.Protected = &b
	}
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidRequest("%s", err)
	}

	all, err := s.ListImages(r.Context(), t, f)
	if err != nil {
		return err
	}
	out, err := pagination.ByMarker(all, func(img Image) string { return img.ID }, page)
	if err != nil {
		return errInvalidRequest("%s", err)
	}

	res := listImagesResponse{Images: out}
	// next_marker is only present when another page follows.
	if n := len(out); n > 0 && out[n-1].ID != all[len(all)-1].ID {
		res.PageInfo = &pageInfo{NextMarker: out[n-1].ID}
	}
	return httpx.WriteJSON(w, http.StatusOK, res)
}

func (s *Service) handleShowImage(w http.ResponseWriter, r *http.Request, t Tenant) error {
	img, err := s.GetImage(r.Context(), t, chi.URLParam(r, "image_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, img)
}
