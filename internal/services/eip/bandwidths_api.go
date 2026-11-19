package eip

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

func (s *Service) handleListBandwidths(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, v1ListLimits)
	if err != nil {
		return errInvalidBandwidth("Get bandwidths error limit is invalid.")
	}
	all, err := s.ListBandwidths(r.Context(), t, ListBandwidthsFilter{
		ShareType:           q.Get("share_type"),
		EnterpriseProjectID: q.Get("enterprise_project_id"),
	})
	if err != nil {
		return err
	}
	paged, err := pagination.ByMarker(all, func(b bandwidth) string { return b.ID }, page)
	if err != nil {
		return errBandwidthNotFound()
	}
	out := make([]bandwidthResp, 0, len(paged))
	for _, bw := range paged {
		resp, err := s.toBandwidthResp(r.Context(), t, bw)
		if err != nil {
			return err
		}
		out = append(out, resp)
	}
	return httpx.WriteJSON(w, http.StatusOK, listBandwidthsResponse{Bandwidths: out})
}

func (s *Service) handleShowBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	bw, err := s.GetBandwidth(r.Context(), t, chi.URLParam(r, "bandwidth_id"))
	if err != nil {
		return err
	}
	resp, err := s.toBandwidthResp(r.Context(), t, bw)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, bandwidthResponse{Bandwidth: resp})
}

func (s *Service) handleUpdateBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateBandwidthRequest
	if err := decode(r, &req, errInvalidBandwidth); err != nil {
		return err
	}
	if req.Bandwidth == nil {
		return errInvalidBandwidth("updateBandwidth input param is invalid.")
	}
	bw, err := s.UpdateBandwidth(r.Context(), t, chi.URLParam(r, "bandwidth_id"), *req.Bandwidth)
	if err != nil {
		return err
	}
	resp, err := s.toBandwidthResp(r.Context(), t, bw)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, bandwidthResponse{Bandwidth: resp})
}

func (s *Service) handleCreateSharedBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createSharedBandwidthRequest
	if err := decode(r, &req, errInvalidBandwidth); err != nil {
		return err
	}
	if req.Bandwidth == nil {
		return errInvalidBandwidth("Bandwidth name or share_type is invalid.")
	}
	bw, err := s.CreateSharedBandwidth(r.Context(), t, *req.Bandwidth)
	if err != nil {
		return err
	}
	resp, err := s.toBandwidthResp(r.Context(), t, bw)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, bandwidthResponse{Bandwidth: resp})
}

func (s *Service) handleUpdatePrePaidBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.handleUpdateBandwidth(w, r, t)
}

func (s *Service) handleDeleteSharedBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if err := s.DeleteSharedBandwidth(r.Context(), t, chi.URLParam(r, "bandwidth_id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleAddPublicIPsIntoSharedBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req addPublicIPsIntoSharedBandwidthRequest
	if err := decode(r, &req, errInvalidBandwidth); err != nil {
		return err
	}
	if req.Bandwidth == nil {
		return errInvalidBandwidth("Invalid publicip_id")
	}
	bw, err := s.AddPublicIPsIntoSharedBandwidth(r.Context(), t, chi.URLParam(r, "bandwidth_id"), *req.Bandwidth)
	if err != nil {
		return err
	}
	resp, err := s.toBandwidthResp(r.Context(), t, bw)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, bandwidthResponse{Bandwidth: resp})
}

func (s *Service) handleRemovePublicIPsFromSharedBandwidth(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req removeFromSharedBandwidthRequest
	if err := decode(r, &req, errInvalidBandwidth); err != nil {
		return err
	}
	if req.Bandwidth == nil {
		return errInvalidBandwidth("Invalid publicip_id")
	}
	if err := s.RemovePublicIPsFromSharedBandwidth(r.Context(), t, chi.URLParam(r, "bandwidth_id"), *req.Bandwidth); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
