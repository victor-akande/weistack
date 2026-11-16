package eip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

type updatePublicIPRequest struct {
	PublicIP *updatePublicIPOptionWire `json:"publicip"`
}

type updatePublicIPOptionWire struct {
	updatePublicIPOption
	portIDPresent bool
}

func (u *updatePublicIPOptionWire) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	_, u.portIDPresent = raw["port_id"]
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(&u.updatePublicIPOption)
}

func (s *Service) handleCreatePublicIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createPublicIPRequest
	if err := decode(r, &req, errInvalidPublicIP); err != nil {
		return err
	}
	pip, err := s.createPublicIP(r.Context(), t, req)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, createPublicIPResponse{
		PublicIP: toPublicIPCreateResp(t, pip),
	})
}

func (s *Service) handleShowPublicIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "publicip_id")
	pip, err := s.getPublicIP(r.Context(), t, id)
	if err != nil {
		return err
	}
	out, err := s.toPublicIPShowResp(r.Context(), t, pip)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, showPublicIPResponse{PublicIP: out})
}

func (s *Service) handleListPublicIPs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, v1ListLimits)
	if err != nil {
		return errInvalidPublicIP("Invalid limit.")
	}
	items, err := s.listPublicIPs(r.Context(), t, listPublicIPsFilter{
		IDs:                 q["id"],
		PortIDs:             q["port_id"],
		PublicIPAddresses:   q["public_ip_address"],
		PrivateIPAddresses:  q["private_ip_address"],
		IPVersion:           q.Get("ip_version"),
		EnterpriseProjectID: q.Get("enterprise_project_id"),
		Page:                page,
	})
	if err != nil {
		return err
	}
	out := make([]publicIPShowResp, 0, len(items))
	for _, p := range items {
		resp, err := s.toPublicIPShowResp(r.Context(), t, p)
		if err != nil {
			return err
		}
		out = append(out, resp)
	}
	return httpx.WriteJSON(w, http.StatusOK, listPublicIPsResponse{PublicIPs: out})
}

func (s *Service) handleUpdatePublicIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updatePublicIPRequest
	if err := decode(r, &req, errInvalidPublicIP); err != nil {
		return err
	}
	if req.PublicIP == nil {
		return errInvalidPublicIP("publicip is required")
	}
	id := chi.URLParam(r, "publicip_id")
	pip, err := s.updatePublicIP(r.Context(), t, id, updatePublicIPSpec{
		PortIDPresent: req.PublicIP.portIDPresent,
		PortID:        req.PublicIP.PortID,
		IPVersion:     req.PublicIP.IPVersion,
		Alias:         req.PublicIP.Alias,
	})
	if err != nil {
		return err
	}
	out, err := s.toPublicIPUpdateResp(r.Context(), t, pip)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, updatePublicIPResponse{PublicIP: out})
}

func (s *Service) handleDeletePublicIP(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "publicip_id")
	if err := s.deletePublicIP(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func toPublicIPCreateResp(t Tenant, p publicIP) publicIPCreateResp {
	return publicIPCreateResp{
		ID:                  p.ID,
		Status:              p.Status,
		Type:                p.Type,
		PublicIPAddress:     p.Address,
		TenantID:            t.ProjectID,
		IPVersion:           4,
		CreateTime:          p.CreatedAt.UTC().Format(v1TimeFormat),
		BandwidthSize:       0,
		EnterpriseProjectID: p.EnterpriseProjectID,
		PublicBorderGroup:   PublicBorderGroupCenter,
		Alias:               p.Alias,
	}
}

func (s *Service) toPublicIPShowResp(ctx context.Context, t Tenant, p publicIP) (publicIPShowResp, error) {
	var (
		bwName      string
		bwShareType string
		bwSize      int
	)
	if p.BandwidthID != "" {
		bw, err := s.bandwidths(t).Get(ctx, p.BandwidthID)
		if err == nil {
			bwName = bw.Name
			bwShareType = bw.ShareType
			bwSize = bw.Size
		} else if !errors.Is(err, store.ErrNotFound) {
			return publicIPShowResp{}, err
		}
	}
	tags := make([]string, 0, len(p.Tags))
	for _, tg := range p.Tags {
		tags = append(tags, tg.Key+"="+tg.Value)
	}
	return publicIPShowResp{
		BandwidthID:         p.BandwidthID,
		BandwidthName:       bwName,
		BandwidthShareType:  bwShareType,
		BandwidthSize:       bwSize,
		CreateTime:          p.CreatedAt.UTC().Format(v1TimeFormat),
		EnterpriseProjectID: p.EnterpriseProjectID,
		ID:                  p.ID,
		PortID:              p.PortID,
		PrivateIPAddress:    p.PrivateIP,
		PublicIPAddress:     p.Address,
		Tags:                tags,
		Status:              p.Status,
		TenantID:            t.ProjectID,
		Type:                p.Type,
		IPVersion:           4,
		PublicBorderGroup:   PublicBorderGroupCenter,
		Alias:               p.Alias,
	}, nil
}

func (s *Service) toPublicIPUpdateResp(ctx context.Context, t Tenant, p publicIP) (publicIPUpdateResp, error) {
	show, err := s.toPublicIPShowResp(ctx, t, p)
	if err != nil {
		return publicIPUpdateResp{}, err
	}
	return publicIPUpdateResp{
		BandwidthID:         show.BandwidthID,
		BandwidthName:       show.BandwidthName,
		BandwidthShareType:  show.BandwidthShareType,
		BandwidthSize:       show.BandwidthSize,
		CreateTime:          show.CreateTime,
		EnterpriseProjectID: show.EnterpriseProjectID,
		ID:                  show.ID,
		PortID:              show.PortID,
		PrivateIPAddress:    show.PrivateIPAddress,
		PublicIPAddress:     show.PublicIPAddress,
		Status:              show.Status,
		TenantID:            show.TenantID,
		Type:                show.Type,
		IPVersion:           show.IPVersion,
		Alias:               show.Alias,
	}, nil
}
