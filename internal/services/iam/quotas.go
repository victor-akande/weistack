package iam

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Quota responses mirror SDK iam/v3 models ShowDomainQuotaResponse,
// ShowProjectQuotaResponse, QuotaResult, and Resources.
type quotaResponse struct {
	Quotas quotaResult `json:"quotas"`
}

type quotaResult struct {
	Resources []quotaResource `json:"resources"`
}

type quotaResource struct {
	Type  string `json:"type"`
	Used  int    `json:"used"`
	Quota int    `json:"quota"`
	Min   int    `json:"min"`
	Max   int    `json:"max"`
}

// validDomainQuotaTypes are the documented options of ShowDomainQuota's type
// query parameter (IAMShowDomainQuota).
var validDomainQuotaTypes = map[string]bool{
	"user":                true,
	"group":               true,
	"idp":                 true,
	"agency":              true,
	"policy":              true,
	"assigment_group_mp":  true,
	"assigment_agency_mp": true,
	"assigment_group_ep":  true,
	"assigment_user_ep":   true,
	"mapping":             true,
}

func (s *Service) handleShowDomainQuota(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	domainID := chi.URLParam(r, "domain_id")
	acct := s.account(ctx)
	if domainID != acct.ID {
		if _, ok := s.dir.AccountByID(domainID); ok {
			return errForbidden()
		}
		return errNotFound("domain", domainID)
	}

	typ := r.URL.Query().Get("type")
	if typ != "" && !validDomainQuotaTypes[typ] {
		return errInvalidParam("type")
	}

	resources := make([]quotaResource, 0, 3)
	if typ == "" || typ == "user" {
		n, err := s.countUsers(ctx)
		if err != nil {
			return err
		}
		resources = append(resources, quotaResource{
			Type:  "user",
			Used:  n,
			Quota: s.quotas.Get(quota.IAMUser),
			Min:   50,
			Max:   1000,
		})
	}
	if typ == "" || typ == "group" {
		gs, err := s.groups(ctx).List(ctx, nil)
		if err != nil {
			return err
		}
		resources = append(resources, quotaResource{
			Type:  "group",
			Used:  len(gs),
			Quota: s.quotas.Get(quota.IAMGroup),
			Min:   10,
			Max:   300,
		})
	}
	if typ == "" || typ == "agency" {
		as, err := s.agencies(ctx).List(ctx, nil)
		if err != nil {
			return err
		}
		resources = append(resources, quotaResource{
			Type:  "agency",
			Used:  len(as),
			Quota: s.quotas.Get(quota.IAMAgency),
			Min:   10,
			Max:   300,
		})
	}

	return httpx.WriteJSON(w, http.StatusOK, quotaResponse{
		Quotas: quotaResult{Resources: resources},
	})
}

func (s *Service) handleShowProjectQuota(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	projectID := chi.URLParam(r, "project_id")
	if _, err := s.projects(ctx).Get(ctx, projectID); errors.Is(err, store.ErrNotFound) {
		acct := s.account(ctx)
		for _, other := range s.dir.Accounts() {
			if other.ID == acct.ID {
				continue
			}
			if _, err := s.projects(withAccount(ctx, other)).Get(ctx, projectID); err == nil {
				return errForbidden()
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return errNotFound("project", projectID)
	} else if err != nil {
		return err
	}

	all, err := s.projects(ctx).List(ctx, nil)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, quotaResponse{
		Quotas: quotaResult{
			Resources: []quotaResource{{
				Type:  "project",
				Used:  len(all),
				Quota: 10,
				Min:   0,
				Max:   50,
			}},
		},
	})
}
