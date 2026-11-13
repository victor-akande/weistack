package iam

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Discovery: the calls Huawei's SDKs and the Terraform provider make to
// find the account (GET /v3/auth/domains) and a region's project
// (GET /v3/projects?name=<region>) when they are not configured.

// project is the account's project in one region. Its ID is stable: the
// default region keeps the configured project ID, others derive theirs
// from the account (identity.Account.ProjectID).
type project struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	DomainID string `json:"domain_id"`
}

// ensureProject records region's project, if it is not yet known. Any
// region name can have a project, as in an account that has every region
// enabled.
func (s *Service) ensureProject(ctx context.Context, region string) error {
	acct := s.account()
	p := project{ID: acct.ProjectID(region, s.defaultRegion, s.defaultProj), Name: region, DomainID: acct.ID}
	if err := s.projects().Create(ctx, p.ID, p); err != nil && !errors.Is(err, store.ErrExists) {
		return err
	}
	return nil
}

type linksSelf struct {
	Self string `json:"self"`
}

type links struct {
	Self     string  `json:"self"`
	Previous *string `json:"previous"`
	Next     *string `json:"next"`
}

// projectView mirrors the SDK model iam/v3 ProjectResult.
type projectView struct {
	IsDomain    bool      `json:"is_domain"`
	Description string    `json:"description"`
	Links       linksSelf `json:"links"`
	Enabled     bool      `json:"enabled"`
	ID          string    `json:"id"`
	ParentID    string    `json:"parent_id"`
	DomainID    string    `json:"domain_id"`
	Name        string    `json:"name"`
}

func selfURL(r *http.Request, path string) string { return "https://" + r.Host + path }

func (p project) view(r *http.Request) projectView {
	return projectView{
		Links: linksSelf{Self: selfURL(r, "/v3/projects/"+p.ID)}, Enabled: true,
		ID: p.ID, ParentID: p.DomainID, DomainID: p.DomainID, Name: p.Name,
	}
}

// domainView mirrors the SDK model iam/v3 Domains.
type domainView struct {
	Enabled     bool      `json:"enabled"`
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Links       linksSelf `json:"links"`
	Description string    `json:"description"`
}

type listAuthDomainsResponse struct {
	Domains []domainView `json:"domains"`
	Links   linksSelf    `json:"links"`
}

// handleListAuthDomains lists the domains the caller may use: the
// emulator's one account. Credentials are not checked, so every caller
// gets it.
func (s *Service) handleListAuthDomains(w http.ResponseWriter, r *http.Request) error {
	acct := s.account()
	return httpx.WriteJSON(w, http.StatusOK, listAuthDomainsResponse{
		Domains: []domainView{{Enabled: true, ID: acct.ID, Name: acct.Name, Links: linksSelf{Self: selfURL(r, "/v3/domains/"+acct.ID)}}},
		Links:   linksSelf{Self: selfURL(r, "/v3/auth/domains")},
	})
}

type listProjectsResponse struct {
	Projects []projectView `json:"projects"`
	Links    links         `json:"links"`
}

type listAuthProjectsResponse struct {
	Projects []projectView `json:"projects"`
	Links    linksSelf     `json:"links"`
}

func (s *Service) handleListAuthProjects(w http.ResponseWriter, r *http.Request) error {
	all, err := s.projects().List(r.Context(), nil)
	if err != nil {
		return err
	}
	out := listAuthProjectsResponse{Projects: make([]projectView, 0, len(all)), Links: linksSelf{Self: selfURL(r, "/v3/auth/projects")}}
	for _, p := range all {
		out.Projects = append(out.Projects, p.view(r))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

// handleListProjects is GET /v3/projects. A region-shaped name finds (and
// records) that region's project, which is how the SDK and Terraform look
// up a project ID.
func (s *Service) handleListProjects(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	page, perPage, err := paging(q.Get("page"), q.Get("per_page"))
	if err != nil {
		return err
	}
	for _, flag := range []string{"enabled", "is_domain"} {
		if v := q.Get(flag); v != "" && v != "true" && v != "false" {
			return errInvalidParam(flag)
		}
	}
	name := q.Get("name")
	if regionRE.MatchString(name) {
		if err := s.ensureProject(r.Context(), name); err != nil {
			return err
		}
	}
	all, err := s.projects().List(r.Context(), func(p project) bool {
		eq := func(want, got string) bool { return want == "" || want == got }
		return eq(name, p.Name) && eq(q.Get("domain_id"), p.DomainID) && eq(q.Get("parent_id"), p.DomainID) &&
			q.Get("enabled") != "false" && q.Get("is_domain") != "true"
	})
	if err != nil {
		return err
	}
	if perPage > 0 {
		start := min((page-1)*perPage, len(all))
		all = all[start:min(start+perPage, len(all))]
	}
	out := listProjectsResponse{Projects: make([]projectView, 0, len(all)), Links: links{Self: selfURL(r, "/v3/projects")}}
	for _, p := range all {
		out.Projects = append(out.Projects, p.view(r))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

// paging reads Keystone's page and per_page: both or neither, positive.
func paging(page, perPage string) (int, int, error) {
	if page == "" && perPage == "" {
		return 0, 0, nil
	}
	p, err := strconv.Atoi(page)
	if err != nil || p < 1 {
		return 0, 0, errInvalidParam("page")
	}
	n, err := strconv.Atoi(perPage)
	if err != nil || n < 1 {
		return 0, 0, errInvalidParam("per_page")
	}
	return p, n, nil
}

type projectResponse struct {
	Project projectView `json:"project"`
}

func (s *Service) handleShowProject(w http.ResponseWriter, r *http.Request) error {
	id := chi.URLParam(r, "project_id")
	p, err := s.projects().Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("project", id)
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, projectResponse{Project: p.view(r)})
}
