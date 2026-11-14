// Package eps emulates the part of Huawei Cloud's Enterprise Project
// Management Service that clients need to find the default enterprise
// project, the only one WeiStack has. IAM grants roles in it.
//
// EPS is global: it is served at eps.myhuaweicloud.com, the endpoint the
// SDKs use.
package eps

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// DefaultID is the ID of the default enterprise project.
const DefaultID = "0"

// Service is the EPS emulator.
type Service struct {
	log     *slog.Logger
	created time.Time
}

// New returns the EPS service. created is when the default enterprise
// project is shown as created: the emulator's start.
func New(log *slog.Logger, created time.Time) (*Service, error) {
	if log == nil {
		return nil, errors.New("eps: a logger is required")
	}
	return &Service{log: log, created: created.UTC().Truncate(time.Second)}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "eps" }

// Version implements server.Service.
func (s *Service) Version() string { return "v1.0 (the default enterprise project)" }

// Routes implements server.Service.
func (s *Service) Routes(r chi.Router) {
	r.Get("/v1.0/enterprise-projects", s.handleList)
}

// epView mirrors the SDK model eps/v1 EpDetail.
type epView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      int    `json:"status"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Type        string `json:"type"`
	DeleteFlag  bool   `json:"delete_flag"`
}

// epTime is the format of EPS times, as in "2018-05-18T06:49:06Z".
const epTime = "2006-01-02T15:04:05Z"

func (s *Service) defaultProject() epView {
	at := s.created.Format(epTime)
	return epView{
		ID: DefaultID, Name: "default", Description: "Default enterprise project.", Status: 1,
		CreatedAt: at, UpdatedAt: at, Type: "prod",
	}
}

// handleList answers GET /v1.0/enterprise-projects with the default
// enterprise project, if it passes the filters: id, name (a substring),
// status and type, then offset and limit. EPS's error codes are not
// emulated, so values out of range are not refused: a bad limit or
// offset counts as unset.
func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	reqctx.From(r.Context()).SetOperation("ListEnterpriseProject")
	q := r.URL.Query()
	ep := s.defaultProject()
	all := []epView{ep}
	all = slices.DeleteFunc(all, func(e epView) bool {
		return q.Get("id") != "" && q.Get("id") != e.ID ||
			q.Get("name") != "" && !strings.Contains(e.Name, q.Get("name")) ||
			q.Get("status") != "" && q.Get("status") != strconv.Itoa(e.Status) ||
			q.Get("type") != "" && q.Get("type") != e.Type
	})
	total := len(all)
	if off, err := strconv.Atoi(q.Get("offset")); err == nil && off > 0 {
		all = all[min(off, len(all)):]
	}
	if limit, err := strconv.Atoi(q.Get("limit")); err == nil && limit >= 1 && limit < len(all) {
		all = all[:limit]
	}
	out := struct {
		EnterpriseProjects []epView `json:"enterprise_projects"`
		TotalCount         int      `json:"total_count"`
	}{all, total}
	if err := httpx.WriteJSON(w, http.StatusOK, out); err != nil {
		apierr.Write(w, r, apierr.StyleFlat, err)
	}
}
