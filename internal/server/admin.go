package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/version"
)

// newAdmin builds the /_weistack router.
func (s *Server) newAdmin() http.Handler {
	r := chi.NewRouter()
	missing := func(w http.ResponseWriter, req *http.Request) {
		apierr.Write(w, req, apierr.StyleFlat, errNoSuchAPI)
	}
	r.NotFound(missing)
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		apierr.Write(w, req, apierr.StyleFlat, apierr.New(http.StatusMethodNotAllowed,
			"WeiStack.0405", "method %s is not allowed on %s", req.Method, req.URL.Path))
	})
	r.Route(adminPrefix, func(r chi.Router) {
		r.Get("/health", s.adminOp("Health", s.handleHealth))
		r.Get("/services", s.adminOp("ListServices", s.handleServices))
		r.Get("/state", s.adminOp("DumpState", s.handleState))
		r.Post("/reset", s.adminOp("Reset", s.handleReset))
		if s.ca != nil {
			r.Get("/ca", s.adminOp("GetCACertificate", s.handleCA))
		}
		if s.cfg.Metrics {
			r.Get("/metrics", s.adminOp("Metrics", s.handleMetrics))
		}
	})
	return r
}

// adminOp names the operation for logs and renders handler errors.
func (s *Server) adminOp(op string, fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqctx.From(r.Context()).SetOperation(op)
		if err := fn(w, r); err != nil {
			s.log.ErrorContext(r.Context(), "admin operation failed", "operation", op, "error", err)
			apierr.Write(w, r, apierr.StyleFlat, err)
		}
	}
}

type healthResponse struct {
	Status        string  `json:"status"`
	Version       string  `json:"version"`
	UptimeSeconds float64 `json:"uptime_seconds"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) error {
	return httpx.WriteJSON(w, http.StatusOK, healthResponse{
		Status:        "ok",
		Version:       version.Version,
		UptimeSeconds: time.Since(s.started).Round(time.Millisecond).Seconds(),
	})
}

type servicesResponse struct {
	Version   string `json:"version"`
	Region    string `json:"region"`
	ProjectID string `json:"project_id"`
	// AccountID and AccountName are the emulator's account, the "domain"
	// of Huawei Cloud's IAM (a provider's domain_id).
	AccountID   string        `json:"account_id,omitempty"`
	AccountName string        `json:"account_name,omitempty"`
	Persist     bool          `json:"persist"`
	Services    []serviceInfo `json:"services"`
}

type serviceInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (s *Server) handleServices(w http.ResponseWriter, _ *http.Request) error {
	out := servicesResponse{
		Version:   version.Version,
		Region:    s.cfg.Region,
		ProjectID: s.projectID,
		Persist:   s.cfg.Persist,
		Services:  make([]serviceInfo, 0, len(s.names)),
	}
	if s.dir != nil {
		out.AccountID, out.AccountName = s.dir.Account().ID, s.dir.Account().Name
	}
	for _, name := range s.names {
		out.Services = append(out.Services, serviceInfo{Name: name, Version: s.services[name].svc.Version()})
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

type stateResponse struct {
	// Resources is keyed by "region/project/kind".
	Resources map[string][]stateRecord `json:"resources"`
}

type stateRecord struct {
	ID      string          `json:"id"`
	Version uint64          `json:"version"`
	Data    json.RawMessage `json:"data"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) error {
	dump, err := s.store.Dump(r.Context())
	if err != nil {
		return apierr.Internal(err)
	}
	out := stateResponse{Resources: make(map[string][]stateRecord, len(dump))}
	for scope, recs := range dump {
		list := make([]stateRecord, 0, len(recs))
		for _, rec := range recs {
			data := json.RawMessage(rec.Data)
			if !json.Valid(data) {
				// Not JSON (should not happen for service records):
				// emit it as a JSON string rather than a broken document.
				data, _ = json.Marshal(string(rec.Data))
			}
			list = append(list, stateRecord{ID: rec.ID, Version: rec.Version, Data: data})
		}
		out.Resources[scope] = list
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

type resetResponse struct {
	Status         string `json:"status"`
	CancelledTasks int    `json:"cancelled_tasks"`
}

// handleReset returns the emulator to its just-started state: pending
// transitions are dropped, the store is wiped and services re-seed.
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) error {
	cancelled := s.engine.CancelAll()
	if err := s.store.Reset(r.Context()); err != nil {
		return apierr.Internal(err)
	}
	for _, name := range s.names {
		if rs, ok := s.services[name].svc.(Resetter); ok {
			if err := rs.Reset(r.Context()); err != nil {
				return apierr.Internal(err)
			}
		}
	}
	s.log.InfoContext(r.Context(), "state reset", "cancelled_tasks", cancelled)
	return httpx.WriteJSON(w, http.StatusOK, resetResponse{Status: "reset", CancelledTasks: cancelled})
}

// handleCA serves the proxy's CA certificate, so clients of a container
// can fetch it without access to its file system.
func (s *Server) handleCA(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.ca.CertPEM())
	return nil
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) error {
	dump, err := s.store.Dump(r.Context())
	if err != nil {
		return apierr.Internal(err)
	}
	resources := make(map[string]int)
	for scope, recs := range dump {
		resources[kindOf(scope)] += len(recs)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	s.metrics.write(w, resources, s.engine.Pending())
	return nil
}

// kindOf extracts the resource kind from a "region/project/kind" scope.
func kindOf(scope string) string {
	for i := len(scope) - 1; i >= 0; i-- {
		if scope[i] == '/' {
			return scope[i+1:]
		}
	}
	return scope
}
