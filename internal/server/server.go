// Package server is WeiStack's HTTP front door. One listener serves
// every emulated service; requests are routed to a service by Host header
// ({service}.{region}.myhuaweicloud.com), falling back to a path prefix
// (/{service}/...). Emulator admin endpoints live under /_weistack.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Service is one emulated Huawei Cloud service.
type Service interface {
	// Name is the service's endpoint label and path prefix, for example
	// "vpc" for vpc.{region}.myhuaweicloud.com and /vpc/...
	Name() string
	// Version describes the API versions served, for example "v1, v3".
	Version() string
	// Routes registers the service's handlers. Paths are exactly those
	// of the real API (the /{service} prefix is already stripped).
	// Unmatched requests get a NotImplemented error unless the service
	// installs its own NotFound handler.
	Routes(r chi.Router)
}

// Resetter is implemented by services that must rebuild state, such as
// seeded public images, after POST /_weistack/reset wipes the store.
type Resetter interface {
	Reset(ctx context.Context) error
}

// BodyLimiter is implemented by services that need a request body limit
// other than the configured default. Zero means unlimited (OBS uploads).
type BodyLimiter interface {
	MaxBodyBytes() int64
}

// Options are the dependencies of a Server.
type Options struct {
	Config config.Config
	// ProjectID is the resolved default project (Config.ProjectID may be
	// empty, meaning "generate").
	ProjectID string
	Logger    *slog.Logger
	Store     store.Store
	Engine    *lifecycle.Engine
	IDs       *ids.Generator
	// Services are all compiled-in services; Config.Services selects
	// which of them are enabled.
	Services []Service
}

// Server routes requests to services and serves the admin API.
type Server struct {
	cfg       config.Config
	projectID string
	log       *slog.Logger
	store     store.Store
	engine    *lifecycle.Engine
	ids       *ids.Generator
	started   time.Time

	services map[string]*mounted
	names    []string // enabled service names, sorted
	metrics  *metrics
	admin    http.Handler
	handler  http.Handler
}

type mounted struct {
	svc     Service
	handler http.Handler
	maxBody int64
}

var serviceNameRE = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

// New validates the options and builds the routing table.
func New(opts Options) (*Server, error) {
	if opts.Logger == nil || opts.Store == nil || opts.Engine == nil || opts.IDs == nil {
		return nil, errors.New("server: Logger, Store, Engine and IDs are required")
	}
	s := &Server{
		cfg:       opts.Config,
		projectID: opts.ProjectID,
		log:       opts.Logger,
		store:     opts.Store,
		engine:    opts.Engine,
		ids:       opts.IDs,
		started:   time.Now(),
		services:  make(map[string]*mounted),
		metrics:   newMetrics(),
	}

	known := make(map[string]bool, len(opts.Services))
	for _, svc := range opts.Services {
		name := svc.Name()
		if !serviceNameRE.MatchString(name) {
			return nil, fmt.Errorf("server: invalid service name %q", name)
		}
		if known[name] {
			return nil, fmt.Errorf("server: service %q registered twice", name)
		}
		known[name] = true
		if !s.cfg.ServiceEnabled(name) {
			continue
		}
		s.services[name] = s.mount(svc)
		s.names = append(s.names, name)
	}
	sort.Strings(s.names)

	// A typo in WEISTACK_SERVICES should fail loudly, not silently
	// start an emulator with a service missing.
	for _, want := range s.cfg.Services {
		if !known[want] {
			return nil, fmt.Errorf("server: unknown service %q in the services list", want)
		}
	}

	s.admin = s.newAdmin()
	s.handler = s.wrap(http.HandlerFunc(s.route))
	return s, nil
}

func (s *Server) mount(svc Service) *mounted {
	name := svc.Name()
	r := chi.NewRouter()
	gap := func(w http.ResponseWriter, req *http.Request) {
		apierr.Write(w, req, apierr.StyleFlat, apierr.NotImplemented(name, req.Method+" "+req.URL.Path))
	}
	r.NotFound(gap)
	r.MethodNotAllowed(gap)
	svc.Routes(r)

	m := &mounted{svc: svc, handler: r, maxBody: s.cfg.MaxBodyBytes}
	if bl, ok := svc.(BodyLimiter); ok {
		m.maxBody = bl.MaxBodyBytes()
	}
	return m
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

// ServiceHandler returns a handler that sends every request to one
// service, for a listener dedicated to it. The admin API stays
// available. It reports false for a service that is not enabled.
func (s *Server) ServiceHandler(name string) (http.Handler, bool) {
	m, ok := s.services[name]
	if !ok {
		return nil, false
	}
	route := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == adminPrefix || strings.HasPrefix(r.URL.Path, adminPrefix+"/") {
			reqctx.From(r.Context()).Service = adminService
			s.admin.ServeHTTP(w, r)
			return
		}
		reqctx.From(r.Context()).Service = name
		dispatch(m, w, r)
	}
	return s.wrap(http.HandlerFunc(route)), true
}

// wrap applies the middleware every request goes through.
func (s *Server) wrap(h http.Handler) http.Handler {
	return chain(h, s.requestContext, s.observe, s.recoverPanics, cors, auth.Middleware(s.log))
}

// ServiceNames returns the enabled services in alphabetical order.
func (s *Server) ServiceNames() []string { return append([]string(nil), s.names...) }

// chain wraps h so that the first middleware is the outermost.
func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
