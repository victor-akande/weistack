package server

import (
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// adminPrefix is the root of the emulator's own API. The leading
// underscore cannot collide with a service name or a real API path.
const adminPrefix = "/_weistack"

// adminService labels admin requests in logs and metrics.
const adminService = "_weistack"

var regionLabelRE = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+$`)

// errNoSuchAPI is what Huawei's API gateway returns for a URL that maps
// to no API.
var errNoSuchAPI = apierr.New(http.StatusNotFound, "APIGW.0101",
	"The API does not exist or has not been published in the environment")

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	info := reqctx.From(r.Context())

	if r.URL.Path == adminPrefix || strings.HasPrefix(r.URL.Path, adminPrefix+"/") {
		info.Service = adminService
		s.admin.ServeHTTP(w, r)
		return
	}

	if m, region, ok := s.byHost(r.Host); ok {
		info.Service = m.svc.Name()
		if region != "" {
			info.Region = region
		}
		dispatch(m, w, r)
		return
	}

	if m, rest, ok := s.byPath(r.URL); ok {
		info.Service = m.svc.Name()
		dispatch(m, w, rest(r))
		return
	}

	// No emulated service, but the host may still name a region
	// (apiexplorer.ap-southeast-3...): log that, not the default.
	if region := hostRegion(r.Host); region != "" {
		info.Region = region
	}
	apierr.Write(w, r, apierr.StyleFlat, errNoSuchAPI)
}

// hostRegion returns the region an endpoint host names in its second
// label ("iam.ap-southeast-3.myhuaweicloud.com"), or "".
func hostRegion(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	labels := strings.Split(strings.ToLower(host), ".")
	if len(labels) > 2 && regionLabelRE.MatchString(labels[1]) {
		return labels[1]
	}
	return ""
}

func dispatch(m *mounted, w http.ResponseWriter, r *http.Request) {
	if m.maxBody > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, m.maxBody)
	}
	m.handler.ServeHTTP(w, r)
}

// byHost resolves a service from a Huawei-style endpoint host name:
//
//	vpc.ap-southeast-1.myhuaweicloud.com
//	my-bucket.obs.ap-southeast-1.myhuaweicloud.com   (OBS virtual-hosted)
//	ecs.localhost:8780                               (local convenience)
//
// A label names a service only when the label after it is a region or
// "localhost", so a bucket that happens to be called "vpc" is not
// mistaken for the VPC service.
func (s *Server) byHost(hostport string) (m *mounted, region string, ok bool) {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	labels := strings.Split(strings.ToLower(host), ".")
	for i := 0; i+1 < len(labels); i++ {
		m, found := s.services[labels[i]]
		if !found {
			continue
		}
		next := labels[i+1]
		switch {
		case regionLabelRE.MatchString(next):
			return m, next, true
		case next == "localhost" && i+2 == len(labels):
			return m, "", true
		}
	}
	return nil, "", false
}

// byPath resolves a service from a /{service}/... path prefix. The
// returned function rewrites a request so the service sees the real API
// path, as it would behind its own host name.
func (s *Server) byPath(u *url.URL) (m *mounted, rewrite func(*http.Request) *http.Request, ok bool) {
	trimmed := strings.TrimPrefix(u.Path, "/")
	name, rest, _ := strings.Cut(trimmed, "/")
	m, found := s.services[name]
	if !found || trimmed == u.Path {
		return nil, nil, false
	}
	prefix := "/" + name

	return m, func(r *http.Request) *http.Request {
		r2 := new(http.Request)
		*r2 = *r
		r2.URL = new(url.URL)
		*r2.URL = *r.URL
		r2.URL.Path = "/" + rest
		if r.URL.RawPath != "" {
			r2.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, prefix)
			if r2.URL.RawPath == "" {
				r2.URL.RawPath = "/"
			}
		}
		return r2
	}, true
}
