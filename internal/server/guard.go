package server

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/hostpattern"
)

// Browsers let any web page send requests to a WeiStack on this
// machine. Two guards keep such pages out:
//
//   - While WeiStack binds only loopback, it answers only Host names
//     that cannot be rebound to it by an attacker's DNS: localhost, IP
//     addresses, the proxy domains and -allowed-hosts. A page on
//     evil.example whose name later resolves to 127.0.0.1 is refused.
//   - The admin API refuses requests that a browser sent from a page
//     that is not on this machine. It can wipe persisted data and mint
//     credentials, so open CORS never applies to it.

// hostGuard holds the Host names a loopback-bound WeiStack answers.
type hostGuard struct {
	domains []string
	extra   []*hostpattern.Pattern
}

// newHostGuard returns nil when WeiStack listens beyond loopback, where
// clients reach it by names WeiStack cannot know (a Compose service, a
// container's address).
func (s *Server) newHostGuard() (*hostGuard, error) {
	if !s.cfg.Loopback() {
		return nil, nil
	}
	g := &hostGuard{domains: s.cfg.ProxyDomains}
	for _, p := range s.cfg.AllowedHosts {
		c, err := hostpattern.Compile(p)
		if err != nil {
			return nil, err
		}
		g.extra = append(g.extra, c)
	}
	return g, nil
}

// allows reports whether a request's Host header is one WeiStack
// answers.
func (g *hostGuard) allows(hostport string) bool {
	host := hostOnly(hostport)
	if host == "" || isLocalName(host) || net.ParseIP(host) != nil {
		return true
	}
	for _, d := range g.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	for _, p := range g.extra {
		if p.Match(host) {
			return true
		}
	}
	return false
}

// hostOnly lowercases a Host header and drops its port, brackets and
// trailing dot.
func hostOnly(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	return strings.ToLower(host)
}

// isLocalName reports whether host is localhost or a name under it,
// which browsers resolve to loopback without asking DNS.
func isLocalName(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// isLocalOrigin reports whether a browser Origin is a page on this
// machine: localhost, a name under it, or a loopback address.
func isLocalOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false // includes "null", sent by sandboxed and file pages
	}
	host := hostOnly(u.Host)
	if isLocalName(host) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// crossSite reports whether a browser sent r from a page that is not on
// this machine. Clients other than browsers send neither header.
func crossSite(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return !isLocalOrigin(origin)
	}
	return r.Header.Get("Sec-Fetch-Site") == "cross-site"
}

// isAdminPath reports whether path is under the admin API.
func isAdminPath(path string) bool {
	return path == adminPrefix || strings.HasPrefix(path, adminPrefix+"/")
}

// guard refuses requests that reach WeiStack by an unknown Host name, and
// cross-site browser requests to the admin API.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Other machines (-lan) reach WeiStack by names it cannot know,
		// and always need credentials, which a rebinding page lacks.
		if s.hosts != nil && !fromNetwork(r.Context()) && !s.hosts.allows(r.Host) {
			s.log.WarnContext(r.Context(), "refused a request for an unknown host name",
				"host", r.Host, "remote", r.RemoteAddr)
			apierr.Write(w, r, apierr.StyleFlat, apierr.New(http.StatusForbidden, "WeiStack.0403",
				"WeiStack does not answer the host name %q; if it is yours, add it to -allowed-hosts (WEISTACK_ALLOWED_HOSTS)", hostOnly(r.Host)))
			return
		}
		if isAdminPath(r.URL.Path) && crossSite(r) {
			s.log.WarnContext(r.Context(), "refused a cross-site browser request to the admin API",
				"origin", r.Header.Get("Origin"), "path", r.URL.Path, "remote", r.RemoteAddr)
			apierr.Write(w, r, apierr.StyleFlat, apierr.New(http.StatusForbidden, "WeiStack.0403",
				"the admin API does not answer web pages from other sites"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
