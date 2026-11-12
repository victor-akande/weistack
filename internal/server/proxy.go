package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/hostpattern"
	"github.com/victor-akande/weistack/internal/tlsca"
)

// Passthrough modes: who may tunnel to hosts WeiStack does not emulate.
const (
	PassthroughLoopback = "loopback" // clients on this machine only
	PassthroughAll      = "all"
	PassthroughNone     = "none"
)

// ProxyOptions configure WeiStack as an HTTP(S) proxy. Clients keep the
// real Huawei Cloud endpoints and set HTTPS_PROXY to WeiStack: requests
// for the emulated domains are answered by the emulator, so nothing
// depends on DNS and no request can reach the real cloud.
type ProxyOptions struct {
	// CA signs the certificates presented for intercepted hosts. Nil
	// disables HTTPS interception.
	CA *tlsca.Authority
	// Domains are intercepted, with all their subdomains...
	Domains []string
	// ...except hosts matching Bypass, which are treated like any host
	// outside the domains.
	Bypass []*hostpattern.Pattern
	// Passthrough is one of the Passthrough constants.
	Passthrough string
}

// proxy implements CONNECT and absolute-form requests.
type proxy struct {
	opts    ProxyOptions
	handler http.Handler
	log     *slog.Logger

	mu      sync.Mutex
	tunnels map[*http.Server]struct{}
	closed  bool
}

func newProxy(opts ProxyOptions, handler http.Handler, log *slog.Logger) *proxy {
	if opts.Passthrough == "" {
		opts.Passthrough = PassthroughLoopback
	}
	return &proxy{opts: opts, handler: handler, log: log, tunnels: map[*http.Server]struct{}{}}
}

// intercepts reports whether host belongs to an emulated domain and is
// not bypassed.
func (p *proxy) intercepts(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, b := range p.opts.Bypass {
		if b.Match(host) {
			return false
		}
	}
	for _, d := range p.opts.Domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func (p *proxy) mayPassThrough(remoteAddr string) bool {
	switch p.opts.Passthrough {
	case PassthroughAll:
		return true
	case PassthroughNone:
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// splitTarget reads "host:port" from a CONNECT request.
func splitTarget(hostport string) (string, string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, "443"
	}
	return host, port
}

// ServeHTTP is WeiStack's entry point: proxy requests are handled here,
// everything else goes to the router.
func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.connect(w, r)
	case r.URL.IsAbs():
		// A plain-HTTP proxy request: the router already uses the host
		// it names. Other hosts are not proxied.
		host, _ := splitTarget(r.URL.Host)
		if !strings.Contains(r.URL.Host, ":") {
			host = r.URL.Host
		}
		if !p.intercepts(host) {
			p.refuse(w, r, host, refusal{
				reason: "WeiStack relays plain HTTP only for the hosts it emulates (" + strings.Join(p.opts.Domains, ", ") + ")",
				fix:    "use HTTPS for this host, or send it around the proxy with NO_PROXY",
			})
			return
		}
		p.handler.ServeHTTP(w, r)
	default:
		p.handler.ServeHTTP(w, r)
	}
}

func (p *proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port := splitTarget(r.Host)
	switch {
	case p.intercepts(host):
		if p.opts.CA == nil {
			http.Error(w, "weistack: HTTPS interception is disabled", http.StatusNotImplemented)
			return
		}
		p.intercept(w, r, host)
	case p.mayPassThrough(r.RemoteAddr):
		p.passthrough(w, r, net.JoinHostPort(host, port))
	default:
		p.refuse(w, r, host, p.tunnelRefusal(r.RemoteAddr))
	}
}

// refusal explains why the proxy will not reach a host, and what would
// change that.
type refusal struct {
	reason, fix string
}

// tunnelRefusal explains a refused tunnel under the passthrough setting.
func (p *proxy) tunnelRefusal(client string) refusal {
	if p.opts.Passthrough == PassthroughNone {
		return refusal{
			reason: "passing traffic through to hosts WeiStack does not emulate is off (-proxy-passthrough none)",
			fix:    "start WeiStack with -proxy-passthrough loopback or all, or send this host around the proxy with NO_PROXY",
		}
	}
	return refusal{
		reason: fmt.Sprintf("only clients on WeiStack's own machine may reach other hosts through it, and %s is not one (-proxy-passthrough loopback)", client),
		fix:    "start WeiStack with -proxy-passthrough all (WEISTACK_PROXY_PASSTHROUGH=all, as a container usually needs), or send this host around the proxy with NO_PROXY",
	}
}

// refuse answers 403 for a host the proxy will not reach. The reason and
// the fix go to the log, the body and a Proxy-Status header (RFC 9209),
// because many clients show only the status line of a failed CONNECT.
func (p *proxy) refuse(w http.ResponseWriter, r *http.Request, host string, why refusal) {
	p.log.Warn("proxy refused a request", "target", r.Host, "client", r.RemoteAddr, "reason", why.reason, "fix", why.fix)
	w.Header().Set("Proxy-Status", fmt.Sprintf("weistack; error=http_request_denied; details=%q", why.reason+"; "+why.fix))
	http.Error(w, fmt.Sprintf("weistack: not proxying to %s: %s.\nTo allow it: %s.", host, why.reason, why.fix), http.StatusForbidden)
}

// hijack takes over the client connection and confirms the tunnel.
func hijack(w http.ResponseWriter) (net.Conn, error) {
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// Bytes the client sent after the CONNECT request may already be
	// buffered; they belong to the tunnel.
	if n := brw.Reader.Buffered(); n > 0 {
		return &bufferedConn{Conn: conn, r: brw.Reader}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// intercept terminates TLS with a certificate for host and serves the
// requests inside the tunnel with the normal router.
func (p *proxy) intercept(w http.ResponseWriter, r *http.Request, host string) {
	conn, err := hijack(w)
	if err != nil {
		p.log.Error("proxy hijack failed", "error", err)
		return
	}
	tlsConn := tls.Server(conn, p.opts.CA.ServerConfig(host))

	hs := &http.Server{
		Handler:           p.handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(p.log.Handler(), slog.LevelDebug),
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return
	}
	p.tunnels[hs] = struct{}{}
	p.mu.Unlock()

	ln := newOneConnListener(tlsConn)
	hs.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			_ = ln.Close()
		}
	}
	p.log.Debug("proxy intercepting", "target", r.Host, "client", r.RemoteAddr)
	go func() {
		_ = hs.Serve(ln)
		p.mu.Lock()
		delete(p.tunnels, hs)
		p.mu.Unlock()
	}()
}

// passthrough relays a tunnel to a host WeiStack does not emulate.
func (p *proxy) passthrough(w http.ResponseWriter, r *http.Request, target string) {
	d := net.Dialer{Timeout: 10 * time.Second}
	upstream, err := d.DialContext(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, fmt.Sprintf("weistack: cannot reach %s: %v", target, err), http.StatusBadGateway)
		return
	}
	conn, err := hijack(w)
	if err != nil {
		_ = upstream.Close()
		return
	}
	p.log.Debug("proxy passing through", "target", target, "client", r.RemoteAddr)
	go relay(conn, upstream)
}

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// Let the other direction finish, then close.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// shutdown drains the intercepted tunnels.
func (p *proxy) shutdown(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	servers := make([]*http.Server, 0, len(p.tunnels))
	for hs := range p.tunnels {
		servers = append(servers, hs)
	}
	p.mu.Unlock()
	var errs []error
	for _, hs := range servers {
		if err := hs.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// oneConnListener hands out one connection, then blocks until closed,
// so that an http.Server can serve a single hijacked connection.
type oneConnListener struct {
	mu   sync.Mutex
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, done: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{} }
