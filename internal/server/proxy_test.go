package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/tlsca"
)

// proxyEnv is a server listening for real, so CONNECT can hijack.
type proxyEnv struct {
	srv *Server
	ca  *tlsca.Authority
	url *url.URL
}

func newProxyEnv(t *testing.T, passthrough string, withCA bool) *proxyEnv {
	t.Helper()
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var ca *tlsca.Authority
	if withCA {
		if ca, err = tlsca.Load(""); err != nil {
			t.Fatal(err)
		}
	}
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	srv, err := New(Options{
		Config: cfg, ProjectID: testProject, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Store: st, Engine: lifecycle.New(lifecycle.Options{}), IDs: ids.New(),
		Services: []Service{&fakeService{name: "vpc"}, &fakeService{name: "obs"}},
		Proxy:    ProxyOptions{CA: ca, Domains: []string{"myhuaweicloud.com"}, Passthrough: passthrough},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		ts.Close()
	})
	u, _ := url.Parse(ts.URL)
	return &proxyEnv{srv: srv, ca: ca, url: u}
}

// client uses the env as its proxy and trusts roots.
func (p *proxyEnv) client(roots *tls.Config) *http.Client {
	tr := &http.Transport{Proxy: http.ProxyURL(p.url), TLSClientConfig: roots, ForceAttemptHTTP2: false}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func getJSON(t *testing.T, c *http.Client, target string) (int, map[string]string) {
	t.Helper()
	res, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer res.Body.Close()
	var out map[string]string
	body, _ := io.ReadAll(res.Body)
	_ = json.Unmarshal(body, &out)
	return res.StatusCode, out
}

func TestProxyInterceptsHTTPS(t *testing.T) {
	t.Parallel()
	p := newProxyEnv(t, PassthroughLoopback, true)
	c := p.client(&tls.Config{RootCAs: p.ca.Pool(), MinVersion: tls.VersionTLS12})

	// The real endpoint host names the service and the region.
	status, out := getJSON(t, c, "https://vpc.af-south-1.myhuaweicloud.com/v1/"+testProject+"/things")
	if status != http.StatusOK || out["service"] != "vpc" || out["region"] != "af-south-1" || out["project_id"] != testProject {
		t.Fatalf("intercepted request: %d %v", status, out)
	}
	// A virtual-hosted bucket needs no DNS: the proxy sees the name.
	status, out = getJSON(t, c, "https://my-bucket.obs.ap-southeast-1.myhuaweicloud.com/v1/x/things")
	if status != http.StatusOK || out["service"] != "obs" {
		t.Fatalf("bucket host: %d %v", status, out)
	}
	// Several requests reuse the tunnel.
	for range 3 {
		if status, _ := getJSON(t, c, "https://vpc.af-south-1.myhuaweicloud.com/v1/p/things"); status != http.StatusOK {
			t.Fatalf("repeated request: %d", status)
		}
	}
	// A host of the domain that is no emulated service gets the gateway's 404.
	res, err := c.Get("https://iam.myhuaweicloud.com/v3/auth/domains")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound || !strings.Contains(string(body), "APIGW.0101") {
		t.Fatalf("unemulated service: %d %s", res.StatusCode, body)
	}
}

func TestProxyCertificateMustBeTrusted(t *testing.T) {
	t.Parallel()
	p := newProxyEnv(t, PassthroughLoopback, true)
	_, err := p.client(&tls.Config{MinVersion: tls.VersionTLS12}).Get("https://vpc.ap-southeast-1.myhuaweicloud.com/v1/p/things")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a client that does not trust the CA connected: %v", err)
	}
	// Skipping verification, as clients' "insecure" options do, works.
	insecure := p.client(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // that is the point of the test
	if status, _ := getJSON(t, insecure, "https://vpc.ap-southeast-1.myhuaweicloud.com/v1/p/things"); status != http.StatusOK {
		t.Fatalf("insecure client: %d", status)
	}
}

func TestProxyPlainHTTP(t *testing.T) {
	t.Parallel()
	p := newProxyEnv(t, PassthroughLoopback, true)
	c := p.client(nil)

	status, out := getJSON(t, c, "http://vpc.cn-north-4.myhuaweicloud.com/v1/"+testProject+"/things")
	if status != http.StatusOK || out["region"] != "cn-north-4" {
		t.Fatalf("plain HTTP through the proxy: %d %v", status, out)
	}
	res, err := c.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("plain HTTP to another host: %d, want 403", res.StatusCode)
	}
}

func TestProxyPassthrough(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "real upstream")
	}))
	defer upstream.Close()
	roots := upstream.Client().Transport.(*http.Transport).TLSClientConfig

	// Loopback clients may tunnel to hosts that are not emulated.
	p := newProxyEnv(t, PassthroughLoopback, true)
	res, err := p.client(roots).Get(upstream.URL)
	if err != nil {
		t.Fatalf("passthrough: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "real upstream" {
		t.Fatalf("passthrough reached %q", body)
	}

	// With passthrough off, the tunnel is refused.
	off := newProxyEnv(t, PassthroughNone, true)
	if _, err := off.client(roots).Get(upstream.URL); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("passthrough none: %v", err)
	}

	// An unreachable target is a 502.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	if _, err := p.client(roots).Get("https://" + dead + "/"); err == nil || !strings.Contains(err.Error(), "Bad Gateway") {
		t.Fatalf("unreachable target: %v", err)
	}
}

func TestPassthroughOnlyForLoopbackClients(t *testing.T) {
	t.Parallel()
	loopback := newProxy(ProxyOptions{}, nil, nil)
	for addr, want := range map[string]bool{
		"127.0.0.1:5000": true, "[::1]:5000": true, "192.0.2.10:5000": false, "172.17.0.1:5000": false, "bogus": false,
	} {
		if got := loopback.mayPassThrough(addr); got != want {
			t.Errorf("loopback mode, client %s: %v", addr, got)
		}
	}
	all := newProxy(ProxyOptions{Passthrough: PassthroughAll}, nil, nil)
	if !all.mayPassThrough("192.0.2.10:5000") {
		t.Error("all mode refused a remote client")
	}
}

func TestInterceptionNeedsACA(t *testing.T) {
	t.Parallel()
	p := newProxyEnv(t, PassthroughLoopback, false)
	_, err := p.client(&tls.Config{InsecureSkipVerify: true}).Get("https://vpc.ap-southeast-1.myhuaweicloud.com/") //nolint:gosec // test
	if err == nil || !strings.Contains(err.Error(), "Not Implemented") {
		t.Fatalf("interception without a CA: %v", err)
	}
}

func TestInterceptsDomains(t *testing.T) {
	t.Parallel()
	p := newProxy(ProxyOptions{Domains: []string{"myhuaweicloud.com"}}, nil, nil)
	for host, want := range map[string]bool{
		"vpc.ap-southeast-1.myhuaweicloud.com": true, "MyHuaweiCloud.com": true, "obs.myhuaweicloud.com.": true,
		"evilmyhuaweicloud.com": false, "myhuaweicloud.com.evil.net": false, "example.com": false,
	} {
		if got := p.intercepts(host); got != want {
			t.Errorf("intercepts(%q) = %v", host, got)
		}
	}
}

func TestShutdownClosesTunnels(t *testing.T) {
	t.Parallel()
	p := newProxyEnv(t, PassthroughLoopback, true)
	c := p.client(&tls.Config{RootCAs: p.ca.Pool(), MinVersion: tls.VersionTLS12})
	if status, _ := getJSON(t, c, "https://vpc.ap-southeast-1.myhuaweicloud.com/v1/p/things"); status != http.StatusOK {
		t.Fatal("first request failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// New tunnels are no longer served.
	fresh := p.client(&tls.Config{RootCAs: p.ca.Pool(), MinVersion: tls.VersionTLS12})
	if _, err := fresh.Get("https://vpc.ap-southeast-1.myhuaweicloud.com/v1/p/things"); err == nil {
		t.Fatal("a tunnel was served after shutdown")
	}
}

func TestOneConnListener(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer b.Close()
	ln := newOneConnListener(a)
	if c, err := ln.Accept(); err != nil || c != a {
		t.Fatalf("first Accept = %v, %v", c, err)
	}
	done := make(chan error, 1)
	go func() { _, err := ln.Accept(); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("second Accept returned before Close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	_ = ln.Close()
	_ = ln.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	if ln.Addr() == nil {
		t.Fatal("Addr is nil")
	}
}

func TestAdminServesCACertificate(t *testing.T) {
	t.Parallel()
	p := newProxyEnv(t, PassthroughLoopback, true)
	res, err := http.Get(p.url.String() + "/_weistack/ca")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || string(body) != string(p.ca.CertPEM()) {
		t.Fatalf("GET /_weistack/ca = %d %q", res.StatusCode, body)
	}

	noCA := newProxyEnv(t, PassthroughLoopback, false)
	res, err = http.Get(noCA.url.String() + "/_weistack/ca")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /_weistack/ca without a CA = %d", res.StatusCode)
	}
}
