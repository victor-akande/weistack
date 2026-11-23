package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

const lanProject = "0123456789abcdef0123456789abcdef"

type lanInstance struct {
	main, lan string
	pool      *x509.CertPool
}

// startLAN starts WeiStack with -lan in accept mode, so that whatever the
// LAN listener checks, it checks because of -lan.
func startLAN(t *testing.T, extra map[string]string) lanInstance {
	t.Helper()
	tls := t.TempDir()
	env := map[string]string{
		"WEISTACK_PORT": "0", "WEISTACK_LAN": "1", "WEISTACK_LAN_PORT": "0", "WEISTACK_TLS_DIR": tls,
		"WEISTACK_LIFECYCLE_DELAY": "0", "WEISTACK_PROJECT_ID": lanProject,
		"WEISTACK_ADMIN_ACCESS_KEY": testAdmin.AccessKey, "WEISTACK_ADMIN_SECRET_KEY": testAdmin.SecretKey,
	}
	for k, v := range extra {
		env[k] = v
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready, lanReady := make(chan net.Addr, 1), make(chan net.Addr, 1)
	go func() {
		done <- Run(ctx, Env{
			Getenv: func(k string) string { return env[k] }, Stdout: io.Discard, Stderr: io.Discard,
			OnReady: func(a net.Addr) { ready <- a }, OnLAN: func(a net.Addr) { lanReady <- a },
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("emulator stopped with %v", err)
		}
	})
	var inst lanInstance
	select {
	case a := <-ready:
		inst.main = a.String()
	case err := <-done:
		t.Fatalf("emulator exited: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("emulator did not become ready")
	}
	_, port, _ := net.SplitHostPort((<-lanReady).String())
	inst.lan = net.JoinHostPort("127.0.0.1", port)
	pem, err := os.ReadFile(filepath.Join(tls, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	inst.pool = x509.NewCertPool()
	inst.pool.AppendCertsFromPEM(pem)
	return inst
}

func (i lanInstance) client() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: i.pool}}}
}

// do sends a request, signed as the administrator if sign is set.
func lanDo(t *testing.T, c *http.Client, method, target string, sign bool) int {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sign {
		sigcheck.SignSDKHMAC(r, testAdmin.AccessKey, testAdmin.SecretKey, r.URL.Path, nil, time.Now())
	}
	res, err := c.Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return res.StatusCode
}

func TestLAN(t *testing.T) {
	t.Parallel()
	inst := startLAN(t, nil)
	c := inst.client()
	_, port, _ := net.SplitHostPort(inst.lan)
	vpcs := "/vpc/v1/" + lanProject + "/vpcs"

	for _, tc := range []struct {
		name, method, target string
		sign                 bool
		want                 int
	}{
		{"health by IP, without a server name", http.MethodGet, "https://" + inst.lan + "/_weistack/health", false, http.StatusOK},
		{"health by name", http.MethodGet, "https://localhost:" + port + "/_weistack/health", false, http.StatusOK},
		{"the CA stays open", http.MethodGet, "https://" + inst.lan + "/_weistack/ca", false, http.StatusOK},
		{"a service, unsigned, in accept mode", http.MethodGet, "https://" + inst.lan + vpcs, false, http.StatusUnauthorized},
		{"a service, signed", http.MethodGet, "https://" + inst.lan + vpcs, true, http.StatusOK},
		{"the admin API, unsigned", http.MethodGet, "https://" + inst.lan + "/_weistack/services", false, http.StatusUnauthorized},
		{"the admin API, signed", http.MethodGet, "https://" + inst.lan + "/_weistack/services", true, http.StatusOK},
		{"state is local only", http.MethodGet, "https://" + inst.lan + "/_weistack/state", true, http.StatusForbidden},
		{"reset is local only", http.MethodPost, "https://" + inst.lan + "/_weistack/reset", true, http.StatusForbidden},
		{"loopback is unchanged", http.MethodGet, "http://" + inst.main + vpcs, false, http.StatusOK},
		{"loopback state is unchanged", http.MethodGet, "http://" + inst.main + "/_weistack/state", false, http.StatusOK},
		{"plain HTTP on the LAN port", http.MethodGet, "http://" + inst.lan + "/_weistack/health", false, http.StatusBadRequest},
	} {
		if got := lanDo(t, c, tc.method, tc.target, tc.sign); got != tc.want {
			t.Errorf("%s: %s %s = %d, want %d", tc.name, tc.method, tc.target, got, tc.want)
		}
	}

	// Through the LAN port as an HTTPS proxy, the tunnel's requests are
	// the network's too.
	proxied := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "https", Host: inst.lan}),
		TLSClientConfig: &tls.Config{RootCAs: inst.pool},
	}}
	cloud := "https://vpc.ap-southeast-1.myhuaweicloud.com/v1/" + lanProject + "/vpcs"
	if got := lanDo(t, proxied, http.MethodGet, cloud, false); got != http.StatusUnauthorized {
		t.Errorf("unsigned through the LAN proxy = %d, want 401", got)
	}
	if got := lanDo(t, proxied, http.MethodGet, cloud, true); got != http.StatusOK {
		t.Errorf("signed through the LAN proxy = %d, want 200", got)
	}
}

func TestLANRefusesOtherClients(t *testing.T) {
	t.Parallel()
	inst := startLAN(t, map[string]string{"WEISTACK_LAN_CLIENTS": "10.0.0.0/8"})
	_, err := inst.client().Get("https://" + inst.lan + "/_weistack/health")
	if err == nil {
		t.Fatal("a client outside -lan-clients was served")
	}
	if strings.Contains(err.Error(), "certificate") {
		t.Fatalf("refused with a certificate error, not a closed connection: %v", err)
	}
}
