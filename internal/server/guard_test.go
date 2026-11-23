package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
)

// TestHostGuard: a loopback-bound WeiStack answers only names an
// attacker's DNS cannot point at it, which stops DNS rebinding.
func TestHostGuard(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(c *config.Config) { c.AllowedHosts = []string{"weistack.test", "*.dev.internal"} },
		&fakeService{name: "vpc"})
	for _, tc := range []struct {
		host string
		want int
	}{
		{"localhost:8780", http.StatusOK},
		{"LOCALHOST.", http.StatusOK},
		{"my-bucket.obs.localhost:8780", http.StatusOK},
		{"127.0.0.1:8780", http.StatusOK},
		{"[::1]:8780", http.StatusOK},
		{"10.1.2.3", http.StatusOK}, // an address cannot be rebound
		{"vpc.ap-southeast-1.myhuaweicloud.com", http.StatusOK},
		{"weistack.test:8780", http.StatusOK},
		{"box.dev.internal", http.StatusOK},
		{"", http.StatusOK},

		{"evil.example:8780", http.StatusForbidden},
		{"localhost.evil.example", http.StatusForbidden},
		{"myhuaweicloud.com.evil.example", http.StatusForbidden},
		{"a.b.dev.internal", http.StatusForbidden}, // * is one label
	} {
		res := h.do(t, http.MethodGet, "/_weistack/health", nil, host(tc.host))
		body := readBody(t, res)
		if res.StatusCode != tc.want {
			t.Errorf("Host %q: status %d, want %d: %s", tc.host, res.StatusCode, tc.want, body)
		}
		if tc.want == http.StatusForbidden && !strings.Contains(body, "-allowed-hosts") {
			t.Errorf("Host %q: refusal does not say how to allow it: %s", tc.host, body)
		}
	}

	// Services are guarded too, not only the admin API.
	res := h.do(t, http.MethodGet, "/vpc/v1/p/things", nil, host("evil.example"))
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("service through a foreign Host: status %d, want 403", res.StatusCode)
	}
}

// TestHostGuardOffBeyondLoopback: bound beyond loopback (a container),
// clients use names WeiStack cannot know, such as a Compose service.
func TestHostGuardOffBeyondLoopback(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(c *config.Config) { c.Host = "0.0.0.0" })
	res := h.do(t, http.MethodGet, "/_weistack/health", nil, host("weistack:8780"))
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", res.StatusCode)
	}
}

// TestAdminRefusesOtherSites replays what a web page on another site
// could do to a local WeiStack before the guard: wipe its data, mint an
// account, read its state.
func TestAdminRefusesOtherSites(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil, &fakeService{name: "vpc"})
	seed(t, h.store)
	browser := func(origin string) func(*http.Request) {
		return func(r *http.Request) {
			r.Host = "127.0.0.1:8780"
			r.Header.Set("Content-Type", "text/plain") // no preflight
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
		}
	}
	for _, origin := range []string{"https://evil.example", "null", "http://192.168.1.5:3000", "http://localhost.evil.example"} {
		for _, tc := range []struct{ method, path string }{
			{http.MethodPost, "/_weistack/reset"},
			{http.MethodGet, "/_weistack/state"},
			{http.MethodPost, "/_weistack/accounts"},
		} {
			res := h.do(t, tc.method, tc.path, strings.NewReader(`{"name":"x"}`), browser(origin))
			res.Body.Close()
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s from %s: status %d, want 403", tc.method, tc.path, origin, res.StatusCode)
			}
			if got := res.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("%s %s from %s: Allow-Origin %q", tc.method, tc.path, origin, got)
			}
		}
	}
	// A browser that sends only Sec-Fetch-Site is refused as well.
	res := h.do(t, http.MethodPost, "/_weistack/reset", nil, func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("reset with Sec-Fetch-Site cross-site: status %d, want 403", res.StatusCode)
	}
	if recs, err := h.store.Dump(t.Context()); err != nil || len(recs) == 0 {
		t.Fatalf("the refused resets wiped the store: %v, %v", recs, err)
	}

	// Pages on this machine and clients that are not browsers still work.
	for _, mutate := range []func(*http.Request){
		browser("http://localhost:3000"),
		browser("http://127.0.0.1:5173"),
		browser("http://dash.localhost"),
		browser(""),
	} {
		res := h.do(t, http.MethodGet, "/_weistack/state", nil, mutate)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("local GET state: status %d, want 200", res.StatusCode)
		}
	}
	res = h.do(t, http.MethodGet, "/_weistack/state", nil, browser("http://localhost:3000"))
	res.Body.Close()
	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("local page: Allow-Origin %q, want *", got)
	}

	// The services keep their open CORS, on purpose.
	res = h.do(t, http.MethodGet, "/vpc/v1/p/things", nil, browser("https://evil.example"))
	res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("service from another site: status %d, Allow-Origin %q", res.StatusCode, res.Header.Get("Access-Control-Allow-Origin"))
	}
}
