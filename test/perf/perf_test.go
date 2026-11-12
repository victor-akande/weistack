//go:build perf

// Package perf checks WeiStack against its performance budgets by
// running the real binary:
//
//   - cold start, from exec to a healthy admin endpoint: under 1 s
//   - idle resident memory: under 50 MB, and within 20% of the baseline
//   - p99 latency of get and list with 1,000 resources stored: under
//     10 ms, in memory and with -persist
//
// The image size budget (40 MB) is checked by the CI image job.
//
// The tests are behind the "perf" build tag, so `go test ./...` skips
// them: run `make perf`. They need Linux, for /proc.
package perf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Budgets, from the project plan.
const (
	coldStartBudget = time.Second
	idleRSSBudgetMB = 50.0
	p99Budget       = 10 * time.Millisecond
	// rssRegression is how far idle memory may grow over the baseline.
	rssRegression = 1.20

	resources = 1000
	samples   = 500
	project   = "0123456789abcdef0123456789abcdef"
)

var (
	bin    string
	report = struct {
		sync.Mutex
		Metrics map[string]float64 `json:"metrics"`
	}{Metrics: map[string]float64{}}
)

func record(name string, value float64) {
	report.Lock()
	defer report.Unlock()
	report.Metrics[name] = value
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "weistack-perf-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bin = filepath.Join(dir, "weistack")
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", bin, "./cmd/weistack")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	if path := os.Getenv("WEISTACK_PERF_REPORT"); path != "" {
		out, _ := json.MarshalIndent(report.Metrics, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// proc is a running emulator.
type proc struct {
	cmd  *exec.Cmd
	base string
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

// start runs the emulator and returns once it is healthy, with the time
// that took.
func start(t *testing.T, env ...string) (*proc, time.Duration) {
	t.Helper()
	port := freePort(t)
	cmd := exec.Command(bin)
	cmd.Env = append(append(os.Environ(),
		"WEISTACK_PORT="+port, "WEISTACK_PROJECT_ID="+project, "WEISTACK_LIFECYCLE_DELAY=0",
		"WEISTACK_LOG_LEVEL=error", "WEISTACK_TLS_DIR="+filepath.Join(t.TempDir(), "tls"),
	), env...)
	p := &proc{cmd: cmd, base: "http://127.0.0.1:" + port}
	client := &http.Client{Timeout: 100 * time.Millisecond}

	began := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	})
	for time.Since(began) < 10*time.Second {
		res, err := client.Get(p.base + "/_weistack/health")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return p, time.Since(began)
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the emulator did not become healthy within 10s")
	return nil, 0
}

// rssMB reads the process's resident set size from /proc.
func (p *proc) rssMB(t *testing.T) float64 {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.cmd.Process.Pid))
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			kb, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), "kB")))
			if err != nil {
				t.Fatalf("parsing %q: %v", line, err)
			}
			return float64(kb) / 1024
		}
	}
	t.Fatal("no VmRSS in /proc status")
	return 0
}

func (p *proc) do(t *testing.T, method, path, body string, hdr map[string]string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, p.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v // Go sends req.Host, not a Host header
			continue
		}
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, out)
	}
	return out
}

// p99 times n sequential requests and returns the 99th percentile.
func p99(t *testing.T, n int, call func(i int)) time.Duration {
	t.Helper()
	for i := range 20 { // warm up connections and caches
		call(i)
	}
	lat := make([]time.Duration, n)
	for i := range n {
		began := time.Now()
		call(i)
		lat[i] = time.Since(began)
	}
	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
	return lat[n*99/100]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func TestColdStart(t *testing.T) {
	var worst time.Duration
	for range 5 {
		p, took := start(t)
		worst = max(worst, took)
		_ = p.cmd.Process.Signal(os.Interrupt)
		_ = p.cmd.Wait()
	}
	record("cold_start_ms", ms(worst))
	t.Logf("cold start, worst of 5: %v (budget %v)", worst, coldStartBudget)
	if worst > coldStartBudget {
		t.Errorf("cold start %v exceeds the %v budget", worst, coldStartBudget)
	}
}

func TestIdleMemory(t *testing.T) {
	p, _ := start(t)
	// Let start-up garbage be collected, as an idle emulator would.
	time.Sleep(2 * time.Second)
	rss := p.rssMB(t)
	record("idle_rss_mb", rss)
	t.Logf("idle RSS: %.1f MB (budget %.0f MB)", rss, idleRSSBudgetMB)
	if rss > idleRSSBudgetMB {
		t.Errorf("idle RSS %.1f MB exceeds the %.0f MB budget", rss, idleRSSBudgetMB)
	}
	base := baseline(t)
	if b, ok := base["idle_rss_mb"]; ok && rss > b*rssRegression {
		t.Errorf("idle RSS %.1f MB is more than %.0f%% over the baseline %.1f MB", rss, (rssRegression-1)*100, b)
	}
}

// baseline reads baseline.json: the metrics of a reference CI run.
func baseline(t *testing.T) map[string]float64 {
	t.Helper()
	raw, err := os.ReadFile("baseline.json")
	if err != nil {
		t.Fatalf("reading the baseline: %v", err)
	}
	var b map[string]float64
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parsing the baseline: %v", err)
	}
	return b
}

func TestLatencyAtScale(t *testing.T) {
	for _, mode := range []struct {
		name string
		env  []string
	}{
		{"memory", nil},
		{"persist", []string{"WEISTACK_PERSIST=1", "WEISTACK_DATA_DIR=" + t.TempDir()}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			p, _ := start(t, mode.env...)
			vpcs := "/vpc/v1/" + project + "/vpcs"
			obsHost := map[string]string{"Host": "obs.ap-southeast-1.myhuaweicloud.com", "Authorization": "OBS AKPERF:c2ln"}

			// 1,000 VPCs and 1,000 objects.
			ids := make([]string, resources)
			for i := range resources {
				out := p.do(t, http.MethodPost, vpcs, fmt.Sprintf(`{"vpc": {"name": "perf-%04d", "cidr": "10.0.0.0/16"}}`, i), nil)
				var created struct {
					VPC struct {
						ID string `json:"id"`
					} `json:"vpc"`
				}
				if err := json.Unmarshal(out, &created); err != nil || created.VPC.ID == "" {
					t.Fatalf("creating VPC %d: %s", i, out)
				}
				ids[i] = created.VPC.ID
			}
			p.do(t, http.MethodPut, "/perf-bucket", "", obsHost)
			for i := range resources {
				p.do(t, http.MethodPut, fmt.Sprintf("/perf-bucket/obj-%04d", i), "payload", obsHost)
			}
			rss := p.rssMB(t)
			record("loaded_rss_mb_"+mode.name, rss)
			t.Logf("RSS with %d VPCs and %d objects: %.1f MB", resources, resources, rss)

			checks := []struct {
				name string
				call func(i int)
			}{
				{"get_vpc", func(i int) { p.do(t, http.MethodGet, vpcs+"/"+ids[i%resources], "", nil) }},
				{"list_vpcs_1000", func(int) { p.do(t, http.MethodGet, vpcs, "", nil) }},
				{"get_object", func(i int) { p.do(t, http.MethodGet, fmt.Sprintf("/perf-bucket/obj-%04d", i%resources), "", obsHost) }},
				{"list_objects_1000", func(int) { p.do(t, http.MethodGet, "/perf-bucket?max-keys=1000", "", obsHost) }},
			}
			for _, c := range checks {
				got := p99(t, samples, c.call)
				record("p99_ms_"+c.name+"_"+mode.name, ms(got))
				t.Logf("%-18s p99 %v (budget %v)", c.name, got, p99Budget)
				if got > p99Budget {
					t.Errorf("%s: p99 %v exceeds the %v budget", c.name, got, p99Budget)
				}
			}
		})
	}
}
