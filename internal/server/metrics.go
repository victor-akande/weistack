package server

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/version"
)

// latencyBuckets are histogram upper bounds in seconds, centred on the
// emulator's single-digit-millisecond budget.
var latencyBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5}

// metrics is a minimal Prometheus-format registry. It is hand-written to
// avoid pulling the Prometheus client (and its dependency tree) into a
// binary whose size and idle memory are budgeted.
type metrics struct {
	mu        sync.Mutex
	requests  map[requestKey]uint64
	latencies map[string]*histogram // by service
}

type requestKey struct {
	service string
	method  string
	code    int
}

type histogram struct {
	counts []uint64 // one per bucket, non-cumulative
	over   uint64   // observations above the last bucket
	sum    float64
}

func newMetrics() *metrics {
	return &metrics{requests: make(map[requestKey]uint64), latencies: make(map[string]*histogram)}
}

// knownMethods bounds the "method" label: arbitrary client-chosen method
// strings must not create unbounded series.
var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
}

func (m *metrics) observe(service, method string, status int, elapsed time.Duration) {
	if service == "" {
		service = "unrouted"
	}
	if !knownMethods[method] {
		method = "OTHER"
	}
	secs := elapsed.Seconds()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[requestKey{service, method, status}]++

	h := m.latencies[service]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(latencyBuckets))}
		m.latencies[service] = h
	}
	h.sum += secs
	i := sort.SearchFloat64s(latencyBuckets, secs)
	if i < len(latencyBuckets) {
		h.counts[i]++
	} else {
		h.over++
	}
}

// write renders the registry in Prometheus text exposition format, with
// series sorted so the output is stable.
func (m *metrics) write(w io.Writer, resources map[string]int, pendingTasks int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Fprintln(w, "# HELP weistack_build_info Build information.")
	fmt.Fprintln(w, "# TYPE weistack_build_info gauge")
	fmt.Fprintf(w, "weistack_build_info{version=%q} 1\n", version.Version)

	fmt.Fprintln(w, "# HELP weistack_http_requests_total HTTP requests handled.")
	fmt.Fprintln(w, "# TYPE weistack_http_requests_total counter")
	keys := make([]requestKey, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.service != b.service {
			return a.service < b.service
		}
		if a.method != b.method {
			return a.method < b.method
		}
		return a.code < b.code
	})
	for _, k := range keys {
		fmt.Fprintf(w, "weistack_http_requests_total{service=%q,method=%q,code=\"%d\"} %d\n",
			k.service, k.method, k.code, m.requests[k])
	}

	fmt.Fprintln(w, "# HELP weistack_http_request_duration_seconds HTTP request latency.")
	fmt.Fprintln(w, "# TYPE weistack_http_request_duration_seconds histogram")
	services := make([]string, 0, len(m.latencies))
	for s := range m.latencies {
		services = append(services, s)
	}
	sort.Strings(services)
	for _, s := range services {
		h := m.latencies[s]
		var cumulative uint64
		for i, le := range latencyBuckets {
			cumulative += h.counts[i]
			fmt.Fprintf(w, "weistack_http_request_duration_seconds_bucket{service=%q,le=%q} %d\n",
				s, strconv.FormatFloat(le, 'g', -1, 64), cumulative)
		}
		cumulative += h.over
		fmt.Fprintf(w, "weistack_http_request_duration_seconds_bucket{service=%q,le=\"+Inf\"} %d\n", s, cumulative)
		fmt.Fprintf(w, "weistack_http_request_duration_seconds_sum{service=%q} %s\n",
			s, strconv.FormatFloat(h.sum, 'g', -1, 64))
		fmt.Fprintf(w, "weistack_http_request_duration_seconds_count{service=%q} %d\n", s, cumulative)
	}

	fmt.Fprintln(w, "# HELP weistack_resources Emulated resources currently stored.")
	fmt.Fprintln(w, "# TYPE weistack_resources gauge")
	kinds := make([]string, 0, len(resources))
	for k := range resources {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		fmt.Fprintf(w, "weistack_resources{kind=%q} %d\n", k, resources[k])
	}

	fmt.Fprintln(w, "# HELP weistack_lifecycle_pending_tasks State transitions waiting to run.")
	fmt.Fprintln(w, "# TYPE weistack_lifecycle_pending_tasks gauge")
	fmt.Fprintf(w, "weistack_lifecycle_pending_tasks %d\n", pendingTasks)
}
