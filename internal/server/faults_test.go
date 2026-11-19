package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/faults"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

func TestFaultInjection(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	reg := faults.New(nil)
	srv, err := New(Options{
		Config: cfg, ProjectID: testProject, Logger: slog.New(slog.DiscardHandler), Store: st,
		Engine: lifecycle.New(lifecycle.Options{Faults: reg}), IDs: ids.NewSeeded(1), Faults: reg,
		Services: []Service{&fakeService{name: "vpc"}, &fakeService{name: "obs"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, target, body string) (int, string) {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}

	// Throttle the next two VPC lists.
	code, out := do(http.MethodPost, "/_weistack/faults", `{"type":"request","service":"vpc","method":"GET","path":"/v1/*/things","status":429,"times":2}`)
	if code != http.StatusCreated || !strings.Contains(out, `"id":"1"`) || !strings.Contains(out, `"remaining":2`) {
		t.Fatalf("add = %d %s", code, out)
	}
	for range 2 {
		code, out = do(http.MethodGet, "/vpc/v1/p1/things", "")
		if code != http.StatusTooManyRequests || !strings.Contains(out, `"error_code":"APIGW.0308"`) || !strings.Contains(out, `"request_id"`) {
			t.Errorf("throttled = %d %s", code, out)
		}
	}
	if code, _ = do(http.MethodGet, "/vpc/v1/p1/things", ""); code != http.StatusOK {
		t.Errorf("after the fault = %d", code)
	}

	// OBS's error, a custom one, and a delay alone.
	do(http.MethodPost, "/_weistack/faults", `{"type":"request","service":"obs","status":503}`)
	if code, out = do(http.MethodGet, "/obs/v1/p1/things", ""); code != 503 || !strings.Contains(out, "<Code>SlowDown</Code>") {
		t.Errorf("OBS = %d %s", code, out)
	}
	do(http.MethodPost, "/_weistack/faults", `{"type":"request","service":"vpc","status":500,"code":"VPC.0001","message":"boom"}`)
	if code, out = do(http.MethodGet, "/vpc/v1/p1/things", ""); code != 500 || !strings.Contains(out, `"error_code":"VPC.0001"`) || !strings.Contains(out, "boom") {
		t.Errorf("custom = %d %s", code, out)
	}
	do(http.MethodPost, "/_weistack/faults", `{"type":"request","service":"vpc","status":502}`)
	if _, out = do(http.MethodGet, "/vpc/v1/p1/things", ""); !strings.Contains(out, `"error_code":"WeiStack.0502"`) {
		t.Errorf("default code = %s", out)
	}
	do(http.MethodPost, "/_weistack/faults", `{"type":"request","service":"vpc","delay_ms":60}`)
	start := time.Now()
	if code, _ = do(http.MethodGet, "/vpc/v1/p1/things", ""); code != http.StatusOK || time.Since(start) < 60*time.Millisecond {
		t.Errorf("delay = %d after %v", code, time.Since(start))
	}

	// Listing, removing, clearing, and a reset.
	do(http.MethodPost, "/_weistack/faults", `{"type":"lifecycle","transition":"ecs.server.build","times":0}`)
	if code, out = do(http.MethodGet, "/_weistack/faults", ""); code != 200 || strings.Count(out, `"type"`) != 1 {
		t.Errorf("list = %d %s", code, out)
	}
	if reg.Fault("ecs.server.build", "s") == nil {
		t.Error("the lifecycle fault does not reach the engine's injector")
	}
	if code, _ = do(http.MethodDelete, "/_weistack/faults/6", ""); code != http.StatusNoContent {
		t.Errorf("remove = %d", code)
	}
	if code, _ = do(http.MethodDelete, "/_weistack/faults/6", ""); code != http.StatusNotFound {
		t.Errorf("remove again = %d", code)
	}
	do(http.MethodPost, "/_weistack/faults", `{"type":"lifecycle","transition":"*"}`)
	if code, _ = do(http.MethodDelete, "/_weistack/faults", ""); code != http.StatusNoContent || len(reg.List()) != 0 {
		t.Errorf("clear = %d", code)
	}
	do(http.MethodPost, "/_weistack/faults", `{"type":"lifecycle","transition":"*"}`)
	if code, _ = do(http.MethodPost, "/_weistack/reset", ""); code != 200 || len(reg.List()) != 0 {
		t.Errorf("reset kept the faults: %d", code)
	}

	for _, body := range []string{
		`nope`, `{"type":"request","service":"kms","status":500}`, `{"type":"request","service":"vpc"}`,
		`{"type":"lifecycle","transition":"*","id":"9"}`, `{"type":"lifecycle","transition":"*","extra":1}`,
	} {
		if code, out = do(http.MethodPost, "/_weistack/faults", body); code != http.StatusBadRequest || !strings.Contains(out, "WeiStack.0400") {
			t.Errorf("%s = %d %s", body, code, out)
		}
	}
}
