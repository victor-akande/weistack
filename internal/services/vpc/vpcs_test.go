package vpc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

const testUnknownID = "00000000-0000-4000-8000-000000000000"

func timeEqual(got Time, want time.Time) bool { return time.Time(got).Equal(want) }

func codeOf(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestCheckVPCCIDR(t *testing.T) {
	t.Parallel()

	valid := []string{
		"10.0.0.0/8", "10.0.0.0/24", "172.16.0.0/12", "172.31.255.0/24",
		"192.168.0.0/16", "192.168.10.0/24", "8.0.0.0/8", "100.128.0.0/16",
	}
	for _, cidr := range valid {
		if err := checkVPCCIDR(cidr); err != nil {
			t.Errorf("checkVPCCIDR(%q): %v", cidr, err)
		}
	}

	invalid := map[string]string{
		"":                    "not in CIDR format",
		"10.0.0.0":            "not in CIDR format",
		"10.0.0.0/33":         "not in CIDR format",
		"abc/8":               "not in CIDR format",
		"10.0.0.1/8":          "host bits",
		"192.168.1.0/16":      "host bits",
		"10.0.0.0/25":         "between 8 and 24",
		"10.0.0.0/7":          "between 8 and 24",
		"0.0.0.0/8":           "reserved range 0.0.0.0/8",
		"100.64.0.0/10":       "reserved range 100.64.0.0/10",
		"100.100.0.0/16":      "reserved range 100.64.0.0/10",
		"127.0.0.0/8":         "reserved range 127.0.0.0/8",
		"169.254.0.0/16":      "reserved range 169.254.0.0/16",
		"198.18.0.0/15":       "reserved range 198.18.0.0/15",
		"214.0.0.0/8":         "reserved range 214.0.0.0/7",
		"240.0.0.0/8":         "reserved range 240.0.0.0/4",
		"fd00::/8":            "not an IPv4",
		"::ffff:10.0.0.0/104": "not an IPv4",
	}
	for cidr, wantSub := range invalid {
		err := checkVPCCIDR(cidr)
		if err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("checkVPCCIDR(%q): err = %v, want it to mention %q", cidr, err, wantSub)
		}
	}
}

func TestCheckNameAndDescription(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"a", "vpc-1", "my_vpc.prod", "网络", strings.Repeat("x", 64), strings.Repeat("网", 64)} {
		if err := checkName(name, false); err != nil {
			t.Errorf("checkName(%q): %v", name, err)
		}
	}
	for _, name := range []string{"a b", "a/b", "a@b", "<a>", strings.Repeat("x", 65)} {
		if err := checkName(name, true); err == nil {
			t.Errorf("checkName(%q) accepted an invalid name", name)
		}
	}
	if err := checkName("", true); err != nil {
		t.Errorf("empty name rejected where allowed: %v", err)
	}
	if err := checkName("", false); err == nil {
		t.Error("empty name accepted where required")
	}

	if err := checkDescription(strings.Repeat("d", 255) + ""); err != nil {
		t.Errorf("255-character description rejected: %v", err)
	}
	for _, desc := range []string{strings.Repeat("d", 256), "a < b", "a > b"} {
		if err := checkDescription(desc); err == nil {
			t.Errorf("checkDescription(%q) accepted an invalid description", desc)
		}
	}
}

func TestVPCStatusTransitions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()

	v, err := e.svc.CreateVPC(ctx, testTenant, CreateVPCOption{Name: ptr("a")})
	if err != nil {
		t.Fatalf("CreateVPC: %v", err)
	}
	if v.Status != VPCStatusCreating {
		t.Fatalf("new VPC status = %q, want CREATING", v.Status)
	}

	// Not before the delay has fully elapsed.
	e.clock.Advance(testDelay - time.Millisecond)
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.GetVPC(ctx, testTenant, v.ID); got.Status != VPCStatusCreating {
		t.Fatalf("status before the delay = %q, want CREATING", got.Status)
	}

	e.clock.Advance(time.Millisecond)
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.GetVPC(ctx, testTenant, v.ID); got.Status != VPCStatusOK {
		t.Fatalf("status after the delay = %q, want OK", got.Status)
	}
}

type failKind string

func (f failKind) Fault(kind, _ string) error {
	if kind == string(f) {
		return errors.New("injected")
	}
	return nil
}

func TestVPCCreationFaultLeadsToErrorStatus(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := lifecycle.New(lifecycle.Options{Logger: log, Faults: failKind(taskVPCCreate)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Run(ctx)

	svc, err := New(Deps{Store: store.NewMemory(), Engine: engine, IDs: ids.New(), Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	v, err := svc.CreateVPC(ctx, testTenant, CreateVPCOption{})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.GetVPC(ctx, testTenant, v.ID); got.Status != VPCStatusError {
		t.Fatalf("status = %q, want ERROR after an injected fault", got.Status)
	}
}

func TestDeletingAVPCCancelsItsPendingTransition(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()

	v, err := e.svc.CreateVPC(ctx, testTenant, CreateVPCOption{})
	if err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	if err := e.svc.DeleteVPC(ctx, testTenant, v.ID); err != nil {
		t.Fatalf("DeleteVPC: %v", err)
	}
	if n := e.engine.Pending(); n != 0 {
		t.Fatalf("%d lifecycle tasks pending after delete", n)
	}
	if err := e.svc.DeleteVPC(ctx, testTenant, v.ID); codeOf(err) != "VPC.0105" {
		t.Fatalf("second delete: %v, want VPC.0105", err)
	}
}

// Two clients racing to create the same name: exactly one must win.
func TestConcurrentCreatesWithOneNameYieldOneVPC(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()

	const workers = 50
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		ok, dups int
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.CreateVPC(ctx, testTenant, CreateVPCOption{Name: ptr("only-one")})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case codeOf(err) == "VPC.0115":
				dups++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || dups != workers-1 {
		t.Fatalf("%d creates succeeded and %d were rejected, want 1 and %d", ok, dups, workers-1)
	}
}

func TestResumeFinishesInterruptedCreates(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "weistack.db")
	st, err := store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}

	// First run: create a VPC and stop before it leaves CREATING.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	idle := lifecycle.New(lifecycle.Options{Delay: time.Hour, Logger: log})
	first, err := New(Deps{Store: st, Engine: idle, IDs: ids.New(), Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	stuck, err := first.CreateVPC(t.Context(), testTenant, CreateVPCOption{Name: ptr("stuck")})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Second run on the same data.
	st, err = store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWithStore(t, st)
	if err := e.svc.Resume(t.Context()); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	e.settle(t)

	got, err := e.svc.GetVPC(t.Context(), testTenant, stuck.ID)
	if err != nil {
		t.Fatalf("GetVPC: %v", err)
	}
	if got.Status != VPCStatusOK {
		t.Fatalf("status after restart = %q, want OK", got.Status)
	}
}

func TestResumeReportsCorruptRecords(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	scope := store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindVPC}
	if _, err := e.store.Put(t.Context(), scope, "bad", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Resume(t.Context()); err == nil {
		t.Fatal("Resume ignored a corrupt record")
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	t.Parallel()
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New succeeded without dependencies")
	}
}

func TestTimeJSON(t *testing.T) {
	t.Parallel()

	in := Time(time.Date(2022, 12, 15, 2, 25, 11, 0, time.UTC))
	b, err := in.MarshalJSON()
	if err != nil || string(b) != `"2022-12-15T02:25:11"` {
		t.Fatalf("MarshalJSON = %s, %v", b, err)
	}
	var out Time
	if err := out.UnmarshalJSON(b); err != nil || !timeEqual(out, time.Time(in)) {
		t.Fatalf("round trip = %v, %v", time.Time(out), err)
	}
	for _, bad := range []string{`5`, `"yesterday"`, `"2022-12-15T02:25:11Z"`, `"`} {
		if err := out.UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("UnmarshalJSON(%s) succeeded", bad)
		}
	}
}
