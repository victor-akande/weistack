package lifecycle

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// start runs an engine for the duration of the test.
func start(t *testing.T, opts Options) *Engine {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	e := New(opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("engine did not stop after its context was cancelled")
		}
	})
	return e
}

func waitIdle(t *testing.T, e *Engine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

// recorder collects the order tasks ran in.
type recorder struct {
	mu  sync.Mutex
	got []string
}

func (r *recorder) task(key, kind, label string) Task {
	return Task{Key: key, Kind: kind, Run: func(context.Context, error) { r.add(label) }}
}

func (r *recorder) add(label string) {
	r.mu.Lock()
	r.got = append(r.got, label)
	r.mu.Unlock()
}

func (r *recorder) labels() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.got...)
}

func TestZeroDelayRunsImmediately(t *testing.T) {
	t.Parallel()

	e := start(t, Options{})
	var rec recorder
	e.Schedule(rec.task("srv-1", "ecs.server.build", "built"))
	waitIdle(t, e)

	if got := rec.labels(); !reflect.DeepEqual(got, []string{"built"}) {
		t.Fatalf("ran %v, want [built]", got)
	}
	if e.Pending() != 0 {
		t.Fatalf("Pending() = %d, want 0", e.Pending())
	}
}

func TestTasksWaitForTheirDelay(t *testing.T) {
	t.Parallel()

	clock := NewFakeClock(epoch)
	e := start(t, Options{Delay: 2 * time.Second, Clock: clock})
	var rec recorder

	if e.Delay() != 2*time.Second {
		t.Fatalf("Delay() = %s", e.Delay())
	}
	e.Schedule(rec.task("a", "k", "a"))
	waitIdle(t, e) // returns at once: nothing is due yet
	if got := rec.labels(); len(got) != 0 {
		t.Fatalf("task ran before its delay: %v", got)
	}

	clock.Advance(1999 * time.Millisecond)
	waitIdle(t, e)
	if got := rec.labels(); len(got) != 0 {
		t.Fatalf("task ran 1ms early: %v", got)
	}

	clock.Advance(time.Millisecond)
	waitIdle(t, e)
	if got := rec.labels(); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("ran %v, want [a]", got)
	}
}

func TestOrderIsByDueTimeThenFIFO(t *testing.T) {
	t.Parallel()

	clock := NewFakeClock(epoch)
	e := start(t, Options{Clock: clock})
	var rec recorder

	e.ScheduleAfter(3*time.Second, rec.task("", "", "late"))
	e.ScheduleAfter(1*time.Second, rec.task("", "", "early-1"))
	e.ScheduleAfter(1*time.Second, rec.task("", "", "early-2"))
	e.ScheduleAfter(1*time.Second, rec.task("", "", "early-3"))
	e.ScheduleAfter(2*time.Second, rec.task("", "", "middle"))
	e.ScheduleAfter(-time.Hour, rec.task("", "", "negative-is-now"))

	clock.Advance(10 * time.Second)
	waitIdle(t, e)

	want := []string{"negative-is-now", "early-1", "early-2", "early-3", "middle", "late"}
	if got := rec.labels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ran %v\nwant %v", got, want)
	}
}

// A transition can schedule the next one: REBOOT -> ACTIVE, or
// queued -> saving -> active.
func TestTasksCanChain(t *testing.T) {
	t.Parallel()

	clock := NewFakeClock(epoch)
	e := start(t, Options{Delay: time.Second, Clock: clock})
	var rec recorder

	e.Schedule(Task{Key: "img", Kind: "ims.image.save", Run: func(context.Context, error) {
		rec.add("saving")
		e.Schedule(rec.task("img", "ims.image.activate", "active"))
	}})

	clock.Advance(time.Second)
	waitIdle(t, e)
	if got := rec.labels(); !reflect.DeepEqual(got, []string{"saving"}) {
		t.Fatalf("after 1s ran %v, want [saving]", got)
	}

	clock.Advance(time.Second)
	waitIdle(t, e)
	if got := rec.labels(); !reflect.DeepEqual(got, []string{"saving", "active"}) {
		t.Fatalf("after 2s ran %v, want [saving active]", got)
	}
}

func TestCancel(t *testing.T) {
	t.Parallel()

	clock := NewFakeClock(epoch)
	e := start(t, Options{Delay: time.Second, Clock: clock})
	var rec recorder

	e.Schedule(rec.task("srv-1", "k", "srv-1 a"))
	e.Schedule(rec.task("srv-2", "k", "srv-2"))
	e.Schedule(rec.task("srv-1", "k", "srv-1 b"))

	if n := e.Cancel("srv-1"); n != 2 {
		t.Fatalf("Cancel returned %d, want 2", n)
	}
	if n := e.Cancel("srv-1"); n != 0 {
		t.Fatalf("second Cancel returned %d, want 0", n)
	}
	if e.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1", e.Pending())
	}

	clock.Advance(time.Second)
	waitIdle(t, e)
	if got := rec.labels(); !reflect.DeepEqual(got, []string{"srv-2"}) {
		t.Fatalf("ran %v, want only [srv-2]", got)
	}
}

func TestCancelAll(t *testing.T) {
	t.Parallel()

	clock := NewFakeClock(epoch)
	e := start(t, Options{Delay: time.Second, Clock: clock})
	var rec recorder

	for range 5 {
		e.Schedule(rec.task("x", "k", "x"))
	}
	if n := e.CancelAll(); n != 5 {
		t.Fatalf("CancelAll returned %d, want 5", n)
	}
	clock.Advance(time.Minute)
	waitIdle(t, e)
	if got := rec.labels(); len(got) != 0 {
		t.Fatalf("cancelled tasks ran: %v", got)
	}

	// The engine keeps working after a reset.
	e.Schedule(rec.task("y", "k", "y"))
	clock.Advance(time.Second)
	waitIdle(t, e)
	if got := rec.labels(); !reflect.DeepEqual(got, []string{"y"}) {
		t.Fatalf("ran %v, want [y]", got)
	}
}

func TestPanicIsContained(t *testing.T) {
	t.Parallel()

	var logs strings.Builder
	var mu sync.Mutex
	logger := slog.New(slog.NewTextHandler(lockedWriter{&mu, &logs}, nil))
	e := start(t, Options{Logger: logger})
	var rec recorder

	e.Schedule(Task{Key: "bad", Kind: "ecs.server.build", Run: func(context.Context, error) { panic("boom") }})
	e.Schedule(rec.task("good", "k", "survived"))
	waitIdle(t, e)

	if got := rec.labels(); !reflect.DeepEqual(got, []string{"survived"}) {
		t.Fatalf("ran %v, want the task after the panic to run", got)
	}
	mu.Lock()
	out := logs.String()
	mu.Unlock()
	for _, sub := range []string{"panicked", "boom", "ecs.server.build", "key=bad"} {
		if !strings.Contains(out, sub) {
			t.Errorf("panic log does not mention %q:\n%s", sub, out)
		}
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

type faultOn struct{ kind string }

var errInjected = errors.New("injected failure")

func (f faultOn) Fault(kind, _ string) error {
	if kind == f.kind {
		return errInjected
	}
	return nil
}

func TestFaultInjection(t *testing.T) {
	t.Parallel()

	e := start(t, Options{Faults: faultOn{kind: "ecs.server.build"}})

	var mu sync.Mutex
	faults := map[string]error{}
	record := func(kind string) Task {
		return Task{Key: "srv", Kind: kind, Run: func(_ context.Context, fault error) {
			mu.Lock()
			faults[kind] = fault
			mu.Unlock()
		}}
	}
	e.Schedule(record("ecs.server.build"))
	e.Schedule(record("ecs.server.stop"))
	waitIdle(t, e)

	mu.Lock()
	defer mu.Unlock()
	if !errors.Is(faults["ecs.server.build"], errInjected) {
		t.Errorf("targeted task got fault %v, want the injected error", faults["ecs.server.build"])
	}
	if faults["ecs.server.stop"] != nil {
		t.Errorf("untargeted task got fault %v, want nil", faults["ecs.server.stop"])
	}
}

func TestWaitIdleHonoursContext(t *testing.T) {
	t.Parallel()

	// The engine is never started, so a due task can never run.
	e := New(Options{})
	e.Schedule(Task{Run: func(context.Context, error) {}})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := e.WaitIdle(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitIdle: err = %v, want deadline exceeded", err)
	}
}

func TestRunStopsOnCancelAndLeavesPendingTasks(t *testing.T) {
	t.Parallel()

	e := New(Options{Delay: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ran := false
	e.Schedule(Task{Run: func(context.Context, error) { ran = true }})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.Run(ctx) }()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if ran {
		t.Fatal("a task due in an hour ran at shutdown")
	}
	if e.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1", e.Pending())
	}
}

func TestSystemClockFiresTimers(t *testing.T) {
	t.Parallel()

	e := start(t, Options{Delay: 10 * time.Millisecond})
	done := make(chan struct{})
	began := time.Now()
	e.Schedule(Task{Run: func(context.Context, error) { close(done) }})

	select {
	case <-done:
		if elapsed := time.Since(began); elapsed < 10*time.Millisecond {
			t.Fatalf("task ran after %s, before its 10ms delay", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("task never ran on the system clock")
	}
}

func TestConcurrentScheduling(t *testing.T) {
	t.Parallel()

	const workers, each = 20, 50
	e := start(t, Options{})

	var (
		mu    sync.Mutex
		count int
		wg    sync.WaitGroup
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				e.Schedule(Task{Run: func(context.Context, error) {
					mu.Lock()
					count++
					mu.Unlock()
				}})
			}
		}()
	}
	wg.Wait()
	waitIdle(t, e)

	mu.Lock()
	defer mu.Unlock()
	if count != workers*each {
		t.Fatalf("%d tasks ran, want %d", count, workers*each)
	}
}

func TestNilRunPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("scheduling a task without Run did not panic")
		}
	}()
	New(Options{}).Schedule(Task{Key: "x"})
}

func TestFakeClock(t *testing.T) {
	t.Parallel()

	clock := NewFakeClock(epoch)
	if !clock.Now().Equal(epoch) {
		t.Fatalf("Now() = %s, want %s", clock.Now(), epoch)
	}

	past := clock.NewTimerAt(epoch.Add(-time.Second))
	select {
	case <-past.C():
	default:
		t.Fatal("timer for a past deadline did not fire immediately")
	}

	future := clock.NewTimerAt(epoch.Add(time.Minute))
	stopped := clock.NewTimerAt(epoch.Add(time.Minute))
	stopped.Stop()

	clock.Advance(59 * time.Second)
	select {
	case <-future.C():
		t.Fatal("timer fired early")
	default:
	}

	clock.Advance(time.Second)
	select {
	case at := <-future.C():
		if !at.Equal(epoch.Add(time.Minute)) {
			t.Fatalf("timer fired at %s", at)
		}
	default:
		t.Fatal("timer did not fire at its deadline")
	}
	select {
	case <-stopped.C():
		t.Fatal("stopped timer fired")
	default:
	}
}

func BenchmarkScheduleAndRun(b *testing.B) {
	e := New(Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	noop := Task{Run: func(context.Context, error) {}}
	for b.Loop() {
		e.Schedule(noop)
	}
	if err := e.WaitIdle(ctx); err != nil {
		b.Fatal(err)
	}
}
