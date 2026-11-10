// Package lifecycle runs the delayed state transitions that make emulated
// resources behave like real ones: a server that is BUILD for a moment
// before it turns ACTIVE, an asynchronous job that later reports SUCCESS.
//
// One goroutine drains a timer heap. There is no goroutine or timer per
// resource, so ten thousand pending transitions cost ten thousand small
// heap entries and nothing else.
package lifecycle

import (
	"container/heap"
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// Task is one deferred piece of work.
type Task struct {
	// Key groups tasks for Cancel. Use the resource ID, so deleting a
	// resource cancels its pending transitions.
	Key string
	// Kind names the transition, for example "ecs.server.build". It is
	// logged and is what a FaultInjector matches on.
	Kind string
	// Run performs the transition. fault is non-nil when a FaultInjector
	// asked for this transition to fail; Run should then move the
	// resource to its error state instead. Run executes on the engine's
	// goroutine and must not block for long.
	Run func(ctx context.Context, fault error)
}

// FaultInjector lets a test or a teaching scenario force transitions to
// fail. It is consulted once per task, just before the task runs.
type FaultInjector interface {
	// Fault returns the error to inject into the task, or nil.
	Fault(kind, key string) error
}

// Options configures an Engine. The zero value is usable.
type Options struct {
	// Delay is how long Schedule waits before running a task. Zero runs
	// tasks as soon as the engine gets to them.
	Delay time.Duration
	// Clock defaults to SystemClock.
	Clock Clock
	// Logger defaults to slog.Default.
	Logger *slog.Logger
	// Faults is optional.
	Faults FaultInjector
}

// Engine schedules and runs Tasks. Create one with New and start it with
// Run. All methods are safe for concurrent use.
type Engine struct {
	delay  time.Duration
	clock  Clock
	log    *slog.Logger
	faults FaultInjector

	mu      sync.Mutex
	queue   taskHeap
	seq     uint64
	running bool
	// changed is closed and replaced whenever the engine may have become
	// idle, waking WaitIdle callers.
	changed chan struct{}
	// wake nudges the run loop when the head of the queue may have changed.
	wake chan struct{}
}

// New returns an Engine. It does nothing until Run is called.
func New(opts Options) *Engine {
	e := &Engine{
		delay:   opts.Delay,
		clock:   opts.Clock,
		log:     opts.Logger,
		faults:  opts.Faults,
		changed: make(chan struct{}),
		wake:    make(chan struct{}, 1),
	}
	if e.clock == nil {
		e.clock = SystemClock{}
	}
	if e.log == nil {
		e.log = slog.Default()
	}
	return e
}

// Delay returns the configured transition delay.
func (e *Engine) Delay() time.Duration { return e.delay }

// Schedule runs t after the configured delay.
func (e *Engine) Schedule(t Task) { e.ScheduleAfter(e.delay, t) }

// ScheduleAfter runs t after d. Tasks due at the same instant run in the
// order they were scheduled.
func (e *Engine) ScheduleAfter(d time.Duration, t Task) {
	if t.Run == nil {
		panic("lifecycle: Task.Run is nil")
	}
	if d < 0 {
		d = 0
	}
	e.mu.Lock()
	e.seq++
	heap.Push(&e.queue, &item{task: t, at: e.clock.Now().Add(d), seq: e.seq})
	e.mu.Unlock()

	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Cancel drops every pending task with the given key and returns how many
// were dropped. A task that is already running is not interrupted.
func (e *Engine) Cancel(key string) int {
	return e.cancel(func(t Task) bool { return t.Key == key })
}

// CancelAll drops every pending task and returns how many were dropped.
func (e *Engine) CancelAll() int {
	return e.cancel(func(Task) bool { return true })
}

func (e *Engine) cancel(match func(Task) bool) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	kept := e.queue[:0]
	dropped := 0
	for _, it := range e.queue {
		if match(it.task) {
			dropped++
			continue
		}
		kept = append(kept, it)
	}
	clear(e.queue[len(kept):])
	e.queue = kept
	heap.Init(&e.queue)
	if dropped > 0 {
		e.notifyLocked()
	}
	return dropped
}

// Pending returns the number of tasks waiting to run.
func (e *Engine) Pending() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.queue)
}

// WaitIdle blocks until no task is running and none is due at the current
// clock time, or until ctx is done. Tasks scheduled for the future do not
// keep it waiting. With a zero Delay (or after advancing a FakeClock) it
// is the way for a test to wait for transitions to finish.
func (e *Engine) WaitIdle(ctx context.Context) error {
	for {
		e.mu.Lock()
		idle := !e.running && (len(e.queue) == 0 || e.queue[0].at.After(e.clock.Now()))
		changed := e.changed
		e.mu.Unlock()
		if idle {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("lifecycle: waiting for idle: %w", ctx.Err())
		case <-changed:
		}
	}
}

// notifyLocked wakes WaitIdle callers. The caller must hold e.mu.
func (e *Engine) notifyLocked() {
	close(e.changed)
	e.changed = make(chan struct{})
}

// Run executes tasks as they fall due until ctx is cancelled. Tasks still
// pending at that point are left unrun. Run must be called at most once.
func (e *Engine) Run(ctx context.Context) {
	for {
		e.mu.Lock()
		if len(e.queue) > 0 && !e.queue[0].at.After(e.clock.Now()) {
			it, _ := heap.Pop(&e.queue).(*item)
			e.running = true
			e.mu.Unlock()

			e.exec(ctx, it.task)

			e.mu.Lock()
			e.running = false
			e.notifyLocked()
			e.mu.Unlock()

			if ctx.Err() != nil {
				return
			}
			continue
		}

		// Nothing is due: sleep until the next deadline, a new task, or
		// shutdown.
		var (
			timer Timer
			fire  <-chan time.Time
		)
		if len(e.queue) > 0 {
			timer = e.clock.NewTimerAt(e.queue[0].at)
			fire = timer.C()
		}
		e.mu.Unlock()

		select {
		case <-ctx.Done():
		case <-e.wake:
		case <-fire:
		}
		if timer != nil {
			timer.Stop()
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// exec runs one task, containing panics so a bug in one transition cannot
// take down every other resource's lifecycle.
func (e *Engine) exec(ctx context.Context, t Task) {
	defer func() {
		if r := recover(); r != nil {
			e.log.ErrorContext(ctx, "lifecycle task panicked",
				"kind", t.Kind, "key", t.Key, "panic", r, "stack", string(debug.Stack()))
		}
	}()

	var fault error
	if e.faults != nil {
		fault = e.faults.Fault(t.Kind, t.Key)
	}
	e.log.DebugContext(ctx, "lifecycle transition", "kind", t.Kind, "key", t.Key, "fault", fault != nil)
	t.Run(ctx, fault)
}

type item struct {
	task Task
	at   time.Time
	seq  uint64
}

// taskHeap orders items by due time, then by scheduling order.
type taskHeap []*item

func (h taskHeap) Len() int { return len(h) }
func (h taskHeap) Less(i, j int) bool {
	if h[i].at.Equal(h[j].at) {
		return h[i].seq < h[j].seq
	}
	return h[i].at.Before(h[j].at)
}
func (h taskHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

// Push implements heap.Interface.
func (h *taskHeap) Push(x any) {
	it, _ := x.(*item)
	*h = append(*h, it)
}

// Pop implements heap.Interface.
func (h *taskHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return it
}
