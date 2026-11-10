package lifecycle

import (
	"sync"
	"time"
)

// Clock abstracts time so tests can drive the engine deterministically.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// NewTimerAt returns a timer that fires once the clock reaches
	// deadline. Timers take an absolute deadline rather than a duration
	// so that a clock advancing between Now and NewTimerAt cannot delay
	// the timer.
	NewTimerAt(deadline time.Time) Timer
}

// Timer is a single-shot timer.
type Timer interface {
	// C delivers one value when the timer fires.
	C() <-chan time.Time
	// Stop releases the timer.
	Stop()
}

// SystemClock is the real wall clock.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// NewTimerAt implements Clock.
func (SystemClock) NewTimerAt(deadline time.Time) Timer {
	return systemTimer{t: time.NewTimer(time.Until(deadline))}
}

type systemTimer struct{ t *time.Timer }

func (s systemTimer) C() <-chan time.Time { return s.t.C }
func (s systemTimer) Stop()               { s.t.Stop() }

// FakeClock is a manually advanced Clock for tests. Time only moves when
// Advance is called.
type FakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*fakeTimer]struct{}
}

// NewFakeClock returns a FakeClock set to start.
func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{now: start, timers: make(map[*fakeTimer]struct{})}
}

// Now implements Clock.
func (f *FakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// NewTimerAt implements Clock.
func (f *FakeClock) NewTimerAt(deadline time.Time) Timer {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTimer{clock: f, deadline: deadline, ch: make(chan time.Time, 1)}
	if !deadline.After(f.now) {
		t.ch <- f.now
		return t
	}
	f.timers[t] = struct{}{}
	return t
}

// Advance moves the clock forward by d and fires every timer that is due.
func (f *FakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	for t := range f.timers {
		if !t.deadline.After(f.now) {
			t.ch <- f.now
			delete(f.timers, t)
		}
	}
}

type fakeTimer struct {
	clock    *FakeClock
	deadline time.Time
	ch       chan time.Time
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	delete(t.clock.timers, t)
}
