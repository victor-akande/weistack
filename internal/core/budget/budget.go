// Package budget limits how much data WeiStack keeps (-max-data-bytes):
// stored records, on disk or in memory, and object data. Once the limit
// is reached, writes that would add data are refused with
// apierr.ErrDataFull; reads and deletes go on, so space can be freed.
// The limit is approximate: it is checked before each write and while
// objects stream in, not under one lock.
package budget

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Budget is a limit on the bytes its sources report. A nil Budget, or a
// zero limit, allows everything.
type Budget struct {
	max int64

	mu      sync.Mutex
	sources []func() int64
}

// New returns a budget of max bytes; 0 means none.
func New(limit int64) *Budget { return &Budget{max: limit} }

// Track adds a source of used bytes.
func (b *Budget) Track(used func() int64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sources = append(b.sources, used)
}

// Used returns the bytes every source reports.
func (b *Budget) Used() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	sources := append([]func() int64(nil), b.sources...)
	b.mu.Unlock()
	var n int64
	for _, s := range sources {
		n += s()
	}
	return n
}

// Max returns the limit, 0 for none.
func (b *Budget) Max() int64 {
	if b == nil {
		return 0
	}
	return b.max
}

// Allow returns apierr.ErrDataFull when adding more bytes would pass the
// limit.
func (b *Budget) Allow(more int64) error {
	if b == nil || b.max <= 0 || b.Used()+more <= b.max {
		return nil
	}
	return apierr.ErrDataFull
}

// Writer counts what passes through w against the budget, and fails
// with apierr.ErrDataFull as soon as it would pass the limit, before
// writing those bytes.
func (b *Budget) Writer(w io.Writer) io.Writer {
	if b == nil || b.max <= 0 {
		return w
	}
	return &writer{w: w, b: b, base: b.Used()}
}

type writer struct {
	w       io.Writer
	b       *Budget
	base    int64 // used when the write began
	written int64
}

func (w *writer) Write(p []byte) (int, error) {
	if w.base+w.written+int64(len(p)) > w.b.max {
		return 0, apierr.ErrDataFull
	}
	n, err := w.w.Write(p)
	w.written += int64(n)
	return n, err
}

// Store returns s with new records refused once the budget is spent.
// Changes to existing records always pass, however they grow: services
// move resources through their states, deletion included, by changing
// them, and a full WeiStack must still let its data be deleted.
func Store(s store.Store, b *Budget) store.Store {
	if b == nil || b.max <= 0 {
		return s
	}
	return &limited{Store: s, b: b}
}

type limited struct {
	store.Store
	b *Budget
}

func (l *limited) Create(ctx context.Context, scope store.Scope, id string, data []byte) (store.Record, error) {
	if err := l.b.Allow(int64(len(data))); err != nil {
		return store.Record{}, err
	}
	return l.Store.Create(ctx, scope, id, data)
}

// Put is refused only when it would add a record.
func (l *limited) Put(ctx context.Context, scope store.Scope, id string, data []byte) (store.Record, error) {
	if _, err := l.Get(ctx, scope, id); errors.Is(err, store.ErrNotFound) {
		if err := l.b.Allow(int64(len(data))); err != nil {
			return store.Record{}, err
		}
	}
	return l.Store.Put(ctx, scope, id, data)
}
