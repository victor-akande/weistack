package store

import (
	"context"
	"sort"
	"sync"
)

// Memory is an in-process Store. State is lost when the process exits.
type Memory struct {
	mu     sync.RWMutex
	scopes map[string]map[string]*memEntry
	seq    uint64
	closed bool
}

type memEntry struct {
	seq     uint64
	version uint64
	data    []byte
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{scopes: make(map[string]map[string]*memEntry)}
}

var _ Store = (*Memory)(nil)

func (e *memEntry) record(id string) Record {
	return Record{ID: id, Version: e.version, Seq: e.seq, Data: clone(e.data)}
}

// ready validates the call. The caller must hold m.mu.
func (m *Memory) ready(ctx context.Context, scope Scope) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if m.closed {
		return "", ErrClosed
	}
	return scope.key()
}

// Get implements Store.
func (m *Memory) Get(ctx context.Context, scope Scope, id string) (Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, err := m.ready(ctx, scope)
	if err != nil {
		return Record{}, err
	}
	e, ok := m.scopes[key][id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return e.record(id), nil
}

// List implements Store.
func (m *Memory) List(ctx context.Context, scope Scope) ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, err := m.ready(ctx, scope)
	if err != nil {
		return nil, err
	}
	return sortedRecords(m.scopes[key]), nil
}

func sortedRecords(entries map[string]*memEntry) []Record {
	out := make([]Record, 0, len(entries))
	for id, e := range entries {
		out = append(out, e.record(id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// Create implements Store.
func (m *Memory) Create(ctx context.Context, scope Scope, id string, data []byte) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.ready(ctx, scope)
	if err != nil {
		return Record{}, err
	}
	if _, ok := m.scopes[key][id]; ok {
		return Record{}, ErrExists
	}
	return m.insert(key, id, data), nil
}

// Put implements Store.
func (m *Memory) Put(ctx context.Context, scope Scope, id string, data []byte) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.ready(ctx, scope)
	if err != nil {
		return Record{}, err
	}
	if e, ok := m.scopes[key][id]; ok {
		e.version++
		e.data = clone(data)
		return e.record(id), nil
	}
	return m.insert(key, id, data), nil
}

// insert adds a new entry. The caller must hold the write lock.
func (m *Memory) insert(key, id string, data []byte) Record {
	if m.scopes[key] == nil {
		m.scopes[key] = make(map[string]*memEntry)
	}
	m.seq++
	e := &memEntry{seq: m.seq, version: 1, data: clone(data)}
	m.scopes[key][id] = e
	return e.record(id)
}

// CompareAndSwap implements Store.
func (m *Memory) CompareAndSwap(ctx context.Context, scope Scope, id string, version uint64, data []byte) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.ready(ctx, scope)
	if err != nil {
		return Record{}, err
	}
	e, ok := m.scopes[key][id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if e.version != version {
		return Record{}, ErrConflict
	}
	e.version++
	e.data = clone(data)
	return e.record(id), nil
}

// Delete implements Store.
func (m *Memory) Delete(ctx context.Context, scope Scope, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.ready(ctx, scope)
	if err != nil {
		return err
	}
	if _, ok := m.scopes[key][id]; !ok {
		return ErrNotFound
	}
	delete(m.scopes[key], id)
	if len(m.scopes[key]) == 0 {
		delete(m.scopes, key)
	}
	return nil
}

// Reset implements Store.
func (m *Memory) Reset(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.closed {
		return ErrClosed
	}
	m.scopes = make(map[string]map[string]*memEntry)
	return nil
}

// Dump implements Store.
func (m *Memory) Dump(ctx context.Context) (map[string][]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.closed {
		return nil, ErrClosed
	}
	out := make(map[string][]Record, len(m.scopes))
	for key, entries := range m.scopes {
		out[key] = sortedRecords(entries)
	}
	return out, nil
}

// Close implements Store. It is safe to call more than once.
func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.scopes = nil
	return nil
}
