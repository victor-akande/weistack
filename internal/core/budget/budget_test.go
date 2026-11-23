package budget

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/store"
)

func TestNilAndZeroAllowEverything(t *testing.T) {
	t.Parallel()
	for _, b := range []*Budget{nil, New(0)} {
		b.Track(func() int64 { return 1 << 40 })
		if err := b.Allow(1 << 40); err != nil {
			t.Errorf("Allow: %v", err)
		}
		var buf bytes.Buffer
		if _, err := b.Writer(&buf).Write([]byte("abc")); err != nil {
			t.Errorf("Write: %v", err)
		}
	}
}

func TestAllowAndWriter(t *testing.T) {
	t.Parallel()
	used := int64(6)
	b := New(10)
	b.Track(func() int64 { return used })
	if err := b.Allow(4); err != nil {
		t.Errorf("Allow(4) at 6 of 10: %v", err)
	}
	if err := b.Allow(5); !errors.Is(err, apierr.ErrDataFull) {
		t.Errorf("Allow(5) at 6 of 10: %v", err)
	}
	var buf bytes.Buffer
	w := b.Writer(&buf)
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	// The next byte fits; two would not, and nothing of them is written.
	if _, err := w.Write([]byte("de")); !errors.Is(err, apierr.ErrDataFull) {
		t.Fatalf("Write past the limit: %v", err)
	}
	if buf.String() != "abc" {
		t.Errorf("wrote %q", buf.String())
	}
}

func TestStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mem := store.NewMemory()
	b := New(10)
	b.Track(mem.Size)
	s := Store(mem, b)
	scope := store.Scope{Region: "r", ProjectID: "p", Kind: "k"}

	rec, err := s.Create(ctx, scope, "a", []byte("12345678"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, scope, "b", []byte("123")); !errors.Is(err, apierr.ErrDataFull) {
		t.Fatalf("Create past the limit: %v", err)
	}
	if _, err := s.Put(ctx, scope, "c", []byte("123")); !errors.Is(err, apierr.ErrDataFull) {
		t.Fatalf("Put of a new record past the limit: %v", err)
	}
	// Existing records still change, even grow, and can be deleted.
	if rec, err = s.CompareAndSwap(ctx, scope, "a", rec.Version, []byte(strings.Repeat("x", 12))); err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	if _, err := s.Put(ctx, scope, "a", []byte("1")); err != nil {
		t.Fatalf("Put of an existing record: %v", err)
	}
	if err := s.Delete(ctx, scope, "a"); err != nil {
		t.Fatal(err)
	}
	if mem.Size() != 0 {
		t.Errorf("Size after deleting everything = %d", mem.Size())
	}
	if _, err := s.Create(ctx, scope, "b", []byte("123")); err != nil {
		t.Errorf("Create once space is free: %v", err)
	}
}

func TestInternalPassesDataFullThrough(t *testing.T) {
	t.Parallel()
	e := apierr.Internal(errors.Join(errors.New("writing"), apierr.ErrDataFull))
	if e.Status != 507 || e.Code != apierr.CodeDataFull {
		t.Errorf("Internal = %d %s", e.Status, e.Code)
	}
}
