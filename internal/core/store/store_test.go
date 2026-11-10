package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

var (
	ctx   = context.Background()
	scope = Scope{Region: "ap-southeast-1", ProjectID: "0123456789abcdef0123456789abcdef", Kind: "vpc"}
)

// implementations lists every Store so the contract tests cover them all.
func implementations() map[string]func(t *testing.T) Store {
	return map[string]func(t *testing.T) Store{
		"memory": func(*testing.T) Store { return NewMemory() },
		"bolt": func(t *testing.T) Store {
			s, err := OpenBolt(filepath.Join(t.TempDir(), "sub", "weistack.db"))
			if err != nil {
				t.Fatalf("OpenBolt: %v", err)
			}
			return s
		},
	}
}

func eachStore(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Helper()
	for name, open := range implementations() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := open(t)
			t.Cleanup(func() { _ = s.Close() })
			fn(t, s)
		})
	}
}

func mustCreate(t *testing.T, s Store, sc Scope, id, data string) Record {
	t.Helper()
	rec, err := s.Create(ctx, sc, id, []byte(data))
	if err != nil {
		t.Fatalf("Create(%s): %v", id, err)
	}
	return rec
}

func TestCreateGet(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		rec := mustCreate(t, s, scope, "a", "one")
		if rec.ID != "a" || rec.Version != 1 || string(rec.Data) != "one" {
			t.Fatalf("Create returned %+v", rec)
		}

		got, err := s.Get(ctx, scope, "a")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Version != 1 || string(got.Data) != "one" || got.Seq != rec.Seq {
			t.Fatalf("Get returned %+v, want %+v", got, rec)
		}

		if _, err := s.Create(ctx, scope, "a", []byte("again")); !errors.Is(err, ErrExists) {
			t.Fatalf("duplicate Create: err = %v, want ErrExists", err)
		}
		if _, err := s.Get(ctx, scope, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get missing: err = %v, want ErrNotFound", err)
		}
	})
}

func TestScopesAreIsolated(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		other := scope
		other.ProjectID = "ffffffffffffffffffffffffffffffff"
		mustCreate(t, s, scope, "a", "mine")

		if _, err := s.Get(ctx, other, "a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("record visible from another project: err = %v", err)
		}
		recs, err := s.List(ctx, other)
		if err != nil || len(recs) != 0 {
			t.Fatalf("List(other) = %v, %v; want empty", recs, err)
		}
		// The same ID may exist independently in another scope.
		mustCreate(t, s, other, "a", "theirs")
	})
}

func TestListIsInCreationOrder(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		ids := []string{"m", "z", "a", "k"}
		for _, id := range ids {
			mustCreate(t, s, scope, id, id)
		}
		// Updating must not move a record.
		if _, err := s.Put(ctx, scope, "z", []byte("changed")); err != nil {
			t.Fatalf("Put: %v", err)
		}

		recs, err := s.List(ctx, scope)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(recs) != len(ids) {
			t.Fatalf("List returned %d records, want %d", len(recs), len(ids))
		}
		for i, rec := range recs {
			if rec.ID != ids[i] {
				t.Fatalf("position %d: got %q, want %q", i, rec.ID, ids[i])
			}
		}
	})
}

func TestPutUpserts(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		first, err := s.Put(ctx, scope, "a", []byte("v1"))
		if err != nil || first.Version != 1 {
			t.Fatalf("first Put = %+v, %v", first, err)
		}
		second, err := s.Put(ctx, scope, "a", []byte("v2"))
		if err != nil || second.Version != 2 || second.Seq != first.Seq {
			t.Fatalf("second Put = %+v, %v", second, err)
		}
		got, _ := s.Get(ctx, scope, "a")
		if string(got.Data) != "v2" {
			t.Fatalf("Data = %q, want v2", got.Data)
		}
	})
}

func TestCompareAndSwap(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		rec := mustCreate(t, s, scope, "a", "v1")

		next, err := s.CompareAndSwap(ctx, scope, "a", rec.Version, []byte("v2"))
		if err != nil || next.Version != 2 {
			t.Fatalf("CompareAndSwap = %+v, %v", next, err)
		}
		// The version read earlier is now stale.
		if _, err := s.CompareAndSwap(ctx, scope, "a", rec.Version, []byte("v3")); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale CompareAndSwap: err = %v, want ErrConflict", err)
		}
		if _, err := s.CompareAndSwap(ctx, scope, "nope", 1, []byte("x")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing CompareAndSwap: err = %v, want ErrNotFound", err)
		}
		got, _ := s.Get(ctx, scope, "a")
		if string(got.Data) != "v2" {
			t.Fatalf("Data = %q, want v2 (stale write must not apply)", got.Data)
		}
	})
}

func TestDelete(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		mustCreate(t, s, scope, "a", "x")
		if err := s.Delete(ctx, scope, "a"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := s.Delete(ctx, scope, "a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second Delete: err = %v, want ErrNotFound", err)
		}
		if _, err := s.Get(ctx, scope, "a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get after Delete: err = %v", err)
		}
		// An ID can be reused after deletion and starts again at version 1.
		if rec := mustCreate(t, s, scope, "a", "y"); rec.Version != 1 {
			t.Fatalf("recreated record has version %d, want 1", rec.Version)
		}
	})
}

func TestResetAndDump(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		subnets := scope
		subnets.Kind = "subnet"
		mustCreate(t, s, scope, "v1", "{}")
		mustCreate(t, s, scope, "v2", "{}")
		mustCreate(t, s, subnets, "s1", "{}")

		dump, err := s.Dump(ctx)
		if err != nil {
			t.Fatalf("Dump: %v", err)
		}
		if len(dump) != 2 || len(dump[scope.String()]) != 2 || len(dump[subnets.String()]) != 1 {
			t.Fatalf("Dump = %v", dump)
		}
		if dump[scope.String()][0].ID != "v1" {
			t.Fatalf("Dump is not in creation order: %v", dump[scope.String()])
		}

		if err := s.Reset(ctx); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		dump, err = s.Dump(ctx)
		if err != nil || len(dump) != 0 {
			t.Fatalf("Dump after Reset = %v, %v; want empty", dump, err)
		}
		// The store stays usable after a reset.
		mustCreate(t, s, scope, "v1", "{}")
	})
}

func TestReturnedDataIsACopy(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		in := []byte("original")
		mustCreate(t, s, scope, "a", string(in))

		got, _ := s.Get(ctx, scope, "a")
		got.Data[0] = 'X'
		listed, _ := s.List(ctx, scope)
		listed[0].Data[1] = 'Y'

		again, _ := s.Get(ctx, scope, "a")
		if string(again.Data) != "original" {
			t.Fatalf("stored data was mutated through a returned slice: %q", again.Data)
		}
	})
}

func TestInvalidScope(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		bad := []Scope{
			{},
			{Region: "r", ProjectID: "p"},
			{Region: "r/x", ProjectID: "p", Kind: "k"},
		}
		for _, sc := range bad {
			if _, err := s.Create(ctx, sc, "a", nil); !errors.Is(err, ErrInvalidScope) {
				t.Errorf("Create(%q): err = %v, want ErrInvalidScope", sc, err)
			}
			if _, err := s.Get(ctx, sc, "a"); !errors.Is(err, ErrInvalidScope) {
				t.Errorf("Get(%q): err = %v, want ErrInvalidScope", sc, err)
			}
			if _, err := s.List(ctx, sc); !errors.Is(err, ErrInvalidScope) {
				t.Errorf("List(%q): err = %v, want ErrInvalidScope", sc, err)
			}
			if err := s.Delete(ctx, sc, "a"); !errors.Is(err, ErrInvalidScope) {
				t.Errorf("Delete(%q): err = %v, want ErrInvalidScope", sc, err)
			}
		}
	})
}

func TestCancelledContext(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		mustCreate(t, s, scope, "a", "x")
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		if _, err := s.Get(cctx, scope, "a"); !errors.Is(err, context.Canceled) {
			t.Errorf("Get: err = %v, want context.Canceled", err)
		}
		if _, err := s.Put(cctx, scope, "a", nil); !errors.Is(err, context.Canceled) {
			t.Errorf("Put: err = %v, want context.Canceled", err)
		}
		if err := s.Reset(cctx); !errors.Is(err, context.Canceled) {
			t.Errorf("Reset: err = %v, want context.Canceled", err)
		}
		if _, err := s.Dump(cctx); !errors.Is(err, context.Canceled) {
			t.Errorf("Dump: err = %v, want context.Canceled", err)
		}
		if _, err := Update(cctx, s, scope, "a", func(b []byte) ([]byte, error) { return b, nil }); !errors.Is(err, context.Canceled) {
			t.Errorf("Update: err = %v, want context.Canceled", err)
		}
	})
}

func TestUseAfterClose(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		mustCreate(t, s, scope, "a", "x")
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if _, err := s.Get(ctx, scope, "a"); !errors.Is(err, ErrClosed) {
			t.Errorf("Get: err = %v, want ErrClosed", err)
		}
		if _, err := s.Create(ctx, scope, "b", nil); !errors.Is(err, ErrClosed) {
			t.Errorf("Create: err = %v, want ErrClosed", err)
		}
		if _, err := s.List(ctx, scope); !errors.Is(err, ErrClosed) {
			t.Errorf("List: err = %v, want ErrClosed", err)
		}
		if err := s.Delete(ctx, scope, "a"); !errors.Is(err, ErrClosed) {
			t.Errorf("Delete: err = %v, want ErrClosed", err)
		}
		if err := s.Reset(ctx); !errors.Is(err, ErrClosed) {
			t.Errorf("Reset: err = %v, want ErrClosed", err)
		}
		if _, err := s.Dump(ctx); !errors.Is(err, ErrClosed) {
			t.Errorf("Dump: err = %v, want ErrClosed", err)
		}
	})
}

// 200 concurrent read-modify-write cycles on one record must all apply:
// this is the "no lost updates" guarantee IPAM and quotas rely on.
func TestUpdateHasNoLostUpdates(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		const workers = 200
		mustCreate(t, s, scope, "counter", "0")

		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := Update(ctx, s, scope, "counter", func(data []byte) ([]byte, error) {
					n, err := strconv.Atoi(string(data))
					if err != nil {
						return nil, err
					}
					return []byte(strconv.Itoa(n + 1)), nil
				})
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
		}

		got, _ := s.Get(ctx, scope, "counter")
		if string(got.Data) != strconv.Itoa(workers) {
			t.Fatalf("counter = %s, want %d", got.Data, workers)
		}
		if got.Version != workers+1 {
			t.Fatalf("version = %d, want %d", got.Version, workers+1)
		}
	})
}

func TestUpdateErrors(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		noop := func(b []byte) ([]byte, error) { return b, nil }
		if _, err := Update(ctx, s, scope, "missing", noop); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Update missing: err = %v, want ErrNotFound", err)
		}

		mustCreate(t, s, scope, "a", "x")
		boom := errors.New("boom")
		_, err := Update(ctx, s, scope, "a", func([]byte) ([]byte, error) { return nil, boom })
		if !errors.Is(err, boom) {
			t.Fatalf("Update: err = %v, want the callback's error", err)
		}
		got, _ := s.Get(ctx, scope, "a")
		if got.Version != 1 || string(got.Data) != "x" {
			t.Fatalf("failed Update changed the record: %+v", got)
		}
	})
}

func TestBoltPersistsAcrossReopen(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "weistack.db")
	s, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt: %v", err)
	}
	mustCreate(t, s, scope, "a", "one")
	mustCreate(t, s, scope, "b", "two")
	if _, err := s.Put(ctx, scope, "a", []byte("one-v2")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s, err = OpenBolt(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()

	recs, err := s.List(ctx, scope)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 2 || recs[0].ID != "a" || string(recs[0].Data) != "one-v2" || recs[0].Version != 2 || recs[1].ID != "b" {
		t.Fatalf("state after reopen = %+v", recs)
	}
	// Sequences keep increasing after a restart, so order stays stable.
	c := mustCreate(t, s, scope, "c", "three")
	if c.Seq <= recs[1].Seq {
		t.Fatalf("new record Seq %d is not after existing Seq %d", c.Seq, recs[1].Seq)
	}
}

func TestBoltOpenErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// A directory is not a database file.
	if _, err := OpenBolt(dir); err == nil {
		t.Fatal("OpenBolt on a directory succeeded")
	}

	// A second open of a locked file fails fast instead of hanging.
	path := filepath.Join(dir, "weistack.db")
	s, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt: %v", err)
	}
	defer s.Close()
	if _, err := OpenBolt(path); err == nil {
		t.Fatal("second OpenBolt of a locked database succeeded")
	}
}

func BenchmarkStore(b *testing.B) {
	for _, name := range []string{"memory", "bolt"} {
		var s Store
		if name == "memory" {
			s = NewMemory()
		} else {
			var err error
			if s, err = OpenBolt(filepath.Join(b.TempDir(), "bench.db")); err != nil {
				b.Fatal(err)
			}
		}
		for i := range 1000 {
			if _, err := s.Create(ctx, scope, fmt.Sprintf("id-%04d", i), []byte(`{"name":"vpc","cidr":"192.168.0.0/16"}`)); err != nil {
				b.Fatal(err)
			}
		}
		b.Run(name+"/Get", func(b *testing.B) {
			for b.Loop() {
				if _, err := s.Get(ctx, scope, "id-0500"); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(name+"/List1000", func(b *testing.B) {
			for b.Loop() {
				if _, err := s.List(ctx, scope); err != nil {
					b.Fatal(err)
				}
			}
		})
		_ = s.Close()
	}
}

func TestParseScope(t *testing.T) {
	t.Parallel()

	got, err := ParseScope(scope.String())
	if err != nil || got != scope {
		t.Fatalf("ParseScope(%q) = %+v, %v; want %+v", scope.String(), got, err, scope)
	}
	for _, bad := range []string{"", "a/b", "a/b/c/d", "a//c"} {
		if _, err := ParseScope(bad); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("ParseScope(%q): err = %v, want ErrInvalidScope", bad, err)
		}
	}
}
