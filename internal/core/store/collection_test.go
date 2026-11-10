package store

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

type vpc struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Hosts  int    `json:"hosts"`
}

func TestCollectionCRUD(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		vpcs := Of[vpc](s, scope)

		a := vpc{ID: "a", Name: "prod", Status: "CREATING"}
		b := vpc{ID: "b", Name: "dev", Status: "OK"}
		if err := vpcs.Create(ctx, a.ID, a); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := vpcs.Create(ctx, b.ID, b); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := vpcs.Create(ctx, a.ID, a); !errors.Is(err, ErrExists) {
			t.Fatalf("duplicate Create: err = %v, want ErrExists", err)
		}

		got, err := vpcs.Get(ctx, "a")
		if err != nil || got != a {
			t.Fatalf("Get = %+v, %v; want %+v", got, err, a)
		}
		if _, err := vpcs.Get(ctx, "zzz"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get missing: err = %v, want ErrNotFound", err)
		}

		all, err := vpcs.List(ctx, nil)
		if err != nil || !reflect.DeepEqual(all, []vpc{a, b}) {
			t.Fatalf("List(nil) = %+v, %v", all, err)
		}
		ok, err := vpcs.List(ctx, func(v vpc) bool { return v.Status == "OK" })
		if err != nil || !reflect.DeepEqual(ok, []vpc{b}) {
			t.Fatalf("List(filter) = %+v, %v", ok, err)
		}
		none, err := vpcs.List(ctx, func(vpc) bool { return false })
		if err != nil || none == nil || len(none) != 0 {
			t.Fatalf("List(no match) = %#v, %v; want empty non-nil slice", none, err)
		}

		updated, err := vpcs.Update(ctx, "a", func(v *vpc) error { v.Status = "OK"; return nil })
		if err != nil || updated.Status != "OK" || updated.Name != "prod" {
			t.Fatalf("Update = %+v, %v", updated, err)
		}

		b.Name = "staging"
		if err := vpcs.Put(ctx, b.ID, b); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if got, _ := vpcs.Get(ctx, "b"); got.Name != "staging" {
			t.Fatalf("after Put, Name = %q", got.Name)
		}

		if err := vpcs.Delete(ctx, "a"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := vpcs.Delete(ctx, "a"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second Delete: err = %v, want ErrNotFound", err)
		}
	})
}

func TestCollectionUpdateAbortsOnError(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		vpcs := Of[vpc](s, scope)
		if err := vpcs.Create(ctx, "a", vpc{ID: "a", Status: "OK"}); err != nil {
			t.Fatalf("Create: %v", err)
		}

		invalid := errors.New("invalid transition")
		_, err := vpcs.Update(ctx, "a", func(v *vpc) error {
			v.Status = "BROKEN"
			return invalid
		})
		if !errors.Is(err, invalid) {
			t.Fatalf("Update: err = %v, want the callback's error", err)
		}
		if got, _ := vpcs.Get(ctx, "a"); got.Status != "OK" {
			t.Fatalf("aborted Update was stored: %+v", got)
		}
		if _, err := vpcs.Update(ctx, "zzz", func(*vpc) error { return nil }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Update missing: err = %v, want ErrNotFound", err)
		}
	})
}

// Models the IPAM requirement: 200 parallel allocations from one record
// must hand out 200 distinct values.
func TestCollectionConcurrentAllocation(t *testing.T) {
	t.Parallel()
	eachStore(t, func(t *testing.T, s Store) {
		const workers = 200
		vpcs := Of[vpc](s, scope)
		if err := vpcs.Create(ctx, "a", vpc{ID: "a"}); err != nil {
			t.Fatalf("Create: %v", err)
		}

		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			seen = map[int]bool{}
		)
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, err := vpcs.Update(ctx, "a", func(v *vpc) error { v.Hosts++; return nil })
				if err != nil {
					t.Errorf("Update: %v", err)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if seen[v.Hosts] {
					t.Errorf("value %d handed out twice", v.Hosts)
				}
				seen[v.Hosts] = true
			}()
		}
		wg.Wait()
		if len(seen) != workers {
			t.Fatalf("%d distinct allocations, want %d", len(seen), workers)
		}
	})
}

func TestCollectionCodecErrors(t *testing.T) {
	t.Parallel()

	s := NewMemory()
	defer s.Close()

	// A value JSON cannot represent is rejected before reaching the store.
	chans := Of[chan int](s, scope)
	if err := chans.Create(ctx, "a", make(chan int)); err == nil {
		t.Fatal("Create of an unencodable value succeeded")
	}
	if err := chans.Put(ctx, "a", make(chan int)); err == nil {
		t.Fatal("Put of an unencodable value succeeded")
	}

	// Stored bytes that are not valid for T surface as errors, not zero values.
	if _, err := s.Put(ctx, scope, "bad", []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	vpcs := Of[vpc](s, scope)
	if _, err := vpcs.Get(ctx, "bad"); err == nil {
		t.Fatal("Get of corrupt data succeeded")
	}
	if _, err := vpcs.List(ctx, nil); err == nil {
		t.Fatal("List over corrupt data succeeded")
	}
	if _, err := vpcs.Update(ctx, "bad", func(*vpc) error { return nil }); err == nil {
		t.Fatal("Update of corrupt data succeeded")
	}
}
