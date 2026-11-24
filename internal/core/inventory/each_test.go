package inventory

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/victor-akande/weistack/internal/core/store"
)

type item struct {
	ID string `json:"id"`
}

func TestEach(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	put := func(sc store.Scope, ids ...string) {
		for _, id := range ids {
			if err := store.Of[item](st, sc).Create(t.Context(), id, item{ID: id}); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}
	}
	const kind = "vpc.vpc"
	put(store.Scope{Region: "r2", ProjectID: "p", Kind: kind}, "c")
	put(store.Scope{Region: "r1", ProjectID: "p", Kind: kind}, "b", "a")
	put(store.Scope{Region: "r1", ProjectID: "p", Kind: "vpc.subnet"}, "s")

	var got []string
	err := Each(t.Context(), st, kind, func(sc store.Scope, it item) error {
		got = append(got, fmt.Sprintf("%s/%s/%s", sc.Region, sc.ProjectID, it.ID))
		return nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	// Scopes sorted, records in creation order.
	if want := []string{"r1/p/b", "r1/p/a", "r2/p/c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Each visited %v, want %v", got, want)
	}

	boom := errors.New("boom")
	calls := 0
	err = Each(t.Context(), st, kind, func(store.Scope, item) error { calls++; return boom })
	if !errors.Is(err, boom) || calls != 1 {
		t.Errorf("Each: err = %v after %d calls; want boom after 1", err, calls)
	}

	if err := Each(t.Context(), st, "none", func(store.Scope, item) error { t.Error("called"); return nil }); err != nil {
		t.Errorf("Each(no records): %v", err)
	}

	// A record that does not decode fails.
	if _, err := st.Create(t.Context(), store.Scope{Region: "r1", ProjectID: "p", Kind: "bad"}, "x", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if err := Each(t.Context(), st, "bad", func(store.Scope, item) error { return nil }); err == nil {
		t.Error("Each over a record that does not decode: no error")
	}

	_ = st.Close()
	if err := Each(t.Context(), st, kind, func(store.Scope, item) error { return nil }); !errors.Is(err, store.ErrClosed) {
		t.Errorf("Each on a closed store: err = %v, want ErrClosed", err)
	}
}
