package ids

import (
	"regexp"
	"sync"
	"testing"
)

var (
	uuidV4RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hex32RE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

func TestFormats(t *testing.T) {
	t.Parallel()

	g := New()
	for range 200 {
		if id := g.UUID(); !uuidV4RE.MatchString(id) {
			t.Fatalf("UUID() = %q, not a lowercase v4 UUID", id)
		}
		if id := g.Hex32(); !hex32RE.MatchString(id) {
			t.Fatalf("Hex32() = %q, not 32 lowercase hex characters", id)
		}
	}
}

func TestSeededIsDeterministic(t *testing.T) {
	t.Parallel()

	a, b, other := NewSeeded(42), NewSeeded(42), NewSeeded(43)
	for i := range 20 {
		ua, ub := a.UUID(), b.UUID()
		if ua != ub {
			t.Fatalf("step %d: same seed diverged: %q vs %q", i, ua, ub)
		}
		if !uuidV4RE.MatchString(ua) {
			t.Fatalf("seeded UUID %q is not a v4 UUID", ua)
		}
		if ua == other.UUID() {
			t.Fatalf("step %d: different seeds produced the same UUID", i)
		}
		if ha, hb := a.Hex32(), b.Hex32(); ha != hb {
			t.Fatalf("step %d: same seed diverged: %q vs %q", i, ha, hb)
		}
		other.Hex32()
	}
}

func TestConcurrentUnique(t *testing.T) {
	t.Parallel()

	const workers, each = 16, 500
	g := New()
	out := make(chan string, workers*each)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				out <- g.UUID()
			}
		}()
	}
	wg.Wait()
	close(out)

	seen := make(map[string]struct{}, workers*each)
	for id := range out {
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID %q", id)
		}
		seen[id] = struct{}{}
	}
}

func BenchmarkUUID(b *testing.B) {
	g := New()
	for b.Loop() {
		g.UUID()
	}
}
