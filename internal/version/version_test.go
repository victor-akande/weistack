package version

import "testing"

func TestString(t *testing.T) {
	t.Parallel()

	const want = "weistack dev (commit none, built unknown)"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
