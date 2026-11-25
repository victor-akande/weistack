package app

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitCode(t *testing.T) {
	t.Parallel()

	base := errors.New("boom")
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"nil usage", usageError(nil), 0},
		{"nil unreachable", unreachableError(nil), 0},
		{"nil api", apiError(500, nil, "", nil), 0},
		{"nil data", dataError(nil), 0},
		{"untyped", base, 1},
		{"wrapped untyped", fmt.Errorf("context: %w", base), 1},
		{"usage", usageError(base), 2},
		{"wrapped usage", fmt.Errorf("context: %w", usageError(base)), 2},
		{"unreachable", unreachableError(base), 3},
		{"wrapped unreachable", fmt.Errorf("context: %w", unreachableError(base)), 3},
		{"api", apiError(404, []byte(`{"error_code":"WeiStack.0404"}`), "check path", base), 4},
		{"wrapped api", fmt.Errorf("context: %w", apiError(503, []byte("unavailable"), "", base)), 4},
		{"data", dataError(base), 5},
		{"wrapped data", fmt.Errorf("context: %w", dataError(base)), 5},
		{"inner data preserved in unreachable", unreachableError(fmt.Errorf("admin: %w", dataError(base))), 5},
		{"inner usage preserved in data", dataError(fmt.Errorf("wrap: %w", usageError(base))), 2},
		{"inner unreachable preserved in usage", usageError(fmt.Errorf("wrap: %w", unreachableError(base))), 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ExitCode(tt.err); got != tt.want {
				t.Fatalf("ExitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
			if tt.err != nil && !errors.Is(tt.err, base) {
				t.Fatalf("errors.Is(%v, base) = false, want true", tt.err)
			}
		})
	}
}
