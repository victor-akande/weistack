package reqctx

import (
	"context"
	"sync"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	info := &Info{RequestID: "abc", Service: "vpc", Region: "ap-southeast-1"}
	ctx := With(context.Background(), info)

	if got := From(ctx); got != info {
		t.Fatalf("From returned %p, want the stored %p", got, info)
	}
	From(ctx).SetOperation("CreateVpc")
	if got := info.Operation(); got != "CreateVpc" {
		t.Fatalf("Operation() = %q, want CreateVpc", got)
	}
}

func TestFromEmptyContext(t *testing.T) {
	t.Parallel()

	got := From(context.Background())
	if got == nil {
		t.Fatal("From returned nil")
	}
	if got.RequestID != "" || got.Operation() != "" {
		t.Fatalf("expected empty Info, got %+v", got)
	}
}

func TestOperationConcurrent(t *testing.T) {
	t.Parallel()

	info := &Info{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() { defer wg.Done(); info.SetOperation("ListVpcs") }()
		go func() { defer wg.Done(); _ = info.Operation() }()
	}
	wg.Wait()
	if got := info.Operation(); got != "ListVpcs" {
		t.Fatalf("Operation() = %q", got)
	}
}
