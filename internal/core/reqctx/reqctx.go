// Package reqctx carries per-request metadata through context.Context so
// that middleware, handlers and error writers agree on the request ID,
// target service and operation without importing each other.
package reqctx

import (
	"context"
	"sync"
)

// Info describes one in-flight request. The routing fields are written
// once by the server before the handler runs; Operation may be set later
// by the handler, so it is guarded for the logging middleware to read.
type Info struct {
	// RequestID is echoed in the X-Request-Id response header.
	RequestID string
	// Service is the emulated service the request was routed to, or "".
	Service string
	// Region is the region the request addressed.
	Region string

	mu        sync.Mutex
	operation string
}

// SetOperation records the API operation name (for example "CreateVpc")
// for logs and metrics.
func (i *Info) SetOperation(op string) {
	i.mu.Lock()
	i.operation = op
	i.mu.Unlock()
}

// Operation returns the operation recorded by SetOperation, or "".
func (i *Info) Operation() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.operation
}

type ctxKey struct{}

// With returns a copy of ctx carrying info.
func With(ctx context.Context, info *Info) context.Context {
	return context.WithValue(ctx, ctxKey{}, info)
}

// From returns the Info stored in ctx. It never returns nil: without a
// stored Info it returns a fresh, empty one, so callers need no nil checks.
func From(ctx context.Context) *Info {
	if info, ok := ctx.Value(ctxKey{}).(*Info); ok && info != nil {
		return info
	}
	return &Info{}
}
