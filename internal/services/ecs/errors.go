package ecs

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error catalogue.
//
// ECS renders errors as {"error": {"code": "Ecs.0005", "message": "..."}}.
// Codes and HTTP statuses come from the "Error Codes" appendix of the ECS
// API reference (source: docs). Message texts are our own wording.

// errInvalidRequest is Ecs.0005: the request body or a parameter is
// invalid.
func errInvalidRequest(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "Ecs.0005", format, args...)
}
