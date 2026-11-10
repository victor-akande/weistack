package ims

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error catalogue.
//
// IMS renders errors as {"error": {"code": "IMG.0024", "message": "..."}}.
// Codes come from the "Error Codes" appendix of the IMS API reference
// (source: docs), which documents HTTP 400 for every code except
// IMG.0026. Message texts are our own wording.

// errInvalidRequest is IMG.0001: the request is malformed or a
// parameter value is not acceptable.
func errInvalidRequest(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "IMG.0001", format, args...)
}

// errImageNotFound is IMG.0027: no image has the requested ID. The
// native OpenStack image paths (/v2/images/{id}) answer 404, which is
// what their clients test for.
func errImageNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "IMG.0027", "The image %s does not exist.", id)
}
