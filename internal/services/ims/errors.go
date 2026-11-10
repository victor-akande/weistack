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

func bad(code, format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, code, format, args...)
}

// Image creation and update.
var (
	errEmptyBody       = bad("IMG.0007", "The request body is empty.")
	errNameMissing     = bad("IMG.0013", "The image name is not specified.")
	errNameTooLong     = bad("IMG.0002", "The image name contains more than 128 characters.")
	errNameFormat      = bad("IMG.0003", "The image name is invalid: it can contain letters, digits, spaces, hyphens (-), underscores (_) and periods (.), and cannot start or end with a space.")
	errDescTooLong     = bad("IMG.0004", "The image description contains more than 1024 characters.")
	errDescFormat      = bad("IMG.0054", "The image description is invalid: it cannot contain angle brackets or line breaks.")
	errInstanceInvalid = bad("IMG.0012", "The ECS ID is not specified or is invalid.")
)

// errNameInUse is IMG.0009.
func errNameInUse(name string) *apierr.Error {
	return bad("IMG.0009", "The image name %q is already in use.", name)
}

// errServerNotFound is IMG.0005.
func errServerNotFound(id string) *apierr.Error {
	return bad("IMG.0005", "The ECS %s does not exist.", id)
}

// errImageUnavailable is IMG.0046: only active images can be updated.
func errImageUnavailable(id, status string) *apierr.Error {
	return bad("IMG.0046", "The image %s is unavailable: its status is %s.", id, status)
}

// errNotOwner is IMG.0047: public images belong to the platform.
func errNotOwner(id string) *apierr.Error {
	return bad("IMG.0047", "Only the owner of image %s can perform this operation.", id)
}

// errImageBeingCreated is IMG.0090.
func errImageBeingCreated(id string) *apierr.Error {
	return bad("IMG.0090", "The image %s is being created and cannot be deleted.", id)
}

// errImageProtected is IMG.0091.
func errImageProtected(id string) *apierr.Error {
	return bad("IMG.0091", "The image %s is protected and cannot be deleted.", id)
}

// errPublicImageDelete is IMG.0094.
func errPublicImageDelete(id string) *apierr.Error {
	return bad("IMG.0094", "The public image %s cannot be deleted.", id)
}

// errJobQuery is IMG.0023: the job cannot be queried, here because it
// does not exist in the project.
func errJobQuery(id string) *apierr.Error {
	return bad("IMG.0023", "An error occurred when querying the job %s: the job does not exist.", id)
}

// jobFailureCode is what a failed job reports: an internal error while
// the platform ran the task.
const jobFailureCode = "IMG.0014"
