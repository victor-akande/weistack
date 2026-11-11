package obs

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error catalogue. OBS uses the S3 error codes and renders errors as an
// XML <Error> document. Codes and statuses are those of the OBS API
// reference ("Error Codes"); message texts follow S3's.

var (
	errAccessDenied = apierr.New(http.StatusForbidden, "AccessDenied", "Access Denied")
	errMalformedXML = apierr.New(http.StatusBadRequest, "MalformedXML",
		"The XML you provided was not well-formed or did not validate against our published schema")
	errInvalidBucketName = apierr.New(http.StatusBadRequest, "InvalidBucketName", "The specified bucket is not valid.")
	errBucketOwnedByYou  = apierr.New(http.StatusConflict, "BucketAlreadyOwnedByYou",
		"Your previous request to create the named bucket succeeded and you already own it.")
	errBucketExists = apierr.New(http.StatusConflict, "BucketAlreadyExists",
		"The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again.")
	errNoSuchBucket     = apierr.New(http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
	errMethodNotAllowed = apierr.New(http.StatusMethodNotAllowed, "MethodNotAllowed", "The specified method is not allowed against this resource.")
	errInvalidURI       = apierr.New(http.StatusBadRequest, "InvalidURI", "Couldn't parse the specified URI.")
)

// Objects.
var (
	errNoSuchKey          = apierr.New(http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
	errBucketNotEmpty     = apierr.New(http.StatusConflict, "BucketNotEmpty", "The bucket you tried to delete is not empty")
	errKeyTooLong         = apierr.New(http.StatusBadRequest, "KeyTooLongError", "Your key is too long")
	errInvalidDigest      = apierr.New(http.StatusBadRequest, "InvalidDigest", "The Content-MD5 you specified is not valid.")
	errBadDigest          = apierr.New(http.StatusBadRequest, "BadDigest", "The Content-MD5 you specified did not match what we received.")
	errIncompleteBody     = apierr.New(http.StatusBadRequest, "IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header")
	errInvalidRange       = apierr.New(http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "The requested range is not satisfiable")
	errPreconditionFailed = apierr.New(http.StatusPreconditionFailed, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
)

func errInvalidArgument(message string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "InvalidArgument", "%s", message)
}

func errInvalidRequest(message string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "InvalidRequest", "%s", message)
}

func errInvalidLocation(got, want string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "InvalidLocationConstraint",
		"The specified location-constraint %q is not valid for this endpoint; use %q.", got, want)
}

// errNotImplemented reports a part of the API the emulator does not
// support. "NotImplemented" is the genuine S3 code for an unsupported
// operation, so clients handle it as they would against the real
// service; the message says it is an emulator gap.
func errNotImplemented(what string) *apierr.Error {
	return apierr.New(http.StatusNotImplemented, "NotImplemented", "weistack does not implement obs %s yet", what)
}
