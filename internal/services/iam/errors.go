package iam

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Codes from Huawei's published error tables, and only those: classic IAM
// (support.huaweicloud.com/intl/en-us/api-iam/iam_02_0006.html) and IAM
// 5.0 (support.huaweicloud.com/intl/en-us/api-iam5/ErrorCode.html). The
// messages are the published ones.

// Classic IAM.

// apiErr400 is a classic IAM code answered with 400 and a published
// message.
func apiErr400(code, msg string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, code, "%s", msg)
}

// errNotFound is IAM.0004: "Could not find %(target)s: %(target_id)s."
func errNotFound(target, id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "IAM.0004", "Could not find %s: %s.", target, id)
}

// errInvalidParam is IAM.0007: "Request parameter %(key)s is invalid."
func errInvalidParam(key string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "IAM.0007", "Request parameter %s is invalid.", key)
}

// errBadBody is IAM.0011.
func errBadBody() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "IAM.0011", "Request body is invalid.")
}

// errRequired is IAM.0072: "'%(key)s' is a required property."
func errRequired(key string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "IAM.0072", "'%s' is a required property.", key)
}

// errInvalidField is IAM.0073.
func errInvalidField(key, value string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "IAM.0073", "Invalid input for field '%s'. The value is '%s'.", key, value)
}

// errConflict is IAM.0005: "Conflict occurred when attempting to store
// %(type)s - %(details)s."
func errConflict(kind, details string) *apierr.Error {
	return apierr.New(http.StatusConflict, "IAM.0005", "Conflict occurred when attempting to store %s - %s.", kind, details)
}

// errForbidden is IAM.0002.
func errForbidden() *apierr.Error {
	return apierr.New(http.StatusForbidden, "IAM.0002", "You are not authorized to perform the requested action.")
}

// The user codes of the classic table.
var (
	errMandatory      = apierr.New(http.StatusBadRequest, "1100", "Mandatory parameters are not specified.")
	errBadUsername    = apierr.New(http.StatusBadRequest, "1101", "Invalid username.")
	errBadEmail       = apierr.New(http.StatusBadRequest, "1102", "Invalid email address.")
	errWrongPassword  = apierr.New(http.StatusBadRequest, "1103", "Incorrect password.")
	errBadPhone       = apierr.New(http.StatusBadRequest, "1104", "Invalid mobile number.")
	errPhonePair      = apierr.New(http.StatusBadRequest, "1106", "The country code and mobile number must be set at the same time.")
	errDeleteRoot     = apierr.New(http.StatusBadRequest, "1107", "The account administrator cannot be deleted.")
	errSamePassword   = apierr.New(http.StatusBadRequest, "1108", "The new password must be different from the old password.")
	errUsernameTaken  = apierr.New(http.StatusBadRequest, "1109", "The username already exists.")
	errTooManyUsers   = apierr.New(http.StatusBadRequest, "1115", "The number of IAM users has reached the maximum allowed limit.")
	errBadDescription = apierr.New(http.StatusBadRequest, "1117", "Invalid user description.")
	errWeakPassword   = apierr.New(http.StatusBadRequest, "1118", "The password is weak.")
	errBadAccessMode  = apierr.New(http.StatusBadRequest, "1120", "Invalid access_mode.")
	errSubjectToken   = apierr.New(http.StatusBadRequest, "IAM.0009", "X-Subject-Token is invalid in the request.")
	errAuthRequired   = apierr.New(http.StatusUnauthorized, "IAM.0001", "The request you have made requires authentication.")
	errLoginPassword  = apierr.New(http.StatusUnauthorized, "IAM.0062", "Incorrect password.")
	errTokenExpired   = apierr.New(http.StatusUnauthorized, "IAM.0066", "The token has expired.")
	errTokenInvalid   = apierr.New(http.StatusUnauthorized, "IAM.0067", "Invalid token.")
	errConsoleOnly    = apierr.New(http.StatusForbidden, "IAM.0081", "This user only supports console access, not programmatic access.")
)

// errUserDisabled is IAM.0082.
func errUserDisabled(name string) *apierr.Error {
	return apierr.New(http.StatusForbidden, "IAM.0082", "The user %s is disabled.", name)
}

// IAM 5.0.

var (
	errV5Input       = apierr.New(http.StatusBadRequest, "PAP5.0257", "the input is invalid")
	errV5Marker      = apierr.New(http.StatusBadRequest, "PAP5.0010", "invalid marker")
	errV5NoGroup     = apierr.New(http.StatusNotFound, "PAP5.0016", "no such group")
	errV5NoUser      = apierr.New(http.StatusNotFound, "PAP5.0021", "no such user")
	errV5UserExists  = apierr.New(http.StatusConflict, "PAP5.0042", "user already exists")
	errV5GroupExists = apierr.New(http.StatusConflict, "PAP5.0043", "group already exists")
	errV5InGroup     = apierr.New(http.StatusConflict, "PAP5.0044", "user already in group")
)

// errV5DeleteConflict is PAP5.0007: "delete conflict: %s".
func errV5DeleteConflict(why string) *apierr.Error {
	return apierr.New(http.StatusConflict, "PAP5.0007", "delete conflict: %s", why)
}

// errV5Denied is PAP5.0001: "access denied: %s".
func errV5Denied(why string) *apierr.Error {
	return apierr.New(http.StatusForbidden, "PAP5.0001", "access denied: %s", why)
}
