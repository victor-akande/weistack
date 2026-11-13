package iam

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Codes from Huawei's published classic IAM error table
// (support.huaweicloud.com/intl/en-us/api-iam/iam_02_0006.html).

// errNotFound is IAM.0004: "Could not find %(target)s: %(target_id)s."
func errNotFound(target, id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "IAM.0004", "Could not find %s: %s.", target, id)
}

// errInvalidParam is IAM.0007: "Request parameter %(key)s is invalid."
func errInvalidParam(key string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "IAM.0007", "Request parameter %s is invalid.", key)
}
