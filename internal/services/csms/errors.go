package csms

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
)

// CSMS's documented error codes (DEW CSMS error table, plus 404 CSMS.0005
// matching Huawei Cloud and the Terraform provider).
// CSMS renders errors in StyleFlat: {"error_code", "error_msg"}.
func csmsErr(status int, code, msg string) *apierr.Error {
	return apierr.New(status, code, "%s", msg)
}

var (
	errParam                = csmsErr(http.StatusBadRequest, "CSMS.0002", "The value of parameter is invalid.")
	errParamKMSKeyID        = csmsErr(http.StatusBadRequest, "CSMS.0002", "The value of parameter is invalid: kms_key_id.")
	errBodyFormat           = csmsErr(http.StatusBadRequest, "CSMS.0004", "The requested body format is wrong.")
	errNotFound             = csmsErr(http.StatusNotFound, "CSMS.0005", "The resource does not exist.")
	errScheduledDeleteState = csmsErr(http.StatusBadRequest, "CSMS.0103", "The secret is in the scheduled deletion state.")
	errSystemStage          = csmsErr(http.StatusBadRequest, "CSMS.0105", "Can not delete the system internal stage.")
	errAlreadyScheduled     = csmsErr(http.StatusBadRequest, "CSMS.0107", "The secret is in schedule delete state.")
	errNotScheduled         = csmsErr(http.StatusBadRequest, "CSMS.0108", "The secret is not in schedule delete state.")
	errStateNotEnabled      = csmsErr(http.StatusForbidden, "CSMS.0109", "The secret state is not enabled.")
	errSecretExists         = csmsErr(http.StatusConflict, "CSMS.0101", "The secret name already exists.")
	errSecretQuota          = csmsErr(http.StatusBadRequest, "CSMS.0202", "The number of secret has reached the upper limit.")
	errStageQuota           = csmsErr(http.StatusBadRequest, "CSMS.0203", "The number of stage has reached the upper limit.")
	errKMSProtected         = csmsErr(http.StatusBadRequest, "CSMS.0401", "Can not get the protected secret value using the provided KMS key.")
)

func errNotImplemented(feature string) *apierr.Error {
	return apierr.New(http.StatusNotImplemented, "WeiStack.0501", "weistack does not implement csms %s yet", feature)
}

// denied is CSMS's documented permission error.
func denied(d *authz.Denial) *apierr.Error {
	return csmsErr(http.StatusForbidden, "CSMS.0302", "The user role has no permission to access the interface.").WithAuthorizationMessage(d.Encoded)
}
