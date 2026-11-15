package kms

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
)

// KMS's documented errors (api-dew ErrorCode), with their published
// messages. KMS answers {"error": {"error_code", "error_msg"}}.
func kmsErr(status int, code, msg string) *apierr.Error {
	return apierr.New(status, code, "%s", msg)
}

var (
	errJSON            = kmsErr(http.StatusBadRequest, "KMS.0202", "Invalid JSON format of the request message.")
	errMissing         = kmsErr(http.StatusBadRequest, "KMS.0204", "Parameters missing in the request message.")
	errKeyID           = kmsErr(http.StatusBadRequest, "KMS.0205", "Invalid key ID.")
	errDisabled        = kmsErr(http.StatusBadRequest, "KMS.0209", "The key has been disabled.")
	errPendingDeletion = kmsErr(http.StatusBadRequest, "KMS.0210", "The key is in Scheduled deletion state and cannot be used.")
	errDefaultKey      = kmsErr(http.StatusBadRequest, "KMS.0211", "Cannot perform this operation on Default Master Keys.")
	errParam           = kmsErr(http.StatusBadRequest, "KMS.0308", "Invalid parameter.")
	errRotationOff     = kmsErr(http.StatusBadRequest, "KMS.0313", "Key rotation is not enabled.")
	errAsymmetricOp    = kmsErr(http.StatusBadRequest, "KMS.0325", "The asymmetric key is not support this operation.")
	errForSign         = kmsErr(http.StatusBadRequest, "KMS.0335", "The cmk is used to sign and verify.")
	errTagList         = kmsErr(http.StatusBadRequest, "KMS.0401", "Tag list cannot be empty.")
	errAction          = kmsErr(http.StatusBadRequest, "KMS.0404", "Invalid action.")
	errTagValue        = kmsErr(http.StatusBadRequest, "KMS.0405", "Invalid tag value.")
	errTagKey          = kmsErr(http.StatusBadRequest, "KMS.0406", "Invalid tag key.")
	errTooManyTags     = kmsErr(http.StatusBadRequest, "KMS.0409", "Too many tags.")
	errAlias           = kmsErr(http.StatusBadRequest, "KMS.1101", "Invalid key_alias.")
	errDescription     = kmsErr(http.StatusBadRequest, "KMS.1103", "Invalid key_description.")
	errDuplicateAlias  = kmsErr(http.StatusBadRequest, "KMS.1104", "Duplicate key aliases.")
	errTooManyKeys     = kmsErr(http.StatusBadRequest, "KMS.1105", "Too many keys.")
	errNotDisabled     = kmsErr(http.StatusBadRequest, "KMS.1201", "The key is not disabled.")
	errNotEnabled      = kmsErr(http.StatusBadRequest, "KMS.1301", "The key is not enabled.")
	errPendingDays     = kmsErr(http.StatusBadRequest, "KMS.1401", "Set the pending deletion period between 7 to 1096 days.")
	errAlreadyPending  = kmsErr(http.StatusBadRequest, "KMS.1402", "The key is already in Pending deletion state.")
	errNotPending      = kmsErr(http.StatusBadRequest, "KMS.1501", "The key is not in Pending deletion state.")
	errLimit           = kmsErr(http.StatusBadRequest, "KMS.1601", "Invalid limit.")
	errMarker          = kmsErr(http.StatusBadRequest, "KMS.1602", "marker must be greater than or equals 0.")
	errRandomLength    = kmsErr(http.StatusBadRequest, "KMS.1801", "random_data_length must be 512 bits.")
	errDatakeyLength   = kmsErr(http.StatusBadRequest, "KMS.1901", "datakey_length must be in the range 8 bits to 8,192 bits.")
	errDatakeyMultiple = kmsErr(http.StatusBadRequest, "KMS.1903", "datakey_length must be a multiple of 8.")
	errPlainText       = kmsErr(http.StatusBadRequest, "KMS.2101", "Invalid plain_text.")
	errDEKHash         = kmsErr(http.StatusBadRequest, "KMS.2103", "Failed to verify the DEK hash.")
	errPlainLength     = kmsErr(http.StatusBadRequest, "KMS.2104", "The length of plain_text does not match datakey_plain_length.")
	errSymmetricAlg    = kmsErr(http.StatusBadRequest, "KMS.2105", "The symmetric key not support this encryption algorithm.")
	errCipherText      = kmsErr(http.StatusBadRequest, "KMS.2201", "Invalid cipher_text.")
	errCipherLength    = kmsErr(http.StatusBadRequest, "KMS.2204", "The length of cipher_text does not match datakey_cipher_length.")
	errRotationOn      = kmsErr(http.StatusBadRequest, "KMS.2901", "Key rotation is not disabled.")
	errInterval        = kmsErr(http.StatusBadRequest, "KMS.3001", "Invalid rotation_interval.")
	errNoKey           = kmsErr(http.StatusNotFound, "KMS.0207", "The key does not exist.")
	errNoTag           = kmsErr(http.StatusNotFound, "KMS.0416", "Invalid tag ID.")
)

// denied is KMS's documented permission error.
func denied(d *authz.Denial) *apierr.Error {
	return kmsErr(http.StatusForbidden, "KMS.0306", "No access permissions.").WithAuthorizationMessage(d.Encoded)
}
