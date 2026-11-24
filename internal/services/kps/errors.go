package kps

import (
	"fmt"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
)

// KPS's documented error codes (DEW error table, plus 404 KPS.6004 and
// 400 KPS.7004 matching Huawei Cloud and the Terraform provider).
// KPS renders errors in StyleFlat: {"error_code", "error_msg"}.
func kpsErr(status int, code, msg string) *apierr.Error {
	return apierr.New(status, code, "%s", msg)
}

var (
	errIllegalTaskID       = kpsErr(http.StatusBadRequest, "KPS.0001", "taskId is illegal.")
	errParam               = kpsErr(http.StatusBadRequest, "KPS.0002", "parameter error.")
	errFailedTaskNotFound  = kpsErr(http.StatusBadRequest, "KPS.0005", "Failed task is not found.")
	errBindKeypairNotExist = kpsErr(http.StatusBadRequest, "KPS.4016", "The key pair is not exist.")
	errNotFound            = kpsErr(http.StatusNotFound, "KPS.6004", "No Keypair find.")
	errNoPrivateKey        = kpsErr(http.StatusBadRequest, "KPS.6005", "No private key managed.")
	errEncryptFailed       = kpsErr(http.StatusBadRequest, "KPS.6008", "Encrypt private key failed.")
	errSavePrivateFailed   = kpsErr(http.StatusBadRequest, "KPS.6010", "Save privatekey failed.")
	errKeyMismatch         = kpsErr(http.StatusBadRequest, "KPS.6011", "The imported private key not match public key.")
)

func errDuplicateKeypair(name string) *apierr.Error {
	return kpsErr(http.StatusBadRequest, "KPS.7004", fmt.Sprintf("Key pair '%s' already exists.", name))
}

// denied is KPS's documented permission error.
func denied(d *authz.Denial) *apierr.Error {
	return kpsErr(http.StatusForbidden, "KPS.9003", "No operation permission.").WithAuthorizationMessage(d.Encoded)
}
