package csms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/cmk"
)

const kmsServiceName = "csms"

func valueAAD(secretID, versionID string) []byte {
	return []byte("weistack:csms:" + secretID + ":" + versionID)
}

// seal encrypts plaintext under a 32-byte AES-256 data key using AES-GCM
// with AAD "weistack:csms:<secret-id>:<version-id>", returning nonce || ciphertext.
func seal(dataKey []byte, secretID, versionID string, plaintext []byte) ([]byte, error) {
	if len(dataKey) != 32 {
		return nil, fmt.Errorf("csms: invalid data key length %d", len(dataKey))
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, valueAAD(secretID, versionID))
	return append(nonce, ct...), nil
}

// open decrypts nonce || ciphertext under dataKey with AAD
// "weistack:csms:<secret-id>:<version-id>".
func open(dataKey []byte, secretID, versionID string, ciphertext []byte) ([]byte, error) {
	if len(dataKey) != 32 {
		return nil, fmt.Errorf("csms: invalid data key length %d", len(dataKey))
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("csms: ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], valueAAD(secretID, versionID))
}

// kmsKeyResource builds a KMS KeyId resource URN from cmk.DataKey.KeyURN
// ("<region>:<account>:key/<id>").
func kmsKeyResource(urn string) authz.Resource {
	region, rest, _ := strings.Cut(urn, ":")
	account, id, _ := strings.Cut(rest, ":key/")
	return authz.Resource{URN: "kms:" + region + ":" + account + ":KeyId:" + id}
}

func kmsKeyIDFromURN(urn string) string {
	_, rest, _ := strings.Cut(urn, ":")
	_, id, _ := strings.Cut(rest, ":key/")
	return id
}

// resolveUsableKMSKey validates that keyID (or "" for csms/default) is a usable
// KMS key for the caller's project, returning its resolved key ID and checking
// kms:cmk:createDataKey when checkDep is true.
func (s *Service) newVersionDataKey(r *http.Request, region, keyID string) (resolvedKeyID string, plain, sealed []byte, err error) {
	if s.keys == nil {
		return "", nil, nil, errNotImplemented("KMS encryption without KMS")
	}
	if keyID != "" && !kmsKeyIDRE.MatchString(keyID) {
		return "", nil, nil, errParamKMSKeyID
	}
	dk, err := s.keys.NewDataKey(r.Context(), region, keyID, kmsServiceName)
	if err != nil {
		if errors.Is(err, cmk.ErrNotFound) || errors.Is(err, cmk.ErrDisabled) {
			return "", nil, nil, errParamKMSKeyID
		}
		return "", nil, nil, err
	}
	if err := authz.CheckDependency(r, "kms", "kms:cmk:createDataKey", kmsKeyResource(dk.KeyURN)); err != nil {
		return "", nil, nil, err
	}
	return kmsKeyIDFromURN(dk.KeyURN), dk.Plain, dk.Sealed, nil
}

// checkUsableKMSKey validates kms_key_id on UpdateSecret (where no new version
// is created immediately, so only key usability is verified).
func (s *Service) checkUsableKMSKey(r *http.Request, region, keyID string) (string, error) {
	if s.keys == nil {
		return "", errNotImplemented("KMS encryption without KMS")
	}
	if keyID != "" && !kmsKeyIDRE.MatchString(keyID) {
		return "", errParamKMSKeyID
	}
	dk, err := s.keys.NewDataKey(r.Context(), region, keyID, kmsServiceName)
	if err != nil {
		if errors.Is(err, cmk.ErrNotFound) || errors.Is(err, cmk.ErrDisabled) {
			return "", errParamKMSKeyID
		}
		return "", err
	}
	clear(dk.Plain)
	return kmsKeyIDFromURN(dk.KeyURN), nil
}

// openVersionDataKey checks kms:cmk:decryptDataKey and opens a version's
// KMS-sealed data key, returning 400 CSMS.0401 if the KMS key is disabled or
// pending deletion / missing.
func (s *Service) openVersionDataKey(r *http.Request, region, accountID, kmsKeyID string, sealedKey []byte) ([]byte, error) {
	if s.keys == nil {
		return nil, errNotImplemented("KMS decryption without KMS")
	}
	res := authz.Resource{URN: "kms:" + region + ":" + accountID + ":KeyId:" + kmsKeyID}
	if err := authz.CheckDependency(r, "kms", "kms:cmk:decryptDataKey", res); err != nil {
		return nil, err
	}
	plain, err := s.keys.OpenDataKey(r.Context(), region, sealedKey)
	if err != nil {
		if errors.Is(err, cmk.ErrNotFound) || errors.Is(err, cmk.ErrDisabled) {
			return nil, errKMSProtected
		}
		return nil, err
	}
	return plain, nil
}

// decodeSecretValue validates that exactly one of secret_string or
// secret_binary is provided and at most 64 KB after decoding.
func decodeSecretValue(secretString, secretBinary *string) (raw []byte, binary bool, err error) {
	hasStr := secretString != nil && *secretString != ""
	hasBin := secretBinary != nil && *secretBinary != ""
	if hasStr == hasBin {
		return nil, false, errParam
	}
	if hasBin {
		decoded, err := base64.StdEncoding.DecodeString(*secretBinary)
		if err != nil || len(decoded) == 0 || len(decoded) > maxValueBytes {
			return nil, false, errParam
		}
		return decoded, true, nil
	}
	b := []byte(*secretString)
	if len(b) > maxValueBytes {
		return nil, false, errParam
	}
	return b, false, nil
}
