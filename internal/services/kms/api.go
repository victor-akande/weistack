package kms

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Routes implements server.Service. Most operations name their key in
// the body, so their permission is checked once it is read.
func (s *Service) Routes(r chi.Router) {
	act, keyParam := authz.Action, authz.Param("KeyId", "key_id")
	r.Route("/v1.0/{project_id}/kms", func(r chi.Router) {
		r.Use(authz.Service(authz.ServiceOptions{Name: "kms", Style: apierr.StyleNestedFlat, Deny: denied}))
		r.With(act("kms:cmk:create")).Post("/create-key", s.handle("CreateKey", s.handleCreateKey))
		r.With(act("kms:cmk:list")).Post("/list-keys", s.handle("ListKeys", s.handleListKeys))
		r.With(authz.Defer()).Post("/describe-key", s.handle("ListKeyDetail", s.keyed("kms:cmk:get", s.handleDescribeKey)))
		r.With(authz.Defer()).Post("/enable-key", s.handle("EnableKey", s.keyed("kms:cmk:enable", s.handleEnableKey)))
		r.With(authz.Defer()).Post("/disable-key", s.handle("DisableKey", s.keyed("kms:cmk:disable", s.handleDisableKey)))
		r.With(authz.Defer()).Post("/schedule-key-deletion", s.handle("DeleteKey", s.handleScheduleDeletion))
		r.With(authz.Defer()).Post("/cancel-key-deletion", s.handle("CancelKeyDeletion", s.keyed("kms:cmk:cancelKeyDeletion", s.handleCancelDeletion)))
		r.With(authz.Defer()).Post("/update-key-alias", s.handle("UpdateKeyAlias", s.handleUpdateAlias))
		r.With(authz.Defer()).Post("/update-key-description", s.handle("UpdateKeyDescription", s.handleUpdateDescription))

		r.With(authz.Defer()).Post("/encrypt-data", s.handle("EncryptData", s.handleEncryptData))
		r.With(authz.Defer()).Post("/decrypt-data", s.handle("DecryptData", s.handleDecryptData))
		r.With(authz.Defer()).Post("/create-datakey", s.handle("CreateDatakey", s.handleCreateDatakey(true)))
		r.With(authz.Defer()).Post("/create-datakey-without-plaintext", s.handle("CreateDatakeyWithoutPlaintext", s.handleCreateDatakey(false)))
		r.With(authz.Defer()).Post("/encrypt-datakey", s.handle("EncryptDatakey", s.handleEncryptDatakey))
		r.With(authz.Defer()).Post("/decrypt-datakey", s.handle("DecryptDatakey", s.handleDecryptDatakey))
		r.With(act("kms::generateRandom")).Post("/gen-random", s.handle("CreateRandom", s.handleGenRandom))
		r.With(authz.Defer()).Post("/sign", s.handle("CreateSign", s.handleSign))
		r.With(authz.Defer()).Post("/verify", s.handle("ValidateSignature", s.handleVerify))
		r.With(authz.Defer()).Post("/get-publickey", s.handle("ShowPublicKey", s.keyed("kms:cmk:getPublicKey", s.handlePublicKey)))
		r.With(authz.Defer()).Post("/generate-mac", s.handle("GenerateMac", s.handleGenerateMac))
		r.With(authz.Defer()).Post("/verify-mac", s.handle("VerifyMac", s.handleVerifyMac))

		r.With(authz.Defer()).Post("/enable-key-rotation", s.handle("EnableKeyRotation", s.keyed("kms:cmk:enableRotation", s.handleEnableRotation)))
		r.With(authz.Defer()).Post("/disable-key-rotation", s.handle("DisableKeyRotation", s.keyed("kms:cmk:disableRotation", s.handleDisableRotation)))
		r.With(authz.Defer()).Post("/update-key-rotation-interval", s.handle("UpdateKeyRotationInterval", s.handleRotationInterval))
		r.With(authz.Defer()).Post("/get-key-rotation-status", s.handle("ShowKeyRotationStatus", s.keyed("kms:cmk:getRotation", s.handleRotationStatus)))

		r.With(authz.Defer()).Post("/create-grant", s.handle("CreateGrant", s.handleCreateGrant))
		r.With(authz.Defer()).Post("/list-grants", s.handle("ListGrants", s.handleListGrants))
		r.With(authz.Defer()).Post("/revoke-grant", s.handle("CancelGrant", s.handleRevokeGrant))
		r.With(authz.Defer()).Post("/retire-grant", s.handle("CancelSelfGrant", s.handleRetireGrant))
		r.With(act("kms::listRetirableGrants")).Post("/list-retirable-grants", s.handle("ListRetirableGrants", s.handleListRetirableGrants))

		r.With(act("kms::listAllTags")).Get("/tags", s.handle("ListKmsTags", s.handleListAllTags))
		r.With(act("kms:cmk:listKeysByTag")).Post("/resource_instances/action", s.handle("ListKmsByTags", s.handleListByTags))
		r.With(act("kms:cmk:getTags", keyParam)).Get("/{key_id}/tags", s.handle("ShowKmsTags", s.handleKeyTags))
		r.With(act("kms:cmk:createTag", keyParam)).Post("/{key_id}/tags", s.handle("CreateKmsTag", s.handleCreateTag))
		r.With(act("kms:cmk:deleteTag", keyParam)).Delete("/{key_id}/tags/{key}", s.handle("DeleteTag", s.handleDeleteTag))
		r.With(act("kms:cmk:createTags", keyParam)).Post("/{key_id}/tags/action", s.handle("BatchCreateKmsTags", s.handleBatchTags))

		r.With(act("kms::getInstance")).Get("/user-instances", s.handle("ShowUserInstances", s.handleUserInstances))
		r.With(act("kms::getQuota")).Get("/user-quotas", s.handle("ShowUserQuotas", s.handleUserQuotas))
	})
}

type handler func(w http.ResponseWriter, r *http.Request, t tenant) error

// handle names the operation for logs, finds where the request acts and
// renders errors in KMS's envelope.
func (s *Service) handle(op string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := reqctx.From(ctx)
		info.SetOperation(op)
		t := tenant{Region: info.Region, ProjectID: chi.URLParam(r, "project_id"), Account: s.account(ctx)}
		err := fn(w, r, t)
		if err == nil {
			return
		}
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(ctx, "kms operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, apierr.StyleNestedFlat, err)
	}
}

// decode reads a request body.
func decode(r *http.Request, v any) error {
	if err := httpx.DecodeJSON(r, v); err != nil {
		return errJSON
	}
	return nil
}

// authorize checks the caller may perform the action on a key.
func authorize(r *http.Request, action, keyID string) error {
	return authz.Check(r, action, authz.Resource{Type: "KeyId", Path: keyID})
}

// keyedHandler acts on the key a body names.
type keyedHandler func(w http.ResponseWriter, r *http.Request, t tenant, k key) error

// keyed is a handler for operations whose body is only a key ID: it
// reads it, checks the action on the key, and finds it.
func (s *Service) keyed(action string, fn keyedHandler) handler {
	return func(w http.ResponseWriter, r *http.Request, t tenant) error {
		var b keyRef
		if err := decode(r, &b); err != nil {
			return err
		}
		k, err := s.authorized(r, t, action, b.KeyID)
		if err != nil {
			return err
		}
		return fn(w, r, t, k)
	}
}

// authorized checks the action on the key a body names and finds it. A
// grant of the key to the caller for the action's operation allows it
// without an IAM permission, and finds the key in another project or
// account.
func (s *Service) authorized(r *http.Request, t tenant, action, keyID string) (key, error) {
	if keyID == "" {
		return key{}, errMissing
	}
	if k, ok := s.grantedKey(r.Context(), t, action, keyID); ok {
		authz.Granted(r)
		return k, nil
	}
	if err := authorize(r, action, keyID); err != nil {
		return key{}, err
	}
	return s.find(r.Context(), t, keyID)
}

func write(w http.ResponseWriter, v any) error { return httpx.WriteJSON(w, http.StatusOK, v) }

// ---- Keys ----

func (s *Service) handleCreateKey(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b createKeyRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	if b.KeyAlias == "" {
		return errMissing
	}
	if b.KeystoreID != "" && b.KeystoreID != defaultKeystore {
		return errParam // dedicated keystores are not emulated
	}
	k, err := s.createKey(r.Context(), t, newKey{
		Alias: b.KeyAlias, Description: b.KeyDescription, Spec: b.KeySpec, Usage: b.KeyUsage,
		Origin: b.Origin, EP: b.EnterpriseProjectID,
	})
	if err != nil {
		return err
	}
	return write(w, struct {
		KeyInfo keyInfo `json:"key_info"`
	}{keyInfo{KeyID: k.ID, DomainID: k.AccountID}})
}

func (s *Service) handleDescribeKey(w http.ResponseWriter, _ *http.Request, _ tenant, k key) error {
	return write(w, struct {
		KeyInfo keyDetails `json:"key_info"`
	}{details(k)})
}

// listLimits are list-keys's documented page sizes.
const (
	defaultListLimit = 1000
	maxListLimit     = 1000
)

func (s *Service) handleListKeys(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b listKeysRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	limit, offset := defaultListLimit, 0
	if b.Limit.set {
		if b.Limit.bad || b.Limit.v < 1 || b.Limit.v > maxListLimit {
			return errLimit
		}
		limit = b.Limit.v
	}
	if b.Marker.set {
		if b.Marker.bad || b.Marker.v < 0 {
			return errMarker
		}
		offset = b.Marker.v
	}
	all, err := s.projectKeys(r.Context(), t)
	if err != nil {
		return err
	}
	var keys []key
	for _, k := range all {
		if (b.KeyState == "" || k.State == b.KeyState) && (b.KeySpec == "" || k.Spec == b.KeySpec) &&
			(b.EnterpriseProjectID == "" || b.EnterpriseProjectID == "all_granted_eps" || k.EP == b.EnterpriseProjectID) {
			keys = append(keys, k)
		}
	}
	out := listKeysResponse{Keys: []string{}, KeyDetails: []keyDetails{}, Truncated: "false", Total: len(keys)}
	if offset < len(keys) {
		page := keys[offset:min(offset+limit, len(keys))]
		for _, k := range page {
			out.Keys = append(out.Keys, k.ID)
			out.KeyDetails = append(out.KeyDetails, details(k))
		}
		if offset+limit < len(keys) {
			out.Truncated, out.NextMarker = "true", strconv.Itoa(offset+limit)
		}
	}
	return write(w, out)
}

func statusOf(k key) any {
	return struct {
		KeyInfo keyStatus `json:"key_info"`
	}{keyStatus{KeyID: k.ID, KeyState: k.State}}
}

func (s *Service) handleEnableKey(w http.ResponseWriter, r *http.Request, t tenant, k key) error {
	k, err := s.update(r.Context(), t, k.ID, func(k *key) error {
		if k.State != stateDisabled {
			return errNotDisabled
		}
		k.State = stateEnabled
		return nil
	})
	if err != nil {
		return err
	}
	return write(w, statusOf(k))
}

func (s *Service) handleDisableKey(w http.ResponseWriter, r *http.Request, t tenant, k key) error {
	k, err := s.update(r.Context(), t, k.ID, func(k *key) error {
		switch {
		case k.Default:
			return errDefaultKey
		case k.State != stateEnabled:
			return errNotEnabled
		}
		k.State = stateDisabled
		return nil
	})
	if err != nil {
		return err
	}
	return write(w, statusOf(k))
}

func (s *Service) handleScheduleDeletion(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b scheduleDeletionRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	if _, err := s.authorized(r, t, "kms:cmk:scheduleKeyDeletion", b.KeyID); err != nil {
		return err
	}
	switch {
	case !b.PendingDays.set:
		return errMissing
	case b.PendingDays.bad || b.PendingDays.v < minPendingDays || b.PendingDays.v > maxPendingDays:
		return errPendingDays
	}
	at := s.now().UTC().Truncate(time.Millisecond).AddDate(0, 0, b.PendingDays.v)
	k, err := s.update(r.Context(), t, b.KeyID, func(k *key) error {
		switch {
		case k.Default:
			return errDefaultKey
		case k.State == statePendingDeletion:
			return errAlreadyPending
		}
		k.State, k.DeletionAt = statePendingDeletion, at
		return nil
	})
	if err != nil {
		return err
	}
	s.log.InfoContext(r.Context(), "kms key scheduled for deletion", "key_id", k.ID, "at", at)
	return write(w, keyStatus{KeyID: k.ID, KeyState: k.State})
}

func (s *Service) handleCancelDeletion(w http.ResponseWriter, r *http.Request, t tenant, k key) error {
	k, err := s.update(r.Context(), t, k.ID, func(k *key) error {
		if k.State != statePendingDeletion {
			return errNotPending
		}
		// A key whose deletion is cancelled is disabled, as on Huawei
		// Cloud.
		k.State, k.DeletionAt = stateDisabled, time.Time{}
		return nil
	})
	if err != nil {
		return err
	}
	return write(w, keyStatus{KeyID: k.ID, KeyState: k.State})
}

func (s *Service) handleUpdateAlias(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b updateAliasRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	if _, err := s.authorized(r, t, "kms:cmk:updateKeyAlias", b.KeyID); err != nil {
		return err
	}
	if !validAlias(b.KeyAlias) {
		return errAlias
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, err := s.projectKeys(r.Context(), t)
	if err != nil {
		return err
	}
	for _, o := range keys {
		if o.ID != b.KeyID && o.Alias == b.KeyAlias {
			return errDuplicateAlias
		}
	}
	k, err := s.update(r.Context(), t, b.KeyID, func(k *key) error {
		if k.Default {
			return errDefaultKey
		}
		if k.State == statePendingDeletion {
			return errPendingDeletion
		}
		k.Alias = b.KeyAlias
		return nil
	})
	if err != nil {
		return err
	}
	return write(w, struct {
		KeyInfo struct {
			KeyID    string `json:"key_id"`
			KeyAlias string `json:"key_alias"`
		} `json:"key_info"`
	}{KeyInfo: struct {
		KeyID    string `json:"key_id"`
		KeyAlias string `json:"key_alias"`
	}{k.ID, k.Alias}})
}

func (s *Service) handleUpdateDescription(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b updateDescriptionRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	if _, err := s.authorized(r, t, "kms:cmk:updateKeyDescription", b.KeyID); err != nil {
		return err
	}
	if b.KeyDescription == nil {
		return errMissing
	}
	if len(*b.KeyDescription) > maxDescription {
		return errDescription
	}
	k, err := s.update(r.Context(), t, b.KeyID, func(k *key) error {
		if k.Default {
			return errDefaultKey
		}
		if k.State == statePendingDeletion {
			return errPendingDeletion
		}
		k.Description = *b.KeyDescription
		return nil
	})
	if err != nil {
		return err
	}
	type info struct {
		KeyID          string `json:"key_id"`
		KeyDescription string `json:"key_description"`
	}
	return write(w, struct {
		KeyInfo info `json:"key_info"`
	}{info{k.ID, k.Description}})
}

// ---- Cryptography ----

// The documented limits of encrypt-data and decrypt-data.
const (
	maxPlainText  = 4096
	maxAAD        = 128
	minCipherText = 128
	maxCipherText = 5648
)

const algSymmetric = "SYMMETRIC_DEFAULT"

// forEncryption checks a key can encrypt with a symmetric algorithm.
func forEncryption(k key, alg string) error {
	if err := usable(k); err != nil {
		return err
	}
	switch {
	case k.Usage == usageSign:
		return errForSign
	case specs[k.Spec] == asymmetric:
		return errAsymmetricOp // asymmetric encryption: not emulated yet
	case specs[k.Spec] == mac:
		return errParam
	case alg != "" && alg != algSymmetric:
		return errSymmetricAlg
	}
	return nil
}

// envelopeHeader names k's current material.
func envelopeHeader(k key) header {
	v := len(k.Materials) - 1
	h := header{account: keyIDBytes(hexAccount(k.AccountID)), key: keyIDBytes(k.ID)}
	if v >= 0 && v < maxMaterials {
		h.material = uint16(v) //nolint:gosec // bounded just above
	}
	return h
}

// hexAccount formats a 32-hex account ID as a key ID, for keyIDBytes.
func hexAccount(id string) string {
	if len(id) != 32 {
		return id
	}
	return id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
}

// encrypt seals plain with k's current material, rotating it first if
// due.
func (s *Service) encrypt(r *http.Request, t tenant, k key, plain, aad []byte) ([]byte, error) {
	k, err := s.rotateIfDue(r.Context(), t, k)
	if err != nil {
		return nil, err
	}
	m, err := s.material(k, len(k.Materials)-1)
	if err != nil {
		return nil, err
	}
	return seal(k.Spec, m, envelopeHeader(k), plain, aad)
}

// decrypt opens an envelope of k.
func (s *Service) decrypt(k key, h header, b, aad []byte) ([]byte, error) {
	m, err := s.material(k, int(h.material))
	if err != nil {
		return nil, errCipherText
	}
	plain, err := open(k.Spec, m, b, aad)
	if err != nil {
		return nil, errCipherText
	}
	return plain, nil
}

// envelopeKey finds the key an envelope names, checking the action on
// it. A key of another account or project is not found.
func (s *Service) envelopeKey(r *http.Request, t tenant, b []byte, action, keyID string) (key, header, error) {
	h, err := parseHeader(b)
	if err != nil {
		return key{}, header{}, errCipherText
	}
	id := keyIDString(h.key)
	if keyID != "" && keyID != id {
		return key{}, header{}, errCipherText
	}
	k, err := s.authorized(r, t, action, id)
	if err != nil {
		return key{}, header{}, err
	}
	if keyIDBytes(hexAccount(k.AccountID)) != h.account {
		return key{}, header{}, errCipherText
	}
	return k, h, nil
}

func (s *Service) handleEncryptData(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b encryptDataRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	k, err := s.authorized(r, t, "kms:cmk:encryptData", b.KeyID)
	if err != nil {
		return err
	}
	switch {
	case len(b.PlainText) == 0 || len(b.PlainText) > maxPlainText:
		return errPlainText
	case len(b.AdditionalAuthenticatedData) > maxAAD:
		return errParam
	}
	var sealed []byte
	if specs[k.Spec] == asymmetric {
		if err := forAsymmetricEncryption(k); err != nil {
			return err
		}
		priv, err := s.privateKey(k)
		if err != nil {
			return err
		}
		if sealed, err = encryptAsymmetric(priv, b.EncryptionAlgorithm, []byte(b.PlainText)); err != nil {
			return err
		}
	} else {
		if err := forEncryption(k, b.EncryptionAlgorithm); err != nil {
			return err
		}
		if sealed, err = s.encrypt(r, t, k, []byte(b.PlainText), []byte(b.AdditionalAuthenticatedData)); err != nil {
			return err
		}
	}
	return write(w, struct {
		KeyID      string `json:"key_id"`
		CipherText string `json:"cipher_text"`
	}{k.ID, base64.StdEncoding.EncodeToString(sealed)})
}

func (s *Service) handleDecryptData(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b decryptDataRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	if b.CipherText == "" {
		return errMissing
	}
	raw, err := base64.StdEncoding.DecodeString(b.CipherText)
	if err != nil || len(b.CipherText) < minCipherText || len(b.CipherText) > maxCipherText {
		return errCipherText
	}
	if len(b.AdditionalAuthenticatedData) > maxAAD {
		return errParam
	}
	if b.EncryptionAlgorithm == algRSAOAEP || b.EncryptionAlgorithm == algSM2 {
		// Asymmetric ciphertexts do not name their key: the request does.
		return s.decryptAsymmetric(w, r, t, b, raw)
	}
	k, h, err := s.envelopeKey(r, t, raw, "kms:cmk:decryptData", b.KeyID)
	if err != nil {
		return err
	}
	if err := forEncryption(k, b.EncryptionAlgorithm); err != nil {
		return err
	}
	plain, err := s.decrypt(k, h, raw, []byte(b.AdditionalAuthenticatedData))
	if err != nil {
		return err
	}
	return write(w, struct {
		KeyID           string `json:"key_id"`
		PlainText       string `json:"plain_text"`
		PlainTextBase64 string `json:"plain_text_base64"`
	}{k.ID, string(plain), base64.StdEncoding.EncodeToString(plain)})
}

func (s *Service) decryptAsymmetric(w http.ResponseWriter, r *http.Request, t tenant, b decryptDataRequest, raw []byte) error {
	k, err := s.authorized(r, t, "kms:cmk:decryptData", b.KeyID)
	if err != nil {
		return err
	}
	if err := forAsymmetricEncryption(k); err != nil {
		return err
	}
	priv, err := s.privateKey(k)
	if err != nil {
		return err
	}
	plain, err := decryptAsymmetric(priv, b.EncryptionAlgorithm, raw)
	if err != nil {
		return err
	}
	return write(w, struct {
		KeyID           string `json:"key_id"`
		PlainText       string `json:"plain_text"`
		PlainTextBase64 string `json:"plain_text_base64"`
	}{k.ID, string(plain), base64.StdEncoding.EncodeToString(plain)})
}

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeBase64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func hexLower(b []byte) string { return hex.EncodeToString(b) }

// dataKeySpecs are the sizes, in bytes, of the data keys create-datakey
// makes by key_spec.
var dataKeySpecs = map[string]int{
	"AES_256": 32, "AES_128": 16, specSM4: 16,
	specHMAC256: 32, specHMAC384: 48, specHMAC512: 64, specHMACSM3: 32,
}

var errDataKeySpec = kmsErr(http.StatusBadRequest, "KMS.1902", "key_spec can only be AES_128 or AES_256.")

// upperHex is how KMS writes data keys and their ciphertexts.
func upperHex(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func (s *Service) handleCreateDatakey(withPlain bool) handler {
	action := "kms:cmk:createDataKey"
	if !withPlain {
		action = "kms:cmk:createDataKeyWithoutPlaintext"
	}
	return func(w http.ResponseWriter, r *http.Request, t tenant) error {
		var b createDatakeyRequest
		if err := decode(r, &b); err != nil {
			return err
		}
		k, err := s.authorized(r, t, action, b.KeyID)
		if err != nil {
			return err
		}
		size := 32
		switch {
		case b.DatakeyLength.set:
			bits := b.DatakeyLength.v
			if b.DatakeyLength.bad || bits < 8 || bits > 8192 {
				return errDatakeyLength
			}
			if bits%8 != 0 {
				return errDatakeyMultiple
			}
			size = bits / 8
		case b.KeySpec != "":
			n, ok := dataKeySpecs[b.KeySpec]
			if !ok {
				return errDataKeySpec
			}
			size = n
		}
		if len(b.AdditionalAuthenticatedData) > maxAAD {
			return errParam
		}
		if err := forEncryption(k, ""); err != nil {
			return err
		}
		dk, err := random(size)
		if err != nil {
			return err
		}
		sealed, err := s.encrypt(r, t, k, dk, []byte(b.AdditionalAuthenticatedData))
		if err != nil {
			return err
		}
		out := struct {
			KeyID      string `json:"key_id"`
			PlainText  string `json:"plain_text,omitempty"`
			CipherText string `json:"cipher_text"`
		}{KeyID: k.ID, CipherText: upperHex(sealed)}
		if withPlain {
			out.PlainText = upperHex(dk)
		}
		return write(w, out)
	}
}

// maxDataKey is the documented range of a data key's length, in bytes.
const maxDataKey = 1024

func (s *Service) handleEncryptDatakey(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b encryptDatakeyRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	k, err := s.authorized(r, t, "kms:cmk:encryptDataKey", b.KeyID)
	if err != nil {
		return err
	}
	switch {
	case b.PlainText == "" || !b.DatakeyPlainLength.set:
		return errMissing
	case b.DatakeyPlainLength.bad || b.DatakeyPlainLength.v < 1 || b.DatakeyPlainLength.v > maxDataKey:
		return errParam
	case len(b.AdditionalAuthenticatedData) > maxAAD:
		return errParam
	}
	raw, err := hex.DecodeString(b.PlainText)
	if err != nil {
		return errPlainText
	}
	if err := forEncryption(k, ""); err != nil {
		return err
	}
	// The plain text is the data key followed by its hash: SHA-256, or
	// SM3 for an SM4 key.
	n := b.DatakeyPlainLength.v
	h := digest(k.Spec)
	if len(raw) != n+h.Size() {
		return errPlainLength
	}
	dk := raw[:n]
	h.Write(dk)
	if !hmac.Equal(h.Sum(nil), raw[n:]) {
		return errDEKHash
	}
	sealed, err := s.encrypt(r, t, k, dk, []byte(b.AdditionalAuthenticatedData))
	if err != nil {
		return err
	}
	return write(w, struct {
		KeyID         string `json:"key_id"`
		CipherText    string `json:"cipher_text"`
		DatakeyLength string `json:"datakey_length"`
	}{k.ID, upperHex(sealed), strconv.Itoa(n)})
}

func (s *Service) handleDecryptDatakey(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b decryptDatakeyRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	switch {
	case b.KeyID == "" || b.CipherText == "" || !b.DatakeyCipherLength.set:
		return errMissing
	case b.DatakeyCipherLength.bad || b.DatakeyCipherLength.v < 1 || b.DatakeyCipherLength.v > maxDataKey:
		return errParam
	case len(b.AdditionalAuthenticatedData) > maxAAD:
		return errParam
	}
	raw, err := hex.DecodeString(b.CipherText)
	if err != nil {
		return errCipherText
	}
	k, h, err := s.envelopeKey(r, t, raw, "kms:cmk:decryptDataKey", b.KeyID)
	if err != nil {
		return err
	}
	if err := forEncryption(k, ""); err != nil {
		return err
	}
	dk, err := s.decrypt(k, h, raw, []byte(b.AdditionalAuthenticatedData))
	if err != nil {
		return err
	}
	if len(dk) != b.DatakeyCipherLength.v {
		return errCipherLength
	}
	d := digest(k.Spec)
	d.Write(dk)
	return write(w, struct {
		DataKey       string `json:"data_key"`
		DatakeyLength string `json:"datakey_length"`
		DatakeyDgst   string `json:"datakey_dgst"`
	}{upperHex(dk), strconv.Itoa(len(dk)), upperHex(d.Sum(nil))})
}

func (s *Service) handleGenRandom(w http.ResponseWriter, r *http.Request, _ tenant) error {
	var b struct {
		RandomDataLength number `json:"random_data_length"`
	}
	if err := decode(r, &b); err != nil {
		return err
	}
	if !b.RandomDataLength.set {
		return errMissing
	}
	if b.RandomDataLength.bad || b.RandomDataLength.v != 512 {
		return errRandomLength
	}
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	return write(w, struct {
		RandomData string `json:"random_data"`
	}{upperHex(buf)})
}
