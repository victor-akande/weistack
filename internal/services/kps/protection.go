package kps

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/ssh"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	vaultPrivateKeyLabel = "weistack:kps:private-key"
	maxBatchKeypairs     = 10
	maxSealedDataKeyLen  = 1 << 20
)

func verifyKeyPairMatch(pubKeyStr, privPEM string) error {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		return errParam
	}
	signer, err := ssh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		return errKeyMismatch
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
		return errKeyMismatch
	}
	return nil
}

func (s *Service) sealPrivateKey(ctx context.Context, t Tenant, kp *Keypair, privatePEM string, enc *encryptionWire) error {
	if enc == nil {
		return errParam
	}
	encType := enc.Type
	if encType == "" {
		encType = "default"
	}
	switch encType {
	case "default":
		sealed, err := s.vault.Seal(privatePEM, vaultPrivateKeyLabel)
		if err != nil {
			return errEncryptFailed
		}
		kp.Protection = "default"
		kp.KMSKeyID = ""
		kp.SealedKey = sealed
		return nil
	case "kms":
		if enc.KMSKeyID == "" && enc.KMSKeyName == "" {
			return errParam
		}
		if s.keys == nil {
			return errEncryptFailed
		}
		var keyID string
		switch {
		case enc.KMSKeyID != "":
			keyID = enc.KMSKeyID
		case enc.KMSKeyName == "kps/default":
			keyID = ""
		default:
			resolved, err := s.keys.ResolveAlias(ctx, t.Region, enc.KMSKeyName)
			if err != nil {
				return errEncryptFailed
			}
			keyID = resolved
		}
		dk, err := s.keys.NewDataKey(ctx, t.Region, keyID, "kps")
		if err != nil {
			return errEncryptFailed
		}
		defer clear(dk.Plain)

		if len(dk.Sealed) == 0 || len(dk.Sealed) > maxSealedDataKeyLen {
			return errEncryptFailed
		}
		gcmPayload, err := encryptAESGCM(dk.Plain, []byte(privatePEM), []byte(vaultPrivateKeyLabel))
		if err != nil {
			return errEncryptFailed
		}
		packed := make([]byte, 4+len(dk.Sealed)+len(gcmPayload))
		binary.BigEndian.PutUint32(packed[:4], uint32(len(dk.Sealed))) //nolint:gosec // length bounded by maxSealedDataKeyLen
		copy(packed[4:], dk.Sealed)
		copy(packed[4+len(dk.Sealed):], gcmPayload)

		kp.Protection = "kms"
		kp.KMSKeyID = dk.KeyID
		kp.SealedKey = packed
		return nil
	default:
		return errParam
	}
}

func (s *Service) openPrivateKey(ctx context.Context, t Tenant, kp Keypair) (string, error) {
	if len(kp.SealedKey) == 0 {
		return "", errNoPrivateKey
	}
	switch kp.Protection {
	case "default":
		plain, err := s.vault.Open(kp.SealedKey, vaultPrivateKeyLabel)
		if err != nil {
			return "", errEncryptFailed
		}
		return plain, nil
	case "kms":
		if s.keys == nil {
			return "", errEncryptFailed
		}
		if len(kp.SealedKey) < 4 {
			return "", errEncryptFailed
		}
		dkLen := int(binary.BigEndian.Uint32(kp.SealedKey[:4]))
		if dkLen <= 0 || len(kp.SealedKey)-4 < dkLen {
			return "", errEncryptFailed
		}
		dkSealed := kp.SealedKey[4 : 4+dkLen]
		gcmPayload := kp.SealedKey[4+dkLen:]

		plainKey, err := s.keys.OpenDataKey(ctx, t.Region, dkSealed)
		if err != nil {
			return "", errEncryptFailed
		}
		defer clear(plainKey)

		plain, err := decryptAESGCM(plainKey, gcmPayload, []byte(vaultPrivateKeyLabel))
		if err != nil {
			return "", errEncryptFailed
		}
		return string(plain), nil
	default:
		return "", errNoPrivateKey
	}
}

func encryptAESGCM(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func decryptAESGCM(key, payload, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(payload) < n {
		return nil, errors.New("kps: truncated ciphertext")
	}
	return aead.Open(nil, payload[:n], payload[n:], aad)
}

func (s *Service) handleImportPrivateKey(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req importPrivateKeyRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return errParam
	}
	if req.Keypair == nil || req.Keypair.Name == "" ||
		req.Keypair.KeyProtection == nil ||
		req.Keypair.KeyProtection.PrivateKey == "" ||
		req.Keypair.KeyProtection.Encryption == nil {
		return errParam
	}

	ctx := r.Context()
	kp, err := s.getKeypair(ctx, t, req.Keypair.Name)
	if err != nil {
		return err
	}
	if err := verifyKeyPairMatch(kp.PublicKey, req.Keypair.KeyProtection.PrivateKey); err != nil {
		return err
	}

	next := kp
	if err := s.sealPrivateKey(ctx, t, &next, req.Keypair.KeyProtection.PrivateKey, req.Keypair.KeyProtection.Encryption); err != nil {
		return err
	}

	now := s.clock().UTC().UnixMilli()
	_, err = s.keypairs(t).Update(ctx, kp.Name, func(cur *Keypair) error {
		if !s.isVisible(ctx, *cur) {
			return errNotFound
		}
		cur.Protection = next.Protection
		cur.KMSKeyID = next.KMSKeyID
		cur.SealedKey = next.SealedKey
		cur.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}

	return httpx.WriteJSON(w, http.StatusOK, importPrivateKeyResponse{
		Keypair: importPrivateKeyAction{Name: kp.Name},
	})
}

func (s *Service) handleExportPrivateKey(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req exportPrivateKeyRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return errParam
	}
	if req.Keypair == nil || req.Keypair.Name == "" {
		return errParam
	}

	ctx := r.Context()
	kp, err := s.getKeypair(ctx, t, req.Keypair.Name)
	if err != nil {
		return err
	}
	privPEM, err := s.openPrivateKey(ctx, t, kp)
	if err != nil {
		return err
	}

	return httpx.WriteJSON(w, http.StatusOK, exportPrivateKeyResponse{
		Keypair: exportPrivateKeyResp{
			Name:       kp.Name,
			PrivateKey: privPEM,
		},
	})
}

func (s *Service) handleClearPrivateKey(w http.ResponseWriter, r *http.Request, t Tenant) error {
	name := chi.URLParam(r, "keypair_name")
	ctx := r.Context()
	kp, err := s.getKeypair(ctx, t, name)
	if err != nil {
		return err
	}

	now := s.clock().UTC().UnixMilli()
	_, err = s.keypairs(t).Update(ctx, kp.Name, func(cur *Keypair) error {
		if !s.isVisible(ctx, *cur) {
			return errNotFound
		}
		cur.Protection = ""
		cur.KMSKeyID = ""
		cur.SealedKey = nil
		cur.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func formatFailedReason(err error) string {
	ae := apierr.From(err)
	raw, encErr := json.Marshal(struct {
		ErrorCode string `json:"error_code"`
		ErrorMsg  string `json:"error_msg"`
	}{
		ErrorCode: ae.Code,
		ErrorMsg:  ae.Message,
	})
	if encErr != nil {
		return `{"error_code":"KPS.0002","error_msg":"parameter error."}`
	}
	return string(raw)
}

func (s *Service) handleBatchImportKeypair(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var items []createKeypairRequest
	if err := httpx.DecodeJSON(r, &items); err != nil {
		return errParam
	}
	if len(items) == 0 || len(items) > maxBatchKeypairs {
		return errParam
	}

	resp := batchImportResponse{
		FailedKeypairs:    []failedKeypairWire{},
		SucceededKeypairs: []createKeypairResponse{},
	}

	ctx := r.Context()
	for _, item := range items {
		if item.Keypair == nil {
			resp.FailedKeypairs = append(resp.FailedKeypairs, failedKeypairWire{
				KeypairName:  "",
				FailedReason: formatFailedReason(errParam),
			})
			continue
		}
		kp, privKey, err := s.createKeypair(ctx, t, *item.Keypair)
		if err != nil {
			resp.FailedKeypairs = append(resp.FailedKeypairs, failedKeypairWire{
				KeypairName:  item.Keypair.Name,
				FailedReason: formatFailedReason(err),
			})
			continue
		}
		resp.SucceededKeypairs = append(resp.SucceededKeypairs, createKeypairResponse{
			Keypair: createKeypairResp{
				Name:        kp.Name,
				Type:        kp.Type,
				PublicKey:   kp.PublicKey,
				PrivateKey:  privKey,
				Fingerprint: kp.Fingerprint,
				UserID:      kp.UserID,
			},
		})
	}

	return httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Service) handleBatchExportPrivateKey(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var items []batchExportItem
	if err := httpx.DecodeJSON(r, &items); err != nil {
		return errParam
	}
	if len(items) == 0 || len(items) > maxBatchKeypairs {
		return errParam
	}

	type exportedEntry struct {
		name string
		pem  string
	}
	ctx := r.Context()
	entries := make([]exportedEntry, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item.Keypair == nil || item.Keypair.Name == "" {
			return errParam
		}
		kp, err := s.getKeypair(ctx, t, item.Keypair.Name)
		if err != nil {
			return err
		}
		privPEM, err := s.openPrivateKey(ctx, t, kp)
		if err != nil {
			return err
		}
		if _, dup := seen[kp.Name]; dup {
			continue
		}
		seen[kp.Name] = struct{}{}
		entries = append(entries, exportedEntry{name: kp.Name, pem: privPEM})
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, entry := range entries {
		fw, err := zw.Create(entry.name + ".pem")
		if err != nil {
			return fmt.Errorf("creating zip entry: %w", err)
		}
		if _, err := io.WriteString(fw, entry.pem); err != nil {
			return fmt.Errorf("writing zip entry: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("closing zip archive: %w", err)
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="keypairs.zip"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
	return nil
}
