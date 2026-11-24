package kps

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func mustGenTestRSA(t *testing.T) (pubStr, privPEM string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), string(pem.EncodeToMemory(block))
}

func mustCreateKMSKey(t *testing.T, e *env, alias string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"key_alias": alias})
	if err != nil {
		t.Fatalf("marshal kms create-key: %v", err)
	}
	status, raw := e.call(t, http.MethodPost, "/v1.0/{project}/kms/create-key", string(body))
	if status != http.StatusOK {
		t.Fatalf("kms create-key status = %d, body = %s", status, raw)
	}
	resp := decodeInto[struct {
		KeyInfo struct {
			KeyID string `json:"key_id"`
		} `json:"key_info"`
	}](t, raw)
	if resp.KeyInfo.KeyID == "" {
		t.Fatalf("empty key_id from kms create-key: %s", raw)
	}
	return resp.KeyInfo.KeyID
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

func TestProtectionDefaultAndKMSRoundTrip(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	t.Run("create_default_protection", func(t *testing.T) {
		reqBody := mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name: "kp-default",
				KeyProtection: &keyProtectionWire{
					Encryption: &encryptionWire{Type: "default"},
				},
			},
		})
		status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", reqBody)
		if status != http.StatusOK {
			t.Fatalf("create status = %d, body = %s", status, raw)
		}
		created := decodeInto[createKeypairResponse](t, raw)
		if created.Keypair.PrivateKey == "" {
			t.Fatal("expected generated private_key in create response")
		}

		stored, err := e.svc.keypairs(testTenant).Get(ctx, "kp-default")
		if err != nil {
			t.Fatalf("store Get: %v", err)
		}
		if stored.Protection != "default" || len(stored.SealedKey) == 0 {
			t.Fatalf("unexpected stored protection: %q len=%d", stored.Protection, len(stored.SealedKey))
		}
		if bytes.Contains(stored.SealedKey, []byte("PRIVATE KEY")) || bytes.Contains(stored.SealedKey, []byte(created.Keypair.PrivateKey)) {
			t.Fatal("stored SealedKey must not contain plaintext PEM")
		}

		expStatus, expRaw := e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kp-default"}}`)
		if expStatus != http.StatusOK {
			t.Fatalf("export status = %d, body = %s", expStatus, expRaw)
		}
		exported := decodeInto[exportPrivateKeyResponse](t, expRaw)
		if exported.Keypair.PrivateKey != created.Keypair.PrivateKey {
			t.Fatal("exported private key does not match created private key")
		}
	})

	t.Run("create_kms_by_key_id_and_disable", func(t *testing.T) {
		keyID := mustCreateKMSKey(t, e, "kps-test-by-id")

		reqBody := mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name: "kp-kms-id",
				KeyProtection: &keyProtectionWire{
					Encryption: &encryptionWire{
						Type:     "kms",
						KMSKeyID: keyID,
					},
				},
			},
		})
		status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", reqBody)
		if status != http.StatusOK {
			t.Fatalf("create status = %d, body = %s", status, raw)
		}
		created := decodeInto[createKeypairResponse](t, raw)

		stored, err := e.svc.keypairs(testTenant).Get(ctx, "kp-kms-id")
		if err != nil {
			t.Fatalf("store Get: %v", err)
		}
		if stored.Protection != "kms" || stored.KMSKeyID != keyID {
			t.Fatalf("unexpected KMS metadata: protection=%q kms_key_id=%q want %q", stored.Protection, stored.KMSKeyID, keyID)
		}
		if bytes.Contains(stored.SealedKey, []byte("PRIVATE KEY")) || bytes.Contains(stored.SealedKey, []byte(created.Keypair.PrivateKey)) {
			t.Fatal("stored KMS SealedKey must not contain plaintext PEM")
		}

		// Detail exposes key_id and is_key_protection = true.
		detStatus, detRaw := e.call(t, http.MethodGet, "/v3/{project}/keypairs/kp-kms-id", "")
		if detStatus != http.StatusOK {
			t.Fatalf("detail status = %d, body = %s", detStatus, detRaw)
		}
		detail := decodeInto[listKeypairDetailResponse](t, detRaw)
		if !detail.Keypair.IsKeyProtection || detail.Keypair.KeyID != keyID {
			t.Fatalf("detail = %+v, want IsKeyProtection=true KeyID=%q", detail.Keypair, keyID)
		}

		// Export succeeds while KMS key is enabled.
		expStatus, expRaw := e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kp-kms-id"}}`)
		if expStatus != http.StatusOK {
			t.Fatalf("export status = %d, body = %s", expStatus, expRaw)
		}
		exported := decodeInto[exportPrivateKeyResponse](t, expRaw)
		if exported.Keypair.PrivateKey != created.Keypair.PrivateKey {
			t.Fatal("exported KMS private key does not match created private key")
		}

		// Disabling the KMS key makes export fail with 400 KPS.6008.
		disStatus, disRaw := e.call(t, http.MethodPost, "/v1.0/{project}/kms/disable-key", mustJSON(t, map[string]string{"key_id": keyID}))
		if disStatus != http.StatusOK {
			t.Fatalf("kms disable-key status = %d, body = %s", disStatus, disRaw)
		}
		e.expect(t, "protection_export_encrypt_failed", http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kp-kms-id"}}`)

		// Re-enabling restores export.
		enStatus, enRaw := e.call(t, http.MethodPost, "/v1.0/{project}/kms/enable-key", mustJSON(t, map[string]string{"key_id": keyID}))
		if enStatus != http.StatusOK {
			t.Fatalf("kms enable-key status = %d, body = %s", enStatus, enRaw)
		}
		expStatus, expRaw = e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kp-kms-id"}}`)
		if expStatus != http.StatusOK {
			t.Fatalf("export after re-enable status = %d, body = %s", expStatus, expRaw)
		}
		exported = decodeInto[exportPrivateKeyResponse](t, expRaw)
		if exported.Keypair.PrivateKey != created.Keypair.PrivateKey {
			t.Fatal("exported KMS private key after re-enable does not match")
		}
	})

	t.Run("create_kms_by_custom_alias", func(t *testing.T) {
		keyID := mustCreateKMSKey(t, e, "kps-custom-alias")
		pub, priv := mustGenTestRSA(t)

		reqBody := mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name:      "kp-kms-alias",
				PublicKey: pub,
				KeyProtection: &keyProtectionWire{
					PrivateKey: priv,
					Encryption: &encryptionWire{
						Type:       "kms",
						KMSKeyName: "kps-custom-alias",
					},
				},
			},
		})
		status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", reqBody)
		if status != http.StatusOK {
			t.Fatalf("create status = %d, body = %s", status, raw)
		}

		stored, err := e.svc.keypairs(testTenant).Get(ctx, "kp-kms-alias")
		if err != nil {
			t.Fatalf("store Get: %v", err)
		}
		if stored.KMSKeyID != keyID {
			t.Fatalf("stored KMSKeyID = %q, want %q", stored.KMSKeyID, keyID)
		}

		expStatus, expRaw := e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kp-kms-alias"}}`)
		if expStatus != http.StatusOK {
			t.Fatalf("export status = %d, body = %s", expStatus, expRaw)
		}
		exported := decodeInto[exportPrivateKeyResponse](t, expRaw)
		if exported.Keypair.PrivateKey != priv {
			t.Fatal("exported private key via custom alias does not match")
		}
	})

	t.Run("create_kms_default_alias", func(t *testing.T) {
		reqBody := mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name: "kp-kms-default",
				KeyProtection: &keyProtectionWire{
					Encryption: &encryptionWire{
						Type:       "kms",
						KMSKeyName: "kps/default",
					},
				},
			},
		})
		status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", reqBody)
		if status != http.StatusOK {
			t.Fatalf("create status = %d, body = %s", status, raw)
		}
		created := decodeInto[createKeypairResponse](t, raw)

		stored, err := e.svc.keypairs(testTenant).Get(ctx, "kp-kms-default")
		if err != nil {
			t.Fatalf("store Get: %v", err)
		}
		if stored.Protection != "kms" || stored.KMSKeyID == "" {
			t.Fatalf("expected kms protection with generated default key ID, got %+v", stored)
		}

		expStatus, expRaw := e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kp-kms-default"}}`)
		if expStatus != http.StatusOK {
			t.Fatalf("export status = %d, body = %s", expStatus, expRaw)
		}
		exported := decodeInto[exportPrivateKeyResponse](t, expRaw)
		if exported.Keypair.PrivateKey != created.Keypair.PrivateKey {
			t.Fatal("exported private key via kps/default does not match")
		}
	})

	t.Run("kms_validation_and_errors", func(t *testing.T) {
		// kms without kms_key_id or kms_key_name -> 400 KPS.0002
		reqMissing := mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name: "kp-kms-no-key",
				KeyProtection: &keyProtectionWire{
					Encryption: &encryptionWire{Type: "kms"},
				},
			},
		})
		e.expect(t, "protection_import_bad_param", http.MethodPost, "/v3/{project}/keypairs", reqMissing)

		// unknown kms alias -> 400 KPS.6008
		reqUnknown := mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name: "kp-kms-unknown",
				KeyProtection: &keyProtectionWire{
					Encryption: &encryptionWire{Type: "kms", KMSKeyName: "does-not-exist"},
				},
			},
		})
		e.expect(t, "protection_export_encrypt_failed", http.MethodPost, "/v3/{project}/keypairs", reqUnknown)

		// invalid encryption type -> 400 KPS.0002
		reqBadType := mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name: "kp-bad-enc",
				KeyProtection: &keyProtectionWire{
					Encryption: &encryptionWire{Type: "invalid"},
				},
			},
		})
		e.expect(t, "protection_import_bad_param", http.MethodPost, "/v3/{project}/keypairs", reqBadType)
	})
}

func TestProtectionImportExportClearGolden(t *testing.T) {
	e := newEnv(t)
	pub1, priv1 := mustGenTestRSA(t)
	_, privOther := mustGenTestRSA(t)

	// Create unprotected keypair kp-import by importing public key only.
	createBody := mustJSON(t, createKeypairRequest{
		Keypair: &createKeypairAction{
			Name:      "kp-import",
			PublicKey: pub1,
		},
	})
	status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", createBody)
	if status != http.StatusOK {
		t.Fatalf("create kp-import status = %d, body = %s", status, raw)
	}

	// Export before private key is imported -> 400 KPS.6005.
	e.expect(t, "protection_export_no_private_key", http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kp-import"}}`)

	// Import mismatched private key -> 400 KPS.6011.
	mismatchBody := mustJSON(t, importPrivateKeyRequest{
		Keypair: &importPrivateKeyAction{
			Name: "kp-import",
			KeyProtection: &keyProtectionWire{
				PrivateKey: privOther,
				Encryption: &encryptionWire{Type: "default"},
			},
		},
	})
	e.expect(t, "protection_import_mismatch", http.MethodPost, "/v3/{project}/keypairs/private-key/import", mismatchBody)

	// Import unparseable private key -> 400 KPS.6011.
	garbageBody := mustJSON(t, importPrivateKeyRequest{
		Keypair: &importPrivateKeyAction{
			Name: "kp-import",
			KeyProtection: &keyProtectionWire{
				PrivateKey: "not-a-private-key",
				Encryption: &encryptionWire{Type: "default"},
			},
		},
	})
	e.expect(t, "protection_import_mismatch", http.MethodPost, "/v3/{project}/keypairs/private-key/import", garbageBody)

	// Import for missing keypair -> 404 KPS.6004.
	missingImportBody := mustJSON(t, importPrivateKeyRequest{
		Keypair: &importPrivateKeyAction{
			Name: "no-such-kp",
			KeyProtection: &keyProtectionWire{
				PrivateKey: priv1,
				Encryption: &encryptionWire{Type: "default"},
			},
		},
	})
	e.expect(t, "protection_import_not_found", http.MethodPost, "/v3/{project}/keypairs/private-key/import", missingImportBody)

	// Import with bad params -> 400 KPS.0002.
	e.expect(t, "protection_import_bad_param", http.MethodPost, "/v3/{project}/keypairs/private-key/import", `{"keypair":{"name":"kp-import"}}`)
	e.expect(t, "protection_import_bad_param", http.MethodPost, "/v3/{project}/keypairs/private-key/import", `{bad-json`)

	// Import matching private key -> 200 OK, golden verifies private_key is NOT echoed.
	validImportBody := mustJSON(t, importPrivateKeyRequest{
		Keypair: &importPrivateKeyAction{
			Name: "kp-import",
			KeyProtection: &keyProtectionWire{
				PrivateKey: priv1,
				Encryption: &encryptionWire{Type: "default"},
			},
		},
	})
	e.expect(t, "protection_import_ok", http.MethodPost, "/v3/{project}/keypairs/private-key/import", validImportBody)

	// Detail now reports is_key_protection = true.
	detStatus, detRaw := e.call(t, http.MethodGet, "/v3/{project}/keypairs/kp-import", "")
	if detStatus != http.StatusOK {
		t.Fatalf("detail status = %d, body = %s", detStatus, detRaw)
	}
	if det := decodeInto[listKeypairDetailResponse](t, detRaw); !det.Keypair.IsKeyProtection {
		t.Fatal("expected is_key_protection=true after ImportPrivateKey")
	}

	// Export missing keypair -> 404 KPS.6004.
	e.expect(t, "protection_export_not_found", http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"no-such-kp"}}`)

	// Create kp-export with protection and verify ExportPrivateKey golden.
	expCreateBody := mustJSON(t, createKeypairRequest{
		Keypair: &createKeypairAction{
			Name: "kp-export",
			KeyProtection: &keyProtectionWire{
				Encryption: &encryptionWire{Type: "default"},
			},
		},
	})
	status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs", expCreateBody)
	if status != http.StatusOK {
		t.Fatalf("create kp-export status = %d, body = %s", status, raw)
	}
	createdExp := decodeInto[createKeypairResponse](t, raw)

	expOut := e.expect(t, "protection_export_ok", http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kp-export"}}`)
	if got := decodeInto[exportPrivateKeyResponse](t, expOut); got.Keypair.PrivateKey != createdExp.Keypair.PrivateKey {
		t.Fatal("exported private key mismatch")
	}

	// Clear private key -> 200 empty body.
	e.expect(t, "protection_clear_ok", http.MethodDelete, "/v3/{project}/keypairs/kp-import/private-key", "")

	// Detail now reports is_key_protection = false.
	detStatus, detRaw = e.call(t, http.MethodGet, "/v3/{project}/keypairs/kp-import", "")
	if detStatus != http.StatusOK {
		t.Fatalf("detail after clear status = %d, body = %s", detStatus, detRaw)
	}
	if det := decodeInto[listKeypairDetailResponse](t, detRaw); det.Keypair.IsKeyProtection {
		t.Fatal("expected is_key_protection=false after ClearPrivateKey")
	}

	// Export after clear -> 400 KPS.6005.
	e.expect(t, "protection_export_no_private_key", http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kp-import"}}`)

	// Clear missing keypair -> 404 KPS.6004.
	e.expect(t, "protection_clear_not_found", http.MethodDelete, "/v3/{project}/keypairs/no-such-kp/private-key", "")
}

func TestProtectionBatchImport(t *testing.T) {
	e := newEnv(t)
	pub1, _ := mustGenTestRSA(t)
	pub2, _ := mustGenTestRSA(t)

	// Pre-create dup-kp so it collides during batch import.
	status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
		Keypair: &createKeypairAction{Name: "dup-kp", PublicKey: pub1},
	}))
	if status != http.StatusOK {
		t.Fatalf("seed dup-kp status = %d, body = %s", status, raw)
	}

	batchReq := mustJSON(t, []createKeypairRequest{
		{Keypair: &createKeypairAction{Name: "dup-kp", PublicKey: pub1}},
		{Keypair: &createKeypairAction{Name: "new-kp", PublicKey: pub2}},
	})
	e.expect(t, "protection_batch_import_ok", http.MethodPost, "/v3/{project}/keypairs/batch-import", batchReq)

	// Empty array -> 400 KPS.0002.
	e.expect(t, "protection_import_bad_param", http.MethodPost, "/v3/{project}/keypairs/batch-import", `[]`)

	// More than 10 items -> 400 KPS.0002.
	tooMany := make([]createKeypairRequest, 11)
	for i := range tooMany {
		tooMany[i] = createKeypairRequest{Keypair: &createKeypairAction{Name: "kp-too-many", PublicKey: pub1}}
	}
	e.expect(t, "protection_import_bad_param", http.MethodPost, "/v3/{project}/keypairs/batch-import", mustJSON(t, tooMany))

	// Nil keypair element records per-item KPS.0002 failure without aborting batch.
	status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs/batch-import", `[{}]`)
	if status != http.StatusOK {
		t.Fatalf("nil item batch status = %d, body = %s", status, raw)
	}
	res := decodeInto[batchImportResponse](t, raw)
	if len(res.FailedKeypairs) != 1 || !strings.Contains(res.FailedKeypairs[0].FailedReason, "KPS.0002") {
		t.Fatalf("unexpected nil item result: %+v", res)
	}
	if res.SucceededKeypairs == nil || len(res.SucceededKeypairs) != 0 {
		t.Fatalf("expected non-nil empty succeeded_keypairs, got %+v", res.SucceededKeypairs)
	}
}

func TestProtectionBatchExport(t *testing.T) {
	e := newEnv(t)

	// Create two protected keypairs (one default, one KMS) and one unprotected keypair.
	status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
		Keypair: &createKeypairAction{
			Name: "exp-default",
			KeyProtection: &keyProtectionWire{
				Encryption: &encryptionWire{Type: "default"},
			},
		},
	}))
	if status != http.StatusOK {
		t.Fatalf("create exp-default status = %d, body = %s", status, raw)
	}
	privDefault := decodeInto[createKeypairResponse](t, raw).Keypair.PrivateKey

	keyID := mustCreateKMSKey(t, e, "kps-batch-export")
	status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
		Keypair: &createKeypairAction{
			Name: "exp-kms",
			KeyProtection: &keyProtectionWire{
				Encryption: &encryptionWire{Type: "kms", KMSKeyID: keyID},
			},
		},
	}))
	if status != http.StatusOK {
		t.Fatalf("create exp-kms status = %d, body = %s", status, raw)
	}
	privKMS := decodeInto[createKeypairResponse](t, raw).Keypair.PrivateKey

	status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
		Keypair: &createKeypairAction{Name: "exp-none"},
	}))
	if status != http.StatusOK {
		t.Fatalf("create exp-none status = %d, body = %s", status, raw)
	}

	// Execute batch export using httptest directly so we can inspect headers as well as body.
	reqBody := `[{"keypair":{"name":"exp-default"}},{"keypair":{"name":"exp-kms"}}]`
	req := httptest.NewRequest(http.MethodPost, "/v3/"+testProject+"/keypairs/private-key/batch-export", strings.NewReader(reqBody))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("batch-export status = %d, body = %s", res.StatusCode, b)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type = %q, want application/zip", ct)
	}
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "keypairs.zip") {
		t.Fatalf("Content-Disposition = %q, want filename keypairs.zip", cd)
	}

	zipBytes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading zip body: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	files := make(map[string]string, len(zr.File))
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open zip entry %s: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read zip entry %s: %v", f.Name, err)
		}
		files[f.Name] = string(data)
	}
	if len(files) != 2 {
		t.Fatalf("zip entry count = %d, want 2", len(files))
	}
	if files["exp-default.pem"] != privDefault {
		t.Fatal("exp-default.pem content does not match private key")
	}
	if files["exp-kms.pem"] != privKMS {
		t.Fatal("exp-kms.pem content does not match private key")
	}

	// Error cases.
	e.expect(t, "protection_export_no_private_key", http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":"exp-none"}}]`)
	e.expect(t, "protection_export_not_found", http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":"no-such-kp"}}]`)
	e.expect(t, "protection_import_bad_param", http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[]`)
	e.expect(t, "protection_import_bad_param", http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":""}}]`)

	// Disabling KMS key fails batch-export with 400 KPS.6008.
	disStatus, disRaw := e.call(t, http.MethodPost, "/v1.0/{project}/kms/disable-key", mustJSON(t, map[string]string{"key_id": keyID}))
	if disStatus != http.StatusOK {
		t.Fatalf("kms disable-key status = %d, body = %s", disStatus, disRaw)
	}
	e.expect(t, "protection_export_encrypt_failed", http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":"exp-kms"}}]`)
}

func TestProtectionNoSecretsInLogs(t *testing.T) {
	e := newEnv(t)
	pub, priv := mustGenTestRSA(t)

	// 1. Create generated keypair with default protection.
	status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
		Keypair: &createKeypairAction{
			Name: "log-gen",
			KeyProtection: &keyProtectionWire{
				Encryption: &encryptionWire{Type: "default"},
			},
		},
	}))
	if status != http.StatusOK {
		t.Fatalf("create log-gen status = %d, body = %s", status, raw)
	}
	genPriv := decodeInto[createKeypairResponse](t, raw).Keypair.PrivateKey

	// 2. Create public-only keypair, then ImportPrivateKey with KMS.
	status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
		Keypair: &createKeypairAction{Name: "log-imp", PublicKey: pub},
	}))
	if status != http.StatusOK {
		t.Fatalf("create log-imp status = %d, body = %s", status, raw)
	}
	status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/import", mustJSON(t, importPrivateKeyRequest{
		Keypair: &importPrivateKeyAction{
			Name: "log-imp",
			KeyProtection: &keyProtectionWire{
				PrivateKey: priv,
				Encryption: &encryptionWire{Type: "kms", KMSKeyName: "kps/default"},
			},
		},
	}))
	if status != http.StatusOK {
		t.Fatalf("import log-imp status = %d, body = %s", status, raw)
	}

	// 3. Export both individually.
	for _, name := range []string{"log-gen", "log-imp"} {
		status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"`+name+`"}}`)
		if status != http.StatusOK {
			t.Fatalf("export %s status = %d, body = %s", name, status, raw)
		}
	}

	// 4. Batch export both.
	status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":"log-gen"}},{"keypair":{"name":"log-imp"}}]`)
	if status != http.StatusOK {
		t.Fatalf("batch-export status = %d, body = %s", status, raw)
	}

	// Inspect all debug/info/error logs emitted during the session.
	logText := e.logs.String()
	if strings.Contains(logText, "PRIVATE KEY") {
		t.Fatalf("logs contain PRIVATE KEY marker:\n%s", logText)
	}
	// Also check a distinctive body slice from each private key PEM.
	for _, pemStr := range []string{genPriv, priv} {
		lines := strings.Split(strings.TrimSpace(pemStr), "\n")
		if len(lines) > 2 && strings.Contains(logText, lines[1]) {
			t.Fatalf("logs leaked private key body line:\n%s", logText)
		}
	}
}

func TestProtectionVerifyKeyPairMatchEd25519(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub1, err := ssh.NewPublicKey(pub1)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub1)))

	block1, err := ssh.MarshalPrivateKey(priv1, "")
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKey: %v", err)
	}
	block2, err := ssh.MarshalPrivateKey(priv2, "")
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKey: %v", err)
	}

	if err := verifyKeyPairMatch(pubStr, string(pem.EncodeToMemory(block1))); err != nil {
		t.Fatalf("matching ed25519 keypair failed: %v", err)
	}
	if err := verifyKeyPairMatch(pubStr, string(pem.EncodeToMemory(block2))); !errors.Is(err, errKeyMismatch) {
		t.Fatalf("mismatched ed25519 keypair err = %v, want errKeyMismatch", err)
	}
}
