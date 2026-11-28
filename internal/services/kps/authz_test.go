package kps

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/ecs"
)

type staticGrants struct {
	doc string
}

func (g staticGrants) Grants(context.Context, identity.Principal, authz.Scope) (authz.Grants, error) {
	p, err := policydoc.Parse([]byte(g.doc))
	if err != nil {
		return authz.Grants{}, err
	}
	return authz.Grants{
		Sources: []policydoc.Source{{Name: "kps-list-only", Policy: p}},
	}, nil
}

type scopedGrants struct {
	byService map[string][]policydoc.Source
}

func newScopedGrants(t *testing.T, kpsDoc, kmsDoc string) scopedGrants {
	t.Helper()
	parse := func(name, raw string) []policydoc.Source {
		if raw == "" {
			return nil
		}
		p, err := policydoc.Parse([]byte(raw))
		if err != nil {
			t.Fatalf("parse policy %s: %v", name, err)
		}
		return []policydoc.Source{{Name: name, Policy: p}}
	}
	kpsSrc := parse("kps-policy", kpsDoc)
	kmsSrc := slices.Concat(kpsSrc, parse("kms-policy", kmsDoc))
	return scopedGrants{
		byService: map[string][]policydoc.Source{
			"kps": kpsSrc,
			"kms": kmsSrc,
		},
	}
}

func (g scopedGrants) Grants(_ context.Context, _ identity.Principal, s authz.Scope) (authz.Grants, error) {
	return authz.Grants{Sources: g.byService[s.Service]}, nil
}

func TestEnforcePermissions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	r := chi.NewRouter()
	e.kms.Routes(r)

	acct := e.dir.Account()
	listOnly := staticGrants{doc: `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["kps:SSHKeyPair:list"]}]}`}

	do := func(method, path, body string) (int, []byte) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, strings.ReplaceAll(path, "{project}", testProject), rd)
		req.Header.Set("Content-Type", "application/json")
		gate := authz.NewGate(authz.GateOptions{
			Principal: identity.Principal{AccountID: acct.ID, UserID: "u-list-only", UserName: "reader"},
			Account:   acct.ID,
			Provider:  listOnly,
			Sealer:    e.vault,
			Log:       e.svc.log,
		})
		ctx := reqctx.With(req.Context(), &reqctx.Info{RequestID: "req-authz", Service: "kms", Region: testRegion})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(authz.WithGate(ctx, gate)))
		return w.Code, w.Body.Bytes()
	}

	// Listing is allowed.
	status, out := do(http.MethodGet, "/v3/{project}/keypairs", "")
	if status != http.StatusOK {
		t.Fatalf("list with kps:SSHKeyPair:list = %d %s, want 200", status, out)
	}

	// Creating is denied with 403 KPS.9003 and an encoded authorization message.
	status, out = do(http.MethodPost, "/v3/{project}/keypairs", `{"keypair":{"name":"denied-kp"}}`)
	if status != http.StatusForbidden {
		t.Fatalf("create without permission = %d %s, want 403", status, out)
	}
	var errBody struct {
		Code string `json:"error_code"`
		Msg  string `json:"error_msg"`
		Enc  string `json:"encoded_authorization_message"`
	}
	if err := json.Unmarshal(out, &errBody); err != nil {
		t.Fatalf("unmarshal denial %s: %v", out, err)
	}
	if errBody.Code != "KPS.9003" || errBody.Enc == "" {
		t.Errorf("denial = %+v, want KPS.9003 with encoded_authorization_message", errBody)
	}
}

type decodedAuthzMsg struct {
	Context struct {
		Action    string   `json:"action"`
		Resources []string `json:"resources"`
	} `json:"context"`
	Failure string `json:"failure"`
}

func decodeKPSDenial(t *testing.T, e *env, status int, raw []byte) decodedAuthzMsg {
	t.Helper()
	if status != http.StatusForbidden {
		t.Fatalf("status = %d (%s), want 403", status, raw)
	}
	var errBody struct {
		Code string `json:"error_code"`
		Msg  string `json:"error_msg"`
		Enc  string `json:"encoded_authorization_message"`
	}
	if err := json.Unmarshal(raw, &errBody); err != nil {
		t.Fatalf("unmarshal 403 body %s: %v", raw, err)
	}
	if errBody.Code != "KPS.9003" || errBody.Enc == "" {
		t.Fatalf("403 body = %+v, want KPS.9003 with encoded_authorization_message", errBody)
	}
	plain, ok := authz.Decode(e.vault, errBody.Enc)
	if !ok {
		t.Fatalf("authz.Decode failed for encoded_authorization_message")
	}
	var msg decodedAuthzMsg
	if err := json.Unmarshal([]byte(plain), &msg); err != nil {
		t.Fatalf("unmarshal decoded authz message %s: %v", plain, err)
	}
	return msg
}

func assertKPSDenied(t *testing.T, e *env, status int, raw []byte, wantAction string, wantResources ...string) {
	t.Helper()
	msg := decodeKPSDenial(t, e, status, raw)
	if msg.Context.Action != wantAction {
		t.Fatalf("decoded action = %q, want %q (resources=%v)", msg.Context.Action, wantAction, msg.Context.Resources)
	}
	if !slices.Equal(msg.Context.Resources, wantResources) {
		t.Fatalf("decoded resources = %v, want %v", msg.Context.Resources, wantResources)
	}
}

func TestKMSDependencyPermissions(t *testing.T) {
	e := newEnv(t)

	r := chi.NewRouter()
	e.kms.Routes(r)

	acct := e.dir.Account()
	key1 := mustCreateKMSKey(t, e, "kps-authz-key-1")
	key2 := mustCreateKMSKey(t, e, "kps-authz-key-2")
	key1URN := "kms:" + testRegion + ":" + acct.ID + ":KeyId:" + key1
	key2URN := "kms:" + testRegion + ":" + acct.ID + ":KeyId:" + key2

	pubSeed, privSeed := mustGenTestRSA(t)

	// Seed domain-scoped KMS-protected keypairs under key1 and key2 for export tests,
	// plus unprotected domain-scoped keypairs for ImportPrivateKey tests.
	for _, tc := range []struct {
		name  string
		keyID string
	}{
		{name: "seed-kms-1", keyID: key1},
		{name: "seed-kms-2", keyID: key2},
	} {
		body := mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name:      tc.name,
				Scope:     "domain",
				PublicKey: pubSeed,
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: tc.keyID},
				},
			},
		})
		if st, out := e.call(t, http.MethodPost, "/v3/{project}/keypairs", body); st != http.StatusOK {
			t.Fatalf("seed %s = %d %s", tc.name, st, out)
		}
	}
	for _, name := range []string{"imp-default", "imp-kms-denied", "imp-list-denied", "imp-kms-ok", "imp-kms-other", "imp-accept"} {
		body := mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name:      name,
				Scope:     "domain",
				PublicKey: pubSeed,
			},
		})
		if st, out := e.call(t, http.MethodPost, "/v3/{project}/keypairs", body); st != http.StatusOK {
			t.Fatalf("seed %s = %d %s", name, st, out)
		}
	}

	doAs := func(userID string, prov authz.Provider, method, path, body string) (int, []byte) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, strings.ReplaceAll(path, "{project}", testProject), rd)
		req.Header.Set("Content-Type", "application/json")
		p := identity.Principal{AccountID: acct.ID, UserID: userID, UserName: userID}
		gate := authz.NewGate(authz.GateOptions{
			Principal: p,
			Account:   acct.ID,
			Provider:  prov,
			Sealer:    e.vault,
			Log:       e.svc.log,
		})
		ctx := reqctx.With(req.Context(), &reqctx.Info{RequestID: "req-kps-kms", Service: "kms", Region: testRegion})
		ctx = auth.WithIdentity(ctx, auth.Identity{Known: true, Principal: p})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(authz.WithGate(ctx, gate)))
		return w.Code, w.Body.Bytes()
	}

	kpsFullDoc := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["kps:*:*"]}]}`

	t.Run("kps_full_without_kms_permissions", func(t *testing.T) {
		prov := newScopedGrants(t, kpsFullDoc, "")

		// Default protection succeeds for CreateKeypair, ImportPrivateKey, BatchImportKeypair,
		// ExportPrivateKey, and BatchExportPrivateKey.
		st, out := doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name: "kps-only-default-create",
				KeyProtection: &keyProtectionWire{
					Encryption: &encryptionWire{Type: "default"},
				},
			},
		}))
		if st != http.StatusOK {
			t.Fatalf("CreateKeypair(default) = %d %s, want 200", st, out)
		}

		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/import", mustJSON(t, importPrivateKeyRequest{
			Keypair: &importPrivateKeyAction{
				Name: "imp-default",
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "default"},
				},
			},
		}))
		if st != http.StatusOK {
			t.Fatalf("ImportPrivateKey(default) = %d %s, want 200", st, out)
		}

		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs/batch-import", mustJSON(t, []createKeypairRequest{
			{
				Keypair: &createKeypairAction{
					Name:      "kps-only-default-batch",
					PublicKey: pubSeed,
					KeyProtection: &keyProtectionWire{
						PrivateKey: privSeed,
						Encryption: &encryptionWire{Type: "default"},
					},
				},
			},
		}))
		if st != http.StatusOK {
			t.Fatalf("BatchImportKeypair(default) = %d %s, want 200", st, out)
		}
		if got := decodeInto[batchImportResponse](t, out); len(got.SucceededKeypairs) != 1 || len(got.FailedKeypairs) != 0 {
			t.Fatalf("BatchImportKeypair(default) = %+v, want 1 succeeded 0 failed", got)
		}

		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"kps-only-default-create"}}`)
		if st != http.StatusOK {
			t.Fatalf("ExportPrivateKey(default) = %d %s, want 200", st, out)
		}

		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":"kps-only-default-create"}}]`)
		if st != http.StatusOK {
			t.Fatalf("BatchExportPrivateKey(default) = %d %s, want 200", st, out)
		}
		if _, err := zip.NewReader(bytes.NewReader(out), int64(len(out))); err != nil {
			t.Fatalf("BatchExportPrivateKey(default) invalid zip: %v", err)
		}

		// CreateKeypair(kms) with explicit kms_key_id -> 403 naming kms:cmk:createDataKey and key1URN.
		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name: "denied-kms-id",
				KeyProtection: &keyProtectionWire{
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:createDataKey", key1URN)
		if _, err := e.svc.keypairs(testTenant).Get(context.Background(), "denied-kms-id"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("denied keypair must not be persisted, got err=%v", err)
		}

		// CreateKeypair(kms) with custom alias kms_key_name -> 403 naming kms:cmk:createDataKey and key1URN.
		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name:      "denied-kms-alias",
				PublicKey: pubSeed,
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyName: "kps-authz-key-1"},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:createDataKey", key1URN)

		// CreateKeypair(kms) with kms_key_name: "kps/default" -> 403 naming kms:cmk:createDataKey and resolved default key URN.
		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name:      "denied-kms-default-alias",
				PublicKey: pubSeed,
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyName: "kps/default"},
				},
			},
		}))
		msg := decodeKPSDenial(t, e, st, out)
		wantPrefix := "kms:" + testRegion + ":" + acct.ID + ":KeyId:"
		if msg.Context.Action != "kms:cmk:createDataKey" || len(msg.Context.Resources) != 1 ||
			!strings.HasPrefix(msg.Context.Resources[0], wantPrefix) || len(msg.Context.Resources[0]) <= len(wantPrefix) {
			t.Fatalf("kps/default denial = %+v, want action=kms:cmk:createDataKey and resource prefix %q", msg.Context, wantPrefix)
		}

		// ImportPrivateKey(kms) -> 403 naming kms:cmk:createDataKey and key1URN.
		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/import", mustJSON(t, importPrivateKeyRequest{
			Keypair: &importPrivateKeyAction{
				Name: "imp-kms-denied",
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:createDataKey", key1URN)

		// BatchImportKeypair(kms), including mixed [default, kms] -> 403 naming kms:cmk:createDataKey and key1URN,
		// without persisting the earlier default item.
		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs/batch-import", mustJSON(t, []createKeypairRequest{
			{
				Keypair: &createKeypairAction{
					Name: "mixed-batch-default",
					KeyProtection: &keyProtectionWire{
						Encryption: &encryptionWire{Type: "default"},
					},
				},
			},
			{
				Keypair: &createKeypairAction{
					Name: "mixed-batch-kms",
					KeyProtection: &keyProtectionWire{
						Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
					},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:createDataKey", key1URN)
		if _, err := e.svc.keypairs(testTenant).Get(context.Background(), "mixed-batch-default"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("mixed batch must not persist default item on 403, got err=%v", err)
		}

		// ExportPrivateKey(kms) and BatchExportPrivateKey(kms) -> 403 naming kms:cmk:decryptDataKey and key1URN.
		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"seed-kms-1"}}`)
		assertKPSDenied(t, e, st, out, "kms:cmk:decryptDataKey", key1URN)

		st, out = doAs("u-kps-only", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":"kps-only-default-create"}},{"keypair":{"name":"seed-kms-1"}}]`)
		assertKPSDenied(t, e, st, out, "kms:cmk:decryptDataKey", key1URN)
	})

	t.Run("create_datakey_without_list_denied", func(t *testing.T) {
		kmsNoListDoc := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["kms:cmk:createDataKey"],"Resource":["` + key1URN + `"]}]}`
		prov := newScopedGrants(t, kpsFullDoc, kmsNoListDoc)

		st, out := doAs("u-no-list", prov, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name:      "no-list-create",
				PublicKey: pubSeed,
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:list")
		if _, err := e.svc.keypairs(testTenant).Get(context.Background(), "no-list-create"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("no-list-create must not be persisted, got err=%v", err)
		}

		st, out = doAs("u-no-list", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/import", mustJSON(t, importPrivateKeyRequest{
			Keypair: &importPrivateKeyAction{
				Name: "imp-list-denied",
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:list")

		st, out = doAs("u-no-list", prov, http.MethodPost, "/v3/{project}/keypairs/batch-import", mustJSON(t, []createKeypairRequest{
			{
				Keypair: &createKeypairAction{
					Name:      "no-list-batch",
					PublicKey: pubSeed,
					KeyProtection: &keyProtectionWire{
						PrivateKey: privSeed,
						Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
					},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:list")
	})

	t.Run("create_datakey_scoped_plus_list", func(t *testing.T) {
		kmsCreateKey1Doc := `{"Version":"5.0","Statement":[` +
			`{"Effect":"Allow","Action":["kms:cmk:createDataKey"],"Resource":["` + key1URN + `"]},` +
			`{"Effect":"Allow","Action":["kms:cmk:list"]}` +
			`]}`
		prov := newScopedGrants(t, kpsFullDoc, kmsCreateKey1Doc)

		// Allowed on key1 for CreateKeypair, ImportPrivateKey, and BatchImportKeypair.
		st, out := doAs("u-create-key1", prov, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name: "ok-kms-create-key1",
				KeyProtection: &keyProtectionWire{
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
				},
			},
		}))
		if st != http.StatusOK {
			t.Fatalf("CreateKeypair(key1) = %d %s, want 200", st, out)
		}

		st, out = doAs("u-create-key1", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/import", mustJSON(t, importPrivateKeyRequest{
			Keypair: &importPrivateKeyAction{
				Name: "imp-kms-ok",
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
				},
			},
		}))
		if st != http.StatusOK {
			t.Fatalf("ImportPrivateKey(key1) = %d %s, want 200", st, out)
		}

		st, out = doAs("u-create-key1", prov, http.MethodPost, "/v3/{project}/keypairs/batch-import", mustJSON(t, []createKeypairRequest{
			{
				Keypair: &createKeypairAction{
					Name:      "ok-kms-batch-key1",
					PublicKey: pubSeed,
					KeyProtection: &keyProtectionWire{
						PrivateKey: privSeed,
						Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
					},
				},
			},
		}))
		if st != http.StatusOK {
			t.Fatalf("BatchImportKeypair(key1) = %d %s, want 200", st, out)
		}
		if got := decodeInto[batchImportResponse](t, out); len(got.SucceededKeypairs) != 1 || len(got.FailedKeypairs) != 0 {
			t.Fatalf("BatchImportKeypair(key1) = %+v, want 1 succeeded 0 failed", got)
		}

		// Denied on key2 (different KMS key)!
		st, out = doAs("u-create-key1", prov, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name:      "denied-kms-create-key2",
				PublicKey: pubSeed,
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key2},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:createDataKey", key2URN)

		st, out = doAs("u-create-key1", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/import", mustJSON(t, importPrivateKeyRequest{
			Keypair: &importPrivateKeyAction{
				Name: "imp-kms-other",
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key2},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:createDataKey", key2URN)

		st, out = doAs("u-create-key1", prov, http.MethodPost, "/v3/{project}/keypairs/batch-import", mustJSON(t, []createKeypairRequest{
			{
				Keypair: &createKeypairAction{
					Name:      "denied-kms-batch-key2",
					PublicKey: pubSeed,
					KeyProtection: &keyProtectionWire{
						PrivateKey: privSeed,
						Encryption: &encryptionWire{Type: "kms", KMSKeyID: key2},
					},
				},
			},
		}))
		assertKPSDenied(t, e, st, out, "kms:cmk:createDataKey", key2URN)
	})

	t.Run("decrypt_datakey_scoped", func(t *testing.T) {
		kmsDecryptKey1Doc := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["kms:cmk:decryptDataKey"],"Resource":["` + key1URN + `"]}]}`
		prov := newScopedGrants(t, kpsFullDoc, kmsDecryptKey1Doc)

		// Allowed on seed-kms-1 (encrypted under key1).
		st, out := doAs("u-decrypt-key1", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"seed-kms-1"}}`)
		if st != http.StatusOK {
			t.Fatalf("ExportPrivateKey(seed-kms-1) = %d %s, want 200", st, out)
		}
		if got := decodeInto[exportPrivateKeyResponse](t, out); got.Keypair.PrivateKey == "" {
			t.Fatal("ExportPrivateKey(seed-kms-1) returned empty private_key")
		}

		st, out = doAs("u-decrypt-key1", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":"seed-kms-1"}}]`)
		if st != http.StatusOK {
			t.Fatalf("BatchExportPrivateKey(seed-kms-1) = %d %s, want 200", st, out)
		}
		if _, err := zip.NewReader(bytes.NewReader(out), int64(len(out))); err != nil {
			t.Fatalf("BatchExportPrivateKey(seed-kms-1) invalid zip: %v", err)
		}

		// Denied on seed-kms-2 (encrypted under key2)!
		st, out = doAs("u-decrypt-key1", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"seed-kms-2"}}`)
		assertKPSDenied(t, e, st, out, "kms:cmk:decryptDataKey", key2URN)

		st, out = doAs("u-decrypt-key1", prov, http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":"seed-kms-1"}},{"keypair":{"name":"seed-kms-2"}}]`)
		assertKPSDenied(t, e, st, out, "kms:cmk:decryptDataKey", key2URN)
	})

	t.Run("accept_mode_and_nova_bypass", func(t *testing.T) {
		// Accept mode (no Gate in request context) allows all KMS-protected operations.
		st, out := e.call(t, http.MethodPost, "/v3/{project}/keypairs", mustJSON(t, createKeypairRequest{
			Keypair: &createKeypairAction{
				Name:      "accept-kms-create",
				PublicKey: pubSeed,
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
				},
			},
		}))
		if st != http.StatusOK {
			t.Fatalf("accept CreateKeypair(kms) = %d %s, want 200", st, out)
		}

		st, out = e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/import", mustJSON(t, importPrivateKeyRequest{
			Keypair: &importPrivateKeyAction{
				Name: "imp-accept",
				KeyProtection: &keyProtectionWire{
					PrivateKey: privSeed,
					Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
				},
			},
		}))
		if st != http.StatusOK {
			t.Fatalf("accept ImportPrivateKey(kms) = %d %s, want 200", st, out)
		}

		st, out = e.call(t, http.MethodPost, "/v3/{project}/keypairs/batch-import", mustJSON(t, []createKeypairRequest{
			{
				Keypair: &createKeypairAction{
					Name:      "accept-kms-batch",
					PublicKey: pubSeed,
					KeyProtection: &keyProtectionWire{
						PrivateKey: privSeed,
						Encryption: &encryptionWire{Type: "kms", KMSKeyID: key1},
					},
				},
			},
		}))
		if st != http.StatusOK {
			t.Fatalf("accept BatchImportKeypair(kms) = %d %s, want 200", st, out)
		}

		st, out = e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/export", `{"keypair":{"name":"accept-kms-create"}}`)
		if st != http.StatusOK {
			t.Fatalf("accept ExportPrivateKey(kms) = %d %s, want 200", st, out)
		}

		st, out = e.call(t, http.MethodPost, "/v3/{project}/keypairs/private-key/batch-export", `[{"keypair":{"name":"accept-kms-create"}}]`)
		if st != http.StatusOK {
			t.Fatalf("accept BatchExportPrivateKey(kms) = %d %s, want 200", st, out)
		}

		// NovaCreate passes nil *http.Request and does not require KMS dependency permissions.
		novaOut, err := e.svc.NovaCreate(context.Background(), testRegion, testProject, ecs.NovaCreateKeypairInput{
			Name:      "nova-kms-kp",
			PublicKey: pubSeed,
			KeyProtection: &ecs.NovaKeyProtectionInput{
				PrivateKey: privSeed,
				Encryption: &ecs.NovaEncryptionInput{Type: "kms", KMSKeyID: key1},
			},
		})
		if err != nil || novaOut.Name != "nova-kms-kp" {
			t.Fatalf("NovaCreate(kms) = %+v, %v", novaOut, err)
		}
	})
}
