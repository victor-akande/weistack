package obs

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/cmk"
)

// fakeKeys is a KMS with one key per name, which can be disabled.
type fakeKeys struct {
	disabled map[string]bool
}

func (f *fakeKeys) NewDataKey(_ context.Context, region, keyID, _ string) (cmk.DataKey, error) {
	if keyID == "" {
		keyID = "obs-default"
	}
	if keyID == "missing" {
		return cmk.DataKey{}, cmk.ErrNotFound
	}
	if f.disabled[keyID] {
		return cmk.DataKey{}, cmk.ErrDisabled
	}
	plain := make([]byte, 32)
	_, _ = rand.Read(plain)
	return cmk.DataKey{KeyID: keyID, KeyURN: region + ":acct:key/" + keyID, Plain: plain, Sealed: append([]byte(keyID+"|"), plain...)}, nil
}

func (f *fakeKeys) OpenDataKey(_ context.Context, _ string, sealed []byte) ([]byte, error) {
	id, plain, _ := bytes.Cut(sealed, []byte("|"))
	if f.disabled[string(id)] {
		return nil, cmk.ErrDisabled
	}
	return plain, nil
}

func (f *fakeKeys) Check(context.Context, string, string, string, string) (string, error) {
	return "", nil
}

func (f *fakeKeys) ResolveAlias(context.Context, string, string) (string, error) {
	return "", cmk.ErrNotFound
}

func newSSEEnv(t *testing.T) (*env, *fakeKeys) {
	t.Helper()
	e := newEnv(t)
	keys := &fakeKeys{disabled: map[string]bool{}}
	e.svc.keys = keys
	mustStatus(t, e.as(t, alice, http.MethodPut, "/enc"), http.StatusOK)
	return e, keys
}

func TestCTRAtAnyOffset(t *testing.T) {
	t.Parallel()
	key, iv := make([]byte, 32), make([]byte, 16)
	_, _ = rand.Read(key)
	// An IV near overflow checks the counter's carry.
	for i := range iv {
		iv[i] = 0xff
	}
	iv[0] = 1
	block, _ := aes.NewCipher(key)
	plain := make([]byte, 1000)
	_, _ = rand.Read(plain)
	whole := make([]byte, len(plain))
	cipher.NewCTR(block, iv).XORKeyStream(whole, plain)
	for _, off := range []int64{0, 1, 15, 16, 17, 255, 256, 999} {
		got := make([]byte, len(plain)-int(off))
		ctrAt(block, iv, off).XORKeyStream(got, plain[off:])
		if !bytes.Equal(got, whole[off:]) {
			t.Errorf("offset %d: the key stream differs", off)
		}
	}
}

func TestSSEKMSObjects(t *testing.T) {
	t.Parallel()
	e, keys := newSSEEnv(t)
	body := strings.Repeat("secret data ", 100)
	got := mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/a", Auth: alice, Body: body,
		Headers: map[string]string{"x-obs-server-side-encryption": "kms", "x-obs-server-side-encryption-kms-key-id": "k1"}}), http.StatusOK)
	if got.Header.Get("x-obs-server-side-encryption") != "kms" || got.Header.Get("x-obs-server-side-encryption-kms-key-id") != testRegion+":acct:key/k1" {
		t.Errorf("PUT headers = %v", got.Header)
	}
	// Stored encrypted: no blob on disk holds the body.
	found := false
	_ = filepath.Walk(e.dir, func(p string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			raw, _ := os.ReadFile(p)
			found = found || bytes.Contains(raw, []byte("secret data"))
		}
		return nil
	})
	if found {
		t.Error("the body is stored in clear")
	}
	get := mustStatus(t, e.as(t, alice, http.MethodGet, "/enc/a"), http.StatusOK)
	if get.Body != body || get.Header.Get("x-obs-server-side-encryption") != "kms" {
		t.Errorf("GET = %q, %v", get.Body[:20], get.Header)
	}
	rng := e.do(t, req{Method: http.MethodGet, Path: "/enc/a", Auth: alice, Headers: map[string]string{"Range": "bytes=17-40"}})
	if rng.Status != http.StatusPartialContent || rng.Body != body[17:41] {
		t.Errorf("range = %d %q", rng.Status, rng.Body)
	}
	// The S3 dialect names the algorithm aws:kms.
	if h := e.as(t, bob, http.MethodHead, "/enc/a"); h.Status == http.StatusOK && h.Header.Get("x-amz-server-side-encryption") != "aws:kms" {
		t.Errorf("S3 HEAD = %v", h.Header)
	}

	// A disabled key leaves the object unreadable.
	keys.disabled["k1"] = true
	wantError(t, e.as(t, alice, http.MethodGet, "/enc/a"), http.StatusBadRequest, "KMS.DisabledException")
	keys.disabled["k1"] = false

	wantError(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/b", Auth: alice, Body: "x",
		Headers: map[string]string{"x-obs-server-side-encryption": "kms", "x-obs-server-side-encryption-kms-key-id": "missing"}}),
		http.StatusBadRequest, "KMS.NotFoundException")
	wantError(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/b", Auth: alice, Body: "x",
		Headers: map[string]string{"x-obs-server-side-encryption": "DES"}}), http.StatusBadRequest, "InvalidArgument")

	// SSE-OBS is reported, SM4 data encryption works.
	h := mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/obs", Auth: alice, Body: "x",
		Headers: map[string]string{"x-obs-server-side-encryption": "AES256"}}), http.StatusOK)
	if h.Header.Get("x-obs-server-side-encryption") != "AES256" {
		t.Errorf("SSE-OBS = %v", h.Header)
	}
	mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/sm4", Auth: alice, Body: body,
		Headers: map[string]string{"x-obs-server-side-encryption": "kms", "x-obs-server-side-data-encryption": "SM4"}}), http.StatusOK)
	if g := e.as(t, alice, http.MethodGet, "/enc/sm4"); g.Body != body || g.Header.Get("x-obs-server-side-data-encryption") != "SM4" {
		t.Errorf("SM4 GET = %d %v", g.Status, g.Header)
	}

	// Copies are encrypted as asked, not as their source.
	mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/plain-copy", Auth: alice,
		Headers: map[string]string{"x-obs-copy-source": "/enc/a"}}), http.StatusOK)
	if g := e.as(t, alice, http.MethodGet, "/enc/plain-copy"); g.Body != body || g.Header.Get("x-obs-server-side-encryption") != "" {
		t.Errorf("plain copy = %v", g.Header)
	}
	mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/again", Auth: alice,
		Headers: map[string]string{"x-obs-copy-source": "/enc/plain-copy", "x-obs-server-side-encryption": "kms"}}), http.StatusOK)
	if g := e.as(t, alice, http.MethodGet, "/enc/again"); g.Body != body || g.Header.Get("x-obs-server-side-encryption") != "kms" {
		t.Errorf("encrypted copy = %v", g.Header)
	}
}

func TestBucketDefaultEncryption(t *testing.T) {
	t.Parallel()
	e, _ := newSSEEnv(t)
	wantError(t, e.as(t, alice, http.MethodGet, "/enc?encryption"), http.StatusNotFound, "NoSuchEncryptionConfiguration")
	cfg := `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>kms</SSEAlgorithm><KMSMasterKeyID>k2</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`
	mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc?encryption", Auth: alice, Body: cfg}), http.StatusOK)
	got := mustStatus(t, e.as(t, alice, http.MethodGet, "/enc?encryption"), http.StatusOK)
	if !strings.Contains(got.Body, "<SSEAlgorithm>kms</SSEAlgorithm>") || !strings.Contains(got.Body, "<KMSMasterKeyID>k2</KMSMasterKeyID>") {
		t.Errorf("GET ?encryption = %s", got.Body)
	}
	// Objects without headers take the default.
	put := mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/d", Auth: alice, Body: "defaulted"}), http.StatusOK)
	if put.Header.Get("x-obs-server-side-encryption-kms-key-id") != testRegion+":acct:key/k2" {
		t.Errorf("defaulted PUT = %v", put.Header)
	}
	if g := e.as(t, alice, http.MethodGet, "/enc/d"); g.Body != "defaulted" {
		t.Errorf("defaulted GET = %q", g.Body)
	}
	mustStatus(t, e.as(t, alice, http.MethodDelete, "/enc?encryption"), http.StatusNoContent)
	wantError(t, e.as(t, alice, http.MethodGet, "/enc?encryption"), http.StatusNotFound, "NoSuchEncryptionConfiguration")
	wantError(t, e.do(t, req{Method: http.MethodPut, Path: "/enc?encryption", Auth: alice, Body: "<nope"}), http.StatusBadRequest, "MalformedXML")

	// A bucket created with encryption headers has that default.
	mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc2", Auth: alice,
		Headers: map[string]string{"x-obs-server-side-encryption": "kms"}}), http.StatusOK)
	if g := mustStatus(t, e.as(t, alice, http.MethodGet, "/enc2?encryption"), http.StatusOK); !strings.Contains(g.Body, ">kms<") {
		t.Errorf("created with encryption = %s", g.Body)
	}
}

func TestSSEKMSMultipart(t *testing.T) {
	t.Parallel()
	e, _ := newSSEEnv(t)
	init := mustStatus(t, e.do(t, req{Method: http.MethodPost, Path: "/enc/big?uploads", Auth: alice,
		Headers: map[string]string{"x-obs-server-side-encryption": "kms"}}), http.StatusOK)
	if init.Header.Get("x-obs-server-side-encryption") != "kms" {
		t.Errorf("initiate headers = %v", init.Header)
	}
	id := between(init.Body, "<UploadId>", "</UploadId>")
	p1, p2 := strings.Repeat("a", minPartSize), "tail"
	e1 := mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/big?partNumber=1&uploadId=" + id, Auth: alice, Body: p1}), http.StatusOK).Header.Get("ETag")
	e2 := mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/enc/big?partNumber=2&uploadId=" + id, Auth: alice, Body: p2}), http.StatusOK).Header.Get("ETag")
	done := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + e1 + `</ETag></Part><Part><PartNumber>2</PartNumber><ETag>` + e2 + `</ETag></Part></CompleteMultipartUpload>`
	mustStatus(t, e.do(t, req{Method: http.MethodPost, Path: "/enc/big?uploadId=" + id, Auth: alice, Body: done}), http.StatusOK)
	got := e.as(t, alice, http.MethodGet, "/enc/big")
	if got.Body != p1+p2 || got.Header.Get("x-obs-server-side-encryption") != "kms" {
		t.Errorf("assembled = %d bytes, %v", len(got.Body), got.Header)
	}
}

func between(s, a, b string) string {
	_, rest, _ := strings.Cut(s, a)
	v, _, _ := strings.Cut(rest, b)
	return v
}
