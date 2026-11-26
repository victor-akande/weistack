package kps

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/identity"
)

const (
	// Deterministic RFC 8032 test vector 1 ed25519 public key and MD5 fingerprint.
	testEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
	testEd25519FP  = "cf:07:be:9d:68:ae:65:54:6d:a0:93:c3:6f:bd:0d:82"
)

func (e *env) callAs(t *testing.T, accessKey, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, strings.ReplaceAll(path, "{project}", testProject), rd)
	r.Host = testHost
	r.Header.Set("Content-Type", "application/json")
	if accessKey != "" {
		r.Header.Set("Authorization", "SDK-HMAC-SHA256 Access="+accessKey+", SignedHeaders=host, Signature=00")
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return res.StatusCode, out
}

func TestKeypairCRUDGolden(t *testing.T) {
	e := newEnv(t)

	// Empty list and missing-keypair 404s.
	e.expect(t, "keypair_list_empty", http.MethodGet, "/v3/{project}/keypairs", "")
	e.expect(t, "keypair_error_6004", http.MethodGet, "/v3/{project}/keypairs/missing", "")
	e.expect(t, "keypair_error_6004", http.MethodPut, "/v3/{project}/keypairs/missing", `{"keypair":{"description":"x"}}`)
	e.expect(t, "keypair_error_6004", http.MethodDelete, "/v3/{project}/keypairs/missing", "")

	// Import a deterministic key pair.
	importBody := fmt.Sprintf(`{"keypair":{"name":"demo-ed25519","public_key":%q}}`, testEd25519Pub)
	raw := e.expect(t, "keypair_import", http.MethodPost, "/v3/{project}/keypairs", importBody)
	if strings.Contains(string(raw), `"private_key"`) {
		t.Fatalf("import response must omit private_key, got %s", raw)
	}

	// Duplicate name gets 400 KPS.7004.
	dupRaw := e.expect(t, "keypair_error_7004", http.MethodPost, "/v3/{project}/keypairs", importBody)
	dupErr := decodeInto[struct {
		ErrorCode string `json:"error_code"`
		ErrorMsg  string `json:"error_msg"`
	}](t, dupRaw)
	if dupErr.ErrorMsg != "Key pair 'demo-ed25519' already exists." {
		t.Fatalf("duplicate error_msg = %q, want %q", dupErr.ErrorMsg, "Key pair 'demo-ed25519' already exists.")
	}

	// List populated and show detail before update (update_time must be null).
	e.expect(t, "keypair_list", http.MethodGet, "/v3/{project}/keypairs", "")
	e.expect(t, "keypair_detail", http.MethodGet, "/v3/{project}/keypairs/demo-ed25519", "")

	// Advance clock and update description.
	e.clock.Advance(5 * time.Second)
	e.expect(t, "keypair_update", http.MethodPut, "/v3/{project}/keypairs/demo-ed25519", `{"keypair":{"description":"production deploy key"}}`)
	e.expect(t, "keypair_detail_updated", http.MethodGet, "/v3/{project}/keypairs/demo-ed25519", "")

	// Clearing description to empty string is allowed.
	e.expect(t, "keypair_update", http.MethodPut, "/v3/{project}/keypairs/demo-ed25519", `{"keypair":{"description":""}}`)
	status, detailRaw := e.call(t, http.MethodGet, "/v3/{project}/keypairs/demo-ed25519", "")
	if status != http.StatusOK {
		t.Fatalf("detail after clearing description: status = %d", status)
	}
	detail := decodeInto[listKeypairDetailResponse](t, detailRaw)
	if detail.Keypair.Description != "" {
		t.Fatalf("description = %q, want empty", detail.Keypair.Description)
	}

	// Delete key pair, confirm 204 then 404 and empty list.
	e.expect(t, "keypair_delete", http.MethodDelete, "/v3/{project}/keypairs/demo-ed25519", "")
	e.expect(t, "keypair_error_6004", http.MethodDelete, "/v3/{project}/keypairs/demo-ed25519", "")
	e.expect(t, "keypair_error_6004", http.MethodGet, "/v3/{project}/keypairs/demo-ed25519", "")
	e.expect(t, "keypair_list_empty", http.MethodGet, "/v3/{project}/keypairs", "")
}

func TestKeypairPaginationGolden(t *testing.T) {
	e := newEnv(t)

	for _, tc := range []struct {
		name  string
		scope string
	}{
		{"kp-1", "user"},
		{"kp-2", "user"},
		{"kp-3", "user"},
		{"kp-4", "domain"},
	} {
		body := fmt.Sprintf(`{"keypair":{"name":%q,"scope":%q,"public_key":%q}}`, tc.name, tc.scope, testEd25519Pub)
		status, out := e.call(t, http.MethodPost, "/v3/{project}/keypairs", body)
		if status != http.StatusOK {
			t.Fatalf("create %s: status = %d, body = %s", tc.name, status, out)
		}
	}

	// Page 1: limit=2 -> kp-1, kp-2, next_marker="kp-2", no previous_marker.
	e.expect(t, "keypair_list_page1", http.MethodGet, "/v3/{project}/keypairs?limit=2", "")
	// Page 2 (middle): limit=1&marker=kp-2 -> kp-3, next_marker="kp-3", previous_marker="kp-3".
	e.expect(t, "keypair_list_page2", http.MethodGet, "/v3/{project}/keypairs?limit=1&marker=kp-2", "")
	// Page 3 (last): limit=2&marker=kp-3 -> kp-4, previous_marker="kp-4", no next_marker.
	e.expect(t, "keypair_list_page3", http.MethodGet, "/v3/{project}/keypairs?limit=2&marker=kp-3", "")
	// Past end and unknown marker both return empty list.
	e.expect(t, "keypair_list_empty", http.MethodGet, "/v3/{project}/keypairs?limit=2&marker=kp-4", "")
	e.expect(t, "keypair_list_empty", http.MethodGet, "/v3/{project}/keypairs?limit=2&marker=no-such-key", "")

	// Invalid limit parameters get 400 KPS.0002.
	for _, q := range []string{"limit=0", "limit=-1", "limit=1001", "limit=abc"} {
		e.expect(t, "keypair_error_0002", http.MethodGet, "/v3/{project}/keypairs?"+q, "")
	}
}

func TestKeypairListNameOrderAndDeletedMarker(t *testing.T) {
	e := newEnv(t)

	createOrder := []string{"kp-delta", "kp-alpha", "kp-echo", "kp-bravo", "kp-charlie"}
	wantSorted := []string{"kp-alpha", "kp-bravo", "kp-charlie", "kp-delta", "kp-echo"}

	for _, name := range createOrder {
		body := fmt.Sprintf(`{"keypair":{"name":%q,"public_key":%q}}`, name, testEd25519Pub)
		status, out := e.call(t, http.MethodPost, "/v3/{project}/keypairs", body)
		if status != http.StatusOK {
			t.Fatalf("create %s: status = %d, body = %s", name, status, out)
		}
	}

	extractNames := func(items []keypairItem) []string {
		names := make([]string, len(items))
		for i, item := range items {
			names[i] = item.Keypair.Name
		}
		return names
	}

	// Unpaginated GET returns key pairs sorted by Name ascending.
	status, raw := e.call(t, http.MethodGet, "/v3/{project}/keypairs", "")
	if status != http.StatusOK {
		t.Fatalf("unpaginated list: status = %d, body = %s", status, raw)
	}
	fullList := decodeInto[listKeypairsResponse](t, raw)
	if got := extractNames(fullList.Keypairs); !slices.Equal(got, wantSorted) {
		t.Fatalf("unpaginated names = %v, want %v", got, wantSorted)
	}
	if int(fullList.PageInfo.CurrentCount) != len(wantSorted) {
		t.Fatalf("unpaginated current_count = %d, want %d", fullList.PageInfo.CurrentCount, len(wantSorted))
	}
	if fullList.PageInfo.NextMarker != "" || fullList.PageInfo.PreviousMarker != "" {
		t.Fatalf("unpaginated markers = (next=%q, prev=%q), want empty", fullList.PageInfo.NextMarker, fullList.PageInfo.PreviousMarker)
	}

	pageSize := 2

	// Page 1: ?limit=2 -> ["kp-alpha", "kp-bravo"], next_marker="kp-bravo", previous_marker="".
	wantPage1 := wantSorted[:pageSize]
	status, raw = e.call(t, http.MethodGet, fmt.Sprintf("/v3/{project}/keypairs?limit=%d", pageSize), "")
	if status != http.StatusOK {
		t.Fatalf("page 1: status = %d, body = %s", status, raw)
	}
	page1 := decodeInto[listKeypairsResponse](t, raw)
	if got := extractNames(page1.Keypairs); !slices.Equal(got, wantPage1) {
		t.Fatalf("page 1 names = %v, want %v", got, wantPage1)
	}
	if int(page1.PageInfo.CurrentCount) != len(wantPage1) {
		t.Fatalf("page 1 current_count = %d, want %d", page1.PageInfo.CurrentCount, len(wantPage1))
	}
	wantPage1Next := wantPage1[len(wantPage1)-1]
	if page1.PageInfo.NextMarker != wantPage1Next || page1.PageInfo.PreviousMarker != "" {
		t.Fatalf("page 1 markers = (next=%q, prev=%q), want (next=%q, prev=\"\")",
			page1.PageInfo.NextMarker, page1.PageInfo.PreviousMarker, wantPage1Next)
	}

	// Delete the marker key pair ("kp-bravo") before requesting page 2.
	deletedMarker := page1.PageInfo.NextMarker
	status, out := e.call(t, http.MethodDelete, "/v3/{project}/keypairs/"+deletedMarker, "")
	if status != http.StatusNoContent {
		t.Fatalf("delete %s: status = %d, want %d (body = %s)", deletedMarker, status, http.StatusNoContent, out)
	}

	remaining := wantSorted[pageSize:]

	// Page 2 with deleted marker: ?limit=2&marker=kp-bravo -> ["kp-charlie", "kp-delta"].
	wantPage2 := remaining[:pageSize]
	status, raw = e.call(t, http.MethodGet, fmt.Sprintf("/v3/{project}/keypairs?limit=%d&marker=%s", pageSize, deletedMarker), "")
	if status != http.StatusOK {
		t.Fatalf("page 2: status = %d, body = %s", status, raw)
	}
	page2 := decodeInto[listKeypairsResponse](t, raw)
	if got := extractNames(page2.Keypairs); !slices.Equal(got, wantPage2) {
		t.Fatalf("page 2 names = %v, want %v", got, wantPage2)
	}
	if int(page2.PageInfo.CurrentCount) != len(wantPage2) {
		t.Fatalf("page 2 current_count = %d, want %d", page2.PageInfo.CurrentCount, len(wantPage2))
	}
	wantPage2Prev := wantPage2[0]
	wantPage2Next := wantPage2[len(wantPage2)-1]
	if page2.PageInfo.PreviousMarker != wantPage2Prev || page2.PageInfo.NextMarker != wantPage2Next {
		t.Fatalf("page 2 markers = (next=%q, prev=%q), want (next=%q, prev=%q)",
			page2.PageInfo.NextMarker, page2.PageInfo.PreviousMarker, wantPage2Next, wantPage2Prev)
	}

	// Page 3: ?limit=2&marker=kp-delta -> ["kp-echo"], previous_marker="kp-echo", next_marker="".
	wantPage3 := remaining[pageSize:]
	status, raw = e.call(t, http.MethodGet, fmt.Sprintf("/v3/{project}/keypairs?limit=%d&marker=%s", pageSize, page2.PageInfo.NextMarker), "")
	if status != http.StatusOK {
		t.Fatalf("page 3: status = %d, body = %s", status, raw)
	}
	page3 := decodeInto[listKeypairsResponse](t, raw)
	if got := extractNames(page3.Keypairs); !slices.Equal(got, wantPage3) {
		t.Fatalf("page 3 names = %v, want %v", got, wantPage3)
	}
	if int(page3.PageInfo.CurrentCount) != len(wantPage3) {
		t.Fatalf("page 3 current_count = %d, want %d", page3.PageInfo.CurrentCount, len(wantPage3))
	}
	wantPage3Prev := wantPage3[0]
	if page3.PageInfo.PreviousMarker != wantPage3Prev || page3.PageInfo.NextMarker != "" {
		t.Fatalf("page 3 markers = (next=%q, prev=%q), want (next=\"\", prev=%q)",
			page3.PageInfo.NextMarker, page3.PageInfo.PreviousMarker, wantPage3Prev)
	}

	// NovaList also returns key pairs in Name order and respects deleted markers.
	ctx := context.Background()
	novaAll, err := e.svc.NovaList(ctx, testRegion, testProject, "", 0)
	if err != nil {
		t.Fatalf("NovaList unpaginated: %v", err)
	}
	wantNovaAll := make([]string, 0, len(wantSorted)-1)
	wantNovaAll = append(wantNovaAll, wantSorted[0])
	wantNovaAll = append(wantNovaAll, remaining...)
	gotNovaAll := make([]string, len(novaAll))
	for i, kp := range novaAll {
		gotNovaAll[i] = kp.Name
	}
	if !slices.Equal(gotNovaAll, wantNovaAll) {
		t.Fatalf("NovaList unpaginated names = %v, want %v", gotNovaAll, wantNovaAll)
	}

	novaAfterDeleted, err := e.svc.NovaList(ctx, testRegion, testProject, deletedMarker, pageSize)
	if err != nil {
		t.Fatalf("NovaList after deleted marker: %v", err)
	}
	gotNovaPage := make([]string, len(novaAfterDeleted))
	for i, kp := range novaAfterDeleted {
		gotNovaPage[i] = kp.Name
	}
	if !slices.Equal(gotNovaPage, wantPage2) {
		t.Fatalf("NovaList(marker=%q, limit=%d) names = %v, want %v", deletedMarker, pageSize, gotNovaPage, wantPage2)
	}
}

func TestKeypairValidationErrors(t *testing.T) {
	e := newEnv(t)

	tooLongName := strings.Repeat("a", maxKeypairNameLen+1)
	maxLenName := strings.Repeat("b", maxKeypairNameLen)
	tooLongDesc := strings.Repeat("d", maxDescriptionLen+1)
	maxLenDesc := strings.Repeat("e", maxDescriptionLen)

	badCreateBodies := []struct {
		label string
		body  string
	}{
		{"malformed JSON", `{not json`},
		{"empty body", ``},
		{"missing keypair object", `{}`},
		{"empty name", `{"keypair":{"name":""}}`},
		{"name too long", fmt.Sprintf(`{"keypair":{"name":%q,"public_key":%q}}`, tooLongName, testEd25519Pub)},
		{"name with space", fmt.Sprintf(`{"keypair":{"name":"bad name","public_key":%q}}`, testEd25519Pub)},
		{"name with dot", fmt.Sprintf(`{"keypair":{"name":"bad.name","public_key":%q}}`, testEd25519Pub)},
		{"name with slash", fmt.Sprintf(`{"keypair":{"name":"bad/name","public_key":%q}}`, testEd25519Pub)},
		{"name with non-ascii", fmt.Sprintf(`{"keypair":{"name":"kép","public_key":%q}}`, testEd25519Pub)},
		{"bad type", fmt.Sprintf(`{"keypair":{"name":"ok-name","type":"rsa","public_key":%q}}`, testEd25519Pub)},
		{"bad scope", fmt.Sprintf(`{"keypair":{"name":"ok-name","scope":"account","public_key":%q}}`, testEd25519Pub)},
		{"bad public key", `{"keypair":{"name":"ok-name","public_key":"not-a-valid-ssh-key"}}`},
		{"two public keys", fmt.Sprintf(`{"keypair":{"name":"ok-name","public_key":%q}}`, testEd25519Pub+"\n"+testEd25519Pub)},
		{"authorized_keys options", fmt.Sprintf(`{"keypair":{"name":"ok-name","public_key":%q}}`, `command="/bin/true" `+testEd25519Pub)},
		{"key_protection missing encryption", fmt.Sprintf(`{"keypair":{"name":"ok-name","public_key":%q,"key_protection":{"private_key":"pem"}}}`, testEd25519Pub)},
		{"key_protection private_key on generate", `{"keypair":{"name":"ok-name","key_protection":{"private_key":"pem","encryption":{"type":"default"}}}}`},
		{"key_protection missing private_key on import", fmt.Sprintf(`{"keypair":{"name":"ok-name","public_key":%q,"key_protection":{"encryption":{"type":"default"}}}}`, testEd25519Pub)},
	}
	for _, tc := range badCreateBodies {
		t.Run("create/"+tc.label, func(t *testing.T) {
			e.expect(t, "keypair_error_0002", http.MethodPost, "/v3/{project}/keypairs", tc.body)
		})
	}

	// Boundary valid creates: 255-char name and x509 type.
	status, out := e.call(t, http.MethodPost, "/v3/{project}/keypairs",
		fmt.Sprintf(`{"keypair":{"name":%q,"type":"x509","public_key":%q}}`, maxLenName, testEd25519Pub))
	if status != http.StatusOK {
		t.Fatalf("create maxLenName: status = %d, body = %s", status, out)
	}
	created := decodeInto[createKeypairResponse](t, out)
	if created.Keypair.Type != "x509" {
		t.Fatalf("type = %q, want x509", created.Keypair.Type)
	}

	// Update description validation errors.
	badUpdateBodies := []struct {
		label string
		body  string
	}{
		{"malformed JSON", `{bad`},
		{"empty body", ``},
		{"missing keypair", `{}`},
		{"missing description", `{"keypair":{}}`},
		{"description too long", fmt.Sprintf(`{"keypair":{"description":%q}}`, tooLongDesc)},
	}
	for _, tc := range badUpdateBodies {
		t.Run("update/"+tc.label, func(t *testing.T) {
			e.expect(t, "keypair_error_0002", http.MethodPut, "/v3/{project}/keypairs/"+maxLenName, tc.body)
		})
	}

	// Boundary valid description: 255 chars.
	e.expect(t, "keypair_update", http.MethodPut, "/v3/{project}/keypairs/"+maxLenName,
		fmt.Sprintf(`{"keypair":{"description":%q}}`, maxLenDesc))
}

func TestKeypairGenerateCryptoAndNoSecretsInLogs(t *testing.T) {
	e := newEnv(t)

	raw := e.expect(t, "keypair_generate", http.MethodPost, "/v3/{project}/keypairs", `{"keypair":{"name":"gen-rsa"}}`)
	resp := decodeInto[createKeypairResponse](t, raw)

	// Public key parses cleanly and matches fingerprint.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Keypair.PublicKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if pub.Type() != "ssh-rsa" {
		t.Fatalf("pub.Type() = %q, want ssh-rsa", pub.Type())
	}
	if got, want := resp.Keypair.Fingerprint, ssh.FingerprintLegacyMD5(pub); got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}

	// Private key PEM parses as 2048-bit PKCS#1 RSA key and matches the returned public key.
	block, rest := pem.Decode([]byte(resp.Keypair.PrivateKey))
	if block == nil {
		t.Fatalf("failed to decode private_key PEM")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("unexpected trailing data in private_key PEM")
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("PEM block type = %q, want RSA PRIVATE KEY", block.Type)
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey: %v", err)
	}
	if bits := priv.N.BitLen(); bits != 2048 {
		t.Fatalf("RSA key size = %d bits, want 2048", bits)
	}
	derivedPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	if !bytes.Equal(derivedPub.Marshal(), pub.Marshal()) {
		t.Fatalf("private key does not match returned public key")
	}

	// Detail reports ssh-rsa algorithm and is_key_protection=false; no SealedKey stored.
	status, detailRaw := e.call(t, http.MethodGet, "/v3/{project}/keypairs/gen-rsa", "")
	if status != http.StatusOK {
		t.Fatalf("detail: status = %d, body = %s", status, detailRaw)
	}
	detail := decodeInto[listKeypairDetailResponse](t, detailRaw)
	if detail.Keypair.Algorithm != "ssh-rsa" {
		t.Fatalf("algorithm = %q, want ssh-rsa", detail.Keypair.Algorithm)
	}
	if detail.Keypair.IsKeyProtection {
		t.Fatalf("is_key_protection = true, want false")
	}
	stored, err := e.svc.keypairs(testTenant).Get(context.Background(), "gen-rsa")
	if err != nil {
		t.Fatalf("store Get: %v", err)
	}
	if len(stored.SealedKey) != 0 {
		t.Fatalf("unprotected generated keypair unexpectedly stored SealedKey")
	}

	// Verify logs recorded creation without leaking private key material.
	logText := e.logs.String()
	if !strings.Contains(logText, "kps keypair created") {
		t.Fatalf("expected creation log entry, got:\n%s", logText)
	}
	if strings.Contains(logText, "PRIVATE KEY") {
		t.Fatalf("log output leaked PRIVATE KEY marker:\n%s", logText)
	}
	// Also check a slice of the base64 body of the PEM is absent from logs.
	lines := strings.Split(strings.TrimSpace(resp.Keypair.PrivateKey), "\n")
	if len(lines) > 2 && strings.Contains(logText, lines[1]) {
		t.Fatalf("log output leaked private key body")
	}
}

func TestKeypairImportEd25519Crypto(t *testing.T) {
	e := newEnv(t)

	pubWithComment := testEd25519Pub + " deploy@host\n"
	body := fmt.Sprintf(`{"keypair":{"name":"ed-key","public_key":%q}}`, pubWithComment)
	status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", body)
	if status != http.StatusOK {
		t.Fatalf("import ed25519: status = %d, body = %s", status, raw)
	}
	resp := decodeInto[createKeypairResponse](t, raw)
	if resp.Keypair.PrivateKey != "" {
		t.Fatalf("imported keypair must not return private_key")
	}
	if resp.Keypair.Fingerprint != testEd25519FP {
		t.Fatalf("fingerprint = %q, want %q", resp.Keypair.Fingerprint, testEd25519FP)
	}
	if resp.Keypair.PublicKey != strings.TrimSpace(pubWithComment) {
		t.Fatalf("public_key = %q, want trimmed %q", resp.Keypair.PublicKey, strings.TrimSpace(pubWithComment))
	}

	status, detailRaw := e.call(t, http.MethodGet, "/v3/{project}/keypairs/ed-key", "")
	if status != http.StatusOK {
		t.Fatalf("detail ed-key: status = %d, body = %s", status, detailRaw)
	}
	detail := decodeInto[listKeypairDetailResponse](t, detailRaw)
	if detail.Keypair.Algorithm != "ssh-ed25519" {
		t.Fatalf("algorithm = %q, want ssh-ed25519", detail.Keypair.Algorithm)
	}
}

func TestKeypairScopeVisibility(t *testing.T) {
	e := newEnv(t)

	acctID := e.dir.Account().ID
	akA, skA := "USERAACCESSKEY000001", "USERASECRETKEY00000000000000000000000001"
	akB, skB := "USERBACCESSKEY000002", "USERBSECRETKEY00000000000000000000000002"
	principalA := identity.Principal{AccountID: acctID, UserID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UserName: "alice"}
	principalB := identity.Principal{AccountID: acctID, UserID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", UserName: "bob"}

	if err := e.dir.Register(akA, principalA, skA); err != nil {
		t.Fatalf("Register user A: %v", err)
	}
	if err := e.dir.Register(akB, principalB, skB); err != nil {
		t.Fatalf("Register user B: %v", err)
	}

	// User A creates one user-scoped and one domain-scoped key pair.
	status, out := e.callAs(t, akA, http.MethodPost, "/v3/{project}/keypairs",
		fmt.Sprintf(`{"keypair":{"name":"alice-user-kp","scope":"user","public_key":%q}}`, testEd25519Pub))
	if status != http.StatusOK {
		t.Fatalf("alice create user kp: status = %d, body = %s", status, out)
	}
	respA := decodeInto[createKeypairResponse](t, out)
	if respA.Keypair.UserID != principalA.UserID {
		t.Fatalf("alice user_id = %q, want %q", respA.Keypair.UserID, principalA.UserID)
	}

	status, out = e.callAs(t, akA, http.MethodPost, "/v3/{project}/keypairs",
		fmt.Sprintf(`{"keypair":{"name":"shared-domain-kp","scope":"domain","public_key":%q}}`, testEd25519Pub))
	if status != http.StatusOK {
		t.Fatalf("alice create domain kp: status = %d, body = %s", status, out)
	}

	// User A sees both in list.
	status, out = e.callAs(t, akA, http.MethodGet, "/v3/{project}/keypairs", "")
	if status != http.StatusOK {
		t.Fatalf("alice list: status = %d, body = %s", status, out)
	}
	listA := decodeInto[listKeypairsResponse](t, out)
	if len(listA.Keypairs) != 2 || listA.PageInfo.CurrentCount != 2 {
		t.Fatalf("alice list count = %d (current_count=%d), want 2", len(listA.Keypairs), listA.PageInfo.CurrentCount)
	}

	// User B sees ONLY the domain key pair in list.
	status, out = e.callAs(t, akB, http.MethodGet, "/v3/{project}/keypairs", "")
	if status != http.StatusOK {
		t.Fatalf("bob list: status = %d, body = %s", status, out)
	}
	listB := decodeInto[listKeypairsResponse](t, out)
	if len(listB.Keypairs) != 1 || listB.Keypairs[0].Keypair.Name != "shared-domain-kp" {
		t.Fatalf("bob list = %+v, want only shared-domain-kp", listB.Keypairs)
	}

	// User B can read detail of shared-domain-kp, but gets 404 KPS.6004 on alice-user-kp.
	status, _ = e.callAs(t, akB, http.MethodGet, "/v3/{project}/keypairs/shared-domain-kp", "")
	if status != http.StatusOK {
		t.Fatalf("bob detail shared-domain-kp: status = %d, want 200", status)
	}

	for _, tc := range []struct {
		method string
		body   string
	}{
		{http.MethodGet, ""},
		{http.MethodPut, `{"keypair":{"description":"hijack"}}`},
		{http.MethodDelete, ""},
	} {
		status, errBody := e.callAs(t, akB, tc.method, "/v3/{project}/keypairs/alice-user-kp", tc.body)
		if status != http.StatusNotFound {
			t.Fatalf("bob %s alice-user-kp: status = %d, want 404 (body: %s)", tc.method, status, errBody)
		}
		var eResp struct {
			ErrorCode string `json:"error_code"`
		}
		_ = json.Unmarshal(errBody, &eResp)
		if eResp.ErrorCode != "KPS.6004" {
			t.Fatalf("bob %s alice-user-kp: error_code = %q, want KPS.6004", tc.method, eResp.ErrorCode)
		}
	}

	// Direct Exists check via auth.WithIdentity agrees with HTTP visibility.
	ctxA := auth.WithIdentity(context.Background(), auth.Identity{Known: true, Principal: principalA})
	ctxB := auth.WithIdentity(context.Background(), auth.Identity{Known: true, Principal: principalB})
	if ok, err := e.svc.Exists(ctxA, testRegion, testProject, "alice-user-kp"); err != nil || !ok {
		t.Fatalf("Exists(ctxA, alice-user-kp) = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := e.svc.Exists(ctxB, testRegion, testProject, "alice-user-kp"); err != nil || ok {
		t.Fatalf("Exists(ctxB, alice-user-kp) = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := e.svc.Exists(ctxB, testRegion, testProject, "shared-domain-kp"); err != nil || !ok {
		t.Fatalf("Exists(ctxB, shared-domain-kp) = (%v, %v), want (true, nil)", ok, err)
	}

	// User B cannot reuse alice-user-kp's name (project-wide uniqueness).
	status, errBody := e.callAs(t, akB, http.MethodPost, "/v3/{project}/keypairs",
		fmt.Sprintf(`{"keypair":{"name":"alice-user-kp","public_key":%q}}`, testEd25519Pub))
	if status != http.StatusBadRequest {
		t.Fatalf("bob duplicate name: status = %d, want 400 (body: %s)", status, errBody)
	}
	var dupResp struct {
		ErrorCode string `json:"error_code"`
	}
	_ = json.Unmarshal(errBody, &dupResp)
	if dupResp.ErrorCode != "KPS.7004" {
		t.Fatalf("bob duplicate name: error_code = %q, want KPS.7004", dupResp.ErrorCode)
	}
}

func TestKeypairConcurrency(t *testing.T) {
	e := newEnv(t)

	const workers = 8
	type result struct {
		status int
		code   string
	}
	results := make([]result, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			<-start
			status, body := e.call(t, http.MethodPost, "/v3/{project}/keypairs",
				fmt.Sprintf(`{"keypair":{"name":"race-kp","public_key":%q}}`, testEd25519Pub))
			var errResp struct {
				ErrorCode string `json:"error_code"`
			}
			if status != http.StatusOK {
				_ = json.Unmarshal(body, &errResp)
			}
			results[idx] = result{status: status, code: errResp.ErrorCode}
		}(i)
	}
	close(start)
	wg.Wait()

	var okCount, dupCount int
	for _, r := range results {
		switch {
		case r.status == http.StatusOK:
			okCount++
		case r.status == http.StatusBadRequest && r.code == "KPS.7004":
			dupCount++
		default:
			t.Errorf("unexpected response: status=%d code=%q", r.status, r.code)
		}
	}
	if okCount != 1 || dupCount != workers-1 {
		t.Fatalf("ok=%d dup=%d, want ok=1 dup=%d", okCount, dupCount, workers-1)
	}

	// Distinct names created concurrently receive unique sequential IDs.
	start2 := make(chan struct{})
	wg.Add(workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			<-start2
			status, body := e.call(t, http.MethodPost, "/v3/{project}/keypairs",
				fmt.Sprintf(`{"keypair":{"name":"par-%d","public_key":%q}}`, idx, testEd25519Pub))
			if status != http.StatusOK {
				t.Errorf("par-%d: status = %d, body = %s", idx, status, body)
			}
		}(i)
	}
	close(start2)
	wg.Wait()

	seenIDs := map[int64]string{}
	for i := range workers {
		name := fmt.Sprintf("par-%d", i)
		status, raw := e.call(t, http.MethodGet, "/v3/{project}/keypairs/"+name, "")
		if status != http.StatusOK {
			t.Fatalf("detail %s: status = %d", name, status)
		}
		d := decodeInto[listKeypairDetailResponse](t, raw)
		if prev, dup := seenIDs[d.Keypair.ID]; dup {
			t.Fatalf("duplicate keypair ID %d assigned to both %s and %s", d.Keypair.ID, prev, name)
		}
		seenIDs[d.Keypair.ID] = name
	}
}
