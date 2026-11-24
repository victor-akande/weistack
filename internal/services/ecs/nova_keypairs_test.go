package ecs

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

const novaKeypairsPath = "/v2.1/{project}/os-keypairs"

type fakeKeypairRecord struct {
	detail        NovaKeypairDetailOutput
	keyProtection *NovaKeyProtectionInput
}

type fakeKeypairs struct {
	mu      sync.Mutex
	nextID  int64
	order   []string
	records map[string]fakeKeypairRecord
	created int64
}

func newFakeKeypairs() *fakeKeypairs {
	return &fakeKeypairs{
		records: map[string]fakeKeypairRecord{},
		created: testEpoch.UnixMilli(),
	}
}

func fakeKey(region, projectID, name string) string {
	return region + "/" + projectID + "/" + name
}

func (f *fakeKeypairs) Exists(_ context.Context, region, projectID, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.records[fakeKey(region, projectID, name)]
	return ok, nil
}

func (f *fakeKeypairs) NovaCreate(_ context.Context, region, projectID string, req NovaCreateKeypairInput) (NovaKeypairOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	k := fakeKey(region, projectID, req.Name)
	if _, exists := f.records[k]; exists {
		return NovaKeypairOutput{}, apierr.New(http.StatusBadRequest, "KPS.7004", "Key pair '%s' already exists.", req.Name)
	}

	f.nextID++
	kpType := req.Type
	if kpType == "" {
		kpType = "ssh"
	}
	userID := req.UserID
	if userID == "" {
		userID = "0123456789abcdef0123456789abcdef"
	}

	pubKey := req.PublicKey
	privKey := ""
	if pubKey == "" {
		pubKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfakegeneratedkey"
		privKey = "-----BEGIN RSA PRIVATE KEY-----\nfake-generated-private-key\n-----END RSA PRIVATE KEY-----\n"
	}
	fp := "49:ef:73:2b:9b:7f:2e:0c:58:d3:e3:42:8e:28:04:3b"

	rec := fakeKeypairRecord{
		detail: NovaKeypairDetailOutput{
			ID:          f.nextID,
			Name:        req.Name,
			Type:        kpType,
			PublicKey:   pubKey,
			Fingerprint: fp,
			UserID:      userID,
			Deleted:     false,
			CreatedAt:   f.created,
		},
		keyProtection: req.KeyProtection,
	}
	f.records[k] = rec
	f.order = append(f.order, k)

	return NovaKeypairOutput{
		Name:        req.Name,
		Type:        kpType,
		PublicKey:   pubKey,
		PrivateKey:  privKey,
		Fingerprint: fp,
		UserID:      userID,
	}, nil
}

func (f *fakeKeypairs) NovaList(_ context.Context, region, projectID, marker string, limit int) ([]NovaKeypairOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	prefix := region + "/" + projectID + "/"
	var all []NovaKeypairOutput
	for _, k := range f.order {
		rec, ok := f.records[k]
		if !ok || len(k) <= len(prefix) || k[:len(prefix)] != prefix {
			continue
		}
		all = append(all, NovaKeypairOutput{
			Name:        rec.detail.Name,
			Type:        rec.detail.Type,
			PublicKey:   rec.detail.PublicKey,
			Fingerprint: rec.detail.Fingerprint,
			UserID:      rec.detail.UserID,
		})
	}

	start := 0
	if marker != "" {
		found := -1
		for i, kp := range all {
			if kp.Name == marker {
				found = i + 1
				break
			}
		}
		if found < 0 || found >= len(all) {
			return []NovaKeypairOutput{}, nil
		}
		start = found
	}
	end := len(all)
	if limit > 0 && limit < end-start {
		end = start + limit
	}
	return all[start:end], nil
}

func (f *fakeKeypairs) NovaGet(_ context.Context, region, projectID, name string) (NovaKeypairDetailOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rec, ok := f.records[fakeKey(region, projectID, name)]
	if !ok {
		return NovaKeypairDetailOutput{}, apierr.New(http.StatusNotFound, "KPS.6004", "No Keypair find.")
	}
	return rec.detail, nil
}

func (f *fakeKeypairs) NovaDelete(_ context.Context, region, projectID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	k := fakeKey(region, projectID, name)
	if _, ok := f.records[k]; !ok {
		return apierr.New(http.StatusNotFound, "KPS.6004", "No Keypair find.")
	}
	delete(f.records, k)
	return nil
}

func (f *fakeKeypairs) setUpdatedAt(region, projectID, name string, ms int64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	k := fakeKey(region, projectID, name)
	if rec, ok := f.records[k]; ok {
		rec.detail.UpdatedAt = ms
		f.records[k] = rec
	}
}

func (f *fakeKeypairs) protectionOf(region, projectID, name string) *NovaKeyProtectionInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[fakeKey(region, projectID, name)].keyProtection
}

func TestServerKeyNameValidationAndMethods(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fk := newFakeKeypairs()
	e.svc.SetKeypairs(fk)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	// Creating a server with an unknown key_name returns 400 Ecs.0314.
	e.expect(t, "nova_keypair_ecs_missing", http.MethodPost, serversPath, n.serverBody("key_name", `"missing-key"`))

	// Create the key pair via Nova, then create a server using it.
	status, out := e.call(t, http.MethodPost, novaKeypairsPath, `{"keypair": {"name": "deploy-key"}}`)
	if status != http.StatusOK {
		t.Fatalf("NovaCreateKeypair: %d %s", status, out)
	}

	_, ids := e.mustCreate(t, n.serverBody("name", `"web-ssh"`, "key_name", `"deploy-key"`))
	e.settle(t)
	serverID := ids[0]

	status, out = e.call(t, http.MethodGet, serversPath+"/"+serverID, "")
	if status != http.StatusOK {
		t.Fatalf("ShowServer: %d %s", status, out)
	}
	detail := decodeInto[serverResponse](t, out).Server
	if detail.KeyName == nil || *detail.KeyName != "deploy-key" {
		t.Fatalf("server key_name = %v, want deploy-key", detail.KeyName)
	}

	// Deleting the key pair leaves the server's key_name as it was.
	e.expect(t, "nova_keypair_delete", http.MethodDelete, novaKeypairsPath+"/deploy-key", "")

	status, out = e.call(t, http.MethodGet, serversPath+"/"+serverID, "")
	if status != http.StatusOK {
		t.Fatalf("ShowServer after keypair delete: %d %s", status, out)
	}
	detail = decodeInto[serverResponse](t, out).Server
	if detail.KeyName == nil || *detail.KeyName != "deploy-key" {
		t.Fatalf("server key_name after keypair delete = %v, want deploy-key", detail.KeyName)
	}

	// ServerExists checks both existing and missing servers.
	ctx := t.Context()
	name, ok, err := e.svc.ServerExists(ctx, testRegion, testProject, serverID)
	if err != nil || !ok || name != "web-ssh" {
		t.Fatalf("ServerExists(existing) = (%q, %v, %v), want (web-ssh, true, nil)", name, ok, err)
	}
	name, ok, err = e.svc.ServerExists(ctx, testRegion, testProject, unknownID)
	if err != nil || ok || name != "" {
		t.Fatalf("ServerExists(missing) = (%q, %v, %v), want (\"\", false, nil)", name, ok, err)
	}

	// SetKeyName updates and clears key_name on an existing server.
	if err := e.svc.SetKeyName(ctx, testRegion, testProject, serverID, "rotated-key"); err != nil {
		t.Fatalf("SetKeyName(set): %v", err)
	}
	status, out = e.call(t, http.MethodGet, serversPath+"/"+serverID, "")
	if status != http.StatusOK {
		t.Fatalf("ShowServer after SetKeyName: %d %s", status, out)
	}
	if got := decodeInto[serverResponse](t, out).Server.KeyName; got == nil || *got != "rotated-key" {
		t.Fatalf("server key_name after SetKeyName = %v, want rotated-key", got)
	}

	if err := e.svc.SetKeyName(ctx, testRegion, testProject, serverID, ""); err != nil {
		t.Fatalf("SetKeyName(clear): %v", err)
	}
	status, out = e.call(t, http.MethodGet, serversPath+"/"+serverID, "")
	if status != http.StatusOK {
		t.Fatalf("ShowServer after SetKeyName clear: %d %s", status, out)
	}
	if got := decodeInto[serverResponse](t, out).Server.KeyName; got != nil {
		t.Fatalf("server key_name after clear = %q, want nil", *got)
	}

	// SetKeyName on a missing server returns Ecs.0114.
	if err := e.svc.SetKeyName(ctx, testRegion, testProject, unknownID, "any"); codeOf(err) != "Ecs.0114" {
		t.Fatalf("SetKeyName(missing) err = %v, want Ecs.0114", err)
	}
}

func TestNovaKeypairLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fk := newFakeKeypairs()
	e.svc.SetKeypairs(fk)

	// Empty list returns {"keypairs": []}.
	e.expect(t, "nova_keypair_list_empty", http.MethodGet, novaKeypairsPath, "")

	// Generate a new key pair: response contains private_key.
	e.expect(t, "nova_keypair_create_generated", http.MethodPost, novaKeypairsPath,
		`{"keypair": {"name": "gen-key"}}`)

	// Import a public key with key_protection: response omits private_key and
	// forwards key_protection to the backend.
	e.expect(t, "nova_keypair_create_imported", http.MethodPost, novaKeypairsPath, `{
		"keypair": {
			"name": "imp-key",
			"public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCimportedkey",
			"key_protection": {
				"private_key": "-----BEGIN RSA PRIVATE KEY-----\nimported\n-----END RSA PRIVATE KEY-----\n",
				"encryption": {
					"type": "kms",
					"kms_key_name": "demo",
					"kms_key_id": "kms-key-1"
				}
			}
		}
	}`)

	prot := fk.protectionOf(testRegion, testProject, "imp-key")
	if prot == nil || prot.PrivateKey == "" || prot.Encryption == nil ||
		prot.Encryption.Type != "kms" || prot.Encryption.KMSKeyName != "demo" || prot.Encryption.KMSKeyID != "kms-key-1" {
		t.Fatalf("forwarded key_protection = %+v, want kms/demo/kms-key-1", prot)
	}

	// List returns both key pairs wrapped in {"keypair": {...}} without private_key.
	e.expect(t, "nova_keypair_list", http.MethodGet, novaKeypairsPath, "")

	// Pagination with limit and marker.
	status, out := e.call(t, http.MethodGet, novaKeypairsPath+"?limit=1", "")
	if status != http.StatusOK {
		t.Fatalf("list limit=1: %d %s", status, out)
	}
	page1 := decodeInto[novaListKeypairsResponse](t, out)
	if len(page1.Keypairs) != 1 || page1.Keypairs[0].Keypair.Name != "gen-key" {
		t.Fatalf("page1 = %+v, want [gen-key]", page1.Keypairs)
	}
	status, out = e.call(t, http.MethodGet, novaKeypairsPath+"?limit=1&marker=gen-key", "")
	if status != http.StatusOK {
		t.Fatalf("list marker=gen-key: %d %s", status, out)
	}
	page2 := decodeInto[novaListKeypairsResponse](t, out)
	if len(page2.Keypairs) != 1 || page2.Keypairs[0].Keypair.Name != "imp-key" {
		t.Fatalf("page2 = %+v, want [imp-key]", page2.Keypairs)
	}

	// Show key pair detail (updated_at is null initially).
	e.expect(t, "nova_keypair_show", http.MethodGet, novaKeypairsPath+"/gen-key", "")

	// Show key pair detail when updated_at is set formats as RFC3339 UTC.
	updated := testEpoch.Add(15 * time.Minute)
	fk.setUpdatedAt(testRegion, testProject, "gen-key", updated.UnixMilli())
	status, out = e.call(t, http.MethodGet, novaKeypairsPath+"/gen-key", "")
	if status != http.StatusOK {
		t.Fatalf("show updated: %d %s", status, out)
	}
	shown := decodeInto[novaShowKeypairResponse](t, out).Keypair
	wantUpdated := updated.UTC().Format(timeLayout)
	if shown.UpdatedAt == nil || *shown.UpdatedAt != wantUpdated {
		t.Fatalf("updated_at = %v, want %q", shown.UpdatedAt, wantUpdated)
	}

	// Delete returns 202 Accepted with an empty body.
	e.expect(t, "nova_keypair_delete", http.MethodDelete, novaKeypairsPath+"/gen-key", "")

	// Show and Delete of a missing key pair return 404 KPS.6004.
	e.expect(t, "nova_keypair_not_found", http.MethodGet, novaKeypairsPath+"/gen-key", "")
	e.expect(t, "nova_keypair_not_found", http.MethodDelete, novaKeypairsPath+"/gen-key", "")
}

func TestNovaKeypairErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fk := newFakeKeypairs()
	e.svc.SetKeypairs(fk)

	// Invalid request bodies return 400 Ecs.0005.
	for _, tt := range []struct {
		name string
		body string
	}{
		{"empty body", ``},
		{"malformed json", `{"keypair":`},
		{"missing keypair object", `{}`},
		{"empty name", `{"keypair": {}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, "error_ecs_0005", http.MethodPost, novaKeypairsPath, tt.body)
		})
	}

	// Duplicate keypair name returns 400 KPS.7004.
	status, out := e.call(t, http.MethodPost, novaKeypairsPath, `{"keypair": {"name": "dup-key"}}`)
	if status != http.StatusOK {
		t.Fatalf("first create: %d %s", status, out)
	}
	e.expect(t, "nova_keypair_duplicate", http.MethodPost, novaKeypairsPath, `{"keypair": {"name": "dup-key"}}`)

	// Invalid limit query values return 400 Ecs.0005.
	for _, q := range []string{"?limit=0", "?limit=1001", "?limit=abc"} {
		t.Run("list "+q, func(t *testing.T) {
			e.expect(t, "error_ecs_0005", http.MethodGet, novaKeypairsPath+q, "")
		})
	}
}

func TestNovaKeypairNotImplementedWhenUnwired(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	e.expect(t, "error_not_implemented", http.MethodPost, novaKeypairsPath, `{"keypair": {"name": "k"}}`)
	e.expect(t, "error_not_implemented", http.MethodGet, novaKeypairsPath, "")
	e.expect(t, "error_not_implemented", http.MethodGet, novaKeypairsPath+"/k", "")
	e.expect(t, "error_not_implemented", http.MethodDelete, novaKeypairsPath+"/k", "")
}
