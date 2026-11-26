package kps

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/inventory"
)

func TestReportResources(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	// Managed key pair in testProject with vault-sealed private key protection.
	status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs",
		`{"keypair":{"name":"managed-kp","key_protection":{"encryption":{"type":"default"}}}}`)
	if status != http.StatusOK {
		t.Fatalf("creating managed keypair: %d %s", status, raw)
	}
	created := decodeInto[createKeypairResponse](t, raw)
	if created.Keypair.PublicKey == "" || created.Keypair.PrivateKey == "" {
		t.Fatalf("expected generated public_key and private_key, got %+v", created.Keypair)
	}

	e.clock.Advance(5 * time.Second)
	updatedAt := e.clock.Now()
	status, raw = e.call(t, http.MethodPut, "/v3/{project}/keypairs/managed-kp",
		`{"keypair":{"description":"updated description"}}`)
	if status != http.StatusOK {
		t.Fatalf("updating description: %d %s", status, raw)
	}

	stored, err := e.svc.keypairs(testTenant).Get(t.Context(), "managed-kp")
	if err != nil {
		t.Fatalf("store Get managed-kp: %v", err)
	}
	if stored.PublicKey == "" || len(stored.SealedKey) == 0 {
		t.Fatalf("expected PublicKey and SealedKey populated in store, got pub=%d sealed=%d",
			len(stored.PublicKey), len(stored.SealedKey))
	}

	// Imported key pair in a second project (UpdatedAt remains 0).
	const otherProject = "fedcba9876543210fedcba9876543210"
	e.clock.Advance(3 * time.Second)
	otherCreated := e.clock.Now()
	status, raw = e.call(t, http.MethodPost, "/v3/"+otherProject+"/keypairs",
		fmt.Sprintf(`{"keypair":{"name":"imported-kp","scope":"domain","public_key":%q}}`, testEd25519Pub))
	if status != http.StatusOK {
		t.Fatalf("creating imported keypair in second project: %d %s", status, raw)
	}

	// Trigger an associate task against a missing server and settle so both
	// kps.task and kps.failed_task records exist in the store and must not be reported.
	status, raw = e.call(t, http.MethodPost, "/v3/{project}/keypairs/associate",
		`{"keypair_name":"managed-kp","server":{"id":"srv-missing"}}`)
	if status != http.StatusAccepted {
		t.Fatalf("associating missing server: %d %s", status, raw)
	}
	e.clock.Advance(testDelay + time.Second)
	if err := e.engine.WaitIdle(t.Context()); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
	status, raw = e.call(t, http.MethodGet, "/v3/{project}/failed-tasks", "")
	if status != http.StatusOK {
		t.Fatalf("listing failed tasks: %d %s", status, raw)
	}
	if failed := decodeInto[listFailedTaskResponse](t, raw); failed.Total != 1 {
		t.Fatalf("failed tasks total = %d, want 1", failed.Total)
	}

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := make(map[string]inventory.Resource)
	for _, r := range snap.Resources {
		got[r.Type.String()+"/"+r.ProjectID+"/"+r.ID] = r
	}
	at := func(typ inventory.Type, project, id string) inventory.Resource {
		t.Helper()
		r, ok := got[typ.String()+"/"+project+"/"+id]
		if !ok {
			t.Fatalf("%s %s in %s is not reported; got %v", typ, id, project, snap.Resources)
		}
		return r
	}

	m := at(inventory.KPSKeypairs, testProject, "managed-kp")
	if m.ID != "managed-kp" || m.Name != "managed-kp" ||
		m.RegionID != testRegion || m.ProjectID != testProject || m.AccountID != "" ||
		m.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!m.Created.Equal(testEpoch) || !m.Updated.Equal(updatedAt) ||
		m.State != inventory.Succeeded || len(m.Tags) != 0 || len(m.Relations) != 0 {
		t.Errorf("managed keypair = %+v", m)
	}

	imp := at(inventory.KPSKeypairs, otherProject, "imported-kp")
	if imp.ID != "imported-kp" || imp.Name != "imported-kp" ||
		imp.RegionID != testRegion || imp.ProjectID != otherProject || imp.AccountID != "" ||
		imp.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!imp.Created.Equal(otherCreated) || !imp.Updated.Equal(otherCreated) ||
		imp.State != inventory.Succeeded || len(imp.Tags) != 0 || len(imp.Relations) != 0 {
		t.Errorf("imported keypair = %+v", imp)
	}

	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.KPSKeypairs: 2,
	}
	if fmt.Sprint(count) != fmt.Sprint(want) {
		t.Errorf("reported %v, want %v", count, want)
	}

	// Verify no public key, private key PEM, fingerprint, or sealed key material
	// appears anywhere in the snapshot representation.
	dump := fmt.Sprintf("%+v", snap)
	forbidden := []struct {
		label string
		text  string
	}{
		{"managed public key", created.Keypair.PublicKey},
		{"imported public key", testEd25519Pub},
		{"private key PEM", created.Keypair.PrivateKey},
		{"PEM header", "PRIVATE KEY"},
		{"managed fingerprint", created.Keypair.Fingerprint},
		{"imported fingerprint", testEd25519FP},
		{"sealed key hex", hex.EncodeToString(stored.SealedKey)},
		{"sealed key raw", string(stored.SealedKey)},
	}
	if pubParts := strings.Fields(created.Keypair.PublicKey); len(pubParts) >= 2 {
		forbidden = append(forbidden, struct {
			label string
			text  string
		}{"managed public key body", pubParts[1]})
	}
	if pemLines := strings.Split(strings.TrimSpace(created.Keypair.PrivateKey), "\n"); len(pemLines) > 2 {
		forbidden = append(forbidden, struct {
			label string
			text  string
		}{"private key PEM body", pemLines[1]})
	}
	for _, tc := range forbidden {
		if tc.text != "" && strings.Contains(dump, tc.text) {
			t.Errorf("inventory snapshot leaked %s", tc.label)
		}
	}
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	cases := []struct {
		name string
		body string
		want inventory.State
	}{
		{
			name: "kp-ssh-user",
			body: fmt.Sprintf(`{"keypair":{"name":"kp-ssh-user","type":"ssh","scope":"user","public_key":%q}}`, testEd25519Pub),
			want: inventory.Succeeded,
		},
		{
			name: "kp-ssh-domain",
			body: fmt.Sprintf(`{"keypair":{"name":"kp-ssh-domain","type":"ssh","scope":"domain","public_key":%q}}`, testEd25519Pub),
			want: inventory.Succeeded,
		},
		{
			name: "kp-x509",
			body: fmt.Sprintf(`{"keypair":{"name":"kp-x509","type":"x509","public_key":%q}}`, testEd25519Pub),
			want: inventory.Succeeded,
		},
		{
			name: "kp-protected",
			body: `{"keypair":{"name":"kp-protected","key_protection":{"encryption":{"type":"default"}}}}`,
			want: inventory.Succeeded,
		},
	}
	for _, tc := range cases {
		status, raw := e.call(t, http.MethodPost, "/v3/{project}/keypairs", tc.body)
		if status != http.StatusOK {
			t.Fatalf("creating %s: %d %s", tc.name, status, raw)
		}
	}

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	states := make(map[string]inventory.State, len(snap.Resources))
	for _, r := range snap.Resources {
		states[r.ID] = r.State
	}
	for _, tc := range cases {
		if got := states[tc.name]; got != tc.want {
			t.Errorf("state(%s) = %s, want %s", tc.name, got, tc.want)
		}
	}
}
