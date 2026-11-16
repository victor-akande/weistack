package kms

import (
	"bytes"
	"errors"
	"testing"

	"github.com/victor-akande/weistack/internal/core/cmk"
)

func TestServiceKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()

	// No key named: the service's default key, made on first use, in the
	// caller's project.
	dk, err := e.svc.NewDataKey(ctx, testRegion, "", "obs")
	if err != nil {
		t.Fatal(err)
	}
	if d := e.describe(t, dk.KeyID); d["key_alias"] != "obs/default" || dk.KeyURN != testRegion+":"+testAccount.ID+":key/"+dk.KeyID {
		t.Errorf("default key = %v, %s", d, dk.KeyURN)
	}
	plain, err := e.svc.OpenDataKey(ctx, testRegion, dk.Sealed)
	if err != nil || !bytes.Equal(plain, dk.Plain) || len(plain) != 32 {
		t.Fatalf("OpenDataKey = %x, %v", plain, err)
	}

	// A named key, by ID or by OBS's longer form.
	id := e.newKey(t, `{"key_alias":"for-obs"}`)
	for _, name := range []string{id, testRegion + ":" + testAccount.ID + ":key/" + id} {
		if got, err := e.svc.NewDataKey(ctx, testRegion, name, "obs"); err != nil || got.KeyID != id {
			t.Errorf("NewDataKey(%s) = %v, %v", name, got.KeyID, err)
		}
	}
	if got, err := e.svc.Check(ctx, testRegion, testProject, id, "evs"); err != nil || got != id {
		t.Errorf("Check = %s, %v", got, err)
	}

	// Disabled, missing and unsuitable keys.
	sealed, err := e.svc.NewDataKey(ctx, testRegion, id, "obs")
	if err != nil {
		t.Fatal(err)
	}
	e.ok(t, "disable-key", ref(id))
	if _, err := e.svc.NewDataKey(ctx, testRegion, id, "obs"); !errors.Is(err, cmk.ErrDisabled) {
		t.Errorf("disabled key = %v", err)
	}
	if _, err := e.svc.OpenDataKey(ctx, testRegion, sealed.Sealed); !errors.Is(err, cmk.ErrDisabled) {
		t.Errorf("opening under a disabled key = %v", err)
	}
	sign := e.newKey(t, `{"key_alias":"signer","key_spec":"EC_P256"}`)
	for _, name := range []string{"00000000-0000-0000-0000-000000000000", "nope", sign} {
		if _, err := e.svc.Check(ctx, testRegion, testProject, name, "rds"); !errors.Is(err, cmk.ErrNotFound) {
			t.Errorf("Check(%s) = %v", name, err)
		}
	}
	if _, err := e.svc.OpenDataKey(ctx, testRegion, []byte("garbage")); !errors.Is(err, cmk.ErrNotFound) {
		t.Errorf("garbage = %v", err)
	}
}
