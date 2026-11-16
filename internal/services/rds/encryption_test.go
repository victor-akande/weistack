package rds

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/cmk"
)

type fakeKeys struct{}

func (fakeKeys) NewDataKey(context.Context, string, string, string) (cmk.DataKey, error) {
	return cmk.DataKey{}, cmk.ErrNotFound
}

func (fakeKeys) OpenDataKey(context.Context, string, []byte) ([]byte, error) {
	return nil, cmk.ErrNotFound
}

func (fakeKeys) Check(_ context.Context, _, _, keyID, _ string) (string, error) {
	if keyID == "good" {
		return "good", nil
	}
	return "", cmk.ErrNotFound
}

func TestEncryptedStorage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.keys = fakeKeys{}
	id, _ := e.mustCreate(t, e.body("name", `"encrypted"`, "disk_encryption_id", `"good"`))
	if inst := e.instance(t, id); inst.DiskEncryptionID != "good" {
		t.Errorf("instance = %+v", inst)
	}
	_, out := e.call(t, http.MethodGet, "/instances?id="+id, "")
	if !strings.Contains(string(out), `"disk_encryption_id":"good"`) {
		t.Errorf("list = %s", out)
	}
	status, out := e.call(t, http.MethodPost, "/instances", e.body("name", `"bad-key"`, "disk_encryption_id", `"missing"`))
	if status != http.StatusBadRequest || !strings.Contains(string(out), "DBS.200001") {
		t.Errorf("unknown key = %d %s", status, out)
	}
}
