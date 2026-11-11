package rds

import (
	"net/http"
	"testing"
)

func TestStorageUsedSpace(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id, _ := e.mustCreate(t, e.body())
	inst := e.instance(t, id)

	status, out := e.call(t, http.MethodGet, "/instances/"+id+"/storage-used-space", "")
	got := decodeInto[storageUsedSpace](t, out)
	if status != http.StatusOK || got.NodeID != inst.NodeIDs[0] || got.Used != "0" {
		t.Fatalf("storage-used-space = %d %s", status, out)
	}
	if status, _ = e.call(t, http.MethodGet, "/instances/00000000000000000000000000000000in01/storage-used-space", ""); status != http.StatusNotFound {
		t.Fatalf("a missing instance: %d", status)
	}
}
