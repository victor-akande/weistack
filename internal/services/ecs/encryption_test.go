package ecs

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/cmk"
)

// fakeKeys knows one usable key, "good", and the default evs key.
type fakeKeys struct{}

func (fakeKeys) NewDataKey(context.Context, string, string, string) (cmk.DataKey, error) {
	return cmk.DataKey{}, cmk.ErrNotFound
}

func (fakeKeys) OpenDataKey(context.Context, string, []byte) ([]byte, error) {
	return nil, cmk.ErrNotFound
}

func (fakeKeys) Check(_ context.Context, _, _, keyID, service string) (string, error) {
	switch keyID {
	case "":
		return service + "-default-key", nil
	case "good":
		return "good", nil
	case "off":
		return "", cmk.ErrDisabled
	}
	return "", cmk.ErrNotFound
}

func (fakeKeys) ResolveAlias(context.Context, string, string) (string, error) {
	return "", cmk.ErrNotFound
}

func TestEncryptedDisks(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.keys = fakeKeys{}
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	status, out := e.call(t, http.MethodPost, "/v1.1/{project}/cloudservers", n.serverBody(
		"root_volume", `{"volumetype": "SSD", "metadata": {"__system__encrypted": "1"}}`,
		"data_volumes", `[{"volumetype": "SAS", "size": 10, "metadata": {"__system__encrypted": "1", "__system__cmkid": "good"}}, {"volumetype": "SAS", "size": 10}]`,
	))
	if status != http.StatusOK {
		t.Fatalf("create = %d %s", status, out)
	}
	created := decodeInto[createServersResponse](t, out)
	vols, err := e.volumes.DisksOf(t.Context(), testTenant.evs(), created.ServerIDs[0])
	if err != nil || len(vols) != 3 {
		t.Fatalf("DisksOf = %+v, %v", vols, err)
	}
	if vols[0].KMSKeyID != "evs-default-key" || vols[1].KMSKeyID != "good" || vols[2].KMSKeyID != "" {
		t.Errorf("disk keys = %q %q %q", vols[0].KMSKeyID, vols[1].KMSKeyID, vols[2].KMSKeyID)
	}

	for _, md := range []string{
		`{"__system__encrypted": "1", "__system__cmkid": "missing"}`,
		`{"__system__encrypted": "1", "__system__cmkid": "off"}`,
		`{"__system__encrypted": "yes"}`,
		`{"__system__cmkid": "good"}`,
	} {
		status, out := e.call(t, http.MethodPost, "/v1.1/{project}/cloudservers", n.serverBody(
			"data_volumes", `[{"volumetype": "SAS", "size": 10, "metadata": `+md+`}]`))
		if status != http.StatusBadRequest || !strings.Contains(string(out), "Ecs.0005") {
			t.Errorf("%s = %d %s", md, status, out)
		}
	}
}
