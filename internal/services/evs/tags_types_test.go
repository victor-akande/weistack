package evs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"

	"github.com/go-chi/chi/v5"
)

func tagsDoJSON(t *testing.T, h http.Handler, method, path, body string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, strings.ReplaceAll(path, "{p}", project), reader)
	r.Host = "evs." + region + ".myhuaweicloud.com"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

func assertEVSError(t *testing.T, status int, raw []byte, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d; body = %s", status, wantStatus, raw)
	}
	var out struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal error: %v: %s", err, raw)
	}
	if out.Error.Code != wantCode {
		t.Fatalf("error.code = %q, want %q; body = %s", out.Error.Code, wantCode, raw)
	}
}

func TestVolumeTagsHTTP(t *testing.T) {
	t.Parallel()
	h := newHandler(t, disks())

	// Initially empty on rootID.
	status, raw := tagsDoJSON(t, h, http.MethodGet, "/v2/{p}/cloudvolumes/"+rootID+"/tags", "")
	if status != http.StatusOK {
		t.Fatalf("ShowVolumeTags status = %d: %s", status, raw)
	}
	var show showVolumeTagsResponse
	if err := json.Unmarshal(raw, &show); err != nil {
		t.Fatal(err)
	}
	if len(show.Tags) != 0 {
		t.Fatalf("initial tags = %v, want empty", show.Tags)
	}

	// Create tags (unsorted keys, including empty value and CJK runes).
	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+rootID+"/tags/action",
		`{"action":"create","tags":[{"key":"env","value":"prod.1"},{"key":"app","value":""},{"key":"中文_1-a","value":"值.1"}]}`)
	if status != http.StatusNoContent || len(raw) != 0 {
		t.Fatalf("create tags = %d %q", status, raw)
	}

	// ShowVolumeTags returns sorted by key.
	status, raw = tagsDoJSON(t, h, http.MethodGet, "/v2/{p}/cloudvolumes/"+rootID+"/tags", "")
	if status != http.StatusOK {
		t.Fatalf("ShowVolumeTags = %d: %s", status, raw)
	}
	if err := json.Unmarshal(raw, &show); err != nil {
		t.Fatal(err)
	}
	wantShow := []volumeTag{
		{Key: "app", Value: ""},
		{Key: "env", Value: "prod.1"},
		{Key: "中文_1-a", Value: "值.1"},
	}
	if !reflect.DeepEqual(show.Tags, wantShow) {
		t.Fatalf("ShowVolumeTags = %#v, want %#v", show.Tags, wantShow)
	}

	// Overwrite existing key and add on dataID for ListVolumeTags aggregation.
	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+rootID+"/tags/action",
		`{"action":"create","tags":[{"key":"env","value":"staging"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("overwrite tag = %d: %s", status, raw)
	}
	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+dataID+"/tags/action",
		`{"action":"create","tags":[{"key":"env","value":"dev"},{"key":"team","value":"core"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("dataID create = %d: %s", status, raw)
	}
	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+otherID+"/tags/action",
		`{"action":"create","tags":[{"key":"env","value":"dev"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("otherID create = %d: %s", status, raw)
	}

	// ListVolumeTags returns map of key to sorted distinct values.
	status, raw = tagsDoJSON(t, h, http.MethodGet, "/v2/{p}/cloudvolumes/tags", "")
	if status != http.StatusOK {
		t.Fatalf("ListVolumeTags = %d: %s", status, raw)
	}
	var list listVolumeTagsResponse
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	wantList := map[string][]string{
		"app":    {""},
		"env":    {"dev", "staging"},
		"team":   {"core"},
		"中文_1-a": {"值.1"},
	}
	if !reflect.DeepEqual(list.Tags, wantList) {
		t.Fatalf("ListVolumeTags = %#v, want %#v", list.Tags, wantList)
	}

	// Delete existing and absent keys (absent ignored).
	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+rootID+"/tags/action",
		`{"action":"delete","tags":[{"key":"app"},{"key":"does-not-exist"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("delete tags = %d: %s", status, raw)
	}
	_, raw = tagsDoJSON(t, h, http.MethodGet, "/v2/{p}/cloudvolumes/"+rootID+"/tags", "")
	if err := json.Unmarshal(raw, &show); err != nil {
		t.Fatal(err)
	}
	if len(show.Tags) != 2 || show.Tags[0].Key != "env" || show.Tags[1].Key != "中文_1-a" {
		t.Fatalf("after delete = %#v", show.Tags)
	}
}

func TestVolumeTagsErrors(t *testing.T) {
	t.Parallel()
	h := newHandler(t, disks())

	// Missing volume -> EVS.5404 on Show, Create, Delete.
	missingID := "44444444-4444-4444-8444-444444444444"
	status, raw := tagsDoJSON(t, h, http.MethodGet, "/v2/{p}/cloudvolumes/"+missingID+"/tags", "")
	assertEVSError(t, status, raw, http.StatusNotFound, "EVS.5404")

	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+missingID+"/tags/action",
		`{"action":"create","tags":[{"key":"k","value":"v"}]}`)
	assertEVSError(t, status, raw, http.StatusNotFound, "EVS.5404")

	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+missingID+"/tags/action",
		`{"action":"delete","tags":[{"key":"k"}]}`)
	assertEVSError(t, status, raw, http.StatusNotFound, "EVS.5404")

	// Bad action / malformed JSON / empty tags -> EVS.1070.
	for _, body := range []string{
		`{`,
		`{}`,
		`{"action":"update","tags":[{"key":"k","value":"v"}]}`,
		`{"action":"create","tags":[]}`,
		`{"action":"delete","tags":[]}`,
	} {
		status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+rootID+"/tags/action", body)
		assertEVSError(t, status, raw, http.StatusBadRequest, "EVS.1070")
	}

	// Bad key / value -> EVS.1062.
	badTagBodies := []string{
		`{"action":"create","tags":[{"key":"","value":"v"}]}`,
		`{"action":"create","tags":[{"key":"` + strings.Repeat("a", 37) + `","value":"v"}]}`,
		`{"action":"create","tags":[{"key":"bad.key","value":"v"}]}`,
		`{"action":"create","tags":[{"key":"bad key","value":"v"}]}`,
		`{"action":"create","tags":[{"key":"k","value":"` + strings.Repeat("b", 44) + `"}]}`,
		`{"action":"create","tags":[{"key":"k","value":"bad/val"}]}`,
		`{"action":"delete","tags":[{"key":"bad.key"}]}`,
	}
	for _, body := range badTagBodies {
		status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+rootID+"/tags/action", body)
		assertEVSError(t, status, raw, http.StatusBadRequest, "EVS.1062")
	}

	// >10 tags -> EVS.1061.
	var tenTags []string
	for i := range 10 {
		tenTags = append(tenTags, fmt.Sprintf(`{"key":"k%d","value":"v%d"}`, i, i))
	}
	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+rootID+"/tags/action",
		`{"action":"create","tags":[`+strings.Join(tenTags, ",")+`]}`)
	if status != http.StatusNoContent {
		t.Fatalf("10 tags = %d: %s", status, raw)
	}
	// Overwriting an existing key when at 10 tags still succeeds.
	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+rootID+"/tags/action",
		`{"action":"create","tags":[{"key":"k0","value":"updated"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("overwrite at 10 tags = %d: %s", status, raw)
	}
	// Adding an 11th key fails with EVS.1061.
	status, raw = tagsDoJSON(t, h, http.MethodPost, "/v2/{p}/cloudvolumes/"+rootID+"/tags/action",
		`{"action":"create","tags":[{"key":"k10","value":"v10"}]}`)
	assertEVSError(t, status, raw, http.StatusBadRequest, "EVS.1061")
}

type staticGrants struct {
	sources []policy.Source
}

func (g staticGrants) Grants(_ context.Context, _ identity.Principal, _ authz.Scope) (authz.Grants, error) {
	return authz.Grants{Sources: g.sources}, nil
}

func TestVolumeTagsActionAuthz(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	svc, err := New(Deps{
		Store:  st,
		Engine: lifecycle.New(lifecycle.Options{}),
		IDs:    ids.NewSeeded(1),
		Logger: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.volumes(Tenant{Region: region, ProjectID: project}).Create(t.Context(), rootID, disks()[0]); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	svc.Routes(r)

	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	vlt, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}

	// Only allow evs:volumes:tagResource (not unTagResource).
	pol, err := policy.Parse([]byte(`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["evs:volumes:tagResource"],"Resource":["*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	allowCreate := staticGrants{sources: []policy.Source{{
		Name:   "allow-tag-create",
		Policy: pol,
	}}}

	call := func(body string) int {
		gate := authz.NewGate(authz.GateOptions{
			Principal: identity.Principal{AccountID: "acct-1", UserID: "u1", UserName: "user"},
			Account:   "acct-1",
			Provider:  allowCreate,
			Sealer:    vlt,
			Log:       log,
		})
		req := httptest.NewRequest(http.MethodPost, "/v2/"+project+"/cloudvolumes/"+rootID+"/tags/action", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ctx := reqctx.With(req.Context(), &reqctx.Info{RequestID: "req-1", Service: "evs", Region: region})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(authz.WithGate(ctx, gate)))
		return w.Code
	}

	if code := call(`{"action":"create","tags":[{"key":"k","value":"v"}]}`); code != http.StatusNoContent {
		t.Fatalf("allowed create = %d, want 204", code)
	}
	if code := call(`{"action":"delete","tags":[{"key":"k"}]}`); code != http.StatusForbidden {
		t.Fatalf("denied delete = %d, want 403", code)
	}
}

func TestCinderListVolumeTypes(t *testing.T) {
	t.Parallel()
	h := newHandler(t, nil)

	status, raw := tagsDoJSON(t, h, http.MethodGet, "/v2/{p}/types", "")
	if status != http.StatusOK {
		t.Fatalf("CinderListVolumeTypes = %d: %s", status, raw)
	}
	var out struct {
		VolumeTypes []map[string]any `json:"volume_types"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		name string
		id   string
	}{
		{"SATA", "f3454cbe-d625-4edd-8de0-7bd3784ec143"},
		{"SAS", "27f8d1f1-52fa-4d6c-976a-0881849963f5"},
		{"GPSSD", "fdfb39b6-1af9-44a3-b379-63d157efbb0c"},
		{"SSD", "e2a523ff-35ef-4cf6-ac9f-cedb3183f858"},
		{"ESSD", "e97c0dde-1a56-4bd4-b8a6-ff86ae28518e"},
		{"GPSSD2", "2ce7f24b-c4b0-4d64-a67e-7af8da40cde8"},
		{"ESSD2", "a96564af-93a9-4c82-8400-6ccd551cb30a"},
	}
	if len(out.VolumeTypes) != len(want) {
		t.Fatalf("len(volume_types) = %d, want %d", len(out.VolumeTypes), len(want))
	}
	for i, vt := range out.VolumeTypes {
		if vt["name"] != want[i].name || vt["id"] != want[i].id || vt["is_public"] != true {
			t.Fatalf("type[%d] = %#v, want %s/%s", i, vt, want[i].name, want[i].id)
		}
		if _, hasDesc := vt["description"]; hasDesc {
			t.Fatalf("type[%d] has unexpected description: %#v", i, vt)
		}
		es := vt["extra_specs"].(map[string]any)
		if es["volume_backend_name"] != want[i].name ||
			es["availability-zone"] != region+"a" ||
			es["RESKEY:availability_zones"] != region+"a,"+region+"b,"+region+"c" ||
			es["os-vendor-extended:sold_out_availability_zones"] != "" {
			t.Fatalf("type[%d].extra_specs = %#v", i, es)
		}
	}
}

func TestCinderListAvailabilityZones(t *testing.T) {
	t.Parallel()
	h := newHandler(t, nil)

	status, raw := tagsDoJSON(t, h, http.MethodGet, "/v2/{p}/os-availability-zone", "")
	if status != http.StatusOK {
		t.Fatalf("CinderListAvailabilityZones = %d: %s", status, raw)
	}
	var out listAvailabilityZonesResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	want := []azInfoWire{
		{ZoneName: region + "a", ZoneState: zoneStateWire{Available: true}},
		{ZoneName: region + "b", ZoneState: zoneStateWire{Available: true}},
		{ZoneName: region + "c", ZoneState: zoneStateWire{Available: true}},
	}
	if !reflect.DeepEqual(out.AvailabilityZoneInfo, want) {
		t.Fatalf("zones = %#v, want %#v", out.AvailabilityZoneInfo, want)
	}
}
