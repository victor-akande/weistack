package evs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

const (
	project = "0123456789abcdef0123456789abcdef"
	region  = "ap-southeast-1"
	rootID  = "11111111-1111-4111-8111-111111111111"
	dataID  = "22222222-2222-4222-8222-222222222222"
	otherID = "33333333-3333-4333-8333-333333333333"
)

type fakeSource struct {
	vols []Volume
	err  error
}

func (f *fakeSource) Volumes(_ context.Context, r, p string) ([]Volume, error) {
	if r != region || p != project {
		return nil, nil
	}
	return f.vols, f.err
}

func newHandler(t *testing.T, src VolumeSource) http.Handler {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := New(Deps{Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	if src != nil {
		svc.SetVolumes(src)
	}
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: project, Logger: log, Store: st, Engine: lifecycle.New(lifecycle.Options{}),
		IDs: ids.New(), Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

func get(t *testing.T, h http.Handler, path string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, strings.ReplaceAll(path, "{p}", project), nil)
	r.Host = "evs." + region + ".myhuaweicloud.com"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %v: %s", path, err, w.Body)
	}
	return w.Code, out
}

func disks() *fakeSource {
	return &fakeSource{vols: []Volume{
		{ID: rootID, Name: "web-volume-0000", Type: "GPSSD", SizeGB: 40, Device: "/dev/vda", Bootable: true,
			ServerID: "srv-1", AvailabilityZone: "ap-southeast-1a", ImageID: "img-1", ImageName: "Ubuntu",
			Created: "2026-01-02T03:04:05Z", Updated: "2026-01-02T03:04:05Z"},
		{ID: dataID, Name: "web-volume-0001", Type: "SSD", SizeGB: 100, Device: "/dev/vdb",
			ServerID: "srv-1", AvailabilityZone: "ap-southeast-1a", Created: "2026-01-02T03:04:05Z", EnterpriseProjectID: "ep"},
		{ID: otherID, Name: "db-volume-0000", Type: "SAS", SizeGB: 40, Device: "/dev/vda", Bootable: true,
			ServerID: "srv-2", AvailabilityZone: "ap-southeast-1b"},
	}}
}

func TestShowVolume(t *testing.T) {
	t.Parallel()
	h := newHandler(t, disks())

	status, out := get(t, h, "/v2/{p}/cloudvolumes/"+rootID)
	if status != http.StatusOK {
		t.Fatalf("ShowVolume: %d %v", status, out)
	}
	v := out["volume"].(map[string]any)
	atts := v["attachments"].([]any)
	att := atts[0].(map[string]any)
	if v["status"] != "in-use" || v["size"] != 40.0 || v["volume_type"] != "GPSSD" || v["bootable"] != "true" ||
		v["os-vol-tenant-attr:tenant_id"] != project || v["enterprise_project_id"] != "0" || v["service_type"] != "EVS" ||
		v["volume_image_metadata"].(map[string]any)["image_id"] != "img-1" ||
		len(atts) != 1 || att["server_id"] != "srv-1" || att["device"] != "/dev/vda" || att["volume_id"] != rootID {
		t.Fatalf("volume = %v", v)
	}

	_, out = get(t, h, "/v2/{p}/cloudvolumes/"+dataID)
	if v := out["volume"].(map[string]any); v["bootable"] != "false" || len(v["volume_image_metadata"].(map[string]any)) != 0 || v["enterprise_project_id"] != "ep" {
		t.Fatalf("data disk = %v", v)
	}

	status, out = get(t, h, "/v2/{p}/cloudvolumes/44444444-4444-4444-8444-444444444444")
	if e := out["error"].(map[string]any); status != http.StatusNotFound || e["code"] != "EVS.5404" {
		t.Fatalf("a missing volume: %d %v", status, out)
	}
	// Another project sees none of them.
	if status, _ = get(t, h, "/v2/ffffffffffffffffffffffffffffffff/cloudvolumes/"+rootID); status != http.StatusNotFound {
		t.Fatalf("another project: %d", status)
	}
}

func TestListVolumes(t *testing.T) {
	t.Parallel()
	h := newHandler(t, disks())
	ids := func(path string) []string {
		t.Helper()
		status, out := get(t, h, path)
		if status != http.StatusOK {
			t.Fatalf("%s: %d %v", path, status, out)
		}
		var got []string
		for _, v := range out["volumes"].([]any) {
			got = append(got, v.(map[string]any)["id"].(string))
		}
		return got
	}
	for path, want := range map[string]int{
		"/v2/{p}/cloudvolumes/detail":                                      3,
		"/v2/{p}/cloudvolumes/detail?server_id=srv-1":                      2,
		"/v2/{p}/cloudvolumes/detail?name=db":                              1,
		"/v2/{p}/cloudvolumes/detail?availability_zone=ap-southeast-1b":    1,
		"/v2/{p}/cloudvolumes/detail?status=available":                     0,
		"/v2/{p}/cloudvolumes/detail?ids=[" + rootID + "," + otherID + "]": 2,
		"/v2/{p}/cloudvolumes/detail?id=" + dataID:                         1,
		"/v2/{p}/cloudvolumes/detail?limit=2":                              2,
		"/v2/{p}/cloudvolumes/detail?limit=2&offset=2":                     1,
		"/v2/ffffffffffffffffffffffffffffffff/cloudvolumes/detail":         0,
	} {
		if got := ids(path); len(got) != want {
			t.Errorf("%s: %d volumes, want %d", path, len(got), want)
		}
	}
	if _, out := get(t, h, "/v2/{p}/cloudvolumes/detail?limit=1"); out["count"] != 3.0 {
		t.Errorf("count is the number of matches, not of the page: %v", out["count"])
	}

	for path, code := range map[string]string{
		"/v2/{p}/cloudvolumes/detail?limit=x":    "EVS.1023",
		"/v2/{p}/cloudvolumes/detail?limit=1001": "EVS.2142",
		"/v2/{p}/cloudvolumes/detail?offset=-1":  "EVS.1070",
	} {
		status, out := get(t, h, path)
		if e, _ := out["error"].(map[string]any); status != http.StatusBadRequest || e["code"] != code {
			t.Errorf("%s: %d %v, want %s", path, status, out, code)
		}
	}
}

func TestWithoutASource(t *testing.T) {
	t.Parallel()
	h := newHandler(t, nil)
	if status, out := get(t, h, "/v2/{p}/cloudvolumes/detail"); status != http.StatusOK || out["count"] != 0.0 {
		t.Fatalf("no source: %d %v", status, out)
	}
	failing := newHandler(t, &fakeSource{err: errors.New("disk on fire")})
	if status, _ := get(t, failing, "/v2/{p}/cloudvolumes/"+rootID); status != http.StatusInternalServerError {
		t.Fatalf("a failing source: %d", status)
	}
}

func TestUnemulatedOperations(t *testing.T) {
	t.Parallel()
	h := newHandler(t, disks())
	r := httptest.NewRequest(http.MethodPost, "/v2/"+project+"/cloudvolumes", strings.NewReader(`{}`))
	r.Host = "evs." + region + ".myhuaweicloud.com"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("creating a volume: %d %s", w.Code, w.Body)
	}
}

func TestNewNeedsALogger(t *testing.T) {
	t.Parallel()
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New accepted no logger")
	}
}
