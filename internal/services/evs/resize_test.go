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
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

type fakeServers struct {
	servers map[string]ServerInfo
}

func (f *fakeServers) ServerForVolume(_ context.Context, _ Tenant, id string) (ServerInfo, error) {
	info, ok := f.servers[id]
	if !ok {
		return ServerInfo{}, ErrServerNotFound
	}
	return info, nil
}

func (f *fakeServers) AttachVolume(_ context.Context, _ Tenant, _, _ string) error {
	return nil
}

type faultOnce struct {
	kind string
	err  error
}

func (f *faultOnce) Fault(kind, _ string) error {
	if kind == f.kind {
		return f.err
	}
	return nil
}

type resizeEnv struct {
	svc     *Service
	handler http.Handler
	clock   *lifecycle.FakeClock
	engine  *lifecycle.Engine
	servers *fakeServers
}

func newResizeEnv(t *testing.T, vols []volume, faults lifecycle.FaultInjector) *resizeEnv {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.NewMemory()
	clock := lifecycle.NewFakeClock(time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC))
	engine := lifecycle.New(lifecycle.Options{Delay: 2 * time.Second, Clock: clock, Logger: log, Faults: faults})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(7)
	svc, err := New(Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeServers{servers: map[string]ServerInfo{}}
	svc.SetServers(fs)

	ten := Tenant{Region: region, ProjectID: project}
	for _, v := range vols {
		if err := svc.volumes(ten).Create(context.Background(), v.ID, v); err != nil {
			t.Fatal(err)
		}
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: project, Logger: log, Store: st, Engine: engine,
		IDs: gen, Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &resizeEnv{svc: svc, handler: srv.Handler(), clock: clock, engine: engine, servers: fs}
}

func (e *resizeEnv) postResize(t *testing.T, volumeID, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v2.1/"+project+"/cloudvolumes/"+volumeID+"/action", strings.NewReader(body))
	r.Host = "evs." + region + ".myhuaweicloud.com"
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("resize %s: %v: %s", volumeID, err, w.Body)
	}
	return w.Code, out
}

func (e *resizeEnv) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(3 * time.Second)
	if err := e.engine.WaitIdle(t.Context()); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

func TestResizeVolumeSuccess(t *testing.T) {
	t.Parallel()
	ten := Tenant{Region: region, ProjectID: project}
	vols := []volume{
		{
			ID: dataID, Name: "avail-vol", Status: statusAvailable, VolumeType: "GPSSD", SizeGB: 20,
			AvailabilityZone: "ap-southeast-1a",
		},
		{
			ID: rootID, Name: "inuse-vol", Status: statusInUse, VolumeType: "SSD", SizeGB: 40,
			Bootable: true, AvailabilityZone: "ap-southeast-1a",
			Attachments: []attachment{{ID: rootID, ServerID: "srv-active", Device: "/dev/vda", BootIndex: 0}},
		},
		{
			ID: otherID, Name: "shutoff-vol", Status: statusInUse, VolumeType: "SAS", SizeGB: 50,
			AvailabilityZone: "ap-southeast-1a",
			Attachments:      []attachment{{ID: otherID, ServerID: "srv-shutoff", Device: "/dev/vdb", BootIndex: -1}},
		},
	}
	e := newResizeEnv(t, vols, nil)
	e.servers.servers["srv-active"] = ServerInfo{AvailabilityZone: "ap-southeast-1a", Status: "ACTIVE"}
	e.servers.servers["srv-shutoff"] = ServerInfo{AvailabilityZone: "ap-southeast-1a", Status: "SHUTOFF"}

	// Available volume resize (with bssParam ignored).
	code, out := e.postResize(t, dataID, `{"os-extend": {"new_size": 30}, "bssParam": {"isAutoPay": "true"}}`)
	if code != http.StatusAccepted || out["job_id"] == "" {
		t.Fatalf("resize available = %d %v", code, out)
	}
	jobID := out["job_id"].(string)

	v, err := e.svc.volumes(ten).Get(t.Context(), dataID)
	if err != nil || v.Status != statusExtending || v.SizeGB != 20 {
		t.Fatalf("during extend = %+v, err=%v", v, err)
	}
	j, err := e.svc.jobs(ten).Get(t.Context(), jobID)
	if err != nil || j.Status != "RUNNING" || j.JobType != "extendVolume" {
		t.Fatalf("running job = %+v, err=%v", j, err)
	}

	e.settle(t)
	v, _ = e.svc.volumes(ten).Get(t.Context(), dataID)
	if v.Status != statusAvailable || v.SizeGB != 30 || v.Pending != nil {
		t.Fatalf("after extend = %+v", v)
	}
	j, _ = e.svc.jobs(ten).Get(t.Context(), jobID)
	if j.Status != "SUCCESS" || j.EndTime == "" || j.Entities.Size != 30 {
		t.Fatalf("finished job = %+v", j)
	}

	// In-use system disk on ACTIVE server (up to 1024).
	code, out = e.postResize(t, rootID, `{"os-extend": {"new_size": 1024}}`)
	if code != http.StatusAccepted {
		t.Fatalf("resize in-use active = %d %v", code, out)
	}
	e.settle(t)
	v, _ = e.svc.volumes(ten).Get(t.Context(), rootID)
	if v.Status != statusInUse || v.SizeGB != 1024 {
		t.Fatalf("in-use active after = %+v", v)
	}

	// In-use data disk on SHUTOFF server.
	code, out = e.postResize(t, otherID, `{"os-extend": {"new_size": 100}}`)
	if code != http.StatusAccepted {
		t.Fatalf("resize in-use shutoff = %d %v", code, out)
	}
	e.settle(t)
	v, _ = e.svc.volumes(ten).Get(t.Context(), otherID)
	if v.Status != statusInUse || v.SizeGB != 100 {
		t.Fatalf("in-use shutoff after = %+v", v)
	}
}

func TestResizeVolumeErrors(t *testing.T) {
	t.Parallel()
	vols := []volume{
		{ID: dataID, Name: "avail", Status: statusAvailable, SizeGB: 20},
		{ID: rootID, Name: "sys", Status: statusAvailable, SizeGB: 40, Bootable: true},
		{
			ID: otherID, Name: "multi-inuse", Status: statusInUse, SizeGB: 20, Multiattach: true,
			Attachments: []attachment{{ID: otherID, ServerID: "srv-active", Device: "/dev/vdb", BootIndex: -1}},
		},
		{
			ID: "44444444-4444-4444-8444-444444444444", Name: "bad-srv", Status: statusInUse, SizeGB: 20,
			Attachments: []attachment{{ID: "444", ServerID: "srv-build", Device: "/dev/vdb", BootIndex: -1}},
		},
		{ID: "55555555-5555-4555-8555-555555555555", Name: "err-vol", Status: statusError, SizeGB: 20},
		{ID: "66666666-6666-4666-8666-666666666666", Name: "multi-avail", Status: statusAvailable, SizeGB: 20, Multiattach: true},
	}
	e := newResizeEnv(t, vols, nil)
	e.servers.servers["srv-active"] = ServerInfo{Status: "ACTIVE"}
	e.servers.servers["srv-build"] = ServerInfo{Status: "BUILD"}

	cases := []struct {
		name     string
		volID    string
		body     string
		wantHTTP int
		wantCode string
	}{
		{"missing volume", "99999999-9999-4999-8999-999999999999", `{"os-extend":{"new_size":30}}`, 404, "EVS.5404"},
		{"missing os-extend", dataID, `{}`, 400, "EVS.1011"},
		{"bad json", dataID, `{`, 400, "EVS.1011"},
		{"not greater (equal)", dataID, `{"os-extend":{"new_size":20}}`, 400, "EVS.1015"},
		{"not greater (smaller)", dataID, `{"os-extend":{"new_size":10}}`, 400, "EVS.1015"},
		{"data disk over 32768", dataID, `{"os-extend":{"new_size":32769}}`, 400, "EVS.1010"},
		{"system disk over 1024", rootID, `{"os-extend":{"new_size":1025}}`, 400, "EVS.1010"},
		{"in-use multiattach", otherID, `{"os-extend":{"new_size":30}}`, 400, "EVS.1065"},
		{"in-use server BUILD", "44444444-4444-4444-8444-444444444444", `{"os-extend":{"new_size":30}}`, 400, "EVS.1066"},
		{"status error", "55555555-5555-4555-8555-555555555555", `{"os-extend":{"new_size":30}}`, 400, "EVS.1064"},
	}
	for _, tc := range cases {
		code, out := e.postResize(t, tc.volID, tc.body)
		errObj, _ := out["error"].(map[string]any)
		if code != tc.wantHTTP || errObj["code"] != tc.wantCode {
			t.Errorf("%s: got %d %v, want %d %s", tc.name, code, out, tc.wantHTTP, tc.wantCode)
		}
	}

	// Available multiattach can be resized.
	code, _ := e.postResize(t, "66666666-6666-4666-8666-666666666666", `{"os-extend":{"new_size":30}}`)
	if code != http.StatusAccepted {
		t.Fatalf("available multiattach resize = %d, want 202", code)
	}
}

func TestResizeVolumeFault(t *testing.T) {
	t.Parallel()
	ten := Tenant{Region: region, ProjectID: project}
	vols := []volume{{ID: dataID, Name: "avail", Status: statusAvailable, SizeGB: 20}}
	e := newResizeEnv(t, vols, &faultOnce{kind: taskVolumeExtend, err: errors.New("backend extend failure")})

	code, out := e.postResize(t, dataID, `{"os-extend": {"new_size": 50}}`)
	if code != http.StatusAccepted {
		t.Fatalf("resize = %d %v", code, out)
	}
	jobID := out["job_id"].(string)

	e.settle(t)
	v, _ := e.svc.volumes(ten).Get(t.Context(), dataID)
	if v.Status != statusErrorExtending || v.SizeGB != 20 || v.Pending != nil {
		t.Fatalf("faulted volume = %+v", v)
	}
	j, _ := e.svc.jobs(ten).Get(t.Context(), jobID)
	if j.Status != "FAIL" || j.ErrorCode != "EVS.2026" || j.FailReason == "" {
		t.Fatalf("faulted job = %+v", j)
	}
}
