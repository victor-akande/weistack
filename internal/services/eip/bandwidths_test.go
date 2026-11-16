package eip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	bwTestProject = "0123456789abcdef0123456789abcdef"
	bwTestRegion  = "ap-southeast-1"
	bwTestHost    = "vpc." + bwTestRegion + ".myhuaweicloud.com"
	bwTestDelay   = 2 * time.Second
)

var (
	bwTestTenant = Tenant{Region: bwTestRegion, ProjectID: bwTestProject}
	bwTestEpoch  = time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
)

type bwEnv struct {
	svc     *Service
	store   store.Store
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	handler http.Handler
}

func newBWEnv(t *testing.T) *bwEnv {
	t.Helper()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(bwTestEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: bwTestDelay, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(7)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatalf("vpc.New: %v", err)
	}
	eipSvc, err := New(Deps{
		Store:  st,
		Engine: engine,
		IDs:    gen,
		Logger: log,
		Ports:  vpcSvc,
		Now:    clock.Now,
	})
	if err != nil {
		t.Fatalf("eip.New: %v", err)
	}
	vpcSvc.Extend(eipSvc)

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: bwTestProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{vpcSvc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &bwEnv{svc: eipSvc, store: st, engine: engine, clock: clock, handler: srv.Handler()}
}

func (e *bwEnv) callV1(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	return e.send(t, method, "/v1/"+bwTestProject+path, rd)
}

func (e *bwEnv) callV20(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	return e.send(t, method, "/v2.0/"+bwTestProject+path, rd)
}

func (e *bwEnv) expectV1(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.callV1(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "bandwidths", goldenName+".json"), status, out)
	return out
}

func (e *bwEnv) expectV20(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.callV20(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "bandwidths", goldenName+".json"), status, out)
	return out
}

func (e *bwEnv) send(t *testing.T, method, path string, rd io.Reader) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest(method, path, rd)
	r.Host = bwTestHost
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if res.Header.Get("X-Request-Id") == "" {
		t.Errorf("%s %s: response has no X-Request-Id", method, path)
	}
	return res.StatusCode, out
}

func bwDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func bwPtr[T any](v T) *T { return &v }

func (e *bwEnv) bwSeedPublicIPWithPER(t *testing.T, bwName string, size int, addr string) (publicIP, bandwidth) {
	t.Helper()
	return e.bwSeedPublicIPWithPERInEP(t, bwName, size, addr, defaultEnterpriseProjectID)
}

func (e *bwEnv) bwSeedPublicIPWithPERInEP(t *testing.T, bwName string, size int, addr, ep string) (publicIP, bandwidth) {
	t.Helper()
	ctx := context.Background()
	pipID := e.svc.ids.UUID()
	bwID := e.svc.ids.UUID()
	now := e.svc.nowUTC()

	bw := bandwidth{
		ID:                  bwID,
		Name:                bwName,
		Size:                size,
		ShareType:           ShareTypePer,
		ChargeMode:          ChargeModeBandwidth,
		EnterpriseProjectID: ep,
		PublicIPIDs:         []string{pipID},
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := e.svc.bandwidths(bwTestTenant).Create(ctx, bw.ID, bw); err != nil {
		t.Fatalf("seeding bandwidth: %v", err)
	}

	pip := publicIP{
		ID:                  pipID,
		Type:                "5_bgp",
		Address:             addr,
		Status:              StatusDown,
		BandwidthID:         bw.ID,
		EnterpriseProjectID: ep,
		Tags:                []tag{},
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := e.svc.publicips(bwTestTenant).Create(ctx, pip.ID, pip); err != nil {
		t.Fatalf("seeding publicIP: %v", err)
	}
	return pip, bw
}

func bwWantErrCode(t *testing.T, err error, wantStatus int, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got nil error, want %d %s", wantStatus, wantCode)
	}
	var apiErr *apierr.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %v (%T) is not *apierr.Error", err, err)
	}
	if apiErr.Status != wantStatus || apiErr.Code != wantCode {
		t.Fatalf("got %d %s (%s), want %d %s", apiErr.Status, apiErr.Code, apiErr.Message, wantStatus, wantCode)
	}
}

func TestSharedBandwidthCRUDAndQuota(t *testing.T) {
	t.Parallel()
	e := newBWEnv(t)
	ctx := context.Background()

	// Create 5 shared bandwidths (the project quota).
	var created []bandwidth
	for i := 1; i <= maxSharedBandwidths; i++ {
		bw, err := e.svc.CreateSharedBandwidth(ctx, bwTestTenant, createSharedBandwidthOption{
			Name: fmt.Sprintf("shared-%d", i),
			Size: 5 * i,
		})
		if err != nil {
			t.Fatalf("CreateSharedBandwidth #%d: %v", i, err)
		}
		if bw.ShareType != ShareTypeWhole || bw.ChargeMode != ChargeModeBandwidth || bw.EnterpriseProjectID != "0" {
			t.Fatalf("unexpected defaults on #%d: %+v", i, bw)
		}
		created = append(created, bw)
	}

	// 6th shared bandwidth exceeds quota -> VPC.0310.
	_, err := e.svc.CreateSharedBandwidth(ctx, bwTestTenant, createSharedBandwidthOption{
		Name: "shared-6",
		Size: 10,
	})
	bwWantErrCode(t, err, http.StatusBadRequest, "VPC.0310")

	// Show and update one shared bandwidth.
	got, err := e.svc.GetBandwidth(ctx, bwTestTenant, created[0].ID)
	if err != nil || got.Name != "shared-1" {
		t.Fatalf("GetBandwidth: %+v, %v", got, err)
	}

	e.clock.Advance(30 * time.Second)
	updated, err := e.svc.UpdateBandwidth(ctx, bwTestTenant, created[0].ID, updateBandwidthOption{
		Name:       bwPtr("shared-1-renamed"),
		Size:       bwPtr(500),
		ChargeMode: bwPtr(ChargeModeTraffic),
	})
	if err != nil {
		t.Fatalf("UpdateBandwidth: %v", err)
	}
	if updated.Name != "shared-1-renamed" || updated.Size != 500 || updated.ChargeMode != ChargeModeTraffic || !updated.UpdatedAt.After(updated.CreatedAt) {
		t.Fatalf("updated = %+v", updated)
	}

	// Delete one shared bandwidth, freeing a quota slot.
	if err := e.svc.DeleteSharedBandwidth(ctx, bwTestTenant, created[0].ID); err != nil {
		t.Fatalf("DeleteSharedBandwidth: %v", err)
	}
	_, err = e.svc.GetBandwidth(ctx, bwTestTenant, created[0].ID)
	bwWantErrCode(t, err, http.StatusNotFound, "VPC.0306")

	// Creating another shared bandwidth succeeds now that only 4 exist.
	if _, err := e.svc.CreateSharedBandwidth(ctx, bwTestTenant, createSharedBandwidthOption{
		Name: "shared-after-delete",
		Size: 10,
	}); err != nil {
		t.Fatalf("CreateSharedBandwidth after delete: %v", err)
	}
}

func TestBandwidthValidationTable(t *testing.T) {
	t.Parallel()
	e := newBWEnv(t)
	ctx := context.Background()

	_, perBW := e.bwSeedPublicIPWithPER(t, "per-bw", 10, "192.0.2.1")
	wholeBW, err := e.svc.CreateSharedBandwidth(ctx, bwTestTenant, createSharedBandwidthOption{
		Name: "whole-bw",
		Size: 10,
	})
	if err != nil {
		t.Fatalf("CreateSharedBandwidth: %v", err)
	}

	createCases := []struct {
		name string
		opt  createSharedBandwidthOption
		code string
	}{
		{"empty name", createSharedBandwidthOption{Name: "", Size: 10}, "VPC.0301"},
		{"invalid name chars", createSharedBandwidthOption{Name: "bad name!", Size: 10}, "VPC.0301"},
		{"name too long", createSharedBandwidthOption{Name: strings.Repeat("a", 65), Size: 10}, "VPC.0301"},
		{"size below 5", createSharedBandwidthOption{Name: "bw", Size: 4}, "VPC.0301"},
		{"size above 2000", createSharedBandwidthOption{Name: "bw", Size: 2001}, "VPC.0301"},
		{"bad charge_mode", createSharedBandwidthOption{Name: "bw", Size: 10, ChargeMode: bwPtr("95peak_plus")}, "VPC.0301"},
		{"bad enterprise_project_id", createSharedBandwidthOption{Name: "bw", Size: 10, EnterpriseProjectID: bwPtr("not-uuid")}, "VPC.0301"},
		{"bad public_border_group", createSharedBandwidthOption{Name: "bw", Size: 10, PublicBorderGroup: bwPtr("edge")}, "VPC.0301"},
		{"bad bandwidth_type", createSharedBandwidthOption{Name: "bw", Size: 10, BandwidthType: bwPtr("bgp")}, "VPC.0301"},
	}
	for _, tc := range createCases {
		t.Run("create/"+tc.name, func(t *testing.T) {
			_, err := e.svc.CreateSharedBandwidth(ctx, bwTestTenant, tc.opt)
			bwWantErrCode(t, err, http.StatusBadRequest, tc.code)
		})
	}

	updateCases := []struct {
		name   string
		bwID   string
		opt    updateBandwidthOption
		status int
		code   string
	}{
		{"unknown id", "00000000-0000-4000-8000-000000000000", updateBandwidthOption{Name: bwPtr("ok")}, http.StatusNotFound, "VPC.0306"},
		{"empty name", perBW.ID, updateBandwidthOption{Name: bwPtr("")}, http.StatusBadRequest, "VPC.0301"},
		{"bad name chars", perBW.ID, updateBandwidthOption{Name: bwPtr("a b")}, http.StatusBadRequest, "VPC.0301"},
		{"per size 0", perBW.ID, updateBandwidthOption{Size: bwPtr(0)}, http.StatusBadRequest, "VPC.0301"},
		{"per size 301", perBW.ID, updateBandwidthOption{Size: bwPtr(301)}, http.StatusBadRequest, "VPC.0301"},
		{"whole size 4", wholeBW.ID, updateBandwidthOption{Size: bwPtr(4)}, http.StatusBadRequest, "VPC.0301"},
		{"whole size 2001", wholeBW.ID, updateBandwidthOption{Size: bwPtr(2001)}, http.StatusBadRequest, "VPC.0301"},
		{"bad charge_mode", wholeBW.ID, updateBandwidthOption{ChargeMode: bwPtr("hourly")}, http.StatusBadRequest, "VPC.0301"},
	}
	for _, tc := range updateCases {
		t.Run("update/"+tc.name, func(t *testing.T) {
			_, err := e.svc.UpdateBandwidth(ctx, bwTestTenant, tc.bwID, tc.opt)
			bwWantErrCode(t, err, tc.status, tc.code)
		})
	}
}

func TestInsertAndRemovePublicIPsAllOrNothingAndLimits(t *testing.T) {
	t.Parallel()
	e := newBWEnv(t)
	ctx := context.Background()

	shared1, err := e.svc.CreateSharedBandwidth(ctx, bwTestTenant, createSharedBandwidthOption{
		Name: "shared-1",
		Size: 20,
	})
	if err != nil {
		t.Fatalf("CreateSharedBandwidth: %v", err)
	}
	shared2, err := e.svc.CreateSharedBandwidth(ctx, bwTestTenant, createSharedBandwidthOption{
		Name: "shared-2",
		Size: 20,
	})
	if err != nil {
		t.Fatalf("CreateSharedBandwidth: %v", err)
	}

	pip1, perBW1 := e.bwSeedPublicIPWithPER(t, "per-1", 5, "192.0.2.1")
	pip2, perBW2 := e.bwSeedPublicIPWithPER(t, "per-2", 5, "192.0.2.2")

	// All-or-nothing insert: pip1 is valid, second ID does not exist -> VPC.0301,
	// and pip1's old PER bandwidth must still exist untouched.
	_, err = e.svc.AddPublicIPsIntoSharedBandwidth(ctx, bwTestTenant, shared1.ID, addPublicIPsIntoSharedBandwidthOption{
		PublicIPInfo: []insertPublicIPInfo{
			{PublicIPID: pip1.ID},
			{PublicIPID: "00000000-0000-4000-8000-000000000000"},
		},
	})
	bwWantErrCode(t, err, http.StatusBadRequest, "VPC.0301")

	if _, err := e.svc.GetBandwidth(ctx, bwTestTenant, perBW1.ID); err != nil {
		t.Fatalf("perBW1 should still exist after failed batch insert: %v", err)
	}
	gotPip1, _ := e.svc.publicips(bwTestTenant).Get(ctx, pip1.ID)
	if gotPip1.BandwidthID != perBW1.ID {
		t.Fatalf("pip1.BandwidthID changed on failed insert: %s", gotPip1.BandwidthID)
	}

	// Insert pip1 and pip2 into shared1: succeeds, deletes perBW1 and perBW2.
	updatedShared, err := e.svc.AddPublicIPsIntoSharedBandwidth(ctx, bwTestTenant, shared1.ID, addPublicIPsIntoSharedBandwidthOption{
		PublicIPInfo: []insertPublicIPInfo{
			{PublicIPID: pip1.ID},
			{PublicIPID: pip2.ID},
		},
	})
	if err != nil {
		t.Fatalf("AddPublicIPsIntoSharedBandwidth: %v", err)
	}
	if len(updatedShared.PublicIPIDs) != 2 {
		t.Fatalf("PublicIPIDs = %v, want 2 EIPs", updatedShared.PublicIPIDs)
	}
	_, err = e.svc.GetBandwidth(ctx, bwTestTenant, perBW1.ID)
	bwWantErrCode(t, err, http.StatusNotFound, "VPC.0306")
	_, err = e.svc.GetBandwidth(ctx, bwTestTenant, perBW2.ID)
	bwWantErrCode(t, err, http.StatusNotFound, "VPC.0306")

	// Inserting an EIP that is already on a WHOLE bandwidth into shared2 -> VPC.0323.
	pip3, perBW3 := e.bwSeedPublicIPWithPER(t, "per-3", 5, "192.0.2.3")
	_, err = e.svc.AddPublicIPsIntoSharedBandwidth(ctx, bwTestTenant, shared2.ID, addPublicIPsIntoSharedBandwidthOption{
		PublicIPInfo: []insertPublicIPInfo{
			{PublicIPID: pip3.ID},
			{PublicIPID: pip1.ID}, // already on shared1
		},
	})
	bwWantErrCode(t, err, http.StatusBadRequest, "VPC.0323")
	// All-or-nothing: pip3 must still be on perBW3.
	if _, err := e.svc.GetBandwidth(ctx, bwTestTenant, perBW3.ID); err != nil {
		t.Fatalf("perBW3 should still exist after failed insert: %v", err)
	}

	// Deleting shared1 while it still has EIPs -> VPC.0304.
	err = e.svc.DeleteSharedBandwidth(ctx, bwTestTenant, shared1.ID)
	bwWantErrCode(t, err, http.StatusConflict, "VPC.0304")

	// Deleting a PER bandwidth via DeleteSharedBandwidth -> VPC.0323.
	err = e.svc.DeleteSharedBandwidth(ctx, bwTestTenant, perBW3.ID)
	bwWantErrCode(t, err, http.StatusBadRequest, "VPC.0323")

	// All-or-nothing remove: pip1 is in shared1, pip3 is not -> VPC.0323, pip1 stays in shared1.
	err = e.svc.RemovePublicIPsFromSharedBandwidth(ctx, bwTestTenant, shared1.ID, removeFromSharedBandwidthOption{
		ChargeMode: ChargeModeTraffic,
		Size:       15,
		PublicIPInfo: []removePublicIPInfo{
			{PublicIPID: pip1.ID},
			{PublicIPID: pip3.ID},
		},
	})
	bwWantErrCode(t, err, http.StatusBadRequest, "VPC.0323")
	gotShared1, _ := e.svc.GetBandwidth(ctx, bwTestTenant, shared1.ID)
	if len(gotShared1.PublicIPIDs) != 2 {
		t.Fatalf("shared1 should still have 2 EIPs after failed remove, got %v", gotShared1.PublicIPIDs)
	}

	// Remove pip1 and pip2 from shared1: each gets a new PER bandwidth named bandwidth-<first 8 chars of EIP ID>.
	err = e.svc.RemovePublicIPsFromSharedBandwidth(ctx, bwTestTenant, shared1.ID, removeFromSharedBandwidthOption{
		ChargeMode: ChargeModeTraffic,
		Size:       25,
		PublicIPInfo: []removePublicIPInfo{
			{PublicIPID: pip1.ID},
			{PublicIPID: pip2.ID},
		},
	})
	if err != nil {
		t.Fatalf("RemovePublicIPsFromSharedBandwidth: %v", err)
	}
	gotShared1, _ = e.svc.GetBandwidth(ctx, bwTestTenant, shared1.ID)
	if len(gotShared1.PublicIPIDs) != 0 {
		t.Fatalf("shared1 PublicIPIDs = %v, want empty", gotShared1.PublicIPIDs)
	}
	for _, id := range []string{pip1.ID, pip2.ID} {
		p, err := e.svc.publicips(bwTestTenant).Get(ctx, id)
		if err != nil {
			t.Fatalf("get pip %s: %v", id, err)
		}
		newBW, err := e.svc.GetBandwidth(ctx, bwTestTenant, p.BandwidthID)
		if err != nil {
			t.Fatalf("get new PER bandwidth for %s: %v", id, err)
		}
		wantName := "bandwidth-" + id[:8]
		if newBW.ShareType != ShareTypePer || newBW.Name != wantName || newBW.Size != 25 || newBW.ChargeMode != ChargeModeTraffic || len(newBW.PublicIPIDs) != 1 || newBW.PublicIPIDs[0] != id {
			t.Fatalf("new PER bandwidth = %+v, want name %q size 25 traffic", newBW, wantName)
		}
	}
}

func TestSharedBandwidthMax20EIPsLimit(t *testing.T) {
	t.Parallel()
	e := newBWEnv(t)
	ctx := context.Background()

	shared, err := e.svc.CreateSharedBandwidth(ctx, bwTestTenant, createSharedBandwidthOption{
		Name: "shared-max",
		Size: 100,
	})
	if err != nil {
		t.Fatalf("CreateSharedBandwidth: %v", err)
	}

	var infos []insertPublicIPInfo
	for i := 1; i <= maxEIPsPerSharedBandwidth; i++ {
		pip, _ := e.bwSeedPublicIPWithPER(t, fmt.Sprintf("per-%d", i), 5, fmt.Sprintf("192.0.2.%d", i))
		infos = append(infos, insertPublicIPInfo{PublicIPID: pip.ID})
	}
	if _, err := e.svc.AddPublicIPsIntoSharedBandwidth(ctx, bwTestTenant, shared.ID, addPublicIPsIntoSharedBandwidthOption{
		PublicIPInfo: infos,
	}); err != nil {
		t.Fatalf("inserting 20 EIPs: %v", err)
	}

	// 21st EIP exceeds maxEIPsPerSharedBandwidth (20) -> VPC.0323.
	pip21, perBW21 := e.bwSeedPublicIPWithPER(t, "per-21", 5, "192.0.2.21")
	_, err = e.svc.AddPublicIPsIntoSharedBandwidth(ctx, bwTestTenant, shared.ID, addPublicIPsIntoSharedBandwidthOption{
		PublicIPInfo: []insertPublicIPInfo{{PublicIPID: pip21.ID}},
	})
	bwWantErrCode(t, err, http.StatusBadRequest, "VPC.0323")

	// perBW21 must still exist.
	if _, err := e.svc.GetBandwidth(ctx, bwTestTenant, perBW21.ID); err != nil {
		t.Fatalf("perBW21 should remain intact: %v", err)
	}
}
