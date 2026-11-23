package ims

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

func newQuotaEnv(t *testing.T, st store.Store, limits quota.Limits) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(testEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock, Logger: log})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = st.Close()
	})

	gen := ids.NewSeeded(11)
	svc, err := New(Deps{
		Quotas:           limits,
		Store:            st,
		Engine:           engine,
		IDs:              gen,
		Logger:           log,
		Now:              clock.Now,
		DefaultProjectID: testProject,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: st, Engine: engine, IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return withServers(&env{svc: svc, store: st, engine: engine, clock: clock, handler: srv.Handler()})
}

type imsErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func wantIMSQuotaError(t *testing.T, status int, out []byte) {
	t.Helper()
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (%s)", status, http.StatusBadRequest, out)
	}
	got := decodeInto[imsErrorResponse](t, out)
	if got.Error.Code != "IMG.0015" {
		t.Errorf("code = %q, want IMG.0015 (%s)", got.Error.Code, out)
	}
	wantMsg := "The number of private images has reached the maximum allowed."
	if got.Error.Message != wantMsg {
		t.Errorf("message = %q, want %q", got.Error.Message, wantMsg)
	}
}

func TestImageQuotaEnforced(t *testing.T) {
	t.Parallel()
	limit := 2
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.IMSImage: limit}))

	var firstID string
	for i := range limit {
		img := e.mustCreateImage(t, fmt.Sprintf("img-%d", i+1))
		if i == 0 {
			firstID = img.ID
		}
	}

	// Creating another private image from a server is refused with IMG.0015.
	status, out := e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", createBody("img-extra"))
	wantIMSQuotaError(t, status, out)

	// Unimplemented create paths (from volume, OBS file) still report 501.
	for _, body := range []string{
		`{"name":"from-vol","volume_id":"` + unknownID + `"}`,
		`{"name":"from-obs","image_url":"bucket:file.zvhd2"}`,
	} {
		st, resp := e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", body)
		if st != http.StatusNotImplemented {
			t.Errorf("body %s: status = %d, want 501 (%s)", body, st, resp)
		}
	}

	// Deleting one image frees a slot.
	status, out = e.call(t, testProject, http.MethodDelete, "/v2/images/"+firstID, "")
	if status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, out)
	}
	_ = e.mustCreateImage(t, "img-extra")
}

func TestImageQuotaUnlimited(t *testing.T) {
	t.Parallel()
	creates := 3
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.IMSImage: quota.Unlimited}))

	for i := range creates {
		_ = e.mustCreateImage(t, fmt.Sprintf("img-%d", i+1))
	}
}

func TestImageQuotaExistingOverLimit(t *testing.T) {
	t.Parallel()
	limit, over := 2, 1
	seeded := limit + over
	st := store.NewMemory()
	coll := store.Of[Image](st, store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindImage})
	now := Time(testEpoch)
	var ids []string
	for i := range seeded {
		id := fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", i+1)
		ids = append(ids, id)
		img := Image{
			ID:         id,
			Name:       fmt.Sprintf("pre-%d", i+1),
			Status:     StatusActive,
			ImageType:  TypePrivate,
			Visibility: VisibilityPrivate,
			Owner:      testProject,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := coll.Create(t.Context(), id, img); err != nil {
			t.Fatalf("seed %s: %v", img.Name, err)
		}
	}

	e := newQuotaEnv(t, st, quota.For(map[quota.Key]int{quota.IMSImage: limit}))

	// Existing images over the limit are all kept.
	imgs, err := e.svc.ListImages(t.Context(), testTenant, ListImagesFilter{ImageType: TypePrivate})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(imgs) != seeded {
		t.Fatalf("len(imgs) = %d, want %d", len(imgs), seeded)
	}

	// New create is refused.
	status, out := e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", createBody("new-img"))
	wantIMSQuotaError(t, status, out)

	// Deleting over+1 images brings usage below limit, allowing a new create.
	for _, id := range ids[:over+1] {
		stCode, body := e.call(t, testProject, http.MethodDelete, "/v2/images/"+id, "")
		if stCode != http.StatusNoContent {
			t.Fatalf("delete %s: %d %s", id, stCode, body)
		}
	}
	_ = e.mustCreateImage(t, "new-img")
}
