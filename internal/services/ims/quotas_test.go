package ims

import (
	"context"
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
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.IMSImage: 2}))

	img1 := e.mustCreateImage(t, "img-1")
	_ = e.mustCreateImage(t, "img-2")

	// Creating a 3rd private image from a server is refused with IMG.0015.
	status, out := e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", createBody("img-3"))
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
	status, out = e.call(t, testProject, http.MethodDelete, "/v2/images/"+img1.ID, "")
	if status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, out)
	}
	_ = e.mustCreateImage(t, "img-3")
}

func TestImageQuotaUnlimited(t *testing.T) {
	t.Parallel()
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.IMSImage: quota.Unlimited}))

	for _, name := range []string{"img-1", "img-2", "img-3"} {
		_ = e.mustCreateImage(t, name)
	}
}

func TestImageQuotaExistingOverLimit(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	coll := store.Of[Image](st, store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindImage})
	now := Time(testEpoch)
	var ids []string
	for _, name := range []string{"pre-1", "pre-2", "pre-3"} {
		id := "00000000-0000-4000-8000-00000000000" + name[len(name)-1:]
		ids = append(ids, id)
		img := Image{
			ID:         id,
			Name:       name,
			Status:     StatusActive,
			ImageType:  TypePrivate,
			Visibility: VisibilityPrivate,
			Owner:      testProject,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := coll.Create(t.Context(), id, img); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	e := newQuotaEnv(t, st, quota.For(map[quota.Key]int{quota.IMSImage: 2}))

	// Existing 3 images over the limit of 2 are all kept.
	imgs, err := e.svc.ListImages(t.Context(), testTenant, ListImagesFilter{ImageType: TypePrivate})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(imgs) != 3 {
		t.Fatalf("len(imgs) = %d, want 3", len(imgs))
	}

	// New create is refused.
	status, out := e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", createBody("new-img"))
	wantIMSQuotaError(t, status, out)

	// Deleting 2 images brings usage to 1 (< 2), allowing a new create.
	for _, id := range ids[:2] {
		stCode, body := e.call(t, testProject, http.MethodDelete, "/v2/images/"+id, "")
		if stCode != http.StatusNoContent {
			t.Fatalf("delete %s: %d %s", id, stCode, body)
		}
	}
	_ = e.mustCreateImage(t, "new-img")
}
