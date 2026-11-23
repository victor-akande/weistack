package obs

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

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
	e := &env{store: st, dir: t.TempDir(), now: testEpoch}
	t.Cleanup(func() { _ = st.Close() })

	gen := ids.NewSeeded(17)
	svc, err := New(Deps{
		Quotas:  limits,
		Store:   st,
		IDs:     gen,
		Logger:  log,
		DataDir: e.dir,
		Now:     func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: st,
		Engine: lifecycle.New(lifecycle.Options{Logger: log}), IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	e.svc, e.handler = svc, srv.Handler()
	return e
}

func wantTooManyBuckets(t *testing.T, got resp) {
	t.Helper()
	wantError(t, got, http.StatusBadRequest, "TooManyBuckets")
	wantMsg := "<Message>You have attempted to create more buckets than allowed.</Message>"
	if !strings.Contains(got.Body, wantMsg) {
		t.Errorf("body missing %s: %s", wantMsg, got.Body)
	}
}

func TestBucketQuotaEnforced(t *testing.T) {
	t.Parallel()
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.OBSBuckets: 2}))

	mustStatus(t, e.as(t, alice, http.MethodPut, "/bucket-1"), http.StatusOK)
	mustStatus(t, e.as(t, alice, http.MethodPut, "/bucket-2"), http.StatusOK)

	// 3rd bucket for alice is refused with 400 TooManyBuckets.
	wantTooManyBuckets(t, e.as(t, alice, http.MethodPut, "/bucket-3"))

	// Re-creating a bucket alice already owns keeps its 409 BucketAlreadyOwnedByYou.
	wantError(t, e.as(t, alice, http.MethodPut, "/bucket-1"), http.StatusConflict, "BucketAlreadyOwnedByYou")

	// Another account (bob) has its own bucket quota.
	mustStatus(t, e.as(t, bob, http.MethodPut, "/bob-1"), http.StatusOK)
	// Trying to create bob's bucket as alice keeps 409 BucketAlreadyExists.
	wantError(t, e.as(t, alice, http.MethodPut, "/bob-1"), http.StatusConflict, "BucketAlreadyExists")

	// Deleting one of alice's buckets frees a slot.
	mustStatus(t, e.as(t, alice, http.MethodDelete, "/bucket-1"), http.StatusNoContent)
	mustStatus(t, e.as(t, alice, http.MethodPut, "/bucket-3"), http.StatusOK)
}

func TestBucketQuotaCountsAllRegions(t *testing.T) {
	t.Parallel()
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.OBSBuckets: 2}))

	if _, err := e.svc.CreateBucket(t.Context(), "AKALICE", "cn-north-4", "north-1"); err != nil {
		t.Fatalf("CreateBucket cn-north-4: %v", err)
	}
	mustStatus(t, e.as(t, alice, http.MethodPut, "/south-1"), http.StatusOK)
	wantTooManyBuckets(t, e.as(t, alice, http.MethodPut, "/south-2"))
}

func TestBucketQuotaUnlimited(t *testing.T) {
	t.Parallel()
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.OBSBuckets: quota.Unlimited}))

	for _, path := range []string{"/unlim-1", "/unlim-2", "/unlim-3"} {
		mustStatus(t, e.as(t, alice, http.MethodPut, path), http.StatusOK)
	}
}

func TestBucketQuotaExistingOverLimit(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	coll := store.Of[Bucket](st, store.Scope{Region: globalRegion, ProjectID: store.Global, Kind: kindBucket})
	for _, name := range []string{"pre-1", "pre-2", "pre-3"} {
		if err := coll.Create(t.Context(), name, Bucket{
			Name:    name,
			Owner:   "AKALICE",
			Region:  testRegion,
			Created: testEpoch,
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	e := newQuotaEnv(t, st, quota.For(map[quota.Key]int{quota.OBSBuckets: 2}))

	// Existing 3 buckets over the limit of 2 are all kept.
	buckets, err := e.svc.ListBuckets(t.Context(), "AKALICE")
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != 3 {
		t.Fatalf("len(buckets) = %d, want 3", len(buckets))
	}

	// New create is refused.
	wantTooManyBuckets(t, e.as(t, alice, http.MethodPut, "/new-bucket"))

	// Deleting 2 buckets brings usage to 1 (< 2), allowing a new create.
	mustStatus(t, e.as(t, alice, http.MethodDelete, "/pre-1"), http.StatusNoContent)
	mustStatus(t, e.as(t, alice, http.MethodDelete, "/pre-2"), http.StatusNoContent)
	mustStatus(t, e.as(t, alice, http.MethodPut, "/new-bucket"), http.StatusOK)
}
