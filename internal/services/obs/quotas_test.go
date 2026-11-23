package obs

import (
	"fmt"
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
	limit := 2
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.OBSBuckets: limit}))

	for i := range limit {
		mustStatus(t, e.as(t, alice, http.MethodPut, fmt.Sprintf("/bucket-%d", i+1)), http.StatusOK)
	}

	// Next bucket for alice is refused with 400 TooManyBuckets.
	wantTooManyBuckets(t, e.as(t, alice, http.MethodPut, "/bucket-extra"))

	// Re-creating a bucket alice already owns keeps its 409 BucketAlreadyOwnedByYou.
	wantError(t, e.as(t, alice, http.MethodPut, "/bucket-1"), http.StatusConflict, "BucketAlreadyOwnedByYou")

	// Another account (bob) has its own bucket quota.
	mustStatus(t, e.as(t, bob, http.MethodPut, "/bob-1"), http.StatusOK)
	// Trying to create bob's bucket as alice keeps 409 BucketAlreadyExists.
	wantError(t, e.as(t, alice, http.MethodPut, "/bob-1"), http.StatusConflict, "BucketAlreadyExists")

	// Deleting one of alice's buckets frees a slot.
	mustStatus(t, e.as(t, alice, http.MethodDelete, "/bucket-1"), http.StatusNoContent)
	mustStatus(t, e.as(t, alice, http.MethodPut, "/bucket-extra"), http.StatusOK)
}

func TestBucketQuotaCountsAllRegions(t *testing.T) {
	t.Parallel()
	limit := 2
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.OBSBuckets: limit}))

	if _, err := e.svc.CreateBucket(t.Context(), "AKALICE", "cn-north-4", "north-1"); err != nil {
		t.Fatalf("CreateBucket cn-north-4: %v", err)
	}
	for i := range limit - 1 {
		mustStatus(t, e.as(t, alice, http.MethodPut, fmt.Sprintf("/south-%d", i+1)), http.StatusOK)
	}
	wantTooManyBuckets(t, e.as(t, alice, http.MethodPut, "/south-extra"))
}

func TestBucketQuotaUnlimited(t *testing.T) {
	t.Parallel()
	creates := 3
	e := newQuotaEnv(t, store.NewMemory(), quota.For(map[quota.Key]int{quota.OBSBuckets: quota.Unlimited}))

	for i := range creates {
		mustStatus(t, e.as(t, alice, http.MethodPut, fmt.Sprintf("/unlim-%d", i+1)), http.StatusOK)
	}
}

func TestBucketQuotaExistingOverLimit(t *testing.T) {
	t.Parallel()
	limit, over := 2, 1
	seeded := limit + over
	st := store.NewMemory()
	coll := store.Of[Bucket](st, store.Scope{Region: globalRegion, ProjectID: store.Global, Kind: kindBucket})
	var names []string
	for i := range seeded {
		name := fmt.Sprintf("pre-%d", i+1)
		names = append(names, name)
		if err := coll.Create(t.Context(), name, Bucket{
			Name:    name,
			Owner:   "AKALICE",
			Region:  testRegion,
			Created: testEpoch,
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	e := newQuotaEnv(t, st, quota.For(map[quota.Key]int{quota.OBSBuckets: limit}))

	// Existing buckets over the limit are all kept.
	buckets, err := e.svc.ListBuckets(t.Context(), "AKALICE")
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != seeded {
		t.Fatalf("len(buckets) = %d, want %d", len(buckets), seeded)
	}

	// New create is refused.
	wantTooManyBuckets(t, e.as(t, alice, http.MethodPut, "/new-bucket"))

	// Deleting over+1 buckets brings usage below limit, allowing a new create.
	for _, name := range names[:over+1] {
		mustStatus(t, e.as(t, alice, http.MethodDelete, "/"+name), http.StatusNoContent)
	}
	mustStatus(t, e.as(t, alice, http.MethodPut, "/new-bucket"), http.StatusOK)
}
