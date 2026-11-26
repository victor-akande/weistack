package obs

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
)

func newInventoryEnv(t *testing.T, keys *identity.Directory, accountOf func(string) (string, bool)) *env {
	t.Helper()
	st := store.NewMemory()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := &env{store: st, dir: dir, now: testEpoch}
	t.Cleanup(func() { _ = st.Close() })

	gen := ids.NewSeeded(17)
	svc, err := New(Deps{
		Store:     st,
		IDs:       gen,
		Logger:    log,
		DataDir:   dir,
		AccountOf: accountOf,
		Now:       func() time.Time { return e.now },
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
		Services: []server.Service{svc}, Directory: keys,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	e.svc, e.handler = svc, srv.Handler()
	return e
}

func TestReportResources(t *testing.T) {
	t.Parallel()

	acct := identity.Account{ID: "0123456789abcdef0123456789abcdef", Name: identity.AccountName}
	const (
		knownAK     = "ADMINKEY000000000000"
		unknownAK   = "AKUNKNOWN00000000000"
		otherRegion = "cn-north-4"
	)
	keys := identity.NewDirectory(acct, identity.Credentials{AccessKey: knownAK, SecretKey: "s"})
	accountOf := func(ak string) (string, bool) {
		p, ok := keys.Lookup(ak)
		return p.AccountID, ok
	}
	e := newInventoryEnv(t, keys, accountOf)

	const (
		knownAuth   = "OBS " + knownAK + ":c2ln"
		unknownAuth = "AWS " + unknownAK + ":c2ln"
	)

	// Known-key bucket in the default region, with default encryption, an
	// uploaded object and an in-progress multipart upload (with a part).
	mustStatus(t, e.do(t, req{
		Method:  http.MethodPut,
		Path:    "/photos",
		Auth:    knownAuth,
		Headers: map[string]string{"x-obs-server-side-encryption": "obs"},
	}), http.StatusOK)
	mustStatus(t, e.do(t, req{
		Method:  http.MethodPut,
		Path:    "/photos/2026/cat.png",
		Auth:    knownAuth,
		Body:    "object-payload-bytes",
		Headers: map[string]string{"x-obs-meta-note": "object-meta-value"},
	}), http.StatusOK)

	initResp := mustStatus(t, e.do(t, req{
		Method: http.MethodPost,
		Path:   "/photos/2026/video.mp4?uploads",
		Auth:   knownAuth,
	}), http.StatusOK)
	var initOut struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal([]byte(initResp.Body), &initOut); err != nil || initOut.UploadID == "" {
		t.Fatalf("initiate upload: %v %s", err, initResp.Body)
	}
	mustStatus(t, e.do(t, req{
		Method: http.MethodPut,
		Path:   fmt.Sprintf("/photos/2026/video.mp4?partNumber=%d&uploadId=%s", minPartNumber, initOut.UploadID),
		Auth:   knownAuth,
		Body:   "multipart-part-bytes",
	}), http.StatusOK)

	// Unknown-key bucket in a second region.
	mustStatus(t, e.do(t, req{
		Method: http.MethodPut,
		Host:   "obs." + otherRegion + ".myhuaweicloud.com",
		Path:   "/archive",
		Auth:   unknownAuth,
	}), http.StatusOK)

	snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := make(map[string]inventory.Resource, len(snap.Resources))
	for _, r := range snap.Resources {
		got[r.Type.String()+"/"+r.RegionID+"/"+r.ID] = r
	}
	at := func(region, id string) inventory.Resource {
		t.Helper()
		r, ok := got[inventory.OBSBuckets.String()+"/"+region+"/"+id]
		if !ok {
			t.Fatalf("%s %s in %s is not reported; got %+v", inventory.OBSBuckets, id, region, snap.Resources)
		}
		return r
	}

	if b := at(testRegion, "photos"); b.ID != "photos" || b.Name != "photos" ||
		b.AccountID != acct.ID || b.RegionID != testRegion || b.ProjectID != "" ||
		b.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!b.Created.Equal(testEpoch) || !b.Updated.Equal(testEpoch) ||
		len(b.Tags) != 0 || b.State != inventory.Succeeded || len(b.Relations) != 0 {
		t.Errorf("photos bucket = %+v", b)
	}
	if b := at(otherRegion, "archive"); b.ID != "archive" || b.Name != "archive" ||
		b.AccountID != "" || b.RegionID != otherRegion || b.ProjectID != "" ||
		b.EnterpriseProjectID != inventory.DefaultEnterpriseProject ||
		!b.Created.Equal(testEpoch) || !b.Updated.Equal(testEpoch) ||
		len(b.Tags) != 0 || b.State != inventory.Succeeded || len(b.Relations) != 0 {
		t.Errorf("archive bucket = %+v", b)
	}

	wantBuckets := []string{"photos", "archive"}
	count := make(map[inventory.Type]int)
	for _, r := range snap.Resources {
		count[r.Type]++
	}
	want := map[inventory.Type]int{
		inventory.OBSBuckets: len(wantBuckets),
	}
	if !reflect.DeepEqual(count, want) {
		t.Errorf("reported %v, want %v", count, want)
	}

	// Objects, multipart uploads, and access keys never appear in the snapshot.
	dump := fmt.Sprintf("%+v", snap)
	for label, text := range map[string]string{
		"object key":       "cat.png",
		"object body":      "object-payload-bytes",
		"object metadata":  "object-meta-value",
		"multipart key":    "video.mp4",
		"multipart upload": initOut.UploadID,
		"multipart body":   "multipart-part-bytes",
		"known access key": knownAK,
		"unknown key":      unknownAK,
	} {
		if strings.Contains(dump, text) {
			t.Errorf("inventory snapshot leaked %s (%q)", label, text)
		}
	}
}

func TestReportResourcesAccountResolution(t *testing.T) {
	t.Parallel()

	const (
		wantAccountID = "fedcba9876543210fedcba9876543210"
		rawKnownAK    = "RAWKNOWNKEY000000000"
	)

	// Without a server Directory, buckets store the raw access key as Owner,
	// and AccountOf resolves known keys while leaving unknown ones empty.
	t.Run("raw key via AccountOf", func(t *testing.T) {
		t.Parallel()
		e := newInventoryEnv(t, nil, func(ak string) (string, bool) {
			if ak == rawKnownAK {
				return wantAccountID, true
			}
			return "", false
		})
		mustStatus(t, e.as(t, "OBS "+rawKnownAK+":c2ln", http.MethodPut, "/raw-known"), http.StatusOK)
		mustStatus(t, e.as(t, bob, http.MethodPut, "/raw-unknown"), http.StatusOK)

		snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		byID := make(map[string]inventory.Resource, len(snap.Resources))
		for _, r := range snap.Resources {
			byID[r.ID] = r
		}
		if got := byID["raw-known"].AccountID; got != wantAccountID {
			t.Errorf("raw-known AccountID = %q, want %q", got, wantAccountID)
		}
		if got := byID["raw-unknown"].AccountID; got != "" {
			t.Errorf("raw-unknown AccountID = %q, want empty", got)
		}
	})

	// Nil AccountOf leaves buckets without an account.
	t.Run("nil AccountOf", func(t *testing.T) {
		t.Parallel()
		acct := identity.Account{ID: wantAccountID, Name: identity.AccountName}
		keys := identity.NewDirectory(acct, identity.Credentials{AccessKey: rawKnownAK, SecretKey: "s"})
		e := newInventoryEnv(t, keys, nil)
		mustStatus(t, e.as(t, "OBS "+rawKnownAK+":c2ln", http.MethodPut, "/no-account-of"), http.StatusOK)

		snap, err := inventory.New(inventory.Options{Reporters: []inventory.Reporter{e.svc}}).Collect(t.Context())
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		if len(snap.Resources) != 1 || snap.Resources[0].AccountID != "" {
			t.Errorf("nil AccountOf resources = %+v, want 1 bucket with empty AccountID", snap.Resources)
		}
	})
}

func TestResourceStates(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for name, b := range map[string]Bucket{
		"plain":     {Name: "plain", Region: testRegion, Created: testEpoch},
		"encrypted": {Name: "encrypted", Region: testRegion, Created: testEpoch, Encryption: &bucketSSE{Algorithm: sseOBS}},
	} {
		if got := e.svc.bucketResource(b).State; got != inventory.Succeeded {
			t.Errorf("%s state = %s, want %s", name, got, inventory.Succeeded)
		}
	}
}
