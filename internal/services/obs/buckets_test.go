package obs

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func TestResolveAddressing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, host, path string
		want             target
	}{
		{"service, path style", "obs.ap-southeast-1.myhuaweicloud.com", "/", target{}},
		{"bucket, path style", "obs.ap-southeast-1.myhuaweicloud.com", "/photos", target{Bucket: "photos"}},
		{"bucket with trailing slash", "obs.ap-southeast-1.myhuaweicloud.com", "/photos/", target{Bucket: "photos"}},
		{"object, path style", "obs.ap-southeast-1.myhuaweicloud.com", "/photos/2026/cat.png", target{"photos", "2026/cat.png"}},
		{"bucket, virtual-hosted", "photos.obs.ap-southeast-1.myhuaweicloud.com", "/", target{Bucket: "photos"}},
		{"object, virtual-hosted", "photos.obs.ap-southeast-1.myhuaweicloud.com:8780", "/2026/cat.png", target{"photos", "2026/cat.png"}},
		{"bucket name with periods", "my.photos.v2.obs.af-south-1.myhuaweicloud.com", "/a", target{"my.photos.v2", "a"}},
		{"bucket called obs", "obs.obs.ap-southeast-1.myhuaweicloud.com", "/a", target{"obs", "a"}},
		{"host is case-insensitive", "Photos.OBS.AP-Southeast-1.MyHuaweiCloud.com", "/Key", target{"photos", "Key"}},
		{"localhost, path style", "obs.localhost:8780", "/photos/a", target{"photos", "a"}},
		{"localhost, virtual-hosted", "photos.obs.localhost:8780", "/a", target{"photos", "a"}},
		{"path prefix on a bare host", "127.0.0.1:8780", "/photos/a", target{"photos", "a"}},
		{"encoded slash stays in the key", "obs.localhost", "/photos/a%2Fb/c", target{"photos", "a/b/c"}},
		{"encoded characters", "obs.localhost", "/photos/my%20file%2B1.txt", target{"photos", "my file+1.txt"}},
		{"key with trailing slash (a folder)", "photos.obs.localhost", "/dir/", target{"photos", "dir/"}},
		{"key that looks like a subresource", "obs.localhost", "/photos/location", target{"photos", "location"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, tt.path, nil)
			r.Host = tt.host
			got, err := resolve(r)
			if err != nil || got != tt.want {
				t.Fatalf("resolve = %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestValidBucketName(t *testing.T) {
	t.Parallel()

	valid := []string{"abc", "my-bucket", "my.bucket.v2", "123", "a1b", "bucket-" + strings.Repeat("x", 56)}
	for _, name := range valid {
		if !validBucketName(name) {
			t.Errorf("%q should be a valid bucket name", name)
		}
	}
	invalid := []string{
		"", "ab", strings.Repeat("x", 64), "My-Bucket", "my_bucket", "-bucket", "bucket-", ".bucket", "bucket.",
		"my..bucket", "my.-bucket", "my-.bucket", "192.168.1.1", "bucket name", "bücket",
	}
	for _, name := range invalid {
		if validBucketName(name) {
			t.Errorf("%q should not be a valid bucket name", name)
		}
	}
}

func TestBucketLifecycleInTheOBSDialect(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	created := mustStatus(t, e.as(t, alice, http.MethodPut, "/photos"), http.StatusOK)
	if created.Header.Get("Location") != "/photos" || created.Body != "" {
		t.Errorf("create: Location %q body %q", created.Header.Get("Location"), created.Body)
	}
	// Every response identifies itself the OBS way.
	if id := created.Header.Get("x-obs-request-id"); !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) ||
		created.Header.Get("x-obs-id-2") == "" || created.Header.Get("Server") != "OBS" || created.Header.Get("x-amz-request-id") != "" {
		t.Errorf("headers = %v", created.Header)
	}

	head := mustStatus(t, e.as(t, alice, http.MethodHead, "/photos"), http.StatusOK)
	if head.Header.Get("x-obs-bucket-location") != testRegion || head.Body != "" {
		t.Errorf("head: %v", head.Header)
	}

	loc := mustStatus(t, e.as(t, alice, http.MethodGet, "/photos?location"), http.StatusOK)
	if want := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<Location xmlns="http://obs.myhwclouds.com/doc/2015-06-30/">ap-southeast-1</Location>`; loc.Body != want {
		t.Errorf("location = %s\nwant %s", loc.Body, want)
	}

	mustStatus(t, e.as(t, alice, http.MethodPut, "/archive"), http.StatusOK)
	list := mustStatus(t, e.as(t, alice, http.MethodGet, "/"), http.StatusOK)
	want := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<ListAllMyBucketsResult xmlns="http://obs.myhwclouds.com/doc/2015-06-30/">` +
		`<Owner><ID>` + ownerID("AKALICE") + `</ID></Owner><Buckets>` +
		`<Bucket><Name>archive</Name><CreationDate>2026-11-10T09:30:00.000Z</CreationDate><Location>ap-southeast-1</Location><BucketType>OBJECT</BucketType></Bucket>` +
		`<Bucket><Name>photos</Name><CreationDate>2026-11-10T09:30:00.000Z</CreationDate><Location>ap-southeast-1</Location><BucketType>OBJECT</BucketType></Bucket>` +
		`</Buckets></ListAllMyBucketsResult>`
	if list.Body != want {
		t.Errorf("list =\n%s\nwant\n%s", list.Body, want)
	}

	deleted := mustStatus(t, e.as(t, alice, http.MethodDelete, "/photos"), http.StatusNoContent)
	if deleted.Body != "" {
		t.Errorf("delete body = %q", deleted.Body)
	}
	wantError(t, e.as(t, alice, http.MethodGet, "/photos?location"), 404, "NoSuchBucket")
	wantError(t, e.as(t, alice, http.MethodDelete, "/photos"), 404, "NoSuchBucket")

	// A HEAD error has no body; the code travels in headers.
	missing := e.as(t, alice, http.MethodHead, "/photos")
	if missing.Status != 404 || missing.Body != "" || missing.Header.Get("x-obs-error-code") != "NoSuchBucket" {
		t.Errorf("HEAD of a missing bucket: %d %q %v", missing.Status, missing.Body, missing.Header)
	}
}

func TestBucketLifecycleInTheS3Dialect(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	created := mustStatus(t, e.as(t, bob, http.MethodPut, "/photos"), http.StatusOK)
	if created.Header.Get("x-amz-request-id") == "" || created.Header.Get("x-obs-request-id") != "" {
		t.Errorf("headers = %v", created.Header)
	}
	head := mustStatus(t, e.as(t, bob, http.MethodHead, "/photos"), http.StatusOK)
	if head.Header.Get("x-amz-bucket-region") != testRegion {
		t.Errorf("head: %v", head.Header)
	}
	loc := mustStatus(t, e.as(t, bob, http.MethodGet, "/photos?location"), http.StatusOK)
	if !strings.Contains(loc.Body, `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>ap-southeast-1</LocationConstraint></CreateBucketConfiguration>`) {
		t.Errorf("location = %s", loc.Body)
	}
	list := mustStatus(t, e.as(t, bob, http.MethodGet, "/"), http.StatusOK)
	for _, sub := range []string{
		`<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`,
		`<DisplayName>AKBOB</DisplayName>`, `<Name>photos</Name>`,
	} {
		if !strings.Contains(list.Body, sub) {
			t.Errorf("list does not contain %s: %s", sub, list.Body)
		}
	}
	if strings.Contains(list.Body, "<Location>") || strings.Contains(list.Body, "BucketType") {
		t.Errorf("S3 listing carries OBS extensions: %s", list.Body)
	}

	// A request with x-amz- headers but no signature is S3 too.
	plain := e.do(t, req{Method: http.MethodGet, Path: "/", Headers: map[string]string{"x-amz-date": "20261110T093000Z"}})
	if plain.Header.Get("x-amz-request-id") == "" {
		t.Errorf("x-amz- header did not select the S3 dialect: %v", plain.Header)
	}
}

func TestBothAddressingStylesReachTheSameBucket(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	virtual := "photos." + testHost
	mustStatus(t, e.do(t, req{Method: http.MethodPut, Host: virtual, Path: "/", Auth: alice}), http.StatusOK)
	mustStatus(t, e.as(t, alice, http.MethodHead, "/photos"), http.StatusOK)                                            // path style
	mustStatus(t, e.do(t, req{Method: http.MethodHead, Host: "photos.obs.localhost:8780", Auth: alice}), http.StatusOK) // localhost
	mustStatus(t, e.do(t, req{Method: http.MethodHead, Host: "127.0.0.1:8780", Path: "/obs/photos", Auth: alice}), http.StatusOK)

	// The region of a bucket is that of the endpoint it was created through.
	mustStatus(t, e.do(t, req{Method: http.MethodPut, Host: "obs.af-south-1.myhuaweicloud.com", Path: "/johannesburg", Auth: alice}), http.StatusOK)
	loc := e.as(t, alice, http.MethodGet, "/johannesburg?location")
	if !strings.Contains(loc.Body, ">af-south-1<") {
		t.Errorf("location = %s", loc.Body)
	}
}

func TestCreateBucketValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	put := func(path, body string) resp {
		return e.do(t, req{Method: http.MethodPut, Path: path, Auth: alice, Body: body})
	}

	for _, name := range []string{"ab", "Has_Upper", "192.168.1.1", "double..dot"} {
		wantError(t, put("/"+name, ""), 400, "InvalidBucketName")
	}

	// The optional body names the region, in either dialect's element.
	mustStatus(t, put("/in-obs", `<CreateBucketConfiguration><Location>ap-southeast-1</Location></CreateBucketConfiguration>`), 200)
	mustStatus(t, put("/in-s3", `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>ap-southeast-1</LocationConstraint></CreateBucketConfiguration>`), 200)
	mustStatus(t, put("/empty-config", `<CreateBucketConfiguration></CreateBucketConfiguration>`), 200)
	wantError(t, put("/elsewhere", `<CreateBucketConfiguration><Location>cn-north-4</Location></CreateBucketConfiguration>`), 400, "InvalidLocationConstraint")
	wantError(t, put("/broken", `<CreateBucketConfiguration><Location>`), 400, "MalformedXML")

	// Names are global: yours twice, or someone else's, both conflict.
	wantError(t, put("/in-obs", ""), 409, "BucketAlreadyOwnedByYou")
	wantError(t, e.as(t, bob, http.MethodPut, "/in-obs"), 409, "BucketAlreadyExists")
	// ...in every region.
	wantError(t, e.do(t, req{Method: http.MethodPut, Host: "obs.af-south-1.myhuaweicloud.com", Path: "/in-obs", Auth: bob}), 409, "BucketAlreadyExists")
}

func TestBucketsBelongToTheirCreator(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	mustStatus(t, e.as(t, alice, http.MethodPut, "/alices"), http.StatusOK)
	mustStatus(t, e.as(t, bob, http.MethodPut, "/bobs"), http.StatusOK)
	mustStatus(t, e.as(t, "", http.MethodPut, "/nobodys"), http.StatusOK) // unsigned

	for auth, want := range map[string]string{alice: "alices", bob: "bobs", "": "nobodys"} {
		list := e.as(t, auth, http.MethodGet, "/")
		if n := strings.Count(list.Body, "<Bucket>"); n != 1 || !strings.Contains(list.Body, "<Name>"+want+"</Name>") {
			t.Errorf("caller %q lists %s", auth, list.Body)
		}
	}
	for _, m := range []string{http.MethodHead, http.MethodDelete} {
		if got := e.as(t, bob, m, "/alices"); got.Status != http.StatusForbidden {
			t.Errorf("%s of another caller's bucket: %d", m, got.Status)
		}
	}
	wantError(t, e.as(t, bob, http.MethodGet, "/alices?location"), 403, "AccessDenied")
	wantError(t, e.as(t, "", http.MethodGet, "/alices?location"), 403, "AccessDenied")

	// The same access key is the same owner whichever signature it uses,
	// including a pre-signed URL's query parameter.
	mustStatus(t, e.as(t, "AWS AKALICE:c2ln", http.MethodHead, "/alices"), http.StatusOK)
	mustStatus(t, e.as(t, "AWS4-HMAC-SHA256 Credential=AKALICE/20261110/ap-southeast-1/s3/aws4_request, SignedHeaders=host, Signature=ab", http.MethodHead, "/alices"), http.StatusOK)
	mustStatus(t, e.as(t, "", http.MethodHead, "/alices?AccessKeyId=AKALICE&Expires=1&Signature=x"), http.StatusOK)
	mustStatus(t, e.as(t, "", http.MethodHead, "/alices?AWSAccessKeyId=AKALICE&Expires=1&Signature=x"), http.StatusOK)

	// The owner ID shown is not the access key.
	if list := e.as(t, alice, http.MethodGet, "/"); strings.Contains(list.Body, "AKALICE") {
		t.Errorf("the OBS listing exposes the access key: %s", list.Body)
	}
}

func TestUnsupportedRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	mustStatus(t, e.as(t, alice, http.MethodPut, "/photos"), http.StatusOK)

	wantError(t, e.as(t, alice, http.MethodPost, "/"), 405, "MethodNotAllowed")
	wantError(t, e.as(t, alice, http.MethodPatch, "/photos"), 405, "MethodNotAllowed")

	// Features that are not emulated say so, with the genuine S3 code.
	for _, sub := range []string{"acl", "versioning", "lifecycle", "policy", "tagging", "cors", "storageinfo", "quota"} {
		got := e.as(t, alice, http.MethodGet, "/photos?"+sub)
		wantError(t, got, 501, "NotImplemented")
		if !strings.Contains(got.Body, "weistack does not implement obs bucket "+sub) {
			t.Errorf("?%s: message does not name the gap: %s", sub, got.Body)
		}
	}
	wantError(t, e.as(t, alice, http.MethodPut, "/photos?versioning"), 501, "NotImplemented")
}

func TestConcurrentCreatesOfOneBucket(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok int
	)
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.svc.CreateBucket(t.Context(), "AKALICE", testRegion, "contested"); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d creates of one bucket name succeeded, want 1", ok)
	}
}

func TestInternalErrorsDoNotLeak(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_ = e.store.Close()

	got := e.as(t, alice, http.MethodGet, "/")
	wantError(t, got, 500, "InternalError")
	if strings.Contains(got.Body, "closed") {
		t.Errorf("the response leaks the internal cause: %s", got.Body)
	}
}

func TestDataDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "nested", "objects")
	e := newEnvWith(t, newMemory(), dir)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("data directory was not created: %v", err)
	}

	// Reset empties the directory but keeps it usable.
	if err := os.WriteFile(filepath.Join(dir, "stray"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "ab", "cd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reset(t.Context()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	// Only the scratch directory for uploads in progress remains.
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != blobTempDir {
		t.Fatalf("after Reset: %v, %v", entries, err)
	}

	// A path that cannot be a directory is reported.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Deps{Store: newMemory(), IDs: e.svc.ids, Logger: e.svc.log, DataDir: filepath.Join(file, "sub")}); err == nil {
		t.Fatal("New accepted an unusable data directory")
	}
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New succeeded without dependencies")
	}
}
