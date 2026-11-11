package obs

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func md5b64(s string) string {
	sum := md5.Sum([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// bucket creates a bucket owned by alice.
func (e *env) bucket(t *testing.T, name string) {
	t.Helper()
	mustStatus(t, e.as(t, alice, http.MethodPut, "/"+name), http.StatusOK)
}

// put uploads an object as alice.
func (e *env) put(t *testing.T, path, body string, headers map[string]string) resp {
	t.Helper()
	return e.do(t, req{Method: http.MethodPut, Path: path, Auth: alice, Body: body, Headers: headers})
}

// get downloads as alice with optional headers.
func (e *env) get(t *testing.T, path string, headers map[string]string) resp {
	t.Helper()
	return e.do(t, req{Method: http.MethodGet, Path: path, Auth: alice, Headers: headers})
}

// blobFiles counts the object bodies on disk.
func (e *env) blobFiles(t *testing.T) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(e.dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestObjectRoundTrip(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "photos")
	const body = "hello, object storage"

	put := mustStatus(t, e.put(t, "/photos/docs/hello.txt", body, map[string]string{
		"Content-Type":        "text/plain",
		"Cache-Control":       "max-age=60",
		"Content-Disposition": `attachment; filename="hello.txt"`,
		"x-obs-meta-author":   "alice",
		"x-obs-meta-Project":  "weistack",
	}), http.StatusOK)
	if put.Header.Get("ETag") != `"`+md5hex(body)+`"` || put.Body != "" {
		t.Errorf("put: ETag %q body %q", put.Header.Get("ETag"), put.Body)
	}

	got := mustStatus(t, e.get(t, "/photos/docs/hello.txt", nil), http.StatusOK)
	if got.Body != body {
		t.Errorf("body = %q", got.Body)
	}
	want := map[string]string{
		"ETag":                `"` + md5hex(body) + `"`,
		"Content-Type":        "text/plain",
		"Content-Length":      "21",
		"Accept-Ranges":       "bytes",
		"Cache-Control":       "max-age=60",
		"Content-Disposition": `attachment; filename="hello.txt"`,
		"Last-Modified":       "Tue, 10 Nov 2026 09:30:00 GMT",
		"x-obs-meta-author":   "alice",
		"x-obs-meta-project":  "weistack",
		"x-obs-storage-class": "STANDARD",
	}
	for name, v := range want {
		if got.Header.Get(name) != v {
			t.Errorf("header %s = %q, want %q", name, got.Header.Get(name), v)
		}
	}

	// HEAD: the same headers, no body.
	head := mustStatus(t, e.as(t, alice, http.MethodHead, "/photos/docs/hello.txt"), http.StatusOK)
	if head.Body != "" || head.Header.Get("Content-Length") != "21" || head.Header.Get("ETag") != want["ETag"] {
		t.Errorf("head: body %q headers %v", head.Body, head.Header)
	}

	// The S3 dialect returns the same metadata under x-amz-meta-.
	s3 := mustStatus(t, e.as(t, "AWS AKALICE:c2ln", http.MethodGet, "/photos/docs/hello.txt"), http.StatusOK)
	if s3.Header.Get("x-amz-meta-author") != "alice" || s3.Header.Get("x-obs-meta-author") != "" || s3.Header.Get("x-obs-storage-class") != "" {
		t.Errorf("S3 dialect headers = %v", s3.Header)
	}

	// Virtual-hosted style reaches the same object.
	vh := e.do(t, req{Method: http.MethodGet, Host: "photos." + testHost, Path: "/docs/hello.txt", Auth: alice})
	if vh.Status != 200 || vh.Body != body {
		t.Errorf("virtual-hosted get: %d %q", vh.Status, vh.Body)
	}

	mustStatus(t, e.as(t, alice, http.MethodDelete, "/photos/docs/hello.txt"), http.StatusNoContent)
	wantError(t, e.get(t, "/photos/docs/hello.txt", nil), 404, "NoSuchKey")
	// Deleting again still succeeds, as in S3.
	mustStatus(t, e.as(t, alice, http.MethodDelete, "/photos/docs/hello.txt"), http.StatusNoContent)

	missing := e.as(t, alice, http.MethodHead, "/photos/docs/hello.txt")
	if missing.Status != 404 || missing.Body != "" || missing.Header.Get("x-obs-error-code") != "NoSuchKey" {
		t.Errorf("HEAD of a missing object: %d %q %v", missing.Status, missing.Body, missing.Header)
	}
	if n := e.blobFiles(t); n != 0 {
		t.Errorf("%d body files remain after the delete", n)
	}
}

func TestObjectDefaultsAndSpecialKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")

	// No Content-Type, empty body, a "folder" key.
	mustStatus(t, e.put(t, "/data/empty", "", nil), 200)
	got := e.get(t, "/data/empty", nil)
	if got.Status != 200 || got.Body != "" || got.Header.Get("Content-Type") != "binary/octet-stream" ||
		got.Header.Get("ETag") != `"d41d8cd98f00b204e9800998ecf8427e"` || got.Header.Get("Content-Length") != "0" {
		t.Errorf("empty object: %d %v", got.Status, got.Header)
	}
	mustStatus(t, e.put(t, "/data/folder/", "", nil), 200)
	mustStatus(t, e.as(t, alice, http.MethodHead, "/data/folder/"), 200)

	// Keys with spaces, unicode, encoded slashes and reserved characters.
	for _, key := range []string{"my file.txt", "résumé/日本語.pdf", "a+b=c&d.txt", "trailing space ", "q?uestion#hash"} {
		path := "/data/" + strings.NewReplacer(" ", "%20", "+", "%2B", "&", "%26", "?", "%3F", "#", "%23", "=", "%3D").Replace(key)
		mustStatus(t, e.put(t, path, "x:"+key, nil), 200)
		if got := e.get(t, path, nil); got.Status != 200 || got.Body != "x:"+key {
			t.Errorf("key %q: %d %q", key, got.Status, got.Body)
		}
	}

	wantError(t, e.put(t, "/data/"+strings.Repeat("k", 1025), "x", nil), 400, "KeyTooLongError")
	mustStatus(t, e.put(t, "/data/"+strings.Repeat("k", 1024), "x", nil), 200)
	wantError(t, e.put(t, "/no-such-bucket/key", "x", nil), 404, "NoSuchBucket")
	wantError(t, e.get(t, "/no-such-bucket/key", nil), 404, "NoSuchBucket")
	wantError(t, e.as(t, alice, http.MethodDelete, "/no-such-bucket/key"), 404, "NoSuchBucket")
}

func TestOverwriteReplacesBodyAndMetadata(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")

	mustStatus(t, e.put(t, "/data/k", "first version", map[string]string{"x-obs-meta-v": "1", "Content-Type": "text/plain"}), 200)
	e.now = e.now.Add(time.Hour)
	mustStatus(t, e.put(t, "/data/k", "second", map[string]string{"x-amz-meta-w": "2"}), 200)

	got := e.get(t, "/data/k", nil)
	if got.Body != "second" || got.Header.Get("x-obs-meta-v") != "" || got.Header.Get("x-obs-meta-w") != "2" ||
		got.Header.Get("Content-Type") != "binary/octet-stream" || got.Header.Get("Last-Modified") != "Tue, 10 Nov 2026 10:30:00 GMT" {
		t.Errorf("after overwrite: %q %v", got.Body, got.Header)
	}
	if n := e.blobFiles(t); n != 1 {
		t.Errorf("%d body files on disk, want 1: the replaced body must be removed", n)
	}
}

func TestContentMD5(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")

	mustStatus(t, e.put(t, "/data/ok", "payload", map[string]string{"Content-MD5": md5b64("payload")}), 200)
	wantError(t, e.put(t, "/data/bad", "payload", map[string]string{"Content-MD5": md5b64("something else")}), 400, "BadDigest")
	wantError(t, e.put(t, "/data/bad", "payload", map[string]string{"Content-MD5": "not base64!"}), 400, "InvalidDigest")
	wantError(t, e.put(t, "/data/bad", "payload", map[string]string{"Content-MD5": "c2hvcnQ="}), 400, "InvalidDigest")

	// A rejected upload leaves neither an object nor a body file.
	wantError(t, e.get(t, "/data/bad", nil), 404, "NoSuchKey")
	if n := e.blobFiles(t); n != 1 {
		t.Errorf("%d body files on disk, want 1", n)
	}
	// A failed overwrite keeps the existing object intact.
	wantError(t, e.put(t, "/data/ok", "tampered", map[string]string{"Content-MD5": md5b64("payload")}), 400, "BadDigest")
	if got := e.get(t, "/data/ok", nil); got.Body != "payload" {
		t.Errorf("a rejected overwrite changed the object: %q", got.Body)
	}
}

func TestRangeDownloads(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	const body = "0123456789abcdefghij" // 20 bytes
	mustStatus(t, e.put(t, "/data/k", body, nil), 200)

	tests := []struct {
		header       string
		status       int
		body         string
		contentRange string
	}{
		{"bytes=0-4", 206, "01234", "bytes 0-4/20"},
		{"bytes=5-9", 206, "56789", "bytes 5-9/20"},
		{"bytes=15-", 206, "fghij", "bytes 15-19/20"},
		{"bytes=-5", 206, "fghij", "bytes 15-19/20"},
		{"bytes=0-0", 206, "0", "bytes 0-0/20"},
		{"bytes=19-19", 206, "j", "bytes 19-19/20"},
		{"bytes=10-999", 206, "abcdefghij", "bytes 10-19/20"}, // end clamped
		{"bytes=-999", 206, body, "bytes 0-19/20"},            // suffix longer than the object
		{"bytes=0-19", 206, body, "bytes 0-19/20"},
		// Ignored, as in S3: the whole object is served.
		{"bytes=0-4,10-14", 200, body, ""},
		{"bytes=5-2", 200, body, ""},
		{"bytes=abc", 200, body, ""},
		{"items=0-4", 200, body, ""},
		{"", 200, body, ""},
	}
	for _, tt := range tests {
		got := e.get(t, "/data/k", map[string]string{"Range": tt.header})
		if got.Status != tt.status || got.Body != tt.body || got.Header.Get("Content-Range") != tt.contentRange {
			t.Errorf("Range %q: %d %q Content-Range %q; want %d %q %q",
				tt.header, got.Status, got.Body, got.Header.Get("Content-Range"), tt.status, tt.body, tt.contentRange)
		}
		if got.Header.Get("Content-Length") != fmt.Sprint(len(tt.body)) {
			t.Errorf("Range %q: Content-Length %q, want %d", tt.header, got.Header.Get("Content-Length"), len(tt.body))
		}
	}

	for _, header := range []string{"bytes=20-", "bytes=20-25", "bytes=-0", "bytes=999-"} {
		got := e.get(t, "/data/k", map[string]string{"Range": header})
		wantError(t, got, 416, "InvalidRange")
	}
	// HEAD with a range reports the range's length, with no body.
	head := e.do(t, req{Method: http.MethodHead, Path: "/data/k", Auth: alice, Headers: map[string]string{"Range": "bytes=0-4"}})
	if head.Status != 206 || head.Body != "" || head.Header.Get("Content-Length") != "5" {
		t.Errorf("ranged HEAD: %d %q %v", head.Status, head.Body, head.Header)
	}
	// Any range on an empty object is unsatisfiable.
	mustStatus(t, e.put(t, "/data/empty", "", nil), 200)
	wantError(t, e.get(t, "/data/empty", map[string]string{"Range": "bytes=-1"}), 416, "InvalidRange")
	wantError(t, e.get(t, "/data/empty", map[string]string{"Range": "bytes=0-"}), 416, "InvalidRange")
}

func TestConditionalDownloads(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	mustStatus(t, e.put(t, "/data/k", "body", nil), 200)
	etag := `"` + md5hex("body") + `"`
	const before, at, after = "Tue, 10 Nov 2026 09:00:00 GMT", "Tue, 10 Nov 2026 09:30:00 GMT", "Tue, 10 Nov 2026 10:00:00 GMT"

	tests := []struct {
		name    string
		headers map[string]string
		status  int
	}{
		{"If-Match hit", map[string]string{"If-Match": etag}, 200},
		{"If-Match star", map[string]string{"If-Match": "*"}, 200},
		{"If-Match in a list", map[string]string{"If-Match": `"zzz", ` + etag}, 200},
		{"If-Match miss", map[string]string{"If-Match": `"zzz"`}, 412},
		{"If-None-Match hit", map[string]string{"If-None-Match": etag}, 304},
		{"If-None-Match miss", map[string]string{"If-None-Match": `"zzz"`}, 200},
		{"If-Modified-Since earlier", map[string]string{"If-Modified-Since": before}, 200},
		{"If-Modified-Since same", map[string]string{"If-Modified-Since": at}, 304},
		{"If-Modified-Since later", map[string]string{"If-Modified-Since": after}, 304},
		{"If-Unmodified-Since earlier", map[string]string{"If-Unmodified-Since": before}, 412},
		{"If-Unmodified-Since later", map[string]string{"If-Unmodified-Since": after}, 200},
		{"If-None-Match wins over If-Modified-Since", map[string]string{"If-None-Match": `"zzz"`, "If-Modified-Since": after}, 200},
		{"unparseable date is ignored", map[string]string{"If-Modified-Since": "yesterday"}, 200},
	}
	for _, tt := range tests {
		got := e.get(t, "/data/k", tt.headers)
		if got.Status != tt.status {
			t.Errorf("%s: status %d, want %d", tt.name, got.Status, tt.status)
		}
		switch tt.status {
		case 304:
			if got.Body != "" || got.Header.Get("ETag") != etag {
				t.Errorf("%s: 304 with body %q, ETag %q", tt.name, got.Body, got.Header.Get("ETag"))
			}
		case 412:
			wantError(t, got, 412, "PreconditionFailed")
		}
	}
}

func TestResponseHeaderOverrides(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	mustStatus(t, e.put(t, "/data/report", "x", map[string]string{"Content-Type": "text/plain"}), 200)

	got := e.get(t, "/data/report?response-content-type=application/pdf&response-content-disposition=attachment%3B%20filename%3Dreport.pdf&response-cache-control=no-store", nil)
	if got.Header.Get("Content-Type") != "application/pdf" || got.Header.Get("Content-Disposition") != "attachment; filename=report.pdf" ||
		got.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("overrides: %v", got.Header)
	}
}

func TestAWSChunkedUpload(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	chunk := func(data string) string {
		return fmt.Sprintf("%x;chunk-signature=0123abcd\r\n%s\r\n", len(data), data)
	}
	const payload = "hello, chunked world"
	framed := chunk("hello, ") + chunk("chunked ") + chunk("world") + "0;chunk-signature=ffff\r\n\r\n"
	s3 := "AWS4-HMAC-SHA256 Credential=AKALICE/20261110/ap-southeast-1/s3/aws4_request, SignedHeaders=host, Signature=ab"

	put := e.do(t, req{Method: http.MethodPut, Path: "/data/chunked", Auth: s3, Body: framed, Headers: map[string]string{
		"x-amz-content-sha256":         "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		"x-amz-decoded-content-length": fmt.Sprint(len(payload)),
		"Content-Encoding":             "aws-chunked,gzip",
	}})
	mustStatus(t, put, 200)
	if put.Header.Get("ETag") != `"`+md5hex(payload)+`"` {
		t.Errorf("ETag %q is not the MD5 of the decoded payload", put.Header.Get("ETag"))
	}
	got := e.get(t, "/data/chunked", nil)
	if got.Body != payload {
		t.Errorf("stored body = %q, want the payload without chunk framing", got.Body)
	}
	// The framing is transport-level: only the real encoding is kept.
	if enc := got.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", enc)
	}

	// With trailing checksum headers, as newer SDKs send.
	trailer := chunk(payload) + "0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n"
	mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/data/trailer", Auth: s3, Body: trailer, Headers: map[string]string{
		"x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "Content-Encoding": "aws-chunked",
	}}), 200)
	if got := e.get(t, "/data/trailer", nil); got.Body != payload || got.Header.Get("Content-Encoding") != "" {
		t.Errorf("trailer upload: %q encoding %q", got.Body, got.Header.Get("Content-Encoding"))
	}

	bad := map[string]string{
		"wrong decoded length": framed,
		"bad chunk size":       "zz;chunk-signature=0\r\nhello\r\n0\r\n\r\n",
		"truncated chunk":      "a;chunk-signature=0\r\nhel",
		"missing crlf":         "5;chunk-signature=0\r\nhelloXX0\r\n\r\n",
		"no final chunk":       chunk("hello"),
	}
	for name, body := range bad {
		headers := map[string]string{"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"}
		if name == "wrong decoded length" {
			headers["x-amz-decoded-content-length"] = "5"
		}
		got := e.do(t, req{Method: http.MethodPut, Path: "/data/bad", Auth: s3, Body: body, Headers: headers})
		if got.Status != 400 || !strings.Contains(got.Body, "IncompleteBody") {
			t.Errorf("%s: %d %s", name, got.Status, got.Body)
		}
	}
	wantError(t, e.do(t, req{Method: http.MethodPut, Path: "/data/bad", Auth: s3, Body: framed, Headers: map[string]string{
		"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "x-amz-decoded-content-length": "many",
	}}), 400, "InvalidArgument")
	wantError(t, e.get(t, "/data/bad", nil), 404, "NoSuchKey")
	if n := e.blobFiles(t); n != 2 {
		t.Errorf("%d body files on disk, want 2", n)
	}
}

func TestCopyObject(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "src")
	e.bucket(t, "dst")
	mustStatus(t, e.put(t, "/src/dir/original%20file.txt", "copy me", map[string]string{
		"Content-Type": "text/plain", "x-obs-meta-origin": "src", "Cache-Control": "no-cache",
	}), 200)
	e.now = e.now.Add(time.Hour)
	copyTo := func(path, source string, headers map[string]string) resp {
		h := map[string]string{"x-obs-copy-source": source}
		for k, v := range headers {
			h[k] = v
		}
		return e.put(t, path, "", h)
	}

	// The source may be given with or without a leading slash, URL-encoded.
	res := mustStatus(t, copyTo("/dst/copy.txt", "/src/dir/original%20file.txt", nil), 200)
	for _, sub := range []string{
		`<CopyObjectResult xmlns="http://obs.myhwclouds.com/doc/2015-06-30/">`,
		`<LastModified>2026-11-10T10:30:00.000Z</LastModified>`, `<ETag>&#34;` + md5hex("copy me") + `&#34;</ETag>`,
	} {
		if !strings.Contains(res.Body, sub) {
			t.Errorf("copy result does not contain %s: %s", sub, res.Body)
		}
	}
	got := e.get(t, "/dst/copy.txt", nil)
	if got.Body != "copy me" || got.Header.Get("Content-Type") != "text/plain" || got.Header.Get("x-obs-meta-origin") != "src" ||
		got.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("copy with default directive: %q %v", got.Body, got.Header)
	}

	// REPLACE takes the new request's metadata; the S3 header names work too.
	mustStatus(t, e.put(t, "/dst/replaced.txt", "", map[string]string{
		"x-amz-copy-source": "src/dir/original%20file.txt", "x-amz-metadata-directive": "REPLACE",
		"Content-Type": "application/json", "x-amz-meta-new": "yes",
	}), 200)
	got = e.get(t, "/dst/replaced.txt", nil)
	if got.Body != "copy me" || got.Header.Get("Content-Type") != "application/json" || got.Header.Get("x-obs-meta-new") != "yes" ||
		got.Header.Get("x-obs-meta-origin") != "" || got.Header.Get("Cache-Control") != "" {
		t.Errorf("copy with REPLACE: %q %v", got.Body, got.Header)
	}

	// The copy is independent of its source.
	mustStatus(t, e.as(t, alice, http.MethodDelete, "/src/dir/original%20file.txt"), 204)
	if got := e.get(t, "/dst/copy.txt", nil); got.Body != "copy me" {
		t.Errorf("deleting the source broke the copy: %d %q", got.Status, got.Body)
	}
	mustStatus(t, e.put(t, "/src/a", "v1", nil), 200)
	mustStatus(t, copyTo("/src/b", "/src/a", nil), 200)
	mustStatus(t, e.put(t, "/src/a", "v2", nil), 200)
	if got := e.get(t, "/src/b", nil); got.Body != "v1" {
		t.Errorf("overwriting the source changed the copy: %q", got.Body)
	}

	// Onto itself: only with REPLACE, which is how metadata is edited.
	wantError(t, copyTo("/src/a", "/src/a", nil), 400, "InvalidRequest")
	mustStatus(t, copyTo("/src/a", "/src/a", map[string]string{"x-obs-metadata-directive": "REPLACE", "x-obs-meta-edited": "1"}), 200)
	if got := e.get(t, "/src/a", nil); got.Body != "v2" || got.Header.Get("x-obs-meta-edited") != "1" {
		t.Errorf("in-place metadata edit: %q %v", got.Body, got.Header)
	}

	wantError(t, copyTo("/dst/x", "/src/missing", nil), 404, "NoSuchKey")
	wantError(t, copyTo("/dst/x", "/no-such-bucket/a", nil), 404, "NoSuchBucket")
	wantError(t, copyTo("/no-such-bucket/x", "/src/a", nil), 404, "NoSuchBucket")
	wantError(t, copyTo("/dst/x", "just-a-bucket", nil), 400, "InvalidArgument")
	wantError(t, copyTo("/dst/x", "/src/%zz", nil), 400, "InvalidArgument")
	wantError(t, copyTo("/dst/x", "/src/a", map[string]string{"x-obs-metadata-directive": "MERGE"}), 400, "InvalidArgument")
	wantError(t, copyTo("/dst/x", "/src/a?versionId=3", nil), 501, "NotImplemented")
	mustStatus(t, copyTo("/dst/x", "/src/a?versionId=null", nil), 200)
	wantError(t, copyTo("/dst/"+strings.Repeat("k", 1025), "/src/a", nil), 400, "KeyTooLongError")

	// A caller cannot copy out of a bucket it does not own.
	mustStatus(t, e.as(t, bob, http.MethodPut, "/bobs"), 200)
	stolen := e.do(t, req{Method: http.MethodPut, Path: "/bobs/stolen", Auth: bob, Headers: map[string]string{"x-amz-copy-source": "/src/a"}})
	wantError(t, stolen, 403, "AccessDenied")
}

func TestBatchDelete(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	for _, k := range []string{"a", "b", "c", "dir/d"} {
		mustStatus(t, e.put(t, "/data/"+k, k, nil), 200)
	}
	del := func(body string) resp {
		return e.do(t, req{Method: http.MethodPost, Path: "/data?delete", Auth: alice, Body: body})
	}

	// Verbose: every key is reported, including one that never existed.
	res := mustStatus(t, del(`<Delete><Object><Key>a</Key></Object><Object><Key>dir/d</Key></Object><Object><Key>ghost</Key></Object></Delete>`), 200)
	want := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<DeleteResult xmlns="http://obs.myhwclouds.com/doc/2015-06-30/">` +
		`<Deleted><Key>a</Key></Deleted><Deleted><Key>dir/d</Key></Deleted><Deleted><Key>ghost</Key></Deleted></DeleteResult>`
	if res.Body != want {
		t.Errorf("result =\n%s\nwant\n%s", res.Body, want)
	}

	// Quiet: only failures are reported, so a clean run lists nothing.
	res = mustStatus(t, del(`<Delete><Quiet>true</Quiet><Object><Key>b</Key></Object></Delete>`), 200)
	if strings.Contains(res.Body, "<Deleted>") {
		t.Errorf("quiet result reports successes: %s", res.Body)
	}

	for _, k := range []string{"a", "b", "dir/d"} {
		wantError(t, e.get(t, "/data/"+k, nil), 404, "NoSuchKey")
	}
	mustStatus(t, e.get(t, "/data/c", nil), 200)
	if n := e.blobFiles(t); n != 1 {
		t.Errorf("%d body files on disk, want 1", n)
	}

	var many strings.Builder
	many.WriteString("<Delete>")
	for i := range 1001 {
		fmt.Fprintf(&many, "<Object><Key>k%d</Key></Object>", i)
	}
	many.WriteString("</Delete>")
	wantError(t, del(many.String()), 400, "MalformedXML")
	wantError(t, del(`<Delete></Delete>`), 400, "MalformedXML")
	wantError(t, del(`<Delete><Object>`), 400, "MalformedXML")
	wantError(t, del(``), 400, "MalformedXML")
	wantError(t, e.do(t, req{Method: http.MethodPost, Path: "/no-such-bucket?delete", Auth: alice, Body: `<Delete><Object><Key>a</Key></Object></Delete>`}), 404, "NoSuchBucket")
}

func TestBucketMustBeEmptyToDelete(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	mustStatus(t, e.put(t, "/data/k", "x", nil), 200)

	wantError(t, e.as(t, alice, http.MethodDelete, "/data"), 409, "BucketNotEmpty")
	mustStatus(t, e.as(t, alice, http.MethodDelete, "/data/k"), 204)
	mustStatus(t, e.as(t, alice, http.MethodDelete, "/data"), 204)

	// A bucket recreated under the same name starts empty.
	e.bucket(t, "data")
	wantError(t, e.get(t, "/data/k", nil), 404, "NoSuchKey")
}

func TestObjectsBelongToTheBucketOwner(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	mustStatus(t, e.put(t, "/data/secret", "x", nil), 200)

	wantError(t, e.as(t, bob, http.MethodGet, "/data/secret"), 403, "AccessDenied")
	wantError(t, e.as(t, bob, http.MethodGet, "/data"), 403, "AccessDenied")
	wantError(t, e.do(t, req{Method: http.MethodPut, Path: "/data/planted", Auth: bob, Body: "y"}), 403, "AccessDenied")
	wantError(t, e.as(t, bob, http.MethodDelete, "/data/secret"), 403, "AccessDenied")
	wantError(t, e.do(t, req{Method: http.MethodPost, Path: "/data?delete", Auth: bob, Body: `<Delete><Object><Key>secret</Key></Object></Delete>`}), 403, "AccessDenied")
	if got := e.as(t, bob, http.MethodHead, "/data/secret"); got.Status != 403 {
		t.Errorf("HEAD as another caller: %d", got.Status)
	}
	mustStatus(t, e.get(t, "/data/secret", nil), 200)
}

func TestUnsupportedObjectRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	mustStatus(t, e.put(t, "/data/k", "x", nil), 200)

	for _, sub := range []string{"acl", "tagging", "restore", "append"} {
		got := e.get(t, "/data/k?"+sub, nil)
		wantError(t, got, 501, "NotImplemented")
		if !strings.Contains(got.Body, "object "+sub) {
			t.Errorf("?%s: message does not name the gap: %s", sub, got.Body)
		}
	}
	wantError(t, e.get(t, "/data/k?versionId=7", nil), 501, "NotImplemented")
	mustStatus(t, e.get(t, "/data/k?versionId=null", nil), 200)
	wantError(t, e.do(t, req{Method: http.MethodPost, Path: "/data", Auth: alice, Body: "form"}), 501, "NotImplemented")
	wantError(t, e.do(t, req{Method: http.MethodPatch, Path: "/data/k", Auth: alice}), 405, "MethodNotAllowed")
}

// A large upload must go to disk as it arrives, not through memory.
func TestLargeObjectIsStreamed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")

	const size = 64 << 20
	pr, pw := io.Pipe()
	hash := md5.New()
	go func() {
		block := make([]byte, 1<<20)
		for i := range block {
			block[i] = byte(i)
		}
		w := io.MultiWriter(pw, hash)
		for range size >> 20 {
			if _, err := w.Write(block); err != nil {
				return
			}
		}
		_ = pw.Close()
	}()

	r, _ := http.NewRequest(http.MethodPut, "/data/big", pr)
	r.Host = testHost
	r.Header.Set("Authorization", alice)
	w := newDiscardRecorder()
	e.handler.ServeHTTP(w, r)
	if w.status != 200 {
		t.Fatalf("upload status %d", w.status)
	}
	wantETag := `"` + hex.EncodeToString(hash.Sum(nil)) + `"`
	if w.header.Get("ETag") != wantETag {
		t.Fatalf("ETag %s, want %s", w.header.Get("ETag"), wantETag)
	}

	// Download it into a hash, again without holding it in memory.
	r, _ = http.NewRequest(http.MethodGet, "/data/big", nil)
	r.Host = testHost
	r.Header.Set("Authorization", alice)
	dl := newDiscardRecorder()
	e.handler.ServeHTTP(dl, r)
	if dl.status != 200 || dl.n != size || `"`+hex.EncodeToString(dl.hash.Sum(nil))+`"` != wantETag {
		t.Fatalf("download: status %d, %d bytes", dl.status, dl.n)
	}

	// The tail of a large object by range.
	r, _ = http.NewRequest(http.MethodGet, "/data/big", nil)
	r.Host = testHost
	r.Header.Set("Authorization", alice)
	r.Header.Set("Range", "bytes=-1048576")
	tail := newDiscardRecorder()
	e.handler.ServeHTTP(tail, r)
	if tail.status != 206 || tail.n != 1<<20 {
		t.Fatalf("ranged download: status %d, %d bytes", tail.status, tail.n)
	}
}

func TestConcurrentWritesToOneKey(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")

	const writers = 30
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := fmt.Sprintf("writer-%02d", i)
			if got := e.put(t, "/data/contested", body, nil); got.Status != 200 {
				t.Errorf("put: %d %s", got.Status, got.Body)
			}
		}()
	}
	wg.Wait()

	// One writer won; the object is internally consistent.
	got := e.get(t, "/data/contested", nil)
	if got.Status != 200 || !strings.HasPrefix(got.Body, "writer-") || got.Header.Get("ETag") != `"`+md5hex(got.Body)+`"` {
		t.Fatalf("after concurrent writes: %d %q ETag %s", got.Status, got.Body, got.Header.Get("ETag"))
	}
}

func TestObjectsSurviveRestartWithPersistence(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	open := func() *env {
		st, err := openBolt(filepath.Join(root, "weistack.db"))
		if err != nil {
			t.Fatal(err)
		}
		return newEnvWith(t, st, filepath.Join(root, "objects"))
	}

	first := open()
	first.bucket(t, "data")
	mustStatus(t, first.put(t, "/data/keep", "still here", map[string]string{"x-obs-meta-k": "v"}), 200)
	if err := first.store.Close(); err != nil {
		t.Fatal(err)
	}

	second := open()
	got := second.get(t, "/data/keep", nil)
	if got.Status != 200 || got.Body != "still here" || got.Header.Get("x-obs-meta-k") != "v" {
		t.Fatalf("after restart: %d %q %v", got.Status, got.Body, got.Header)
	}

	// A reset removes the bodies with the metadata.
	if err := second.store.Reset(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := second.svc.Reset(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := second.blobFiles(t); n != 0 {
		t.Fatalf("%d body files remain after a reset", n)
	}
	// And the service keeps working.
	second.bucket(t, "data")
	mustStatus(t, second.put(t, "/data/new", "x", nil), 200)
}

func TestMissingBodyFileIsAnInternalError(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	mustStatus(t, e.put(t, "/data/k", "x", nil), 200)

	// Simulate the body vanishing behind the emulator's back.
	if err := os.RemoveAll(e.dir); err != nil {
		t.Fatal(err)
	}
	got := e.get(t, "/data/k", nil)
	wantError(t, got, 500, "InternalError")
	if strings.Contains(got.Body, e.dir) {
		t.Errorf("the error leaks a filesystem path: %s", got.Body)
	}
	// Metadata-only requests still work.
	mustStatus(t, e.as(t, alice, http.MethodHead, "/data/k"), 200)
}
