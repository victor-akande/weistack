package obs

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// partBody returns a part of exactly n bytes, distinct per seed.
func partBody(seed byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i%7)
	}
	return string(b)
}

func (e *env) initiate(t *testing.T, path string, headers map[string]string) string {
	t.Helper()
	res := mustStatus(t, e.do(t, req{Method: http.MethodPost, Path: path + "?uploads", Auth: alice, Headers: headers}), http.StatusOK)
	var out struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal([]byte(res.Body), &out); err != nil || out.UploadID == "" {
		t.Fatalf("initiate: %v %s", err, res.Body)
	}
	return out.UploadID
}

func (e *env) uploadPart(t *testing.T, path, id string, n int, body string) resp {
	t.Helper()
	return e.do(t, req{Method: http.MethodPut, Path: fmt.Sprintf("%s?partNumber=%d&uploadId=%s", path, n, id), Auth: alice, Body: body})
}

// completeBody lists parts as number:etag pairs, in the order given.
func completeBody(parts ...string) string {
	var b strings.Builder
	b.WriteString("<CompleteMultipartUpload>")
	for _, p := range parts {
		n, etag, _ := strings.Cut(p, ":")
		fmt.Fprintf(&b, "<Part><PartNumber>%s</PartNumber><ETag>&quot;%s&quot;</ETag></Part>", n, etag)
	}
	b.WriteString("</CompleteMultipartUpload>")
	return b.String()
}

func (e *env) complete(t *testing.T, path, id, body string) resp {
	t.Helper()
	return e.do(t, req{Method: http.MethodPost, Path: path + "?uploadId=" + id, Auth: alice, Body: body})
}

func compositeETag(parts ...string) string {
	h := md5.New()
	for _, p := range parts {
		sum := md5.Sum([]byte(p))
		h.Write(sum[:])
	}
	return fmt.Sprintf("%s-%d", hex.EncodeToString(h.Sum(nil)), len(parts))
}

func TestMultipartUploadEndToEnd(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	path := "/data/videos/big.bin"

	id := e.initiate(t, path, map[string]string{
		"Content-Type": "video/mp4", "x-obs-meta-camera": "front", "Cache-Control": "max-age=3600",
	})
	if len(id) != 32 || strings.ToUpper(id) != id {
		t.Errorf("upload ID %q is not 32 uppercase hex characters", id)
	}

	p1, p2, p3 := partBody('a', minPartSize), partBody('k', minPartSize+17), "the last part may be small"
	// Parts may arrive in any order.
	for n, body := range map[int]string{2: p2, 3: p3, 1: p1} {
		res := mustStatus(t, e.uploadPart(t, path, id, n, body), http.StatusOK)
		if res.Header.Get("ETag") != quote(md5hex(body)) {
			t.Errorf("part %d ETag = %s", n, res.Header.Get("ETag"))
		}
	}

	// Listed while in progress, then completed.
	parts := mustStatus(t, e.get(t, path+"?uploadId="+id, nil), http.StatusOK)
	for _, sub := range []string{"<PartNumber>1</PartNumber>", "<PartNumber>3</PartNumber>", fmt.Sprintf("<Size>%d</Size>", len(p2)), "<UploadId>" + id + "</UploadId>"} {
		if !strings.Contains(parts.Body, sub) {
			t.Errorf("ListParts does not contain %s: %s", sub, parts.Body)
		}
	}
	uploads := mustStatus(t, e.get(t, "/data?uploads", nil), http.StatusOK)
	if !strings.Contains(uploads.Body, "<Key>videos/big.bin</Key>") || !strings.Contains(uploads.Body, "<UploadId>"+id+"</UploadId>") {
		t.Errorf("ListMultipartUploads: %s", uploads.Body)
	}
	// Not an object until it is completed.
	wantError(t, e.get(t, path, nil), 404, "NoSuchKey")

	res := mustStatus(t, e.complete(t, path, id, completeBody("1:"+md5hex(p1), "2:"+md5hex(p2), "3:"+md5hex(p3))), http.StatusOK)
	wantETag := compositeETag(p1, p2, p3)
	for _, sub := range []string{
		`<CompleteMultipartUploadResult xmlns="http://obs.myhwclouds.com/doc/2015-06-30/">`,
		"<Location>http://" + testHost + "/data/videos/big.bin</Location>",
		"<Bucket>data</Bucket>", "<Key>videos/big.bin</Key>", "<ETag>&#34;" + wantETag + "&#34;</ETag>",
	} {
		if !strings.Contains(res.Body, sub) {
			t.Errorf("complete result does not contain %s: %s", sub, res.Body)
		}
	}

	got := mustStatus(t, e.get(t, path, nil), http.StatusOK)
	if got.Body != p1+p2+p3 {
		t.Fatalf("assembled object has %d bytes, want %d", len(got.Body), len(p1+p2+p3))
	}
	if got.Header.Get("ETag") != quote(wantETag) || got.Header.Get("Content-Type") != "video/mp4" ||
		got.Header.Get("x-obs-meta-camera") != "front" || got.Header.Get("Cache-Control") != "max-age=3600" {
		t.Errorf("object headers = %v", got.Header)
	}
	// A range across the boundary of two parts.
	cross := e.get(t, path, map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", minPartSize-3, minPartSize+2)})
	if cross.Status != 206 || cross.Body != (p1 + p2)[minPartSize-3:minPartSize+3] {
		t.Errorf("range across parts: %d %q", cross.Status, cross.Body)
	}

	// The upload is gone, with its part files.
	wantError(t, e.get(t, path+"?uploadId="+id, nil), 404, "NoSuchUpload")
	if n := e.blobFiles(t); n != 1 {
		t.Errorf("%d body files on disk, want only the assembled object", n)
	}
	if list := e.get(t, "/data?uploads", nil); strings.Contains(list.Body, "<Upload>") {
		t.Errorf("the completed upload is still listed: %s", list.Body)
	}
}

func TestMultipartPartRules(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	path := "/data/k"
	id := e.initiate(t, path, nil)

	for _, n := range []string{"0", "10001", "-1", "one", ""} {
		got := e.do(t, req{Method: http.MethodPut, Path: path + "?partNumber=" + n + "&uploadId=" + id, Auth: alice, Body: "x"})
		wantError(t, got, 400, "InvalidArgument")
	}
	mustStatus(t, e.uploadPart(t, path, id, 10000, "last allowed number"), 200)
	wantError(t, e.uploadPart(t, path, "NOSUCHUPLOAD", 1, "x"), 404, "NoSuchUpload")
	wantError(t, e.uploadPart(t, "/data/other-key", id, 1, "x"), 404, "NoSuchUpload")
	wantError(t, e.do(t, req{Method: http.MethodPut, Path: path + "?partNumber=1&uploadId=" + id, Auth: alice, Body: "x",
		Headers: map[string]string{"Content-MD5": md5b64("y")}}), 400, "BadDigest")
	wantError(t, e.do(t, req{Method: http.MethodPut, Path: path + "?partNumber=1&uploadId=" + id, Auth: alice,
		Headers: map[string]string{"x-obs-copy-source": "/data/k"}}), 501, "NotImplemented")

	// Uploading a part number again replaces it and its file.
	mustStatus(t, e.uploadPart(t, path, id, 1, "first"), 200)
	before := e.blobFiles(t)
	mustStatus(t, e.uploadPart(t, path, id, 1, "second"), 200)
	if after := e.blobFiles(t); after != before {
		t.Errorf("re-uploading a part left %d files, want %d", after, before)
	}
	parts := e.get(t, path+"?uploadId="+id, nil)
	if !strings.Contains(parts.Body, "<ETag>&#34;"+md5hex("second")+"&#34;</ETag>") || strings.Contains(parts.Body, md5hex("first")) {
		t.Errorf("ListParts after re-upload: %s", parts.Body)
	}

	// Other callers cannot touch the upload.
	for _, r := range []req{
		{Method: http.MethodPut, Path: path + "?partNumber=2&uploadId=" + id, Auth: bob, Body: "x"},
		{Method: http.MethodGet, Path: path + "?uploadId=" + id, Auth: bob},
		{Method: http.MethodDelete, Path: path + "?uploadId=" + id, Auth: bob},
		{Method: http.MethodPost, Path: path + "?uploadId=" + id, Auth: bob, Body: completeBody("1:" + md5hex("second"))},
		{Method: http.MethodPost, Path: path + "?uploads", Auth: bob},
		{Method: http.MethodGet, Path: "/data?uploads", Auth: bob},
	} {
		wantError(t, e.do(t, r), 403, "AccessDenied")
	}
	wantError(t, e.do(t, req{Method: http.MethodPost, Path: "/data/" + strings.Repeat("k", 1025) + "?uploads", Auth: alice}), 400, "KeyTooLongError")
	wantError(t, e.do(t, req{Method: http.MethodPost, Path: "/no-such-bucket/k?uploads", Auth: alice}), 404, "NoSuchBucket")
	wantError(t, e.do(t, req{Method: http.MethodPatch, Path: path + "?uploadId=" + id, Auth: alice}), 405, "MethodNotAllowed")
}

func TestCompleteValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	path := "/data/k"
	id := e.initiate(t, path, nil)
	big, small := partBody('a', minPartSize), "tiny"
	mustStatus(t, e.uploadPart(t, path, id, 1, big), 200)
	mustStatus(t, e.uploadPart(t, path, id, 2, small), 200)
	mustStatus(t, e.uploadPart(t, path, id, 3, big), 200)
	b, s := md5hex(big), md5hex(small)

	tests := []struct {
		name, body string
		status     int
		code       string
	}{
		{"not xml", "<CompleteMultipartUpload>", 400, "MalformedXML"},
		{"no parts", completeBody(), 400, "MalformedXML"},
		{"descending", completeBody("2:"+s, "1:"+b), 400, "InvalidPartOrder"},
		{"repeated number", completeBody("1:"+b, "1:"+b), 400, "InvalidPartOrder"},
		{"unknown part", completeBody("1:"+b, "4:"+b), 400, "InvalidPart"},
		{"wrong etag", completeBody("1:" + s), 400, "InvalidPart"},
		{"small part not last", completeBody("1:"+b, "2:"+s, "3:"+b), 400, "EntityTooSmall"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantError(t, e.complete(t, path, id, tt.body), tt.status, tt.code)
		})
	}
	wantError(t, e.complete(t, path, "NOSUCHUPLOAD", completeBody("1:"+b)), 404, "NoSuchUpload")
	wantError(t, e.complete(t, "/data/other-key", id, completeBody("1:"+b)), 404, "NoSuchUpload")

	// A failed completion leaves the upload usable; a subset of the parts
	// may then be chosen, and the rest are discarded.
	mustStatus(t, e.complete(t, path, id, completeBody("1:"+b, "2:"+s)), 200)
	if got := e.get(t, path, nil); got.Body != big+small {
		t.Fatalf("object has %d bytes, want %d", len(got.Body), len(big+small))
	}
	if n := e.blobFiles(t); n != 1 {
		t.Errorf("%d body files on disk, want 1: the unchosen part must be removed", n)
	}
	// It cannot be completed twice.
	wantError(t, e.complete(t, path, id, completeBody("1:"+b, "2:"+s)), 404, "NoSuchUpload")

	// A single part, of any size, is a valid upload; ETags may come unquoted.
	one := e.initiate(t, "/data/single", nil)
	mustStatus(t, e.uploadPart(t, "/data/single", one, 7, "just one"), 200)
	body := "<CompleteMultipartUpload><Part><PartNumber>7</PartNumber><ETag>" + md5hex("just one") + "</ETag></Part></CompleteMultipartUpload>"
	mustStatus(t, e.complete(t, "/data/single", one, body), 200)
	if got := e.get(t, "/data/single", nil); got.Body != "just one" || got.Header.Get("ETag") != quote(compositeETag("just one")) {
		t.Errorf("single-part object: %q %s", got.Body, got.Header.Get("ETag"))
	}
}

func TestCompletingReplacesAnExistingObject(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	mustStatus(t, e.put(t, "/data/k", "old", map[string]string{"x-obs-meta-old": "1"}), 200)

	id := e.initiate(t, "/data/k", nil)
	mustStatus(t, e.uploadPart(t, "/data/k", id, 1, "new"), 200)
	// The old object stays readable while the upload is in progress.
	if got := e.get(t, "/data/k", nil); got.Body != "old" {
		t.Errorf("during the upload: %q", got.Body)
	}
	mustStatus(t, e.complete(t, "/data/k", id, completeBody("1:"+md5hex("new"))), 200)
	got := e.get(t, "/data/k", nil)
	if got.Body != "new" || got.Header.Get("x-obs-meta-old") != "" {
		t.Errorf("after completion: %q %v", got.Body, got.Header)
	}
	if n := e.blobFiles(t); n != 1 {
		t.Errorf("%d body files on disk, want 1", n)
	}
}

func TestAbortUpload(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	id := e.initiate(t, "/data/k", nil)
	mustStatus(t, e.uploadPart(t, "/data/k", id, 1, "a"), 200)
	mustStatus(t, e.uploadPart(t, "/data/k", id, 2, "b"), 200)

	// A bucket holding parts cannot be deleted, as in OBS.
	wantError(t, e.as(t, alice, http.MethodDelete, "/data"), 409, "BucketNotEmpty")

	mustStatus(t, e.do(t, req{Method: http.MethodDelete, Path: "/data/k?uploadId=" + id, Auth: alice}), 204)
	if n := e.blobFiles(t); n != 0 {
		t.Errorf("%d part files remain after the abort", n)
	}
	wantError(t, e.do(t, req{Method: http.MethodDelete, Path: "/data/k?uploadId=" + id, Auth: alice}), 404, "NoSuchUpload")
	wantError(t, e.uploadPart(t, "/data/k", id, 3, "c"), 404, "NoSuchUpload")
	wantError(t, e.complete(t, "/data/k", id, completeBody("1:"+md5hex("a"))), 404, "NoSuchUpload")
	wantError(t, e.get(t, "/data/k", nil), 404, "NoSuchKey")

	mustStatus(t, e.as(t, alice, http.MethodDelete, "/data"), 204)
}

func TestListPartsAndUploadsPaging(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")

	id := e.initiate(t, "/data/k", nil)
	for _, n := range []int{5, 1, 9, 3} {
		mustStatus(t, e.uploadPart(t, "/data/k", id, n, fmt.Sprint(n)), 200)
	}
	type partsPage struct {
		Numbers   []int `xml:"Part>PartNumber"`
		Next      int   `xml:"NextPartNumberMarker"`
		Truncated bool  `xml:"IsTruncated"`
	}
	page := func(query string) partsPage {
		t.Helper()
		res := mustStatus(t, e.get(t, "/data/k?uploadId="+id+query, nil), 200)
		var p partsPage
		if err := xml.Unmarshal([]byte(res.Body), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := page(""); fmt.Sprint(p.Numbers) != "[1 3 5 9]" || p.Truncated {
		t.Errorf("all parts: %+v", p)
	}
	first := page("&max-parts=2")
	if fmt.Sprint(first.Numbers) != "[1 3]" || !first.Truncated || first.Next != 3 {
		t.Errorf("first page: %+v", first)
	}
	if p := page(fmt.Sprintf("&max-parts=2&part-number-marker=%d", first.Next)); fmt.Sprint(p.Numbers) != "[5 9]" || p.Truncated {
		t.Errorf("second page: %+v", p)
	}
	wantError(t, e.get(t, "/data/k?uploadId="+id+"&max-parts=x", nil), 400, "InvalidArgument")
	wantError(t, e.get(t, "/data/k?uploadId="+id+"&part-number-marker=-1", nil), 400, "InvalidArgument")

	// Several uploads, including two for one key.
	ids := map[string]string{"a/1": e.initiate(t, "/data/a/1", nil), "a/2": e.initiate(t, "/data/a/2", nil), "b": e.initiate(t, "/data/b", nil)}
	second := e.initiate(t, "/data/b", nil)
	type uploadsPage struct {
		Keys      []string `xml:"Upload>Key"`
		IDs       []string `xml:"Upload>UploadId"`
		NextKey   string   `xml:"NextKeyMarker"`
		NextID    string   `xml:"NextUploadIdMarker"`
		Truncated bool     `xml:"IsTruncated"`
	}
	list := func(query string) uploadsPage {
		t.Helper()
		res := mustStatus(t, e.get(t, "/data?uploads"+query, nil), 200)
		var p uploadsPage
		if err := xml.Unmarshal([]byte(res.Body), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := list(""); strings.Join(p.Keys, ",") != "a/1,a/2,b,b,k" {
		t.Errorf("all uploads: %v", p.Keys)
	}
	if p := list("&prefix=a/"); strings.Join(p.Keys, ",") != "a/1,a/2" {
		t.Errorf("prefix a/: %v", p.Keys)
	}
	// Walk one at a time; the two uploads of "b" are told apart by ID.
	var walked []string
	query := "&max-uploads=1"
	for range 10 {
		p := list(query)
		walked = append(walked, p.IDs...)
		if !p.Truncated {
			break
		}
		query = "&max-uploads=1&key-marker=" + p.NextKey + "&upload-id-marker=" + p.NextID
	}
	want := []string{ids["a/1"], ids["a/2"]}
	bs := []string{ids["b"], second}
	if bs[0] > bs[1] {
		bs[0], bs[1] = bs[1], bs[0]
	}
	want = append(want, bs...)
	want = append(want, id)
	if strings.Join(walked, ",") != strings.Join(want, ",") {
		t.Errorf("walk = %v\nwant %v", walked, want)
	}
	// A key marker alone skips every upload of that key.
	if p := list("&key-marker=b"); strings.Join(p.Keys, ",") != "k" {
		t.Errorf("after key-marker b: %v", p.Keys)
	}
	wantError(t, e.get(t, "/data?uploads&delimiter=/", nil), 501, "NotImplemented")
	wantError(t, e.get(t, "/data?uploads&max-uploads=x", nil), 400, "InvalidArgument")
}

func TestSizeLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.maxObjectSize = 10
	e.bucket(t, "data")

	mustStatus(t, e.put(t, "/data/ok", "0123456789", nil), 200)
	wantError(t, e.put(t, "/data/big", "0123456789A", nil), 400, "EntityTooLarge")

	id := e.initiate(t, "/data/parts", nil)
	mustStatus(t, e.uploadPart(t, "/data/parts", id, 1, "0123456789"), 200)
	wantError(t, e.uploadPart(t, "/data/parts", id, 2, "0123456789A"), 400, "EntityTooLarge")

	// The limit is per request: parts add up to more than it.
	mustStatus(t, e.uploadPart(t, "/data/parts", id, 2, "0123456789"), 200)
	e.svc.maxObjectSize = DefaultMaxObjectSize // the 100 KB rule is not under test here
	body := completeBody("2:" + md5hex("0123456789"))
	mustStatus(t, e.complete(t, "/data/parts", id, body), 200)

	// A chunked body that declares more than the limit is refused before
	// it is read.
	e.svc.maxObjectSize = 10
	chunked := e.do(t, req{Method: http.MethodPut, Path: "/data/declared", Auth: "AWS4-HMAC-SHA256 Credential=AKALICE/x/y/s3/aws4_request", Body: "1;chunk-signature=0\r\nx\r\n0\r\n\r\n",
		Headers: map[string]string{"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "x-amz-decoded-content-length": "11"}})
	wantError(t, chunked, 400, "EntityTooLarge")
	if n := e.blobFiles(t); n != 2 {
		t.Errorf("%d body files on disk, want 2", n)
	}
}

func TestConcurrentPartUploads(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	id := e.initiate(t, "/data/k", nil)

	const parts = 24
	var wg sync.WaitGroup
	for n := 1; n <= parts; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := e.uploadPart(t, "/data/k", id, n, partBody(byte(n), minPartSize)); got.Status != 200 {
				t.Errorf("part %d: %d %s", n, got.Status, got.Body)
			}
		}()
	}
	wg.Wait()

	var list []string
	var bodies []string
	for n := 1; n <= parts; n++ {
		body := partBody(byte(n), minPartSize)
		list = append(list, fmt.Sprintf("%d:%s", n, md5hex(body)))
		bodies = append(bodies, body)
	}
	res := mustStatus(t, e.complete(t, "/data/k", id, completeBody(list...)), 200)
	if !strings.Contains(res.Body, compositeETag(bodies...)) {
		t.Errorf("composite ETag missing from %s", res.Body)
	}
	got := e.get(t, "/data/k", nil)
	if got.Body != strings.Join(bodies, "") {
		t.Fatalf("assembled object has %d bytes, want %d", len(got.Body), parts*minPartSize)
	}
}

func TestUploadSurvivesRestart(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	open := func() *env {
		st, err := openBolt(filepath.Join(root, "weistack.db"))
		if err != nil {
			t.Fatal(err)
		}
		return newEnvWith(t, st, filepath.Join(root, "objects"))
	}
	p1, p2 := partBody('p', minPartSize), "tail"

	first := open()
	first.bucket(t, "data")
	id := first.initiate(t, "/data/k", map[string]string{"x-obs-meta-resumed": "yes"})
	mustStatus(t, first.uploadPart(t, "/data/k", id, 1, p1), 200)
	if err := first.store.Close(); err != nil {
		t.Fatal(err)
	}

	second := open()
	mustStatus(t, second.uploadPart(t, "/data/k", id, 2, p2), 200)
	mustStatus(t, second.complete(t, "/data/k", id, completeBody("1:"+md5hex(p1), "2:"+md5hex(p2))), 200)
	got := second.get(t, "/data/k", nil)
	if got.Body != p1+p2 || got.Header.Get("x-obs-meta-resumed") != "yes" {
		t.Fatalf("after a restart mid-upload: %d bytes, %v", len(got.Body), got.Header)
	}
}

func TestMissingPartFileFailsCompletionCleanly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	id := e.initiate(t, "/data/k", nil)
	mustStatus(t, e.uploadPart(t, "/data/k", id, 1, "only part"), 200)

	u, err := e.svc.uploads("data").Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.blobs.remove(u.Parts[1].Blob); err != nil {
		t.Fatal(err)
	}
	wantError(t, e.complete(t, "/data/k", id, completeBody("1:"+md5hex("only part"))), 500, "InternalError")
	// The upload is released, so it can be aborted.
	mustStatus(t, e.do(t, req{Method: http.MethodDelete, Path: "/data/k?uploadId=" + id, Auth: alice}), 204)
}
