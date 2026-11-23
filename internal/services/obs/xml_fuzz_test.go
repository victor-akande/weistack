package obs

import (
	"net/http"
	"testing"
)

// FuzzXMLBodies sends any body to the operations that parse XML: bucket
// creation, batch delete, completing a multipart upload, and bucket
// encryption. None may fail as WeiStack's fault (5xx), which is also how
// a panic would show.
func FuzzXMLBodies(f *testing.F) {
	for _, s := range []string{
		`<CreateBucketConfiguration><LocationConstraint>ap-southeast-1</LocationConstraint></CreateBucketConfiguration>`,
		`<Delete><Quiet>true</Quiet><Object><Key>a</Key></Object><Object><Key>b</Key><VersionId>x</VersionId></Object></Delete>`,
		`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"x"</ETag></Part></CompleteMultipartUpload>`,
		`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>kms</SSEAlgorithm><KMSMasterKeyID>k</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`,
		`<!DOCTYPE x [<!ENTITY a "aaaa">]><Delete><Object><Key>&a;</Key></Object></Delete>`,
		`<Delete>` + "\x00" + `</Delete>`,
	} {
		for op := range uint8(4) {
			f.Add(op, s)
		}
	}
	e := newEnv(f)
	if r := e.do(f, req{Method: http.MethodPut, Path: "/fuzz"}); r.Status != http.StatusOK {
		f.Fatalf("create bucket = %d %s", r.Status, r.Body)
	}
	upload := e.initiateTB(f, "/fuzz/big")
	f.Fuzz(func(t *testing.T, op uint8, body string) {
		var q req
		switch op % 4 {
		case 0:
			q = req{Method: http.MethodPut, Path: "/fuzz-new", Body: body}
		case 1:
			q = req{Method: http.MethodPost, Path: "/fuzz?delete", Body: body}
		case 2:
			q = req{Method: http.MethodPost, Path: "/fuzz/big?uploadId=" + upload, Body: body}
		case 3:
			q = req{Method: http.MethodPut, Path: "/fuzz?encryption", Body: body}
		}
		if r := e.do(t, q); r.Status >= 500 {
			t.Fatalf("%s %s with %q = %d %s", q.Method, q.Path, body, r.Status, r.Body)
		}
		// Undo a successful creation, so the next run creates again.
		e.do(t, req{Method: http.MethodDelete, Path: "/fuzz-new"})
	})
}

// initiateTB starts a multipart upload and returns its ID.
func (e *env) initiateTB(t testing.TB, path string) string {
	t.Helper()
	r := e.do(t, req{Method: http.MethodPost, Path: path + "?uploads"})
	id := between(r.Body, "<UploadId>", "</UploadId>")
	if r.Status != http.StatusOK || id == "" {
		t.Fatalf("initiate = %d %s", r.Status, r.Body)
	}
	return id
}
