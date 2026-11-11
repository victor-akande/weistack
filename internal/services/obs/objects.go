package obs

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/store"
)

// Object is the stored record of an object. Its body is a blob.
type Object struct {
	Key  string `json:"key"`
	Blob string `json:"blob"`
	Size int64  `json:"size"`
	// ETag is the hex MD5 of the body, without the quotes it is sent in.
	ETag        string `json:"etag"`
	ContentType string `json:"content_type"`
	// Headers are the standard headers stored with the object and
	// returned on download (Cache-Control, Content-Disposition, ...).
	Headers map[string]string `json:"headers,omitempty"`
	// Meta is the user metadata, keyed by the lowercase name that
	// follows "x-obs-meta-" or "x-amz-meta-".
	Meta     map[string]string `json:"meta,omitempty"`
	Modified time.Time         `json:"modified"`
}

const (
	maxKeyBytes        = 1024
	defaultContentType = "binary/octet-stream"
	storageClass       = "STANDARD"
)

// storedHeaders are the request headers kept with an object.
var storedHeaders = []string{"Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Expires"}

// objects returns the collection of one bucket's objects. Each bucket
// has its own, so listing a bucket never reads another's.
func (s *Service) objects(bucket string) store.Collection[Object] {
	return store.Of[Object](s.store, store.Scope{Region: globalRegion, ProjectID: store.Global, Kind: "obs.object." + bucket})
}

// getObject returns an object of a bucket the caller owns.
func (s *Service) getObject(ctx context.Context, owner, bucket, key string) (Object, error) {
	if _, err := s.bucketFor(ctx, owner, bucket); err != nil {
		return Object{}, err
	}
	obj, err := s.objects(bucket).Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return Object{}, errNoSuchKey
	}
	return obj, err
}

// putObject installs obj as the bucket's object, replacing and
// discarding any previous body under the same key.
func (s *Service) putObject(ctx context.Context, bucket string, obj Object) error {
	objects := s.objects(bucket)
	old, err := objects.Get(ctx, obj.Key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := objects.Put(ctx, obj.Key, obj); err != nil {
		return err
	}
	if old.Blob != "" && old.Blob != obj.Blob {
		if err := s.blobs.remove(old.Blob); err != nil {
			s.log.WarnContext(ctx, "removing a replaced object body failed", "error", err)
		}
	}
	return nil
}

// deleteObject removes an object and its body. Deleting a key that does
// not exist succeeds, as in S3.
func (s *Service) deleteObject(ctx context.Context, bucket, key string) error {
	objects := s.objects(bucket)
	obj, err := objects.Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := objects.Delete(ctx, key); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return s.blobs.remove(obj.Blob)
}

// userMeta collects user metadata from request headers of either dialect.
func userMeta(h http.Header) map[string]string {
	var meta map[string]string
	for name, values := range h {
		lower := strings.ToLower(name)
		for _, prefix := range []string{"x-obs-meta-", "x-amz-meta-"} {
			if key, ok := strings.CutPrefix(lower, prefix); ok && key != "" {
				if meta == nil {
					meta = make(map[string]string)
				}
				meta[key] = strings.Join(values, ",")
			}
		}
	}
	return meta
}

// describe fills an object's content type, stored headers and user
// metadata from request headers.
func describe(obj *Object, h http.Header) {
	obj.ContentType = h.Get("Content-Type")
	obj.Headers = nil
	for _, name := range storedHeaders {
		v := h.Get(name)
		if name == "Content-Encoding" {
			v = stripAWSChunked(v) // transport framing, not a property of the object
		}
		if v != "" {
			if obj.Headers == nil {
				obj.Headers = make(map[string]string)
			}
			obj.Headers[name] = v
		}
	}
	obj.Meta = userMeta(h)
}

func stripAWSChunked(encoding string) string {
	var kept []string
	for _, part := range strings.Split(encoding, ",") {
		if part = strings.TrimSpace(part); part != "" && part != "aws-chunked" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, ",")
}

func quote(etag string) string { return `"` + etag + `"` }

func (s *Service) handlePutObject(c *call) error {
	if src := c.vendorHeader("copy-source"); src != "" {
		return s.handleCopyObject(c, src)
	}
	ctx := c.r.Context()
	if _, err := s.bucketFor(ctx, c.owner, c.target.Bucket); err != nil {
		return err
	}
	if len(c.target.Key) > maxKeyBytes {
		return errKeyTooLong
	}

	// Validate what can be validated before reading the body.
	var wantMD5 string
	if raw := c.r.Header.Get("Content-MD5"); raw != "" {
		sum, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(sum) != 16 {
			return errInvalidDigest
		}
		wantMD5 = hex.EncodeToString(sum)
	}

	var body io.Reader = c.r.Body
	wantSize := int64(-1)
	if isAWSChunked(c.r) {
		body = newAWSChunkedReader(c.r.Body)
		if raw := c.r.Header.Get("x-amz-decoded-content-length"); raw != "" {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || n < 0 {
				return errInvalidArgument("x-amz-decoded-content-length is not a valid length")
			}
			wantSize = n
		}
	}

	obj := Object{Key: c.target.Key, Blob: s.ids.UUID(), Modified: s.now().UTC()}
	size, sum, err := s.blobs.put(obj.Blob, body)
	if err != nil {
		if errors.Is(err, errBadChunk) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errIncompleteBody
		}
		return err
	}
	discard := func(e error) error {
		if rmErr := s.blobs.remove(obj.Blob); rmErr != nil {
			s.log.WarnContext(ctx, "removing a rejected upload failed", "error", rmErr)
		}
		return e
	}
	if wantSize >= 0 && size != wantSize {
		return discard(errIncompleteBody)
	}
	if wantMD5 != "" && wantMD5 != sum {
		return discard(errBadDigest)
	}
	obj.Size, obj.ETag = size, sum
	describe(&obj, c.r.Header)
	if err := s.putObject(ctx, c.target.Bucket, obj); err != nil {
		return discard(err)
	}
	c.w.Header().Set("ETag", quote(obj.ETag))
	c.w.WriteHeader(http.StatusOK)
	return nil
}

type copyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	XMLNS        string   `xml:"xmlns,attr"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// parseCopySource reads a copy-source header: "/bucket/key" or
// "bucket/key", URL-encoded, optionally with a version.
func parseCopySource(raw string) (bucket, key string, err error) {
	path, query, _ := strings.Cut(raw, "?")
	if v, _ := url.ParseQuery(query); v.Get("versionId") != "" && v.Get("versionId") != "null" {
		return "", "", errNotImplemented("copying a specific object version")
	}
	path, uerr := url.PathUnescape(strings.TrimPrefix(path, "/"))
	if uerr != nil {
		return "", "", errInvalidArgument("the copy source is not a valid URL-encoded path")
	}
	bucket, key, ok := strings.Cut(path, "/")
	if !ok || bucket == "" || key == "" {
		return "", "", errInvalidArgument("the copy source must have the form /bucket/key")
	}
	return bucket, key, nil
}

func (s *Service) handleCopyObject(c *call, source string) error {
	ctx := c.r.Context()
	srcBucket, srcKey, err := parseCopySource(source)
	if err != nil {
		return err
	}
	if _, err := s.bucketFor(ctx, c.owner, c.target.Bucket); err != nil {
		return err
	}
	if len(c.target.Key) > maxKeyBytes {
		return errKeyTooLong
	}
	src, err := s.getObject(ctx, c.owner, srcBucket, srcKey)
	if err != nil {
		return err
	}

	directive := strings.ToUpper(c.vendorHeader("metadata-directive"))
	switch directive {
	case "", "COPY", "REPLACE":
	default:
		return errInvalidArgument("the metadata directive must be COPY or REPLACE")
	}
	if srcBucket == c.target.Bucket && srcKey == c.target.Key && directive != "REPLACE" {
		return errInvalidRequest("This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata.")
	}

	dst := src
	dst.Key, dst.Blob, dst.Modified = c.target.Key, s.ids.UUID(), s.now().UTC()
	if directive == "REPLACE" {
		describe(&dst, c.r.Header)
	}
	if err := s.blobs.link(src.Blob, dst.Blob); err != nil {
		return err
	}
	if err := s.putObject(ctx, c.target.Bucket, dst); err != nil {
		_ = s.blobs.remove(dst.Blob)
		return err
	}
	return c.writeXML(copyObjectResult{
		XMLNS: c.dialect.namespace(), LastModified: dst.Modified.Format(timeLayout), ETag: quote(dst.ETag),
	})
}

// byteRange is the part of an object a download asks for.
type byteRange struct {
	start, length int64
	partial       bool
}

// parseRange interprets a Range header for an object of the given size.
// As in S3, only a single range is honoured: a header that is malformed
// or names several ranges is ignored and the whole object is served. A
// well-formed range that cannot be satisfied is an error.
func parseRange(header string, size int64) (byteRange, error) {
	whole := byteRange{length: size}
	spec, ok := strings.CutPrefix(header, "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return whole, nil
	}
	first, last, ok := strings.Cut(strings.TrimSpace(spec), "-")
	if !ok {
		return whole, nil
	}

	if first == "" { // suffix: the last N bytes
		n, ok := nonNegative(last)
		switch {
		case !ok:
			return whole, nil
		case n == 0 || size == 0:
			return byteRange{}, errInvalidRange
		}
		n = min(n, size)
		return byteRange{start: size - n, length: n, partial: true}, nil
	}

	start, ok := nonNegative(first)
	if !ok {
		return whole, nil
	}
	end := size - 1
	if last != "" {
		e, ok := nonNegative(last)
		if !ok || e < start {
			return whole, nil
		}
		end = min(e, size-1)
	}
	if start >= size {
		return byteRange{}, errInvalidRange
	}
	return byteRange{start: start, length: end - start + 1, partial: true}, nil
}

// nonNegative parses a decimal integer that must not be negative.
func nonNegative(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n >= 0
}

// precondition evaluates the conditional request headers. It returns
// the status to answer with (304 or 412), or 0 to proceed.
func precondition(h http.Header, obj Object) int {
	etagMatches := func(list string) bool {
		for _, candidate := range strings.Split(list, ",") {
			candidate = strings.Trim(strings.TrimSpace(candidate), `"`)
			if candidate == "*" || candidate == obj.ETag {
				return true
			}
		}
		return false
	}
	modified := obj.Modified.Truncate(time.Second)

	if v := h.Get("If-Match"); v != "" && !etagMatches(v) {
		return http.StatusPreconditionFailed
	}
	if t, err := http.ParseTime(h.Get("If-Unmodified-Since")); err == nil && modified.After(t) {
		return http.StatusPreconditionFailed
	}
	if v := h.Get("If-None-Match"); v != "" {
		if etagMatches(v) {
			return http.StatusNotModified
		}
	} else if t, err := http.ParseTime(h.Get("If-Modified-Since")); err == nil && !modified.After(t) {
		return http.StatusNotModified
	}
	return 0
}

// responseOverrides are query parameters that replace a response header
// of a download, used by pre-signed links.
var responseOverrides = map[string]string{
	"response-content-type":        "Content-Type",
	"response-content-language":    "Content-Language",
	"response-expires":             "Expires",
	"response-cache-control":       "Cache-Control",
	"response-content-disposition": "Content-Disposition",
	"response-content-encoding":    "Content-Encoding",
}

// writeObjectHeaders sets the headers that describe an object.
func (c *call) writeObjectHeaders(obj Object) {
	h := c.w.Header()
	h.Set("ETag", quote(obj.ETag))
	h.Set("Last-Modified", obj.Modified.UTC().Format(http.TimeFormat))
	h.Set("Accept-Ranges", "bytes")
	contentType := obj.ContentType
	if contentType == "" {
		contentType = defaultContentType
	}
	h.Set("Content-Type", contentType)
	for name, v := range obj.Headers {
		h.Set(name, v)
	}
	for key, v := range obj.Meta {
		h.Set(c.dialect.prefix()+"meta-"+key, v)
	}
	if c.dialect == dialectOBS {
		h.Set("x-obs-storage-class", storageClass)
	}
	q := c.r.URL.Query()
	for param, name := range responseOverrides {
		if v := q.Get(param); v != "" {
			h.Set(name, v)
		}
	}
}

// handleGetObject serves GET and HEAD of an object.
func (s *Service) handleGetObject(c *call) error {
	obj, err := s.getObject(c.r.Context(), c.owner, c.target.Bucket, c.target.Key)
	if err != nil {
		return err
	}
	if status := precondition(c.r.Header, obj); status == http.StatusPreconditionFailed {
		return errPreconditionFailed
	} else if status == http.StatusNotModified {
		c.w.Header().Set("ETag", quote(obj.ETag))
		c.w.Header().Set("Last-Modified", obj.Modified.UTC().Format(http.TimeFormat))
		c.w.WriteHeader(http.StatusNotModified)
		return nil
	}
	rng, err := parseRange(c.r.Header.Get("Range"), obj.Size)
	if err != nil {
		return err
	}

	// Open before writing any header, so a missing body is still a clean
	// error response.
	var body *io.SectionReader
	if c.r.Method != http.MethodHead {
		f, err := s.blobs.open(obj.Blob)
		if err != nil {
			return err
		}
		defer f.Close()
		body = io.NewSectionReader(f, rng.start, rng.length)
	}

	c.writeObjectHeaders(obj)
	h := c.w.Header()
	h.Set("Content-Length", strconv.FormatInt(rng.length, 10))
	status := http.StatusOK
	if rng.partial {
		status = http.StatusPartialContent
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rng.start, rng.start+rng.length-1, obj.Size))
	}
	c.w.WriteHeader(status)
	if body != nil {
		// The response has started; a failure now can only be logged.
		if _, err := io.Copy(c.w, body); err != nil {
			s.log.DebugContext(c.r.Context(), "download interrupted", "key", obj.Key, "error", err)
		}
	}
	return nil
}

func (s *Service) handleDeleteObject(c *call) error {
	ctx := c.r.Context()
	if _, err := s.bucketFor(ctx, c.owner, c.target.Bucket); err != nil {
		return err
	}
	if err := s.deleteObject(ctx, c.target.Bucket, c.target.Key); err != nil {
		return err
	}
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

// maxBatchDelete is the most keys one batch delete may name.
const maxBatchDelete = 1000

type deleteRequest struct {
	Quiet   bool `xml:"Quiet"`
	Objects []struct {
		Key string `xml:"Key"`
	} `xml:"Object"`
}

type deletedKey struct {
	Key string `xml:"Key"`
}

type deleteError struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

type deleteResult struct {
	XMLName xml.Name      `xml:"DeleteResult"`
	XMLNS   string        `xml:"xmlns,attr"`
	Deleted []deletedKey  `xml:"Deleted"`
	Errors  []deleteError `xml:"Error"`
}

func (s *Service) handleDeleteObjects(c *call) error {
	ctx := c.r.Context()
	if _, err := s.bucketFor(ctx, c.owner, c.target.Bucket); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(c.r.Body, maxConfigBody))
	if err != nil {
		return err
	}
	var req deleteRequest
	if err := xml.Unmarshal(raw, &req); err != nil || len(req.Objects) == 0 || len(req.Objects) > maxBatchDelete {
		return errMalformedXML
	}

	res := deleteResult{XMLNS: c.dialect.namespace()}
	for _, o := range req.Objects {
		if err := s.deleteObject(ctx, c.target.Bucket, o.Key); err != nil {
			s.log.ErrorContext(ctx, "batch delete of one object failed", "key", o.Key, "error", err)
			res.Errors = append(res.Errors, deleteError{Key: o.Key, Code: "InternalError", Message: "We encountered an internal error. Please try again."})
			continue
		}
		// In quiet mode only failures are reported.
		if !req.Quiet {
			res.Deleted = append(res.Deleted, deletedKey{Key: o.Key})
		}
	}
	return c.writeXML(res)
}
