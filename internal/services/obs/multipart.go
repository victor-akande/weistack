package obs

import (
	"context"
	"crypto/md5" //nolint:gosec // multipart ETags are MD5-based by protocol
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/store"
)

// Upload is the stored record of a multipart upload in progress. Part
// bodies are blobs; they become one object when the upload completes.
type Upload struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Initiated time.Time `json:"initiated"`
	// The object's description, given when the upload was initiated.
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	Parts       map[int]Part      `json:"parts"`
	// Completing is set while the parts are being assembled; no part can
	// be added or the upload aborted meanwhile.
	Completing bool `json:"completing,omitempty"`
}

// Part is one uploaded part.
type Part struct {
	Blob     string    `json:"blob"`
	Size     int64     `json:"size"`
	ETag     string    `json:"etag"`
	Modified time.Time `json:"modified"`
}

const (
	minPartNumber = 1
	maxPartNumber = 10000
	// minPartSize applies to every part but the last, checked when the
	// upload completes. It is that of OBS 3.0 buckets; S3 requires 5 MiB.
	minPartSize = 100 << 10
	// maxListParts bounds ListParts and ListMultipartUploads pages.
	maxListParts = 1000
)

// uploads returns the multipart uploads of one bucket.
func (s *Service) uploads(bucket string) store.Collection[Upload] {
	return store.Of[Upload](s.store, store.Scope{Region: globalRegion, ProjectID: store.Global, Kind: "obs.upload." + bucket})
}

// getUpload returns an upload of the caller's bucket for the target key.
// An upload of another key is reported as missing, as in S3.
func (s *Service) getUpload(c *call, id string) (Upload, error) {
	if _, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket); err != nil {
		return Upload{}, err
	}
	u, err := s.uploads(c.target.Bucket).Get(c.r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.Key != c.target.Key) {
		return Upload{}, errNoSuchUpload
	}
	return u, err
}

type initiateResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

func (s *Service) handleInitiateUpload(c *call) error {
	ctx := c.r.Context()
	if _, err := s.bucketFor(ctx, c.owner, c.target.Bucket); err != nil {
		return err
	}
	if len(c.target.Key) > maxKeyBytes {
		return errKeyTooLong
	}
	// The object's description travels on the initiating request.
	var desc Object
	describe(&desc, c.r.Header)
	u := Upload{
		ID:          strings.ToUpper(s.ids.Hex32()),
		Key:         c.target.Key,
		Initiated:   s.now().UTC(),
		ContentType: desc.ContentType,
		Headers:     desc.Headers,
		Meta:        desc.Meta,
		Parts:       map[int]Part{},
	}
	if err := s.uploads(c.target.Bucket).Create(ctx, u.ID, u); err != nil {
		return err
	}
	return c.writeXML(initiateResult{XMLNS: c.dialect.namespace(), Bucket: c.target.Bucket, Key: u.Key, UploadID: u.ID})
}

func (s *Service) handleUploadPart(c *call) error {
	ctx := c.r.Context()
	q := c.r.URL.Query()
	number, err := strconv.Atoi(q.Get("partNumber"))
	if err != nil || number < minPartNumber || number > maxPartNumber {
		return errInvalidArgument(fmt.Sprintf("Part number must be an integer between %d and %d, inclusive", minPartNumber, maxPartNumber))
	}
	id := q.Get("uploadId")
	// Fail fast before reading the body; the record is checked again
	// when the part is recorded.
	if u, err := s.getUpload(c, id); err != nil {
		return err
	} else if u.Completing {
		return errNoSuchUpload
	}

	blob, size, sum, err := s.receive(c)
	if err != nil {
		return err
	}
	part := Part{Blob: blob, Size: size, ETag: sum, Modified: s.now().UTC()}

	s.uploadMu.Lock()
	var replaced string
	_, err = s.uploads(c.target.Bucket).Update(ctx, id, func(u *Upload) error {
		if u.Completing || u.Key != c.target.Key {
			return errNoSuchUpload
		}
		replaced = u.Parts[number].Blob
		u.Parts[number] = part
		return nil
	})
	s.uploadMu.Unlock()

	if errors.Is(err, store.ErrNotFound) {
		err = errNoSuchUpload // aborted or completed while the part was arriving
	}
	if err != nil {
		s.discard(ctx, blob)
		return err
	}
	if replaced != "" {
		s.discard(ctx, replaced) // the same part number uploaded again
	}
	c.w.Header().Set("ETag", quote(part.ETag))
	c.w.WriteHeader(http.StatusOK)
	return nil
}

type completeRequest struct {
	Parts []struct {
		PartNumber int    `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	} `xml:"Part"`
}

type completeResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// selectParts validates a completion request against an upload and
// returns the chosen parts in order.
func selectParts(req completeRequest, u Upload) ([]Part, error) {
	if len(req.Parts) == 0 {
		return nil, errMalformedXML
	}
	chosen := make([]Part, 0, len(req.Parts))
	for i, p := range req.Parts {
		if i > 0 && p.PartNumber <= req.Parts[i-1].PartNumber {
			return nil, errInvalidPartOrder
		}
		part, ok := u.Parts[p.PartNumber]
		if !ok || strings.Trim(strings.TrimSpace(p.ETag), `"`) != part.ETag {
			return nil, errInvalidPart
		}
		chosen = append(chosen, part)
	}
	for _, part := range chosen[:len(chosen)-1] {
		if part.Size < minPartSize {
			return nil, errEntityTooSmall
		}
	}
	return chosen, nil
}

// multipartETag is the ETag of an assembled object: the MD5 of the
// parts' binary MD5s, followed by the number of parts.
func multipartETag(parts []Part) string {
	h := md5.New() //nolint:gosec // see import
	for _, p := range parts {
		sum, _ := hex.DecodeString(p.ETag)
		h.Write(sum)
	}
	return hex.EncodeToString(h.Sum(nil)) + "-" + strconv.Itoa(len(parts))
}

func (s *Service) handleCompleteUpload(c *call) error {
	ctx := c.r.Context()
	id := c.r.URL.Query().Get("uploadId")

	raw, err := io.ReadAll(io.LimitReader(c.r.Body, maxConfigBody))
	if err != nil {
		return err
	}
	var req completeRequest
	if err := xml.Unmarshal(raw, &req); err != nil {
		return errMalformedXML
	}
	if _, err := s.bucketFor(ctx, c.owner, c.target.Bucket); err != nil {
		return err
	}

	// Claim the upload: from here no part can be added and no one else
	// can complete or abort it.
	var (
		u      Upload
		chosen []Part
	)
	s.uploadMu.Lock()
	u, err = s.uploads(c.target.Bucket).Update(ctx, id, func(rec *Upload) error {
		if rec.Completing || rec.Key != c.target.Key {
			return errNoSuchUpload
		}
		var verr error
		if chosen, verr = selectParts(req, *rec); verr != nil {
			return verr
		}
		rec.Completing = true
		return nil
	})
	s.uploadMu.Unlock()
	if errors.Is(err, store.ErrNotFound) {
		return errNoSuchUpload
	}
	if err != nil {
		return err
	}
	release := func() {
		s.uploadMu.Lock()
		defer s.uploadMu.Unlock()
		if _, err := s.uploads(c.target.Bucket).Update(ctx, id, func(rec *Upload) error {
			rec.Completing = false
			return nil
		}); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.ErrorContext(ctx, "releasing a multipart upload failed", "upload_id", id, "error", err)
		}
	}

	// Assemble the chosen parts into one new blob, streaming.
	blobs := make([]string, len(chosen))
	for i, p := range chosen {
		blobs[i] = p.Blob
	}
	parts := &partsReader{store: s.blobs, blobs: blobs}
	blob := s.ids.UUID()
	size, _, err := s.blobs.put(blob, parts)
	_ = parts.Close()
	if err != nil {
		release()
		return err
	}

	obj := Object{
		Key: u.Key, Blob: blob, Size: size, ETag: multipartETag(chosen), Modified: s.now().UTC(),
		ContentType: u.ContentType, Headers: u.Headers, Meta: u.Meta,
	}
	if err := s.putObject(ctx, c.target.Bucket, obj); err != nil {
		s.discard(ctx, blob)
		release()
		return err
	}

	// The upload is done: remove its record and every part body, chosen
	// or not.
	s.uploadMu.Lock()
	err = s.uploads(c.target.Bucket).Delete(ctx, id)
	s.uploadMu.Unlock()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "removing a completed upload failed", "upload_id", id, "error", err)
	}
	for _, p := range u.Parts {
		s.discard(ctx, p.Blob)
	}

	location := fmt.Sprintf("%s://%s/%s/%s", scheme(c.r), c.r.Host, c.target.Bucket, c.target.Key)
	return c.writeXML(completeResult{
		XMLNS: c.dialect.namespace(), Location: location, Bucket: c.target.Bucket, Key: obj.Key, ETag: quote(obj.ETag),
	})
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// partsReader reads a sequence of blobs as one stream, opening one file
// at a time so that an object of 10,000 parts does not need 10,000 open
// files.
type partsReader struct {
	store *blobStore
	blobs []string
	cur   *os.File
}

func (p *partsReader) Read(buf []byte) (int, error) {
	for {
		if p.cur == nil {
			if len(p.blobs) == 0 {
				return 0, io.EOF
			}
			f, err := p.store.open(p.blobs[0])
			if err != nil {
				return 0, err
			}
			p.cur, p.blobs = f, p.blobs[1:]
		}
		n, err := p.cur.Read(buf)
		if errors.Is(err, io.EOF) {
			_ = p.cur.Close()
			p.cur = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (p *partsReader) Close() error {
	if p.cur != nil {
		return p.cur.Close()
	}
	return nil
}

func (s *Service) handleAbortUpload(c *call) error {
	ctx := c.r.Context()
	id := c.r.URL.Query().Get("uploadId")
	if _, err := s.getUpload(c, id); err != nil {
		return err
	}

	s.uploadMu.Lock()
	u, err := s.uploads(c.target.Bucket).Get(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound) || (err == nil && u.Completing):
		err = errNoSuchUpload
	case err == nil:
		err = s.uploads(c.target.Bucket).Delete(ctx, id)
	}
	s.uploadMu.Unlock()
	if err != nil {
		return err
	}
	for _, p := range u.Parts {
		s.discard(ctx, p.Blob)
	}
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

type xmlPart struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

type listPartsResult struct {
	XMLName              xml.Name  `xml:"ListPartsResult"`
	XMLNS                string    `xml:"xmlns,attr"`
	Bucket               string    `xml:"Bucket"`
	Key                  string    `xml:"Key"`
	UploadID             string    `xml:"UploadId"`
	Initiator            xmlOwner  `xml:"Initiator"`
	Owner                xmlOwner  `xml:"Owner"`
	StorageClass         string    `xml:"StorageClass"`
	PartNumberMarker     int       `xml:"PartNumberMarker"`
	NextPartNumberMarker int       `xml:"NextPartNumberMarker"`
	MaxParts             int       `xml:"MaxParts"`
	IsTruncated          bool      `xml:"IsTruncated"`
	Parts                []xmlPart `xml:"Part"`
}

// pageLimit reads a page-size parameter: maxListParts when absent, at
// most maxListParts.
func pageLimit(raw, name string) (int, error) {
	if raw == "" {
		return maxListParts, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, errInvalidArgument(name + " must be a non-negative integer")
	}
	return min(n, maxListParts), nil
}

func (s *Service) handleListParts(c *call) error {
	q := c.r.URL.Query()
	u, err := s.getUpload(c, q.Get("uploadId"))
	if err != nil {
		return err
	}
	limit, err := pageLimit(q.Get("max-parts"), "max-parts")
	if err != nil {
		return err
	}
	marker := 0
	if raw := q.Get("part-number-marker"); raw != "" {
		if marker, err = strconv.Atoi(raw); err != nil || marker < 0 {
			return errInvalidArgument("part-number-marker must be a non-negative integer")
		}
	}

	numbers := make([]int, 0, len(u.Parts))
	for n := range u.Parts {
		if n > marker {
			numbers = append(numbers, n)
		}
	}
	sort.Ints(numbers)

	owner := xmlOwner{ID: ownerID(c.owner)}
	res := listPartsResult{
		XMLNS: c.dialect.namespace(), Bucket: c.target.Bucket, Key: u.Key, UploadID: u.ID,
		Initiator: owner, Owner: owner, StorageClass: storageClass,
		PartNumberMarker: marker, MaxParts: limit,
	}
	if len(numbers) > limit {
		numbers, res.IsTruncated = numbers[:limit], true
	}
	for _, n := range numbers {
		p := u.Parts[n]
		res.Parts = append(res.Parts, xmlPart{PartNumber: n, LastModified: p.Modified.Format(timeLayout), ETag: quote(p.ETag), Size: p.Size})
		res.NextPartNumberMarker = n
	}
	return c.writeXML(res)
}

type xmlUpload struct {
	Key          string   `xml:"Key"`
	UploadID     string   `xml:"UploadId"`
	Initiator    xmlOwner `xml:"Initiator"`
	Owner        xmlOwner `xml:"Owner"`
	StorageClass string   `xml:"StorageClass"`
	Initiated    string   `xml:"Initiated"`
}

type listUploadsResult struct {
	XMLName            xml.Name    `xml:"ListMultipartUploadsResult"`
	XMLNS              string      `xml:"xmlns,attr"`
	Bucket             string      `xml:"Bucket"`
	KeyMarker          string      `xml:"KeyMarker"`
	UploadIDMarker     string      `xml:"UploadIdMarker"`
	NextKeyMarker      string      `xml:"NextKeyMarker,omitempty"`
	NextUploadIDMarker string      `xml:"NextUploadIdMarker,omitempty"`
	Prefix             string      `xml:"Prefix"`
	MaxUploads         int         `xml:"MaxUploads"`
	IsTruncated        bool        `xml:"IsTruncated"`
	Uploads            []xmlUpload `xml:"Upload"`
}

// uploadsAfter reports whether an upload sorts after the markers: by
// key, then by upload ID within a key.
func uploadsAfter(u Upload, keyMarker, idMarker string) bool {
	if keyMarker == "" {
		return true
	}
	if u.Key != keyMarker {
		return u.Key > keyMarker
	}
	return idMarker != "" && u.ID > idMarker
}

func (s *Service) handleListUploads(c *call) error {
	ctx := c.r.Context()
	if _, err := s.bucketFor(ctx, c.owner, c.target.Bucket); err != nil {
		return err
	}
	q := c.r.URL.Query()
	if q.Get("delimiter") != "" {
		return errNotImplemented("ListMultipartUploads with a delimiter")
	}
	limit, err := pageLimit(q.Get("max-uploads"), "max-uploads")
	if err != nil {
		return err
	}
	prefix, keyMarker, idMarker := q.Get("prefix"), q.Get("key-marker"), q.Get("upload-id-marker")

	all, err := s.uploads(c.target.Bucket).List(ctx, func(u Upload) bool {
		return strings.HasPrefix(u.Key, prefix) && uploadsAfter(u, keyMarker, idMarker)
	})
	if err != nil {
		return err
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Key != all[j].Key {
			return all[i].Key < all[j].Key
		}
		return all[i].ID < all[j].ID
	})

	owner := xmlOwner{ID: ownerID(c.owner)}
	res := listUploadsResult{
		XMLNS: c.dialect.namespace(), Bucket: c.target.Bucket,
		KeyMarker: keyMarker, UploadIDMarker: idMarker, Prefix: prefix, MaxUploads: limit,
	}
	if len(all) > limit {
		all, res.IsTruncated = all[:limit], true
	}
	for _, u := range all {
		res.Uploads = append(res.Uploads, xmlUpload{
			Key: u.Key, UploadID: u.ID, Initiator: owner, Owner: owner,
			StorageClass: storageClass, Initiated: u.Initiated.Format(timeLayout),
		})
	}
	if res.IsTruncated && len(all) > 0 {
		last := all[len(all)-1]
		res.NextKeyMarker, res.NextUploadIDMarker = last.Key, last.ID
	}
	return c.writeXML(res)
}

// hasUploads reports whether a bucket has multipart uploads in progress.
func (s *Service) hasUploads(ctx context.Context, bucket string) (bool, error) {
	found, err := s.uploads(bucket).List(ctx, nil)
	return len(found) > 0, err
}
