package obs

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Routes implements server.Service. OBS does not have fixed paths: the
// bucket and key are in the host name or the path, and the operation is
// chosen by method and query string, so one handler takes everything.
func (s *Service) Routes(r chi.Router) {
	r.Handle("/*", http.HandlerFunc(s.serve))
}

// call is one request being served.
type call struct {
	w       http.ResponseWriter
	r       *http.Request
	dialect dialect
	owner   string
	region  string
	target  target
}

// maxConfigBody bounds the small XML bodies of bucket operations.
const maxConfigBody = 1 << 20

func (s *Service) serve(w http.ResponseWriter, r *http.Request) {
	info := reqctx.From(r.Context())
	c := &call{w: w, r: r, dialect: dialectOf(r), owner: caller(r), region: info.Region}

	// Every response, success or error, identifies the request.
	h := w.Header()
	h.Set("Server", "OBS")
	h.Set(c.dialect.prefix()+"request-id", info.RequestID)
	h.Set(c.dialect.prefix()+"id-2", info.RequestID)

	var err error
	if c.target, err = resolve(r); err != nil {
		s.fail(c, "Resolve", errInvalidURI)
		return
	}
	op, fn := s.route(c)
	info.SetOperation(op)
	if err := fn(c); err != nil {
		s.fail(c, op, err)
	}
}

// fail renders an error. A HEAD response has no body, so the code and
// message are also sent as headers, where the SDKs look for them.
func (s *Service) fail(c *call, op string, err error) {
	var e *apierr.Error
	if !errors.As(err, &e) {
		s.log.ErrorContext(c.r.Context(), "obs operation failed", "operation", op, "error", err)
		// Internal failures use the S3 code clients expect.
		e = apierr.New(http.StatusInternalServerError, "InternalError",
			"We encountered an internal error. Please try again.")
	}
	c.w.Header().Set(c.dialect.prefix()+"error-code", e.Code)
	c.w.Header().Set(c.dialect.prefix()+"error-message", e.Message)
	apierr.Write(c.w, c.r, apierr.StyleXML, e)
}

// subresource returns the first of names present in the query string.
func (c *call) subresource(names ...string) string {
	q := c.r.URL.Query()
	for _, name := range names {
		if _, ok := q[name]; ok {
			return name
		}
	}
	return ""
}

// bucketSubresources are bucket-level features addressed by a query
// parameter. Of these the emulator answers only reads of configuration
// it never stores (config.go).
var bucketSubresources = []string{
	"acl", "policy", "versioning", "versions", "lifecycle", "cors", "tagging", "website", "logging",
	"notification", "encryption", "replication", "quota", "storageinfo", "storagePolicy", "storageClass",
	"metadata", "inventory", "customdomain", "requestPayment", "object-lock", "directcoldaccess",
	"append", "restore",
}

type handlerFunc func(*call) error

// route picks the operation for a request and names it for logs.
func (s *Service) route(c *call) (string, handlerFunc) {
	notAllowed := func(*call) error { return errMethodNotAllowed }
	m := c.r.Method

	switch {
	case c.target.Bucket == "":
		if m == http.MethodGet {
			return "ListBuckets", s.handleListBuckets
		}
		return "Service", notAllowed

	case c.target.Key == "":
		if sub := c.subresource(bucketSubresources...); sub != "" {
			if read, ok := s.configs[sub]; ok && m == http.MethodGet {
				return "GetBucket?" + sub, read
			}
			return "Bucket?" + sub, func(*call) error { return errNotImplemented("bucket " + sub) }
		}
		switch m {
		case http.MethodPut:
			return "CreateBucket", s.handleCreateBucket
		case http.MethodHead:
			return "HeadBucket", s.handleHeadBucket
		case http.MethodDelete:
			return "DeleteBucket", s.handleDeleteBucket
		case http.MethodGet:
			if c.subresource("location") != "" {
				return "GetBucketLocation", s.handleGetBucketLocation
			}
			if c.subresource("uploads") != "" {
				return "ListMultipartUploads", s.handleListUploads
			}
			if c.r.URL.Query().Get("list-type") == "2" {
				return "ListObjectsV2", s.handleListObjects
			}
			return "ListObjects", s.handleListObjects
		case http.MethodPost:
			if c.subresource("delete") != "" {
				return "DeleteObjects", s.handleDeleteObjects
			}
			return "PostObject", func(*call) error { return errNotImplemented("browser-based POST uploads") }
		}
		return "Bucket", notAllowed
	}

	// An object. Multipart uploads first: they are addressed by ?uploads
	// and ?uploadId.
	q := c.r.URL.Query()
	if _, initiate := q["uploads"]; initiate && m == http.MethodPost {
		return "InitiateMultipartUpload", s.handleInitiateUpload
	}
	if q.Get("uploadId") != "" {
		switch m {
		case http.MethodPut:
			if c.vendorHeader("copy-source") != "" {
				return "CopyPart", func(*call) error { return errNotImplemented("copying a part (UploadPartCopy)") }
			}
			return "UploadPart", s.handleUploadPart
		case http.MethodPost:
			return "CompleteMultipartUpload", s.handleCompleteUpload
		case http.MethodDelete:
			return "AbortMultipartUpload", s.handleAbortUpload
		case http.MethodGet:
			return "ListParts", s.handleListParts
		}
		return "Upload", notAllowed
	}
	if sub := c.subresource(objectSubresources...); sub != "" {
		return "Object?" + sub, func(*call) error { return errNotImplemented("object " + sub) }
	}
	if v := c.r.URL.Query().Get("versionId"); v != "" && v != "null" {
		return "Object?versionId", func(*call) error { return errNotImplemented("object versions") }
	}
	switch m {
	case http.MethodPut:
		if c.vendorHeader("copy-source") != "" {
			return "CopyObject", s.handlePutObject
		}
		return "PutObject", s.handlePutObject
	case http.MethodGet:
		return "GetObject", s.handleGetObject
	case http.MethodHead:
		return "HeadObject", s.handleGetObject
	case http.MethodDelete:
		return "DeleteObject", s.handleDeleteObject
	}
	return "Object", notAllowed
}

// objectSubresources are object-level features addressed by a query
// parameter that the emulator does not implement.
var objectSubresources = []string{
	"acl", "tagging", "restore", "append", "modify", "truncate", "rename", "metadata", "select", "torrent",
	"retention", "legal-hold", "partNumber",
}

// vendorHeader returns a vendor header of the request in whichever
// dialect it was sent: clients are not always consistent.
func (c *call) vendorHeader(name string) string {
	if v := c.r.Header.Get("x-obs-" + name); v != "" {
		return v
	}
	return c.r.Header.Get("x-amz-" + name)
}

// writeXML sends a 200 response carrying an XML document with the
// standard declaration.
func (c *call) writeXML(v any) error {
	body, err := xml.Marshal(v)
	if err != nil {
		return err
	}
	c.w.Header().Set("Content-Type", "application/xml")
	c.w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(c.w, xml.Header)
	_, _ = c.w.Write(body)
	return nil
}

func (s *Service) handleListBuckets(c *call) error {
	buckets, err := s.ListBuckets(c.r.Context(), c.owner)
	if err != nil {
		return err
	}
	res := listBucketsResult{
		XMLNS:   c.dialect.namespace(),
		Owner:   xmlOwner{ID: ownerID(c.owner)},
		Buckets: make([]xmlBucket, 0, len(buckets)),
	}
	if c.dialect == dialectS3 {
		res.Owner.DisplayName = c.owner
	}
	for _, b := range buckets {
		xb := xmlBucket{Name: b.Name, CreationDate: b.Created.Format(timeLayout)}
		if c.dialect == dialectOBS {
			xb.Location, xb.BucketType = b.Region, "OBJECT"
		}
		res.Buckets = append(res.Buckets, xb)
	}
	return c.writeXML(res)
}

func (s *Service) handleCreateBucket(c *call) error {
	// The body is optional; when present it names the bucket's region,
	// which must be the region of the endpoint the request was sent to.
	raw, err := io.ReadAll(io.LimitReader(c.r.Body, maxConfigBody))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		var cfg createBucketConfiguration
		if err := xml.Unmarshal(raw, &cfg); err != nil {
			return errMalformedXML
		}
		location := cfg.Location
		if location == "" {
			location = cfg.LocationConstraint
		}
		if location != "" && location != c.region {
			return errInvalidLocation(location, c.region)
		}
	}
	b, err := s.CreateBucket(c.r.Context(), c.owner, c.region, c.target.Bucket)
	if err != nil {
		return err
	}
	c.w.Header().Set("Location", "/"+b.Name)
	c.w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleHeadBucket(c *call) error {
	b, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket)
	if err != nil {
		return err
	}
	h := c.w.Header()
	if c.dialect == dialectOBS {
		h.Set("x-obs-bucket-location", b.Region)
		h.Set("x-obs-version", "3.0")
		h.Set("x-obs-storage-class", "STANDARD")
	} else {
		h.Set("x-amz-bucket-region", b.Region)
	}
	c.w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleGetBucketLocation(c *call) error {
	b, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket)
	if err != nil {
		return err
	}
	if c.dialect == dialectS3 {
		return c.writeXML(locationS3{XMLNS: namespaceS3, LocationConstraint: b.Region})
	}
	return c.writeXML(locationOBS{XMLNS: namespaceOBS, Value: b.Region})
}

func (s *Service) handleDeleteBucket(c *call) error {
	if err := s.DeleteBucket(c.r.Context(), c.owner, c.target.Bucket); err != nil {
		return err
	}
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}
