package obs

import (
	"context"
	"encoding/xml"
	"errors"
	"sort"
	"time"

	"github.com/victor-akande/weistack/internal/core/store"
)

// timeLayout is the timestamp format of OBS XML responses.
const timeLayout = "2006-01-02T15:04:05.000Z"

// Bucket is the stored record of a bucket.
type Bucket struct {
	Name string `json:"name"`
	// Owner is the access key that created the bucket.
	Owner string `json:"owner"`
	// Region is the bucket's location.
	Region  string    `json:"region"`
	Created time.Time `json:"created"`
}

// CreateBucket creates a bucket owned by owner in region.
func (s *Service) CreateBucket(ctx context.Context, owner, region, name string) (Bucket, error) {
	if !validBucketName(name) {
		return Bucket{}, errInvalidBucketName
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.buckets().Get(ctx, name)
	switch {
	case err == nil && existing.Owner == owner:
		return Bucket{}, errBucketOwnedByYou
	case err == nil:
		return Bucket{}, errBucketExists
	case !errors.Is(err, store.ErrNotFound):
		return Bucket{}, err
	}
	b := Bucket{Name: name, Owner: owner, Region: region, Created: s.now().UTC()}
	if err := s.buckets().Create(ctx, name, b); err != nil {
		return Bucket{}, err
	}
	return b, nil
}

// bucketFor returns a bucket the caller owns. A bucket of another owner
// is reported as access denied, a missing one as NoSuchBucket.
func (s *Service) bucketFor(ctx context.Context, owner, name string) (Bucket, error) {
	b, err := s.buckets().Get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return Bucket{}, errNoSuchBucket
	}
	if err != nil {
		return Bucket{}, err
	}
	if b.Owner != owner {
		return Bucket{}, errAccessDenied
	}
	return b, nil
}

// ListBuckets returns the buckets owned by owner, sorted by name.
func (s *Service) ListBuckets(ctx context.Context, owner string) ([]Bucket, error) {
	out, err := s.buckets().List(ctx, func(b Bucket) bool { return b.Owner == owner })
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteBucket removes an empty bucket.
func (s *Service) DeleteBucket(ctx context.Context, owner, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.bucketFor(ctx, owner, name); err != nil {
		return err
	}
	page, err := s.listObjects(ctx, name, "", "", "", 1)
	if err != nil {
		return err
	}
	if len(page.Objects) > 0 {
		return errBucketNotEmpty
	}
	// OBS also refuses to delete a bucket that holds parts of uploads in
	// progress; they must be completed or aborted first.
	if pending, err := s.hasUploads(ctx, name); err != nil {
		return err
	} else if pending {
		return errBucketNotEmpty
	}
	return s.buckets().Delete(ctx, name)
}

// XML bodies. Element names are those of the S3 API, which OBS shares.

type xmlOwner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName,omitempty"`
}

type xmlBucket struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
	// Location and BucketType are OBS extensions.
	Location   string `xml:"Location,omitempty"`
	BucketType string `xml:"BucketType,omitempty"`
}

type listBucketsResult struct {
	XMLName xml.Name    `xml:"ListAllMyBucketsResult"`
	XMLNS   string      `xml:"xmlns,attr"`
	Owner   xmlOwner    `xml:"Owner"`
	Buckets []xmlBucket `xml:"Buckets>Bucket"`
}

// createBucketConfiguration is the optional body of a bucket creation.
// OBS names the element Location, S3 LocationConstraint.
type createBucketConfiguration struct {
	Location           string `xml:"Location"`
	LocationConstraint string `xml:"LocationConstraint"`
}

// A location response has two forms. In the OBS dialect it is a bare
// <Location>. In the S3 dialect OBS wraps the value in a
// <CreateBucketConfiguration>, unlike Amazon S3, whose response is a
// bare <LocationConstraint>; Huawei's SDK requires the wrapped form.
type locationOBS struct {
	XMLName xml.Name `xml:"Location"`
	XMLNS   string   `xml:"xmlns,attr"`
	Value   string   `xml:",chardata"`
}

type locationS3 struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	XMLNS              string   `xml:"xmlns,attr"`
	LocationConstraint string   `xml:"LocationConstraint"`
}
