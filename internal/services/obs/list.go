package obs

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// maxListKeys is the largest page a listing returns, and the default.
const maxListKeys = 1000

// listing is one page of a bucket listing.
type listing struct {
	Objects   []Object
	Prefixes  []string
	Truncated bool
	// Next is the last entry of the page, key or common prefix: the
	// position the following page starts after.
	Next string
}

// listObjects returns one page of a bucket's contents.
//
// Keys are in byte order. Only keys starting with prefix and sorting
// after "after" are considered. With a delimiter, keys that contain it
// beyond the prefix are rolled up into one common prefix each, which
// counts as a single entry towards limit.
func (s *Service) listObjects(ctx context.Context, bucket, prefix, delimiter, after string, limit int) (listing, error) {
	all, err := s.objects(bucket).List(ctx, func(o Object) bool {
		return strings.HasPrefix(o.Key, prefix) && o.Key > after
	})
	if err != nil {
		return listing{}, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Key < all[j].Key })

	var page listing
	if limit <= 0 {
		return page, nil
	}
	lastPrefix := ""
	for _, obj := range all {
		entry, rolledUp := obj.Key, false
		if delimiter != "" {
			if i := strings.Index(obj.Key[len(prefix):], delimiter); i >= 0 {
				entry, rolledUp = obj.Key[:len(prefix)+i+len(delimiter)], true
			}
		}
		if rolledUp && (entry == lastPrefix || entry <= after) {
			continue // already reported, on this page or an earlier one
		}
		if len(page.Objects)+len(page.Prefixes) == limit {
			page.Truncated = true
			break
		}
		if rolledUp {
			page.Prefixes = append(page.Prefixes, entry)
			lastPrefix = entry
		} else {
			page.Objects = append(page.Objects, obj)
		}
		page.Next = entry
	}
	return page, nil
}

type xmlContents struct {
	Key          string    `xml:"Key"`
	LastModified string    `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
	Owner        *xmlOwner `xml:"Owner,omitempty"`
	StorageClass string    `xml:"StorageClass"`
}

type xmlPrefix struct {
	Prefix string `xml:"Prefix"`
}

// listBucketResult is the response of both listing versions; the fields
// each version does not use are omitted.
type listBucketResult struct {
	XMLName xml.Name `xml:"ListBucketResult"`
	XMLNS   string   `xml:"xmlns,attr"`
	Name    string   `xml:"Name"`
	Prefix  string   `xml:"Prefix"`
	// Version 1.
	Marker     *string `xml:"Marker"`
	NextMarker string  `xml:"NextMarker,omitempty"`
	// Version 2.
	StartAfter            string `xml:"StartAfter,omitempty"`
	ContinuationToken     string `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string `xml:"NextContinuationToken,omitempty"`
	KeyCount              *int   `xml:"KeyCount"`

	MaxKeys        int           `xml:"MaxKeys"`
	Delimiter      string        `xml:"Delimiter,omitempty"`
	EncodingType   string        `xml:"EncodingType,omitempty"`
	IsTruncated    bool          `xml:"IsTruncated"`
	Contents       []xmlContents `xml:"Contents"`
	CommonPrefixes []xmlPrefix   `xml:"CommonPrefixes"`
}

// encodeKey applies encoding-type=url, which lets keys with characters
// XML cannot carry survive a listing. Slashes are kept readable, as S3
// keeps them.
func encodeKey(key string, encode bool) string {
	if !encode {
		return key
	}
	return strings.ReplaceAll(url.QueryEscape(key), "%2F", "/")
}

func (s *Service) handleListObjects(c *call) error {
	ctx := c.r.Context()
	if _, err := s.bucketFor(ctx, c.owner, c.target.Bucket); err != nil {
		return err
	}
	q := c.r.URL.Query()

	limit := maxListKeys
	if raw := q.Get("max-keys"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return errInvalidArgument("max-keys must be a non-negative integer")
		}
		limit = min(n, maxListKeys)
	}
	encode := false
	switch q.Get("encoding-type") {
	case "":
	case "url":
		encode = true
	default:
		return errInvalidArgument("encoding-type must be url")
	}
	prefix, delimiter := q.Get("prefix"), q.Get("delimiter")
	v2 := q.Get("list-type") == "2"

	res := listBucketResult{
		XMLNS:     c.dialect.namespace(),
		Name:      c.target.Bucket,
		Prefix:    encodeKey(prefix, encode),
		Delimiter: encodeKey(delimiter, encode),
		MaxKeys:   limit,
	}
	if encode {
		res.EncodingType = "url"
	}

	// Where the page starts.
	after := q.Get("marker")
	if v2 {
		after = q.Get("start-after")
		res.StartAfter = encodeKey(after, encode)
		if token := q.Get("continuation-token"); token != "" {
			decoded, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				return errInvalidArgument("The continuation token provided is incorrect")
			}
			after = string(decoded)
			res.ContinuationToken = token
		}
	} else {
		marker := encodeKey(after, encode)
		res.Marker = &marker
	}

	page, err := s.listObjects(ctx, c.target.Bucket, prefix, delimiter, after, limit)
	if err != nil {
		return err
	}
	res.IsTruncated = page.Truncated

	withOwner := !v2 || q.Get("fetch-owner") == "true"
	for _, obj := range page.Objects {
		entry := xmlContents{
			Key:          encodeKey(obj.Key, encode),
			LastModified: obj.Modified.Format(timeLayout),
			ETag:         quote(obj.ETag),
			Size:         obj.Size,
			StorageClass: storageClass,
		}
		if withOwner {
			entry.Owner = &xmlOwner{ID: ownerID(c.owner)}
		}
		res.Contents = append(res.Contents, entry)
	}
	for _, p := range page.Prefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, xmlPrefix{Prefix: encodeKey(p, encode)})
	}

	if v2 {
		count := len(page.Objects) + len(page.Prefixes)
		res.KeyCount = &count
		if page.Truncated {
			res.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(page.Next))
		}
	} else if page.Truncated {
		res.NextMarker = encodeKey(page.Next, encode)
	}
	return c.writeXML(res)
}
