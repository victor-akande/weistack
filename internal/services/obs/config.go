package obs

import (
	"encoding/xml"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Bucket configuration reads.
//
// WeiStack stores no bucket configuration: a bucket has no policy, CORS
// rules, tags, website, lifecycle rules or encryption, is unversioned,
// has no quota and logs nothing. Reading that configuration therefore
// has a truthful answer, which is what tools such as Terraform ask for
// after every create. Each answer is the one OBS gives for a bucket that
// was never configured: an empty document, or the specific "NoSuch..."
// 404 clients check for. Writing configuration is still not implemented.

// configReads maps a bucket subresource to its GET handler.
func (s *Service) configReads() map[string]handlerFunc {
	missing := func(e *apierr.Error) handlerFunc {
		return func(c *call) error {
			if _, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket); err != nil {
				return err
			}
			return e
		}
	}
	return map[string]handlerFunc{
		"acl":            s.handleGetBucketACL,
		"policy":         missing(errNoSuchBucketPolicy),
		"lifecycle":      missing(errNoSuchLifecycle),
		"cors":           missing(errNoSuchCORS),
		"tagging":        missing(errNoSuchTagSet),
		"website":        missing(errNoSuchWebsite),
		"encryption":     s.handleGetBucketEncryption,
		"versioning":     s.emptyConfig(func(ns string) any { return versioningConfiguration{XMLNS: ns} }),
		"logging":        s.emptyConfig(func(ns string) any { return bucketLoggingStatus{XMLNS: ns} }),
		"notification":   s.emptyConfig(func(ns string) any { return notificationConfiguration{XMLNS: ns} }),
		"quota":          s.emptyConfig(func(ns string) any { return bucketQuota{XMLNS: ns} }),
		"customdomain":   s.emptyConfig(func(ns string) any { return customDomains{XMLNS: ns} }),
		"requestPayment": s.emptyConfig(func(ns string) any { return requestPayment{XMLNS: ns, Payer: "BucketOwner"} }),
		"storagePolicy":  s.emptyConfig(func(ns string) any { return storagePolicy{XMLNS: ns, DefaultStorageClass: storageClassStandard} }),
		"storageClass":   s.emptyConfig(func(ns string) any { return storageClassOBS{XMLNS: ns, Value: storageClassStandard} }),
		"storageinfo":    s.handleGetStorageInfo,
	}
}

// storageClassStandard is the only storage class WeiStack has.
const storageClassStandard = "STANDARD"

// emptyConfig answers with a fixed document once the bucket is found.
func (s *Service) emptyConfig(doc func(namespace string) any) handlerFunc {
	return func(c *call) error {
		if _, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket); err != nil {
			return err
		}
		return c.writeXML(doc(c.dialect.namespace()))
	}
}

// handleGetBucketACL reports the default ACL: the owner has full control.
func (s *Service) handleGetBucketACL(c *call) error {
	if _, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket); err != nil {
		return err
	}
	id := ownerID(c.owner)
	return c.writeXML(accessControlPolicy{
		XMLNS: c.dialect.namespace(),
		Owner: xmlOwner{ID: id},
		Grants: []grant{{
			Grantee:    grantee{XSI: xmlSchemaInstance, Type: "CanonicalUser", ID: id},
			Permission: "FULL_CONTROL",
		}},
	})
}

// handleGetBucketEncryption reports that the bucket has no default
// encryption, under the code of the request's dialect.
func (s *Service) handleGetBucketEncryption(c *call) error {
	if _, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket); err != nil {
		return err
	}
	if c.dialect == dialectS3 {
		return errNoEncryptionS3
	}
	return errNoEncryptionOBS
}

// handleGetStorageInfo reports the bucket's real size and object count.
func (s *Service) handleGetStorageInfo(c *call) error {
	ctx := c.r.Context()
	if _, err := s.bucketFor(ctx, c.owner, c.target.Bucket); err != nil {
		return err
	}
	objects, err := s.objects(c.target.Bucket).List(ctx, nil)
	if err != nil {
		return err
	}
	info := storageInfo{XMLNS: c.dialect.namespace(), ObjectNumber: int64(len(objects))}
	for _, o := range objects {
		info.Size += o.Size
	}
	return c.writeXML(info)
}

var (
	errNoSuchBucketPolicy = apierr.New(http.StatusNotFound, "NoSuchBucketPolicy", "The bucket policy does not exist")
	errNoSuchLifecycle    = apierr.New(http.StatusNotFound, "NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist")
	errNoSuchCORS         = apierr.New(http.StatusNotFound, "NoSuchCORSConfiguration", "The CORS configuration does not exist")
	errNoSuchTagSet       = apierr.New(http.StatusNotFound, "NoSuchTagSet", "The TagSet does not exist")
	errNoSuchWebsite      = apierr.New(http.StatusNotFound, "NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration")
	errNoEncryptionOBS    = apierr.New(http.StatusNotFound, "NoSuchEncryptionConfiguration", "The server side encryption configuration was not found")
	errNoEncryptionS3     = apierr.New(http.StatusNotFound, "ServerSideEncryptionConfigurationNotFoundError", "The server side encryption configuration was not found")
)

const xmlSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance"

type accessControlPolicy struct {
	XMLName xml.Name `xml:"AccessControlPolicy"`
	XMLNS   string   `xml:"xmlns,attr"`
	Owner   xmlOwner `xml:"Owner"`
	Grants  []grant  `xml:"AccessControlList>Grant"`
}

type grant struct {
	Grantee    grantee `xml:"Grantee"`
	Permission string  `xml:"Permission"`
}

type grantee struct {
	XSI  string `xml:"xmlns:xsi,attr"`
	Type string `xml:"xsi:type,attr"`
	ID   string `xml:"ID"`
}

type versioningConfiguration struct {
	XMLName xml.Name `xml:"VersioningConfiguration"`
	XMLNS   string   `xml:"xmlns,attr"`
}

type bucketLoggingStatus struct {
	XMLName xml.Name `xml:"BucketLoggingStatus"`
	XMLNS   string   `xml:"xmlns,attr"`
}

type notificationConfiguration struct {
	XMLName xml.Name `xml:"NotificationConfiguration"`
	XMLNS   string   `xml:"xmlns,attr"`
}

// bucketQuota is OBS's quota document; 0 means no quota.
type bucketQuota struct {
	XMLName      xml.Name `xml:"Quota"`
	XMLNS        string   `xml:"xmlns,attr"`
	StorageQuota int64    `xml:"StorageQuota"`
}

type customDomains struct {
	XMLName xml.Name `xml:"ListBucketCustomDomainsResult"`
	XMLNS   string   `xml:"xmlns,attr"`
}

type requestPayment struct {
	XMLName xml.Name `xml:"RequestPaymentConfiguration"`
	XMLNS   string   `xml:"xmlns,attr"`
	Payer   string   `xml:"Payer"`
}

// storagePolicy answers ?storagePolicy, the S3 dialect's form.
type storagePolicy struct {
	XMLName             xml.Name `xml:"StoragePolicy"`
	XMLNS               string   `xml:"xmlns,attr"`
	DefaultStorageClass string   `xml:"DefaultStorageClass"`
}

// storageClassOBS answers ?storageClass, the OBS dialect's form.
type storageClassOBS struct {
	XMLName xml.Name `xml:"StorageClass"`
	XMLNS   string   `xml:"xmlns,attr"`
	Value   string   `xml:",chardata"`
}

type storageInfo struct {
	XMLName      xml.Name `xml:"GetBucketStorageInfoResult"`
	XMLNS        string   `xml:"xmlns,attr"`
	Size         int64    `xml:"Size"`
	ObjectNumber int64    `xml:"ObjectNumber"`
}
