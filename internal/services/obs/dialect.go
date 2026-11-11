package obs

import (
	"crypto/md5" //nolint:gosec // identifiers and ETags are MD5 by protocol, not for security
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/victor-akande/weistack/internal/core/auth"
)

// dialect is the flavour of the protocol a request speaks.
type dialect int

const (
	// dialectOBS is Huawei's: "x-obs-" headers and the OBS XML namespace.
	dialectOBS dialect = iota
	// dialectS3 is Amazon's: "x-amz-" headers and the S3 XML namespace.
	dialectS3
)

const (
	namespaceOBS = "http://obs.myhwclouds.com/doc/2015-06-30/"
	namespaceS3  = "http://s3.amazonaws.com/doc/2006-03-01/"
)

// dialectOf decides which dialect a request speaks. S3 is chosen only on
// positive evidence (an AWS signature or an x-amz- header); everything
// else, including unsigned requests, gets the OBS dialect.
func dialectOf(r *http.Request) dialect {
	switch auth.FromContext(r.Context()).Scheme {
	case auth.SchemeOBS:
		return dialectOBS
	case auth.SchemeAWSV2, auth.SchemeAWSV4:
		return dialectS3
	}
	for name := range r.Header {
		if strings.HasPrefix(name, "X-Amz-") {
			return dialectS3
		}
	}
	return dialectOBS
}

// prefix is the vendor prefix of the dialect's headers.
func (d dialect) prefix() string {
	if d == dialectS3 {
		return "x-amz-"
	}
	return "x-obs-"
}

func (d dialect) namespace() string {
	if d == dialectS3 {
		return namespaceS3
	}
	return namespaceOBS
}

// anonymous is the owner of requests that carry no access key.
const anonymous = "anonymous"

// caller returns the access key a request claims, which is the identity
// buckets are owned by. Signatures are not verified.
func caller(r *http.Request) string {
	if ak := auth.FromContext(r.Context()).AccessKey; ak != "" {
		return ak
	}
	// Pre-signed URLs carry the key in the query string.
	q := r.URL.Query()
	for _, name := range []string{"AccessKeyId", "AWSAccessKeyId"} {
		if ak := q.Get(name); ak != "" {
			return ak
		}
	}
	return anonymous
}

// ownerID renders an access key as the 32-hex ID the API shows for an
// owner, without exposing the key itself.
func ownerID(accessKey string) string {
	sum := md5.Sum([]byte("weistack:obs:owner:" + accessKey)) //nolint:gosec // see import
	return hex.EncodeToString(sum[:])
}
