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

// caller returns who a request acts as, which is what buckets are owned
// by. A key WeiStack knows acts for its account, as on Huawei Cloud, so
// all of an account's users share its buckets. Any other key is, as in
// v0.1, an owner of its own. Signatures are not verified.
func caller(r *http.Request) string {
	id := auth.FromContext(r.Context())
	if owner := id.Owner(); owner != "" {
		return owner
	}
	// Pre-signed URLs carry the key in the query string.
	q := r.URL.Query()
	for _, name := range []string{"AccessKeyId", "AWSAccessKeyId"} {
		if ak := q.Get(name); ak != "" {
			return auth.Resolve(auth.Identity{AccessKey: ak}, auth.ResolverFromContext(r.Context())).Owner()
		}
	}
	return anonymous
}

// ownerID renders an owner as the 32-hex ID the API shows: an account's
// own ID, or for a raw access key a stable hash that does not expose it.
func ownerID(owner string) string {
	if account, ok := strings.CutPrefix(owner, auth.AccountOwnerPrefix); ok {
		return account
	}
	sum := md5.Sum([]byte("weistack:obs:owner:" + owner)) //nolint:gosec // see import
	return hex.EncodeToString(sum[:])
}
