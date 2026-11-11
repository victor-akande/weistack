package obs

import (
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// target is what a request addresses: nothing (the service), a bucket,
// or an object in a bucket.
type target struct {
	Bucket string
	Key    string
}

var regionLabelRE = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+$`)

// resolve works out the bucket and key a request addresses, in either
// style:
//
//	virtual-hosted   my-bucket.obs.ap-southeast-1.myhuaweicloud.com/dir/key
//	path             obs.ap-southeast-1.myhuaweicloud.com/my-bucket/dir/key
//
// A bucket name may itself contain periods, so in the virtual-hosted
// style everything before the "obs" label is the bucket.
func resolve(r *http.Request) (target, error) {
	bucket := hostBucket(r.Host)

	// The escaped path is used so that an encoded slash inside a key
	// (%2F) is not mistaken for a separator.
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/")
	if bucket == "" {
		var rest string
		bucket, rest, _ = strings.Cut(path, "/")
		path = rest
		var err error
		if bucket, err = url.PathUnescape(bucket); err != nil {
			return target{}, err
		}
	}
	key, err := url.PathUnescape(path)
	if err != nil {
		return target{}, err
	}
	return target{Bucket: bucket, Key: key}, nil
}

// hostBucket extracts the bucket from a virtual-hosted style host name,
// or returns "" when the host addresses the service itself.
func hostBucket(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	labels := strings.Split(strings.ToLower(host), ".")
	// The service label is the last "obs" that is followed by a region
	// or by "localhost"; a bucket may be called "obs" too.
	for i := len(labels) - 2; i >= 1; i-- {
		if labels[i] != "obs" {
			continue
		}
		next := labels[i+1]
		if regionLabelRE.MatchString(next) || (next == "localhost" && i+2 == len(labels)) {
			return strings.Join(labels[:i], ".")
		}
	}
	return ""
}

var (
	bucketNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)
	ipLikeRE     = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
)

// validBucketName enforces the OBS naming rules: 3 to 63 characters of
// lowercase letters, digits, hyphens and periods; starting and ending
// with a letter or digit; not shaped like an IP address; and without
// adjacent periods or a period next to a hyphen.
func validBucketName(name string) bool {
	return bucketNameRE.MatchString(name) &&
		!ipLikeRE.MatchString(name) &&
		!strings.Contains(name, "..") &&
		!strings.Contains(name, ".-") &&
		!strings.Contains(name, "-.")
}
