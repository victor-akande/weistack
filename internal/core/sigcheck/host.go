package sigcheck

import (
	"net"
	"regexp"
	"strings"
)

var regionLabelRE = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+$`)

// HostBucket extracts the bucket from an OBS virtual-hosted host name,
// such as my-bucket.obs.ap-southeast-1.myhuaweicloud.com, lower-cased, or
// returns "" when the host addresses the service itself. A bucket name
// may contain periods, so everything before the "obs" label is the
// bucket.
func HostBucket(hostport string) string { return strings.ToLower(HostBucketAsSent(hostport)) }

// HostBucketAsSent is HostBucket with the case the client used, which
// is what a v2 signature covers.
func HostBucketAsSent(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	labels := strings.Split(host, ".")
	// The service label is the last "obs" that is followed by a region
	// or by "localhost"; a bucket may be called "obs" too.
	for i := len(labels) - 2; i >= 1; i-- {
		if !strings.EqualFold(labels[i], "obs") {
			continue
		}
		next := strings.ToLower(labels[i+1])
		if regionLabelRE.MatchString(next) || (next == "localhost" && i+2 == len(labels)) {
			return strings.Join(labels[:i], ".")
		}
	}
	return ""
}
