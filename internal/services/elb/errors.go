package elb

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error constructors for every documented ELB error code in guide §3.
// Sources: error-codes.tsv and the individual ELB v3 API pages.

// ELB.8902 (400): error-codes.tsv — invalid input parameter or unparseable body.
func errInvalidInput(field string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "ELB.8902", "Invalid input for '%s'.", field)
}

// ELB.8904 (404): error-codes.tsv — resource could not be found.
func errNotFound(kind, id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "ELB.8904", "%s %s could not be found.", kind, id)
}

// ELB.8907 (409): error-codes.tsv — resource in use or duplicate conflict.
func errConflict(reason string) *apierr.Error {
	return apierr.New(http.StatusConflict, "ELB.8907", "Data conflict. %s", reason)
}

// ELB.8959 (400): error-codes.tsv — flavor field cannot be updated across types (L4/L7).
func errFlavorTypeChange(field, from, to string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "ELB.8959", "The %s flavor field does not support update from %s to %s.", field, from, to)
}

// ELB.8938 (400): error-codes.tsv — IP member protocol not supported by pool.
func errIPMemberProtocol(protocols string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "ELB.8938", "The IP member is supported only when the pool protocol is %s.", protocols)
}

// ELB.8939 (400): error-codes.tsv — IP member requires load balancer ip_target_enable=true.
func errIPTargetDisabled() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "ELB.8939", "The load balancer's ip_target_enable must be true when adding IP members.")
}

// ELB.1011 (400): error-codes.tsv — invalid server certificate or private key content/mismatch.
func errInvalidCertificate() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "ELB.1011", "Invalid private key or certificate content.")
}

// ELB.5051 (400): error-codes.tsv — invalid CA certificate content.
func errInvalidCACertificate() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "ELB.5051", "CA certificate content is not valid.")
}

// ELB.8909 (400): error-codes.tsv — certificate with multiple domains not supported where one is required.
func errMultipleDomainsNotSupported() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "ELB.8909", "Certificates with multiple domains are not supported by dedicated load balancers.")
}

// ELB.8934 (400): error-codes.tsv — no free IP address in the subnet.
func errSubnetFull() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "ELB.8934", "The number of available IP addresses in the subnet on the downstream plane is insufficient.")
}

// ELB.1091 (403): error-codes.tsv — load balancer quota exceeded.
func errLoadBalancerQuotaExceeded() *apierr.Error {
	return apierr.New(http.StatusForbidden, "ELB.1091", "The number of load balancers exceeds the quota.")
}

// ELB.6091 (403): error-codes.tsv — listener quota exceeded.
func errListenerQuotaExceeded() *apierr.Error {
	return apierr.New(http.StatusForbidden, "ELB.6091", "The number of listeners reaches the limit.")
}

// ELB.2001 (403): error-codes.tsv — member quota exceeded.
func errMemberQuotaExceeded() *apierr.Error {
	return apierr.New(http.StatusForbidden, "ELB.2001", "Creating the member failed. The total number of members exceeds the upper limit.")
}

// ELB.5151 (400): error-codes.tsv — certificate quota exceeded.
func errCertificateQuotaExceeded() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "ELB.5151", "The certificate quantity exceeds the quota.")
}

// ELB.8905 (409): error-codes.tsv — quota exceeded for resource (pool, l7policy, l7policies_per_listener).
func errResourceQuotaExceeded(resource string) *apierr.Error {
	return apierr.New(http.StatusConflict, "ELB.8905", "Quota exceeded for resources: %s", resource)
}

// WeiStack.0501 (501): unimplemented operation or out-of-scope feature.
func errNotImplemented(feature string) *apierr.Error {
	return apierr.NotImplemented("elb", feature)
}
