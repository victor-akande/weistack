package eip

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error catalogue for EIP and bandwidths (§3, error-codes.tsv).
// Each constructor corresponds to one documented error code and comments
// the API page(s) where it appears.

// errInvalidEnterpriseProjectID is VPC.0011 (eip_api_0001).
func errInvalidEnterpriseProjectID() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0011", "Invalid enterprise project ID.")
}

// errInvalidBandwidth is VPC.0301 (eip_api_0001, eip_apiBandwidth_0001,
// eip_apiBandwidth_0002, eip_apiBandwidth_0003, eip_apisharedbandwidth_0001,
// eip_apisharedbandwidth_0004, eip_apisharedbandwidth_0005, eip_apisharedbandwidth_0006).
func errInvalidBandwidth(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0301", format, args...)
}

// errBandwidthInUse is VPC.0304 (eip_apisharedbandwidth_0003).
func errBandwidthInUse() *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0304", "The shared bandwidth still has EIPs. Remove them first.")
}

// errBandwidthNotFound is VPC.0306 (eip_api_0001, eip_apiBandwidth_0001,
// eip_apiBandwidth_0002, eip_apisharedbandwidth_0003).
func errBandwidthNotFound() *apierr.Error {
	return apierr.New(http.StatusNotFound, "VPC.0306", "EIP bandwidth with the ID not found.")
}

// errSharedBandwidthQuota is VPC.0310 (eip_apisharedbandwidth_0001).
func errSharedBandwidthQuota() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0310", "Insufficient shared bandwidth quota.")
}

// errSharedBandwidthModify is VPC.0323 (eip_apisharedbandwidth_0003,
// eip_apisharedbandwidth_0004, eip_apisharedbandwidth_0005).
func errSharedBandwidthModify() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0323", "EIPs cannot be added to or removed from the shared bandwidth.")
}

// errInvalidPublicIP is VPC.0501 (eip_api_0001, eip_api_0002, eip_api_0003,
// eip_api_0004, eip_api_0005, eip_apitag_0001, eip_apitag_0004, eip_apitag_0005).
func errInvalidPublicIP(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0501", format, args...)
}

// errPublicIPNotFound is VPC.0504 (eip_api_0002, eip_api_0003, eip_api_0004,
// eip_api_0005, eip_apitag_0001, eip_apitag_0002, eip_apitag_0003, eip_apitag_0004).
func errPublicIPNotFound() *apierr.Error {
	return apierr.New(http.StatusNotFound, "VPC.0504", "Floating IP could not be found.")
}

// errInvalidPort is VPC.0508 (eip_api_0001, AssociatePublicips).
func errInvalidPort() *apierr.Error {
	return apierr.New(http.StatusInternalServerError, "VPC.0508", "Port is invalid.")
}

// errPublicIPAlreadyBound is VPC.0510 (eip_api_0004, AssociatePublicips).
func errPublicIPAlreadyBound() *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0510", "EIP has already been bound to a port.")
}

// errPortAlreadyBound is VPC.0511 (eip_api_0001, eip_api_0004, AssociatePublicips).
func errPortAlreadyBound() *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0511", "The port has already been bound with an EIP.")
}

// errPublicIPBusy is VPC.0512 (eip_api_0004, eip_api_0005).
func errPublicIPBusy() *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0512", "Resource status is busy, try it again later.")
}

// errPublicIPBound is VPC.0517 (eip_api_0005).
func errPublicIPBound() *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0517", "EIP is bound to a port. Unbind it first.")
}

// errPublicIPQuota is VPC.0521 (eip_api_0001).
func errPublicIPQuota() *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0521", "Quota exceeded for resources: ['floatingip'].")
}

// errIPAddressInUse is VPC.0522 (eip_api_0001).
func errIPAddressInUse() *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0522", "The IP address is in use.")
}

// errAddressPoolExhausted is VPC.0532 (eip_api_0001).
func errAddressPoolExhausted() *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0532", "No more IP addresses available on network.")
}

// errInvalidV3Input is EIP.7901 (eip_api_0001, AssociatePublicips,
// DisassociatePublicips, UpdatePublicip, ListPublicipsV3, ShowPublicipV3).
func errInvalidV3Input(format string, args ...any) *apierr.Error {
	if format == "" {
		return apierr.New(http.StatusBadRequest, "EIP.7901", "Invalid input parameter.")
	}
	return apierr.New(http.StatusBadRequest, "EIP.7901", format, args...)
}
