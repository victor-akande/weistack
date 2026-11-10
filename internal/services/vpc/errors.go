package vpc

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error catalogue.
//
// Codes and HTTP statuses come from the "Error Codes" appendix of the VPC
// API reference (source: docs). Which code a given condition produces is
// taken from that table's per-operation grouping and is provisional until
// checked against recorded traffic; message texts are our own wording.
// The v1 API (VPCs, subnets) renders errors as {"code", "message"}.

// errInvalidVPC is VPC.0101: a VPC request parameter is invalid.
func errInvalidVPC(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0101", format, args...)
}

// errVPCNameExists is VPC.0115: VPC names are unique within a project.
func errVPCNameExists(name string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0115", "The VPC name %q already exists.", name)
}

// errVPCNotFound is VPC.0105 with 404: the backend has no such VPC.
func errVPCNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "VPC.0105", "Neutron Error: VPC %s could not be found.", id)
}

// errVPCBusy is VPC.0103: the VPC is still being created.
func errVPCBusy(id string) *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0103", "The VPC %s is being created. Try again later.", id)
}

// errVPCHasSubnets is VPC.0104: a VPC with subnets cannot be deleted.
func errVPCHasSubnets(id string) *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.0104", "The VPC %s contains subnets. Delete the subnets first.", id)
}

// errVPCCIDRExcludesSubnet is VPC.0117: a VPC's CIDR block must keep
// covering its subnets.
func errVPCCIDRExcludesSubnet(cidr, subnetCIDR string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0117",
		"The VPC CIDR block %s does not contain the subnet CIDR block %s.", cidr, subnetCIDR)
}

// errSubnetVPCNotFound is VPC.0003: the vpc_id of a subnet request does
// not exist in this project.
func errSubnetVPCNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "VPC.0003", "The VPC %s does not exist.", id)
}

// errInvalidSubnet is VPC.0201: a subnet request parameter is invalid.
func errInvalidSubnet(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0201", format, args...)
}

// errSubnetNotFound is VPC.0202 with 404.
func errSubnetNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "VPC.0202",
		"Query resource by id %s fail.the subnet could not be found.", id)
}

// errSubnetOutsideVPC is VPC.0203.
func errSubnetOutsideVPC(cidr, vpcCIDR string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0203",
		"The subnet CIDR block %s is not in the VPC CIDR block %s.", cidr, vpcCIDR)
}

// errSubnetCIDRConflict is VPC.0204.
func errSubnetCIDRConflict(cidr, other string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0204",
		"The subnet CIDR block %s conflicts with the existing subnet CIDR block %s in the VPC.", cidr, other)
}

// errSubnetBusy is VPC.0205: the subnet is still being processed.
func errSubnetBusy(id string) *apierr.Error {
	return apierr.New(http.StatusInternalServerError, "VPC.0205", "The subnet %s is being processed. Try again later.", id)
}

// errSubnetNotInVPC is VPC.0207.
func errSubnetNotInVPC(id, vpcID string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0207", "The subnet %s does not belong to the VPC %s.", id, vpcID)
}

// errSubnetInUse is VPC.0208: private IP addresses of the subnet are
// still in use. The API reference documents this as a 500.
func errSubnetInUse(id string, n int) *apierr.Error {
	return apierr.New(http.StatusInternalServerError, "VPC.0208",
		"The subnet %s has %d private IP address(es) in use. Release them first.", id, n)
}

// errInvalidSubnetCIDR is VPC.0212.
func errInvalidSubnetCIDR(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0212", format, args...)
}

// The v3 API (security groups and rules) renders errors as
// {"request_id", "error_code", "error_msg"}. The reference documents
// VPC.9902 for rejected requests (400 for a bad value, 409 for a
// conflict) and VPC.9904 for anything that does not exist.

// errInvalidSecGroup is VPC.9902 with 400: a v3 request is invalid.
func errInvalidSecGroup(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.9902", format, args...)
}

// errSecGroupConflict is VPC.9902 with 409: the request conflicts with
// existing state (duplicate rule, group that cannot be deleted).
func errSecGroupConflict(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusConflict, "VPC.9902", format, args...)
}

// errSecGroupNotFound is VPC.9904.
func errSecGroupNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "VPC.9904", "Security group %s does not exist.", id)
}

// errSecGroupRuleNotFound is VPC.9904.
func errSecGroupRuleNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "VPC.9904", "Security group rule %s does not exist.", id)
}

// errAddressGroupNotFound is VPC.9904. IP address groups are not
// emulated, so no remote_address_group_id can exist.
func errAddressGroupNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "VPC.9904", "IP address group %s does not exist.", id)
}
