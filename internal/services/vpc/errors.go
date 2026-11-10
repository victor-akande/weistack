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
