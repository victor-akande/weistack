package ecs

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error catalogue.
//
// ECS renders errors as {"error": {"code": "Ecs.0005", "message": "..."}}.
// Codes and HTTP statuses come from the "Error Codes" appendix of the ECS
// API reference (source: docs). Message texts are our own wording.

// errInvalidRequest is Ecs.0005: the request body or a parameter is
// invalid.
func errInvalidRequest(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "Ecs.0005", format, args...)
}

func bad(code, format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, code, format, args...)
}

// errServerNotFound is Ecs.0114.
func errServerNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "Ecs.0114", "The ECS %s does not exist.", id)
}

// errJobNotFound is Common.0011: the job ID is not valid in the project.
func errJobNotFound(id string) *apierr.Error {
	return bad("Common.0011", "The job %s does not exist.", id)
}

// errQuota is Ecs.0001.
func errQuota(what string, want, used, limit int) *apierr.Error {
	return bad("Ecs.0001", "The %s quota is insufficient: %d requested, %d of %d in use.", what, want, used, limit)
}

// Server creation.
var (
	errNameTooLong  = bad("Ecs.0914", "The ECS name contains more than 64 characters.")
	errNameInvalid  = bad("Ecs.0915", "The ECS name is empty or contains invalid characters: use letters, digits, underscores (_), hyphens (-) and periods (.).")
	errPassword     = bad("Ecs.0011", "The password does not meet the complexity requirements: 8 to 26 characters with at least three of uppercase letters, lowercase letters, digits and special characters.")
	errTooManyNICs  = bad("Ecs.0050", "The number of NICs exceeds the upper limit (12).")
	errTooManyDisks = bad("Ecs.0042", "The number of data disks exceeds the upper limit (23).")
	errTooManyTags  = bad("Ecs.0905", "The number of tags exceeds the upper limit (10).")
)

func errTooManyServers(n int) *apierr.Error {
	return bad("Ecs.0913", "The number of ECSs to be created (%d) exceeds the upper limit (%d).", n, maxCreateCount)
}

func errImageNotFound(id string) *apierr.Error {
	return bad("Ecs.0031", "The image %s does not exist.", id)
}

func errImageNotActive(id, status string) *apierr.Error {
	return bad("Ecs.0032", "The image %s is not in the active state (status %s).", id, status)
}

func errImageFlavorMismatch(image, flavor string) *apierr.Error {
	return bad("Ecs.0007", "The image %s and the flavor %s use different CPU architectures.", image, flavor)
}

func errFlavorNotFound(name string) *apierr.Error {
	return bad("Ecs.0029", "The flavor %s does not exist.", name)
}

// errNetworkInvalid is Ecs.0014: a VPC, subnet or security group
// parameter is invalid.
func errNetworkInvalid(format string, args ...any) *apierr.Error {
	return bad("Ecs.0014", format, args...)
}

func errSubnetNotFound(id string) *apierr.Error {
	return bad("Ecs.0038", "The subnet %s does not exist.", id)
}

func errSubnetNotInVPC(subnet, vpcID string) *apierr.Error {
	return bad("Ecs.0064", "The subnet %s does not belong to the VPC %s.", subnet, vpcID)
}

func errIPInUse(ip string) *apierr.Error {
	return bad("Ecs.0010", "The private IP address %s is already in use.", ip)
}

func errIPNotInSubnet(ip, subnet string) *apierr.Error {
	return bad("Ecs.0039", "The private IP address %s cannot be used in the subnet %s.", ip, subnet)
}

func errSubnetFull(subnet string) *apierr.Error {
	return bad("Ecs.0012", "The subnet %s does not have enough free IP addresses.", subnet)
}

func errDiskType(t string) *apierr.Error {
	return bad("Ecs.0043", "The disk type %q does not exist.", t)
}

func errTag(code, format string, args ...any) *apierr.Error {
	return bad(code, format, args...)
}

// jobFailureCode is the error_code of a failed job.
const jobFailureCode = "Ecs.0000"

// errStatus is Ecs.0100: the server's status does not allow the
// operation.
func errStatus(id, status, need string) *apierr.Error {
	return bad("Ecs.0100", "The status of ECS %s (%s) does not allow this operation: %s.", id, status, need)
}

// errBatchTooLarge is Ecs.0118.
func errBatchTooLarge(n int) *apierr.Error {
	return bad("Ecs.0118", "The number of ECSs in the batch (%d) exceeds the upper limit (%d).", n, maxBatch)
}

// errSameFlavor is Ecs.0810.
func errSameFlavor(name string) *apierr.Error {
	return bad("Ecs.0810", "The target flavor %s is the same as the current flavor.", name)
}

// errFlavorSwitch is Ecs.0804.
func errFlavorSwitch(from, to string) *apierr.Error {
	return bad("Ecs.0804", "The ECS cannot be changed from flavor %s to flavor %s: the CPU architectures differ.", from, to)
}
