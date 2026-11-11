package rds

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error catalogue.
//
// RDS renders errors as {"error_code": "DBS.200001", "error_msg": "..."}.
// Codes and statuses come from the "Error Codes" appendix of the RDS API
// reference (source: docs). Message texts are our own wording.

func dbs(status int, code, format string, args ...any) *apierr.Error {
	return apierr.New(status, code, format, args...)
}

// errInvalid is DBS.200001: a request parameter is invalid.
func errInvalid(format string, args ...any) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.200001", format, args...)
}

func errInstanceNotFound(id string) *apierr.Error {
	return dbs(http.StatusNotFound, "DBS.200002", "The DB instance %s does not exist.", id)
}

func errEngineUnsupported(engine, version string) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.200040", "The DB engine %s %s is not supported.", engine, version)
}

func errFlavorNotFound(code string) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.200053", "The specification %s does not exist.", code)
}

func errFlavorInvalid(format string, args ...any) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.200054", format, args...)
}

func errQuota(limit int) *apierr.Error {
	return dbs(http.StatusRequestEntityTooLarge, "DBS.200046", "The DB instance quota (%d) has been reached.", limit)
}

func errVPCNotFound(id string) *apierr.Error {
	return dbs(http.StatusNotFound, "DBS.200503", "The VPC %s does not exist.", id)
}

func errSubnetNotFound(id, vpcID string) *apierr.Error {
	return dbs(http.StatusNotFound, "DBS.200501", "The subnet %s does not exist or does not belong to the VPC %s.", id, vpcID)
}

func errSecurityGroupNotFound(id string) *apierr.Error {
	return dbs(http.StatusNotFound, "DBS.200050", "The security group %s does not exist.", id)
}

// errBusy is DBS.200011: another operation is running on the instance.
func errBusy(id string) *apierr.Error {
	return dbs(http.StatusConflict, "DBS.200011", "Another operation is being performed on the DB instance %s or the instance is faulty. Try again later.", id)
}

// errStatus is DBS.200086: the instance status does not allow the
// operation.
func errStatus(id, status string) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.200086", "This operation is not allowed for the DB instance %s in status %s.", id, status)
}

func errVolumeRange(lo, hi int) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.200023", "The storage size must be between %d GB and %d GB.", lo, hi)
}

var (
	errVolumeMultiple = dbs(http.StatusBadRequest, "DBS.200027", "The storage size must be a multiple of 10 GB.")
	errVolumeShrink   = dbs(http.StatusBadRequest, "DBS.200306", "The new storage size must be greater than the current size.")
	errPassword       = dbs(http.StatusBadRequest, "DBS.200052", "The root password is invalid: it does not meet the complexity requirements of the DB engine.")
	errPort           = dbs(http.StatusBadRequest, "DBS.280364", "The database port is invalid.")
)

func errName(format string, args ...any) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.200021", format, args...)
}

func errNameExists(name string) *apierr.Error {
	return dbs(http.StatusConflict, "DBS.200022", "The DB instance name %q already exists.", name)
}

func errZone(az string) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.200025", "The availability zone %q is invalid.", az)
}

func errJobNotFound(id string) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.200543", "The job %s does not exist.", id)
}

// errNotImplemented reports a request feature the emulator does not
// support, naming it.
func errNotImplemented(what string) *apierr.Error {
	return apierr.NotImplemented("rds", what)
}

func errBackupNotFound(id string) *apierr.Error {
	return dbs(http.StatusNotFound, "DBS.201010", "The backup %s does not exist.", id)
}

func errBackupStatus(id, status string) *apierr.Error {
	return dbs(http.StatusBadRequest, "DBS.201208", "This operation is not allowed for the backup %s in status %s.", id, status)
}
