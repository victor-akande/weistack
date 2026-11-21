package evs

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error catalogue from error-codes.tsv.
var (
	errVolumeNotFound      = apierr.New(http.StatusNotFound, "EVS.5404", "Resource(Volume, Snapshot, Backup .etc) cound not be found.")
	errInvalidLimit        = apierr.New(http.StatusBadRequest, "EVS.1023", "invalid filter limit!")
	errLimitTooLarge       = apierr.New(http.StatusBadRequest, "EVS.2142", "invalid filter limit, can not greater than 1000.")
	errInvalidRequest      = apierr.New(http.StatusBadRequest, "EVS.1070", "invalid request.")
	errInvalidVolumeName   = apierr.New(http.StatusBadRequest, "EVS.1003", "invalid volume name!")
	errInvalidVolumeDesc   = apierr.New(http.StatusBadRequest, "EVS.1004", "invalid volume description!")
	errInvalidBackupID     = apierr.New(http.StatusBadRequest, "EVS.1006", "invalid backup id!")
	errUpdateBothEmpty     = apierr.New(http.StatusBadRequest, "EVS.1007", "volume name and description can not both be empty!")
	errNullCreateVolumeReq = apierr.New(http.StatusBadRequest, "EVS.1008", "null createVolumeReq!")
	errInvalidVolumeSize   = apierr.New(http.StatusBadRequest, "EVS.1010", "invalid volume size!")
	errMultipleSources     = apierr.New(http.StatusBadRequest, "EVS.1016", "Invalid input received: May specify only one of imageRef, snapshot_id, backup_id!")
	errInvalidVolumeType   = apierr.New(http.StatusBadRequest, "EVS.1020", "invalid volume type!")
	errInvalidVolumeCount  = apierr.New(http.StatusBadRequest, "EVS.1021", "the quantity of volume is invalid!")
	errInvalidAZ           = apierr.New(http.StatusBadRequest, "EVS.1036", "invalid availability zone!")
	errDeleteInvalidStatus = apierr.New(http.StatusBadRequest, "EVS.1046", "volume status must be available, error, error_extending, error_restoring, error_rollbacking when delete volume!")
	errInvalidPassthrough  = apierr.New(http.StatusBadRequest, "EVS.1057", "invalid hw:passthrough in metadata!")
	errTooManyTags         = apierr.New(http.StatusBadRequest, "EVS.1061", "The Volume Tags is Exceed Max Limit Num.")
	errInvalidTag          = apierr.New(http.StatusBadRequest, "EVS.1062", "invalid tag!")
	errInvalidBssParam     = apierr.New(http.StatusBadRequest, "EVS.2147", "invalid bssParam.")
	errServerNotFound      = apierr.New(http.StatusBadRequest, "EVS.2229", "input server id not found at ECS.")
	errServerAZMismatch    = apierr.New(http.StatusBadRequest, "EVS.2263", "input available-zone is not equal to ecs available-zone!")
	errJobNotFound         = apierr.New(http.StatusBadRequest, "Common.0011", "No jobs found.")
)
