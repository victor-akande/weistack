package evs

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
)

// Error catalogue from error-codes.tsv.
var (
	errVolumeNotFound = apierr.New(http.StatusNotFound, "EVS.5404", "Resource(Volume, Snapshot, Backup .etc) cound not be found.")
	errInvalidLimit   = apierr.New(http.StatusBadRequest, "EVS.1023", "invalid filter limit!")
	errLimitTooLarge  = apierr.New(http.StatusBadRequest, "EVS.2142", "invalid filter limit, can not greater than 1000.")
	errInvalidRequest = apierr.New(http.StatusBadRequest, "EVS.1070", "invalid request.")
)
