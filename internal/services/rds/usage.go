package rds

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
)

// storageUsedSpace mirrors the SDK model rds/v3 ShowStorageUsedSpaceResponse.
type storageUsedSpace struct {
	NodeID string `json:"node_id"`
	// Used is the disk space used, in GB, as a string.
	Used string `json:"used"`
}

// handleStorageUsedSpace reports the primary node's disk usage. No
// database engine runs behind an instance, so nothing is ever stored:
// usage is always zero.
func (s *Service) handleStorageUsedSpace(w http.ResponseWriter, r *http.Request, t Tenant) error {
	inst, err := s.GetInstance(r.Context(), t, chi.URLParam(r, "instance_id"))
	if err != nil {
		return err
	}
	node := ""
	if len(inst.NodeIDs) > 0 {
		node = inst.NodeIDs[0]
	}
	return httpx.WriteJSON(w, http.StatusOK, storageUsedSpace{NodeID: node, Used: "0"})
}
