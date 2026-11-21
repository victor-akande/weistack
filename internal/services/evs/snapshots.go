package evs

import (
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

const autobkSnapshotPrefix = "autobk_snapshot_"

type createSnapshotRequestBody struct {
	Snapshot *createSnapshotOption `json:"snapshot"`
}

type createSnapshotOption struct {
	VolumeID    string            `json:"volume_id"`
	Force       bool              `json:"force"`
	Metadata    map[string]string `json:"metadata"`
	Description string            `json:"description"`
	Name        string            `json:"name"`
}

type updateSnapshotRequestBody struct {
	Snapshot *updateSnapshotOption `json:"snapshot"`
}

type updateSnapshotOption struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type rollbackSnapshotRequestBody struct {
	Rollback *rollbackSnapshotOption `json:"rollback"`
}

type rollbackSnapshotOption struct {
	Name     string `json:"name"`
	VolumeID string `json:"volume_id"`
}

type snapshotResponse struct {
	Snapshot snapshotWire `json:"snapshot"`
}

type listSnapshotsResponse struct {
	Count     int            `json:"count"`
	Snapshots []snapshotWire `json:"snapshots"`
}

type rollbackSnapshotResponse struct {
	Rollback rollbackInfo `json:"rollback"`
}

type rollbackInfo struct {
	VolumeID string `json:"volume_id"`
}

// snapshotWire mirrors the SDK models SnapshotDetails and SnapshotList.
type snapshotWire struct {
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
	Metadata    map[string]string `json:"metadata"`
	VolumeID    string            `json:"volume_id"`
	Size        int               `json:"size"`
	ProjectID   string            `json:"os-extended-snapshot-attributes:project_id"`
	Progress    string            `json:"os-extended-snapshot-attributes:progress"`
	ServiceType string            `json:"service_type"`
}

func snapshotDetail(sn snapshot, projectID string) snapshotWire {
	meta := map[string]string{}
	if len(sn.Metadata) > 0 {
		meta = maps.Clone(sn.Metadata)
	}
	progress := "100%"
	if sn.Status == statusCreating {
		progress = "0%"
	}
	return snapshotWire{
		ID:          sn.ID,
		Status:      sn.Status,
		Name:        sn.Name,
		Description: sn.Description,
		CreatedAt:   sn.CreatedAt,
		UpdatedAt:   sn.UpdatedAt,
		Metadata:    meta,
		VolumeID:    sn.VolumeID,
		Size:        sn.SizeGB,
		ProjectID:   projectID,
		Progress:    progress,
		ServiceType: "EVS",
	}
}

func (s *Service) handleCreateSnapshot(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var body createSnapshotRequestBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return errInvalidRequest
	}
	if body.Snapshot == nil {
		return errInvalidRequest
	}
	opt := *body.Snapshot
	if opt.VolumeID == "" {
		return errInvalidResourceID
	}
	if utf8.RuneCountInString(opt.Name) > maxVolumeNameLen {
		return errInvalidVolumeName
	}
	if utf8.RuneCountInString(opt.Description) > maxVolumeDescLen {
		return errInvalidVolumeDesc
	}

	now := s.now().UTC().Format(volumeTimeLayout)
	snID := s.ids.UUID()

	s.mu.Lock()
	v, err := s.volumes(t).Get(r.Context(), opt.VolumeID)
	if errors.Is(err, store.ErrNotFound) {
		s.mu.Unlock()
		return errVolumeNotFound
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if !canCreateSnapshot(v, opt.Force) {
		s.mu.Unlock()
		return errInvalidResourceStatus
	}

	ep := v.EnterpriseProjectID
	if ep == "" {
		ep = "0"
	}
	sn := snapshot{
		ID:                  snID,
		Name:                opt.Name,
		Description:         opt.Description,
		Status:              statusCreating,
		VolumeID:            v.ID,
		SizeGB:              v.SizeGB,
		VolumeType:          v.VolumeType,
		AvailabilityZone:    v.AvailabilityZone,
		Metadata:            maps.Clone(opt.Metadata),
		EnterpriseProjectID: ep,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.snapshots(t).Create(r.Context(), sn.ID, sn); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	s.scheduleSnapshotCreate(t, sn.ID)
	return httpx.WriteJSON(w, http.StatusAccepted, snapshotResponse{
		Snapshot: snapshotDetail(sn, t.ProjectID),
	})
}

func canCreateSnapshot(v volume, force bool) bool {
	switch v.Status {
	case statusAvailable, statusInUse:
		return true
	case statusAttaching:
		return force
	default:
		return false
	}
}

func (s *Service) handleShowSnapshot(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "snapshot_id")
	sn, err := s.snapshots(t).Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return errVolumeNotFound
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, snapshotResponse{
		Snapshot: snapshotDetail(sn, t.ProjectID),
	})
}

func (s *Service) handleListSnapshots(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseOffset(q, pagination.Limits{Default: maxLimit, Min: 1, Max: 1 << 30})
	switch {
	case errors.Is(err, pagination.ErrInvalidOffset):
		return errInvalidRequest
	case err != nil:
		return errInvalidLimit
	case page.Limit > maxLimit:
		return errLimitTooLarge
	}

	all, err := s.snapshots(t).List(r.Context(), nil)
	if err != nil {
		return err
	}

	var idFilter []string
	for _, id := range q["id"] {
		if id != "" {
			idFilter = append(idFilter, id)
		}
	}
	eq := func(want, got string) bool { return want == "" || want == got }
	matched := make([]snapshot, 0, len(all))
	for _, sn := range all {
		if len(idFilter) > 0 && !slices.Contains(idFilter, sn.ID) {
			continue
		}
		if !eq(q.Get("name"), sn.Name) ||
			!eq(q.Get("status"), sn.Status) ||
			!eq(q.Get("volume_id"), sn.VolumeID) ||
			!eq(q.Get("availability_zone"), sn.AvailabilityZone) {
			continue
		}
		if ep := q.Get("enterprise_project_id"); ep != "" && ep != "all_granted_eps" {
			snEP := sn.EnterpriseProjectID
			if snEP == "" {
				snEP = "0"
			}
			if snEP != ep {
				continue
			}
		}
		matched = append(matched, sn)
	}

	out := listSnapshotsResponse{Count: len(matched), Snapshots: []snapshotWire{}}
	for _, sn := range pagination.ByOffset(matched, page) {
		out.Snapshots = append(out.Snapshots, snapshotDetail(sn, t.ProjectID))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) handleUpdateSnapshot(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "snapshot_id")
	var body updateSnapshotRequestBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return errInvalidRequest
	}
	if body.Snapshot == nil || (body.Snapshot.Name == nil && body.Snapshot.Description == nil) {
		return errUpdateBothEmpty
	}
	opt := body.Snapshot
	if opt.Name != nil && utf8.RuneCountInString(*opt.Name) > maxVolumeNameLen {
		return errInvalidVolumeName
	}
	if opt.Description != nil && utf8.RuneCountInString(*opt.Description) > maxVolumeDescLen {
		return errInvalidVolumeDesc
	}

	now := s.now().UTC().Format(volumeTimeLayout)
	s.mu.Lock()
	updated, err := s.snapshots(t).Update(r.Context(), id, func(sn *snapshot) error {
		if opt.Name != nil {
			sn.Name = *opt.Name
		}
		if opt.Description != nil {
			sn.Description = *opt.Description
		}
		sn.UpdatedAt = now
		return nil
	})
	s.mu.Unlock()
	if errors.Is(err, store.ErrNotFound) {
		return errVolumeNotFound
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, snapshotResponse{
		Snapshot: snapshotDetail(updated, t.ProjectID),
	})
}

func (s *Service) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "snapshot_id")

	s.mu.Lock()
	sn, err := s.snapshots(t).Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.mu.Unlock()
		return errVolumeNotFound
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if sn.Status != statusAvailable && sn.Status != statusError {
		s.mu.Unlock()
		return errDeleteSnapshotInvalidStatus
	}
	err = s.snapshots(t).Delete(r.Context(), id)
	s.mu.Unlock()
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusAccepted)
	return nil
}

func (s *Service) handleRollbackSnapshot(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "snapshot_id")
	var body rollbackSnapshotRequestBody
	if err := httpx.DecodeJSON(r, &body); err != nil {
		return errInvalidRequest
	}
	if body.Rollback == nil {
		return errInvalidRequest
	}
	if body.Rollback.VolumeID == "" {
		return errInvalidResourceID
	}

	now := s.now().UTC().Format(volumeTimeLayout)
	s.mu.Lock()
	sn, err := s.snapshots(t).Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.mu.Unlock()
		return errVolumeNotFound
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if strings.HasPrefix(sn.Name, autobkSnapshotPrefix) {
		s.mu.Unlock()
		return errInvalidResourceStatus
	}
	if body.Rollback.VolumeID != sn.VolumeID {
		s.mu.Unlock()
		return errInvalidResourceID
	}
	if sn.Status != statusAvailable {
		s.mu.Unlock()
		return errSnapshotUnavailable
	}

	v, err := s.volumes(t).Get(r.Context(), sn.VolumeID)
	if errors.Is(err, store.ErrNotFound) {
		s.mu.Unlock()
		return errVolumeNotFound
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if (v.Status != statusAvailable && v.Status != statusErrorRollbacking) || v.Pending != nil {
		s.mu.Unlock()
		return errInvalidResourceStatus
	}

	_, err = s.volumes(t).Update(r.Context(), v.ID, func(cur *volume) error {
		cur.Status = statusRollbacking
		cur.Pending = &pending{Op: "rollback", SnapshotID: sn.ID}
		cur.UpdatedAt = now
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		return err
	}

	s.scheduleSnapshotRollback(t, v.ID)
	return httpx.WriteJSON(w, http.StatusAccepted, rollbackSnapshotResponse{
		Rollback: rollbackInfo{VolumeID: v.ID},
	})
}
