package rds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/reqctx"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/zones"
)

// Routes implements server.Service. Paths are those of the real API.
func (s *Service) Routes(r chi.Router) {
	r.Route("/v3/{project_id}", func(r chi.Router) {
		r.Get("/datastores/{database_name}", s.handle("ListDatastores", s.handleListDatastores))
		r.Get("/flavors/{database_name}", s.handle("ListFlavors", s.handleListFlavors))
		r.Post("/instances", s.handle("CreateInstance", s.handleCreate))
		r.Get("/instances", s.handle("ListInstances", s.handleList))
		r.Delete("/instances/{instance_id}", s.handle("DeleteInstance", s.handleDelete))
		r.Post("/instances/{instance_id}/action", s.handle("InstanceAction", s.handleAction))
		r.Post("/backups", s.handle("CreateManualBackup", s.handleCreateBackup))
		r.Get("/backups", s.handle("ListBackups", s.handleListBackups))
		r.Delete("/backups/{backup_id}", s.handle("DeleteManualBackup", s.handleDeleteBackup))
		r.Get("/jobs", s.handle("ListJobInfo", s.handleShowJob))
	})
}

type handler func(w http.ResponseWriter, r *http.Request, t Tenant) error

// handle adapts a handler: it names the operation for logs, resolves the
// tenant and renders errors in the RDS envelope.
func (s *Service) handle(op string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := reqctx.From(r.Context())
		info.SetOperation(op)
		t := Tenant{Region: info.Region, ProjectID: chi.URLParam(r, "project_id")}
		err := fn(w, r, t)
		if err == nil {
			return
		}
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(r.Context(), "rds operation failed", "operation", op, "error", err)
		}
		apierr.Write(w, r, apierr.StyleFlat, err)
	}
}

// engineFromPath resolves the {database_name} of a path.
func engineFromPath(r *http.Request) (Engine, error) {
	name := chi.URLParam(r, "database_name")
	if unemulated(name) {
		return Engine{}, errNotImplemented("the " + name + " engine")
	}
	e, ok := engineNamed(name)
	if !ok {
		return Engine{}, errInvalid("The DB engine %q is not supported.", name)
	}
	return e, nil
}

func (s *Service) handleListDatastores(w http.ResponseWriter, r *http.Request, _ Tenant) error {
	e, err := engineFromPath(r)
	if err != nil {
		return err
	}
	res := listDatastoresResponse{DataStores: make([]datastoreVersion, 0, len(e.Versions))}
	for _, v := range e.Versions {
		res.DataStores = append(res.DataStores, datastoreVersion{ID: nameUUID("weistack:rds:datastore:" + e.Name + ":" + v), Name: v})
	}
	return httpx.WriteJSON(w, http.StatusOK, res)
}

func (s *Service) handleListFlavors(w http.ResponseWriter, r *http.Request, t Tenant) error {
	e, err := engineFromPath(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	version, spec := q.Get("version_name"), q.Get("spec_code")
	if version != "" && !slices.Contains(e.Versions, version) {
		return errEngineUnsupported(e.Name, version)
	}
	res := listFlavorsResponse{Flavors: []Flavor{}}
	for _, f := range flavorsOf(e) {
		if spec != "" && f.Code != spec {
			continue
		}
		fl := Flavor{
			ID: nameUUID("weistack:rds:flavor:" + f.Code), VCPUs: strconv.Itoa(f.VCPUs), RAM: f.RAMGB,
			SpecCode: f.Code, InstanceMode: strings.ToLower(f.Mode), GroupType: "general",
			AZStatus: map[string]string{}, AZDesc: map[string]string{}, VersionName: e.Versions,
		}
		for _, az := range zones.Of(t.Region) {
			fl.AZStatus[az], fl.AZDesc[az] = "normal", az
		}
		res.Flavors = append(res.Flavors, fl)
	}
	return httpx.WriteJSON(w, http.StatusOK, res)
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var opt CreateInstanceOption
	if err := httpx.DecodeJSON(r, &opt); err != nil {
		return errInvalid("The request body is invalid: %s", err)
	}
	inst, job, err := s.CreateInstance(r.Context(), t, opt)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusAccepted, createInstanceResponse{Instance: inst.created(), JobID: job.ID})
}

// Paging of ListInstances: offset is an index, limit 1 to 100.
const maxListLimit = 100

// parseTags reads the tags filter: "key=value" pairs, comma-separated; a
// bare key matches any value.
func parseTags(raw string) []Tag {
	var out []Tag
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		out = append(out, Tag{Key: k, Value: v})
	}
	return out
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	offset, limit := 0, maxListLimit
	if raw := q.Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return errInvalid("offset must be a non-negative integer")
		}
		offset = n
	}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxListLimit {
			return errInvalid("limit must be an integer from 1 to %d", maxListLimit)
		}
		limit = n
	}
	if id := q.Get("id"); id == "*" {
		return errInvalid("id cannot be only *")
	}
	all, err := s.ListInstances(r.Context(), t, ListInstancesFilter{
		ID: q.Get("id"), Name: q.Get("name"), Type: q.Get("type"), Engine: q.Get("datastore_type"),
		VPCID: q.Get("vpc_id"), SubnetID: q.Get("subnet_id"), EnterpriseProjectID: q.Get("eps_id"),
		Tags: parseTags(q.Get("tags")),
	})
	if err != nil {
		return err
	}
	res := listInstancesResponse{TotalCount: len(all), Instances: []InstanceResponse{}}
	if offset < len(all) {
		for _, inst := range all[offset:min(offset+limit, len(all))] {
			res.Instances = append(res.Instances, inst.view())
		}
	}
	return httpx.WriteJSON(w, http.StatusOK, res)
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request, t Tenant) error {
	job, err := s.DeleteInstance(r.Context(), t, chi.URLParam(r, "instance_id"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusAccepted, jobIDResponse{JobID: job.ID})
}

func (s *Service) handleShowJob(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := r.URL.Query().Get("id")
	if id == "" {
		return errInvalid("id is required")
	}
	job, err := s.GetJob(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, jobResponse{Job: job})
}

// handleAction serves restart, resize and storage scaling, which share
// one path and are told apart by the body's single top-level key.
func (s *Service) handleAction(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req actionRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return errInvalid("The request body is invalid: %s", err)
	}
	id := chi.URLParam(r, "instance_id")
	info := reqctx.From(r.Context())
	var (
		job Job
		err error
	)
	switch {
	case req.Restart != nil && req.ResizeFlavor == nil && req.EnlargeVolume == nil:
		info.SetOperation("StartInstanceRestartAction")
		job, err = s.RestartInstance(r.Context(), t, id)
	case req.ResizeFlavor != nil && req.Restart == nil && req.EnlargeVolume == nil:
		info.SetOperation("StartResizeFlavorAction")
		job, err = s.ResizeInstance(r.Context(), t, id, *req.ResizeFlavor)
	case req.EnlargeVolume != nil && req.Restart == nil && req.ResizeFlavor == nil:
		info.SetOperation("StartInstanceEnlargeVolumeAction")
		job, err = s.EnlargeVolume(r.Context(), t, id, *req.EnlargeVolume)
	default:
		return errInvalid("The request body must contain exactly one of restart, resize_flavor and enlarge_volume.")
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusAccepted, jobIDResponse{JobID: job.ID})
}

func (s *Service) handleCreateBackup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var opt CreateBackupOption
	if err := httpx.DecodeJSON(r, &opt); err != nil {
		return errInvalid("The request body is invalid: %s", err)
	}
	b, err := s.CreateBackup(r.Context(), t, opt)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusAccepted, createBackupResponse{Backup: backupInfo{
		ID: b.ID, InstanceID: b.InstanceID, Name: b.Name, Description: b.Description, Databases: b.Databases,
		BeginTime: b.BeginTime, Status: b.Status, Type: b.Type,
	}})
}

func (s *Service) handleListBackups(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	instanceID := q.Get("instance_id")
	if instanceID == "" {
		return errInvalid("instance_id is required")
	}
	offset, limit := 0, maxListLimit
	if raw := q.Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return errInvalid("offset must be a non-negative integer")
		}
		offset = n
	}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxListLimit {
			return errInvalid("limit must be an integer from 1 to %d", maxListLimit)
		}
		limit = n
	}
	all, err := s.ListBackups(r.Context(), t, instanceID, q.Get("backup_id"), q.Get("backup_type"), q.Get("status"))
	if err != nil {
		return err
	}
	res := listBackupsResponse{TotalCount: len(all), Backups: []backupForList{}}
	if offset < len(all) {
		for _, b := range all[offset:min(offset+limit, len(all))] {
			res.Backups = append(res.Backups, backupForList{
				ID: b.ID, InstanceID: b.InstanceID, Name: b.Name, Databases: b.Databases, BeginTime: b.BeginTime,
				EndTime: b.EndTime, Status: b.Status, Type: b.Type, Size: b.Size, Datastore: b.Datastore,
			})
		}
	}
	return httpx.WriteJSON(w, http.StatusOK, res)
}

func (s *Service) handleDeleteBackup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if err := s.DeleteBackup(r.Context(), t, chi.URLParam(r, "backup_id")); err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, struct{}{})
}

// Resume continues the operations that were in flight when a persistent
// emulator last stopped. Call it once at startup.
func (s *Service) Resume(ctx context.Context) error {
	dump, err := s.store.Dump(ctx)
	if err != nil {
		return fmt.Errorf("rds: resuming operations: %w", err)
	}
	for key, recs := range dump {
		scope, err := store.ParseScope(key)
		if err != nil || scope.Kind != kindInstance {
			continue
		}
		t := Tenant{Region: scope.Region, ProjectID: scope.ProjectID}
		for _, rec := range recs {
			var inst Instance
			if err := json.Unmarshal(rec.Data, &inst); err != nil {
				return fmt.Errorf("rds: decoding %s/%s: %w", key, rec.ID, err)
			}
			if inst.Pending != nil {
				s.schedule(t, inst.ID, *inst.Pending)
			}
		}
	}
	return nil
}
