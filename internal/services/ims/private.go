package ims

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	maxNameLen        = 128
	maxDescriptionLen = 1024
	defaultMinDiskGB  = 40
	defaultEnterprise = "0"
)

// imageNameRE: letters (any script), digits, spaces, hyphens,
// underscores and periods.
var imageNameRE = regexp.MustCompile(`^[\p{L}\p{N} _.\-]+$`)

func checkImageName(name string) error {
	switch {
	case name == "":
		return errNameMissing
	case utf8.RuneCountInString(name) > maxNameLen:
		return errNameTooLong
	case !imageNameRE.MatchString(name) || strings.TrimSpace(name) != name:
		return errNameFormat
	}
	return nil
}

func checkImageDescription(desc string) error {
	switch {
	case utf8.RuneCountInString(desc) > maxDescriptionLen:
		return errDescTooLong
	case strings.ContainsAny(desc, "<>\r\n"):
		return errDescFormat
	}
	return nil
}

// checkNameFree enforces that private image names are unique within a
// project. The caller must hold s.mu.
func (s *Service) checkNameFree(ctx context.Context, t Tenant, name, exceptID string) error {
	clash, err := s.privateImages(t).List(ctx, func(img Image) bool { return img.Name == name && img.ID != exceptID })
	if err != nil {
		return err
	}
	if len(clash) > 0 {
		return errNameInUse(name)
	}
	return nil
}

// CreateImage starts creating a private system disk image from a
// server and returns the job that tracks it. The image exists at once
// in status queued, turns saving and then active.
func (s *Service) CreateImage(ctx context.Context, t Tenant, opt CreateImageOption) (Job, error) {
	// Report the creation modes that are not emulated as gaps rather
	// than as bad requests.
	switch {
	case opt.ImageURL != nil:
		return Job{}, apierr.NotImplemented("ims", "CreateImage from an image file (image_url)")
	case opt.VolumeID != nil:
		return Job{}, apierr.NotImplemented("ims", "CreateImage from a data disk (volume_id)")
	case len(opt.DataImages) > 0 && string(opt.DataImages) != "null":
		return Job{}, apierr.NotImplemented("ims", "CreateImage with data disk images (data_images)")
	}

	if err := checkImageName(opt.Name); err != nil {
		return Job{}, err
	}
	if err := checkImageDescription(opt.Description); err != nil {
		return Job{}, err
	}
	if !uuidRE.MatchString(opt.InstanceID) {
		return Job{}, errInstanceInvalid
	}
	for name, v := range map[string]*int{"min_ram": opt.MinRAM, "max_ram": opt.MaxRAM} {
		if v != nil && *v < 0 {
			return Job{}, errInvalidRequest("%s must not be negative", name)
		}
	}
	if opt.MinRAM != nil && opt.MaxRAM != nil && *opt.MaxRAM != 0 && *opt.MaxRAM < *opt.MinRAM {
		return Job{}, errInvalidRequest("max_ram must not be less than min_ram")
	}
	tags, err := imageTags(opt)
	if err != nil {
		return Job{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.servers == nil {
		return Job{}, errServerNotFound(opt.InstanceID)
	}
	server, err := s.servers.LookupServer(ctx, t.Region, t.ProjectID, opt.InstanceID)
	if errors.Is(err, ErrServerNotFound) {
		return Job{}, errServerNotFound(opt.InstanceID)
	}
	if err != nil {
		return Job{}, err
	}
	if err := s.checkNameFree(ctx, t, opt.Name, ""); err != nil {
		return Job{}, err
	}

	now := s.now().UTC()
	created := Time(now.Truncate(time.Second))
	img := Image{
		ID:                  s.ids.UUID(),
		Name:                opt.Name,
		Description:         opt.Description,
		DataOrigin:          "instance," + server.ID,
		Status:              StatusQueued,
		ImageType:           TypePrivate,
		Visibility:          VisibilityPrivate,
		Owner:               t.ProjectID,
		IsRegistered:        "false",
		ImageSourceType:     "uds",
		ContainerFormat:     "bare",
		DiskFormat:          "zvhd2",
		VirtualEnvType:      "FusionCompute",
		HwFirmwareType:      "bios",
		OSType:              "Linux",
		OSBit:               "64",
		Platform:            "Other",
		OSVersion:           "Other Linux(64 bit)",
		MinDisk:             defaultMinDiskGB,
		EnterpriseProjectID: defaultEnterprise,
		Tags:                tags,
		CreatedAt:           created,
		UpdatedAt:           created,
	}
	// The image takes its operating system from the image the server
	// was built from.
	if server.ImageID != "" {
		if src, err := s.GetImage(ctx, t, server.ImageID); err == nil {
			img.OSType, img.OSBit, img.Platform, img.OSVersion = src.OSType, src.OSBit, src.Platform, src.OSVersion
			img.HwFirmwareType, img.SupportArm = src.HwFirmwareType, src.SupportArm
			img.MinDisk, img.MinRAM = src.MinDisk, src.MinRAM
		}
	}
	if server.SystemDiskGB > 0 {
		img.MinDisk = server.SystemDiskGB
	}
	if opt.MinRAM != nil {
		img.MinRAM = *opt.MinRAM
	}
	if opt.MaxRAM != nil && *opt.MaxRAM > 0 {
		img.MaxRAM = strconv.Itoa(*opt.MaxRAM)
	}
	if opt.EnterpriseProjectID != "" {
		if opt.EnterpriseProjectID != defaultEnterprise && !uuidRE.MatchString(opt.EnterpriseProjectID) {
			return Job{}, errInvalidRequest("enterprise_project_id %q is invalid", opt.EnterpriseProjectID)
		}
		img.EnterpriseProjectID = opt.EnterpriseProjectID
	}
	img.setLinks()

	job := Job{
		Status:    JobRunning,
		JobID:     s.ids.Hex32(),
		JobType:   jobTypeCreateImage,
		BeginTime: now.Format(jobTimeLayout),
		Entities:  JobEntities{ImageID: img.ID},
	}
	if err := s.privateImages(t).Create(ctx, img.ID, img); err != nil {
		return Job{}, err
	}
	if err := s.jobs(t).Create(ctx, job.JobID, job); err != nil {
		return Job{}, err
	}
	s.scheduleSave(t, img.ID, job.JobID)
	return job, nil
}

// imageTags merges the two tag forms of the request into the image's
// tag list: "tags" entries as given, "image_tags" pairs as "key=value".
func imageTags(opt CreateImageOption) ([]string, error) {
	if len(opt.Tags) > 0 && len(opt.ImageTags) > 0 {
		return nil, errInvalidRequest("tags and image_tags cannot be used together")
	}
	out := []string{}
	for _, tag := range opt.Tags {
		if tag == "" {
			return nil, errInvalidRequest("tags must not contain an empty string")
		}
		out = append(out, tag)
	}
	for _, kv := range opt.ImageTags {
		if kv.Key == "" {
			return nil, errInvalidRequest("image_tags keys must not be empty")
		}
		out = append(out, kv.Key+"="+kv.Value)
	}
	return out, nil
}

// scheduleSave queues the first step of image creation: queued -> saving.
func (s *Service) scheduleSave(t Tenant, imageID, jobID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  imageID,
		Kind: taskImageSave,
		Run: func(ctx context.Context, fault error) {
			if fault != nil {
				s.failCreation(ctx, t, imageID, jobID, fault)
				return
			}
			if s.setStatus(ctx, t, imageID, StatusSaving) {
				s.scheduleActivate(t, imageID, jobID)
			}
		},
	})
}

// scheduleActivate queues the second step: saving -> active, job done.
func (s *Service) scheduleActivate(t Tenant, imageID, jobID string) {
	s.engine.Schedule(lifecycle.Task{
		Key:  imageID,
		Kind: taskImageActivate,
		Run: func(ctx context.Context, fault error) {
			if fault != nil {
				s.failCreation(ctx, t, imageID, jobID, fault)
				return
			}
			if s.setStatus(ctx, t, imageID, StatusActive) {
				s.finishJob(ctx, t, jobID, JobSuccess, "")
			}
		},
	})
}

// setStatus moves an image to status and reports whether it still exists.
func (s *Service) setStatus(ctx context.Context, t Tenant, imageID, status string) bool {
	now := Time(s.now().UTC().Truncate(time.Second))
	_, err := s.privateImages(t).Update(ctx, imageID, func(img *Image) error {
		img.Status = status
		img.UpdatedAt = now
		if status == StatusActive {
			img.ActiveAt = &now
			img.Checksum = emptyChecksum
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.ErrorContext(ctx, "image transition failed", "image_id", imageID, "status", status, "error", err)
		}
		return false
	}
	return true
}

func (s *Service) failCreation(ctx context.Context, t Tenant, imageID, jobID string, cause error) {
	s.setStatus(ctx, t, imageID, StatusKilled)
	s.finishJob(ctx, t, jobID, JobFail, cause.Error())
}

func (s *Service) finishJob(ctx context.Context, t Tenant, jobID, status, reason string) {
	end := s.now().UTC().Format(jobTimeLayout)
	_, err := s.jobs(t).Update(ctx, jobID, func(j *Job) error {
		j.Status = status
		j.EndTime = end
		if status == JobFail {
			code := jobFailureCode
			j.ErrorCode, j.FailReason = &code, &reason
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "finishing job failed", "job_id", jobID, "error", err)
	}
}

// GetJob returns an asynchronous job of the project.
func (s *Service) GetJob(ctx context.Context, t Tenant, id string) (Job, error) {
	job, err := s.jobs(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return Job{}, errJobQuery(id)
	}
	return job, err
}

// ownImage loads a private image of the tenant for modification,
// distinguishing "public, not yours" from "does not exist".
func (s *Service) ownImage(ctx context.Context, t Tenant, id string, public func(string) *apierr.Error) (Image, error) {
	img, err := s.privateImages(t).Get(ctx, id)
	if err == nil {
		return img, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return Image{}, err
	}
	if err := s.ensureSeeded(ctx, t.Region); err != nil {
		return Image{}, err
	}
	if _, err := s.publicImages(t.Region).Get(ctx, id); err == nil {
		return Image{}, public(id)
	}
	return Image{}, errImageNotFound(id)
}

// patchValue reads the value of a patch operation, which the SDK sends
// as a string and other clients may send as a number.
func patchValue(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String(), nil
	}
	return "", errInvalidRequest("value must be a string or a number")
}

// applyPatch applies one operation to img.
func applyPatch(img *Image, op PatchOp) error {
	action := strings.ToLower(op.Op)
	if action != "add" && action != "replace" && action != "remove" {
		return errInvalidRequest("op %q must be add, replace or remove", op.Op)
	}
	if !strings.HasPrefix(op.Path, "/") {
		return errInvalidRequest("path %q must start with a slash", op.Path)
	}
	field := strings.TrimPrefix(op.Path, "/")

	var value string
	if action != "remove" {
		if len(op.Value) == 0 {
			return errInvalidRequest("op %s on %s needs a value", action, op.Path)
		}
		var err error
		if value, err = patchValue(op.Value); err != nil {
			return err
		}
	}

	switch field {
	case "name":
		if action == "remove" {
			return errNameMissing
		}
		if err := checkImageName(value); err != nil {
			return err
		}
		img.Name = value
	case "__description":
		if err := checkImageDescription(value); err != nil {
			return err
		}
		img.Description = value
	case "min_ram":
		n := 0
		if action != "remove" {
			var err error
			if n, err = strconv.Atoi(value); err != nil || n < 0 {
				return errInvalidRequest("min_ram %q must be a non-negative integer", value)
			}
		}
		img.MinRAM = n
	case "max_ram":
		if action != "remove" {
			if n, err := strconv.Atoi(value); err != nil || n < 0 {
				return errInvalidRequest("max_ram %q must be a non-negative integer", value)
			}
		}
		img.MaxRAM = value
	case "hw_firmware_type":
		if value != "bios" && value != "uefi" {
			return errInvalidRequest("hw_firmware_type must be bios or uefi")
		}
		img.HwFirmwareType = value
	case "enterprise_project_id":
		if value != defaultEnterprise && !uuidRE.MatchString(value) {
			return errInvalidRequest("enterprise_project_id %q is invalid", value)
		}
		img.EnterpriseProjectID = value
	default:
		return apierr.NotImplemented("ims", fmt.Sprintf("UpdateImage of attribute %s", op.Path))
	}
	return nil
}

// UpdateImage applies patch operations to an active private image and
// returns the result. Either every operation applies or none does.
func (s *Service) UpdateImage(ctx context.Context, t Tenant, id string, ops []PatchOp) (Image, error) {
	if len(ops) == 0 {
		return Image{}, errEmptyBody
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := s.ownImage(ctx, t, id, errNotOwner)
	if err != nil {
		return Image{}, err
	}
	if cur.Status != StatusActive {
		return Image{}, errImageUnavailable(id, cur.Status)
	}
	next := cur
	for _, op := range ops {
		if err := applyPatch(&next, op); err != nil {
			return Image{}, err
		}
	}
	if next.MaxRAM != "" && next.MaxRAM != "0" {
		if maxRAM, _ := strconv.Atoi(next.MaxRAM); maxRAM < next.MinRAM {
			return Image{}, errInvalidRequest("max_ram must not be less than min_ram")
		}
	}
	if next.Name != cur.Name {
		if err := s.checkNameFree(ctx, t, next.Name, id); err != nil {
			return Image{}, err
		}
	}
	next.UpdatedAt = Time(s.now().UTC().Truncate(time.Second))
	if err := s.privateImages(t).Put(ctx, id, next); err != nil {
		return Image{}, err
	}
	return next, nil
}

// DeleteImage removes a private image. Public images, protected images
// and images still being created cannot be deleted.
func (s *Service) DeleteImage(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	img, err := s.ownImage(ctx, t, id, errPublicImageDelete)
	if err != nil {
		return err
	}
	switch {
	case img.Status == StatusQueued || img.Status == StatusSaving:
		return errImageBeingCreated(id)
	case img.Protected:
		return errImageProtected(id)
	}
	if err := s.privateImages(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s.engine.Cancel(id)
	return nil
}

// Resume reschedules image creations that were in flight when a
// persistent emulator last stopped. Call it once at startup.
func (s *Service) Resume(ctx context.Context) error {
	dump, err := s.store.Dump(ctx)
	if err != nil {
		return fmt.Errorf("ims: resuming transitions: %w", err)
	}
	for key, recs := range dump {
		scope, err := store.ParseScope(key)
		if err != nil || scope.Kind != kindJob {
			continue
		}
		t := Tenant{Region: scope.Region, ProjectID: scope.ProjectID}
		for _, rec := range recs {
			var job Job
			if err := json.Unmarshal(rec.Data, &job); err != nil {
				return fmt.Errorf("ims: decoding %s/%s: %w", key, rec.ID, err)
			}
			if job.Status != JobRunning {
				continue
			}
			img, err := s.privateImages(t).Get(ctx, job.Entities.ImageID)
			switch {
			case errors.Is(err, store.ErrNotFound):
				s.finishJob(ctx, t, job.JobID, JobFail, "the image no longer exists")
			case err != nil:
				return err
			case img.Status == StatusQueued:
				s.scheduleSave(t, img.ID, job.JobID)
			case img.Status == StatusSaving:
				s.scheduleActivate(t, img.ID, job.JobID)
			default:
				// The image finished but the job was not closed.
				s.finishJob(ctx, t, job.JobID, JobSuccess, "")
			}
		}
	}
	return nil
}
