package ims

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/victor-akande/weistack/internal/core/wiretime"
)

// Time is a timestamp in the IMS wire format ("2018-09-06T14:03:27Z").
type Time time.Time

// MarshalJSON implements json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	return wiretime.AppendQuoted(make([]byte, 0, 24), time.Time(t), true), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Time) UnmarshalJSON(b []byte) error {
	parsed, err := wiretime.ParseQuoted(b, true)
	if err != nil {
		return fmt.Errorf("ims: timestamp %s: %w", b, err)
	}
	*t = Time(parsed)
	return nil
}

// Image statuses.
const (
	StatusQueued = "queued"
	StatusSaving = "saving"
	StatusActive = "active"
	StatusKilled = "killed"
)

// Image types (__imagetype) and visibilities.
const (
	TypeGold    = "gold" // a public image
	TypePrivate = "private"

	VisibilityPublic  = "public"
	VisibilityPrivate = "private"
)

// Image mirrors the SDK model ims/v2 ImageInfo, limited to the fields
// the real service returns for the images WeiStack can hold. It is both
// the stored record and the response body. Field order follows the
// example response in the API reference.
type Image struct {
	Schema              string   `json:"schema"`
	MinDisk             int      `json:"min_disk"`
	CreatedAt           Time     `json:"created_at"`
	ImageSourceType     string   `json:"__image_source_type"`
	ContainerFormat     string   `json:"container_format"`
	File                string   `json:"file"`
	UpdatedAt           Time     `json:"updated_at"`
	Protected           bool     `json:"protected"`
	Checksum            string   `json:"checksum"`
	ID                  string   `json:"id"`
	IsRegistered        string   `json:"__isregistered"`
	MinRAM              int      `json:"min_ram"`
	LazyLoading         string   `json:"__lazyloading,omitempty"`
	Owner               string   `json:"owner"`
	OSType              string   `json:"__os_type"`
	ImageType           string   `json:"__imagetype"`
	Visibility          string   `json:"visibility"`
	VirtualEnvType      string   `json:"virtual_env_type"`
	Tags                []string `json:"tags"`
	Platform            string   `json:"__platform"`
	Size                int64    `json:"size"`
	OSBit               string   `json:"__os_bit"`
	OSVersion           string   `json:"__os_version"`
	Name                string   `json:"name"`
	Self                string   `json:"self"`
	DiskFormat          string   `json:"disk_format"`
	VirtualSize         *int64   `json:"virtual_size"`
	HwFirmwareType      string   `json:"hw_firmware_type"`
	Status              string   `json:"status"`
	SupportArm          string   `json:"__support_arm,omitempty"`
	ActiveAt            *Time    `json:"active_at,omitempty"`
	Description         string   `json:"__description,omitempty"`
	DataOrigin          string   `json:"__data_origin,omitempty"`
	EnterpriseProjectID string   `json:"enterprise_project_id,omitempty"`
	MaxRAM              string   `json:"max_ram,omitempty"`
}

// ListImagesFilter selects and orders images in ListImages. Empty
// fields match everything.
type ListImagesFilter struct {
	ImageType       string // __imagetype
	Visibility      string
	ID              string
	Name            string
	Status          string
	Platform        string // __platform
	OSType          string // __os_type
	OSBit           string // __os_bit
	Owner           string
	Tag             string
	DiskFormat      string
	ContainerFormat string
	VirtualEnvType  string
	Protected       *bool
	// SortKey is one of the sortKeys; SortDir is "asc" or "desc".
	SortKey string
	SortDir string
}

// pageInfo mirrors the SDK model ims/v2 PageInfo.
type pageInfo struct {
	NextMarker string `json:"next_marker"`
}

type listImagesResponse struct {
	Images   []Image   `json:"images"`
	PageInfo *pageInfo `json:"page_info,omitempty"`
}

// CreateImageOption mirrors the SDK model ims/v2 CreateImageRequestBody,
// limited to creating a system disk image from a server.
type CreateImageOption struct {
	Name                string        `json:"name"`
	Description         string        `json:"description"`
	InstanceID          string        `json:"instance_id"`
	EnterpriseProjectID string        `json:"enterprise_project_id"`
	Tags                []string      `json:"tags"`
	ImageTags           []TagKeyValue `json:"image_tags"`
	MaxRAM              *int          `json:"max_ram"`
	MinRAM              *int          `json:"min_ram"`
	// The fields below select creation modes the emulator does not
	// support; they are decoded so the gap can be reported by name.
	ImageURL   *string         `json:"image_url"`
	VolumeID   *string         `json:"volume_id"`
	DataImages json.RawMessage `json:"data_images"`
}

// TagKeyValue mirrors the SDK model ims/v2 TagKeyValue.
type TagKeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// PatchOp mirrors the SDK model ims/v2 UpdateImageRequestBody: one
// JSON-patch-like operation of an image update. Value is a string in
// the SDK; numbers are accepted too.
type PatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type createImageResponse struct {
	JobID string `json:"job_id"`
}

// Job statuses.
const (
	JobRunning = "RUNNING"
	JobSuccess = "SUCCESS"
	JobFail    = "FAIL"
)

// jobTypeCreateImage is the job_type of an image created from a server.
const jobTypeCreateImage = "createImageByInstance"

// jobTimeLayout is the timestamp format of job records.
const jobTimeLayout = "2006-01-02T15:04:05.000Z"

// Job mirrors the SDK model ims/v2 ShowJobResponse. It is both the
// stored record and the response body.
type Job struct {
	Status     string      `json:"status"`
	Entities   JobEntities `json:"entities"`
	JobID      string      `json:"job_id"`
	JobType    string      `json:"job_type"`
	BeginTime  string      `json:"begin_time"`
	EndTime    string      `json:"end_time"`
	ErrorCode  *string     `json:"error_code"`
	FailReason *string     `json:"fail_reason"`
}

// JobEntities mirrors the SDK model ims/v2 JobEntities.
type JobEntities struct {
	ImageID string `json:"image_id"`
}
