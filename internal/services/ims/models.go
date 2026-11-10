package ims

import (
	"fmt"
	"time"
)

// timeLayout is the timestamp format of the IMS API ("2018-09-06T14:03:27Z").
const timeLayout = "2006-01-02T15:04:05Z"

// Time is a timestamp in the IMS wire format.
type Time time.Time

// MarshalJSON implements json.Marshaler.
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(t).UTC().Format(timeLayout) + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Time) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return fmt.Errorf("ims: timestamp %s is not a string", b)
	}
	parsed, err := time.ParseInLocation(timeLayout, string(b[1:len(b)-1]), time.UTC)
	if err != nil {
		return fmt.Errorf("ims: parsing timestamp: %w", err)
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
