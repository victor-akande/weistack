package evs

import (
	"net/http"
)

// statusInUse is the status of an attached disk; every disk WeiStack
// has is attached.
const statusInUse = "in-use"

// volumeDetail mirrors the SDK model evs/v2 VolumeDetail.
type volumeDetail struct {
	ID                  string            `json:"id"`
	Links               []link            `json:"links"`
	Name                string            `json:"name"`
	Status              string            `json:"status"`
	Attachments         []attachment      `json:"attachments"`
	AvailabilityZone    string            `json:"availability_zone"`
	Host                string            `json:"os-vol-host-attr:host"`
	SnapshotID          string            `json:"snapshot_id"`
	Description         string            `json:"description"`
	CreatedAt           string            `json:"created_at"`
	UpdatedAt           string            `json:"updated_at"`
	TenantID            string            `json:"os-vol-tenant-attr:tenant_id"`
	ImageMetadata       map[string]string `json:"volume_image_metadata"`
	VolumeType          string            `json:"volume_type"`
	Size                int               `json:"size"`
	Bootable            string            `json:"bootable"`
	Metadata            map[string]string `json:"metadata"`
	ReplicationStatus   string            `json:"replication_status"`
	Shareable           string            `json:"shareable"`
	Multiattach         bool              `json:"multiattach"`
	ServiceType         string            `json:"service_type"`
	Encrypted           bool              `json:"encrypted"`
	Tags                map[string]string `json:"tags"`
	EnterpriseProjectID string            `json:"enterprise_project_id"`
}

type link struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

// attachment mirrors the SDK model evs/v2 Attachment.
type attachment struct {
	ID           string `json:"id"`
	AttachmentID string `json:"attachment_id"`
	AttachedAt   string `json:"attached_at"`
	Device       string `json:"device"`
	HostName     string `json:"host_name"`
	ServerID     string `json:"server_id"`
	VolumeID     string `json:"volume_id"`
}

func detail(v Volume, t tenant, r *http.Request) volumeDetail {
	bootable := "false"
	image := map[string]string{}
	if v.Bootable {
		bootable = "true"
	}
	if v.ImageID != "" {
		image["image_id"] = v.ImageID
		image["image_name"] = v.ImageName
	}
	epid := v.EnterpriseProjectID
	if epid == "" {
		epid = "0"
	}
	self := "https://" + r.Host + "/v2/" + t.projectID + "/os-vendor-volumes/" + v.ID
	return volumeDetail{
		ID:    v.ID,
		Links: []link{{Href: self, Rel: "self"}, {Href: self, Rel: "bookmark"}},
		Name:  v.Name, Status: statusInUse,
		Attachments: []attachment{{
			// A disk has exactly one attachment, so it reuses the disk's ID.
			ID: v.ID, AttachmentID: v.ID, AttachedAt: v.Created, Device: v.Device,
			ServerID: v.ServerID, VolumeID: v.ID,
		}},
		AvailabilityZone: v.AvailabilityZone,
		CreatedAt:        v.Created, UpdatedAt: v.Updated,
		TenantID:          t.projectID,
		ImageMetadata:     image,
		VolumeType:        v.Type,
		Size:              v.SizeGB,
		Bootable:          bootable,
		Metadata:          map[string]string{"__system__encrypted": "0", "hw:passthrough": "false"},
		ReplicationStatus: "disabled",
		Shareable:         "false",
		ServiceType:       "EVS",
		Tags:              map[string]string{},

		EnterpriseProjectID: epid,
	}
}
