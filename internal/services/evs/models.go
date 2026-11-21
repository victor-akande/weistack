package evs

import (
	"maps"
	"net/http"
	"strconv"
)

const (
	volumeTimeLayout = "2006-01-02T15:04:05.000000"
	jobTimeLayout    = "2006-01-02T15:04:05.000Z"
)

// Volume and snapshot statuses (EVSStatus.txt).
const (
	statusAvailable        = "available"
	statusCreating         = "creating"
	statusExtending        = "extending"
	statusDeleting         = "deleting"
	statusAttaching        = "attaching"
	statusDetaching        = "detaching"
	statusInUse            = "in-use"
	statusError            = "error"
	statusErrorExtending   = "error_extending"
	statusErrorDeleting    = "error_deleting"
	statusErrorRestoring   = "error_restoring"
	statusErrorRollbacking = "error_rollbacking"
	statusRollbacking      = "rollbacking"
)

// volume is an EVS disk. Its JSON layout is part of data format 2.
type volume struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Description         string            `json:"description"`
	Status              string            `json:"status"`
	SizeGB              int               `json:"size"`
	VolumeType          string            `json:"volume_type"`
	AvailabilityZone    string            `json:"availability_zone"`
	Bootable            bool              `json:"bootable"`
	ImageID             string            `json:"image_id,omitempty"`
	ImageName           string            `json:"image_name,omitempty"`
	SnapshotID          string            `json:"snapshot_id,omitempty"`
	KMSKeyID            string            `json:"kms_key_id,omitempty"`
	Passthrough         bool              `json:"passthrough,omitempty"` // metadata hw:passthrough
	Multiattach         bool              `json:"multiattach,omitempty"`
	IOPS                int               `json:"iops,omitempty"`
	Throughput          int               `json:"throughput,omitempty"`
	QoSID               string            `json:"qos_id,omitempty"`   // the id of the iops and throughput objects
	Metadata            map[string]string `json:"metadata,omitempty"` // the caller's keys, without the system ones
	Tags                map[string]string `json:"tags,omitempty"`
	EnterpriseProjectID string            `json:"enterprise_project_id"`
	Attachments         []attachment      `json:"attachments"`
	Pending             *pending          `json:"pending,omitempty"`
	CreatedAt           string            `json:"created_at"`
	UpdatedAt           string            `json:"updated_at"`
}

type attachment struct {
	ID                  string `json:"id"` // the attachment ID
	ServerID            string `json:"server_id"`
	Device              string `json:"device"`
	BootIndex           int    `json:"boot_index"` // 0 for a system disk, -1 for a data disk
	DeleteOnTermination bool   `json:"delete_on_termination"`
	AttachedAt          string `json:"attached_at"`
}

// pending is the asynchronous operation in flight, kept so it resumes
// after a restart.
type pending struct {
	Op         string `json:"op"`     // "create", "extend", "delete", "rollback", "attach", "detach"
	JobID      string `json:"job_id"` // EVS's job, or ECS's for attach and detach
	ServerID   string `json:"server_id,omitempty"`
	Device     string `json:"device,omitempty"`
	NewSize    int    `json:"new_size,omitempty"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	AttachTo   string `json:"attach_to,omitempty"` // create's server_id
}

type snapshot struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Description         string            `json:"description"`
	Status              string            `json:"status"`
	VolumeID            string            `json:"volume_id"`
	SizeGB              int               `json:"size"`
	VolumeType          string            `json:"volume_type"`
	AvailabilityZone    string            `json:"availability_zone"`
	Metadata            map[string]string `json:"metadata,omitempty"`
	EnterpriseProjectID string            `json:"enterprise_project_id"`
	CreatedAt           string            `json:"created_at"`
	UpdatedAt           string            `json:"updated_at"`
}

// job mirrors the SDK model evs/v2 ShowJobResponse.
type job struct {
	Status     string      `json:"status"`
	Entities   jobEntities `json:"entities"`
	JobID      string      `json:"job_id"`
	JobType    string      `json:"job_type"`
	BeginTime  string      `json:"begin_time"`
	EndTime    string      `json:"end_time"`
	ErrorCode  string      `json:"error_code,omitempty"`
	FailReason string      `json:"fail_reason,omitempty"`
}

type jobEntities struct {
	VolumeType   string   `json:"volume_type,omitempty"`
	Size         int      `json:"size,omitempty"`
	VolumeID     string   `json:"volume_id,omitempty"`
	Name         string   `json:"name,omitempty"`
	SubJobsTotal int      `json:"sub_jobs_total,omitempty"`
	SubJobs      []subJob `json:"sub_jobs,omitempty"`
}

type subJob struct {
	Status     string      `json:"status"`
	Entities   jobEntities `json:"entities"`
	JobID      string      `json:"job_id"`
	JobType    string      `json:"job_type"`
	BeginTime  string      `json:"begin_time"`
	EndTime    string      `json:"end_time"`
	ErrorCode  string      `json:"error_code,omitempty"`
	FailReason string      `json:"fail_reason,omitempty"`
}

// volumeDetail mirrors the SDK model evs/v2 VolumeDetail.
type volumeDetail struct {
	ID                  string            `json:"id"`
	Links               []link            `json:"links"`
	Name                string            `json:"name"`
	Status              string            `json:"status"`
	Attachments         []attachmentWire  `json:"attachments"`
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
	IOPS                *qosWire          `json:"iops,omitempty"`
	Throughput          *qosWire          `json:"throughput,omitempty"`
}

type link struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

// attachmentWire mirrors the SDK model evs/v2 Attachment.
type attachmentWire struct {
	ID           string `json:"id"`
	AttachmentID string `json:"attachment_id"`
	AttachedAt   string `json:"attached_at"`
	Device       string `json:"device"`
	HostName     string `json:"host_name"`
	ServerID     string `json:"server_id"`
	VolumeID     string `json:"volume_id"`
}

type qosWire struct {
	Frozened bool   `json:"frozened"`
	ID       string `json:"id"`
	TotalVal int    `json:"total_val"`
}

func detail(v volume, t Tenant, r *http.Request) volumeDetail {
	image := map[string]string{}
	if v.ImageID != "" {
		image["image_id"] = v.ImageID
		image["image_name"] = v.ImageName
	}

	metadata := make(map[string]string, len(v.Metadata)+3)
	maps.Copy(metadata, v.Metadata)
	metadata["__system__encrypted"] = "0"
	if v.KMSKeyID != "" {
		metadata["__system__encrypted"] = "1"
		metadata["__system__cmkid"] = v.KMSKeyID
	}
	metadata["hw:passthrough"] = strconv.FormatBool(v.Passthrough)

	tags := map[string]string{}
	if len(v.Tags) > 0 {
		tags = maps.Clone(v.Tags)
	}

	epid := v.EnterpriseProjectID
	if epid == "" {
		epid = "0"
	}

	atts := make([]attachmentWire, 0, len(v.Attachments))
	for _, a := range v.Attachments {
		atts = append(atts, attachmentWire{
			ID:           a.ID,
			AttachmentID: a.ID,
			AttachedAt:   a.AttachedAt,
			Device:       a.Device,
			HostName:     "",
			ServerID:     a.ServerID,
			VolumeID:     v.ID,
		})
	}

	var iops, throughput *qosWire
	if v.IOPS > 0 {
		iops = &qosWire{Frozened: false, ID: v.QoSID, TotalVal: v.IOPS}
	}
	if v.Throughput > 0 {
		throughput = &qosWire{Frozened: false, ID: v.QoSID, TotalVal: v.Throughput}
	}

	self := "https://" + r.Host + "/v2/" + t.ProjectID + "/os-vendor-volumes/" + v.ID
	return volumeDetail{
		ID:                  v.ID,
		Links:               []link{{Href: self, Rel: "self"}, {Href: self, Rel: "bookmark"}},
		Name:                v.Name,
		Status:              v.Status,
		Attachments:         atts,
		AvailabilityZone:    v.AvailabilityZone,
		SnapshotID:          v.SnapshotID,
		Description:         v.Description,
		CreatedAt:           v.CreatedAt,
		UpdatedAt:           v.UpdatedAt,
		TenantID:            t.ProjectID,
		ImageMetadata:       image,
		VolumeType:          v.VolumeType,
		Size:                v.SizeGB,
		Bootable:            strconv.FormatBool(v.Bootable),
		Metadata:            metadata,
		ReplicationStatus:   "disabled",
		Shareable:           strconv.FormatBool(v.Multiattach),
		Multiattach:         v.Multiattach,
		ServiceType:         "EVS",
		Encrypted:           v.KMSKeyID != "",
		Tags:                tags,
		EnterpriseProjectID: epid,
		IOPS:                iops,
		Throughput:          throughput,
	}
}
