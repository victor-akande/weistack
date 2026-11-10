package ecs

import "encoding/json"

// Wire timestamp formats.
const (
	// timeLayout is used by created and updated ("2019-05-22T03:19:19Z").
	timeLayout = "2006-01-02T15:04:05Z"
	// usageTimeLayout is used by OS-SRV-USG:launched_at and terminated_at.
	usageTimeLayout = "2006-01-02T15:04:05.000000"
	// jobTimeLayout is used by job records ("2016-04-25T20:04:47.591Z").
	jobTimeLayout = "2006-01-02T15:04:05.000Z"
)

// Server statuses.
const (
	StatusBuild   = "BUILD"
	StatusActive  = "ACTIVE"
	StatusShutoff = "SHUTOFF"
	StatusError   = "ERROR"
)

// Server is the stored record of a server. The API form is ServerDetail,
// built by Server.detail.
type Server struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	// TaskState is the operation in flight ("deleting", ...), or "".
	TaskState string `json:"task_state"`

	Flavor string `json:"flavor"`
	// ImageID and the image attributes below are captured at creation,
	// so the server keeps describing itself after the image is deleted.
	ImageID   string `json:"image_id"`
	ImageName string `json:"image_name"`
	ImageType string `json:"image_type"`
	OSType    string `json:"os_type"`
	OSBit     string `json:"os_bit"`

	VPCID            string `json:"vpc_id"`
	AvailabilityZone string `json:"availability_zone"`
	NICs             []NIC  `json:"nics"`
	// SecurityGroups are the IDs of the server's security groups.
	SecurityGroups []string `json:"security_groups"`
	// PublicIP is the elastic IP requested at creation, if any. It is
	// data only: no EIP service stands behind it.
	PublicIP string `json:"public_ip"`

	RootVolume  Volume   `json:"root_volume"`
	DataVolumes []Volume `json:"data_volumes"`

	KeyName  string            `json:"key_name"`
	UserData string            `json:"user_data"`
	Metadata map[string]string `json:"metadata"`
	Tags     []string          `json:"tags"`

	EnterpriseProjectID string `json:"enterprise_project_id"`
	TenantID            string `json:"tenant_id"`
	UserID              string `json:"user_id"`
	HostID              string `json:"host_id"`
	InstanceName        string `json:"instance_name"`
	ReservationID       string `json:"reservation_id"`
	LaunchIndex         int    `json:"launch_index"`

	// Timestamps are stored as RFC 3339 UTC strings.
	Created    string `json:"created"`
	Updated    string `json:"updated"`
	LaunchedAt string `json:"launched_at"`
}

// NIC is one network interface of a server.
type NIC struct {
	SubnetID string `json:"subnet_id"`
	PortID   string `json:"port_id"`
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
}

// Volume is a disk of a server. No EVS service stands behind it.
type Volume struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	SizeGB int    `json:"size"`
	Device string `json:"device"`
}

// ServerDetail mirrors the SDK model ecs/v2 ServerDetail.
type ServerDetail struct {
	Status             string                     `json:"status"`
	Updated            string                     `json:"updated"`
	HostID             string                     `json:"hostId"`
	Host               string                     `json:"OS-EXT-SRV-ATTR:host"`
	Addresses          map[string][]ServerAddress `json:"addresses"`
	KeyName            *string                    `json:"key_name"`
	Image              ServerImage                `json:"image"`
	TaskState          *string                    `json:"OS-EXT-STS:task_state"`
	VMState            string                     `json:"OS-EXT-STS:vm_state"`
	InstanceName       string                     `json:"OS-EXT-SRV-ATTR:instance_name"`
	HypervisorHostname string                     `json:"OS-EXT-SRV-ATTR:hypervisor_hostname"`
	Flavor             ServerFlavor               `json:"flavor"`
	ID                 string                     `json:"id"`
	SecurityGroups     []ServerSecurityGroup      `json:"security_groups"`
	AvailabilityZone   string                     `json:"OS-EXT-AZ:availability_zone"`
	UserID             string                     `json:"user_id"`
	Name               string                     `json:"name"`
	Created            string                     `json:"created"`
	TenantID           string                     `json:"tenant_id"`
	DiskConfig         string                     `json:"OS-DCF:diskConfig"`
	AccessIPv4         string                     `json:"accessIPv4"`
	AccessIPv6         string                     `json:"accessIPv6"`
	Progress           int                        `json:"progress"`
	PowerState         int                        `json:"OS-EXT-STS:power_state"`
	ConfigDrive        string                     `json:"config_drive"`
	Metadata           map[string]string          `json:"metadata"`
	LaunchedAt         *string                    `json:"OS-SRV-USG:launched_at"`
	TerminatedAt       *string                    `json:"OS-SRV-USG:terminated_at"`
	VolumesAttached    []ServerVolume             `json:"os-extended-volumes:volumes_attached"`
	Description        string                     `json:"description"`
	HostStatus         string                     `json:"host_status"`
	Hostname           string                     `json:"OS-EXT-SRV-ATTR:hostname"`
	ReservationID      string                     `json:"OS-EXT-SRV-ATTR:reservation_id"`
	LaunchIndex        int                        `json:"OS-EXT-SRV-ATTR:launch_index"`
	KernelID           string                     `json:"OS-EXT-SRV-ATTR:kernel_id"`
	RamdiskID          string                     `json:"OS-EXT-SRV-ATTR:ramdisk_id"`
	RootDeviceName     string                     `json:"OS-EXT-SRV-ATTR:root_device_name"`
	UserData           *string                    `json:"OS-EXT-SRV-ATTR:user_data"`
	Locked             bool                       `json:"locked"`
	Tags               []string                   `json:"tags"`
	SchedulerHints     map[string]any             `json:"os:scheduler_hints"`
	EnterpriseProject  string                     `json:"enterprise_project_id"`
	SysTags            []ServerSystemTag          `json:"sys_tags"`
}

// ServerAddress mirrors the SDK model ecs/v2 ServerAddress.
type ServerAddress struct {
	Version string `json:"version"`
	Addr    string `json:"addr"`
	Type    string `json:"OS-EXT-IPS:type"`
	MACAddr string `json:"OS-EXT-IPS-MAC:mac_addr"`
	PortID  string `json:"OS-EXT-IPS:port_id"`
	Primary bool   `json:"primary"`
}

// ServerImage mirrors the SDK model ecs/v2 ServerImage.
type ServerImage struct {
	ID string `json:"id"`
}

// ServerFlavor mirrors the SDK model ecs/v2 ServerFlavor. All values
// are strings in the real API.
type ServerFlavor struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Disk  string `json:"disk"`
	VCPUs string `json:"vcpus"`
	RAM   string `json:"ram"`
}

// ServerSecurityGroup mirrors the SDK model ecs/v2 ServerSecurityGroup.
type ServerSecurityGroup struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// ServerVolume mirrors the SDK model ecs/v2 ServerExtendVolumeAttachment.
type ServerVolume struct {
	ID                  string `json:"id"`
	DeleteOnTermination string `json:"delete_on_termination"`
	BootIndex           string `json:"bootIndex"`
	Device              string `json:"device"`
}

// ServerSystemTag mirrors the SDK model ecs/v2 ServerSystemTag.
type ServerSystemTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CreateServerOption mirrors the SDK model ecs/v2 PostPaidServer.
type CreateServerOption struct {
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	ImageRef         string            `json:"imageRef"`
	FlavorRef        string            `json:"flavorRef"`
	VPCID            string            `json:"vpcid"`
	NICs             []CreateNIC       `json:"nics"`
	RootVolume       *CreateVolume     `json:"root_volume"`
	DataVolumes      []CreateVolume    `json:"data_volumes"`
	SecurityGroups   []CreateSecGroup  `json:"security_groups"`
	AvailabilityZone string            `json:"availability_zone"`
	Count            *int              `json:"count"`
	AdminPass        *string           `json:"adminPass"`
	KeyName          string            `json:"key_name"`
	UserData         string            `json:"user_data"`
	Metadata         map[string]string `json:"metadata"`
	ServerTags       []CreateTag       `json:"server_tags"`
	Tags             []string          `json:"tags"`
	PublicIP         json.RawMessage   `json:"publicip"`
	ExtendParam      *CreateExtend     `json:"extendparam"`
}

// CreateNIC mirrors the SDK model ecs/v2 PostPaidServerNic.
type CreateNIC struct {
	SubnetID  string `json:"subnet_id"`
	IPAddress string `json:"ip_address"`
}

// CreateVolume mirrors the SDK models ecs/v2 PostPaidServerRootVolume
// and PostPaidServerDataVolume.
type CreateVolume struct {
	VolumeType string `json:"volumetype"`
	Size       *int   `json:"size"`
}

// CreateSecGroup mirrors the SDK model ecs/v2 PostPaidServerSecurityGroup.
type CreateSecGroup struct {
	ID string `json:"id"`
}

// CreateTag mirrors the SDK model ecs/v2 PostPaidServerTag.
type CreateTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CreateExtend mirrors the SDK model ecs/v2 PostPaidServerExtendParam,
// limited to the field the emulator uses.
type CreateExtend struct {
	EnterpriseProjectID string `json:"enterprise_project_id"`
}

// ListServersFilter selects servers in ListServers. Empty fields match
// everything.
type ListServersFilter struct {
	Name                string // fuzzy: substring match
	Status              string
	Flavor              string
	IP                  string // fuzzy: prefix of a private address
	IPEq                string // exact private address
	ServerID            string
	ReservationID       string
	EnterpriseProjectID string
	Tags                []string // all must be present ("key" or "key=value")
	NotTags             []string // none may be present
}

type createServersRequest struct {
	DryRun bool                `json:"dry_run"`
	Server *CreateServerOption `json:"server"`
}

type createServersResponse struct {
	JobID     string   `json:"job_id"`
	ServerIDs []string `json:"serverIds"`
}

type serverResponse struct {
	Server ServerDetail `json:"server"`
}

type listServersResponse struct {
	Count   int            `json:"count"`
	Servers []ServerDetail `json:"servers"`
}

type deleteServersRequest struct {
	Servers        []serverRef `json:"servers"`
	DeletePublicIP bool        `json:"delete_publicip"`
	DeleteVolume   bool        `json:"delete_volume"`
}

type serverRef struct {
	ID string `json:"id"`
}

type jobResponse struct {
	JobID string `json:"job_id"`
}

// Job statuses.
const (
	JobRunning = "RUNNING"
	JobSuccess = "SUCCESS"
	JobFail    = "FAIL"
)

// Job mirrors the SDK model ecs/v2 ShowJobResponse. It is both the
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

// JobEntities mirrors the SDK model ecs/v2 JobEntities.
type JobEntities struct {
	SubJobsTotal int      `json:"sub_jobs_total"`
	SubJobs      []SubJob `json:"sub_jobs"`
}

// SubJob mirrors the SDK model ecs/v2 SubJob: the part of a job that
// concerns one server.
type SubJob struct {
	Status     string         `json:"status"`
	Entities   SubJobEntities `json:"entities"`
	JobID      string         `json:"job_id"`
	JobType    string         `json:"job_type"`
	BeginTime  string         `json:"begin_time"`
	EndTime    string         `json:"end_time"`
	ErrorCode  *string        `json:"error_code"`
	FailReason *string        `json:"fail_reason"`
}

// SubJobEntities mirrors the SDK model ecs/v2 SubJobEntities.
type SubJobEntities struct {
	ServerID string `json:"server_id"`
}
