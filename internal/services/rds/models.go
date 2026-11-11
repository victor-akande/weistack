package rds

import "time"

// timeLayout is the timestamp format of RDS responses
// ("2018-08-20T02:33:49+0000").
const timeLayout = "2006-01-02T15:04:05-0700"

func stamp(t time.Time) string { return t.UTC().Format(timeLayout) }

// Instance statuses.
const (
	StatusBuild      = "BUILD"
	StatusCreateFail = "CREATE FAIL"
	StatusActive     = "ACTIVE"
	StatusFailed     = "FAILED"
	StatusRebooting  = "REBOOTING"
	StatusModifying  = "MODIFYING"
	StatusBackingUp  = "BACKING UP"
)

// Instance is the stored record of a DB instance. The API form is
// InstanceResponse, built by Instance.view.
type Instance struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	Engine          string    `json:"engine"`
	Version         string    `json:"version"`
	Mode            string    `json:"mode"`
	ReplicationMode string    `json:"replication_mode,omitempty"`
	FlavorRef       string    `json:"flavor_ref"`
	VolumeType      string    `json:"volume_type"`
	VolumeSize      int       `json:"volume_size"`
	Region          string    `json:"region"`
	Zones           []string  `json:"zones"`
	VPCID           string    `json:"vpc_id"`
	SubnetID        string    `json:"subnet_id"`
	SecurityGroupID string    `json:"security_group_id"`
	Port            int       `json:"port"`
	PrivateIP       string    `json:"private_ip"`
	BackupStart     string    `json:"backup_start"`
	KeepDays        int       `json:"keep_days"`
	ConfigurationID string    `json:"configuration_id,omitempty"`
	EnterpriseProj  string    `json:"enterprise_project_id"`
	TimeZone        string    `json:"time_zone"`
	Tags            []Tag     `json:"tags"`
	NodeIDs         []string  `json:"node_ids"`
	Created         time.Time `json:"created"`
	Updated         time.Time `json:"updated"`
	// Pending is the operation in flight, kept on the record so that it
	// can be resumed after a restart.
	Pending *Pending `json:"pending,omitempty"`
}

// Pending describes an operation that completes after the lifecycle
// delay.
type Pending struct {
	Kind  string `json:"kind"`
	JobID string `json:"job_id"`
	// Final is the status the instance lands in on success.
	Final  string `json:"final,omitempty"`
	Flavor string `json:"flavor,omitempty"`
	Size   int    `json:"size,omitempty"`
	Backup string `json:"backup,omitempty"`
}

// Tag mirrors the SDK models rds/v3 TagWithKeyValue and TagResponse.
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Datastore mirrors the SDK model rds/v3 Datastore.
type Datastore struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

// Volume mirrors the SDK model rds/v3 Volume.
type Volume struct {
	Type string `json:"type"`
	Size int    `json:"size"`
}

// HA mirrors the SDK model rds/v3 Ha.
type HA struct {
	Mode            string `json:"mode"`
	ReplicationMode string `json:"replication_mode,omitempty"`
}

// BackupStrategy mirrors the SDK model rds/v3 BackupStrategy.
type BackupStrategy struct {
	StartTime string `json:"start_time"`
	KeepDays  *int   `json:"keep_days,omitempty"`
}

// ChargeInfo mirrors the SDK model rds/v3 ChargeInfo.
type ChargeInfo struct {
	ChargeMode string `json:"charge_mode"`
}

// CreateInstanceOption mirrors the SDK model rds/v3 InstanceRequest.
type CreateInstanceOption struct {
	Name                string          `json:"name"`
	Datastore           *Datastore      `json:"datastore"`
	HA                  *HA             `json:"ha"`
	ConfigurationID     *string         `json:"configuration_id"`
	Port                *string         `json:"port"`
	Password            *string         `json:"password"`
	BackupStrategy      *BackupStrategy `json:"backup_strategy"`
	EnterpriseProjectID *string         `json:"enterprise_project_id"`
	DiskEncryptionID    *string         `json:"disk_encryption_id"`
	FlavorRef           string          `json:"flavor_ref"`
	Volume              *Volume         `json:"volume"`
	Region              string          `json:"region"`
	AvailabilityZone    string          `json:"availability_zone"`
	VPCID               string          `json:"vpc_id"`
	SubnetID            string          `json:"subnet_id"`
	SecurityGroupID     string          `json:"security_group_id"`
	ChargeInfo          *ChargeInfo     `json:"charge_info"`
	TimeZone            *string         `json:"time_zone"`
	Tags                []Tag           `json:"tags"`
	// Fields of features the emulator does not support; decoded so the
	// gap can be reported by name.
	ReplicaOfID  *string `json:"replica_of_id"`
	RestorePoint any     `json:"restore_point"`
	DryRun       *bool   `json:"dry_run"`
	Count        *int    `json:"count"`
}

// CreatedInstance mirrors the SDK model rds/v3 CreateInstanceRespItem.
type CreatedInstance struct {
	ID                  string         `json:"id"`
	Name                string         `json:"name"`
	Status              string         `json:"status"`
	Datastore           Datastore      `json:"datastore"`
	HA                  *HA            `json:"ha,omitempty"`
	ConfigurationID     string         `json:"configuration_id,omitempty"`
	Port                string         `json:"port"`
	BackupStrategy      BackupStrategy `json:"backup_strategy"`
	EnterpriseProjectID string         `json:"enterprise_project_id"`
	DiskEncryptionID    string         `json:"disk_encryption_id"`
	FlavorRef           string         `json:"flavor_ref"`
	Volume              Volume         `json:"volume"`
	Region              string         `json:"region"`
	AvailabilityZone    string         `json:"availability_zone"`
	VPCID               string         `json:"vpc_id"`
	SubnetID            string         `json:"subnet_id"`
	SecurityGroupID     string         `json:"security_group_id"`
	ChargeInfo          ChargeInfo     `json:"charge_info"`
}

type createInstanceResponse struct {
	Instance CreatedInstance `json:"instance"`
	JobID    string          `json:"job_id"`
}

// InstanceResponse mirrors the SDK model rds/v3 InstanceResponse.
type InstanceResponse struct {
	ID                  string            `json:"id"`
	Status              string            `json:"status"`
	Name                string            `json:"name"`
	Port                int               `json:"port"`
	Type                string            `json:"type"`
	Region              string            `json:"region"`
	Datastore           Datastore         `json:"datastore"`
	Created             string            `json:"created"`
	Updated             string            `json:"updated"`
	Volume              Volume            `json:"volume"`
	Nodes               []Node            `json:"nodes"`
	PrivateIPs          []string          `json:"private_ips"`
	PublicIPs           []string          `json:"public_ips"`
	EnableSSL           bool              `json:"enable_ssl"`
	DBUserName          string            `json:"db_user_name"`
	VPCID               string            `json:"vpc_id"`
	SubnetID            string            `json:"subnet_id"`
	SecurityGroupID     string            `json:"security_group_id"`
	FlavorRef           string            `json:"flavor_ref"`
	CPU                 string            `json:"cpu"`
	Mem                 string            `json:"mem"`
	SwitchStrategy      string            `json:"switch_strategy"`
	ReadOnlyByUser      bool              `json:"read_only_by_user"`
	HA                  *HAResponse       `json:"ha,omitempty"`
	ChargeInfo          ChargeInfo        `json:"charge_info"`
	BackupStrategy      BackupStrategyOut `json:"backup_strategy"`
	MaintenanceWindow   string            `json:"maintenance_window"`
	RelatedInstance     []RelatedInstance `json:"related_instance"`
	DiskEncryptionID    string            `json:"disk_encryption_id"`
	EnterpriseProjectID string            `json:"enterprise_project_id"`
	TimeZone            string            `json:"time_zone"`
	Tags                []Tag             `json:"tags"`
	AssociatedWithDDM   bool              `json:"associated_with_ddm"`
}

// Node mirrors the SDK model rds/v3 NodeResponse.
type Node struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Role             string `json:"role"`
	Status           string `json:"status"`
	AvailabilityZone string `json:"availability_zone"`
}

// HAResponse mirrors the SDK model rds/v3 HaResponse.
type HAResponse struct {
	ReplicationMode string `json:"replication_mode"`
}

// BackupStrategyOut mirrors the SDK model rds/v3 BackupStrategyForResponse.
type BackupStrategyOut struct {
	StartTime string `json:"start_time"`
	KeepDays  int    `json:"keep_days"`
}

// RelatedInstance mirrors the SDK model rds/v3 RelatedInstance.
type RelatedInstance struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type listInstancesResponse struct {
	Instances  []InstanceResponse `json:"instances"`
	TotalCount int                `json:"total_count"`
}

// Flavor mirrors the SDK model rds/v3 Flavor. vcpus is a string and ram
// is in GB.
type Flavor struct {
	ID           string            `json:"id"`
	VCPUs        string            `json:"vcpus"`
	RAM          int               `json:"ram"`
	SpecCode     string            `json:"spec_code"`
	InstanceMode string            `json:"instance_mode"`
	AZStatus     map[string]string `json:"az_status"`
	AZDesc       map[string]string `json:"az_desc"`
	VersionName  []string          `json:"version_name"`
	GroupType    string            `json:"group_type"`
}

type listFlavorsResponse struct {
	Flavors []Flavor `json:"flavors"`
}

// datastoreVersion mirrors the SDK model rds/v3 LDatastore.
type datastoreVersion struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type listDatastoresResponse struct {
	DataStores []datastoreVersion `json:"dataStores"`
}

type jobIDResponse struct {
	JobID string `json:"job_id"`
}

// Job statuses.
const (
	JobRunning   = "Running"
	JobCompleted = "Completed"
	JobFailed    = "Failed"
)

// Job mirrors the SDK model rds/v3 GetJobInfoResponseBodyJob. It is both
// the stored record and the response body.
type Job struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	Created    string         `json:"created"`
	Ended      string         `json:"ended,omitempty"`
	Process    string         `json:"process,omitempty"`
	Instance   JobInstance    `json:"instance"`
	Entities   map[string]any `json:"entities,omitempty"`
	FailReason string         `json:"fail_reason,omitempty"`
}

// JobInstance mirrors the SDK model rds/v3 GetTaskDetailListRspJobsInstance.
type JobInstance struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type jobResponse struct {
	Job Job `json:"job"`
}

// ListInstancesFilter selects instances in ListInstances. Empty fields
// match everything.
type ListInstancesFilter struct {
	ID, Name, Type, Engine, VPCID, SubnetID, EnterpriseProjectID string
	Tags                                                         []Tag
}

// actionRequest is the body of POST /instances/{id}/action: exactly one
// of the three actions.
type actionRequest struct {
	Restart       *struct{}      `json:"restart"`
	ResizeFlavor  *ResizeOption  `json:"resize_flavor"`
	EnlargeVolume *EnlargeOption `json:"enlarge_volume"`
}

// ResizeOption mirrors the SDK model rds/v3 ResizeFlavorObject.
type ResizeOption struct {
	SpecCode string `json:"spec_code"`
}

// EnlargeOption mirrors the SDK model rds/v3 EnlargeVolumeObject.
type EnlargeOption struct {
	Size int `json:"size"`
}

// Backup statuses and types.
const (
	BackupBuilding  = "BUILDING"
	BackupCompleted = "COMPLETED"
	BackupFailed    = "FAILED"
	BackupManual    = "manual"
)

// Backup is the stored record of a backup. It is kept when its instance
// is deleted, as manual backups are.
type Backup struct {
	ID          string           `json:"id"`
	InstanceID  string           `json:"instance_id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Databases   []BackupDatabase `json:"databases,omitempty"`
	BeginTime   string           `json:"begin_time"`
	EndTime     string           `json:"end_time"`
	Status      string           `json:"status"`
	Type        string           `json:"type"`
	Size        int64            `json:"size"`
	Datastore   Datastore        `json:"datastore"`
}

// BackupDatabase mirrors the SDK model rds/v3 BackupDatabase.
type BackupDatabase struct {
	Name string `json:"name"`
}

// CreateBackupOption mirrors the SDK model rds/v3 CreateManualBackupRequestBody.
type CreateBackupOption struct {
	InstanceID  string           `json:"instance_id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Databases   []BackupDatabase `json:"databases"`
}

// backupInfo mirrors the SDK model rds/v3 BackupInfo, the body of a
// creation response.
type backupInfo struct {
	ID          string           `json:"id"`
	InstanceID  string           `json:"instance_id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Databases   []BackupDatabase `json:"databases,omitempty"`
	BeginTime   string           `json:"begin_time"`
	Status      string           `json:"status"`
	Type        string           `json:"type"`
}

type createBackupResponse struct {
	Backup backupInfo `json:"backup"`
}

// backupForList mirrors the SDK model rds/v3 BackupForList.
type backupForList struct {
	ID                string           `json:"id"`
	InstanceID        string           `json:"instance_id"`
	Name              string           `json:"name"`
	Databases         []BackupDatabase `json:"databases,omitempty"`
	BeginTime         string           `json:"begin_time"`
	EndTime           string           `json:"end_time"`
	Status            string           `json:"status"`
	Type              string           `json:"type"`
	Size              int64            `json:"size"`
	Datastore         Datastore        `json:"datastore"`
	AssociatedWithDDM bool             `json:"associated_with_ddm"`
}

type listBackupsResponse struct {
	Backups    []backupForList `json:"backups"`
	TotalCount int             `json:"total_count"`
}
