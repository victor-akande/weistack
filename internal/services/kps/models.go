package kps

// Store kinds under scope {Region, ProjectID, Kind}.
const (
	kindKeypair    = "kps.keypair"
	kindTask       = "kps.task"
	kindFailedTask = "kps.failed_task"
)

// Lifecycle task kinds, matched by fault injection.
const (
	taskAssociate    = "kps.keypair.associate"
	taskDisassociate = "kps.keypair.disassociate"
)

// Keypair is the stored representation of an SSH key pair.
type Keypair struct {
	ID          int64  `json:"id"` // sequence per project, as the SDK's int64
	Name        string `json:"name"`
	Type        string `json:"type"`  // ssh | x509
	Scope       string `json:"scope"` // user | domain
	UserID      string `json:"user_id"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	Description string `json:"description"`
	Protection  string `json:"protection"` // "" | default | kms
	KMSKeyID    string `json:"kms_key_id,omitempty"`
	SealedKey   []byte `json:"sealed_key,omitempty"` // vault- or KMS-sealed PEM; never serialised to clients
	CreatedAt   int64  `json:"created_at"`           // ms
	UpdatedAt   int64  `json:"updated_at"`
}

// Task is the stored representation of an asynchronous key pair associate or
// disassociate task.
type Task struct {
	ID, Operation, KeypairName, ServerID, Status string // Status: RUNNING | SUCCESS | FAILED
	ErrorCode, ErrorMsg                          string
	CreatedAt                                    int64
}

// Wire types mirroring huaweicloud-sdk-go-v3 services/kps/v3/model.

type encryptionWire struct {
	Type       string `json:"type"`
	KMSKeyName string `json:"kms_key_name,omitempty"`
	KMSKeyID   string `json:"kms_key_id,omitempty"`
}

type keyProtectionWire struct {
	PrivateKey string          `json:"private_key,omitempty"`
	Encryption *encryptionWire `json:"encryption"`
}

type createKeypairAction struct {
	Name          string             `json:"name"`
	Type          string             `json:"type,omitempty"`
	PublicKey     string             `json:"public_key,omitempty"`
	Scope         string             `json:"scope,omitempty"`
	UserID        string             `json:"user_id,omitempty"`
	KeyProtection *keyProtectionWire `json:"key_protection,omitempty"`
}

type createKeypairRequest struct {
	Keypair *createKeypairAction `json:"keypair"`
}

type createKeypairResp struct {
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	UserID      string `json:"user_id,omitempty"`
}

type createKeypairResponse struct {
	Keypair createKeypairResp `json:"keypair"`
}

type keypairSummary struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	Scope           string `json:"scope"`
	PublicKey       string `json:"public_key"`
	Fingerprint     string `json:"fingerprint"`
	IsKeyProtection bool   `json:"is_key_protection"`
	FrozenState     string `json:"frozen_state"`
}

type keypairItem struct {
	Keypair keypairSummary `json:"keypair"`
}

type pageInfoWire struct {
	NextMarker     string `json:"next_marker,omitempty"`
	PreviousMarker string `json:"previous_marker,omitempty"`
	CurrentCount   int32  `json:"current_count"`
}

type listKeypairsResponse struct {
	Keypairs []keypairItem `json:"keypairs"`
	PageInfo pageInfoWire  `json:"page_info"`
}

type keypairDetailWire struct {
	Name            string `json:"name"`
	ID              int64  `json:"id"`
	Type            string `json:"type"`
	Scope           string `json:"scope"`
	PublicKey       string `json:"public_key"`
	Fingerprint     string `json:"fingerprint"`
	IsKeyProtection bool   `json:"is_key_protection"`
	Deleted         bool   `json:"deleted"`
	Description     string `json:"description"`
	UserID          string `json:"user_id"`
	CreateTime      int64  `json:"create_time"`
	DeleteTime      *int64 `json:"delete_time"`
	UpdateTime      *int64 `json:"update_time"`
	FrozenState     int32  `json:"frozen_state"`
	KeyID           string `json:"key_id,omitempty"`
	Algorithm       string `json:"algorithm,omitempty"`
}

type listKeypairDetailResponse struct {
	Keypair keypairDetailWire `json:"keypair"`
}

type updateDescriptionRequest struct {
	Keypair *struct {
		Description *string `json:"description"`
	} `json:"keypair"`
}

type importPrivateKeyAction struct {
	Name          string             `json:"name"`
	UserID        string             `json:"user_id,omitempty"`
	KeyProtection *keyProtectionWire `json:"key_protection,omitempty"`
}

type importPrivateKeyRequest struct {
	Keypair *importPrivateKeyAction `json:"keypair"`
}

type importPrivateKeyResponse struct {
	Keypair importPrivateKeyAction `json:"keypair"`
}

type exportPrivateKeyRequest struct {
	Keypair *struct {
		Name string `json:"name"`
	} `json:"keypair"`
}

type exportPrivateKeyResp struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
}

type exportPrivateKeyResponse struct {
	Keypair exportPrivateKeyResp `json:"keypair"`
}

type failedKeypairWire struct {
	KeypairName  string `json:"keypair_name"`
	FailedReason string `json:"failed_reason"`
}

type batchImportResponse struct {
	FailedKeypairs    []failedKeypairWire     `json:"failed_keypairs"`
	SucceededKeypairs []createKeypairResponse `json:"succeeded_keypairs"`
}

type batchExportItem struct {
	Keypair *struct {
		Name string `json:"name"`
	} `json:"keypair"`
}

type authWire struct {
	Type string `json:"type,omitempty"`
	Key  string `json:"key,omitempty"`
}

type ecsServerInfoWire struct {
	ID              string    `json:"id"`
	Auth            *authWire `json:"auth,omitempty"`
	DisablePassword *bool     `json:"disable_password,omitempty"`
	Port            *int64    `json:"port,omitempty"`
}

type associateKeypairRequest struct {
	KeypairName string             `json:"keypair_name"`
	Server      *ecsServerInfoWire `json:"server"`
}

type disassociateServerInfoWire struct {
	ID   string    `json:"id"`
	Auth *authWire `json:"auth,omitempty"`
}

type disassociateKeypairRequest struct {
	Server *disassociateServerInfoWire `json:"server"`
}

type taskActionResponse struct {
	TaskID    string `json:"task_id,omitempty"`
	ServerID  string `json:"server_id,omitempty"`
	Status    string `json:"status,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	ErrorMsg  string `json:"error_msg,omitempty"`
}

type batchAssociateRequest struct {
	BatchKeypairs []associateKeypairRequest `json:"batch_keypairs"`
}

type batchAssociateResponse struct {
	Tasks []taskActionResponse `json:"tasks"`
}

type listKeypairTaskResponse struct {
	ServerID   string `json:"server_id"`
	TaskID     string `json:"task_id"`
	TaskStatus string `json:"task_status"`
}

type runningTaskWire struct {
	TaskID      string `json:"task_id"`
	OperateType string `json:"operate_type"`
	TaskTime    string `json:"task_time"`
	ServerName  string `json:"server_name"`
	ServerID    string `json:"server_id"`
	KeypairName string `json:"keypair_name"`
}

type listRunningTaskResponse struct {
	Total int32             `json:"total"`
	Tasks []runningTaskWire `json:"tasks"`
}

type failedTaskWire struct {
	TaskID        string  `json:"task_id"`
	OperateType   string  `json:"operate_type"`
	TaskTime      string  `json:"task_time"`
	TaskErrorCode *string `json:"task_error_code"`
	TaskErrorMsg  string  `json:"task_error_msg"`
	ServerName    string  `json:"server_name"`
	ServerID      string  `json:"server_id"`
	KeypairName   string  `json:"keypair_name"`
}

type listFailedTaskResponse struct {
	Total int32            `json:"total"`
	Tasks []failedTaskWire `json:"tasks"`
}
