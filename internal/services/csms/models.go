package csms

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	kindSecret           = "csms.secret"
	kindVersion          = "csms.version"
	kindDeleteTransition = "csms.secret.delete"

	stateEnabled       = "ENABLED"
	statePendingDelete = "PENDING_DELETE"

	secretTypeCommon  = "COMMON"
	replicaStandalone = "STANDALONE"

	stageCurrent  = "SYSCURRENT"
	stagePrevious = "SYSPREVIOUS"

	maxValueBytes        = 64 * 1024
	maxDescriptionBytes  = 2048
	maxVersionsPerSecret = 20
	maxStagesPerSecret   = 12
	maxTagsPerSecret     = 20
	maxTagKeyLen         = 128
	maxTagValueLen       = 255
	maxEventSubs         = 1

	defaultListLimit = 50
	maxListLimit     = 1000
	defaultTagLimit  = 10
	maxTagLimit      = 1000

	minRecoveryDays     = 7
	maxRecoveryDays     = 30
	defaultRecoveryDays = 30

	defaultPasswordLen = 32
	minPasswordLen     = 1
	maxPasswordLen     = 255

	backupPrefix     = ")CloudSecretManagementBackupV1.com"
	backupVaultLabel = "weistack:csms:backup"
)

var (
	nameRE      = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
	versionIDRE = regexp.MustCompile(`^v[0-9]{1,10}$`)
	kmsKeyIDRE  = regexp.MustCompile(`^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$`)
	epIDRE      = regexp.MustCompile(`^(0|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
)

// Secret is a persisted CSMS secret record, keyed by Name in kind "csms.secret".
type Secret struct {
	ID                  string           `json:"id"` // UUID
	Name                string           `json:"name"`
	State               string           `json:"state"` // ENABLED | PENDING_DELETE
	KMSKeyID            string           `json:"kms_key_id"`
	Description         string           `json:"description"`
	SecretType          string           `json:"secret_type"` // COMMON
	EnterpriseProjectID string           `json:"enterprise_project_id"`
	EventSubscriptions  []string         `json:"event_subscriptions,omitempty"`
	Stages              map[string]Stage `json:"stages"`       // name -> stage
	NextVersion         int              `json:"next_version"` // the n of the next "vn"
	Tags                []Tag            `json:"tags"`
	CreatedAt           int64            `json:"created_at"` // ms
	UpdatedAt           int64            `json:"updated_at"`
	ScheduledDeleteAt   int64            `json:"scheduled_delete_at,omitempty"`
	LastUsedAt          int64            `json:"last_used_at,omitempty"`
}

// Stage is a version stage entry on a Secret.
type Stage struct {
	VersionID string `json:"version_id"`
	UpdatedAt int64  `json:"updated_at"` // ms
}

// Version is a persisted CSMS secret version record, keyed "<secret-name>/<version-id>"
// in kind "csms.version". Plaintext values are never stored here.
type Version struct {
	ID         string `json:"id"` // v1, v2, ...
	SecretID   string `json:"secret_id"`
	KMSKeyID   string `json:"kms_key_id"`
	Binary     bool   `json:"binary"`     // secret_binary rather than secret_string
	SealedKey  []byte `json:"sealed_key"` // KMS-sealed data key
	Ciphertext []byte `json:"ciphertext"` // nonce || AES-GCM(value)
	ExpireAt   int64  `json:"expire_at,omitempty"`
	CreatedAt  int64  `json:"created_at"`
}

// Tag is a key/value tag on a Secret.
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func versionStoreKey(secretName, versionID string) string {
	return secretName + "/" + versionID
}

func parseVersionNum(id string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(id, "v"))
	if err != nil {
		return 0
	}
	return n
}

// stagesForVersion returns the stages pointing at versionID, with built-in
// stages first (SYSCURRENT, SYSPREVIOUS) followed by custom stages sorted by name.
func stagesForVersion(stages map[string]Stage, versionID string) []string {
	var builtins, custom []string
	if st, ok := stages[stageCurrent]; ok && st.VersionID == versionID {
		builtins = append(builtins, stageCurrent)
	}
	if st, ok := stages[stagePrevious]; ok && st.VersionID == versionID {
		builtins = append(builtins, stagePrevious)
	}
	for name, st := range stages {
		if name == stageCurrent || name == stagePrevious {
			continue
		}
		if st.VersionID == versionID {
			custom = append(custom, name)
		}
	}
	sort.Strings(custom)
	out := make([]string, 0, len(builtins)+len(custom))
	out = append(out, builtins...)
	out = append(out, custom...)
	return out
}

// Wire representations mirroring huaweicloud-sdk-go-v3 services/csms/v1/model.

type secretView struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	State               string   `json:"state"`
	KMSKeyID            string   `json:"kms_key_id"`
	Description         string   `json:"description"`
	CreateTime          int64    `json:"create_time"`
	UpdateTime          int64    `json:"update_time"`
	ScheduledDeleteTime *int64   `json:"scheduled_delete_time,omitempty"`
	SecretType          string   `json:"secret_type"`
	AutoRotation        bool     `json:"auto_rotation"`
	EventSubscriptions  []string `json:"event_subscriptions"`
	EnterpriseProjectID string   `json:"enterprise_project_id"`
	LastUsedTime        *int64   `json:"last_used_time,omitempty"`
	DomainID            string   `json:"domain_id,omitempty"`
	ReplicaType         string   `json:"replica_type"`
}

func toSecretView(sec Secret, accountID string) secretView {
	subs := sec.EventSubscriptions
	if subs == nil {
		subs = []string{}
	}
	v := secretView{
		ID:                  sec.ID,
		Name:                sec.Name,
		State:               sec.State,
		KMSKeyID:            sec.KMSKeyID,
		Description:         sec.Description,
		CreateTime:          sec.CreatedAt,
		UpdateTime:          sec.UpdatedAt,
		SecretType:          sec.SecretType,
		AutoRotation:        false,
		EventSubscriptions:  subs,
		EnterpriseProjectID: sec.EnterpriseProjectID,
		DomainID:            accountID,
		ReplicaType:         replicaStandalone,
	}
	if sec.State == statePendingDelete && sec.ScheduledDeleteAt > 0 {
		at := sec.ScheduledDeleteAt
		v.ScheduledDeleteTime = &at
	}
	if sec.LastUsedAt > 0 {
		at := sec.LastUsedAt
		v.LastUsedTime = &at
	}
	return v
}

type secretResponse struct {
	Secret secretView `json:"secret"`
}

type pageInfoView struct {
	NextMarker     string `json:"next_marker,omitempty"`
	PreviousMarker string `json:"previous_marker,omitempty"`
	CurrentCount   int    `json:"current_count"`
}

type listSecretsResponse struct {
	Secrets  []secretView `json:"secrets"`
	PageInfo pageInfoView `json:"page_info"`
}

type versionMetadataView struct {
	ID            string   `json:"id"`
	CreateTime    int64    `json:"create_time"`
	ExpireTime    *int64   `json:"expire_time,omitempty"`
	KMSKeyID      string   `json:"kms_key_id"`
	SecretName    string   `json:"secret_name"`
	VersionStages []string `json:"version_stages"`
}

func toVersionMetadataView(sec Secret, ver Version) versionMetadataView {
	v := versionMetadataView{
		ID:            ver.ID,
		CreateTime:    ver.CreatedAt,
		KMSKeyID:      ver.KMSKeyID,
		SecretName:    sec.Name,
		VersionStages: stagesForVersion(sec.Stages, ver.ID),
	}
	if ver.ExpireAt > 0 {
		exp := ver.ExpireAt
		v.ExpireTime = &exp
	}
	return v
}

type versionMetadataResponse struct {
	VersionMetadata versionMetadataView `json:"version_metadata"`
}

type listVersionsResponse struct {
	VersionMetadatas []versionMetadataView `json:"version_metadatas"`
	PageInfo         pageInfoView          `json:"page_info"`
}

type versionView struct {
	VersionMetadata versionMetadataView `json:"version_metadata"`
	SecretBinary    *string             `json:"secret_binary,omitempty"`
	SecretString    *string             `json:"secret_string,omitempty"`
}

type versionResponse struct {
	Version versionView `json:"version"`
}

type stageView struct {
	Name       string `json:"name"`
	UpdateTime int64  `json:"update_time"`
	SecretName string `json:"secret_name"`
	VersionID  string `json:"version_id"`
}

func toStageView(secretName, stageName string, st Stage) stageView {
	return stageView{
		Name:       stageName,
		UpdateTime: st.UpdatedAt,
		SecretName: secretName,
		VersionID:  st.VersionID,
	}
}

type stageResponse struct {
	Stage stageView `json:"stage"`
}
