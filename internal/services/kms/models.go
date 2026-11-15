package kms

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"
)

// Request and response types mirror the official Go SDK's models
// (services/kms/v2/model). KMS sends numbers as strings ("pending_days":
// "7"), as the SDK and Terraform's client do; number accepts either.

// number is a count sent as a JSON string or number.
type number struct {
	set bool
	v   int
	bad bool
}

func (n *number) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		return nil
	}
	n.set = true
	var s string
	if json.Unmarshal(b, &s) == nil {
		v, err := strconv.Atoi(s)
		n.v, n.bad = v, err != nil
		return nil
	}
	var v int
	n.bad = json.Unmarshal(b, &v) != nil
	n.v = v
	return nil
}

// keyRef is the body of the operations that name only a key.
type keyRef struct {
	KeyID    string `json:"key_id"`
	Sequence string `json:"sequence"`
}

type createKeyRequest struct {
	KeyAlias            string `json:"key_alias"`
	KeySpec             string `json:"key_spec"`
	KeyUsage            string `json:"key_usage"`
	KeyDescription      string `json:"key_description"`
	Origin              string `json:"origin"`
	EnterpriseProjectID string `json:"enterprise_project_id"`
	Sequence            string `json:"sequence"`
	KeystoreID          string `json:"keystore_id"`
}

type keyInfo struct {
	KeyID    string `json:"key_id"`
	DomainID string `json:"domain_id"`
}

// keyDetails is the SDK's KeyDetails.
type keyDetails struct {
	KeyID                  string `json:"key_id"`
	DomainID               string `json:"domain_id"`
	KeyAlias               string `json:"key_alias"`
	Realm                  string `json:"realm"`
	KeySpec                string `json:"key_spec"`
	KeyUsage               string `json:"key_usage"`
	KeyDescription         string `json:"key_description"`
	CreationDate           string `json:"creation_date"`
	ScheduledDeletionDate  string `json:"scheduled_deletion_date"`
	KeyState               string `json:"key_state"`
	DefaultKeyFlag         string `json:"default_key_flag"`
	KeyType                string `json:"key_type"`
	ExpirationTime         string `json:"expiration_time"`
	Origin                 string `json:"origin"`
	KeyRotationEnabled     string `json:"key_rotation_enabled"`
	SysEnterpriseProjectID string `json:"sys_enterprise_project_id"`
	KeystoreID             string `json:"keystore_id"`
	KeystoreType           string `json:"keystore_type"`
}

// millis is KMS's time format: milliseconds since the epoch, as a
// string.
func millis(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return strconv.FormatInt(t.UnixMilli(), 10)
}

// defaultKeystore is the ID KMS shows for its own keystore.
const defaultKeystore = "0"

func details(k key) keyDetails {
	d := keyDetails{
		KeyID: k.ID, DomainID: k.AccountID, KeyAlias: k.Alias, Realm: k.Region, KeySpec: k.Spec, KeyUsage: k.Usage,
		KeyDescription: k.Description, CreationDate: millis(k.CreatedAt), KeyState: k.State,
		DefaultKeyFlag: "0", KeyType: "1", Origin: k.Origin, KeyRotationEnabled: strconv.FormatBool(k.Rotation),
		SysEnterpriseProjectID: k.EP, KeystoreID: defaultKeystore, KeystoreType: "DEFAULT",
	}
	if k.Default {
		d.DefaultKeyFlag = "1"
	}
	if k.State == statePendingDeletion {
		d.ScheduledDeletionDate = millis(k.DeletionAt)
	}
	return d
}

type keyStatus struct {
	KeyID    string `json:"key_id"`
	KeyState string `json:"key_state"`
}

type listKeysRequest struct {
	Limit               number `json:"limit"`
	Marker              number `json:"marker"`
	KeyState            string `json:"key_state"`
	KeySpec             string `json:"key_spec"`
	EnterpriseProjectID string `json:"enterprise_project_id"`
	Sequence            string `json:"sequence"`
}

type listKeysResponse struct {
	Keys       []string     `json:"keys"`
	KeyDetails []keyDetails `json:"key_details"`
	NextMarker string       `json:"next_marker"`
	Truncated  string       `json:"truncated"`
	Total      int          `json:"total"`
}

type scheduleDeletionRequest struct {
	KeyID       string `json:"key_id"`
	PendingDays number `json:"pending_days"`
	Sequence    string `json:"sequence"`
}

type updateAliasRequest struct {
	KeyID    string `json:"key_id"`
	KeyAlias string `json:"key_alias"`
	Sequence string `json:"sequence"`
}

type updateDescriptionRequest struct {
	KeyID          string  `json:"key_id"`
	KeyDescription *string `json:"key_description"`
	Sequence       string  `json:"sequence"`
}

type encryptDataRequest struct {
	KeyID                       string `json:"key_id"`
	PlainText                   string `json:"plain_text"`
	EncryptionAlgorithm         string `json:"encryption_algorithm"`
	AdditionalAuthenticatedData string `json:"additional_authenticated_data"`
	Sequence                    string `json:"sequence"`
}

type decryptDataRequest struct {
	CipherText                  string `json:"cipher_text"`
	EncryptionAlgorithm         string `json:"encryption_algorithm"`
	KeyID                       string `json:"key_id"`
	AdditionalAuthenticatedData string `json:"additional_authenticated_data"`
	Sequence                    string `json:"sequence"`
}

type createDatakeyRequest struct {
	KeyID                       string `json:"key_id"`
	KeySpec                     string `json:"key_spec"`
	DatakeyLength               number `json:"datakey_length"`
	AdditionalAuthenticatedData string `json:"additional_authenticated_data"`
	Sequence                    string `json:"sequence"`
}

type encryptDatakeyRequest struct {
	KeyID                       string `json:"key_id"`
	PlainText                   string `json:"plain_text"`
	DatakeyPlainLength          number `json:"datakey_plain_length"`
	AdditionalAuthenticatedData string `json:"additional_authenticated_data"`
	Sequence                    string `json:"sequence"`
}

type decryptDatakeyRequest struct {
	KeyID                       string `json:"key_id"`
	CipherText                  string `json:"cipher_text"`
	DatakeyCipherLength         number `json:"datakey_cipher_length"`
	AdditionalAuthenticatedData string `json:"additional_authenticated_data"`
	Sequence                    string `json:"sequence"`
}

type rotationIntervalRequest struct {
	KeyID            string `json:"key_id"`
	RotationInterval number `json:"rotation_interval"`
	Sequence         string `json:"sequence"`
}

type rotationStatus struct {
	KeyRotationEnabled bool   `json:"key_rotation_enabled"`
	RotationInterval   int    `json:"rotation_interval"`
	LastRotationTime   string `json:"last_rotation_time"`
	NumberOfRotations  int    `json:"number_of_rotations"`
}

type tagItem struct {
	Key   string  `json:"key"`
	Value *string `json:"value"`
}

type tagFilter struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

type listByTagsRequest struct {
	Limit    number      `json:"limit"`
	Offset   number      `json:"offset"`
	Action   string      `json:"action"`
	Tags     []tagFilter `json:"tags"`
	Matches  []tagItem   `json:"matches"`
	Sequence string      `json:"sequence"`
}

type tagView struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type taggedResource struct {
	ResourceID     string     `json:"resource_id"`
	ResourceDetail keyDetails `json:"resource_detail"`
	ResourceName   string     `json:"resource_name"`
	Tags           []tagView  `json:"tags"`
}
