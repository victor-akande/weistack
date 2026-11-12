package vpc

import (
	"fmt"
	"time"

	"github.com/victor-akande/weistack/internal/core/wiretime"
)

// TimeZ is a timestamp in the VPC v3 wire format ("2020-07-09T05:56:27Z").
type TimeZ time.Time

// MarshalJSON implements json.Marshaler.
func (t TimeZ) MarshalJSON() ([]byte, error) {
	return wiretime.AppendQuoted(make([]byte, 0, 24), time.Time(t), true), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *TimeZ) UnmarshalJSON(b []byte) error {
	parsed, err := wiretime.ParseQuoted(b, true)
	if err != nil {
		return fmt.Errorf("vpc: timestamp %s: %w", b, err)
	}
	*t = TimeZ(parsed)
	return nil
}

// Tag mirrors the SDK model vpc/v3 ResourceTag.
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// SecurityGroup mirrors the SDK model vpc/v3 SecurityGroup: a group
// without its rules, as returned by the list operation. It is also the
// stored record.
type SecurityGroup struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Description         string `json:"description"`
	ProjectID           string `json:"project_id"`
	CreatedAt           TimeZ  `json:"created_at"`
	UpdatedAt           TimeZ  `json:"updated_at"`
	EnterpriseProjectID string `json:"enterprise_project_id"`
	Tags                []Tag  `json:"tags"`
}

// SecurityGroupInfo mirrors the SDK model vpc/v3 SecurityGroupInfo: a
// group with its rules, as returned by create, show and update.
type SecurityGroupInfo struct {
	SecurityGroup
	SecurityGroupRules []SecurityGroupRule `json:"security_group_rules"`
}

// SecurityGroupRule mirrors the SDK model vpc/v3 SecurityGroupRule.
// Unset optional fields are JSON null, as in the real API.
type SecurityGroupRule struct {
	ID                   string  `json:"id"`
	Description          string  `json:"description"`
	SecurityGroupID      string  `json:"security_group_id"`
	Direction            string  `json:"direction"`
	Protocol             *string `json:"protocol"`
	Ethertype            string  `json:"ethertype"`
	Multiport            *string `json:"multiport"`
	Action               string  `json:"action"`
	Priority             int     `json:"priority"`
	RemoteGroupID        *string `json:"remote_group_id"`
	RemoteIPPrefix       *string `json:"remote_ip_prefix"`
	RemoteAddressGroupID *string `json:"remote_address_group_id"`
	CreatedAt            TimeZ   `json:"created_at"`
	UpdatedAt            TimeZ   `json:"updated_at"`
	ProjectID            string  `json:"project_id"`
	Enabled              bool    `json:"enabled"`
}

// CreateSecurityGroupOption mirrors the SDK model vpc/v3
// CreateSecurityGroupOption.
type CreateSecurityGroupOption struct {
	Name                string  `json:"name"`
	Description         *string `json:"description"`
	EnterpriseProjectID *string `json:"enterprise_project_id"`
	Tags                *[]Tag  `json:"tags"`
}

// UpdateSecurityGroupOption mirrors the SDK model vpc/v3
// UpdateSecurityGroupOption. A nil field is left unchanged.
type UpdateSecurityGroupOption struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

// CreateSecurityGroupRuleOption mirrors the SDK model vpc/v3
// CreateSecurityGroupRuleOption.
type CreateSecurityGroupRuleOption struct {
	SecurityGroupID      string  `json:"security_group_id"`
	Description          *string `json:"description"`
	Direction            string  `json:"direction"`
	Ethertype            *string `json:"ethertype"`
	Protocol             *string `json:"protocol"`
	Multiport            *string `json:"multiport"`
	RemoteIPPrefix       *string `json:"remote_ip_prefix"`
	RemoteGroupID        *string `json:"remote_group_id"`
	RemoteAddressGroupID *string `json:"remote_address_group_id"`
	Action               *string `json:"action"`
	Priority             *int    `json:"priority"`
	Enabled              *bool   `json:"enabled"`
}

// ListSecurityGroupsFilter selects groups in ListSecurityGroups. A nil or
// empty slice matches everything; otherwise any listed value matches.
type ListSecurityGroupsFilter struct {
	IDs                 []string
	Names               []string
	Descriptions        []string
	EnterpriseProjectID string
}

// ListSecurityGroupRulesFilter selects rules in ListSecurityGroupRules.
type ListSecurityGroupRulesFilter struct {
	IDs                   []string
	SecurityGroupIDs      []string
	Protocols             []string
	Descriptions          []string
	RemoteGroupIDs        []string
	Ethertypes            []string
	RemoteAddressGroupIDs []string
	Priorities            []int
	Direction             string
	Action                string
	RemoteIPPrefix        string
	Enabled               *bool
}

// pageInfo mirrors the SDK model vpc/v3 PageInfo.
type pageInfo struct {
	PreviousMarker string  `json:"previous_marker"`
	CurrentCount   int     `json:"current_count"`
	NextMarker     *string `json:"next_marker,omitempty"`
}

type createSecurityGroupRequest struct {
	DryRun        bool                       `json:"dry_run"`
	SecurityGroup *CreateSecurityGroupOption `json:"security_group"`
}

type updateSecurityGroupRequest struct {
	DryRun        bool                       `json:"dry_run"`
	SecurityGroup *UpdateSecurityGroupOption `json:"security_group"`
}

type createSecurityGroupRuleRequest struct {
	DryRun            bool                           `json:"dry_run"`
	SecurityGroupRule *CreateSecurityGroupRuleOption `json:"security_group_rule"`
}

type securityGroupResponse struct {
	RequestID     string            `json:"request_id"`
	SecurityGroup SecurityGroupInfo `json:"security_group"`
}

type listSecurityGroupsResponse struct {
	RequestID      string          `json:"request_id"`
	SecurityGroups []SecurityGroup `json:"security_groups"`
	PageInfo       pageInfo        `json:"page_info"`
}

type securityGroupRuleResponse struct {
	RequestID         string            `json:"request_id"`
	SecurityGroupRule SecurityGroupRule `json:"security_group_rule"`
}

type listSecurityGroupRulesResponse struct {
	RequestID          string              `json:"request_id"`
	SecurityGroupRules []SecurityGroupRule `json:"security_group_rules"`
	PageInfo           pageInfo            `json:"page_info"`
}

// dryRunResponse is the 202 body of a request sent with dry_run: the
// checks passed and nothing was created.
type dryRunResponse struct {
	RequestID string `json:"request_id"`
	ErrorMsg  string `json:"error_msg"`
	ErrorCode string `json:"error_code"`
}
