package iam

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Classic IAM permissions: the system-defined roles and policies every
// account has, and the account's custom policies (/v3.0/OS-ROLE/roles).
// Classic IAM calls both "roles", and assigns either to user groups.

const kindRole = "iam.role"

// Scopes of a permission, its "type": AX global services, XA
// region-specific projects, AA both.
const (
	typeGlobal  = "AX"
	typeProject = "XA"
	typeBoth    = "AA"
)

// role is a system-defined or custom permission, as the API shows it.
type role struct {
	ID            string
	Name          string
	DisplayName   string
	Type          string
	Catalog       string
	Description   string
	DescriptionCN string
	// Fine marks a fine-grained policy (Version 1.1), as opposed to a
	// role (Version 1.0).
	Fine   bool
	Policy json.RawMessage
	Custom bool
	// Created and Updated are a custom policy's.
	Created, Updated time.Time
}

// systemRole describes a system-defined permission. Names, display
// names and descriptions are those Huawei documents (the Terraform
// provider's identity_role table); scope and kind come from Huawei's
// table of system-defined permissions. The catalog is the service's
// abbreviation, BASE for account-wide permissions and Server
// Administrator, as Huawei's examples show it.
//
// Huawei does not publish the statements of its system permissions,
// only what each one allows ("supported operations" tables on each
// service's permissions page, and the descriptions). The statements
// here are written to match those: FullAccess grants every action of
// the service, ReadOnlyAccess its get and list actions (which, through
// the classic aliases, cover every read), and the others what their
// tables and descriptions say. roles_matrix_test.go checks each against
// the documented tables.
type systemRole struct {
	name, display, description, catalog, scope string
	fine                                       bool
	statements                                 []systemStatement
}

// systemStatement is one Allow statement: Actions, or with Not every
// action except those.
type systemStatement struct {
	Not     bool
	Actions []string
}

func allow(actions ...string) []systemStatement {
	return []systemStatement{{Actions: actions}}
}

// readOnly is the get and list actions of the given services.
func readOnly(services ...string) []systemStatement {
	var actions []string
	for _, svc := range services {
		actions = append(actions, svc+":*:get*", svc+":*:list*")
	}
	return allow(actions...)
}

// tenantServices are the services of the account-wide roles Tenant
// Administrator and Tenant Guest, which cover every service but IAM.
var tenantServices = []string{"ecs", "evs", "ims", "vpc", "obs", "rds", "eps", "nat", "elb", "kms"}

// OBS's documented permissions (usermanual-permissions iam_01_0001,
// and the statement of Huawei's policy example in iam_01_0019).
var (
	obsBucketsViewer = []string{"obs:bucket:listAllMyBuckets", "obs:bucket:headBucket", "obs:bucket:getBucketLocation"}
	obsReadOnly      = append(slices.Clone(obsBucketsViewer), "obs:bucket:listBucket")
	obsOperate       = append(slices.Clone(obsReadOnly),
		"obs:object:putObject", "obs:object:getObject", "obs:object:deleteObject", "obs:object:getObjectAcl",
		"obs:bucket:listBucketMultipartUploads", "obs:object:listMultipartUploadParts", "obs:object:abortMultipartUpload")
)

// vpcAdministrator is every VPC resource type but security groups and
// their rules, which the role excludes (productdesc-vpc
// overview_permission).
var vpcAdministrator = []string{
	"vpc:vpcs:*", "vpc:subnets:*", "vpc:subNetworkInterfaces:*", "vpc:ports:*", "vpc:privateIps:*",
	"vpc:networks:*", "vpc:routeTables:*", "vpc:peerings:*", "vpc:firewalls:*", "vpc:addressGroups:*",
	"vpc:flowLogs:*", "vpc:trafficMirrorSessions:*", "vpc:trafficMirrorFilters:*",
	"vpc:trafficMirrorFilterRules:*", "vpc:quotas:*", "vpc:nativeSubnets:*", "vpc:nativePorts:*",
	"vpc:nativeNetworks:*", "vpc:nativeRouters:*", "vpc:nativeFirewallGroups:*",
	"vpc:nativeFirewallPolicies:*", "vpc:nativeFirewallRules:*",
}

// systemRoles is the catalogue: the services WeiStack emulates, and the
// account-wide permissions.
var systemRoles = []systemRole{
	{"system_all_1001", "FullAccess", "Full permissions for all services that support policy-based authorization", "BASE", typeGlobal, true, allow("*:*:*")},
	{"te_admin", "Tenant Administrator", "Tenant Administrator (Exclude IAM)", "BASE", typeBoth, false, []systemStatement{{Not: true, Actions: []string{"iam:*:*"}}}},
	{"readonly", "Tenant Guest", "Tenant Guest (Exclude IAM)", "BASE", typeBoth, false, append(readOnly(tenantServices...), allow("obs:bucket:headBucket")...)},
	{"secu_admin", "Security Administrator", "Full permissions for Identity and Access Management", "BASE", typeGlobal, false, allow("iam:*:*")},

	{"server_adm", "Server Administrator", "Server Administrator", "BASE", typeProject, false, allow(
		"ecs:*:*", "evs:*:*", "ims:*:*", "vpc:securityGroups:*", "vpc:securityGroupRules:*", "vpc:ports:*", "vpc:firewalls:*")},
	{"system_all_3", "ECS FullAccess", "All permissions of ECS service", "ECS", typeProject, true, allow("ecs:*:*")},
	{"system_all_1", "ECS CommonOperations", "Permissions for basic ECS operations,such as start,stop restart a ECS,query ECS details,automatic recovery of ECSs and so on", "ECS", typeProject, true, allow(
		"ecs:*:get*", "ecs:*:list*", "ecs:cloudServers:start", "ecs:cloudServers:stop", "ecs:cloudServers:reboot",
		"ecs:cloudServers:vnc", "ecs:cloudServers:batchCreateServerTags", "ecs:cloudServers:batchDeleteServerTags",
		"ecs:cloudServers:getAutoRecovery", "ecs:cloudServers:setAutoRecovery")},
	{"system_all_8", "ECS ReadOnlyAccess", "The read-only permissions to all ECS resources, which can be used for statistics and survey", "ECS", typeProject, true, readOnly("ecs")},

	{"ims_adm", "IMS Administrator", "IMS Administrator", "IMS", typeProject, false, allow("ims:*:*")},
	{"system_all_16", "IMS FullAccess", "All permissions of Image Management Service", "IMS", typeProject, true, allow("ims:*:*")},
	{"system_all_22", "IMS ReadOnlyAccess", "The read-only permissions to all IMS resources, which can be used for statistics and survey", "IMS", typeProject, true, readOnly("ims")},

	{"system_all_6", "EVS FullAccess", "Full permissions for Elastic Volume Service, including creating, expanding, attaching, detaching, querying, and deleting EVS disks", "EVS", typeProject, true, allow("evs:*:*")},
	{"system_all_2", "EVS ReadOnlyAccess", "Read-only permissions for Elastic Volume Service", "EVS", typeProject, true, readOnly("evs")},

	{"system_all_159", "OBS Administrator", "Object Storage Service Administrator", "OBS", typeGlobal, true, allow("obs:*:*")},
	{"system_all_72", "OBS OperateAccess", "Basic operation permissions to view the bucket list, obtain bucket metadata, list objects in a bucket, query bucket location, upload objects, download objects, delete objects, and obtain object ACLs", "OBS", typeGlobal, true, allow(obsOperate...)},
	{"system_all_64", "OBS ReadOnlyAccess", "Permissions to view the bucket list, obtain bucket metadata, list objects in a bucket, and query bucket location", "OBS", typeGlobal, true, allow(obsReadOnly...)},
	{"obs_b_list", "OBS Buckets Viewer", "Permissions to view the bucket list, obtain bucket metadata, and query bucket location", "OBS", typeGlobal, false, allow(obsBucketsViewer...)},

	{"vpc_netadm", "VPC Administrator", "VPC Administrator", "VPC", typeProject, false, allow(vpcAdministrator...)},
	{"system_all_7", "VPC FullAccess", "All permissions of VPC service", "VPC", typeProject, true, allow("vpc:*:*")},
	{"system_all_5", "VPC ReadOnlyAccess", "The read-only permissions to all VPC resources, which can be used for statistics and survey", "VPC", typeProject, true, readOnly("vpc")},

	{"rds_adm", "RDS Administrator", "RDS Administrator", "RDS", typeProject, false, allow("rds:*:*")},
	{"system_all_14", "RDS FullAccess", "Full permissions for Relational Database Service", "RDS", typeProject, true, allow("rds:*:*")},
	{"system_all_12", "RDS ReadOnlyAccess", "Read-only permissions for Relational Database Service", "RDS", typeProject, true, readOnly("rds")},

	{"nat_adm", "NAT Administrator", "NAT Gateway administrator with full permissions for this service", "NAT", typeProject, false, allow("nat:*:*")},
	{"system_all_75", "NAT FullAccess", "All permissions of NAT Gateway service", "NAT", typeProject, true, allow("nat:*:*")},
	{"system_all_76", "NAT ReadOnlyAccess", "The read-only permissions to all NAT Gateway resources", "NAT", typeProject, true, readOnly("nat")},

	{"elb_adm", "ELB Administrator", "Elastic Load Balance administrator with full permissions for this service", "ELB", typeProject, false, allow("elb:*:*")},
	{"system_all_56", "ELB FullAccess", "All permissions of ELB service", "ELB", typeProject, true, allow("elb:*:*")},
	{"system_all_55", "ELB ReadOnlyAccess", "Read-only permissions for Elastic Load Balance", "ELB", typeProject, true, readOnly("elb")},

	{"kms_adm", "KMS Administrator", "KMS Administrator", "KMS", typeProject, false, allow("kms:*:*")},
	{"system_all_10", "EPS FullAccess", "All operations on the Enterprise Project Management service", "EPS", typeGlobal, true, allow("eps:*:*")},
}

// document is a system permission's policy: Version 1.1 for a
// fine-grained policy, 1.0 for a role.
func (sr systemRole) document() json.RawMessage {
	type stmt struct {
		Effect    string   `json:"Effect"`
		Action    []string `json:"Action,omitempty"`
		NotAction []string `json:"NotAction,omitempty"`
	}
	doc := struct {
		Version   string `json:"Version"`
		Statement []stmt `json:"Statement"`
	}{Version: policydoc.VersionRole}
	if sr.fine {
		doc.Version = policydoc.VersionFine
	}
	for _, st := range sr.statements {
		s := stmt{Effect: "Allow", Action: st.Actions}
		if st.Not {
			s.Action, s.NotAction = nil, st.Actions
		}
		doc.Statement = append(doc.Statement, s)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err) // static data
	}
	return raw
}

// catalogue is systemRoles as roles, and by ID. Each document is parsed
// once, so a mistake in the table fails at start-up.
var catalogue, catalogueByID = func() ([]role, map[string]role) {
	all := make([]role, 0, len(systemRoles))
	byID := make(map[string]role, len(systemRoles))
	for _, sr := range systemRoles {
		sum := sha256.Sum256([]byte("weistack:system-role:" + sr.name))
		doc := sr.document()
		if _, err := policydoc.Parse(doc); err != nil {
			panic(fmt.Sprintf("iam: system role %s: %v", sr.name, err))
		}
		ro := role{
			ID: hex.EncodeToString(sum[:16]), Name: sr.name, DisplayName: sr.display, Type: sr.scope,
			Catalog: sr.catalog, Description: sr.description, Fine: sr.fine, Policy: doc,
		}
		all = append(all, ro)
		byID[ro.ID] = ro
	}
	return all, byID
}()

// customRole is a custom policy record.
type customRole struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	DisplayName   string          `json:"display_name"`
	Type          string          `json:"type"`
	Description   string          `json:"description"`
	DescriptionCN string          `json:"description_cn,omitempty"`
	Policy        json.RawMessage `json:"policy"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

func (c customRole) role() role {
	return role{
		ID: c.ID, Name: c.Name, DisplayName: c.DisplayName, Type: c.Type, Catalog: "CUSTOMED",
		Description: c.Description, DescriptionCN: c.DescriptionCN, Fine: true, Policy: c.Policy,
		Custom: true, Created: c.CreatedAt, Updated: c.UpdatedAt,
	}
}

func (s *Service) customRoles(ctx context.Context) store.Collection[customRole] {
	return store.Of[customRole](s.store, s.scope(ctx, kindRole))
}

// findRole returns a system or custom role by ID.
func (s *Service) findRole(ctx context.Context, id string) (role, bool, error) {
	if ro, ok := catalogueByID[id]; ok {
		return ro, true, nil
	}
	c, err := s.customRoles(ctx).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return role{}, false, nil
	}
	return c.role(), err == nil, err
}

// roleView mirrors the SDK models RoleResult and the custom policy
// results.
type roleView struct {
	DomainID      *string         `json:"domain_id"`
	Flag          string          `json:"flag,omitempty"`
	DescriptionCN *string         `json:"description_cn,omitempty"`
	Catalog       string          `json:"catalog"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Links         links           `json:"links"`
	ID            string          `json:"id"`
	DisplayName   string          `json:"display_name"`
	Type          string          `json:"type"`
	Policy        json.RawMessage `json:"policy"`
	References    *int            `json:"references,omitempty"`
	CreatedTime   string          `json:"created_time,omitempty"`
	UpdatedTime   string          `json:"updated_time,omitempty"`
}

// unixMillis is how custom policy times are written: a Unix time in
// milliseconds, as a string.
func unixMillis(t time.Time) string { return strconv.FormatInt(t.UnixMilli(), 10) }

func (s *Service) roleView(r *http.Request, ro role) roleView {
	ctx := r.Context()
	v := roleView{
		Catalog: ro.Catalog, Name: ro.Name, Description: ro.Description, ID: ro.ID,
		DisplayName: ro.DisplayName, Type: ro.Type, Policy: ro.Policy,
		Links: links{Self: selfURL(r, "/v3/roles/"+ro.ID)},
	}
	if ro.Fine && !ro.Custom {
		v.Flag = "fine_grained"
	}
	if ro.DescriptionCN != "" {
		v.DescriptionCN = &ro.DescriptionCN
	}
	if ro.Custom {
		acct := s.account(ctx).ID
		v.DomainID = &acct
		v.CreatedTime, v.UpdatedTime = unixMillis(ro.Created), unixMillis(ro.Updated)
	}
	return v
}

type roleResponse struct {
	Role roleView `json:"role"`
}

type rolesResponse struct {
	Roles       []roleView `json:"roles"`
	Links       links      `json:"links"`
	TotalNumber int        `json:"total_number"`
}

// pageOf cuts Keystone's page and per_page from all; perPage 0 means
// everything.
func pageOf[T any](all []T, page, perPage int) []T {
	if perPage == 0 {
		return all
	}
	start := min((page-1)*perPage, len(all))
	return all[start:min(start+perPage, len(all))]
}

// readPaging reads page and per_page, per_page at most maxPerPage.
func readPaging(r *http.Request, maxPerPage int) (int, int, error) {
	q := r.URL.Query()
	page, perPage, err := paging(q.Get("page"), q.Get("per_page"))
	if err == nil && perPage > maxPerPage {
		err = errInvalidParam("per_page")
	}
	return page, perPage, err
}

// GET /v3/roles: the system-defined permissions, or with domain_id the
// account's custom policies.
func (s *Service) handleListRoles(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	q := r.URL.Query()
	page, perPage, err := readPaging(r, 500)
	if err != nil {
		return err
	}
	scopes := map[string][]string{
		"":        nil,
		"all":     nil,
		"domain":  {typeBoth, typeGlobal},
		"project": {typeBoth, typeProject},
	}
	inScope, ok := scopes[q.Get("type")]
	if !ok {
		return errInvalidParam("type")
	}
	permType := q.Get("permission_type")
	if permType != "" && permType != "policy" && permType != "role" {
		return errInvalidParam("permission_type")
	}

	var all []role
	if d := q.Get("domain_id"); d != "" {
		if d == s.account(ctx).ID {
			all, err = s.listCustomRoles(ctx)
			if err != nil {
				return err
			}
		}
	} else {
		all = catalogue
	}
	keep := func(ro role) bool {
		switch {
		case q.Get("name") != "" && ro.Name != q.Get("name"),
			q.Get("display_name") != "" && !strings.Contains(ro.DisplayName, q.Get("display_name")),
			q.Get("catalog") != "" && ro.Catalog != q.Get("catalog"),
			inScope != nil && !slices.Contains(inScope, ro.Type),
			permType == "policy" && !ro.Fine,
			permType == "role" && ro.Fine:
			return false
		}
		return true
	}
	all = slices.DeleteFunc(slices.Clone(all), func(ro role) bool { return !keep(ro) })
	return s.writeRoles(w, r, "/v3/roles", all, page, perPage)
}

func (s *Service) writeRoles(w http.ResponseWriter, r *http.Request, path string, all []role, page, perPage int) error {
	got := pageOf(all, page, perPage)
	out := rolesResponse{Roles: make([]roleView, 0, len(got)), Links: links{Self: selfURL(r, path)}, TotalNumber: len(all)}
	for _, ro := range got {
		out.Roles = append(out.Roles, s.roleView(r, ro))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) listCustomRoles(ctx context.Context) ([]role, error) {
	cs, err := s.customRoles(ctx).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make([]role, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.role())
	}
	return out, nil
}

// getRole returns the role in the path, or IAM.0004.
func (s *Service) getRole(r *http.Request) (role, error) {
	id := chi.URLParam(r, "role_id")
	ro, ok, err := s.findRole(r.Context(), id)
	if err == nil && !ok {
		err = errNotFound("role", id)
	}
	return ro, err
}

// GET /v3/roles/{role_id}.
func (s *Service) handleShowRole(w http.ResponseWriter, r *http.Request) error {
	ro, err := s.getRole(r)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, roleResponse{s.roleView(r, ro)})
}

// Custom policies: /v3.0/OS-ROLE/roles.

// customRoleBody is a custom policy request. Fields are raw so that each
// can be checked as Huawei's error codes describe.
type customRoleBody struct {
	Role *struct {
		DisplayName   json.RawMessage `json:"display_name"`
		Type          json.RawMessage `json:"type"`
		Description   json.RawMessage `json:"description"`
		DescriptionCN json.RawMessage `json:"description_cn"`
		Policy        json.RawMessage `json:"policy"`
	} `json:"role"`
}

// Rules for custom policies, from Huawei's documentation and error codes.
// The display name's limit is the documented constraint, 128 characters,
// though IAM.1002's published message says 64; the message is kept as
// published.
const (
	maxPolicyChars  = 6144
	maxStatements   = 8
	maxActions      = 100
	maxActionLen    = 128
	maxResourceURIs = 20
	maxDisplayName  = 128
)

var (
	displayNameRE = regexp.MustCompile(`^[\p{L}0-9 \-_.,]+$`)
	actionRE      = regexp.MustCompile(`^[a-zA-Z0-9*?_\-]+:[a-zA-Z0-9*?_\-]+:[a-zA-Z0-9*?_\-.]+$`)
)

// rawString reads a JSON string; ok is false if raw is present and not a
// string.
func rawString(raw json.RawMessage) (s string, present, ok bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", false, true
	}
	err := json.Unmarshal(raw, &s)
	return s, true, err == nil
}

// applyCustomRole validates b and applies it to c. On create every field
// but description_cn is required.
func applyCustomRole(b customRoleBody, c *customRole, create bool) error {
	if b.Role == nil {
		return errRequired("role")
	}
	f := b.Role

	name, present, ok := rawString(f.DisplayName)
	switch {
	case !ok || (present || create) && strings.TrimSpace(name) == "":
		return errDisplayNameBlank
	case present && utf8.RuneCountInString(name) > maxDisplayName:
		return errDisplayNameLong(utf8.RuneCountInString(name))
	case present && !displayNameRE.MatchString(name):
		return errDisplayNameChars
	case present:
		c.DisplayName = name
	}

	typ, present, ok := rawString(f.Type)
	switch {
	case !ok || (present || create) && strings.TrimSpace(typ) == "":
		return errTypeBlank
	case present && typ != typeGlobal && typ != typeProject:
		return errCustomType
	case present:
		c.Type = typ
	}

	// No limits are documented for the descriptions; they must be
	// strings.
	desc, present, ok := rawString(f.Description)
	switch {
	case !ok:
		return errRoleDescription
	case present:
		c.Description = desc
	}
	descCN, present, ok := rawString(f.DescriptionCN)
	switch {
	case !ok:
		return errRoleDescriptionCN
	case present:
		c.DescriptionCN = descCN
	}

	if len(f.Policy) == 0 || string(f.Policy) == "null" {
		if create {
			return errRequired("policy")
		}
		return nil
	}
	policy, err := checkPolicy(f.Policy)
	if err != nil {
		return err
	}
	c.Policy = policy
	return nil
}

// checkPolicy validates a custom policy document and returns it compact.
func checkPolicy(raw json.RawMessage) (json.RawMessage, error) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, errPolicyObject
	}
	if n := utf8.RuneCount(compact.Bytes()); n > maxPolicyChars {
		return nil, errPolicySize(n)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errPolicyObject
	}
	if v, _, ok := rawString(doc["Version"]); !ok || v != "1.1" {
		return nil, errPolicyVersion
	}
	var statements []map[string]json.RawMessage
	if err := json.Unmarshal(doc["Statement"], &statements); err != nil || doc["Statement"] == nil {
		return nil, errStatementArray
	}
	if len(statements) == 0 || len(statements) > maxStatements {
		return nil, errStatementCount(len(statements))
	}
	for _, st := range statements {
		if err := checkStatement(st); err != nil {
			return nil, err
		}
	}
	// The document must also be one the evaluator understands: its
	// resources and conditions are checked here.
	if _, err := policydoc.Parse(compact.Bytes()); err != nil {
		return nil, classicPolicyError(err)
	}
	return json.RawMessage(compact.Bytes()), nil
}

// classicPolicyError maps a document error to the code classic IAM
// documents for it.
func classicPolicyError(err error) error {
	var pe *policydoc.Error
	if !errors.As(err, &pe) {
		return errPolicyObject
	}
	switch pe.Kind {
	case policydoc.ErrResource:
		service, _, _ := strings.Cut(pe.Item, ":")
		return apiErr400("IAM.1045", fmt.Sprintf("Resource URI '%s' or service '%s' is invalid.", pe.Item, service))
	case policydoc.ErrOperator:
		return apiErr400("IAM.1059", fmt.Sprintf("Invalid key '%s'.", pe.Item))
	case policydoc.ErrConditionKey:
		return apiErr400("IAM.1052", fmt.Sprintf("Invalid attribute '%s'.", pe.Item))
	case policydoc.ErrConditionList:
		return apiErr400("IAM.1053", fmt.Sprintf("Attribute '%s' must be a JSONArray.", pe.Item))
	case policydoc.ErrConditionValue:
		return apiErr400("IAM.1057", fmt.Sprintf("Value %s of attribute %s for operator %s contains invalid characters.", pe.Value, pe.Item, pe.Operator))
	case policydoc.ErrEffect:
		return errEffect
	case policydoc.ErrAction:
		return errActionArray
	case policydoc.ErrStatement:
		return errStatementArray
	}
	return errPolicyObject
}

func checkStatement(st map[string]json.RawMessage) error {
	effect, _, ok := rawString(st["Effect"])
	if !ok || !strings.EqualFold(effect, "allow") && !strings.EqualFold(effect, "deny") {
		return errEffect
	}
	action, notAction := st["Action"], st["NotAction"]
	if action != nil && notAction != nil {
		return errActionAndNotAction
	}
	if action == nil {
		action = notAction
	}
	var actions []string
	if err := json.Unmarshal(action, &actions); err != nil || action == nil {
		return errActionArray
	}
	if len(actions) > maxActions {
		return errActionCount(len(actions))
	}
	for _, a := range actions {
		if len(a) > maxActionLen {
			return errActionLen(len(a))
		}
		if !actionRE.MatchString(a) {
			return errActionChars(a)
		}
	}
	if res, ok := st["Resource"]; ok && string(res) != "null" {
		var uris []string
		if json.Unmarshal(res, &uris) == nil && (len(uris) == 0 || len(uris) > maxResourceURIs) {
			return errResourceCount(len(uris))
		}
	}
	return nil
}

// nextCustomName returns the next custom policy name, as Huawei names
// them: custom_<account ID>_<n>. The caller holds s.mu.
func (s *Service) nextCustomName(ctx context.Context) (string, error) {
	prefix := "custom_" + s.account(ctx).ID + "_"
	all, err := s.customRoles(ctx).List(ctx, nil)
	if err != nil {
		return "", err
	}
	next := 0
	for _, c := range all {
		if n, err := strconv.Atoi(strings.TrimPrefix(c.Name, prefix)); err == nil && n >= next {
			next = n + 1
		}
	}
	return prefix + strconv.Itoa(next), nil
}

// POST /v3.0/OS-ROLE/roles.
func (s *Service) handleCreateCustomRole(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	var b customRoleBody
	if err := decodeClassic(r, &b); err != nil {
		return err
	}
	now := s.now().UTC()
	c := customRole{ID: s.ids.Hex32(), CreatedAt: now, UpdatedAt: now}
	if err := applyCustomRole(b, &c, true); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, err := s.nextCustomName(ctx)
	if err != nil {
		return err
	}
	c.Name = name
	if err := s.customRoles(ctx).Create(ctx, c.ID, c); err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, roleResponse{s.roleView(r, c.role())})
}

// GET /v3.0/OS-ROLE/roles.
func (s *Service) handleListCustomRoles(w http.ResponseWriter, r *http.Request) error {
	page, perPage, err := readPaging(r, 300)
	if err != nil {
		return err
	}
	all, err := s.listCustomRoles(r.Context())
	if err != nil {
		return err
	}
	return s.writeRoles(w, r, "/v3/roles", all, page, perPage)
}

func (s *Service) getCustomRole(r *http.Request) (customRole, error) {
	ctx := r.Context()
	id := chi.URLParam(r, "role_id")
	c, err := s.customRoles(ctx).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return customRole{}, errNotFound("role", id)
	}
	return c, err
}

// GET /v3.0/OS-ROLE/roles/{role_id}, with the number of assignments.
func (s *Service) handleShowCustomRole(w http.ResponseWriter, r *http.Request) error {
	c, err := s.getCustomRole(r)
	if err != nil {
		return err
	}
	refs, err := s.assignmentsOf(r.Context(), func(a assignment) bool { return a.RoleID == c.ID })
	if err != nil {
		return err
	}
	v := s.roleView(r, c.role())
	n := len(refs)
	v.References = &n
	return httpx.WriteJSON(w, http.StatusOK, roleResponse{v})
}

// PATCH /v3.0/OS-ROLE/roles/{role_id}.
func (s *Service) handleUpdateCustomRole(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	var b customRoleBody
	if err := decodeClassic(r, &b); err != nil {
		return err
	}
	id := chi.URLParam(r, "role_id")
	now := s.now().UTC()
	c, err := s.customRoles(ctx).Update(ctx, id, func(c *customRole) error {
		if err := applyCustomRole(b, c, false); err != nil {
			return err
		}
		c.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("role", id)
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, roleResponse{s.roleView(r, c.role())})
}

// DELETE /v3.0/OS-ROLE/roles/{role_id}: the policy and its assignments.
// Huawei answers 200 with a message.
func (s *Service) handleDeleteCustomRole(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	c, err := s.getCustomRole(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.deleteAssignments(ctx, func(a assignment) bool { return a.RoleID == c.ID }); err != nil {
		return err
	}
	if err := s.customRoles(ctx).Delete(ctx, c.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, struct {
		Message string `json:"message"`
	}{"Delete success"})
}

// The custom policy codes of classic IAM's table.
var (
	errDisplayNameBlank   = apiErr400("IAM.1001", "The display_name must be a string and cannot be left blank or contain spaces.")
	errDisplayNameChars   = apiErr400("IAM.1003", "The display_name contains invalid characters.")
	errTypeBlank          = apiErr400("IAM.1004", "The type must be a string and cannot be left blank or contain spaces.")
	errCustomType         = apiErr400("IAM.1009", "The type of a custom policy must be 'AX' or 'XA'.")
	errRoleDescription    = apiErr400("IAM.1018", "Invalid description.")
	errRoleDescriptionCN  = apiErr400("IAM.1019", "Invalid description_cn.")
	errPolicyObject       = apiErr400("IAM.1020", "The policy must be a JSONObject.")
	errPolicyVersion      = apiErr400("IAM.1024", "The version of a fine-grained policy must be '1.1'.")
	errStatementArray     = apiErr400("IAM.1027", "The Statement/Rules must be a JSONArray.")
	errEffect             = apiErr400("IAM.1029", "The value of Effect must be 'allow' or 'deny'.")
	errActionArray        = apiErr400("IAM.1030", "The Action or NotAction must be a JSONArray.")
	errActionAndNotAction = apiErr400("IAM.1031", "The Action and NotAction cannot be set at the same time in a statement.")
)

func errDisplayNameLong(n int) error {
	return apiErr400("IAM.1002", fmt.Sprintf("The length [%d] of the display name exceeds 64 characters.", n))
}

func errPolicySize(n int) error {
	return apiErr400("IAM.1021", fmt.Sprintf("The size [%d] of the policy exceeds 6,144 characters.", n))
}

func errStatementCount(n int) error {
	return apiErr400("IAM.1028", fmt.Sprintf("The number of statements [%d] must be greater than 0 and less than or equal to 8.", n))
}

func errActionCount(n int) error {
	return apiErr400("IAM.1033", fmt.Sprintf("The number of actions [%d] exceeds 100.", n))
}

func errActionLen(n int) error {
	return apiErr400("IAM.1034", fmt.Sprintf("The length [%d] of an action URN exceeds 128 characters.", n))
}

func errActionChars(urn string) error {
	return apiErr400("IAM.1035", fmt.Sprintf("Action URN '%s' contains invalid characters.", urn))
}

func errResourceCount(n int) error {
	return apiErr400("IAM.1037", fmt.Sprintf("The number of resource URIs [%d] must be greater than 0 and less than or equal to 20.", n))
}
