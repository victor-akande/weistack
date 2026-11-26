package csms

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/identity"
	policydoc "github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

type tagStaticGrants struct {
	doc string
}

func (g tagStaticGrants) Grants(context.Context, identity.Principal, authz.Scope) (authz.Grants, error) {
	p, err := policydoc.Parse([]byte(g.doc))
	if err != nil {
		return authz.Grants{}, err
	}
	return authz.Grants{
		Sources: []policydoc.Source{{Name: "csms-tag-policy", Policy: p}},
	}, nil
}

func tagDoWithProvider(
	t *testing.T,
	e *env,
	principal identity.Principal,
	provider authz.Provider,
	method, path, body string,
) (int, []byte) {
	t.Helper()
	r := chi.NewRouter()
	e.kms.Routes(r)

	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, strings.ReplaceAll(path, "{project}", testProject), rd)
	req.Host = testHost
	req.Header.Set("Content-Type", "application/json")

	acct := e.dir.Account()
	gate := authz.NewGate(authz.GateOptions{
		Principal: principal,
		Account:   acct.ID,
		Provider:  provider,
		Sealer:    e.vault,
		Log:       e.svc.log,
	})
	ctx := reqctx.With(req.Context(), &reqctx.Info{RequestID: "req-tag-authz", Service: "kms", Region: testRegion})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req.WithContext(authz.WithGate(ctx, gate)))
	return w.Code, w.Body.Bytes()
}

func tagCreateSecret(t *testing.T, e *env, name, desc string) secretView {
	t.Helper()
	payload := fmt.Sprintf(`{"name":%q,"description":%q,"secret_string":%q}`, name, desc, "val-"+name)
	status, out := e.call(t, http.MethodPost, "/v1/{project}/secrets", payload)
	if status != http.StatusOK {
		t.Fatalf("CreateSecret(%s) = %d %s, want 200", name, status, out)
	}
	return decodeInto[secretResponse](t, out).Secret
}

func tagAssertDenied(t *testing.T, op string, status int, out []byte) {
	t.Helper()
	if status != http.StatusForbidden {
		t.Fatalf("%s = %d %s, want 403", op, status, out)
	}
	var errBody struct {
		Code string `json:"error_code"`
		Msg  string `json:"error_msg"`
		Enc  string `json:"encoded_authorization_message"`
	}
	if err := json.Unmarshal(out, &errBody); err != nil {
		t.Fatalf("%s decode denial %s: %v", op, out, err)
	}
	if errBody.Code != "CSMS.0302" || errBody.Enc == "" {
		t.Errorf("%s denial = %+v, want CSMS.0302 with encoded_authorization_message", op, errBody)
	}
}

func TestTagGolden(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	// Empty project tags before any secrets exist.
	e.expect(t, "tag_project_list_empty", http.MethodGet, "/v1/{project}/csms/tags", "")

	secA := tagCreateSecret(t, e, "app-db-secret", "db credentials")
	secB := tagCreateSecret(t, e, "app-cache-secret", "cache credentials")

	// Empty secret tags.
	e.expect(t, "tag_list_empty", http.MethodGet, "/v1/{project}/csms/"+secA.ID+"/tags", "")

	// CreateSecretTag + BatchCreateOrDeleteTags + ListSecretTags (including empty value "").
	e.expect(t, "tag_create", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags", `{"tag":{"key":"env","value":"prod"}}`)
	e.expect(t, "tag_batch_create", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags/action",
		`{"action":"create","tags":[{"key":"team","value":"platform"},{"key":"empty"}]}`)
	e.expect(t, "tag_list", http.MethodGet, "/v1/{project}/csms/"+secA.ID+"/tags", "")

	// Batch delete and single delete.
	e.expect(t, "tag_batch_delete", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags/action",
		`{"action":"delete","tags":[{"key":"empty"}]}`)
	e.expect(t, "tag_delete", http.MethodDelete, "/v1/{project}/csms/"+secA.ID+"/tags/team", "")

	// Add second tag on secA and a tag on secB, then query project tags & resource instances.
	e.expect(t, "tag_create", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags", `{"tag":{"key":"owner","value":"secops"}}`)
	e.expect(t, "tag_create", http.MethodPost, "/v1/{project}/csms/"+secB.ID+"/tags", `{"tag":{"key":"env","value":"staging"}}`)

	e.expect(t, "tag_project_list", http.MethodGet, "/v1/{project}/csms/tags", "")
	e.expect(t, "tag_instances_filter", http.MethodPost, "/v1/{project}/csms/resource_instances/action",
		`{"action":"filter","tags":[{"key":"env","values":["prod"]}]}`)
	e.expect(t, "tag_instances_count", http.MethodPost, "/v1/{project}/csms/resource_instances/action",
		`{"action":"count","tags":[{"key":"owner","values":["secops"]}]}`)

	// Error cases across all operations: CSMS.0002, CSMS.0004, CSMS.0005.
	const missingID = "00000000-0000-0000-0000-000000000000"

	e.expect(t, "tag_error_0004", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags", "{bad")
	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags", `{}`)
	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags", `{"tag":{"key":"_sys_reserved","value":"v"}}`)
	e.expect(t, "tag_error_0005", http.MethodPost, "/v1/{project}/csms/"+missingID+"/tags", `{"tag":{"key":"k","value":"v"}}`)

	e.expect(t, "tag_error_0005", http.MethodGet, "/v1/{project}/csms/"+missingID+"/tags", "")

	e.expect(t, "tag_error_0004", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags/action", "{bad")
	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags/action", `{"action":"invalid","tags":[{"key":"k"}]}`)
	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/"+secA.ID+"/tags/action", `{"action":"create","tags":[]}`)
	e.expect(t, "tag_error_0005", http.MethodPost, "/v1/{project}/csms/"+missingID+"/tags/action", `{"action":"create","tags":[{"key":"k","value":"v"}]}`)

	e.expect(t, "tag_error_0002", http.MethodDelete, "/v1/{project}/csms/"+secA.ID+"/tags/_sys_bad", "")
	e.expect(t, "tag_error_0005", http.MethodDelete, "/v1/{project}/csms/"+secA.ID+"/tags/no-such-key", "")
	e.expect(t, "tag_error_0005", http.MethodDelete, "/v1/{project}/csms/"+missingID+"/tags/env", "")

	e.expect(t, "tag_error_0004", http.MethodPost, "/v1/{project}/csms/resource_instances/action", "{bad")
	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/resource_instances/action", `{"action":"unknown"}`)
}

func TestTagValidationAndLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sec := tagCreateSecret(t, e, "tag-limits-sec", "")

	// Key & value length boundaries using service constants (never magic literals).
	maxKey := strings.Repeat("秘", maxTagKeyLen)
	overKey := maxKey + "x"
	maxVal := strings.Repeat("v", maxTagValueLen-1) + "/"
	overVal := maxVal + "x"

	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags",
		fmt.Sprintf(`{"tag":{"key":%q,"value":"ok"}}`, overKey))
	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags",
		fmt.Sprintf(`{"tag":{"key":"ok","value":%q}}`, overVal))

	// Valid boundary key & value (including '/' in value and Unicode letters in key).
	e.expect(t, "tag_create", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags",
		fmt.Sprintf(`{"tag":{"key":%q,"value":%q}}`, maxKey, maxVal))
	e.expect(t, "tag_delete", http.MethodDelete, "/v1/{project}/csms/"+sec.ID+"/tags/"+url.PathEscape(maxKey), "")

	// Invalid characters and whitespace rules.
	badKeys := []string{
		"",
		" leading",
		"trailing ",
		"_sys_internal",
		"slash/not/allowed",
		"star*bad",
		"ctrl\x07char",
	}
	for _, k := range badKeys {
		status, _ := e.call(t, http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags",
			fmt.Sprintf(`{"tag":{"key":%q,"value":"v"}}`, k))
		if status != http.StatusBadRequest {
			t.Errorf("CreateSecretTag with bad key %q = %d, want 400", k, status)
		}
	}

	// Keys starting with "sys_" (not "_sys_") and containing " _.:=+-@" are valid; URL-escaped delete works.
	specialKey := "sys_csms:rds.primary=1+2-3@host"
	e.expect(t, "tag_create", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags",
		fmt.Sprintf(`{"tag":{"key":%q,"value":"path/to/db"}}`, specialKey))
	e.expect(t, "tag_delete", http.MethodDelete, "/v1/{project}/csms/"+sec.ID+"/tags/"+url.PathEscape(specialKey), "")

	// Duplicate keys in BatchCreateOrDeleteTags must fail with CSMS.0002.
	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags/action",
		`{"action":"create","tags":[{"key":"dup","value":"1"},{"key":"dup","value":"2"}]}`)

	// Batch deleting a key that is not on the secret is idempotent (204).
	e.expect(t, "tag_batch_delete", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags/action",
		`{"action":"delete","tags":[{"key":"not-present","value":"ignored"}]}`)

	// Cap test using maxTagsPerSecret: fill up to maxTagsPerSecret, verify updating an existing key
	// succeeds, and adding 1 extra fails with 400 CSMS.0002.
	for i := range maxTagsPerSecret {
		body := fmt.Sprintf(`{"tag":{"key":"k-%d","value":"v-%d"}}`, i, i)
		status, out := e.call(t, http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags", body)
		if status != http.StatusNoContent {
			t.Fatalf("adding tag %d/%d = %d %s, want 204", i+1, maxTagsPerSecret, status, out)
		}
	}
	// Updating an existing tag at maxTagsPerSecret is allowed.
	e.expect(t, "tag_create", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags",
		`{"tag":{"key":"k-0","value":"updated"}}`)
	// Adding one more tag beyond maxTagsPerSecret fails with 400 CSMS.0002.
	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags",
		`{"tag":{"key":"overflow","value":"nope"}}`)
	e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags/action",
		`{"action":"create","tags":[{"key":"overflow-batch","value":"nope"}]}`)
}

func TestTagResourceInstancesFiltering(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	s1 := tagCreateSecret(t, e, "svc-alpha-prod", "")
	s2 := tagCreateSecret(t, e, "svc-alpha-dev", "")
	s3 := tagCreateSecret(t, e, "svc-beta-prod", "")

	_, _ = e.call(t, http.MethodPost, "/v1/{project}/csms/"+s1.ID+"/tags/action",
		`{"action":"create","tags":[{"key":"env","value":"prod"},{"key":"tier","value":"backend"}]}`)
	_, _ = e.call(t, http.MethodPost, "/v1/{project}/csms/"+s2.ID+"/tags/action",
		`{"action":"create","tags":[{"key":"env","value":"dev"},{"key":"tier","value":"backend"}]}`)
	_, _ = e.call(t, http.MethodPost, "/v1/{project}/csms/"+s3.ID+"/tags/action",
		`{"action":"create","tags":[{"key":"env","value":"prod"},{"key":"tier","value":"frontend"}]}`)

	// Empty values [] matches any value for that key; OR within values, AND across keys.
	status, raw := e.call(t, http.MethodPost, "/v1/{project}/csms/resource_instances/action",
		`{"action":"filter","tags":[{"key":"tier","values":[]},{"key":"env","values":["prod","dev"]}],"limit":"1","offset":"1"}`)
	if status != http.StatusOK {
		t.Fatalf("filter paged = %d %s", status, raw)
	}
	got := decodeInto[listResourceInstancesResponse](t, raw)
	if got.TotalCount != 3 || len(got.Resources) != 1 || got.Resources[0].ResourceName != "svc-alpha-dev" {
		t.Fatalf("filter paged = %+v, want total_count=3 and [svc-alpha-dev]", got)
	}

	// Numeric limit & offset also work; matches substring filters by secret name.
	status, raw = e.call(t, http.MethodPost, "/v1/{project}/csms/resource_instances/action",
		`{"action":"filter","matches":[{"key":"resource_name","value":"alpha"}],"limit":10,"offset":0}`)
	if status != http.StatusOK {
		t.Fatalf("filter matches = %d %s", status, raw)
	}
	got = decodeInto[listResourceInstancesResponse](t, raw)
	if got.TotalCount != 2 || len(got.Resources) != 2 {
		t.Fatalf("filter matches alpha = %+v, want 2 hits", got)
	}

	// Empty match value "" returns empty list per CSMS docs ("If not specified / empty, an empty value is returned").
	status, raw = e.call(t, http.MethodPost, "/v1/{project}/csms/resource_instances/action",
		`{"action":"filter","matches":[{"key":"resource_name","value":""}]}`)
	if status != http.StatusOK {
		t.Fatalf("filter empty match = %d %s", status, raw)
	}
	got = decodeInto[listResourceInstancesResponse](t, raw)
	if got.TotalCount != 0 || len(got.Resources) != 0 {
		t.Fatalf("filter empty match = %+v, want 0 hits", got)
	}

	// Validation errors: limit/offset bounds, maxFilterTags, maxFilterTagValues, duplicate values, bad matches.
	var tooManyFilters []string
	for i := range maxFilterTags + 1 {
		tooManyFilters = append(tooManyFilters, fmt.Sprintf(`{"key":"k-%d","values":["v"]}`, i))
	}
	var tooManyValues []string
	for i := range maxFilterTagValues + 1 {
		tooManyValues = append(tooManyValues, fmt.Sprintf(`"v-%d"`, i))
	}

	badBodies := []string{
		`{"action":"filter","limit":"0"}`,
		fmt.Sprintf(`{"action":"filter","limit":"%d"}`, maxTagLimit+1),
		`{"action":"filter","limit":"abc"}`,
		`{"action":"filter","offset":"-1"}`,
		`{"action":"filter","offset":"abc"}`,
		`{"action":"filter","tags":[` + strings.Join(tooManyFilters, ",") + `]}`,
		`{"action":"filter","tags":[{"key":"env","values":[` + strings.Join(tooManyValues, ",") + `]}]}`,
		`{"action":"filter","tags":[{"key":"env","values":["dup","dup"]}]}`,
		`{"action":"filter","matches":[{"key":"wrong_key","value":"svc"}]}`,
		`{"action":"filter","matches":[{"key":"resource_name"}]}`,
	}
	for _, b := range badBodies {
		e.expect(t, "tag_error_0002", http.MethodPost, "/v1/{project}/csms/resource_instances/action", b)
	}
}

func TestTagEnforceURNResolution(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	allowed := tagCreateSecret(t, e, "allowed-sec", "")
	other := tagCreateSecret(t, e, "other-sec", "")

	acct := e.dir.Account()
	allowedURN := fmt.Sprintf("csms:%s:%s:secretName:allowed-sec", testRegion, acct.ID)
	policyDoc := fmt.Sprintf(`{
		"Version": "5.0",
		"Statement": [{
			"Effect": "Allow",
			"Action": [
				"csms:secret:createTag",
				"csms:secret:listTags",
				"csms:secret:batchCreateOrDeleteTags",
				"csms:secret:deleteTag"
			],
			"Resource": [%q]
		}]
	}`, allowedURN)

	principal := identity.Principal{AccountID: acct.ID, UserID: "u-tagger", UserName: "tagger"}
	provider := tagStaticGrants{doc: policyDoc}

	// Tagging allowed-sec by its UUID resolves secretName URN to allowed-sec and succeeds.
	status, out := tagDoWithProvider(t, e, principal, provider,
		http.MethodPost, "/v1/{project}/csms/"+allowed.ID+"/tags", `{"tag":{"key":"env","value":"prod"}}`)
	if status != http.StatusNoContent {
		t.Fatalf("CreateSecretTag(allowed) = %d %s, want 204", status, out)
	}
	status, out = tagDoWithProvider(t, e, principal, provider,
		http.MethodPost, "/v1/{project}/csms/"+allowed.ID+"/tags/action", `{"action":"create","tags":[{"key":"team","value":"sec"}]}`)
	if status != http.StatusNoContent {
		t.Fatalf("BatchCreateOrDeleteTags(allowed) = %d %s, want 204", status, out)
	}
	status, out = tagDoWithProvider(t, e, principal, provider,
		http.MethodGet, "/v1/{project}/csms/"+allowed.ID+"/tags", "")
	if status != http.StatusOK {
		t.Fatalf("ListSecretTags(allowed) = %d %s, want 200", status, out)
	}
	status, out = tagDoWithProvider(t, e, principal, provider,
		http.MethodDelete, "/v1/{project}/csms/"+allowed.ID+"/tags/team", "")
	if status != http.StatusNoContent {
		t.Fatalf("DeleteSecretTag(allowed) = %d %s, want 204", status, out)
	}

	// Tagging or listing tags on other-sec by its UUID resolves to secretName:other-sec and is denied with 403 CSMS.0302.
	status, out = tagDoWithProvider(t, e, principal, provider,
		http.MethodPost, "/v1/{project}/csms/"+other.ID+"/tags", `{"tag":{"key":"env","value":"prod"}}`)
	tagAssertDenied(t, "CreateSecretTag(other)", status, out)

	status, out = tagDoWithProvider(t, e, principal, provider,
		http.MethodGet, "/v1/{project}/csms/"+other.ID+"/tags", "")
	tagAssertDenied(t, "ListSecretTags(other)", status, out)
}

func TestTagEnforceReadOnlyAccess(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	sec := tagCreateSecret(t, e, "ro-secret", "readonly check")
	e.expect(t, "tag_create", http.MethodPost, "/v1/{project}/csms/"+sec.ID+"/tags", `{"tag":{"key":"env","value":"prod"}}`)

	// Create an IAM user & group and assign the CSMS ReadOnlyAccess (csms_readonly) system policy on testProject.
	const iamHost = "iam.myhuaweicloud.com"
	status, rawUser := e.callHost(t, iamHost, http.MethodPost, "/v3/users", `{"user":{"name":"csms-reader"}}`, "")
	if status != http.StatusCreated {
		t.Fatalf("create IAM user = %d %s", status, rawUser)
	}
	var userResp struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rawUser, &userResp); err != nil {
		t.Fatalf("decode user: %v", err)
	}

	status, rawGroup := e.callHost(t, iamHost, http.MethodPost, "/v3/groups", `{"group":{"name":"csms-readers"}}`, "")
	if status != http.StatusCreated {
		t.Fatalf("create IAM group = %d %s", status, rawGroup)
	}
	var groupResp struct {
		Group struct {
			ID string `json:"id"`
		} `json:"group"`
	}
	if err := json.Unmarshal(rawGroup, &groupResp); err != nil {
		t.Fatalf("decode group: %v", err)
	}

	status, out := e.callHost(t, iamHost, http.MethodPut,
		"/v3/groups/"+groupResp.Group.ID+"/users/"+userResp.User.ID, "", "")
	if status != http.StatusNoContent {
		t.Fatalf("add user to group = %d %s", status, out)
	}

	status, rawRoles := e.callHost(t, iamHost, http.MethodGet, "/v3/roles?name=csms_readonly", "", "")
	if status != http.StatusOK {
		t.Fatalf("lookup csms_readonly = %d %s", status, rawRoles)
	}
	var rolesResp struct {
		Roles []struct {
			ID string `json:"id"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(rawRoles, &rolesResp); err != nil || len(rolesResp.Roles) != 1 {
		t.Fatalf("roles csms_readonly = %s (%v)", rawRoles, err)
	}

	status, out = e.callHost(t, iamHost, http.MethodPut,
		"/v3/projects/"+testProject+"/groups/"+groupResp.Group.ID+"/roles/"+rolesResp.Roles[0].ID, "", "")
	if status != http.StatusNoContent {
		t.Fatalf("grant csms_readonly = %d %s", status, out)
	}

	acct := e.dir.Account()
	principal := identity.Principal{AccountID: acct.ID, UserID: userResp.User.ID, UserName: "csms-reader"}

	// Allowed under CSMS ReadOnlyAccess: all three tag-read endpoints plus secret reads.
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"ListSecretTags", http.MethodGet, "/v1/{project}/csms/" + sec.ID + "/tags", ""},
		{"ListProjectSecretsTags", http.MethodGet, "/v1/{project}/csms/tags", ""},
		{"ListResourceInstances", http.MethodPost, "/v1/{project}/csms/resource_instances/action", `{"action":"filter"}`},
		{"ShowSecret", http.MethodGet, "/v1/{project}/secrets/" + sec.Name, ""},
		{"ListSecrets", http.MethodGet, "/v1/{project}/secrets", ""},
	} {
		st, body := tagDoWithProvider(t, e, principal, e.iam, tc.method, tc.path, tc.body)
		if st != http.StatusOK {
			t.Errorf("%s with csms_readonly = %d %s, want 200", tc.name, st, body)
		}
	}

	// Denied under CSMS ReadOnlyAccess: all tag-write endpoints and CreateSecret -> 403 CSMS.0302.
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"CreateSecretTag", http.MethodPost, "/v1/{project}/csms/" + sec.ID + "/tags", `{"tag":{"key":"k2","value":"v2"}}`},
		{"BatchCreateOrDeleteTags", http.MethodPost, "/v1/{project}/csms/" + sec.ID + "/tags/action", `{"action":"create","tags":[{"key":"k2","value":"v2"}]}`},
		{"DeleteSecretTag", http.MethodDelete, "/v1/{project}/csms/" + sec.ID + "/tags/env", ""},
		{"CreateSecret", http.MethodPost, "/v1/{project}/secrets", `{"name":"denied-sec","secret_string":"x"}`},
	} {
		st, body := tagDoWithProvider(t, e, principal, e.iam, tc.method, tc.path, tc.body)
		tagAssertDenied(t, tc.name, st, body)
	}
}
