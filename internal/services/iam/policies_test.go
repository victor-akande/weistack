package iam

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// docJSON returns a policy document as the JSON string the API carries.
func docJSON(doc string) string {
	b, _ := json.Marshal(doc)
	return string(b)
}

const allowAll = `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["*"]}]}`

func (e *env) newPolicy(t *testing.T, name, path string) map[string]any {
	t.Helper()
	return obj(e.want(t, http.StatusCreated, http.MethodPost, "/v5/policies",
		`{"policy_name":"`+name+`","path":"`+path+`","policy_document":`+docJSON(allowAll)+`,"description":"d"}`)["policy"])
}

func TestPoliciesV5(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	p := e.newPolicy(t, "readers", "team/")
	id := p["policy_id"].(string)
	if p["policy_type"] != "custom" || p["default_version_id"] != "v1" || p["attachment_count"] != float64(0) ||
		p["urn"] != "iam::"+testAccount.ID+":policy:team/readers" || p["path"] != "team/" || p["created_at"] == "" {
		t.Fatalf("created = %v", p)
	}
	e.wantErr(t, http.StatusConflict, "PAP5.0025", http.MethodPost, "/v5/policies",
		`{"policy_name":"readers","policy_document":`+docJSON(allowAll)+`}`)
	e.newPolicy(t, "writers", "")

	for name, tc := range map[string]struct {
		status   int
		code, in string
	}{
		"no name":       {400, "PAP5.0257", `{"policy_document":` + docJSON(allowAll) + `}`},
		"bad name":      {400, "PAP5.0257", `{"policy_name":"a b","policy_document":` + docJSON(allowAll) + `}`},
		"no document":   {400, "PAP5.0257", `{"policy_name":"x"}`},
		"long text":     {400, "PAP5.0257", `{"policy_name":"x","description":"` + strings.Repeat("d", 1001) + `","policy_document":` + docJSON(allowAll) + `}`},
		"path":          {400, "PAP5.0030", `{"policy_name":"x","path":"no-slash","policy_document":` + docJSON(allowAll) + `}`},
		"not JSON":      {400, "PAP5.0011", `{"policy_name":"x","policy_document":"{"}`},
		"version":       {400, "PAP5.0011", `{"policy_name":"x","policy_document":` + docJSON(`{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["*"]}]}`) + `}`},
		"no statements": {400, "PAP5.0011", `{"policy_name":"x","policy_document":` + docJSON(`{"Version":"5.0","Statement":[]}`) + `}`},
		"effect case":   {400, "PAP5.0011", `{"policy_name":"x","policy_document":` + docJSON(`{"Version":"5.0","Statement":[{"Effect":"allow","Action":["*"]}]}`) + `}`},
		"both actions":  {400, "PAP5.0011", `{"policy_name":"x","policy_document":` + docJSON(`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["*"],"NotAction":["a"]}]}`) + `}`},
		"no action":     {400, "PAP5.0011", `{"policy_name":"x","policy_document":` + docJSON(`{"Version":"5.0","Statement":[{"Effect":"Allow","Resource":["*"]}]}`) + `}`},
		"unknown key":   {400, "PAP5.0011", `{"policy_name":"x","policy_document":` + docJSON(`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["*"],"Extra":1}]}`) + `}`},
		"bad condition": {400, "PAP5.0011", `{"policy_name":"x","policy_document":` + docJSON(`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["*"],"Condition":{"StringEquals":{"k":1}}}]}`) + `}`},
		"too large": {409, "PAP5.0027", `{"policy_name":"x","policy_document":` + docJSON(`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["`+
			strings.Repeat("a", 6200)+`"]}]}`) + `}`},
	} {
		w, out := e.do(t, http.MethodPost, "/v5/policies", tc.in)
		if w.Code != tc.status || out["error_code"] != tc.code {
			t.Errorf("%s: %d %v, want %d %s", name, w.Code, out, tc.status, tc.code)
		}
	}
	// A full statement passes.
	full := `{"Version":"5.0","Statement":[{"Sid":"s1","Effect":"Deny","NotAction":["obs:*:*"],"NotResource":["obs:*:*:bucket:x"],` +
		`"Condition":{"StringEquals":{"g:UserName":["a","b"]},"Bool":{"g:MFAPresent":"true"}}}]}`
	e.want(t, http.StatusCreated, http.MethodPost, "/v5/policies", `{"policy_name":"full","policy_document":`+docJSON(full)+`}`)

	// Listing, filtered and paged.
	count := func(query string) int {
		t.Helper()
		return len(list(e.want(t, http.StatusOK, http.MethodGet, "/v5/policies?"+query, "")["policies"]))
	}
	for query, want := range map[string]int{
		"": 3, "policy_type=custom": 3, "policy_type=system": 0, "path_prefix=team/": 1, "only_attached=true": 0, "limit=2": 2,
	} {
		if got := count(query); got != want {
			t.Errorf("policies?%s = %d, want %d", query, got, want)
		}
	}
	e.wantErr(t, http.StatusBadRequest, "PAP5.0257", http.MethodGet, "/v5/policies?policy_type=other", "")

	e.want(t, http.StatusNoContent, http.MethodPut, "/v5/policies/"+id, `{"description":"new"}`)
	if got := obj(e.want(t, http.StatusOK, http.MethodGet, "/v5/policies/"+id, "")["policy"]); got["description"] != "new" {
		t.Fatalf("updated = %v", got)
	}
	e.wantErr(t, http.StatusNotFound, "PAP5.0018", http.MethodGet, "/v5/policies/nope", "")
	e.wantErr(t, http.StatusNotFound, "PAP5.0018", http.MethodPut, "/v5/policies/nope", `{"description":"x"}`)

	e.want(t, http.StatusNoContent, http.MethodDelete, "/v5/policies/"+id, "")
	e.wantErr(t, http.StatusNotFound, "PAP5.0018", http.MethodDelete, "/v5/policies/"+id, "")
}

func TestPolicyVersionsV5(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.newPolicy(t, "versioned", "")["policy_id"].(string)
	base := "/v5/policies/" + id + "/versions"
	doc := func(action string) string {
		return docJSON(`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["` + action + `"]}]}`)
	}

	v := obj(e.want(t, http.StatusCreated, http.MethodPost, base, `{"policy_document":`+doc("ecs:*:*")+`}`)["policy_version"])
	if v["version_id"] != "v2" || v["is_default"] != false {
		t.Fatalf("v2 = %v", v)
	}
	v = obj(e.want(t, http.StatusCreated, http.MethodPost, base, `{"policy_document":`+doc("vpc:*:*")+`,"set_as_default":true}`)["policy_version"])
	if v["version_id"] != "v3" || v["is_default"] != true {
		t.Fatalf("v3 = %v", v)
	}
	if p := obj(e.want(t, http.StatusOK, http.MethodGet, "/v5/policies/"+id, "")["policy"]); p["default_version_id"] != "v3" {
		t.Fatalf("default = %v", p["default_version_id"])
	}

	// Newest first, as Terraform expects: it deletes the last one listed
	// as the earliest.
	versions := list(e.want(t, http.StatusOK, http.MethodGet, base, "")["versions"])
	var ids []string
	for _, v := range versions {
		ids = append(ids, obj(v)["version_id"].(string))
	}
	if strings.Join(ids, ",") != "v3,v2,v1" {
		t.Fatalf("versions = %v", ids)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, base+"?limit=1&marker=v2", "")["versions"]); len(got) != 1 || obj(got[0])["version_id"] != "v2" {
		t.Fatalf("page = %v", got)
	}

	// At most five; the default cannot be deleted.
	e.want(t, http.StatusCreated, http.MethodPost, base, `{"policy_document":`+doc("a:b:c")+`}`)
	e.want(t, http.StatusCreated, http.MethodPost, base, `{"policy_document":`+doc("a:b:d")+`}`)
	e.wantErr(t, http.StatusConflict, "PAP5.0028", http.MethodPost, base, `{"policy_document":`+doc("a:b:e")+`}`)
	e.wantErr(t, http.StatusConflict, "PAP5.0007", http.MethodDelete, base+"/v3", "")
	e.want(t, http.StatusNoContent, http.MethodDelete, base+"/v1", "")
	e.wantErr(t, http.StatusNotFound, "PAP5.0020", http.MethodGet, base+"/v1", "")
	// Numbers are never reused.
	if v := obj(e.want(t, http.StatusCreated, http.MethodPost, base, `{"policy_document":`+doc("a:b:f")+`}`)["policy_version"]); v["version_id"] != "v6" {
		t.Fatalf("after a delete = %v", v)
	}

	e.want(t, http.StatusOK, http.MethodPost, base+"/v2/set-default", "")
	if got := obj(e.want(t, http.StatusOK, http.MethodGet, base+"/v2", "")["policy_version"]); got["is_default"] != true ||
		!strings.Contains(got["document"].(string), "ecs:*:*") {
		t.Fatalf("v2 = %v", got)
	}
	if got := obj(e.want(t, http.StatusOK, http.MethodGet, base+"/v3", "")["policy_version"]); got["is_default"] != false {
		t.Fatalf("v3 = %v", got)
	}
	e.wantErr(t, http.StatusNotFound, "PAP5.0020", http.MethodPost, base+"/v9/set-default", "")
	e.wantErr(t, http.StatusNotFound, "PAP5.0018", http.MethodGet, "/v5/policies/nope/versions", "")
	e.wantErr(t, http.StatusBadRequest, "PAP5.0011", http.MethodPost, base, `{"policy_document":"{}"}`)
}

func TestPolicyAttachmentsV5(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	pid := e.newPolicy(t, "attached", "")["policy_id"].(string)
	uid := e.newUser(t, "ivan")
	gid := e.newGroup(t, "devs")
	p := "/v5/policies/" + pid

	e.want(t, http.StatusOK, http.MethodPost, p+"/attach-user", `{"user_id":"`+uid+`"}`)
	e.want(t, http.StatusOK, http.MethodPost, p+"/attach-group", `{"group_id":"`+gid+`"}`)
	e.wantErr(t, http.StatusConflict, "PAP5.0026", http.MethodPost, p+"/attach-user", `{"user_id":"`+uid+`"}`)
	e.wantErr(t, http.StatusNotFound, "PAP5.0021", http.MethodPost, p+"/attach-user", `{"user_id":"nobody"}`)
	e.wantErr(t, http.StatusNotFound, "PAP5.0016", http.MethodPost, p+"/attach-group", `{"group_id":"nogroup"}`)
	e.wantErr(t, http.StatusNotFound, "PAP5.0018", http.MethodPost, "/v5/policies/nope/attach-user", `{"user_id":"`+uid+`"}`)
	e.wantErr(t, http.StatusBadRequest, "PAP5.0257", http.MethodPost, p+"/attach-user", `{}`)

	if got := obj(e.want(t, http.StatusOK, http.MethodGet, p, "")["policy"]); got["attachment_count"] != float64(2) {
		t.Fatalf("attachment_count = %v", got["attachment_count"])
	}
	held := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/users/"+uid+"/attached-policies", "")["attached_policies"])
	if len(held) != 1 || obj(held[0])["policy_name"] != "attached" || obj(held[0])["attached_at"] == "" {
		t.Fatalf("user's policies = %v", held)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/groups/"+gid+"/attached-policies", "")["attached_policies"]); len(got) != 1 {
		t.Fatalf("group's policies = %v", got)
	}
	e.wantErr(t, http.StatusNotFound, "PAP5.0021", http.MethodGet, "/v5/users/nobody/attached-policies", "")

	entities := e.want(t, http.StatusOK, http.MethodGet, p+"/attached-entities", "")
	if len(list(entities["policy_users"])) != 1 || len(list(entities["policy_groups"])) != 1 || len(list(entities["policy_agencies"])) != 0 {
		t.Fatalf("entities = %v", entities)
	}
	if got := e.want(t, http.StatusOK, http.MethodGet, p+"/attached-entities?entity_type=group", ""); len(list(got["policy_users"])) != 0 {
		t.Fatalf("groups only = %v", got)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/policies?only_attached=true", "")["policies"]); len(got) != 1 {
		t.Fatalf("only attached = %v", got)
	}

	// An attached policy cannot be deleted.
	e.wantErr(t, http.StatusConflict, "PAP5.0007", http.MethodDelete, p, "")

	e.want(t, http.StatusOK, http.MethodPost, p+"/detach-group", `{"group_id":"`+gid+`"}`)
	e.wantErr(t, http.StatusNotFound, "PAP5.0019", http.MethodPost, p+"/detach-group", `{"group_id":"`+gid+`"}`)

	// Ten policies per user at most.
	for i := range 9 {
		id := e.newPolicy(t, "extra"+strconv.Itoa(i), "")["policy_id"].(string)
		e.want(t, http.StatusOK, http.MethodPost, "/v5/policies/"+id+"/attach-user", `{"user_id":"`+uid+`"}`)
	}
	last := e.newPolicy(t, "eleventh", "")["policy_id"].(string)
	e.wantErr(t, http.StatusConflict, "PAP5.0005", http.MethodPost, "/v5/policies/"+last+"/attach-user", `{"user_id":"`+uid+`"}`)

	// Deleting the user detaches its policies.
	e.want(t, http.StatusNoContent, http.MethodDelete, "/v5/users/"+uid, "")
	if got := obj(e.want(t, http.StatusOK, http.MethodGet, p, "")["policy"]); got["attachment_count"] != float64(0) {
		t.Fatalf("after the user's delete = %v", got)
	}
	e.want(t, http.StatusNoContent, http.MethodDelete, p, "")
}
