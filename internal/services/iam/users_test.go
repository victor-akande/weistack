package iam

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// do sends a request with a JSON body to the region-less IAM host.
func (e *env) do(t *testing.T, method, path, body string, header ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "iam.myhuaweicloud.com"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, w.Body)
		}
	}
	return w, out
}

func (e *env) want(t *testing.T, status int, method, path, body string) map[string]any {
	t.Helper()
	w, out := e.do(t, method, path, body)
	if w.Code != status {
		t.Fatalf("%s %s = %d %v, want %d", method, path, w.Code, out, status)
	}
	return out
}

func (e *env) wantErr(t *testing.T, status int, code, method, path, body string) {
	t.Helper()
	w, out := e.do(t, method, path, body)
	if w.Code != status || out["error_code"] != code {
		t.Errorf("%s %s %s = %d %v, want %d %s", method, path, body, w.Code, out, status, code)
	}
}

func obj(v any) map[string]any { return v.(map[string]any) }

func list(v any) []any { return v.([]any) }

func TestRootUser(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	root := testAccount.RootUserID()

	out := e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-USER/users/"+root, "")
	u := obj(out["user"])
	if u["name"] != "weistack" || u["is_domain_owner"] != true || u["domain_id"] != testAccount.ID || u["enabled"] != true {
		t.Fatalf("root user = %v", u)
	}
	v5 := obj(e.want(t, http.StatusOK, http.MethodGet, "/v5/users/"+root, "")["user"])
	if v5["is_root_user"] != true || v5["urn"] != "iam::"+testAccount.ID+":user:weistack" {
		t.Fatalf("v5 root user = %v", v5)
	}

	e.wantErr(t, http.StatusBadRequest, "1107", http.MethodDelete, "/v3/users/"+root, "")
	e.wantErr(t, http.StatusConflict, "PAP5.0007", http.MethodDelete, "/v5/users/"+root, "")
	e.wantErr(t, http.StatusForbidden, "IAM.0002", http.MethodPatch, "/v3/users/"+root, `{"user":{"name":"other"}}`)
	e.wantErr(t, http.StatusForbidden, "PAP5.0001", http.MethodPut, "/v5/users/"+root, `{"enabled":false}`)

	// A reset wipes the store; the root user and the project come back.
	if err := e.svc.Reset(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.want(t, http.StatusOK, http.MethodGet, "/v3/users/"+root, "")
	_, projects := e.get(t, "/v3/auth/projects")
	if len(names(t, projects)) != 1 {
		t.Fatalf("projects after reset = %v", projects)
	}
}

func TestClassicUsers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	out := e.want(t, http.StatusCreated, http.MethodPost, "/v3.0/OS-USER/users",
		`{"user":{"name":"alice","domain_id":"`+testAccount.ID+`","password":"Passw0rd!x","email":"a@example.com",
		"areacode":"0086","phone":"13800000000","description":"first","access_mode":"programmatic"}}`)
	u := obj(out["user"])
	id := u["id"].(string)
	if len(id) != 32 || u["name"] != "alice" || u["email"] != "a@example.com" || u["access_mode"] != "programmatic" ||
		u["is_domain_owner"] != false || u["password"] != nil || u["password_expires_at"] != nil {
		t.Fatalf("created = %v", u)
	}
	if _, err := time.Parse(osUserTime, u["create_time"].(string)); err != nil {
		t.Fatalf("create_time %v: %v", u["create_time"], err)
	}

	// Keystone sees the same user.
	ks := obj(e.want(t, http.StatusOK, http.MethodGet, "/v3/users/"+id, "")["user"])
	if ks["name"] != "alice" || ks["description"] != "first" || !strings.HasSuffix(obj(ks["links"])["self"].(string), "/v3/users/"+id) {
		t.Fatalf("keystone view = %v", ks)
	}
	all := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/users", "")["users"])
	if len(all) != 2 {
		t.Fatalf("users = %v", all)
	}
	for query, want := range map[string]int{"?name=alice": 1, "?name=bob": 0, "?enabled=false": 0, "?domain_id=x": 0} {
		if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/users"+query, "")["users"]); len(got) != want {
			t.Errorf("GET /v3/users%s: %d users, want %d", query, len(got), want)
		}
	}

	// Updates through both forms.
	e.want(t, http.StatusOK, http.MethodPatch, "/v3/users/"+id, `{"user":{"name":"alice2","enabled":false}}`)
	u = obj(e.want(t, http.StatusOK, http.MethodPut, "/v3.0/OS-USER/users/"+id, `{"user":{"description":"changed"}}`)["user"])
	if u["name"] != "alice2" || u["enabled"] != false || u["description"] != "changed" {
		t.Fatalf("updated = %v", u)
	}
	w, _ := e.do(t, http.MethodPut, "/v3.0/OS-USER/users/"+id+"/info", `{"user":{"email":"b@example.com","mobile":"0044-7700900000"}}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("info = %d", w.Code)
	}
	u = obj(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-USER/users/"+id, "")["user"])
	if u["email"] != "b@example.com" || u["areacode"] != "0044" || u["phone"] != "7700900000" {
		t.Fatalf("after info = %v", u)
	}

	// Login protection defaults to off and keeps what is set.
	lp := obj(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-USER/users/"+id+"/login-protect", "")["login_protect"])
	if lp["enabled"] != false || lp["verification_method"] != "none" || lp["user_id"] != id {
		t.Fatalf("login protect = %v", lp)
	}
	e.want(t, http.StatusOK, http.MethodPut, "/v3.0/OS-USER/users/"+id+"/login-protect", `{"login_protect":{"enabled":true,"verification_method":"email"}}`)
	lp = obj(e.want(t, http.StatusOK, http.MethodGet, "/v3.0/OS-USER/users/"+id+"/login-protect", "")["login_protect"])
	if lp["enabled"] != true || lp["verification_method"] != "email" {
		t.Fatalf("login protect = %v", lp)
	}

	if w, _ := e.do(t, http.MethodDelete, "/v3/users/"+id, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", w.Code)
	}
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v3/users/"+id, "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v3.0/OS-USER/users/"+id+"/login-protect", "")
}

func TestClassicUserErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.want(t, http.StatusCreated, http.MethodPost, "/v3/users", `{"user":{"name":"bob"}}`)
	d := testAccount.ID
	for _, tt := range []struct {
		status    int
		code      string
		path, req string
	}{
		{400, "IAM.0011", "/v3/users", `{`},
		{400, "IAM.0072", "/v3/users", `{}`},
		{400, "IAM.0072", "/v3/users", `{"user":{}}`},
		{400, "1100", "/v3.0/OS-USER/users", `{"user":{"name":"x"}}`},
		{400, "1109", "/v3/users", `{"user":{"name":"bob"}}`},
		{400, "1101", "/v3/users", `{"user":{"name":"1bob"}}`},
		{400, "1101", "/v3/users", `{"user":{"name":"` + strings.Repeat("a", 65) + `"}}`},
		{400, "1117", "/v3/users", `{"user":{"name":"c","description":"a#b"}}`},
		{400, "1118", "/v3/users", `{"user":{"name":"c","password":"short1"}}`},
		{400, "1118", "/v3/users", `{"user":{"name":"c","password":"alllowercase"}}`},
		{400, "1118", "/v3/users", `{"user":{"name":"Abcdefgh1","password":"1hgfedcbA"}}`},
		{400, "1102", "/v3.0/OS-USER/users", `{"user":{"name":"c","domain_id":"` + d + `","email":"nope"}}`},
		{400, "1104", "/v3.0/OS-USER/users", `{"user":{"name":"c","domain_id":"` + d + `","areacode":"86","phone":"x"}}`},
		{400, "1106", "/v3.0/OS-USER/users", `{"user":{"name":"c","domain_id":"` + d + `","phone":"123"}}`},
		{400, "1120", "/v3.0/OS-USER/users", `{"user":{"name":"c","domain_id":"` + d + `","access_mode":"web"}}`},
		{400, "IAM.0073", "/v3.0/OS-USER/users", `{"user":{"name":"c","domain_id":"other"}}`},
	} {
		e.wantErr(t, tt.status, tt.code, http.MethodPost, tt.path, tt.req)
	}
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPatch, "/v3/users/nope", `{"user":{"description":"x"}}`)
	e.wantErr(t, http.StatusBadRequest, "IAM.0007", http.MethodGet, "/v3/users?enabled=maybe", "")
	e.wantErr(t, http.StatusBadRequest, "IAM.0073", http.MethodPut, "/v3.0/OS-USER/users/"+testAccount.RootUserID()+"/login-protect",
		`{"login_protect":{"enabled":true,"verification_method":"none"}}`)
}

func TestUserQuota(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for i := range maxUsers {
		e.want(t, http.StatusCreated, http.MethodPost, "/v3/users", `{"user":{"name":"u`+string(rune('A'+i/26))+string(rune('a'+i%26))+`"}}`)
	}
	e.wantErr(t, http.StatusBadRequest, "1115", http.MethodPost, "/v3/users", `{"user":{"name":"onemore"}}`)
}

func TestPasswordChange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3/users", `{"user":{"name":"carol","password":"Passw0rd!x"}}`)["user"])["id"].(string)
	path := "/v3/users/" + id + "/password"
	e.wantErr(t, http.StatusBadRequest, "1103", http.MethodPost, path, `{"user":{"original_password":"wrong","password":"N3wPassword"}}`)
	e.wantErr(t, http.StatusBadRequest, "1108", http.MethodPost, path, `{"user":{"original_password":"Passw0rd!x","password":"Passw0rd!x"}}`)
	e.wantErr(t, http.StatusBadRequest, "1118", http.MethodPost, path, `{"user":{"original_password":"Passw0rd!x","password":"weak"}}`)
	e.wantErr(t, http.StatusBadRequest, "IAM.0072", http.MethodPost, path, `{"user":{"password":"N3wPassword"}}`)
	if w, out := e.do(t, http.MethodPost, path, `{"user":{"original_password":"Passw0rd!x","password":"N3wPassword"}}`); w.Code != http.StatusNoContent {
		t.Fatalf("change = %d %v", w.Code, out)
	}
	e.wantErr(t, http.StatusBadRequest, "1103", http.MethodPost, path, `{"user":{"original_password":"Passw0rd!x","password":"An0therOne"}}`)
}

func TestClassicGroups(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3/users", `{"user":{"name":"dave"}}`)["user"])["id"].(string)
	g := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3/groups", `{"group":{"name":"devs","description":"developers"}}`)["group"])
	gid := g["id"].(string)
	if g["name"] != "devs" || g["domain_id"] != testAccount.ID || g["create_time"].(float64) <= 0 {
		t.Fatalf("group = %v", g)
	}
	e.wantErr(t, http.StatusConflict, "IAM.0005", http.MethodPost, "/v3/groups", `{"group":{"name":"devs"}}`)
	e.wantErr(t, http.StatusBadRequest, "IAM.0072", http.MethodPost, "/v3/groups", `{"group":{}}`)
	e.wantErr(t, http.StatusBadRequest, "IAM.0073", http.MethodPost, "/v3/groups", `{"group":{"name":"a.b"}}`)

	members := "/v3/groups/" + gid + "/users/" + uid
	if w, _ := e.do(t, http.MethodHead, members, ""); w.Code != http.StatusNotFound {
		t.Fatalf("HEAD before = %d", w.Code)
	}
	for range 2 { // adding again succeeds
		if w, _ := e.do(t, http.MethodPut, members, ""); w.Code != http.StatusNoContent {
			t.Fatalf("PUT = %d", w.Code)
		}
	}
	if w, _ := e.do(t, http.MethodHead, members, ""); w.Code != http.StatusNoContent {
		t.Fatalf("HEAD after = %d", w.Code)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/groups/"+gid+"/users", "")["users"]); len(got) != 1 || obj(got[0])["id"] != uid {
		t.Fatalf("members = %v", got)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/users/"+uid+"/groups", "")["groups"]); len(got) != 1 || obj(got[0])["name"] != "devs" {
		t.Fatalf("user's groups = %v", got)
	}
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, "/v3/groups/"+gid+"/users/nope", "")
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodPut, "/v3/groups/nope/users/"+uid, "")

	e.want(t, http.StatusOK, http.MethodPatch, "/v3/groups/"+gid, `{"group":{"name":"developers"}}`)
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/groups?name=developers", "")["groups"]); len(got) != 1 {
		t.Fatalf("by name = %v", got)
	}

	if w, _ := e.do(t, http.MethodDelete, members, ""); w.Code != http.StatusNoContent {
		t.Fatalf("remove = %d", w.Code)
	}
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodDelete, members, "")

	// Deleting a user takes it out of its groups.
	e.do(t, http.MethodPut, members, "")
	e.do(t, http.MethodDelete, "/v3/users/"+uid, "")
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v3/groups/"+gid+"/users", "")["users"]); len(got) != 0 {
		t.Fatalf("members after user deleted = %v", got)
	}
	if w, _ := e.do(t, http.MethodDelete, "/v3/groups/"+gid, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete group = %d", w.Code)
	}
	e.wantErr(t, http.StatusNotFound, "IAM.0004", http.MethodGet, "/v3/groups/"+gid, "")
}

func TestV5UsersAndGroups(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	u := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v5/users", `{"name":"erin","description":"v5 user","enabled":true}`)["user"])
	uid := u["user_id"].(string)
	if u["user_name"] != "erin" || u["urn"] != "iam::"+testAccount.ID+":user:erin" || u["is_root_user"] != false {
		t.Fatalf("v5 user = %v", u)
	}
	if _, err := time.Parse(time.RFC3339, u["created_at"].(string)); err != nil {
		t.Fatalf("created_at: %v", err)
	}
	// Classic IAM sees it.
	e.want(t, http.StatusOK, http.MethodGet, "/v3/users/"+uid, "")
	e.wantErr(t, http.StatusConflict, "PAP5.0042", http.MethodPost, "/v5/users", `{"name":"erin","enabled":true}`)
	e.wantErr(t, http.StatusBadRequest, "PAP5.0257", http.MethodPost, "/v5/users", `{"enabled":true}`)
	e.wantErr(t, http.StatusBadRequest, "PAP5.0257", http.MethodPost, "/v5/users", `{"name":" x"}`)

	u = obj(e.want(t, http.StatusOK, http.MethodPut, "/v5/users/"+uid, `{"new_user_name":"erin2","new_description":"renamed","enabled":false}`)["user"])
	if u["user_name"] != "erin2" || u["description"] != "renamed" || u["enabled"] != false {
		t.Fatalf("updated = %v", u)
	}
	e.wantErr(t, http.StatusNotFound, "PAP5.0021", http.MethodPut, "/v5/users/nope", `{"enabled":true}`)

	g := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v5/groups", `{"group_name":"ops","description":"operators"}`)["group"])
	gid := g["group_id"].(string)
	if g["urn"] != "iam::"+testAccount.ID+":group:ops" {
		t.Fatalf("v5 group = %v", g)
	}
	e.wantErr(t, http.StatusConflict, "PAP5.0043", http.MethodPost, "/v5/groups", `{"group_name":"ops"}`)
	if w, out := e.do(t, http.MethodPost, "/v5/groups/"+gid+"/add-user", `{"user_id":"`+uid+`"}`); w.Code != http.StatusNoContent {
		t.Fatalf("add-user = %d %v", w.Code, out)
	}
	e.wantErr(t, http.StatusConflict, "PAP5.0044", http.MethodPost, "/v5/groups/"+gid+"/add-user", `{"user_id":"`+uid+`"}`)
	e.wantErr(t, http.StatusNotFound, "PAP5.0021", http.MethodPost, "/v5/groups/"+gid+"/add-user", `{"user_id":"nope"}`)
	e.wantErr(t, http.StatusNotFound, "PAP5.0016", http.MethodPost, "/v5/groups/nope/add-user", `{"user_id":"`+uid+`"}`)

	// Membership shows through both APIs.
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/users?group_id="+gid, "")["users"]); len(got) != 1 {
		t.Fatalf("v5 members = %v", got)
	}
	if got := list(e.want(t, http.StatusOK, http.MethodGet, "/v5/groups?user_id="+uid, "")["groups"]); len(got) != 1 {
		t.Fatalf("v5 user's groups = %v", got)
	}
	if w, _ := e.do(t, http.MethodHead, "/v3/groups/"+gid+"/users/"+uid, ""); w.Code != http.StatusNoContent {
		t.Fatalf("classic HEAD = %d", w.Code)
	}
	if w, _ := e.do(t, http.MethodPost, "/v5/groups/"+gid+"/remove-user", `{"user_id":"`+uid+`"}`); w.Code != http.StatusNoContent {
		t.Fatalf("remove-user = %d", w.Code)
	}
	e.wantErr(t, http.StatusNotFound, "PAP5.0021", http.MethodPost, "/v5/groups/"+gid+"/remove-user", `{"user_id":"`+uid+`"}`)

	g = obj(e.want(t, http.StatusOK, http.MethodPut, "/v5/groups/"+gid, `{"new_group_name":"ops2","new_group_description":"x"}`)["group"])
	if g["group_name"] != "ops2" || g["description"] != "x" {
		t.Fatalf("updated group = %v", g)
	}
	last := e.want(t, http.StatusOK, http.MethodGet, "/v5/users/"+uid+"/last-login", "")
	if len(obj(last["user_last_login"])) != 0 {
		t.Fatalf("last login = %v", last)
	}

	if w, _ := e.do(t, http.MethodDelete, "/v5/groups/"+gid, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete group = %d", w.Code)
	}
	e.wantErr(t, http.StatusNotFound, "PAP5.0016", http.MethodGet, "/v5/groups/"+gid, "")
	if w, _ := e.do(t, http.MethodDelete, "/v5/users/"+uid, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete user = %d", w.Code)
	}
	e.wantErr(t, http.StatusNotFound, "PAP5.0021", http.MethodGet, "/v5/users/"+uid, "")
}

func TestV5Paging(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, n := range []string{"a", "b", "c"} {
		e.want(t, http.StatusCreated, http.MethodPost, "/v5/groups", `{"group_name":"`+n+`"}`)
	}
	var seen []string
	marker := ""
	for range 5 {
		out := e.want(t, http.StatusOK, http.MethodGet, "/v5/groups?limit=2&marker="+marker, "")
		for _, g := range list(out["groups"]) {
			seen = append(seen, obj(g)["group_name"].(string))
		}
		next, _ := obj(out["page_info"])["next_marker"].(string)
		if next == "" {
			break
		}
		marker = next
	}
	if strings.Join(seen, ",") != "a,b,c" {
		t.Fatalf("paged = %v", seen)
	}
	e.wantErr(t, http.StatusBadRequest, "PAP5.0010", http.MethodGet, "/v5/groups?marker=nope", "")
	e.wantErr(t, http.StatusBadRequest, "PAP5.0257", http.MethodGet, "/v5/users?limit=0", "")
}

func TestTokens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	uid := obj(e.want(t, http.StatusCreated, http.MethodPost, "/v3/users", `{"user":{"name":"frank","password":"Passw0rd!x"}}`)["user"])["id"].(string)
	login := func(password, scope string) (*httptest.ResponseRecorder, map[string]any) {
		return e.do(t, http.MethodPost, "/v3/auth/tokens", `{"auth":{"identity":{"methods":["password"],"password":{"user":
			{"name":"frank","password":"`+password+`","domain":{"name":"weistack"}}}}`+scope+`}}`)
	}

	w, out := login("Passw0rd!x", `,"scope":{"project":{"name":"`+testRegion+`"}}`)
	tok := w.Header().Get("X-Subject-Token")
	if w.Code != http.StatusCreated || tok == "" {
		t.Fatalf("login = %d %v", w.Code, out)
	}
	body := obj(out["token"])
	p := obj(body["project"])
	if p["id"] != testProject || obj(body["user"])["id"] != uid || list(body["methods"])[0] != "password" {
		t.Fatalf("token = %v", body)
	}
	issued, _ := time.Parse(keystoneTime, body["issued_at"].(string))
	expires, _ := time.Parse(keystoneTime, body["expires_at"].(string))
	if expires.Sub(issued) != tokenLifetime {
		t.Fatalf("lifetime = %v", expires.Sub(issued))
	}
	if strings.Contains(e.dump(t), tok) || strings.Contains(e.dump(t), "Passw0rd!x") {
		t.Fatal("a token or password was stored")
	}

	// Validate, and swap for a domain-scoped token.
	w, out = e.do(t, http.MethodGet, "/v3/auth/tokens?nocatalog=true", "", "X-Subject-Token", tok)
	if w.Code != http.StatusOK || obj(out["token"])["catalog"] != nil {
		t.Fatalf("validate = %d %v", w.Code, out)
	}
	w, out = e.do(t, http.MethodPost, "/v3/auth/tokens", `{"auth":{"identity":{"methods":["token"],"token":{"id":"`+tok+`"}},"scope":{"domain":{"id":"`+testAccount.ID+`"}}}}`)
	if w.Code != http.StatusCreated || obj(obj(out["token"])["domain"])["id"] != testAccount.ID {
		t.Fatalf("scoped = %d %v", w.Code, out)
	}

	// Last login is recorded.
	last := obj(e.want(t, http.StatusOK, http.MethodGet, "/v5/users/"+uid+"/last-login", "")["user_last_login"])
	if last["last_login_at"] == nil {
		t.Fatal("no last login")
	}

	// Failures.
	if w, out := login("wrong", ""); w.Code != http.StatusUnauthorized || out["error_code"] != "IAM.0062" {
		t.Fatalf("wrong password = %d %v", w.Code, out)
	}
	if w, out := e.do(t, http.MethodGet, "/v3/auth/tokens", ""); w.Code != http.StatusBadRequest || out["error_code"] != "IAM.0009" {
		t.Fatalf("no subject token = %d %v", w.Code, out)
	}
	if w, out := e.do(t, http.MethodGet, "/v3/auth/tokens", "", "X-Subject-Token", "nope"); w.Code != http.StatusUnauthorized || out["error_code"] != "IAM.0067" {
		t.Fatalf("unknown token = %d %v", w.Code, out)
	}

	// A password change ends the token; disabling the user stops logins.
	e.do(t, http.MethodPost, "/v3/users/"+uid+"/password", `{"user":{"original_password":"Passw0rd!x","password":"N3wPassword"}}`)
	if w, _ := e.do(t, http.MethodGet, "/v3/auth/tokens", "", "X-Subject-Token", tok); w.Code != http.StatusUnauthorized {
		t.Fatalf("token after password change = %d", w.Code)
	}
	e.do(t, http.MethodPatch, "/v3/users/"+uid, `{"user":{"enabled":false}}`)
	if w, out := login("N3wPassword", ""); w.Code != http.StatusForbidden || out["error_code"] != "IAM.0082" {
		t.Fatalf("disabled = %d %v", w.Code, out)
	}
	e.do(t, http.MethodPatch, "/v3/users/"+uid, `{"user":{"enabled":true,"access_mode":"console"}}`)
	e.do(t, http.MethodPut, "/v3.0/OS-USER/users/"+uid, `{"user":{"access_mode":"console"}}`)
	if w, out := login("N3wPassword", ""); w.Code != http.StatusForbidden || out["error_code"] != "IAM.0081" {
		t.Fatalf("console only = %d %v", w.Code, out)
	}
	if w, out := e.do(t, http.MethodPost, "/v3/auth/tokens", `{"auth":{"identity":{"methods":["password"],"password":{"user":
		{"name":"nobody","password":"x","domain":{"name":"weistack"}}}}}}`); w.Code != http.StatusUnauthorized || out["error_code"] != "IAM.0001" {
		t.Fatalf("unknown user = %d %v", w.Code, out)
	}
}

// dump returns everything the store holds, as text.
func (e *env) dump(t *testing.T) string {
	t.Helper()
	all, err := e.svc.store.Dump(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, recs := range all {
		for _, r := range recs {
			b.Write(r.Data)
		}
	}
	return b.String()
}
