package kms

import (
	"net/http"
	"testing"

	"github.com/victor-akande/weistack/internal/core/identity"
)

func TestGrants(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	partner := identity.Account{ID: "0123456789abcdef0123456789abcdef", Name: "partner"}
	if err := e.dir.AddAccount(partner, identity.Credentials{AccessKey: "PARTNERKEY0000000000", SecretKey: "PartnerSecret0000000"}); err != nil {
		t.Fatal(err)
	}
	partnerProject := partner.DerivedProjectID(testRegion)
	if err := e.dir.Register("USERKEY0000000000000", identity.Principal{AccountID: testAccount.ID, UserID: "ureader", UserName: "reader"}, "s"); err != nil {
		t.Fatal(err)
	}
	id := e.newKey(t, `{"key_alias":"shared"}`)
	ct := e.ok(t, "encrypt-data", `{"key_id":"`+id+`","plain_text":"for the partner"}`)["cipher_text"].(string)

	// Before a grant, the partner does not find the key.
	asPartner := func(op, body string) (int, map[string]any) {
		return e.callAs(t, "PARTNERKEY0000000000", partnerProject, http.MethodPost, op, body)
	}
	if code, _ := asPartner("decrypt-data", `{"cipher_text":"`+ct+`"}`); code != http.StatusNotFound {
		t.Fatalf("decrypt before the grant = %d", code)
	}

	// A grant to the partner's account, for decryption only.
	gid := e.ok(t, "create-grant", `{"key_id":"`+id+`","grantee_principal":"`+partner.ID+`","grantee_principal_type":"domain","operations":["decrypt-data","describe-key"],"name":"partner"}`)["grant_id"].(string)
	if len(gid) != 64 {
		t.Errorf("grant_id %q", gid)
	}
	if code, out := asPartner("decrypt-data", `{"cipher_text":"`+ct+`"}`); code != http.StatusOK || out["plain_text"] != "for the partner" {
		t.Errorf("decrypt with the grant = %d %v", code, out)
	}
	if code, out := asPartner("describe-key", ref(id)); code != http.StatusOK || out["key_info"].(map[string]any)["domain_id"] != testAccount.ID {
		t.Errorf("describe with the grant = %d %v", code, out)
	}
	if code, _ := asPartner("encrypt-data", `{"key_id":"`+id+`","plain_text":"x"}`); code != http.StatusNotFound {
		t.Errorf("encrypt without the operation granted = %d", code)
	}

	// A user grant with a retiring principal.
	ug := e.ok(t, "create-grant", `{"key_id":"`+id+`","grantee_principal":"ureader","operations":["encrypt-data"],"retiring_principal":"ureader"}`)["grant_id"].(string)
	asUser := func(op, body string) (int, map[string]any) {
		return e.callAs(t, "USERKEY0000000000000", testProject, http.MethodPost, op, body)
	}
	if code, out := asUser("list-retirable-grants", `{}`); code != http.StatusOK || out["total"] != float64(1) {
		t.Errorf("retirable = %d %v", code, out)
	}
	list := e.ok(t, "list-grants", ref(id))
	if list["total"] != float64(2) {
		t.Errorf("list-grants = %v", list)
	}
	first := list["grants"].([]any)[0].(map[string]any)
	if first["grant_id"] != gid || first["grantee_principal_type"] != "domain" || first["issuing_principal"] != testAccount.ID {
		t.Errorf("first grant = %v", first)
	}
	if code, out := asUser("retire-grant", `{"key_id":"`+id+`","grant_id":"`+ug+`"}`); code != http.StatusOK {
		t.Errorf("retire = %d %v", code, out)
	}

	// Revoking ends the partner's access.
	e.ok(t, "revoke-grant", `{"key_id":"`+id+`","grant_id":"`+gid+`"}`)
	if code, _ := asPartner("decrypt-data", `{"cipher_text":"`+ct+`"}`); code != http.StatusNotFound {
		t.Errorf("decrypt after revoking = %d", code)
	}

	// Errors.
	for _, c := range []struct{ body, code string }{
		{`{"key_id":"` + id + `","grantee_principal":"x","operations":["create-grant"]}`, "KMS.2401"},
		{`{"key_id":"` + id + `","grantee_principal":"a-b","operations":["encrypt-data"]}`, "KMS.2402"},
		{`{"key_id":"` + id + `","grantee_principal":"x","operations":["delete-key"]}`, "KMS.0308"},
		{`{"key_id":"` + id + `","grantee_principal":"x","operations":["encrypt-data"],"grantee_principal_type":"group"}`, "KMS.0308"},
		{`{"key_id":"` + id + `","grantee_principal":"x"}`, "KMS.0204"},
	} {
		e.wantErr(t, 400, c.code, "create-grant", c.body)
	}
	e.wantErr(t, 400, "KMS.2501", "revoke-grant", `{"key_id":"`+id+`","grant_id":"`+gid+`"}`)
	other := e.newKey(t, `{"key_alias":"other"}`)
	g2 := e.ok(t, "create-grant", `{"key_id":"`+id+`","grantee_principal":"x","operations":["encrypt-data"]}`)["grant_id"].(string)
	e.wantErr(t, 400, "KMS.2502", "revoke-grant", `{"key_id":"`+other+`","grant_id":"`+g2+`"}`)
	dk, err := e.svc.defaultKey(t.Context(), tenant{Region: testRegion, ProjectID: testProject, Account: testAccount}, "obs")
	if err != nil {
		t.Fatal(err)
	}
	e.wantErr(t, 400, "KMS.0211", "create-grant", `{"key_id":"`+dk.ID+`","grantee_principal":"x","operations":["encrypt-data"]}`)
}
