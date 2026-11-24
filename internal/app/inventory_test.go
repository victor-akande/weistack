package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
)

// TestInventory: the inventory lists what the services hold, with the
// account IAM says owns each project.
func TestInventory(t *testing.T) {
	t.Parallel()
	inst := startInstance(t, nil)
	info := inst.services(t)
	if status, body := inst.send(t, http.MethodPost, "/vpc/v1/"+info.ProjectID+"/vpcs",
		[]byte(`{"vpc": {"name": "inventoried", "cidr": "10.0.0.0/16"}}`)); status != http.StatusOK {
		t.Fatalf("creating a VPC = %d %s", status, body)
	}

	status, body := inst.get(t, "/_weistack/inventory?type=vpc.vpcs")
	if status != http.StatusOK {
		t.Fatalf("GET inventory = %d %s", status, body)
	}
	var out struct {
		Resources []struct {
			Name      string `json:"name"`
			AccountID string `json:"account_id"`
			ProjectID string `json:"project_id"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Resources) != 1 || out.Resources[0].Name != "inventoried" ||
		out.Resources[0].AccountID != info.AccountID || info.AccountID == "" || out.Resources[0].ProjectID != info.ProjectID {
		t.Fatalf("inventory = %s; want the VPC, in account %s", body, info.AccountID)
	}
}

// TestInventoryThroughAdminCommand: under enforce, weistack admin signs
// the query string too.
func TestInventoryThroughAdminCommand(t *testing.T) {
	t.Parallel()
	vars := map[string]string{"WEISTACK_IAM": "enforce", "WEISTACK_TLS_DIR": t.TempDir()}
	inst := startInstance(t, vars)
	_, port, _ := net.SplitHostPort(inst.addr)
	if status, _ := inst.get(t, "/_weistack/inventory"); status != http.StatusUnauthorized {
		t.Fatalf("unsigned GET inventory = %d, want 401", status)
	}
	var stdout bytes.Buffer
	err := Run(context.Background(), Env{
		Args:   []string{"admin", "GET", "inventory?type=vpc.vpcs&region_id=ap-southeast-1", "-port", port},
		Getenv: func(k string) string { return vars[k] }, Stdout: &stdout, Stderr: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("admin GET inventory: %v", err)
	}
	if got := stdout.String(); !bytes.Contains([]byte(got), []byte(`"count":0`)) {
		t.Fatalf("admin GET inventory = %s, want an empty inventory", got)
	}
}
