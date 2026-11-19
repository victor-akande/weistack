package sdk

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

// addFault adds a fault through the emulator's admin API.
func addFault(t *testing.T, rule string) {
	t.Helper()
	res, err := http.Post("http://"+emulatorAddr+"/_weistack/faults", "application/json", bytes.NewReader([]byte(rule)))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /_weistack/faults %s = %d", rule, res.StatusCode)
	}
}

// TestFaults injects a throttled request and a failed VPC creation
// through the admin API, and sees them through the SDK. It does not run
// in parallel: a lifecycle fault applies to the next VPC created in any
// project, which must be this test's.
func TestFaults(t *testing.T) {
	partner := addAccount(t, "sdk-faults-"+suffix(t))
	c := vpcIn(t, partner.AK, partner.SK, partner.ProjectID)

	// The next creation in this project is throttled, as by API Gateway.
	addFault(t, `{"type":"request","service":"vpc","method":"POST","path":"/v1/`+partner.ProjectID+`/vpcs","status":429}`)
	_, err := c.CreateVpc(&vpc.CreateVpcRequest{Body: &vpc.CreateVpcRequestBody{Vpc: &vpc.CreateVpcOption{Name: ptr("throttled")}}})
	wantError(t, err, 429, "APIGW.0308")

	// The retry succeeds, but the VPC's activation fails.
	addFault(t, `{"type":"lifecycle","transition":"vpc.vpc.create"}`)
	created, err := c.CreateVpc(&vpc.CreateVpcRequest{Body: &vpc.CreateVpcRequestBody{Vpc: &vpc.CreateVpcOption{Name: ptr("doomed")}}})
	if err != nil {
		t.Fatalf("CreateVpc after the throttle: %v", err)
	}
	id := created.Vpc.Id
	t.Cleanup(func() { _, _ = c.DeleteVpc(&vpc.DeleteVpcRequest{VpcId: id}) })
	eventually(t, "the VPC to fail", func() bool {
		shown, err := c.ShowVpc(&vpc.ShowVpcRequest{VpcId: id})
		return err == nil && shown.Vpc.Status.Value() == "ERROR"
	})
}

// suffix is a short random suffix for names that must be unique.
func suffix(t *testing.T) string {
	t.Helper()
	return strings.ToLower(rand.Text()[:6])
}
