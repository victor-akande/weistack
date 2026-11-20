package nat

import (
	"net/http"
	"testing"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/store"
)

func TestPrivateScaffoldAndErrorCatalogue(t *testing.T) {
	t.Parallel()

	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{store: st}
	tenant := Tenant{Region: "ap-southeast-1", ProjectID: "0123456789abcdef0123456789abcdef"}
	ctx := t.Context()

	// Exercise the §2 private NAT store collections scaffolded in Wave 0.
	pg := privateGateway{ID: "pg-1", Name: "pg", Spec: "Small", VPCID: "v-1", SubnetID: "s-1", NgportIP: "10.0.0.5"}
	if err := svc.privateGateways(tenant).Create(ctx, pg.ID, pg); err != nil {
		t.Fatalf("privateGateways.Create: %v", err)
	}
	ts := transitSubnet{ID: "ts-1", Name: "ts", SubnetID: "s-2", VPCID: "v-1", CIDR: "10.0.1.0/24"}
	if err := svc.transitSubnets(tenant).Create(ctx, ts.ID, ts); err != nil {
		t.Fatalf("transitSubnets.Create: %v", err)
	}
	ti := transitIP{ID: "ti-1", SubnetID: "s-2", Address: "10.0.1.10", NetworkInterfaceID: "ni-1"}
	if err := svc.transitIPs(tenant).Create(ctx, ti.ID, ti); err != nil {
		t.Fatalf("transitIPs.Create: %v", err)
	}
	ps := privateSnat{ID: "ps-1", GatewayID: pg.ID, SubnetID: "s-1", TransitIPIDs: []string{ti.ID}}
	if err := svc.privateSnats(tenant).Create(ctx, ps.ID, ps); err != nil {
		t.Fatalf("privateSnats.Create: %v", err)
	}
	pd := privateDnat{ID: "pd-1", GatewayID: pg.ID, TransitIPID: ti.ID, PrivateIP: "10.0.0.20", Type: "CUSTOMIZE", Protocol: "tcp", InternalPort: "80", TransitPort: "8080"}
	if err := svc.privateDnats(tenant).Create(ctx, pd.ID, pd); err != nil {
		t.Fatalf("privateDnats.Create: %v", err)
	}

	if len(privateSpecs) != 5 || privateSpecs[0].Name != "Small" || privateSpecs[0].QPSMax != 6000 || privateTimeFormat == "" || privateTransitIPPoolSizeMax != 1 {
		t.Fatalf("unexpected privateSpecs: %+v", privateSpecs)
	}
	pi := pageInfo{NextMarker: "m1", PreviousMarker: "m0", CurrentCount: 1}
	if pi.CurrentCount != 1 {
		t.Fatalf("unexpected pageInfo: %+v", pi)
	}

	cases := []struct {
		err        *apierr.Error
		wantStatus int
		wantCode   string
	}{
		{errPrivateNotFound("Gateway", "g1"), http.StatusNotFound, "NAT.1002"},
		{errPrivateSubnetNotInVPC("s1", "g1"), http.StatusNotFound, "NAT.1003"},
		{errPrivatePortNotFound("p1"), http.StatusNotFound, "NAT.1009"},
		{errTransitSubnetUnavailable("s1"), http.StatusBadRequest, "NAT.1101"},
		{errDownlinkVPCLimit(1), http.StatusBadRequest, "NAT.1201"},
		{errPrivateHasDependencies("g1"), http.StatusBadRequest, "NAT.1202"},
		{errSamePrivateSpec("Small"), http.StatusBadRequest, "NAT.1206"},
		{errPrivateRuleLimit(20), http.StatusBadRequest, "NAT.1207"},
		{errTransitIPInGatewayVPC("ti1"), http.StatusConflict, "NAT.1303"},
		{errPrivatePortNotInVPC("p1"), http.StatusConflict, "NAT.1304"},
		{errTransitIPUsedByDnat("ti1"), http.StatusConflict, "NAT.1305"},
		{errPrivateDnatAnyPortMismatch(), http.StatusBadRequest, "NAT.1306"},
		{errPrivateDnatInternalConflict(), http.StatusConflict, "NAT.1307"},
		{errTransitIPUsedBySnat("ti1"), http.StatusConflict, "NAT.1308"},
		{errPrivateDnatPortAllPortConflict("p1"), http.StatusConflict, "NAT.1309"},
		{errPrivateDnatTransitConflict(), http.StatusConflict, "NAT.1310"},
		{errPrivateDnatTargetInvalid(), http.StatusBadRequest, "NAT.1311"},
		{errIPInUse("s1", "10.0.0.5"), http.StatusConflict, "NAT.1403"},
		{errInvalidIP("999.0.0.1"), http.StatusBadRequest, "NAT.1405"},
		{errTransitIPUsedByOtherGateway("ti1", "g2"), http.StatusConflict, "NAT.1406"},
		{errTransitIPUsedByRules("ti1"), http.StatusConflict, "NAT.1409"},
		{errTransitIPDnatAllPortConflict("ti1"), http.StatusConflict, "NAT.1410"},
		{errPrivateSnatSubnetOrCIDR(), http.StatusBadRequest, "NAT.1501"},
		{errPrivateSnatInvalidCIDR(), http.StatusBadRequest, "NAT.1502"},
		{errPrivateSnatNetworkExists("s1"), http.StatusConflict, "NAT.1503"},
		{errPrivateSnatCIDRExists("10.0.0.0/24"), http.StatusConflict, "NAT.1505"},
		{errPrivateSnatTransitIPLimit(20), http.StatusBadRequest, "NAT.1506"},
		{errPrivateSnatInvalidTransitIPID(), http.StatusBadRequest, "NAT.1507"},
	}
	for _, tc := range cases {
		if tc.err.Status != tc.wantStatus || tc.err.Code != tc.wantCode {
			t.Errorf("got (%d, %s), want (%d, %s)", tc.err.Status, tc.err.Code, tc.wantStatus, tc.wantCode)
		}
	}
}
