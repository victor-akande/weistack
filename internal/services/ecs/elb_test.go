package ecs

import (
	"testing"

	"github.com/victor-akande/weistack/internal/services/vpc"
)

func TestServerAt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()

	// Create two VPCs: VPC 1 with two subnets, VPC 2 with one subnet.
	n1 := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	sn1b, err := e.network.CreateSubnet(ctx, testTenant.vpc(), vpc.CreateSubnetOption{
		Name:      "subnet-1b",
		CIDR:      "192.168.2.0/24",
		GatewayIP: "192.168.2.1",
		VPCID:     n1.vpcID,
	})
	if err != nil {
		t.Fatalf("CreateSubnet 1b: %v", err)
	}
	e.settle(t)

	n2 := e.mustNetwork(t, testTenant, "192.168.10.0/24")

	// Server 1 in VPC 1 with two NICs (subnet 1a and subnet 1b).
	_, ids1 := e.mustCreate(t, n1.serverBody(
		"name", `"srv-multi-nic"`,
		"nics", `[{"subnet_id": "`+n1.subnetID+`", "ip_address": "192.168.1.10"}, {"subnet_id": "`+sn1b.ID+`", "ip_address": "192.168.2.20"}]`,
	))
	srv1ID := ids1[0]

	// Before settling, server is BUILD.
	vt := testTenant.vpc()
	if status, ok, err := e.svc.ServerAt(ctx, vt, n1.vpcID, n1.subnetID, "192.168.1.10"); err != nil || !ok || status != StatusBuild {
		t.Fatalf("ServerAt during BUILD = (%q, %v, %v), want (%q, true, nil)", status, ok, err, StatusBuild)
	}

	// Settle -> ACTIVE.
	e.settle(t)

	// Server 2 in VPC 2.
	srv2ID := e.mustServer(t, n2,
		"name", `"srv-vpc2"`,
		"nics", `[{"subnet_id": "`+n2.subnetID+`", "ip_address": "192.168.10.30"}]`,
	)

	tests := []struct {
		name       string
		tenant     vpc.Tenant
		vpcID      string
		subnetID   string
		ip         string
		wantStatus string
		wantOK     bool
	}{
		{
			name:       "primary NIC exact subnet and VPC",
			tenant:     vt,
			vpcID:      n1.vpcID,
			subnetID:   n1.subnetID,
			ip:         "192.168.1.10",
			wantStatus: StatusActive,
			wantOK:     true,
		},
		{
			name:       "secondary NIC exact subnet and VPC",
			tenant:     vt,
			vpcID:      n1.vpcID,
			subnetID:   sn1b.ID,
			ip:         "192.168.2.20",
			wantStatus: StatusActive,
			wantOK:     true,
		},
		{
			name:       "any subnet in VPC 1 (IP member lookup)",
			tenant:     vt,
			vpcID:      n1.vpcID,
			subnetID:   "",
			ip:         "192.168.2.20",
			wantStatus: StatusActive,
			wantOK:     true,
		},
		{
			name:       "empty VPC and empty subnet matches tenant server",
			tenant:     vt,
			vpcID:      "",
			subnetID:   "",
			ip:         "192.168.10.30",
			wantStatus: StatusActive,
			wantOK:     true,
		},
		{
			name:     "wrong subnet for IP",
			tenant:   vt,
			vpcID:    n1.vpcID,
			subnetID: sn1b.ID,
			ip:       "192.168.1.10",
			wantOK:   false,
		},
		{
			name:     "wrong VPC for IP (IP member must stay in LB VPC)",
			tenant:   vt,
			vpcID:    n1.vpcID,
			subnetID: "",
			ip:       "192.168.10.30",
			wantOK:   false,
		},
		{
			name:     "wrong VPC even when subnet matches",
			tenant:   vt,
			vpcID:    n2.vpcID,
			subnetID: n1.subnetID,
			ip:       "192.168.1.10",
			wantOK:   false,
		},
		{
			name:     "unknown IP",
			tenant:   vt,
			vpcID:    n1.vpcID,
			subnetID: n1.subnetID,
			ip:       "192.168.1.99",
			wantOK:   false,
		},
		{
			name:     "empty IP",
			tenant:   vt,
			vpcID:    n1.vpcID,
			subnetID: n1.subnetID,
			ip:       "",
			wantOK:   false,
		},
		{
			name:     "other project does not see server",
			tenant:   vpc.Tenant{Region: testRegion, ProjectID: otherProject},
			vpcID:    n1.vpcID,
			subnetID: n1.subnetID,
			ip:       "192.168.1.10",
			wantOK:   false,
		},
		{
			name:     "other region does not see server",
			tenant:   vpc.Tenant{Region: "eu-west-0", ProjectID: testProject},
			vpcID:    n1.vpcID,
			subnetID: n1.subnetID,
			ip:       "192.168.1.10",
			wantOK:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, ok, err := e.svc.ServerAt(ctx, tc.tenant, tc.vpcID, tc.subnetID, tc.ip)
			if err != nil {
				t.Fatalf("ServerAt error: %v", err)
			}
			if ok != tc.wantOK || status != tc.wantStatus {
				t.Fatalf("ServerAt = (%q, %v), want (%q, %v)", status, ok, tc.wantStatus, tc.wantOK)
			}
		})
	}

	// Stop server 1 -> SHUTOFF, then start -> ACTIVE, then delete -> not found.
	if _, err := e.svc.StopServers(ctx, testTenant, []string{srv1ID}, "SOFT"); err != nil {
		t.Fatalf("StopServers: %v", err)
	}
	e.settle(t)
	if status, ok, err := e.svc.ServerAt(ctx, vt, n1.vpcID, n1.subnetID, "192.168.1.10"); err != nil || !ok || status != StatusShutoff {
		t.Fatalf("ServerAt after stop = (%q, %v, %v), want (%q, true, nil)", status, ok, err, StatusShutoff)
	}

	if _, err := e.svc.StartServers(ctx, testTenant, []string{srv1ID}); err != nil {
		t.Fatalf("StartServers: %v", err)
	}
	e.settle(t)
	if status, ok, err := e.svc.ServerAt(ctx, vt, n1.vpcID, n1.subnetID, "192.168.1.10"); err != nil || !ok || status != StatusActive {
		t.Fatalf("ServerAt after start = (%q, %v, %v), want (%q, true, nil)", status, ok, err, StatusActive)
	}

	if _, err := e.svc.DeleteServers(ctx, testTenant, []string{srv2ID}); err != nil {
		t.Fatalf("DeleteServers: %v", err)
	}
	e.settle(t)
	if status, ok, err := e.svc.ServerAt(ctx, vt, n2.vpcID, n2.subnetID, "192.168.10.30"); err != nil || ok || status != "" {
		t.Fatalf("ServerAt after delete = (%q, %v, %v), want (\"\", false, nil)", status, ok, err)
	}
}
