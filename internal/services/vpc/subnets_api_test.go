package vpc

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const docsSubnetBody = `{"subnet": {
	"name": "subnet", "cidr": "192.168.20.0/24", "gateway_ip": "192.168.20.1", "vpc_id": %q,
	"primary_dns": "114.114.114.114", "secondary_dns": "114.114.115.115",
	"availability_zone": "ap-southeast-1a",
	"extra_dhcp_opts": [{"opt_name": "ntp", "opt_value": "10.100.0.33,10.100.0.34"}]}}`

func TestSubnetLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")

	e.expect(t, "list_subnets_empty", http.MethodGet, "/subnets", "")

	out := e.expect(t, "create_subnet", http.MethodPost, "/subnets", fmt.Sprintf(docsSubnetBody, v.ID))
	sn := decodeInto[subnetResponse](t, out).Subnet
	if sn.NeutronNetworkID != sn.ID || sn.NeutronSubnetID == sn.ID || sn.VPCID != v.ID {
		t.Fatalf("IDs: %+v", sn)
	}
	path := "/vpcs/" + v.ID + "/subnets/" + sn.ID

	// UNKNOWN until the lifecycle delay has passed.
	e.expect(t, "error_subnet_busy", http.MethodDelete, path, "")
	e.settle(t)
	e.expect(t, "show_subnet", http.MethodGet, "/subnets/"+sn.ID, "")
	e.expect(t, "list_subnets", http.MethodGet, "/subnets", "")
	e.expect(t, "list_subnets", http.MethodGet, "/subnets?vpc_id="+v.ID, "")
	e.expect(t, "list_subnets_empty", http.MethodGet, "/subnets?vpc_id="+testUnknownID, "")

	e.expect(t, "update_subnet", http.MethodPut, path, `{"subnet": {"name": "subnet-renamed"}}`)

	// A VPC cannot be deleted, or shrunk away from, a subnet it holds.
	e.expect(t, "error_vpc_has_subnets", http.MethodDelete, "/vpcs/"+v.ID, "")
	e.expect(t, "error_vpc_cidr_excludes_subnet", http.MethodPut, "/vpcs/"+v.ID, `{"vpc": {"cidr": "192.168.0.0/20"}}`)
	if status, out := e.call(t, http.MethodPut, "/vpcs/"+v.ID, `{"vpc": {"cidr": "192.168.0.0/19"}}`); status != http.StatusOK {
		t.Fatalf("shrinking the VPC to a block that still covers the subnet: %d %s", status, out)
	}

	e.expect(t, "delete_subnet", http.MethodDelete, path, "")
	e.expect(t, "error_subnet_not_found", http.MethodGet, "/subnets/"+sn.ID, "")
	e.expect(t, "error_subnet_not_found", http.MethodDelete, path, "")
	e.expect(t, "error_subnet_not_found", http.MethodPut, path, `{"subnet": {"name": "x"}}`)
	e.expect(t, "delete_vpc", http.MethodDelete, "/vpcs/"+v.ID, "")
}

func TestCreateSubnetIPv6(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")

	out := e.expect(t, "create_subnet_ipv6", http.MethodPost, "/subnets", fmt.Sprintf(
		`{"subnet": {"name": "subnet6", "cidr": "192.168.30.0/24", "gateway_ip": "192.168.30.1", "vpc_id": %q, "ipv6_enable": true}}`, v.ID))
	sn := decodeInto[subnetResponse](t, out).Subnet
	if !strings.HasSuffix(sn.CIDRv6, "::/64") || !strings.HasSuffix(sn.GatewayIPv6, "::1") {
		t.Fatalf("IPv6 fields: %q %q", sn.CIDRv6, sn.GatewayIPv6)
	}
	e.settle(t)

	// Turning IPv6 off removes the fields; turning it on again restores them.
	path := "/vpcs/" + v.ID + "/subnets/" + sn.ID
	e.expect(t, "update_subnet", http.MethodPut, path, `{"subnet": {"name": "subnet6", "ipv6_enable": false}}`)
	got, _ := e.svc.GetSubnet(t.Context(), testTenant, sn.ID)
	if got.IPv6Enable || got.CIDRv6 != "" || got.NeutronSubnetIDv6 != "" {
		t.Fatalf("after disabling IPv6: %+v", got)
	}
	e.expect(t, "update_subnet", http.MethodPut, path, `{"subnet": {"name": "subnet6", "ipv6_enable": true}}`)
	got, _ = e.svc.GetSubnet(t.Context(), testTenant, sn.ID)
	if !got.IPv6Enable || got.CIDRv6 == "" || !isUUID(got.NeutronSubnetIDv6) {
		t.Fatalf("after re-enabling IPv6: %+v", got)
	}
}

func TestCreateSubnetRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")
	e.mustCreateSubnet(t, v.ID, "existing", "192.168.10.0/24", "192.168.10.1")

	sub := func(fields string) string {
		base := map[string]string{
			"name": `"s"`, "cidr": `"192.168.20.0/24"`, "gateway_ip": `"192.168.20.1"`, "vpc_id": `"` + v.ID + `"`,
		}
		var extra []string
		for _, kv := range strings.Split(fields, ";") {
			if kv == "" {
				continue
			}
			k, val, _ := strings.Cut(kv, "=")
			if _, isBase := base[k]; isBase {
				base[k] = val
			} else {
				extra = append(extra, fmt.Sprintf("%q: %s", k, val))
			}
		}
		parts := extra
		for k, val := range base {
			if val != "<omit>" {
				parts = append(parts, fmt.Sprintf("%q: %s", k, val))
			}
		}
		return `{"subnet": {` + strings.Join(parts, ", ") + `}}`
	}

	tests := []struct {
		name   string
		body   string
		golden string
	}{
		{"empty body", ``, "error_subnet_invalid"},
		{"missing subnet object", `{}`, "error_subnet_invalid"},
		{"missing name", sub(`name=<omit>`), "error_subnet_invalid"},
		{"bad name", sub(`name="a b"`), "error_subnet_invalid"},
		{"bad description", sub(`description="<b>"`), "error_subnet_invalid"},
		{"missing cidr", sub(`cidr=<omit>`), "error_subnet_invalid"},
		{"cidr not a cidr", sub(`cidr="192.168.20.0"`), "error_subnet_cidr_invalid"},
		{"cidr with host bits", sub(`cidr="192.168.20.5/24"`), "error_subnet_cidr_invalid"},
		{"cidr mask too long", sub(`cidr="192.168.20.0/30";gateway_ip="192.168.20.1"`), "error_subnet_cidr_invalid"},
		{"missing gateway", sub(`gateway_ip=<omit>`), "error_subnet_invalid"},
		{"gateway not an ip", sub(`gateway_ip="gw"`), "error_subnet_invalid"},
		{"gateway outside subnet", sub(`gateway_ip="192.168.21.1"`), "error_subnet_invalid"},
		{"gateway is network address", sub(`gateway_ip="192.168.20.0"`), "error_subnet_invalid"},
		{"gateway is broadcast address", sub(`gateway_ip="192.168.20.255"`), "error_subnet_invalid"},
		{"bad primary dns", sub(`primary_dns="dns.example"`), "error_subnet_invalid"},
		{"bad dnsList entry", sub(`dnsList=["8.8.8.8","x"]`), "error_subnet_invalid"},
		{"unknown dhcp option", sub(`extra_dhcp_opts=[{"opt_name":"router"}]`), "error_subnet_invalid"},
		{"repeated dhcp option", sub(`extra_dhcp_opts=[{"opt_name":"ntp"},{"opt_name":"ntp"}]`), "error_subnet_invalid"},
		{"missing vpc_id", sub(`vpc_id=<omit>`), "error_subnet_invalid"},
		{"malformed vpc_id", sub(`vpc_id="nope"`), "error_subnet_invalid"},
		{"unknown vpc", sub(`vpc_id="` + testUnknownID + `"`), "error_subnet_vpc_not_found"},
		{"outside the vpc", sub(`cidr="10.0.0.0/24";gateway_ip="10.0.0.1"`), "error_subnet_outside_vpc"},
		{"larger than the vpc", sub(`cidr="192.0.0.0/8";gateway_ip="192.0.0.1"`), "error_subnet_outside_vpc"},
		{"same cidr as a sibling", sub(`cidr="192.168.10.0/24";gateway_ip="192.168.10.1"`), "error_subnet_cidr_conflict"},
		{"inside a sibling", sub(`cidr="192.168.10.128/25";gateway_ip="192.168.10.129"`), "error_subnet_cidr_conflict"},
		{"contains a sibling", sub(`cidr="192.168.8.0/21";gateway_ip="192.168.8.1"`), "error_subnet_cidr_conflict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, "/subnets", tt.body)
		})
	}

	got, err := e.svc.ListSubnets(t.Context(), testTenant, ListSubnetsFilter{})
	if err != nil || len(got) != 1 {
		t.Fatalf("%d subnets exist after rejected creates (err %v), want 1", len(got), err)
	}
}

func TestSubnetDNSRules(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.mustCreateVPC(t, "vpc", "10.0.0.0/8")

	create := func(n int, dns string) Subnet {
		t.Helper()
		body := fmt.Sprintf(`{"subnet": {"name": "s%d", "cidr": "10.0.%d.0/24", "gateway_ip": "10.0.%d.1", "vpc_id": %q%s}}`, n, n, n, v.ID, dns)
		status, out := e.call(t, http.MethodPost, "/subnets", body)
		if status != http.StatusOK {
			t.Fatalf("create: %d %s", status, out)
		}
		return decodeInto[subnetResponse](t, out).Subnet
	}
	join := func(sn Subnet) string {
		return sn.PrimaryDNS + "|" + sn.SecondaryDNS + "|" + strings.Join(sn.DNSList, ",")
	}

	tests := []struct{ dns, want string }{
		{``, "||"},
		{`, "primary_dns": "1.1.1.1"`, "1.1.1.1||1.1.1.1"},
		{`, "primary_dns": "1.1.1.1", "secondary_dns": "2.2.2.2"`, "1.1.1.1|2.2.2.2|1.1.1.1,2.2.2.2"},
		// With only the secondary given, the primary takes its value.
		{`, "secondary_dns": "2.2.2.2"`, "2.2.2.2||2.2.2.2"},
		{`, "primary_dns": "1.1.1.1", "dnsList": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]`, "1.1.1.1||1.1.1.1,2.2.2.2,3.3.3.3"},
	}
	for i, tt := range tests {
		if got := join(create(i+1, tt.dns)); got != tt.want {
			t.Errorf("dns %q: got %q, want %q", tt.dns, got, tt.want)
		}
	}
}

func TestUpdateSubnet(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")
	other := e.mustCreateVPC(t, "other", "10.0.0.0/8")
	sn := e.mustCreateSubnet(t, v.ID, "s", "192.168.1.0/24", "192.168.1.1")
	path := "/vpcs/" + v.ID + "/subnets/" + sn.ID

	e.clock.Advance(60 * 1e9)
	e.expect(t, "update_subnet", http.MethodPut, path, `{"subnet": {
		"name": "renamed", "description": "web tier", "dhcp_enable": false,
		"primary_dns": "8.8.8.8", "secondary_dns": "8.8.4.4",
		"extra_dhcp_opts": [{"opt_name": "addresstime", "opt_value": "24h"}],
		"enable_network_address_usage_metrics": true}}`)

	got, err := e.svc.GetSubnet(t.Context(), testTenant, sn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "renamed" || got.Description != "web tier" || got.DHCPEnable ||
		got.PrimaryDNS != "8.8.8.8" || strings.Join(got.DNSList, ",") != "8.8.8.8,8.8.4.4" ||
		len(got.ExtraDHCPOpts) != 1 || !got.EnableNetworkAddressUsageMetrics {
		t.Fatalf("updated = %+v", got)
	}
	if timeEqual(got.UpdatedAt, testEpoch) || got.CIDR != "192.168.1.0/24" {
		t.Fatalf("updated_at/cidr: %+v", got)
	}

	for name, body := range map[string]string{
		"missing subnet object": `{}`,
		"missing name":          `{"subnet": {"description": "x"}}`,
		"bad name":              `{"subnet": {"name": "a b"}}`,
		"bad description":       `{"subnet": {"name": "s", "description": "<"}}`,
		"bad dns":               `{"subnet": {"name": "s", "primary_dns": "nope"}}`,
		"bad dhcp option":       `{"subnet": {"name": "s", "extra_dhcp_opts": [{"opt_name": "x"}]}}`,
		"malformed":             `[`,
	} {
		t.Run(name, func(t *testing.T) {
			e.expect(t, "error_subnet_invalid", http.MethodPut, path, body)
		})
	}

	ok := `{"subnet": {"name": "s"}}`
	e.expect(t, "error_subnet_not_in_vpc", http.MethodPut, "/vpcs/"+other.ID+"/subnets/"+sn.ID, ok)
	e.expect(t, "error_subnet_not_in_vpc", http.MethodDelete, "/vpcs/"+other.ID+"/subnets/"+sn.ID, "")
	e.expect(t, "error_subnet_invalid", http.MethodPut, "/vpcs/nope/subnets/"+sn.ID, ok)
	e.expect(t, "error_subnet_invalid", http.MethodPut, "/vpcs/"+v.ID+"/subnets/nope", ok)
	e.expect(t, "error_subnet_invalid", http.MethodGet, "/subnets/nope", "")
}

func TestListSubnetsPaging(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.mustCreateVPC(t, "a", "10.0.0.0/8")
	b := e.mustCreateVPC(t, "b", "172.16.0.0/12")
	s1 := e.mustCreateSubnet(t, a.ID, "s1", "10.0.1.0/24", "10.0.1.1")
	e.mustCreateSubnet(t, b.ID, "s2", "172.16.1.0/24", "172.16.1.1")
	s3 := e.mustCreateSubnet(t, a.ID, "s3", "10.0.3.0/24", "10.0.3.1")

	tests := []struct{ query, want string }{
		{"", "s1,s2,s3"},
		{"?vpc_id=" + a.ID, "s1,s3"},
		{"?limit=1&vpc_id=" + a.ID, "s1"},
		{"?marker=" + s1.ID + "&vpc_id=" + a.ID, "s3"},
		{"?marker=" + s3.ID, ""},
	}
	for _, tt := range tests {
		status, out := e.call(t, http.MethodGet, "/subnets"+tt.query, "")
		if status != http.StatusOK {
			t.Fatalf("list %s: %d %s", tt.query, status, out)
		}
		var names []string
		for _, sn := range decodeInto[listSubnetsResponse](t, out).Subnets {
			names = append(names, sn.Name)
		}
		if got := strings.Join(names, ","); got != tt.want {
			t.Errorf("list %q = %q, want %q", tt.query, got, tt.want)
		}
	}
	e.expect(t, "error_subnet_invalid", http.MethodGet, "/subnets?limit=x", "")
	e.expect(t, "error_subnet_invalid", http.MethodGet, "/subnets?marker="+testUnknownID, "")
}

func TestSubnetWithAllocatedIPsCannotBeDeleted(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")
	sn := e.mustCreateSubnet(t, v.ID, "s", "192.168.1.0/24", "192.168.1.1")
	path := "/vpcs/" + v.ID + "/subnets/" + sn.ID

	ip, err := e.svc.AllocateIP(t.Context(), testTenant, sn.ID, "ecs:server-1", "")
	if err != nil {
		t.Fatal(err)
	}
	e.expect(t, "error_subnet_in_use", http.MethodDelete, path, "")

	if err := e.svc.ReleaseIP(t.Context(), testTenant, sn.ID, ip); err != nil {
		t.Fatal(err)
	}
	e.expect(t, "delete_subnet", http.MethodDelete, path, "")
}
