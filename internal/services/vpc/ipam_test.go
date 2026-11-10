package vpc

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

func TestAddressPlan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		cidr, gateway string
		capacity      int
		first         string
		usable        []string
		unusable      []string
	}{
		{
			cidr: "192.168.20.0/24", gateway: "192.168.20.1", capacity: 251, first: "192.168.20.2",
			usable:   []string{"192.168.20.2", "192.168.20.100", "192.168.20.252"},
			unusable: []string{"192.168.20.0", "192.168.20.1", "192.168.20.253", "192.168.20.254", "192.168.20.255", "192.168.21.5"},
		},
		{
			// A gateway that is not the first address.
			cidr: "10.0.0.0/24", gateway: "10.0.0.100", capacity: 251, first: "10.0.0.1",
			usable:   []string{"10.0.0.1", "10.0.0.99", "10.0.0.101"},
			unusable: []string{"10.0.0.100"},
		},
		{
			// A gateway inside the reserved tail does not cost an extra address.
			cidr: "10.0.0.0/24", gateway: "10.0.0.254", capacity: 252, first: "10.0.0.1",
			usable: []string{"10.0.0.252"}, unusable: []string{"10.0.0.253", "10.0.0.254"},
		},
		{cidr: "10.1.0.0/16", gateway: "10.1.0.1", capacity: 65531, first: "10.1.0.2"},
		{
			cidr: "10.0.0.0/28", gateway: "10.0.0.1", capacity: 11, first: "10.0.0.2",
			usable: []string{"10.0.0.12"}, unusable: []string{"10.0.0.13", "10.0.0.14", "10.0.0.15"},
		},
		{
			cidr: "10.0.0.0/29", gateway: "10.0.0.1", capacity: 3, first: "10.0.0.2",
			usable: []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"}, unusable: []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.cidr+" gw "+tt.gateway, func(t *testing.T) {
			t.Parallel()
			plan, err := newAddressPlan(tt.cidr, tt.gateway)
			if err != nil {
				t.Fatal(err)
			}
			if got := plan.capacity(); got != tt.capacity {
				t.Errorf("capacity = %d, want %d", got, tt.capacity)
			}
			first, ok := plan.firstFree(nil)
			if !ok || first.String() != tt.first {
				t.Errorf("firstFree = %s, %v; want %s", first, ok, tt.first)
			}
			for _, ip := range tt.usable {
				if !plan.usable(netip.MustParseAddr(ip)) {
					t.Errorf("%s should be usable", ip)
				}
			}
			for _, ip := range tt.unusable {
				if plan.usable(netip.MustParseAddr(ip)) {
					t.Errorf("%s should not be usable", ip)
				}
			}

			// capacity must agree with what can actually be allocated.
			if tt.capacity <= 300 {
				taken := map[string]string{}
				for {
					addr, ok := plan.firstFree(taken)
					if !ok {
						break
					}
					if !plan.usable(addr) {
						t.Fatalf("firstFree returned unusable %s", addr)
					}
					taken[addr.String()] = "x"
				}
				if len(taken) != tt.capacity {
					t.Errorf("allocated %d addresses, capacity says %d", len(taken), tt.capacity)
				}
			}
		})
	}

	if _, err := newAddressPlan("nope", "10.0.0.1"); err == nil {
		t.Error("newAddressPlan accepted a bad CIDR")
	}
	if _, err := newAddressPlan("10.0.0.0/24", "nope"); err == nil {
		t.Error("newAddressPlan accepted a bad gateway")
	}
}

func TestLastAddr(t *testing.T) {
	t.Parallel()
	for cidr, want := range map[string]string{
		"192.168.20.0/24": "192.168.20.255",
		"10.0.0.0/8":      "10.255.255.255",
		"172.16.0.0/12":   "172.31.255.255",
		"10.0.0.8/29":     "10.0.0.15",
	} {
		if got := lastAddr(netip.MustParsePrefix(cidr)).String(); got != want {
			t.Errorf("lastAddr(%s) = %s, want %s", cidr, got, want)
		}
	}
}

func TestAllocateAndReleaseIP(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")
	sn := e.mustCreateSubnet(t, v.ID, "s", "192.168.1.0/24", "192.168.1.1")

	alloc := func(want string) (string, error) { return e.svc.AllocateIP(ctx, testTenant, sn.ID, "ecs:x", want) }
	available := func() int {
		t.Helper()
		got, err := e.svc.GetSubnet(ctx, testTenant, sn.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.AvailableIPAddressCount
	}

	// Sequential: lowest free address first.
	for _, want := range []string{"192.168.1.2", "192.168.1.3", "192.168.1.4"} {
		if got, err := alloc(""); err != nil || got != want {
			t.Fatalf("AllocateIP = %q, %v; want %q", got, err, want)
		}
	}
	if got := available(); got != 248 {
		t.Fatalf("available_ip_address_count = %d, want 248", got)
	}

	// A released address is the next one handed out.
	if err := e.svc.ReleaseIP(ctx, testTenant, sn.ID, "192.168.1.3"); err != nil {
		t.Fatal(err)
	}
	if got, _ := alloc(""); got != "192.168.1.3" {
		t.Fatalf("after release got %q, want the freed 192.168.1.3", got)
	}

	// A specific address.
	if got, err := alloc("192.168.1.50"); err != nil || got != "192.168.1.50" {
		t.Fatalf("requested address: %q, %v", got, err)
	}
	if _, err := alloc("192.168.1.50"); !errors.Is(err, ErrIPInUse) {
		t.Fatalf("taken address: err = %v, want ErrIPInUse", err)
	}
	for _, bad := range []string{"192.168.1.1", "192.168.1.0", "192.168.1.255", "192.168.1.254", "192.168.2.9", "nope"} {
		if _, err := alloc(bad); !errors.Is(err, ErrIPNotUsable) {
			t.Errorf("AllocateIP(%q): err = %v, want ErrIPNotUsable", bad, err)
		}
	}
	if got := available(); got != 247 {
		t.Fatalf("failed allocations changed the count: %d, want 247", got)
	}

	// Unknown subnets.
	if _, err := e.svc.AllocateIP(ctx, testTenant, testUnknownID, "x", ""); !errors.Is(err, ErrSubnetNotFound) {
		t.Fatalf("unknown subnet: err = %v, want ErrSubnetNotFound", err)
	}
	if err := e.svc.ReleaseIP(ctx, testTenant, testUnknownID, "10.0.0.1"); err != nil {
		t.Fatalf("release in an unknown subnet should be a no-op: %v", err)
	}
	if err := e.svc.ReleaseIP(ctx, testTenant, sn.ID, "192.168.1.200"); err != nil {
		t.Fatalf("releasing a free address should be a no-op: %v", err)
	}
}

func TestSubnetExhaustion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	v := e.mustCreateVPC(t, "vpc", "10.0.0.0/8")
	sn := e.mustCreateSubnet(t, v.ID, "tiny", "10.0.0.0/29", "10.0.0.1")

	for i := range 3 {
		if _, err := e.svc.AllocateIP(ctx, testTenant, sn.ID, fmt.Sprint(i), ""); err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
	}
	if _, err := e.svc.AllocateIP(ctx, testTenant, sn.ID, "one-too-many", ""); !errors.Is(err, ErrSubnetFull) {
		t.Fatalf("err = %v, want ErrSubnetFull", err)
	}
	got, _ := e.svc.GetSubnet(ctx, testTenant, sn.ID)
	if got.AvailableIPAddressCount != 0 {
		t.Fatalf("available_ip_address_count = %d, want 0", got.AvailableIPAddressCount)
	}
}

// The plan's concurrency requirement: 200 parallel allocations against
// one subnet, no duplicate addresses and no lost updates.
func TestConcurrentAllocationsAreUnique(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")
	sn := e.mustCreateSubnet(t, v.ID, "s", "192.168.1.0/24", "192.168.1.1")

	const workers = 200
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		seen = map[string]bool{}
	)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := e.svc.AllocateIP(ctx, testTenant, sn.ID, fmt.Sprintf("ecs:%d", i), "")
			if err != nil {
				t.Errorf("AllocateIP: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[ip] {
				t.Errorf("address %s allocated twice", ip)
			}
			seen[ip] = true
		}()
	}
	wg.Wait()

	if len(seen) != workers {
		t.Fatalf("%d distinct addresses, want %d", len(seen), workers)
	}
	got, _ := e.svc.GetSubnet(ctx, testTenant, sn.ID)
	if got.AvailableIPAddressCount != 251-workers {
		t.Fatalf("available_ip_address_count = %d, want %d (lost updates?)", got.AvailableIPAddressCount, 251-workers)
	}
}

func TestSubnetStatusTransitionsAndResume(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	v := e.mustCreateVPC(t, "vpc", "192.168.0.0/16")

	sn, err := e.svc.CreateSubnet(ctx, testTenant, CreateSubnetOption{
		Name: "s", CIDR: "192.168.1.0/24", GatewayIP: "192.168.1.1", VPCID: v.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sn.Status != SubnetStatusUnknown {
		t.Fatalf("new subnet status = %q, want UNKNOWN", sn.Status)
	}

	// Simulate a restart that lost the pending transition.
	if n := e.engine.CancelAll(); n != 1 {
		t.Fatalf("cancelled %d tasks, want 1", n)
	}
	e.settle(t)
	if got, _ := e.svc.GetSubnet(ctx, testTenant, sn.ID); got.Status != SubnetStatusUnknown {
		t.Fatalf("status = %q, want still UNKNOWN", got.Status)
	}
	if err := e.svc.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	if got, _ := e.svc.GetSubnet(ctx, testTenant, sn.ID); got.Status != SubnetStatusActive {
		t.Fatalf("status after Resume = %q, want ACTIVE", got.Status)
	}
}

func TestSubnetInAVPCWithoutCIDR(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	status, out := e.call(t, "POST", "/vpcs", `{"vpc": {"name": "no-cidr"}}`)
	if status != 200 {
		t.Fatalf("%d %s", status, out)
	}
	v := decodeInto[vpcResponse](t, out).VPC
	e.settle(t)
	// With no VPC block to stay inside, only sibling overlap applies.
	e.mustCreateSubnet(t, v.ID, "s", "10.9.0.0/24", "10.9.0.1")
}
