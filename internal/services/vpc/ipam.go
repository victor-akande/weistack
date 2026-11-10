package vpc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/victor-akande/weistack/internal/core/store"
)

// Errors returned by the private IP allocator. The services that consume
// addresses (ECS, RDS) map them to their own error codes.
var (
	// ErrSubnetNotFound means the subnet does not exist in the tenant.
	ErrSubnetNotFound = errors.New("vpc: subnet not found")
	// ErrSubnetFull means every usable address is allocated.
	ErrSubnetFull = errors.New("vpc: no free private IP address in subnet")
	// ErrIPInUse means the requested address is already allocated.
	ErrIPInUse = errors.New("vpc: private IP address already in use")
	// ErrIPNotUsable means the requested address is outside the subnet
	// or is one of its reserved addresses.
	ErrIPNotUsable = errors.New("vpc: private IP address is not usable in subnet")
)

// reservedTail is how many addresses below the broadcast address the
// platform keeps for itself (system interface and DHCP). Together with
// the network, gateway and broadcast addresses this leaves 251 usable
// addresses in a /24, matching available_ip_address_count in the API
// reference.
const reservedTail = 2

// addressPlan describes which addresses of a subnet can be handed out.
type addressPlan struct {
	block    netip.Prefix
	gateway  netip.Addr
	last     netip.Addr // broadcast address
	tailFrom netip.Addr // first of the reserved tail addresses
}

func newAddressPlan(cidr, gateway string) (addressPlan, error) {
	block, err := parseIPv4CIDR(cidr)
	if err != nil {
		return addressPlan{}, err
	}
	gw, err := netip.ParseAddr(gateway)
	if err != nil {
		return addressPlan{}, fmt.Errorf("gateway %q is not an IP address", gateway)
	}
	last := lastAddr(block)
	tail := last
	for range reservedTail {
		tail = tail.Prev()
	}
	return addressPlan{block: block, gateway: gw, last: last, tailFrom: tail}, nil
}

// lastAddr returns the highest (broadcast) address of an IPv4 block.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}) //nolint:gosec // deliberate byte truncation
}

// usable reports whether addr may be allocated to a resource.
func (p addressPlan) usable(addr netip.Addr) bool {
	return p.block.Contains(addr) &&
		addr != p.block.Addr() && // network address
		addr != p.gateway &&
		addr.Compare(p.tailFrom) < 0 // reserved tail and broadcast
}

// capacity is the number of usable addresses.
func (p addressPlan) capacity() int {
	total := 1 << (32 - p.block.Bits())
	n := total - 1 - reservedTail - 1 // network, tail, broadcast
	// The gateway costs one more address unless it already sits on a
	// reserved one.
	if p.block.Contains(p.gateway) && p.gateway != p.block.Addr() && p.gateway.Compare(p.tailFrom) < 0 {
		n--
	}
	if n < 0 {
		n = 0
	}
	return n
}

// firstFree returns the lowest usable address not in taken.
func (p addressPlan) firstFree(taken map[string]string) (netip.Addr, bool) {
	for addr := p.block.Addr().Next(); addr.IsValid() && addr.Compare(p.tailFrom) < 0; addr = addr.Next() {
		if addr == p.gateway {
			continue
		}
		if _, used := taken[addr.String()]; !used {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// AllocateIP reserves a private IP address in a subnet for owner (for
// example "ecs:<server id>") and returns it. With want empty the lowest
// free address is chosen; otherwise exactly want is reserved or an error
// is returned. It is safe for concurrent use: two callers never receive
// the same address.
func (s *Service) AllocateIP(ctx context.Context, t Tenant, subnetID, owner, want string) (string, error) {
	var wanted netip.Addr
	if want != "" {
		var err error
		if wanted, err = netip.ParseAddr(want); err != nil {
			return "", fmt.Errorf("%w: %q is not an IP address", ErrIPNotUsable, want)
		}
	}

	s.ipamMu.Lock()
	defer s.ipamMu.Unlock()

	var got string
	_, err := s.subnets(t).Update(ctx, subnetID, func(rec *subnetRecord) error {
		plan, err := newAddressPlan(rec.CIDR, rec.GatewayIP)
		if err != nil {
			return err
		}
		addr := wanted
		if want == "" {
			var ok bool
			if addr, ok = plan.firstFree(rec.Allocations); !ok {
				return ErrSubnetFull
			}
		} else {
			if !plan.usable(addr) {
				return fmt.Errorf("%w: %s in %s", ErrIPNotUsable, addr, rec.CIDR)
			}
			if _, used := rec.Allocations[addr.String()]; used {
				return fmt.Errorf("%w: %s", ErrIPInUse, addr)
			}
		}
		if rec.Allocations == nil {
			rec.Allocations = make(map[string]string)
		}
		got = addr.String()
		rec.Allocations[got] = owner
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrSubnetNotFound
	}
	if err != nil {
		return "", err
	}
	return got, nil
}

// ReleaseIP returns an address to the subnet's free pool. Releasing an
// address that is not allocated, or whose subnet is gone, is a no-op, so
// cleanup paths can call it unconditionally.
func (s *Service) ReleaseIP(ctx context.Context, t Tenant, subnetID, ip string) error {
	s.ipamMu.Lock()
	defer s.ipamMu.Unlock()

	_, err := s.subnets(t).Update(ctx, subnetID, func(rec *subnetRecord) error {
		delete(rec.Allocations, ip)
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// contains reports whether outer fully contains inner.
func contains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}
