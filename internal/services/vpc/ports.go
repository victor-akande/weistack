package vpc

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

// Ports.
//
// A port is a network interface in a subnet. WeiStack creates ports only
// as the NICs of ECS servers, which own them: ECS is the PortSource, and
// the VPC API shows those ports read-only. Creating, updating and
// deleting ports is not emulated.

// Port is a NIC as its owner describes it.
type Port struct {
	ID string
	// SubnetID is the ID of the (v1) subnet the port is in.
	SubnetID string
	IP       string
	MAC      string
	// DeviceID is the server the port belongs to, DeviceOwner its kind,
	// for example "compute:ap-southeast-1a".
	DeviceID       string
	DeviceOwner    string
	SecurityGroups []string
}

// PortSource lists the ports of a project. The ECS service implements it.
type PortSource interface {
	Ports(ctx context.Context, t Tenant) ([]Port, error)
}

// portSource is guarded by its own mutex: ECS is installed after both
// services exist, since ECS depends on VPC.
type portSource struct {
	mu  sync.Mutex
	src PortSource
}

// SetPorts installs the source of ports.
func (s *Service) SetPorts(src PortSource) {
	s.ports.mu.Lock()
	defer s.ports.mu.Unlock()
	s.ports.src = src
}

func (s *Service) listPorts(ctx context.Context, t Tenant) ([]Port, error) {
	s.ports.mu.Lock()
	src := s.ports.src
	s.ports.mu.Unlock()
	if src == nil {
		return nil, nil
	}
	return src.Ports(ctx, t)
}

// v1Port mirrors the SDK model vpc/v2 Port.
type v1Port struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	NetworkID           string            `json:"network_id"`
	AdminStateUp        bool              `json:"admin_state_up"`
	MACAddress          string            `json:"mac_address"`
	FixedIPs            []fixedIP         `json:"fixed_ips"`
	DeviceID            string            `json:"device_id"`
	DeviceOwner         string            `json:"device_owner"`
	TenantID            string            `json:"tenant_id"`
	Status              string            `json:"status"`
	SecurityGroups      []string          `json:"security_groups"`
	AllowedAddressPairs []addressPair     `json:"allowed_address_pairs"`
	ExtraDHCPOpts       []ExtraDHCPOption `json:"extra_dhcp_opts"`
	VIFDetails          map[string]any    `json:"binding:vif_details"`
	Profile             map[string]any    `json:"binding:profile"`
	VNICType            string            `json:"binding:vnic_type"`
	DNSAssignment       []dnsAssignment   `json:"dns_assignment"`
	DNSName             string            `json:"dns_name"`
	InstanceID          string            `json:"instance_id"`
	InstanceType        string            `json:"instance_type"`
	PortSecurityEnabled bool              `json:"port_security_enabled"`
	ZoneID              string            `json:"zone_id"`
	EnableEFI           bool              `json:"enable_efi"`
}

type fixedIP struct {
	SubnetID  string `json:"subnet_id"`
	IPAddress string `json:"ip_address"`
}

type addressPair struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address,omitempty"`
}

type dnsAssignment struct {
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	FQDN      string `json:"fqdn"`
}

const portStatusActive = "ACTIVE"

func errPortNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "VPC.2502", "Port %s not found", id)
}

func errInvalidPort(format string, args ...any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.2500", format, args...)
}

// v1Port renders a port. fixed_ips names the subnet by its Neutron
// subnet ID and network_id by the v1 subnet ID, as the real API does.
func (s *Service) v1Port(ctx context.Context, t Tenant, p Port) (v1Port, error) {
	neutronSubnet := ""
	sn, err := s.GetSubnet(ctx, t, p.SubnetID)
	var apiErr *apierr.Error
	switch {
	case err == nil:
		neutronSubnet = sn.NeutronSubnetID
	case !errors.As(err, &apiErr):
		return v1Port{}, err
	}
	groups := p.SecurityGroups
	if groups == nil {
		groups = []string{}
	}
	return v1Port{
		ID: p.ID, NetworkID: p.SubnetID, AdminStateUp: true, MACAddress: p.MAC,
		FixedIPs: []fixedIP{{SubnetID: neutronSubnet, IPAddress: p.IP}},
		DeviceID: p.DeviceID, DeviceOwner: p.DeviceOwner, TenantID: t.ProjectID, Status: portStatusActive,
		SecurityGroups: groups, AllowedAddressPairs: []addressPair{}, ExtraDHCPOpts: []ExtraDHCPOption{},
		VIFDetails: map[string]any{}, Profile: map[string]any{}, VNICType: "normal",
		DNSAssignment: []dnsAssignment{}, PortSecurityEnabled: true,
	}, nil
}

type showPortResponse struct {
	Port v1Port `json:"port"`
}

func (s *Service) handleShowPort(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "port_id")
	all, err := s.listPorts(r.Context(), t)
	if err != nil {
		return err
	}
	for _, p := range all {
		if p.ID == id {
			out, err := s.v1Port(r.Context(), t, p)
			if err != nil {
				return err
			}
			return httpx.WriteJSON(w, http.StatusOK, showPortResponse{Port: out})
		}
	}
	return errPortNotFound(id)
}

type listPortsResponse struct {
	Ports []v1Port `json:"ports"`
}

func (s *Service) handleListPorts(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, v1ListLimits)
	if err != nil {
		return errInvalidPort("%s", err)
	}
	all, err := s.listPorts(r.Context(), t)
	if err != nil {
		return err
	}
	eq := func(param, got string) bool { want := q.Get(param); return want == "" || want == got }
	matched := make([]Port, 0, len(all))
	for _, p := range all {
		if eq("id", p.ID) && eq("device_id", p.DeviceID) && eq("device_owner", p.DeviceOwner) &&
			eq("network_id", p.SubnetID) && eq("mac_address", p.MAC) && eq("status", portStatusActive) && eq("name", "") {
			matched = append(matched, p)
		}
	}
	window, err := pagination.ByMarker(matched, func(p Port) string { return p.ID }, page)
	if errors.Is(err, pagination.ErrMarkerNotFound) {
		return errPortNotFound(page.ID)
	}
	if err != nil {
		return err
	}
	out := listPortsResponse{Ports: make([]v1Port, 0, len(window))}
	for _, p := range window {
		v, err := s.v1Port(r.Context(), t, p)
		if err != nil {
			return err
		}
		out.Ports = append(out.Ports, v)
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}
