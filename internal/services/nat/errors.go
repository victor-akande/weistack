package nat

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
)

// Error catalogue for NAT Gateway (§3, error-codes.tsv).
// Each constructor corresponds to one documented error code and comments
// the API page(s) where it appears.

// denied is NAT's documented permission error (VPC.2201, error-codes.tsv).
func denied(d *authz.Denial) *apierr.Error {
	return apierr.New(http.StatusForbidden, "VPC.2201", "%s", d.Message()).WithAuthorizationMessage(d.Encoded)
}

// --- Common & Public NAT errors (§3.1–§3.4, error-codes.tsv) ---

// errInvalidEnterpriseProjectID is VPC.0011 (CreateNatGateway, CreatePrivateNat, CreateTransitIp).
func errInvalidEnterpriseProjectID() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "VPC.0011", "EnterpriseProjectId is invalid")
}

// errInvalidParams is NAT.0002 (CreateNatGateway, UpdateNatGateway, ListNatGateways,
// CreateNatGatewaySnatRule, UpdateNatGatewaySnatRule, ListNatGatewaySnatRules,
// BatchCreateNatGatewayDnatRules, UpdateNatGatewayDnatRule, ListNatGatewayDnatRules,
// DeleteNatGatewayTag, BatchCreateDeleteNatGatewayTag).
func errInvalidParams(format string, args ...any) *apierr.Error {
	if format == "" {
		return apierr.New(http.StatusBadRequest, "NAT.0002", "Invalid parameters.")
	}
	return apierr.New(http.StatusBadRequest, "NAT.0002", format, args...)
}

// errRouterNotFound is NAT.0004 (CreateNatGateway).
func errRouterNotFound(routerID string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.0004", "The router %s does not exist.", routerID)
}

// errNetworkNotFound is NAT.0005 (CreateNatGateway).
func errNetworkNotFound(networkID string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.0005", "Network %s does not exist.", networkID)
}

// errRulesExist is NAT.0006 (DeleteNatGateway).
func errRulesExist() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0006", "Rule has not been deleted.")
}

// errSubnetNotInRouter is NAT.0008 (CreateNatGateway, CreateNatGatewaySnatRule).
func errSubnetNotInRouter(routerID, subnetID string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0008", "Router %s has no port for subnet %s.", routerID, subnetID)
}

// errInvalidDescription is NAT.0014 (CreateNatGateway, UpdateNatGateway,
// CreateNatGatewaySnatRule, UpdateNatGatewaySnatRule,
// CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errInvalidDescription() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0014", "Invalid input for description.+exceeds maximum length of 255.")
}

// errInvalidSpec is NAT.0016 (CreateNatGateway, UpdateNatGateway).
func errInvalidSpec(spec string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0016", "Invalid input for spec. Reason: '%s' is not in ['1', '2', '3', '4', '5'].", spec)
}

// errSnatNetworkNotFound is NAT.0019 (CreateNatGatewaySnatRule).
func errSnatNetworkNotFound(networkID string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.0019", "Network %s could not be found.", networkID)
}

// errPortNotFound is NAT.0023 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errPortNotFound(portID string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.0023", "Port '%s' could not be found.", portID)
}

// errFloatingIPNotFound is NAT.0026 (CreateNatGatewaySnatRule, UpdateNatGatewaySnatRule,
// CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errFloatingIPNotFound(fip string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0026", "Floating IP %s could not be found.", fip)
}

// errGatewayNotActive is NAT.0103 (UpdateNatGateway, DeleteNatGateway,
// CreateNatGatewaySnatRule, CreateNatGatewayDnatRule).
func errGatewayNotActive(gatewayID string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0103", "NatGateway %s is not ACTIVE.", gatewayID)
}

// errGatewayNotFound is NAT.0105 (ShowNatGateway, UpdateNatGateway, DeleteNatGateway,
// CreateNatGatewaySnatRule, CreateNatGatewayDnatRule, ShowNatGatewayTag,
// CreateNatGatewayTag, DeleteNatGatewayTag, BatchCreateDeleteNatGatewayTag).
func errGatewayNotFound(gatewayID string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.0105", "NatGateway %s does not exist.", gatewayID)
}

// errSnatNetworkOrCIDR is NAT.0202 (CreateNatGatewaySnatRule).
func errSnatNetworkOrCIDR() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0202", "Either network_id or cidr must be specified.Both can not be specified at the same time")
}

// errSnatInvalidCIDR is NAT.0203 (CreateNatGatewaySnatRule).
func errSnatInvalidCIDR() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0203", "cidr is invalid, make sure it's format is correct.")
}

// errSnatSourceTypeMismatch is NAT.0204 (CreateNatGatewaySnatRule).
func errSnatSourceTypeMismatch() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0204", "source_type and network_id is incompatible.")
}

// errSnatCIDRNotInSubnet is NAT.0205 (CreateNatGatewaySnatRule).
func errSnatCIDRNotInSubnet() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0205", "cidr must be a subset of subnet's cidr.")
}

// errSnatCIDRConflict is NAT.0207 (CreateNatGatewaySnatRule).
func errSnatCIDRConflict() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0207", "cidr in the request conflicts with cidrs of existing rules.")
}

// errSnatNetworkExists is NAT.0208 (CreateNatGatewaySnatRule).
func errSnatNetworkExists(networkID string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0208", "Snat rule for network %s exists.", networkID)
}

// errSnatRuleNotFound is NAT.0209 (ShowNatGatewaySnatRule, UpdateNatGatewaySnatRule, DeleteNatGatewaySnatRule).
func errSnatRuleNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.0209", "No Snat Rule exist with id %s", id)
}

// errSnatInvalidFloatingIPID is NAT.0210 (CreateNatGatewaySnatRule).
func errSnatInvalidFloatingIPID(fip string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0210", "Invalid input for floating_ip_id. Reason: '%s' is not a valid UUID.", fip)
}

// errSnatFloatingIPLimit is NAT.0211 (CreateNatGatewaySnatRule, UpdateNatGatewaySnatRule).
func errSnatFloatingIPLimit(limit int) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0211", "%d EIP has been associated to this SNAT rules's EIP pool, no more is allowed.", limit)
}

// errDnatInvalidProtocol is NAT.0302 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatInvalidProtocol(proto string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0302", "Dnat rule protocol %s not supported.Only protocol values ['tcp', 'udp', 'any'] and integer representations [6, 17, 0] are supported.", proto)
}

// errDnatInvalidPort is NAT.0303 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatInvalidPort(port any) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0303", "Invalid value for port %v", port)
}

// errDnatInternalConflict is NAT.0304 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatInternalConflict() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0304", "The port_id, private_ip, internal port and protocol specified have been occupied.")
}

// errDnatExternalConflict is NAT.0305 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatExternalConflict() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0305", "The floating ip, external port and protocol specified have been occupied.")
}

// errDnatAnyPortMismatch is NAT.0306 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatAnyPortMismatch() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0306", "The external port equals 0 and internal port equals 0 and protocol equals any must satisfied at the same time.")
}

// errDnatPortAllPortConflict is NAT.0307 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatPortAllPortConflict() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0307", "The port_id already existing dnat allport rules or dnat_rules, can no longer create dnat rules or dnat allport rules.")
}

// errDnatPrivateIPAllPortConflict is NAT.0308 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatPrivateIPAllPortConflict() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0308", "The private_ip already existing dnat allport rules or dnat rules, can no longer create dnat rules or dnat allport rules.")
}

// errDnatLimitExceeded is NAT.0309 (UpdateNatGateway, CreateNatGatewayDnatRule).
func errDnatLimitExceeded(limit int) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0309", "%d DNAT rules has been associated to this NAT Gateway, no more is allowed", limit)
}

// errDnatTargetMissing is NAT.0310 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatTargetMissing() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0310", "The port_id and private_ip values are both empty, at least one value is not empty.")
}

// errDnatInvalidPrivateIP is NAT.0311 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatInvalidPrivateIP() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0311", "The private ip address is not legal.")
}

// errDnatBatchLimit is NAT.0314 (BatchCreateNatGatewayDnatRules).
func errDnatBatchLimit(limit int) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0314", "batch create dnat rules max limit: %d", limit)
}

// errDnatInvalidPortVPC is NAT.0315 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatInvalidPortVPC(portID string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0315", "Port %s is not a valid port.", portID)
}

// errDnatBothTargets is NAT.0317 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errDnatBothTargets() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0317", "The port_id and private_ip exist at the same time and value is not empty, but at least one value is empty.")
}

// errDnatRuleNotFound is NAT.0319 (ShowNatGatewayDnatRule, UpdateNatGatewayDnatRule, DeleteNatGatewayDnatRule).
func errDnatRuleNotFound(id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.0319", "No Dnat Rule exist with id %s", id)
}

// errFloatingIPBoundToPort is NAT.0402 (CreateNatGatewaySnatRule, UpdateNatGatewaySnatRule,
// CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errFloatingIPBoundToPort(fip, portID string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0402", "Floating Ip %s has associated with port %s.", fip, portID)
}

// errDuplicateSnatFloatingIP is NAT.0403 (CreateNatGatewaySnatRule, UpdateNatGatewaySnatRule).
func errDuplicateSnatFloatingIP(fip string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0403", "There is a duplicate EIP %s in SNAT rule.", fip)
}

// errFloatingIPUsedByGateway is NAT.0404 (CreateNatGatewaySnatRule, UpdateNatGatewaySnatRule,
// CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errFloatingIPUsedByGateway(fip, gatewayID string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0404", "Floating Ip %s has used by nat gateway %s.", fip, gatewayID)
}

// errFloatingIPOccupied is NAT.0405 (CreateNatGatewaySnatRule, UpdateNatGatewaySnatRule,
// CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errFloatingIPOccupied(fip string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0405", "Floating Ip %s has been occupied.", fip)
}

// errFloatingIPDnatAllPortConflict is NAT.0408 (CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errFloatingIPDnatAllPortConflict(fip string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0408", "Floating Ip %s can not be associated with both DNAT rule and DNAT all port rule.", fip)
}

// errFloatingIPSnatDnatAllPortConflict is NAT.0409 (CreateNatGatewaySnatRule, UpdateNatGatewaySnatRule,
// CreateNatGatewayDnatRule, UpdateNatGatewayDnatRule).
func errFloatingIPSnatDnatAllPortConflict(fip string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.0409", "Floating Ip %s can not be associated with both SNAT rule and DNAT all port rule.", fip)
}

// --- Shared & Private NAT errors (§3.4–§3.10, error-codes.tsv) ---

// errPrivateNotFound is NAT.1002 (ShowPrivateNat, UpdatePrivateNat, DeletePrivateNat,
// CreateTransitSubnet, ShowTransitSubnet, UpdateTransitSubnet, DeleteTransitSubnet,
// CreateTransitIp, ShowTransitIp, DeleteTransitIp, CreatePrivateSnat, ShowPrivateSnat,
// UpdatePrivateSnat, DeletePrivateSnat, CreatePrivateDnat, ShowPrivateDnat,
// UpdatePrivateDnat, DeletePrivateDnat, private tag operations).
func errPrivateNotFound(kind, id string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.1002", "%s %s could not be found.", kind, id)
}

// errPrivateSubnetNotInVPC is NAT.1003 (CreatePrivateSnat).
func errPrivateSubnetNotInVPC(subnetID, gatewayID string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.1003", "VirSubnet %s could not be found in vpc for gateway %s.", subnetID, gatewayID)
}

// errPrivatePortNotFound is NAT.1009 (CreatePrivateDnat, UpdatePrivateDnat).
func errPrivatePortNotFound(portID string) *apierr.Error {
	return apierr.New(http.StatusNotFound, "NAT.1009", "Port %s information is missing.", portID)
}

// errBadJSON is NAT.1010 (all JSON decode errors and private NAT bad input parameters).
func errBadJSON(format string, args ...any) *apierr.Error {
	if format == "" {
		return apierr.New(http.StatusBadRequest, "NAT.1010", "Request parameter Json parsing failed.")
	}
	return apierr.New(http.StatusBadRequest, "NAT.1010", "Request parameter Json parsing failed "+format+".", args...)
}

// errInvalidTag is NAT.1015 (CreateNatGateway, CreatePrivateNat, CreateTransitSubnet,
// CreateTransitIp, all public and private tag write operations).
func errInvalidTag() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1015", "Tags parameter is illegal.")
}

// errTooManyTags is NAT.1016 (CreateNatGateway, CreatePrivateNat, CreateTransitSubnet,
// CreateTransitIp, all public and private tag write operations).
func errTooManyTags(limit int) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1016", "The number of tags exceeds the limit %d.", limit)
}

// errTransitSubnetUnavailable is NAT.1101 (CreateTransitSubnet, CreateTransitIp).
func errTransitSubnetUnavailable(subnetID string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1101", "Transit subnet can not be create with this network %s.", subnetID)
}

// errDownlinkVPCLimit is NAT.1201 (CreatePrivateNat).
func errDownlinkVPCLimit(limit int) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1201", "%d downlink vpc has been associated to this private nat gateway, no more is allowed.", limit)
}

// errPrivateHasDependencies is NAT.1202 (DeletePrivateNat, DeleteTransitSubnet).
func errPrivateHasDependencies(id string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1202", "There are one or more rules still in use on the gateway %s, can not be deleted.", id)
}

// errSamePrivateSpec is NAT.1206 (UpdatePrivateNat).
func errSamePrivateSpec(spec string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1206", "Update (%s) spec to (%s) are the same as the original.", spec, spec)
}

// errPrivateRuleLimit is NAT.1207 (UpdatePrivateNat, CreatePrivateSnat, CreatePrivateDnat).
func errPrivateRuleLimit(limit int) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1207", "Add this gateway rule over rule max %d.", limit)
}

// errTransitIPInGatewayVPC is NAT.1303 (CreatePrivateSnat, UpdatePrivateSnat, CreatePrivateDnat, UpdatePrivateDnat).
func errTransitIPInGatewayVPC(transitIPID string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1303", "Transit ip %s is in this vpc, not support to specified.", transitIPID)
}

// errPrivatePortNotInVPC is NAT.1304 (CreatePrivateDnat, UpdatePrivateDnat).
func errPrivatePortNotInVPC(portID string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1304", "Port %s is not in this vpc, not support to specified.", portID)
}

// errTransitIPUsedByDnat is NAT.1305 (CreatePrivateSnat, UpdatePrivateSnat).
func errTransitIPUsedByDnat(transitIPID string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1305", "Transit ip %s is used by exist dnat rule.", transitIPID)
}

// errPrivateDnatAnyPortMismatch is NAT.1306 (CreatePrivateDnat, UpdatePrivateDnat).
func errPrivateDnatAnyPortMismatch() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1306", "dnat Parameters entered are illegal, protocol:any should be entered with internal_service_port:0 and transit_service_port:0 together.")
}

// errPrivateDnatInternalConflict is NAT.1307 (CreatePrivateDnat, UpdatePrivateDnat).
func errPrivateDnatInternalConflict() *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1307", "Internal parameters entered conflict with exist dnat rules.")
}

// errTransitIPUsedBySnat is NAT.1308 (CreatePrivateDnat, UpdatePrivateDnat).
func errTransitIPUsedBySnat(transitIPID string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1308", "Transit ip %s is used by exist snat rule.", transitIPID)
}

// errPrivateDnatPortAllPortConflict is NAT.1309 (CreatePrivateDnat, UpdatePrivateDnat).
func errPrivateDnatPortAllPortConflict(portID string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1309", "Port %s is used by exist dnat rule.", portID)
}

// errPrivateDnatTransitConflict is NAT.1310 (CreatePrivateDnat, UpdatePrivateDnat).
func errPrivateDnatTransitConflict() *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1310", "Transit parameters entered conflict with exist dnat rules.")
}

// errPrivateDnatTargetInvalid is NAT.1311 (CreatePrivateDnat, UpdatePrivateDnat).
func errPrivateDnatTargetInvalid() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1311", "The networkInterfaceId(port_id) and private_ip_address(fixed_ip_address) exist at the same time or both are empty, but at least one value is empty.")
}

// errIPInUse is NAT.1403 (CreatePrivateNat, CreateTransitIp).
func errIPInUse(subnetID, ip string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1403", "Unable to complete operation for subnet %s. The IP address %s is in use.", subnetID, ip)
}

// errSubnetFull is NAT.1404 (CreateNatGateway, CreatePrivateNat, CreateTransitIp).
func errSubnetFull(subnetID string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1404", "No more IP addresses available on subnet %s.", subnetID)
}

// errInvalidIP is NAT.1405 (CreatePrivateNat, CreateTransitIp, CreatePrivateDnat, UpdatePrivateDnat).
func errInvalidIP(ip string) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1405", "IP address %s is not a valid IP for the subnet.", ip)
}

// errTransitIPUsedByOtherGateway is NAT.1406 (CreatePrivateSnat, UpdatePrivateSnat, CreatePrivateDnat, UpdatePrivateDnat).
func errTransitIPUsedByOtherGateway(transitIPID, gatewayID string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1406", "Transit ip %s has used by private nat gateway %s.", transitIPID, gatewayID)
}

// errTransitIPUsedByRules is NAT.1409 (DeleteTransitIp).
func errTransitIPUsedByRules(transitIPID string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1409", "Transit ip %s is used by rules.", transitIPID)
}

// errTransitIPDnatAllPortConflict is NAT.1410 (CreatePrivateDnat, UpdatePrivateDnat).
func errTransitIPDnatAllPortConflict(transitIPID string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1410", "Transit ip %s is used by dnat rules of other protocols.", transitIPID)
}

// errPrivateSnatSubnetOrCIDR is NAT.1501 (CreatePrivateSnat).
func errPrivateSnatSubnetOrCIDR() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1501", "Either virSubnet(network) or cidr must be specified. Both can not be specified at the same time.")
}

// errPrivateSnatInvalidCIDR is NAT.1502 (CreatePrivateSnat).
func errPrivateSnatInvalidCIDR() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1502", "Cidr is invalid, make sure it's format is correct.")
}

// errPrivateSnatNetworkExists is NAT.1503 (CreatePrivateSnat).
func errPrivateSnatNetworkExists(subnetID string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1503", "Snat rule for network %s exists.", subnetID)
}

// errPrivateSnatCIDRExists is NAT.1505 (CreatePrivateSnat).
func errPrivateSnatCIDRExists(cidr string) *apierr.Error {
	return apierr.New(http.StatusConflict, "NAT.1505", "Snat rule for cidr %s exists.", cidr)
}

// errPrivateSnatTransitIPLimit is NAT.1506 (CreatePrivateSnat, UpdatePrivateSnat).
func errPrivateSnatTransitIPLimit(limit int) *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1506", "%d transit ip has been associated to this SNAT rules's transit ip pool, no more is allowed.", limit)
}

// errPrivateSnatInvalidTransitIPID is NAT.1507 (CreatePrivateSnat, UpdatePrivateSnat).
func errPrivateSnatInvalidTransitIPID() *apierr.Error {
	return apierr.New(http.StatusBadRequest, "NAT.1507", "'transit_ip_id' attribute value should be 'uuid' type!")
}
