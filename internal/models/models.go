package models

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AppConfig is the top-level structure persisted to YAML.
type AppConfig struct {
	Server   ServerConfig   `yaml:"server"`
	Peers    []Peer         `yaml:"peers"`
	BGPPeers []BGPPeer      `yaml:"bgpPeers,omitempty"`
	ZeroTier ZeroTierConfig `yaml:"zerotier,omitempty"`
}

// Clone returns an independent copy suitable for rollback and reconciliation.
func (c AppConfig) Clone() AppConfig {
	clone := c
	clone.Peers = append([]Peer(nil), c.Peers...)
	for i := range clone.Peers {
		clone.Peers[i].ExitNodeRoutes = append([]string(nil), c.Peers[i].ExitNodeRoutes...)
		clone.Peers[i].AdvertisedRoutes = append([]string(nil), c.Peers[i].AdvertisedRoutes...)
		clone.Peers[i].PolicyRoutes = append([]string(nil), c.Peers[i].PolicyRoutes...)
		clone.Peers[i].BGPRouteFilters = append([]RouteFilter(nil), c.Peers[i].BGPRouteFilters...)
		clone.Peers[i].BGPExportFilters = append([]RouteFilter(nil), c.Peers[i].BGPExportFilters...)
	}
	clone.BGPPeers = append([]BGPPeer(nil), c.BGPPeers...)
	for i := range clone.BGPPeers {
		clone.BGPPeers[i].RouteFilters = append([]RouteFilter(nil), c.BGPPeers[i].RouteFilters...)
		clone.BGPPeers[i].ExportFilters = append([]RouteFilter(nil), c.BGPPeers[i].ExportFilters...)
	}
	clone.ZeroTier.Networks = append([]ZeroTierNetwork(nil), c.ZeroTier.Networks...)
	return clone
}

// ZeroTierConfig is the desired state of the local ZeroTier client.
type ZeroTierConfig struct {
	Enabled                               bool              `yaml:"enabled,omitempty"`
	Port                                  uint16            `yaml:"port,omitempty"` // primary port, 0 means the default 9993
	DisableMasquerade                     bool              `yaml:"disableMasquerade,omitempty"`
	ExcludeAdvertisedRoutesFromMasquerade bool              `yaml:"excludeAdvertisedRoutesFromMasquerade,omitempty"`
	Networks                              []ZeroTierNetwork `yaml:"networks,omitempty"`
}

// ZeroTierNetwork is a network the client should be joined to.
type ZeroTierNetwork struct {
	ID           string `yaml:"id"`             // 16 hex characters
	Name         string `yaml:"name,omitempty"` // local label, not the network's own name
	AllowManaged bool   `yaml:"allowManaged"`
	AllowGlobal  bool   `yaml:"allowGlobal,omitempty"`
	AllowDefault bool   `yaml:"allowDefault,omitempty"`
	AllowDNS     bool   `yaml:"allowDNS,omitempty"`
}

// ZeroTierPort returns the configured primary port, or the ZeroTier default.
func (z *ZeroTierConfig) ZeroTierPort() uint16 {
	if z.Port == 0 {
		return 9993
	}
	return z.Port
}

// FindZeroTierNetwork returns a pointer to the network with the given ID, or nil.
func FindZeroTierNetwork(networks []ZeroTierNetwork, id string) *ZeroTierNetwork {
	for i := range networks {
		if strings.EqualFold(networks[i].ID, id) {
			return &networks[i]
		}
	}
	return nil
}

// ServerConfig represents the [Interface] section of wg0.conf.
type ServerConfig struct {
	PrivateKey string `yaml:"privateKey"`
	ListenPort uint16 `yaml:"listenPort"`
	Address    string `yaml:"address"`
	Endpoint   string `yaml:"endpoint,omitempty"`
	DNS        string `yaml:"dns,omitempty"`
	MTU        uint16 `yaml:"mtu,omitempty"`
	Table      string `yaml:"table,omitempty"`
	FwMark     string `yaml:"fwMark,omitempty"`
	PreUp      string `yaml:"preUp,omitempty"`
	PostUp     string `yaml:"postUp,omitempty"`
	PreDown    string `yaml:"preDown,omitempty"`
	PostDown   string `yaml:"postDown,omitempty"`
	SaveConfig bool   `yaml:"saveConfig,omitempty"`

	// BGP
	BGPEnabled       bool   `yaml:"bgpEnabled,omitempty"`
	BGPListenAddress string `yaml:"bgpListenAddress,omitempty"`
	BGPListenPort    uint16 `yaml:"bgpListenPort,omitempty"`
	BGPASN           uint32 `yaml:"bgpAsn,omitempty"`
}

// RouteFilter represents a single routing policy filter for BGP.
type RouteFilter struct {
	Prefix  string `yaml:"prefix"`
	Matcher string `yaml:"matcher"` // exact, orlonger
	Action  string `yaml:"action"`  // accept, reject
}

// BGPPeer is a standalone BGP session that is not tied to a WireGuard peer —
// e.g. a route reflector or router reachable directly (not over a tunnel).
type BGPPeer struct {
	ID                    string `yaml:"id"`
	Name                  string `yaml:"name"`
	Enabled               bool   `yaml:"enabled"`
	Connect               bool   `yaml:"connect,omitempty"`
	RedistributeConnected bool   `yaml:"redistributeConnected,omitempty"`
	PeerIP                string `yaml:"peerIP"`
	PeerPort              uint16 `yaml:"peerPort,omitempty"`
	PeerASN               uint32 `yaml:"peerAsn"`
	// RouteFilters governs which prefixes received from this peer are accepted.
	RouteFilters []RouteFilter `yaml:"routeFilters,omitempty"`
	// ExportFilters governs which locally known prefixes are advertised to this peer.
	ExportFilters []RouteFilter `yaml:"exportFilters,omitempty"`
	CreatedAt     time.Time     `yaml:"createdAt"`
	UpdatedAt     time.Time     `yaml:"updatedAt"`
}

// Validate checks all fields on BGPPeer and returns all errors found.
func (p *BGPPeer) Validate() ValidationErrors {
	var errs ValidationErrors

	if strings.TrimSpace(p.Name) == "" {
		errs = append(errs, ValidationError{Field: "name", Message: "required"})
	} else if len(p.Name) > 64 {
		errs = append(errs, ValidationError{Field: "name", Message: "maximum 64 characters"})
	} else if !nameRegexp.MatchString(p.Name) {
		errs = append(errs, ValidationError{Field: "name", Message: "only letters, numbers, spaces, dashes, dots, underscores"})
	}

	if p.PeerIP == "" {
		errs = append(errs, ValidationError{Field: "bgpPeerIP", Message: "required"})
	} else if net.ParseIP(p.PeerIP) == nil {
		errs = append(errs, ValidationError{Field: "bgpPeerIP", Message: "must be a valid IP address"})
	}

	if p.PeerPort == 0 {
		errs = append(errs, ValidationError{Field: "bgpPeerPort", Message: "must be > 0"})
	} else if p.PeerPort != 179 {
		errs = append(errs, ValidationError{Field: "bgpPeerPort", Message: "the embedded BGP engine currently supports peer port 179 only"})
	}

	if p.PeerASN == 0 {
		errs = append(errs, ValidationError{Field: "bgpPeerAsn", Message: "required"})
	}

	errs = append(errs, validateRouteFilters(p.RouteFilters, "routeFilters")...)
	errs = append(errs, validateRouteFilters(p.ExportFilters, "exportFilters")...)

	return errs
}

// validateRouteFilters checks a list of BGP route filter terms, shared by the
// import (received) and export (advertised) filter lists on both Peer and
// BGPPeer. fieldPrefix names the field in validation errors, e.g. "bgpRouteFilters".
func validateRouteFilters(filters []RouteFilter, fieldPrefix string) ValidationErrors {
	var errs ValidationErrors
	for i, filter := range filters {
		if filter.Prefix == "" {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("%s[%d].prefix", fieldPrefix, i), Message: "required"})
		} else if _, _, err := net.ParseCIDR(filter.Prefix); err != nil {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("%s[%d].prefix", fieldPrefix, i), Message: "invalid CIDR"})
		}

		if filter.Matcher != "exact" && filter.Matcher != "orlonger" {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("%s[%d].matcher", fieldPrefix, i), Message: "must be 'exact' or 'orlonger'"})
		}

		if filter.Action != "accept" && filter.Action != "reject" {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("%s[%d].action", fieldPrefix, i), Message: "must be 'accept' or 'reject'"})
		}
	}
	return errs
}

// Peer represents a WireGuard peer (client).
type Peer struct {
	ID                   string   `yaml:"id"`
	Name                 string   `yaml:"name"`
	PrivateKey           string   `yaml:"privateKey"`
	PublicKey            string   `yaml:"publicKey"`
	PresharedKey         string   `yaml:"presharedKey,omitempty"`
	AllowedIPs           string   `yaml:"allowedIPs"`
	Endpoint             string   `yaml:"endpoint,omitempty"`
	PersistentKeepalive  uint16   `yaml:"persistentKeepalive,omitempty"`
	DNS                  string   `yaml:"dns,omitempty"`
	ClientAllowedIPs     string   `yaml:"clientAllowedIPs,omitempty"`
	IsExitNode           bool     `yaml:"isExitNode,omitempty"`
	ExitNodeID           string   `yaml:"exitNodeID,omitempty"`
	ExitNodeAllowAll     bool     `yaml:"exitNodeAllowAll,omitempty"`
	ExitNodeRoutes       []string `yaml:"exitNodeRoutes,omitempty"`
	AdvertisedRoutes     []string `yaml:"advertisedRoutes,omitempty"`
	PolicyRoutes         []string `yaml:"policyRoutes,omitempty"`
	StrictPolicyRouting  bool     `yaml:"strictPolicyRouting,omitempty"`
	RoutingTableID       uint     `yaml:"routingTableID,omitempty"`
	PolicyRoutingTableID uint     `yaml:"policyRoutingTableID,omitempty"`
	Enabled              bool     `yaml:"enabled"`

	// BGP
	BGPEnabled bool `yaml:"bgpEnabled,omitempty"`
	BGPConnect bool `yaml:"bgpConnect,omitempty"`
	// BGPRedistributeConnected advertises this host's local and connected routes.
	BGPRedistributeConnected bool   `yaml:"bgpRedistributeConnected,omitempty"`
	BGPPeerIP                string `yaml:"bgpPeerIP,omitempty"`
	BGPPeerPort              uint16 `yaml:"bgpPeerPort,omitempty"`
	BGPPeerASN               uint32 `yaml:"bgpPeerAsn,omitempty"`
	// BGPRouteFilters governs which prefixes received from this peer are accepted.
	BGPRouteFilters []RouteFilter `yaml:"bgpRouteFilters,omitempty"`
	// BGPExportFilters governs which locally known prefixes are advertised to this peer.
	BGPExportFilters []RouteFilter `yaml:"bgpExportFilters,omitempty"`

	CreatedAt time.Time `yaml:"createdAt"`
	UpdatedAt time.Time `yaml:"updatedAt"`
	LastSeen  time.Time `yaml:"lastSeen,omitempty"`
}

// BGPRoute represents a single prefix in the BGP AdjRIBIn or AdjRIBOut.
type BGPRoute struct {
	Prefix    string `json:"prefix"`
	NextHop   string `json:"nextHop"`
	LocalPref uint32 `json:"localPref"`
	ASPath    string `json:"asPath"`
	Status    string `json:"status"` // "Accepted", "Filtered", or "Advertised"
}

// BGPPeerStats holds statistics, received and advertised prefixes for a single BGP peer.
type BGPPeerStats struct {
	IP               string     `json:"ip"`
	ASN              uint32     `json:"asn"`
	State            string     `json:"state"`
	Uptime           string     `json:"uptime"`
	UpdatesReceived  uint64     `json:"updatesReceived"`
	Routes           []BGPRoute `json:"routes"`
	AdvertisedRoutes []BGPRoute `json:"advertisedRoutes"`
}

// BGPStats aggregates all BGP statistics for the daemon.
type BGPStats struct {
	RouterID string         `json:"routerId"`
	ASN      uint32         `json:"asn"`
	Running  bool           `json:"running"`
	Peers    []BGPPeerStats `json:"peers"`
}

// WGDevice is the WireGuard interface wg-busy manages.
const WGDevice = "wg0"

// GatewayNet is an on-link network a policy route gateway can live in, together
// with the interface it is reachable through (wg0, or a ZeroTier zt* device).
type GatewayNet struct {
	Device string
	CIDR   string
}

// GatewayNets returns every network a policy route gateway may point into: the
// WireGuard subnet, plus the ZeroTier subnets the node has joined. Entries that
// are not valid CIDRs are dropped — they can never match a gateway, and keeping
// them would turn an unconfigured server address into "no gateway is valid".
func GatewayNets(serverAddr string, ztNets []GatewayNet) []GatewayNet {
	var nets []GatewayNet
	add := func(device, cidr string) {
		if cidr = strings.TrimSpace(cidr); cidr != "" {
			if _, _, err := net.ParseCIDR(cidr); err == nil {
				nets = append(nets, GatewayNet{Device: device, CIDR: cidr})
			}
		}
	}
	for _, part := range strings.Split(serverAddr, ",") {
		add(WGDevice, part)
	}
	for _, n := range ztNets {
		add(n.Device, n.CIDR)
	}
	return nets
}

// DeviceForGateway returns the interface the gateway IP is directly reachable
// on, or "" if it is not on-link for any known network.
func DeviceForGateway(gateway string, nets []GatewayNet) string {
	ip := net.ParseIP(strings.TrimSpace(gateway))
	if ip == nil {
		return ""
	}
	for _, n := range nets {
		if _, cidr, err := net.ParseCIDR(strings.TrimSpace(n.CIDR)); err == nil && cidr.Contains(ip) {
			return n.Device
		}
	}
	return ""
}

// ValidationError represents a single field validation error.
type ValidationError struct {
	Field   string
	Message string
}

// ValidationErrors collects multiple validation errors.
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	msgs := make([]string, len(ve))
	for i, e := range ve {
		msgs[i] = fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return strings.Join(msgs, "; ")
}

// HasField returns true if there is an error for the given field.
func (ve ValidationErrors) HasField(field string) bool {
	for _, e := range ve {
		if e.Field == field {
			return true
		}
	}
	return false
}

// Validate checks all fields on ServerConfig and returns all errors found.
func (s *ServerConfig) Validate() ValidationErrors {
	var errs ValidationErrors

	if s.PrivateKey == "" {
		errs = append(errs, ValidationError{Field: "privateKey", Message: "required"})
	} else if !isValidBase64Key(s.PrivateKey) {
		errs = append(errs, ValidationError{Field: "privateKey", Message: "must be a 44-character base64 key"})
	}

	if s.ListenPort == 0 {
		errs = append(errs, ValidationError{Field: "listenPort", Message: "required and must be > 0"})
	}

	if s.Address == "" {
		errs = append(errs, ValidationError{Field: "address", Message: "required"})
	} else if !isValidCIDRList(s.Address) {
		errs = append(errs, ValidationError{Field: "address", Message: "must be valid CIDR (e.g. 10.0.0.1/24)"})
	}

	if s.Endpoint != "" && !isValidEndpoint(s.Endpoint) {
		errs = append(errs, ValidationError{Field: "endpoint", Message: "must be host:port"})
	}

	if s.DNS != "" && !isValidDNSList(s.DNS) {
		errs = append(errs, ValidationError{Field: "dns", Message: "must be comma-separated IPs or hostnames"})
	}

	if s.MTU != 0 && s.MTU < 1280 {
		errs = append(errs, ValidationError{Field: "mtu", Message: "must be 1280-65535"})
	}

	if s.Table != "" && !isValidTable(s.Table) {
		errs = append(errs, ValidationError{Field: "table", Message: "must be 'off', 'auto', or a numeric value"})
	}

	if s.FwMark != "" && !isValidFwMark(s.FwMark) {
		errs = append(errs, ValidationError{Field: "fwMark", Message: "must be a number, hex (0x...), or 'off'"})
	}

	if len(s.PreUp) > 4096 {
		errs = append(errs, ValidationError{Field: "preUp", Message: "maximum 4096 characters"})
	}
	if len(s.PostUp) > 4096 {
		errs = append(errs, ValidationError{Field: "postUp", Message: "maximum 4096 characters"})
	}
	if len(s.PreDown) > 4096 {
		errs = append(errs, ValidationError{Field: "preDown", Message: "maximum 4096 characters"})
	}
	if len(s.PostDown) > 4096 {
		errs = append(errs, ValidationError{Field: "postDown", Message: "maximum 4096 characters"})
	}

	if s.BGPEnabled {
		if s.BGPListenAddress != "" && net.ParseIP(s.BGPListenAddress) == nil {
			errs = append(errs, ValidationError{Field: "bgpListenAddress", Message: "must be a valid IP address"})
		}
		if s.BGPListenPort == 0 {
			errs = append(errs, ValidationError{Field: "bgpListenPort", Message: "must be > 0"})
		}
		if s.BGPASN == 0 {
			errs = append(errs, ValidationError{Field: "bgpAsn", Message: "required when BGP is enabled"})
		}
	}

	return errs
}

var networkIDRegexp = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

// Validate checks the ZeroTier configuration and returns all errors found.
func (z *ZeroTierConfig) Validate() ValidationErrors {
	var errs ValidationErrors

	if z.Port != 0 && z.Port < 1024 {
		errs = append(errs, ValidationError{Field: "ztPort", Message: "must be 1024-65535, or empty for the default (9993)"})
	}

	seen := make(map[string]bool, len(z.Networks))
	for i, n := range z.Networks {
		id := strings.ToLower(strings.TrimSpace(n.ID))
		field := fmt.Sprintf("ztNetworks[%d].id", i)

		switch {
		case id == "":
			errs = append(errs, ValidationError{Field: field, Message: "required"})
		case !networkIDRegexp.MatchString(id):
			errs = append(errs, ValidationError{Field: field, Message: fmt.Sprintf("must be 16 hexadecimal characters: %s", n.ID)})
		case seen[id]:
			errs = append(errs, ValidationError{Field: field, Message: fmt.Sprintf("duplicate network: %s", n.ID)})
		default:
			seen[id] = true
		}

		if len(n.Name) > 64 {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("ztNetworks[%d].name", i), Message: "maximum 64 characters"})
		}
	}

	return errs
}

var nameRegexp = regexp.MustCompile(`^[a-zA-Z0-9 _.\-]+$`)

// Validate checks all fields on Peer and returns all errors found.
// gateways are the on-link networks a policy route gateway may point into —
// build them with GatewayNets. Pass nil to skip the gateway reachability check.
func (p *Peer) Validate(gateways []GatewayNet) ValidationErrors {
	var errs ValidationErrors

	if strings.TrimSpace(p.Name) == "" {
		errs = append(errs, ValidationError{Field: "name", Message: "required"})
	} else if len(p.Name) > 64 {
		errs = append(errs, ValidationError{Field: "name", Message: "maximum 64 characters"})
	} else if !nameRegexp.MatchString(p.Name) {
		errs = append(errs, ValidationError{Field: "name", Message: "only letters, numbers, spaces, dashes, dots, underscores"})
	}

	if p.PrivateKey == "" {
		errs = append(errs, ValidationError{Field: "privateKey", Message: "required"})
	} else if !isValidBase64Key(p.PrivateKey) {
		errs = append(errs, ValidationError{Field: "privateKey", Message: "must be a 44-character base64 key"})
	}

	if p.PublicKey == "" {
		errs = append(errs, ValidationError{Field: "publicKey", Message: "required"})
	} else if !isValidBase64Key(p.PublicKey) {
		errs = append(errs, ValidationError{Field: "publicKey", Message: "must be a 44-character base64 key"})
	}

	if p.PresharedKey != "" && !isValidBase64Key(p.PresharedKey) {
		errs = append(errs, ValidationError{Field: "presharedKey", Message: "must be a 44-character base64 key"})
	}

	if p.AllowedIPs == "" {
		errs = append(errs, ValidationError{Field: "allowedIPs", Message: "required"})
	} else if !isValidCIDRList(p.AllowedIPs) {
		errs = append(errs, ValidationError{Field: "allowedIPs", Message: "must be comma-separated CIDRs"})
	}

	if p.Endpoint != "" && !isValidEndpoint(p.Endpoint) {
		errs = append(errs, ValidationError{Field: "endpoint", Message: "must be host:port"})
	}

	if p.ClientAllowedIPs != "" && !isValidCIDRList(p.ClientAllowedIPs) {
		errs = append(errs, ValidationError{Field: "clientAllowedIPs", Message: "must be comma-separated CIDRs"})
	}

	if p.DNS != "" && !isValidDNSList(p.DNS) {
		errs = append(errs, ValidationError{Field: "dns", Message: "must be comma-separated IPs or hostnames"})
	}

	if p.IsExitNode && p.ExitNodeID != "" {
		errs = append(errs, ValidationError{Field: "exitNodeID", Message: "a peer cannot be both an exit node and use an exit node"})
	}

	if p.IsExitNode && !p.ExitNodeAllowAll && len(p.ExitNodeRoutes) > 0 {
		for _, route := range p.ExitNodeRoutes {
			if _, _, err := net.ParseCIDR(route); err != nil {
				errs = append(errs, ValidationError{Field: "exitNodeRoutes", Message: fmt.Sprintf("invalid CIDR: %s", route)})
			}
		}
	}

	if len(p.AdvertisedRoutes) > 0 {
		for _, route := range p.AdvertisedRoutes {
			if _, _, err := net.ParseCIDR(route); err != nil {
				errs = append(errs, ValidationError{Field: "advertisedRoutes", Message: fmt.Sprintf("invalid CIDR: %s", route)})
			}
		}
	}

	if len(p.PolicyRoutes) > 0 {
		// Policy routes are installed as "ip route add <cidr> via <gw> dev <iface>",
		// so the gateway must be on-link for one of the interfaces we manage —
		// the WireGuard subnet, or a ZeroTier network the node has joined.
		for _, pr := range p.PolicyRoutes {
			parts := strings.Split(pr, " via ")
			if len(parts) != 2 {
				errs = append(errs, ValidationError{Field: "policyRoutes", Message: fmt.Sprintf("invalid format (must be 'CIDR via IP'): %s", pr)})
				continue
			}
			if _, _, err := net.ParseCIDR(strings.TrimSpace(parts[0])); err != nil {
				errs = append(errs, ValidationError{Field: "policyRoutes", Message: fmt.Sprintf("invalid CIDR: %s", parts[0])})
			}
			gw := net.ParseIP(strings.TrimSpace(parts[1]))
			if gw == nil {
				errs = append(errs, ValidationError{Field: "policyRoutes", Message: fmt.Sprintf("invalid Gateway IP: %s", parts[1])})
			} else if len(gateways) > 0 && DeviceForGateway(gw.String(), gateways) == "" {
				errs = append(errs, ValidationError{
					Field:   "policyRoutes",
					Message: fmt.Sprintf("gateway %s is not directly reachable: it must be inside %s", gw, describeGateways(gateways)),
				})
			}
		}
	}

	// Strict mode installs a reject rule after the peer's own table lookups.
	// Without a table to consult first it would drop everything, so require one
	// rather than letting the peer silently lose all connectivity.
	if p.StrictPolicyRouting && len(p.PolicyRoutes) == 0 && p.ExitNodeID == "" {
		errs = append(errs, ValidationError{
			Field:   "strictPolicyRouting",
			Message: "requires at least one policy route (or an exit node); otherwise all traffic from this peer would be blocked",
		})
	}

	if p.BGPEnabled {
		if p.BGPPeerIP == "" {
			errs = append(errs, ValidationError{Field: "bgpPeerIP", Message: "required when BGP is enabled"})
		} else if net.ParseIP(p.BGPPeerIP) == nil {
			errs = append(errs, ValidationError{Field: "bgpPeerIP", Message: "must be a valid IP address"})
		}
		if p.BGPPeerPort == 0 {
			errs = append(errs, ValidationError{Field: "bgpPeerPort", Message: "must be > 0"})
		}
		if p.BGPPeerASN == 0 {
			errs = append(errs, ValidationError{Field: "bgpPeerAsn", Message: "required when BGP is enabled"})
		}

		errs = append(errs, validateRouteFilters(p.BGPRouteFilters, "bgpRouteFilters")...)
		errs = append(errs, validateRouteFilters(p.BGPExportFilters, "bgpExportFilters")...)
	}

	return errs
}

// ValidateExitNodeRefs validates relationships that require the complete peer set.
func ValidateExitNodeRefs(peers []Peer) ValidationErrors {
	exitNodes := make(map[string]bool, len(peers))
	for _, p := range peers {
		if p.Enabled && p.IsExitNode {
			exitNodes[p.ID] = true
		}
	}

	var errs ValidationErrors
	for _, p := range peers {
		if p.ExitNodeID != "" && !exitNodes[p.ExitNodeID] {
			errs = append(errs, ValidationError{
				Field:   "exitNodeID",
				Message: fmt.Sprintf("references missing, disabled, or non-exit peer %q", p.ExitNodeID),
			})
		}
	}
	return errs
}

// ValidateConfig checks invariants that individual forms cannot enforce because
// they depend on the complete configuration. Dynamic gateway reachability is
// intentionally checked by the peer form; here Peer.Validate(nil) still checks
// every persisted field without rejecting a temporarily unavailable ZeroTier
// gateway during an unrelated save.
func ValidateConfig(cfg AppConfig) ValidationErrors {
	var errs ValidationErrors
	errs = append(errs, cfg.Server.Validate()...)
	errs = append(errs, cfg.ZeroTier.Validate()...)
	for i := range cfg.Peers {
		errs = append(errs, cfg.Peers[i].Validate(nil)...)
	}
	errs = append(errs, ValidateExitNodeRefs(cfg.Peers)...)
	for i := range cfg.BGPPeers {
		errs = append(errs, cfg.BGPPeers[i].Validate()...)
	}

	peerIDs := make(map[string]string, len(cfg.Peers))
	publicKeys := make(map[string]string, len(cfg.Peers))
	allowedPrefixes := make(map[string]string)
	bgpPeers := make(map[string]string)
	routingTables := make(map[uint]string)
	for _, p := range cfg.Peers {
		if previous, ok := peerIDs[p.ID]; ok {
			errs = append(errs, ValidationError{Field: "id", Message: fmt.Sprintf("peer %q duplicates ID used by %q", p.Name, previous)})
		} else {
			peerIDs[p.ID] = p.Name
		}
		if previous, ok := publicKeys[p.PublicKey]; ok {
			errs = append(errs, ValidationError{Field: "publicKey", Message: fmt.Sprintf("peer %q duplicates key used by %q", p.Name, previous)})
		} else {
			publicKeys[p.PublicKey] = p.Name
		}
		if p.IsExitNode && p.RoutingTableID == 0 {
			errs = append(errs, ValidationError{Field: "routingTableID", Message: fmt.Sprintf("exit-node peer %q has no routing table", p.Name)})
		}
		if len(p.PolicyRoutes) > 0 && p.PolicyRoutingTableID == 0 {
			errs = append(errs, ValidationError{Field: "policyRoutingTableID", Message: fmt.Sprintf("peer %q has policy routes but no routing table", p.Name)})
		}
		for _, table := range []struct {
			id    uint
			field string
			role  string
		}{
			{p.RoutingTableID, "routingTableID", "exit-node table"},
			{p.PolicyRoutingTableID, "policyRoutingTableID", "policy table"},
		} {
			if table.id == 0 {
				continue
			}
			owner := fmt.Sprintf("peer %q %s", p.Name, table.role)
			if previous, ok := routingTables[table.id]; ok {
				errs = append(errs, ValidationError{Field: table.field, Message: fmt.Sprintf("%s reuses table %d assigned to %s", owner, table.id, previous)})
			} else {
				routingTables[table.id] = owner
			}
		}
		if !p.Enabled {
			continue
		}

		for _, prefix := range effectiveAllowedPrefixes(p) {
			if previous, ok := allowedPrefixes[prefix]; ok {
				errs = append(errs, ValidationError{
					Field:   "allowedIPs",
					Message: fmt.Sprintf("peer %q and %q both claim %s", previous, p.Name, prefix),
				})
			} else {
				allowedPrefixes[prefix] = p.Name
			}
		}

		if p.BGPEnabled {
			if p.BGPPeerPort != 179 {
				errs = append(errs, ValidationError{Field: "bgpPeerPort", Message: "the embedded BGP engine currently supports peer port 179 only"})
			}
			if ip := net.ParseIP(strings.TrimSpace(p.BGPPeerIP)); ip != nil {
				key := ip.String()
				if previous, ok := bgpPeers[key]; ok {
					errs = append(errs, ValidationError{Field: "bgpPeerIP", Message: fmt.Sprintf("peer %q duplicates BGP address used by %q", p.Name, previous)})
				} else {
					bgpPeers[key] = p.Name
				}
			}
		}
	}

	bgpPeerIDs := make(map[string]string, len(cfg.BGPPeers))
	for _, p := range cfg.BGPPeers {
		if previous, ok := bgpPeerIDs[p.ID]; ok {
			errs = append(errs, ValidationError{Field: "id", Message: fmt.Sprintf("BGP peer %q duplicates ID used by %q", p.Name, previous)})
		} else {
			bgpPeerIDs[p.ID] = p.Name
		}
		if !p.Enabled {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(p.PeerIP)); ip != nil {
			key := ip.String()
			if previous, ok := bgpPeers[key]; ok {
				errs = append(errs, ValidationError{Field: "bgpPeerIP", Message: fmt.Sprintf("BGP peer %q duplicates address used by %q", p.Name, previous)})
			} else {
				bgpPeers[key] = p.Name
			}
		}
	}

	return errs
}

func effectiveAllowedPrefixes(p Peer) []string {
	var values []string
	if p.IsExitNode && p.ExitNodeAllowAll {
		values = []string{"0.0.0.0/0", "::/0"}
	} else {
		values = append(values, strings.Split(p.AllowedIPs, ",")...)
		if p.IsExitNode {
			values = append(values, p.ExitNodeRoutes...)
		}
		values = append(values, p.AdvertisedRoutes...)
	}

	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, network, err := net.ParseCIDR(strings.TrimSpace(value)); err == nil {
			result = append(result, network.String())
		}
	}
	return result
}

// CascadeClearExitNode removes all references to the given exit node peer ID.
func CascadeClearExitNode(peers []Peer, exitNodeID string) {
	for i := range peers {
		if peers[i].ExitNodeID == exitNodeID {
			peers[i].ExitNodeID = ""
		}
	}
}

// FindPeerByID returns a pointer to the peer with the given ID, or nil.
func FindPeerByID(peers []Peer, id string) *Peer {
	for i := range peers {
		if peers[i].ID == id {
			return &peers[i]
		}
	}
	return nil
}

// FindBGPPeerByID returns a pointer to the custom BGP peer with the given ID, or nil.
func FindBGPPeerByID(peers []BGPPeer, id string) *BGPPeer {
	for i := range peers {
		if peers[i].ID == id {
			return &peers[i]
		}
	}
	return nil
}

// ExitNodePeers returns all enabled peers marked as exit nodes.
func ExitNodePeers(peers []Peer) []Peer {
	var result []Peer
	for _, p := range peers {
		if p.IsExitNode && p.Enabled {
			result = append(result, p)
		}
	}
	return result
}

// --- Validation helpers ---

func isValidBase64Key(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 44 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func isValidCIDRList(s string) bool {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		_, _, err := net.ParseCIDR(part)
		if err != nil {
			return false
		}
	}
	return true
}

// describeGateways renders the usable gateway networks for an error message,
// e.g. "10.0.0.1/24 (wg0) or 10.147.17.36/24 (zt5u4va25t)".
func describeGateways(nets []GatewayNet) string {
	parts := make([]string, 0, len(nets))
	for _, n := range nets {
		parts = append(parts, fmt.Sprintf("%s (%s)", n.CIDR, n.Device))
	}
	switch len(parts) {
	case 0:
		return "a directly connected subnet"
	case 1:
		return parts[0]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1]
	}
}

var hostnameRegexp = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`)

func isValidDNSList(s string) bool {
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		if net.ParseIP(part) != nil {
			continue
		}
		if hostnameRegexp.MatchString(part) {
			continue
		}
		return false
	}
	return true
}

func isValidEndpoint(s string) bool {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}

func isValidTable(s string) bool {
	if s == "off" || s == "auto" {
		return true
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0
}

func isValidFwMark(s string) bool {
	if s == "off" {
		return true
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		_, err := strconv.ParseUint(s[2:], 16, 32)
		return err == nil
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// PeerIPs extracts every unique host IP (without masks) from a CIDR list.
func PeerIPs(cidrs string) []string {
	var result []string
	seen := make(map[string]bool)
	for _, cidr := range strings.Split(cidrs, ",") {
		ip, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		result = append(result, ip.String())
	}
	return result
}

// PeerSources returns every unique source selector represented by AllowedIPs.
// Host routes omit the redundant mask; wider prefixes retain it so strict
// routing covers every source address the WireGuard peer is authorized to use.
func PeerSources(cidrs string) []string {
	var result []string
	seen := make(map[string]bool)
	for _, cidr := range strings.Split(cidrs, ",") {
		ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		selector := network.String()
		if ones == bits {
			selector = ip.String()
		}
		if !seen[selector] {
			seen[selector] = true
			result = append(result, selector)
		}
	}
	return result
}

// FirstIP extracts the first IP (without mask) from a CIDR list.
func FirstIP(cidrs string) string {
	if ips := PeerIPs(cidrs); len(ips) > 0 {
		return ips[0]
	}
	return ""
}
