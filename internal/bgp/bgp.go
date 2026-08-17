package bgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/server"
	"github.com/bio-routing/bio-rd/protocols/kernel"
	"github.com/bio-routing/bio-rd/route"
	"github.com/bio-routing/bio-rd/routingtable/filter"
	"github.com/bio-routing/bio-rd/routingtable/filter/actions"
	"github.com/bio-routing/bio-rd/routingtable/vrf"
	biolog "github.com/bio-routing/bio-rd/util/log"

	"github.com/yix/wg-busy/internal/models"
)

var (
	mu                 sync.Mutex
	active             *bgpRuntime
	newKernel          = kernel.New
	newBGPServer       = server.NewBGPServer
	interfaceAddresses = systemInterfaceAddresses
	peerLocalAddress   = routeLocalAddress
	// ztAddressProvider reports the node's own addresses on joined ZeroTier
	// networks, so the BGP listener can also bind to them. Set via
	// SetZeroTierAddressProvider; nil until wired up (e.g. in tests).
	ztAddressProvider func() []models.GatewayNet
)

// SetZeroTierAddressProvider registers the callback used to look up the
// node's own ZeroTier interface addresses, so BGP can also listen on them
// when a specific (non-wildcard) BGP listen address is configured. Without
// this, a BGP peer reachable only over a ZeroTier network could never dial in.
func SetZeroTierAddressProvider(fn func() []models.GatewayNet) {
	mu.Lock()
	defer mu.Unlock()
	ztAddressProvider = fn
}

type bgpServerState struct {
	routerID      uint32
	asn           uint32
	listenAddress string
	listenPort    uint16
	// extraListen is a comma-joined, sorted list of additional host IPs to
	// listen on (currently: ZeroTier addresses). Kept as a string so
	// bgpServerState stays comparable with ==.
	extraListen string
}

type bgpRuntime struct {
	server      server.BGPServer
	vrfs        *vrf.VRFRegistry
	kernel      *kernel.Kernel
	listeners   *listenerManager
	state       bgpServerState
	localRoutes map[string]localRoute
	peerNames   map[string]string
}

type localRoute struct {
	prefix *bnet.Prefix
	path   *route.Path
}

// bgpKernelClient keeps locally originated paths in the BGP RIB without
// attempting to install routes that already exist on the host back into the
// kernel. Learned BGP paths continue to be installed as before.
type bgpKernelClient struct{ *kernel.Kernel }

func (c bgpKernelClient) AddPathInitialDump(prefix *bnet.Prefix, path *route.Path) error {
	return c.AddPath(prefix, path)
}

func (c bgpKernelClient) AddPath(prefix *bnet.Prefix, path *route.Path) error {
	if path.Type != route.BGPPathType {
		return nil
	}
	return c.Kernel.AddPath(prefix, path)
}

func (c bgpKernelClient) RemovePath(prefix *bnet.Prefix, path *route.Path) bool {
	if path.Type != route.BGPPathType {
		return true
	}
	return c.Kernel.RemovePath(prefix, path)
}

// routerIDFromAddress parses a WireGuard address CIDR (e.g. "10.0.0.1/24") and
// returns the host IP encoded as a uint32 suitable for use as a BGP Router ID.
func routerIDFromAddress(cidr string) (uint32, error) {
	// Address may be comma-separated; take the first entry.
	cidr = strings.TrimSpace(strings.SplitN(cidr, ",", 2)[0])
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("parse wg address %q: %w", cidr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("BGP Router ID requires an IPv4 address, got %q", ip.String())
	}
	return binary.BigEndian.Uint32(ip4), nil
}

// Configure applies the given application configuration to the bio-rd BGP server instance.
// It starts, stops, or reconfigures the BGP environment and peers accordingly.
func Configure(cfg *models.AppConfig) error {
	mu.Lock()
	defer mu.Unlock()

	if !cfg.Server.BGPEnabled {
		if active != nil {
			log.Println("[BGP] BGP is disabled in config — stopping BGP server")
		}
		return stopLocked()
	}

	routerID, err := routerIDFromAddress(cfg.Server.Address)
	if err != nil {
		return fmt.Errorf("cannot derive BGP Router ID from WireGuard address: %w", err)
	}
	desiredState := stateFor(cfg.Server, routerID)
	if active == nil || active.state != desiredState {
		if active != nil {
			log.Println("[BGP] Server settings changed — restarting BGP runtime")
			if err := stopLocked(); err != nil {
				return err
			}
		}
		candidate, err := startRuntime(cfg, desiredState)
		if err != nil {
			return err
		}
		active = candidate
		invalidateStatsCacheLocked()
		return nil
	}

	if err := applyRuntimeConfig(active, cfg); err != nil {
		return err
	}
	invalidateStatsCacheLocked()
	return nil
}

func stateFor(cfg models.ServerConfig, routerID uint32) bgpServerState {
	address := strings.TrimSpace(cfg.BGPListenAddress)
	if address == "" {
		address = "::"
	}
	return bgpServerState{
		routerID:      routerID,
		asn:           cfg.BGPASN,
		listenAddress: address,
		listenPort:    cfg.BGPListenPort,
		extraListen:   strings.Join(extraListenHosts(address), ","),
	}
}

// extraListenHosts returns the additional host IPs the BGP listener should
// bind to besides the primary listen address — the node's own ZeroTier
// interface addresses, so a peer reachable only over ZeroTier can still
// dial in. Skipped when the primary address is already a wildcard, since
// that already covers every interface including ZeroTier's.
func extraListenHosts(primary string) []string {
	if primary == "::" || primary == "0.0.0.0" || ztAddressProvider == nil {
		return nil
	}

	seen := map[string]bool{primary: true}
	var hosts []string
	for _, n := range ztAddressProvider() {
		ip, _, err := net.ParseCIDR(strings.TrimSpace(n.CIDR))
		if err != nil {
			continue
		}
		host := ip.String()
		if seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func desiredPeers(cfg *models.AppConfig, defVRF *vrf.VRF, routerID uint32, localPrefixes []string) (map[bnet.IP]server.PeerConfig, error) {
	desired := make(map[bnet.IP]server.PeerConfig)

	for _, p := range cfg.BGPPeers {
		if !p.Enabled {
			continue
		}
		bPeerIP, peerCfg, err := buildPeerConfig(cfg, defVRF, routerID, p.Name, p.Connect, p.RedistributeConnected, p.MaxReceivedPrefixLength, p.MaxAdvertisedPrefixLength, p.PeerIP, p.PeerPort, p.PeerASN, p.RouteFilters, p.ExportFilters, localPrefixes)
		if err != nil {
			return nil, err
		}
		if _, exists := desired[bPeerIP]; exists {
			return nil, fmt.Errorf("multiple enabled BGP peers use address %s", bPeerIP.String())
		}
		desired[bPeerIP] = peerCfg
	}

	return desired, nil
}

// buildPeerConfig builds a bio-rd peer config for a single BGP session, shared
// by WireGuard-attached peers and standalone custom peers.
func buildPeerConfig(cfg *models.AppConfig, defVRF *vrf.VRF, routerID uint32, name string, connect, redistributeConnected bool, maxReceivedPrefixLength, maxAdvertisedPrefixLength uint16, peerIP string, peerPort uint16, peerASN uint32, routeFilters, exportFilters []models.RouteFilter, localPrefixes []string) (bnet.IP, server.PeerConfig, error) {
	bPeerIP, err := bnet.IPFromString(peerIP)
	if err != nil {
		return bnet.IP{}, server.PeerConfig{}, fmt.Errorf("peer %q has invalid BGP peer IP %q: %w", name, peerIP, err)
	}
	if peerPort != 179 {
		return bnet.IP{}, server.PeerConfig{}, fmt.Errorf("peer %q uses unsupported BGP peer port %d; only 179 is supported", name, peerPort)
	}
	if maxReceivedPrefixLength > 128 || maxAdvertisedPrefixLength > 128 {
		return bnet.IP{}, server.PeerConfig{}, fmt.Errorf("peer %q has a max prefix length greater than 128", name)
	}

	peerCfg := server.PeerConfig{
		AdminEnabled:               true,
		AuthenticationKey:          "",       // TODO: add support for preshared keys
		Passive:                    !connect, // by default wg-busy only responds; peers must initiate
		TTL:                        255,      // eBGP multihop over WireGuard tunnel
		ReconnectInterval:          15 * time.Second,
		KeepAlive:                  30 * time.Second,
		HoldTime:                   90 * time.Second,
		PeerAddress:                &bPeerIP,
		LocalAS:                    cfg.Server.BGPASN,
		PeerAS:                     peerASN,
		RouterID:                   routerID,
		VRF:                        defVRF,
		AdvertiseIPv4MultiProtocol: true, // Required to negotiate IPv4 AFI over IPv6 sessions
	}

	if redistributeConnected {
		localAddress, err := peerLocalAddress(peerIP)
		if err != nil {
			return bnet.IP{}, server.PeerConfig{}, fmt.Errorf("peer %q: determine local BGP session address: %w", name, err)
		}
		lA, err := bnet.IPFromString(localAddress)
		if err != nil {
			return bnet.IP{}, server.PeerConfig{}, fmt.Errorf("peer %q: invalid local BGP session address %q: %w", name, localAddress, err)
		}
		peerCfg.LocalAddress = lA.Dedup()
	} else if cfg.Server.BGPListenAddress != "" {
		if lA, err := bnet.IPFromString(cfg.Server.BGPListenAddress); err == nil {
			peerCfg.LocalAddress = &lA
		} else {
			log.Printf("[BGP WARN] Invalid BGP listen address %q: %v", cfg.Server.BGPListenAddress, err)
		}
	}
	if peerCfg.LocalAddress == nil {
		// bio-rd panics if LocalAddress is nil. Default to generic unspec IPv6 which covers all interfaces.
		unspec, _ := bnet.IPFromString("::")
		peerCfg.LocalAddress = &unspec
	}
	// bio-rd canonicalizes these pointers inside AddPeer and later compares
	// LocalAddress by pointer identity. Canonicalize the desired config too so
	// an unrelated save does not look like a peer-address change.
	peerCfg.LocalAddress = peerCfg.LocalAddress.Dedup()
	peerCfg.PeerAddress = peerCfg.PeerAddress.Dedup()

	importFilter := prependMaxPrefixLengthFilter(buildFilterChain("import", routeFilters), "received", maxReceivedPrefixLength)
	exportFilter := buildExportFilterChain(exportFilters, redistributeConnected, maxAdvertisedPrefixLength, localPrefixes, peerCfg.LocalAddress)

	afi := &server.AddressFamilyConfig{
		ImportFilterChain: importFilter,
		ExportFilterChain: exportFilter,
	}

	// Always enable both IPv4 and IPv6 unicast so peers can
	// advertise routes of either family over a single session.
	peerCfg.IPv4 = afi
	peerCfg.IPv6 = afi

	log.Printf("[BGP] Desired peer: name=%q ip=%s localAS=%d peerAS=%d filters=%d",
		name, bPeerIP.String(), cfg.Server.BGPASN, peerASN, len(routeFilters))

	return bPeerIP, peerCfg, nil
}

// routeLocalAddress asks the kernel which source address it would use to
// reach a peer. Connecting a UDP socket performs the route lookup without
// sending any traffic.
func routeLocalAddress(peerIP string) (string, error) {
	ip := net.ParseIP(peerIP)
	if ip == nil {
		return "", fmt.Errorf("invalid peer IP %q", peerIP)
	}
	network := "udp6"
	if ip.To4() != nil {
		network = "udp4"
	}
	conn, err := net.DialUDP(network, nil, &net.UDPAddr{IP: ip, Port: 179})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil || local.IP.IsUnspecified() {
		return "", fmt.Errorf("kernel returned no usable source address for %s", peerIP)
	}
	return local.IP.String(), nil
}

func reconcilePeers(runtime *bgpRuntime, cfg *models.AppConfig, localPrefixes []string) error {
	defVRF := runtime.vrfs.GetVRFByName(vrf.DefaultVRFName)
	desired, err := desiredPeers(cfg, defVRF, runtime.state.routerID, localPrefixes)
	if err != nil {
		return err
	}
	currentPeers := runtime.server.GetPeers()

	for _, cp := range currentPeers {
		if _, ok := desired[*cp.Addr()]; !ok {
			log.Printf("[BGP] Removing peer %s (no longer in config)", cp.Addr().String())
			runtime.server.DisposePeer(cp.VRF(), cp.Addr())
		}
	}

	var applyErrs []error
	for peerIP, peerCfg := range desired {
		peerCopy := peerIP
		oldCfg := runtime.server.GetPeerConfig(defVRF, &peerCopy)
		if oldCfg == nil {
			if err := runtime.server.AddPeer(peerCfg); err != nil {
				applyErrs = append(applyErrs, fmt.Errorf("add BGP peer %s: %w", peerCopy.String(), err))
			}
			continue
		}
		if peerNeedsReplacement(oldCfg, &peerCfg) {
			previous := *oldCfg
			runtime.server.DisposePeer(defVRF, &peerCopy)
			if err := runtime.server.AddPeer(peerCfg); err != nil {
				restoreErr := runtime.server.AddPeer(previous)
				replaceErr := fmt.Errorf("replace BGP peer %s: %w", peerCopy.String(), err)
				if restoreErr != nil {
					replaceErr = errors.Join(replaceErr, fmt.Errorf("restore BGP peer %s: %w", peerCopy.String(), restoreErr))
				}
				applyErrs = append(applyErrs, replaceErr)
			}
		}
	}
	return errors.Join(applyErrs...)
}

// peerNeedsReplacement compares the semantic peer configuration. Route-filter
// changes replace the peer because bio-rd's live replacement API updates only
// current FSMs, not the base configuration used by future passive sessions.
func peerNeedsReplacement(current, desired *server.PeerConfig) bool {
	if current.NeedsRestart(desired) {
		return true
	}
	return addressFamilyChanged(current.IPv4, desired.IPv4) || addressFamilyChanged(current.IPv6, desired.IPv6)
}

func addressFamilyChanged(current, desired *server.AddressFamilyConfig) bool {
	if current == nil || desired == nil {
		return current != desired
	}
	return !current.ImportFilterChain.Equal(desired.ImportFilterChain) ||
		!current.ExportFilterChain.Equal(desired.ExportFilterChain)
}

func startRuntime(cfg *models.AppConfig, state bgpServerState) (*bgpRuntime, error) {
	biolog.SetLogger(newStdLogger())
	registry := vrf.NewVRFRegistry()
	defVRF := registry.CreateVRFIfNotExists(vrf.DefaultVRFName, 0)
	log.Println("[BGP] Initialising kernel route integration")
	kernelRoutes, err := newKernel()
	if err != nil {
		return nil, fmt.Errorf("failed to init kernel routing: %w", err)
	}
	kernelClient := bgpKernelClient{Kernel: kernelRoutes}
	defVRF.IPv4UnicastRIB().Register(kernelClient)
	defVRF.IPv6UnicastRIB().Register(kernelClient)

	listenAddrs := []string{net.JoinHostPort(state.listenAddress, fmt.Sprint(state.listenPort))}
	for _, host := range strings.Split(state.extraListen, ",") {
		if host == "" {
			continue
		}
		listenAddrs = append(listenAddrs, net.JoinHostPort(host, fmt.Sprint(state.listenPort)))
	}
	if len(listenAddrs) > 1 {
		log.Printf("[BGP] Listening on %d addresses (including ZeroTier): %v", len(listenAddrs), listenAddrs)
	}
	listenAddrsByVRF := map[string][]string{
		vrf.DefaultVRFName: listenAddrs,
	}
	listeners := newListenerManager(listenAddrsByVRF)
	srvCfg := server.BGPServerConfig{
		RouterID:         state.routerID,
		DefaultVRF:       defVRF,
		ListenAddrsByVRF: listenAddrsByVRF,
	}
	runtime := &bgpRuntime{
		server:      newBGPServer(srvCfg),
		vrfs:        registry,
		kernel:      kernelRoutes,
		listeners:   listeners,
		state:       state,
		localRoutes: make(map[string]localRoute),
		peerNames:   make(map[string]string),
	}
	runtime.server.SetListenerManager(listeners)
	if err := applyRuntimeConfig(runtime, cfg); err != nil {
		_ = runtime.shutdown()
		return nil, err
	}
	runtime.server.Start()
	log.Println("[BGP] Kernel route integration active — learned routes will be installed in the main routing table")
	return runtime, nil
}

func stopLocked() error {
	invalidateStatsCacheLocked()
	if active == nil {
		return nil
	}
	err := active.shutdown()
	active = nil
	return err
}

func (runtime *bgpRuntime) shutdown() error {
	for _, peer := range runtime.server.GetPeers() {
		runtime.server.DisposePeer(peer.VRF(), peer.Addr())
	}
	listenerErr := runtime.listeners.Close()
	runtime.kernel.Dispose()
	return listenerErr
}

// buildFilterChain builds a filter chain for either direction of a BGP
// session. kind is "import" (received prefixes) or "export" (advertised
// prefixes) and is only used to label log output.
func buildFilterChain(kind string, filters []models.RouteFilter) filter.Chain {
	if len(filters) == 0 {
		log.Printf("[BGP] No %s filters configured — accepting all prefixes (accept-all policy)", kind)
		return filter.NewAcceptAllFilterChain()
	}

	log.Printf("[BGP] Building %s filter chain with %d term(s)", kind, len(filters))
	var terms []*filter.Term
	for i, f := range filters {
		pfx, err := bnet.PrefixFromString(f.Prefix)
		if err != nil {
			log.Printf("[BGP WARN] Filter term %d: invalid prefix %q: %v — skipping", i, f.Prefix, err)
			continue
		}

		var matcher filter.PrefixMatcher
		if strings.ToLower(f.Matcher) == "exact" {
			matcher = filter.NewExactMatcher()
		} else {
			matcher = filter.NewOrLongerMatcher()
		}

		routeFilter := filter.NewRouteFilter(pfx.Ptr(), matcher)
		termCond := filter.NewTermConditionWithRouteFilters(routeFilter)

		var action actions.Action
		if strings.ToLower(f.Action) == "accept" {
			action = &actions.AcceptAction{}
		} else {
			action = &actions.RejectAction{}
		}

		termName := fmt.Sprintf("term-%d", i)
		log.Printf("[BGP] %s filter term %q: prefix=%s matcher=%s action=%s", kind, termName, f.Prefix, f.Matcher, f.Action)
		terms = append(terms, filter.NewTerm(termName, []*filter.TermCondition{termCond}, []actions.Action{action}))
	}

	// Implicit reject at the end — anything not matched above is denied.
	log.Printf("[BGP] %s filter chain: implicit default-reject at end of chain", kind)
	terms = append(terms, filter.NewTerm("default-reject", []*filter.TermCondition{}, []actions.Action{&actions.RejectAction{}}))

	return filter.Chain{filter.NewFilter(kind+"-filter", terms)}
}

func buildExportFilterChain(filters []models.RouteFilter, redistributeConnected bool, maxPrefixLength uint16, localPrefixes []string, localNextHop *bnet.IP) filter.Chain {
	chain := prependMaxPrefixLengthFilter(buildFilterChain("export", filters), "advertised", maxPrefixLength)
	if redistributeConnected {
		if localNextHop == nil {
			return chain
		}
		nextHopSelf := filter.NewFilter("redistributed-next-hop-self", []*filter.Term{
			filter.NewTerm("set-local-session-address", nil, []actions.Action{newRedistributedNextHopAction(localNextHop)}),
		})
		return append(filter.Chain{nextHopSelf}, chain...)
	}

	terms := make([]*filter.Term, 0, len(localPrefixes))
	for i, prefix := range localPrefixes {
		parsed, err := bnet.PrefixFromString(prefix)
		if err != nil {
			continue
		}
		condition := filter.NewTermConditionWithRouteFilters(filter.NewRouteFilter(parsed.Dedup(), filter.NewExactMatcher()))
		terms = append(terms, filter.NewTerm(
			fmt.Sprintf("reject-local-connected-%d", i),
			[]*filter.TermCondition{condition},
			[]actions.Action{&actions.RejectAction{}},
		))
	}
	if len(terms) == 0 {
		return chain
	}
	rejectConnected := filter.NewFilter("reject-local-connected", terms)
	return append(filter.Chain{rejectConnected}, chain...)
}

type redistributedNextHopAction struct {
	nextHop *bnet.IP
}

func newRedistributedNextHopAction(nextHop *bnet.IP) *redistributedNextHopAction {
	return &redistributedNextHopAction{nextHop: nextHop.Dedup()}
}

func (a *redistributedNextHopAction) Do(_ *bnet.Prefix, path *route.Path) actions.Result {
	if path == nil || !path.IsRedistributed() {
		return actions.Result{Path: path}
	}
	modified := path.Copy()
	modified.SetNextHop(a.nextHop)
	return actions.Result{Path: modified}
}

func (a *redistributedNextHopAction) Equal(other actions.Action) bool {
	b, ok := other.(*redistributedNextHopAction)
	return ok && a.nextHop == b.nextHop
}

func prependMaxPrefixLengthFilter(chain filter.Chain, kind string, max uint16) filter.Chain {
	if max == 0 {
		return chain
	}

	var terms []*filter.Term
	for _, family := range []struct {
		name   string
		prefix string
		limit  uint8
	}{
		{name: "ipv4", prefix: "0.0.0.0/0", limit: 32},
		{name: "ipv6", prefix: "::/0", limit: 128},
	} {
		if max >= uint16(family.limit) {
			continue
		}
		prefix, _ := bnet.PrefixFromString(family.prefix)
		condition := filter.NewTermConditionWithRouteFilters(filter.NewRouteFilter(
			prefix.Dedup(),
			filter.NewInRangeMatcher(uint8(max+1), family.limit),
		))
		terms = append(terms, filter.NewTerm(
			fmt.Sprintf("reject-%s-longer-than-%d", family.name, max),
			[]*filter.TermCondition{condition},
			[]actions.Action{&actions.RejectAction{}},
		))
	}
	if len(terms) == 0 {
		return chain
	}
	return append(filter.Chain{filter.NewFilter(kind+"-max-prefix-length", terms)}, chain...)
}

func wantsLocalRoutes(cfg *models.AppConfig) bool {
	for _, peer := range cfg.BGPPeers {
		if peer.Enabled && peer.RedistributeConnected {
			return true
		}
	}
	return false
}

func desiredLocalPrefixes(cfg *models.AppConfig) ([]string, error) {
	if wantsLocalRoutes(cfg) {
		addresses, err := interfaceAddresses()
		if err != nil {
			return nil, fmt.Errorf("discover local and connected BGP routes: %w", err)
		}
		return localAndConnectedPrefixes(addresses), nil
	}
	return nil, nil
}

func applyRuntimeConfig(runtime *bgpRuntime, cfg *models.AppConfig) error {
	prefixes, err := desiredLocalPrefixes(cfg)
	if err != nil {
		return err
	}
	desired := make(map[string]bool, len(prefixes))
	for _, prefix := range prefixes {
		desired[prefix] = true
	}

	defVRF := runtime.vrfs.GetVRFByName(vrf.DefaultVRFName)
	// Withdraw stale routes before relaxing any peer export policy.
	for prefix, existing := range runtime.localRoutes {
		if desired[prefix] {
			continue
		}
		localRIB(defVRF, existing.prefix).RemovePath(existing.prefix, existing.path)
		delete(runtime.localRoutes, prefix)
	}

	if err := reconcilePeers(runtime, cfg, prefixes); err != nil {
		return err
	}

	peerNames := make(map[string]string)
	for _, p := range cfg.BGPPeers {
		if p.Enabled && p.PeerIP != "" {
			if ip, err := bnet.IPFromString(p.PeerIP); err == nil {
				peerNames[ip.String()] = p.Name
			} else {
				peerNames[p.PeerIP] = p.Name
			}
		}
	}
	runtime.peerNames = peerNames

	// Install new routes only after every opted-out peer has its deny policy.
	for _, prefix := range prefixes {
		if _, exists := runtime.localRoutes[prefix]; exists {
			continue
		}
		parsed, err := bnet.PrefixFromString(prefix)
		if err != nil {
			return fmt.Errorf("parse local BGP route %q: %w", prefix, err)
		}
		path := &route.Path{Type: route.StaticPathType, LTime: uint32(time.Now().Unix())}
		if err := localRIB(defVRF, parsed).AddPath(parsed, path); err != nil {
			return fmt.Errorf("add local BGP route %s: %w", prefix, err)
		}
		runtime.localRoutes[prefix] = localRoute{prefix: parsed, path: path}
	}
	return nil
}

func localRIB(defVRF *vrf.VRF, prefix *bnet.Prefix) interface {
	AddPath(*bnet.Prefix, *route.Path) error
	RemovePath(*bnet.Prefix, *route.Path) bool
} {
	if prefix.Addr().IsIPv4() {
		return defVRF.IPv4UnicastRIB()
	}
	return defVRF.IPv6UnicastRIB()
}

func systemInterfaceAddresses() ([]net.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var addresses []net.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		ifaceAddresses, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for %s: %w", iface.Name, err)
		}
		addresses = append(addresses, ifaceAddresses...)
	}
	return addresses, nil
}

func localAndConnectedPrefixes(addresses []net.Addr) []string {
	seen := make(map[string]bool)
	for _, address := range addresses {
		var ip net.IP
		var mask net.IPMask
		switch address := address.(type) {
		case *net.IPNet:
			ip, mask = address.IP, address.Mask
		case *net.IPAddr:
			ip = address.IP
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
		default:
			var network *net.IPNet
			var err error
			ip, network, err = net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			mask = network.Mask
		}

		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}

		ones, bits := mask.Size()
		if ones < 0 || (bits != 32 && bits != 128) {
			continue
		}
		seen[(&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()] = true
		seen[fmt.Sprintf("%s/%d", ip.String(), bits)] = true
	}

	prefixes := make([]string, 0, len(seen))
	for prefix := range seen {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	return prefixes
}
