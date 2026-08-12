package bgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/server"
	"github.com/bio-routing/bio-rd/protocols/kernel"
	"github.com/bio-routing/bio-rd/routingtable/filter"
	"github.com/bio-routing/bio-rd/routingtable/filter/actions"
	"github.com/bio-routing/bio-rd/routingtable/vrf"
	biolog "github.com/bio-routing/bio-rd/util/log"

	"github.com/yix/wg-busy/internal/models"
)

var (
	mu           sync.Mutex
	active       *bgpRuntime
	newKernel    = kernel.New
	newBGPServer = server.NewBGPServer
)

type bgpServerState struct {
	routerID      uint32
	asn           uint32
	listenAddress string
	listenPort    uint16
}

type bgpRuntime struct {
	server    server.BGPServer
	vrfs      *vrf.VRFRegistry
	kernel    *kernel.Kernel
	listeners *listenerManager
	state     bgpServerState
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
		return nil
	}

	return reconcilePeers(active, cfg)
}

func stateFor(cfg models.ServerConfig, routerID uint32) bgpServerState {
	address := strings.TrimSpace(cfg.BGPListenAddress)
	if address == "" {
		address = "::"
	}
	return bgpServerState{routerID: routerID, asn: cfg.BGPASN, listenAddress: address, listenPort: cfg.BGPListenPort}
}

func desiredPeers(cfg *models.AppConfig, defVRF *vrf.VRF, routerID uint32) (map[bnet.IP]server.PeerConfig, error) {
	desired := make(map[bnet.IP]server.PeerConfig)

	for _, p := range cfg.Peers {
		if !p.Enabled || !p.BGPEnabled {
			continue
		}

		bPeerIP, err := bnet.IPFromString(p.BGPPeerIP)
		if err != nil {
			return nil, fmt.Errorf("peer %q has invalid BGP peer IP %q: %w", p.Name, p.BGPPeerIP, err)
		}
		if p.BGPPeerPort != 179 {
			return nil, fmt.Errorf("peer %q uses unsupported BGP peer port %d; only 179 is supported", p.Name, p.BGPPeerPort)
		}
		if _, exists := desired[bPeerIP]; exists {
			return nil, fmt.Errorf("multiple enabled BGP peers use address %s", bPeerIP.String())
		}

		peerCfg := server.PeerConfig{
			AdminEnabled:               true,
			AuthenticationKey:          "",            // TODO: add support for preshared keys
			Passive:                    !p.BGPConnect, // by default wg-busy only responds; peers must initiate
			TTL:                        255,           // eBGP multihop over WireGuard tunnel
			ReconnectInterval:          15 * time.Second,
			KeepAlive:                  30 * time.Second,
			HoldTime:                   90 * time.Second,
			PeerAddress:                &bPeerIP,
			LocalAS:                    cfg.Server.BGPASN,
			PeerAS:                     p.BGPPeerASN,
			RouterID:                   routerID,
			VRF:                        defVRF,
			AdvertiseIPv4MultiProtocol: true, // Required to negotiate IPv4 AFI over IPv6 sessions
		}

		if cfg.Server.BGPListenAddress != "" {
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

		importFilter := buildFilterChain(p.BGPRouteFilters)
		exportFilter := filter.NewAcceptAllFilterChain()

		afi := &server.AddressFamilyConfig{
			ImportFilterChain: importFilter,
			ExportFilterChain: exportFilter,
		}

		// Always enable both IPv4 and IPv6 unicast so peers can
		// advertise routes of either family over a single session.
		peerCfg.IPv4 = afi
		peerCfg.IPv6 = afi

		log.Printf("[BGP] Desired peer: name=%q ip=%s localAS=%d peerAS=%d filters=%d",
			p.Name, bPeerIP.String(), cfg.Server.BGPASN, p.BGPPeerASN, len(p.BGPRouteFilters))

		desired[bPeerIP] = peerCfg
	}
	return desired, nil
}

func reconcilePeers(runtime *bgpRuntime, cfg *models.AppConfig) error {
	defVRF := runtime.vrfs.GetVRFByName(vrf.DefaultVRFName)
	desired, err := desiredPeers(cfg, defVRF, runtime.state.routerID)
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
	defVRF.IPv4UnicastRIB().Register(kernelRoutes)
	defVRF.IPv6UnicastRIB().Register(kernelRoutes)

	listenAddress := net.JoinHostPort(state.listenAddress, fmt.Sprint(state.listenPort))
	listenAddrsByVRF := map[string][]string{
		vrf.DefaultVRFName: {listenAddress},
	}
	listeners := newListenerManager(listenAddrsByVRF)
	srvCfg := server.BGPServerConfig{
		RouterID:         state.routerID,
		DefaultVRF:       defVRF,
		ListenAddrsByVRF: listenAddrsByVRF,
	}
	runtime := &bgpRuntime{server: newBGPServer(srvCfg), vrfs: registry, kernel: kernelRoutes, listeners: listeners, state: state}
	runtime.server.SetListenerManager(listeners)
	if err := reconcilePeers(runtime, cfg); err != nil {
		_ = runtime.shutdown()
		return nil, err
	}
	runtime.server.Start()
	log.Println("[BGP] Kernel route integration active — learned routes will be installed in the main routing table")
	return runtime, nil
}

func stopLocked() error {
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

func buildFilterChain(filters []models.RouteFilter) filter.Chain {
	if len(filters) == 0 {
		log.Println("[BGP] No route filters configured — accepting all prefixes (accept-all policy)")
		return filter.NewAcceptAllFilterChain()
	}

	log.Printf("[BGP] Building filter chain with %d term(s)", len(filters))
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
		log.Printf("[BGP] Filter term %q: prefix=%s matcher=%s action=%s", termName, f.Prefix, f.Matcher, f.Action)
		terms = append(terms, filter.NewTerm(termName, []*filter.TermCondition{termCond}, []actions.Action{action}))
	}

	// Implicit reject at the end — anything not matched above is denied.
	log.Println("[BGP] Filter chain: implicit default-reject at end of chain")
	terms = append(terms, filter.NewTerm("default-reject", []*filter.TermCondition{}, []actions.Action{&actions.RejectAction{}}))

	return filter.Chain{filter.NewFilter("dynamic-filter", terms)}
}
