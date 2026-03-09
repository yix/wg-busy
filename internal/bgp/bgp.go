package bgp

import (
	"encoding/binary"
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
	mu       sync.Mutex
	bgpSrv   server.BGPServer
	vrfReg   *vrf.VRFRegistry
	kSrv     *kernel.Kernel
	localASN uint32
)

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
		if bgpSrv != nil {
			log.Println("[BGP] BGP is disabled in config — stopping BGP server")
		}
		return stop()
	}

	routerID, err := routerIDFromAddress(cfg.Server.Address)
	if err != nil {
		return fmt.Errorf("cannot derive BGP Router ID from WireGuard address: %w", err)
	}
	if bgpSrv == nil {
		log.Printf("[BGP] Starting BGP server: routerID=%s ASN=%d listen=%s:%d",
			net.IP(binary.BigEndian.AppendUint32(nil, routerID)).String(),
			cfg.Server.BGPASN, cfg.Server.BGPListenAddress, cfg.Server.BGPListenPort)
		if err := start(cfg.Server, routerID); err != nil {
			log.Printf("[BGP ERROR] Failed to start BGP server: %v", err)
			return err
		}
	} else if bgpSrv.RouterID() != routerID {
		log.Printf("[BGP] Router ID changed — restarting BGP server")
		_ = stop()
		if err := start(cfg.Server, routerID); err != nil {
			log.Printf("[BGP ERROR] Failed to restart BGP server: %v", err)
			return err
		}
	}

	defVRF := vrfReg.GetVRFByName(vrf.DefaultVRFName)

	// Calculate desired peers
	desiredPeers := make(map[bnet.IP]server.PeerConfig)

	for _, p := range cfg.Peers {
		if !p.Enabled || !p.BGPEnabled {
			continue
		}

		bPeerIP, err := bnet.IPFromString(p.BGPPeerIP)
		if err != nil {
			log.Printf("[BGP WARN] Peer %q: invalid BGP peer IP %q: %v — skipping", p.Name, p.BGPPeerIP, err)
			continue
		}

		peerCfg := server.PeerConfig{
			AdminEnabled:      true,
			Passive:           true, // wg-busy only responds; peers must initiate
			TTL:               255,  // eBGP multihop over WireGuard tunnel
			ReconnectInterval: 15 * time.Second,
			KeepAlive:         30 * time.Second,
			HoldTime:          90 * time.Second,
			PeerAddress:       &bPeerIP,
			LocalAS:           cfg.Server.BGPASN,
			PeerAS:            p.BGPPeerASN,
			RouterID:          routerID,
			VRF:               defVRF,
		}

		if cfg.Server.BGPListenAddress != "" {
			if lA, err := bnet.IPFromString(cfg.Server.BGPListenAddress); err == nil {
				peerCfg.LocalAddress = &lA
			} else {
				log.Printf("[BGP WARN] Invalid BGP listen address %q: %v", cfg.Server.BGPListenAddress, err)
			}
		}

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

		desiredPeers[bPeerIP] = peerCfg
	}

	if bgpSrv != nil {
		currentPeers := bgpSrv.GetPeers()

		// Remove stale peers
		for _, cp := range currentPeers {
			if _, ok := desiredPeers[*cp.Addr()]; !ok {
				log.Printf("[BGP] Removing peer %s (no longer in config)", cp.Addr().String())
				bgpSrv.DisposePeer(cp.VRF(), cp.Addr())
			}
		}

		// Add or replace peers
		for bPeerIP, pCfg := range desiredPeers {
			bPeerCopy := bPeerIP
			oldCfg := bgpSrv.GetPeerConfig(defVRF, &bPeerCopy)
			if oldCfg != nil {
				if oldCfg.NeedsRestart(&pCfg) {
					log.Printf("[BGP] Peer %s config changed — restarting session", bPeerCopy.String())
					bgpSrv.DisposePeer(defVRF, &bPeerCopy)
					if err := bgpSrv.AddPeer(pCfg); err != nil {
						log.Printf("[BGP ERROR] Failed to re-add peer %s: %v", bPeerCopy.String(), err)
					} else {
						log.Printf("[BGP] Peer %s re-added successfully", bPeerCopy.String())
					}
				} else {
					log.Printf("[BGP] Peer %s: updating import/export filter chains", bPeerCopy.String())
					if pCfg.IPv4 != nil {
						if err := bgpSrv.ReplaceImportFilterChain(defVRF, &bPeerCopy, pCfg.IPv4.ImportFilterChain); err != nil {
							log.Printf("[BGP ERROR] Peer %s: failed to replace IPv4 import filter: %v", bPeerCopy.String(), err)
						}
						if err := bgpSrv.ReplaceExportFilterChain(defVRF, &bPeerCopy, pCfg.IPv4.ExportFilterChain); err != nil {
							log.Printf("[BGP ERROR] Peer %s: failed to replace IPv4 export filter: %v", bPeerCopy.String(), err)
						}
					}
					if pCfg.IPv6 != nil {
						if err := bgpSrv.ReplaceImportFilterChain(defVRF, &bPeerCopy, pCfg.IPv6.ImportFilterChain); err != nil {
							log.Printf("[BGP ERROR] Peer %s: failed to replace IPv6 import filter: %v", bPeerCopy.String(), err)
						}
						if err := bgpSrv.ReplaceExportFilterChain(defVRF, &bPeerCopy, pCfg.IPv6.ExportFilterChain); err != nil {
							log.Printf("[BGP ERROR] Peer %s: failed to replace IPv6 export filter: %v", bPeerCopy.String(), err)
						}
					}
				}
			} else {
				log.Printf("[BGP] Adding new peer %s (AS%d)", bPeerCopy.String(), pCfg.PeerAS)
				if err := bgpSrv.AddPeer(pCfg); err != nil {
					log.Printf("[BGP ERROR] Failed to add peer %s: %v", bPeerCopy.String(), err)
				} else {
					log.Printf("[BGP] Peer %s added, initiating connection", bPeerCopy.String())
				}
			}
		}
	}

	return nil
}

func start(cfg models.ServerConfig, routerID uint32) error {
	// Wire bio-rd's internal logger to Go's std logger so FSM transitions,
	// OPEN/NOTIFICATION messages, and TCP events are visible in wg-busy logs.
	biolog.SetLogger(newStdLogger())

	localASN = cfg.BGPASN

	vrfReg = vrf.NewVRFRegistry()
	defVRF := vrfReg.CreateVRFIfNotExists(vrf.DefaultVRFName, 0)

	listenAddr := cfg.BGPListenAddress
	if listenAddr == "" {
		listenAddr = "[::]"
		log.Printf("[BGP] No listen address configured, defaulting to all interfaces (%s)", listenAddr)
	}
	listenAddrsByVRF := map[string][]string{
		vrf.DefaultVRFName: {fmt.Sprintf("%s:%d", listenAddr, cfg.BGPListenPort)},
	}

	log.Printf("[BGP] Creating BGP server: routerID=%s ASN=%d listenAddr=%s:%d",
		net.IP(binary.BigEndian.AppendUint32(nil, routerID)).String(),
		cfg.BGPASN, listenAddr, cfg.BGPListenPort)

	srvCfg := server.BGPServerConfig{
		RouterID:         routerID,
		DefaultVRF:       defVRF,
		ListenAddrsByVRF: listenAddrsByVRF,
	}

	bgpSrv = server.NewBGPServer(srvCfg)
	bgpSrv.Start()
	log.Println("[BGP] BGP server started, listening for incoming connections")

	// Initialize Kernel routing module to auto-inject learned routes into main table.
	log.Println("[BGP] Initialising kernel route integration")
	k, err := kernel.New()
	if err != nil {
		return fmt.Errorf("failed to init kernel routing: %w", err)
	}
	kSrv = k

	defVRF.IPv4UnicastRIB().Register(kSrv)
	defVRF.IPv6UnicastRIB().Register(kSrv)
	log.Println("[BGP] Kernel route integration active — learned routes will be installed in the main routing table")

	return nil
}

func stop() error {
	if kSrv != nil {
		log.Println("[BGP] Deregistering kernel route integration")
		kSrv.Dispose()
		kSrv = nil
	}
	if bgpSrv != nil {
		peers := bgpSrv.GetPeers()
		log.Printf("[BGP] Stopping BGP server — disposing %d peer(s)", len(peers))
		for _, cp := range peers {
			log.Printf("[BGP] Disposing peer %s", cp.Addr().String())
			bgpSrv.DisposePeer(cp.VRF(), cp.Addr())
		}
		bgpSrv = nil
	}
	vrfReg = nil
	log.Println("[BGP] BGP server stopped")
	return nil
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
