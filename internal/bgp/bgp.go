package bgp

import (
	"fmt"
	"strings"
	"sync"
	"time"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/server"
	"github.com/bio-routing/bio-rd/protocols/kernel"
	"github.com/bio-routing/bio-rd/routingtable/filter"
	"github.com/bio-routing/bio-rd/routingtable/filter/actions"
	"github.com/bio-routing/bio-rd/routingtable/vrf"

	"github.com/yix/wg-busy/internal/models"
)

var (
	mu     sync.Mutex
	bgpSrv server.BGPServer
	vrfReg *vrf.VRFRegistry
	kSrv   *kernel.Kernel
)

// Configure applies the given application configuration to the bio-rd BGP server instance.
// It starts, stops, or reconfigures the BGP environment and peers accordingly.
func Configure(cfg *models.AppConfig) error {
	mu.Lock()
	defer mu.Unlock()

	if !cfg.Server.BGPEnabled {
		return stop()
	}

	if bgpSrv == nil {
		if err := start(cfg.Server); err != nil {
			return err
		}
	} else if bgpSrv.RouterID() != cfg.Server.BGPASN {
		// bio-rd router ID cannot (easily) be changed on the fly without restarting the server.
		// For simplicity, we restart the BGP server if RouterID changes.
		_ = stop()
		if err := start(cfg.Server); err != nil {
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
			continue
		}

		peerCfg := server.PeerConfig{
			AdminEnabled:      true,
			ReconnectInterval: 15 * time.Second,
			KeepAlive:         30 * time.Second,
			HoldTime:          90 * time.Second,
			PeerAddress:       &bPeerIP,
			LocalAS:           cfg.Server.BGPASN,
			PeerAS:            p.BGPPeerASN,
			RouterID:          cfg.Server.BGPASN,
			VRF:               defVRF,
		}

		if cfg.Server.BGPListenAddress != "" {
			if lA, err := bnet.IPFromString(cfg.Server.BGPListenAddress); err == nil {
				peerCfg.LocalAddress = &lA
			}
		}

		importFilter := buildFilterChain(p.BGPRouteFilters)
		exportFilter := filter.NewAcceptAllFilterChain() // For simplicity, export all local routing entries

		afi := &server.AddressFamilyConfig{
			ImportFilterChain: importFilter,
			ExportFilterChain: exportFilter,
		}

		if bPeerIP.IsIPv4() {
			peerCfg.IPv4 = afi
		} else {
			peerCfg.IPv6 = afi
		}

		desiredPeers[bPeerIP] = peerCfg
	}

	if bgpSrv != nil {
		currentPeers := bgpSrv.GetPeers()

		// Remove stale peers
		for _, cp := range currentPeers {
			if _, ok := desiredPeers[*cp.Addr()]; !ok {
				bgpSrv.DisposePeer(cp.VRF(), cp.Addr())
			}
		}

		// Add or replace peers
		for bPeerIP, pCfg := range desiredPeers {
			bPeerCopy := bPeerIP
			oldCfg := bgpSrv.GetPeerConfig(defVRF, &bPeerCopy)
			if oldCfg != nil {
				if oldCfg.NeedsRestart(&pCfg) {
					bgpSrv.DisposePeer(defVRF, &bPeerCopy)
					_ = bgpSrv.AddPeer(pCfg)
				} else {
					if pCfg.IPv4 != nil {
						_ = bgpSrv.ReplaceImportFilterChain(defVRF, &bPeerCopy, pCfg.IPv4.ImportFilterChain)
						_ = bgpSrv.ReplaceExportFilterChain(defVRF, &bPeerCopy, pCfg.IPv4.ExportFilterChain)
					}
					if pCfg.IPv6 != nil {
						_ = bgpSrv.ReplaceImportFilterChain(defVRF, &bPeerCopy, pCfg.IPv6.ImportFilterChain)
						_ = bgpSrv.ReplaceExportFilterChain(defVRF, &bPeerCopy, pCfg.IPv6.ExportFilterChain)
					}
				}
			} else {
				_ = bgpSrv.AddPeer(pCfg)
			}
		}
	}

	return nil
}

func start(cfg models.ServerConfig) error {
	vrfReg = vrf.NewVRFRegistry()
	defVRF := vrfReg.CreateVRFIfNotExists(vrf.DefaultVRFName, 0)

	listenAddrsByVRF := map[string][]string{}
	listenAddr := cfg.BGPListenAddress
	if listenAddr == "" {
		listenAddr = "[::]"
	}
	listenAddrsByVRF[vrf.DefaultVRFName] = []string{fmt.Sprintf("%s:%d", listenAddr, cfg.BGPListenPort)}

	srvCfg := server.BGPServerConfig{
		RouterID:         cfg.BGPASN,
		DefaultVRF:       defVRF,
		ListenAddrsByVRF: listenAddrsByVRF,
	}

	bgpSrv = server.NewBGPServer(srvCfg)
	bgpSrv.Start()

	// Initialize Kernel routing module to auto-inject learned routes into main table.
	k, err := kernel.New()
	if err != nil {
		return fmt.Errorf("failed to init kernel routing: %w", err)
	}
	kSrv = k

	defVRF.IPv4UnicastRIB().Register(kSrv)
	defVRF.IPv6UnicastRIB().Register(kSrv)

	return nil
}

func stop() error {
	if kSrv != nil {
		kSrv.Dispose()
		kSrv = nil
	}
	// bio-rd BGPServer doesn't have a clean global Stop() method currently exposed in its interface.
	// For now, we clear the references allowing GC and resource drops.
	// To cleanly stop, one would typically stop listeners or dispose of the VRF/peers.
	if bgpSrv != nil {
		for _, cp := range bgpSrv.GetPeers() {
			bgpSrv.DisposePeer(cp.VRF(), cp.Addr())
		}
		bgpSrv = nil
	}
	vrfReg = nil
	return nil
}

func buildFilterChain(filters []models.RouteFilter) filter.Chain {
	if len(filters) == 0 {
		return filter.NewAcceptAllFilterChain()
	}

	var terms []*filter.Term
	for i, f := range filters {
		pfx, err := bnet.PrefixFromString(f.Prefix)
		if err != nil {
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

		terms = append(terms, filter.NewTerm(fmt.Sprintf("term-%d", i), []*filter.TermCondition{termCond}, []actions.Action{action}))
	}

	// Implicit reject at the end, typical for route policies if no match.
	terms = append(terms, filter.NewTerm("default-reject", []*filter.TermCondition{}, []actions.Action{&actions.RejectAction{}}))

	return filter.Chain{filter.NewFilter("dynamic-filter", terms)}
}
