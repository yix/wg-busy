package bgp

import (
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/packet"
	"github.com/bio-routing/bio-rd/routingtable/vrf"

	"github.com/yix/wg-busy/internal/models"
)

var advertisedRoutesWatcher struct {
	sync.Mutex
	once sync.Once
	fn   func()
}

// AdvertisedRoutesByPeer returns the live prefixes in each peer's Adj-RIB-Out.
func AdvertisedRoutesByPeer() map[string][]string {
	mu.Lock()
	defer mu.Unlock()

	result := make(map[string][]string)
	if active == nil {
		return result
	}
	for _, peer := range active.server.GetPeers() {
		seen := make(map[string]bool)
		for _, af := range []uint16{packet.AFIIPv4, packet.AFIIPv6} {
			ribOut := active.server.GetRIBOut(peer.VRF(), peer.Addr(), af, packet.SAFIUnicast)
			if ribOut == nil {
				continue
			}
			for _, route := range ribOut.Dump() {
				prefix := route.Prefix().String()
				if !seen[prefix] {
					seen[prefix] = true
					result[peer.Addr().String()] = append(result[peer.Addr().String()], prefix)
				}
			}
		}
		sort.Strings(result[peer.Addr().String()])
	}
	return result
}

// OnAdvertisedRoutesChanged registers a callback fired when the set of
// prefixes in any peer's Adj-RIB-Out changes.
func OnAdvertisedRoutesChanged(fn func()) {
	advertisedRoutesWatcher.Lock()
	advertisedRoutesWatcher.fn = fn
	advertisedRoutesWatcher.Unlock()
	advertisedRoutesWatcher.once.Do(func() { go watchAdvertisedRoutes() })
}

func watchAdvertisedRoutes() {
	last := ""
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		routes := AdvertisedRoutesByPeer()
		signature := advertisedRoutesSignature(routes)
		if signature != last {
			last = signature
			advertisedRoutesWatcher.Lock()
			fn := advertisedRoutesWatcher.fn
			advertisedRoutesWatcher.Unlock()
			if fn != nil {
				fn()
			}
		}
		<-ticker.C
	}
}

func advertisedRoutesSignature(routes map[string][]string) string {
	peers := make([]string, 0, len(routes))
	for peer := range routes {
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	var signature strings.Builder
	for _, peer := range peers {
		signature.WriteString(peer)
		signature.WriteByte('=')
		prefixes := append([]string(nil), routes[peer]...)
		sort.Strings(prefixes)
		signature.WriteString(strings.Join(prefixes, ","))
		signature.WriteByte(';')
	}
	return signature.String()
}

// bgpStateToString maps the bio-rd BGP FSM state to a human readable string.
func bgpStateToString(state uint8) string {
	switch state {
	case 0:
		return "Down"
	case 1:
		return "Idle"
	case 2:
		return "Connect"
	case 3:
		return "Active"
	case 4:
		return "OpenSent"
	case 5:
		return "OpenConfirm"
	case 6:
		return "Established"
	default:
		return "Unknown"
	}
}

// GetBGPStats collects current statistics from the bio-rd BGP server instance.
func GetBGPStats() *models.BGPStats {
	mu.Lock()
	defer mu.Unlock()

	res := &models.BGPStats{
		Running: false,
		Peers:   make([]models.BGPPeerStats, 0),
	}

	if active == nil {
		return res
	}

	res.Running = true
	res.RouterID = bnet.IPv4(active.server.RouterID()).String()
	res.ASN = active.state.asn

	metrics, err := active.server.Metrics()
	if err != nil || metrics == nil {
		log.Printf("[BGP STATS] Metrics() returned err=%v metrics=%v", err, metrics)
		return res
	}

	defVRF := active.vrfs.GetVRFByName(vrf.DefaultVRFName)

	for _, pm := range metrics.Peers {
		stateStr := bgpStateToString(pm.State)

		// Aggregate route counts from AddressFamilies (more reliable than
		// FSM-level counters which can read the wrong FSM after reconnections).
		var totalRoutesReceived, totalRoutesSent uint64
		for _, af := range pm.AddressFamilies {
			totalRoutesReceived += af.RoutesReceived
			totalRoutesSent += af.RoutesSent
		}

		log.Printf("[BGP STATS] Peer %s: state=%d(%s) updatesRx=%d updatesTx=%d afCount=%d routesRx=%d routesTx=%d since=%v",
			pm.IP.String(), pm.State, stateStr,
			pm.UpdatesReceived, pm.UpdatesSent,
			len(pm.AddressFamilies), totalRoutesReceived, totalRoutesSent, pm.Since)

		peerStat := models.BGPPeerStats{
			IP:               pm.IP.String(),
			ASN:              pm.ASN,
			State:            stateStr,
			UpdatesReceived:  pm.UpdatesReceived,
			Routes:           make([]models.BGPRoute, 0),
			AdvertisedRoutes: make([]models.BGPRoute, 0),
		}

		if !pm.Since.IsZero() && pm.State == 6 {
			d := time.Since(pm.Since).Truncate(time.Second)
			peerStat.Uptime = d.String()
		} else {
			peerStat.Uptime = "0s"
		}

		if pm.State == 6 {
			locRIBv4 := defVRF.IPv4UnicastRIB()
			locRIBv6 := defVRF.IPv6UnicastRIB()

			// AFI 1 (IPv4), SAFI 1 (Unicast)
			ribv4 := active.server.GetRIBIn(defVRF, pm.IP, packet.AFIIPv4, packet.SAFIUnicast)
			if ribv4 != nil {
				for _, r := range ribv4.Dump() {
					status := "Filtered"
					if locRIBv4 != nil && locRIBv4.Get(r.Prefix()) != nil {
						status = "Accepted"
					}
					for _, p := range r.Paths() {
						peerStat.Routes = append(peerStat.Routes, models.BGPRoute{
							Prefix:    r.Prefix().String(),
							NextHop:   p.NextHop().String(),
							LocalPref: p.BGPPath.BGPPathA.LocalPref,
							ASPath:    p.BGPPath.ASPath.String(),
							Status:    status,
						})
					}
				}
			}

			// AFI 2 (IPv6), SAFI 1 (Unicast)
			ribv6 := active.server.GetRIBIn(defVRF, pm.IP, packet.AFIIPv6, packet.SAFIUnicast)
			if ribv6 != nil {
				for _, r := range ribv6.Dump() {
					status := "Filtered"
					if locRIBv6 != nil && locRIBv6.Get(r.Prefix()) != nil {
						status = "Accepted"
					}
					for _, p := range r.Paths() {
						peerStat.Routes = append(peerStat.Routes, models.BGPRoute{
							Prefix:    r.Prefix().String(),
							NextHop:   p.NextHop().String(),
							LocalPref: p.BGPPath.BGPPathA.LocalPref,
							ASPath:    p.BGPPath.ASPath.String(),
							Status:    status,
						})
					}
				}
			}

			// AFI 1/2 (IPv4/IPv6), SAFI 1 (Unicast) — the AdjRIBOut only holds
			// prefixes that already passed the peer's export filter chain, so
			// everything dumped here is, by definition, advertised.
			for _, af := range []struct {
				afi  uint16
				safi uint8
			}{{packet.AFIIPv4, packet.SAFIUnicast}, {packet.AFIIPv6, packet.SAFIUnicast}} {
				ribOut := active.server.GetRIBOut(defVRF, pm.IP, af.afi, af.safi)
				if ribOut == nil {
					continue
				}
				for _, r := range ribOut.Dump() {
					for _, p := range r.Paths() {
						peerStat.AdvertisedRoutes = append(peerStat.AdvertisedRoutes, models.BGPRoute{
							Prefix:    r.Prefix().String(),
							NextHop:   p.NextHop().String(),
							LocalPref: p.BGPPath.BGPPathA.LocalPref,
							ASPath:    p.BGPPath.ASPath.String(),
							Status:    "Advertised",
						})
					}
				}
			}
		}

		// Sort: Accepted routes first, Filtered last.
		sort.Slice(peerStat.Routes, func(i, j int) bool {
			return peerStat.Routes[i].Status == "Accepted" && peerStat.Routes[j].Status != "Accepted"
		})

		res.Peers = append(res.Peers, peerStat)
	}

	// bio-rd's Metrics() does not guarantee peer order, so without this the
	// BGP tab's peer list would reshuffle on every 2s poll.
	sortPeerStats(res.Peers)

	return res
}

func sortPeerStats(peers []models.BGPPeerStats) {
	sort.Slice(peers, func(i, j int) bool { return peers[i].IP < peers[j].IP })
}
