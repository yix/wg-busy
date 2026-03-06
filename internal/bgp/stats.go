package bgp

import (
	"time"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/packet"
	"github.com/bio-routing/bio-rd/routingtable/vrf"

	"github.com/yix/wg-busy/internal/models"
)

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

	if bgpSrv == nil {
		return res
	}

	res.Running = true
	res.RouterID = bnet.IPv4(bgpSrv.RouterID()).String()
	res.ASN = bgpSrv.RouterID() // RouterID is typically derived from or matching the local ASN in this config. We could use local config ASN if provided, but let's stick to RouterID for simplicity unless we have access to the config from here.

	metrics, err := bgpSrv.Metrics()
	if err != nil || metrics == nil {
		return res
	}

	defVRF := vrfReg.GetVRFByName(vrf.DefaultVRFName)

	for _, pm := range metrics.Peers {
		peerStat := models.BGPPeerStats{
			IP:              pm.IP.String(),
			ASN:             pm.ASN,
			State:           bgpStateToString(pm.State),
			UpdatesReceived: pm.UpdatesReceived,
			Routes:          make([]models.BGPRoute, 0),
		}

		if !pm.Since.IsZero() && pm.State == 6 {
			// Calculate uptime
			d := time.Since(pm.Since).Truncate(time.Second)
			peerStat.Uptime = d.String()
		} else {
			peerStat.Uptime = "0s"
		}

		if pm.State == 6 {
			// AFI 1 (IPv4), SAFI 1 (Unicast)
			ribv4 := bgpSrv.GetRIBIn(defVRF, pm.IP, packet.AFIIPv4, packet.SAFIUnicast)
			if ribv4 != nil {
				for _, r := range ribv4.Dump() {
					for _, p := range r.Paths() {
						peerStat.Routes = append(peerStat.Routes, models.BGPRoute{
							Prefix:       r.Prefix().String(),
							NextHop:      p.NextHop().String(),
							LocalPref:    p.BGPPath.BGPPathA.LocalPref,
							ASPath:       p.BGPPath.ASPath.String(),
							IsHidden:     p.IsHidden(),
							HiddenReason: p.HiddenReasonString(),
						})
					}
				}
			}

			// AFI 2 (IPv6), SAFI 1 (Unicast)
			ribv6 := bgpSrv.GetRIBIn(defVRF, pm.IP, packet.AFIIPv6, packet.SAFIUnicast)
			if ribv6 != nil {
				for _, r := range ribv6.Dump() {
					for _, p := range r.Paths() {
						peerStat.Routes = append(peerStat.Routes, models.BGPRoute{
							Prefix:       r.Prefix().String(),
							NextHop:      p.NextHop().String(),
							LocalPref:    p.BGPPath.BGPPathA.LocalPref,
							ASPath:       p.BGPPath.ASPath.String(),
							IsHidden:     p.IsHidden(),
							HiddenReason: p.HiddenReasonString(),
						})
					}
				}
			}
		}

		res.Peers = append(res.Peers, peerStat)
	}

	return res
}
