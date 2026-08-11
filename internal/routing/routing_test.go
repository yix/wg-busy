package routing

import (
	"strings"
	"testing"

	"github.com/yix/wg-busy/internal/models"
)

// Policy routes must be pinned to the interface their gateway is on-link for:
// wg0 for a WireGuard peer, the zt* device for a ZeroTier peer.
func TestPolicyRouteDeviceSelection(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{
			{
				ID: "p1", Name: "alice", Enabled: true, AllowedIPs: "10.0.0.5/32",
				PolicyRoutingTableID: 100,
				PolicyRoutes: []string{
					"10.5.5.0/24 via 10.0.0.2",     // WireGuard peer
					"10.9.9.0/24 via 10.147.17.99", // ZeroTier peer
				},
			},
			{ID: "p2", Name: "exit", Enabled: true, AllowedIPs: "10.0.0.6/32", IsExitNode: true, ExitNodeAllowAll: true, RoutingTableID: 101},
		},
	}

	gateways := models.GatewayNets(cfg.Server.Address, []models.GatewayNet{
		{Device: "zt5u4va25t", CIDR: "10.147.17.36/24"},
	})

	up := strings.Join(GeneratePostUpCommands(cfg, gateways), "\n")

	if !strings.Contains(up, "ip route add 10.5.5.0/24 via 10.0.0.2 dev wg0 table 100") {
		t.Errorf("WireGuard gateway not routed over wg0:\n%s", up)
	}
	if !strings.Contains(up, "ip route add 10.9.9.0/24 via 10.147.17.99 dev zt5u4va25t table 100 || true") {
		t.Errorf("ZeroTier gateway not routed over its zt device:\n%s", up)
	}

	down := strings.Join(GeneratePostDownCommands(cfg, gateways), "\n")
	if !strings.Contains(down, "ip route del 10.9.9.0/24 via 10.147.17.99 dev zt5u4va25t table 100 || true") {
		t.Errorf("ZeroTier route not cleaned up on its own device:\n%s", down)
	}

	// Without ZeroTier the same route falls back to wg0 rather than emitting an
	// empty device, which would be a syntax error at apply time.
	noZT := strings.Join(GeneratePostUpCommands(cfg, models.GatewayNets(cfg.Server.Address, nil)), "\n")
	if !strings.Contains(noZT, "ip route add 10.9.9.0/24 via 10.147.17.99 dev wg0 table 100") {
		t.Errorf("unknown gateway did not fall back to wg0:\n%s", noZT)
	}
}

// Policy routes do not depend on exit nodes; a config with only policy routes
// must still produce commands.
func TestPolicyRoutesWithoutExitNode(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{{
			ID: "p1", Name: "alice", Enabled: true, AllowedIPs: "10.0.0.5/32",
			PolicyRoutingTableID: 100,
			PolicyRoutes:         []string{"10.5.5.0/24 via 10.0.0.2"},
		}},
	}
	gateways := models.GatewayNets(cfg.Server.Address, nil)

	up := GeneratePostUpCommands(cfg, gateways)
	if len(up) == 0 {
		t.Fatal("no PostUp commands emitted for a peer with policy routes and no exit node")
	}
	joined := strings.Join(up, "\n")
	if !strings.Contains(joined, "ip rule add from 10.0.0.5 table 100") {
		t.Errorf("policy rule missing:\n%s", joined)
	}
	if !strings.Contains(joined, "ip route add 10.5.5.0/24 via 10.0.0.2 dev wg0 table 100") {
		t.Errorf("policy route missing:\n%s", joined)
	}

	if len(GeneratePostDownCommands(cfg, gateways)) == 0 {
		t.Error("no PostDown commands emitted; routes would leak on interface down")
	}
}
