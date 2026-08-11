package routing

import (
	"fmt"
	"strings"

	"github.com/yix/wg-busy/internal/models"
)

const routingTableBase uint = 100

// AssignRoutingTableID finds the next unused routing table ID for an exit node.
func AssignRoutingTableID(peers []models.Peer) uint {
	used := make(map[uint]bool)
	for _, p := range peers {
		if p.RoutingTableID > 0 {
			used[p.RoutingTableID] = true
		}
		if p.PolicyRoutingTableID > 0 {
			used[p.PolicyRoutingTableID] = true
		}
	}
	for id := routingTableBase; ; id++ {
		if !used[id] {
			return id
		}
	}
}

// policyRouteCmd renders one policy route. The gateway decides the interface:
// a WireGuard peer IP routes over wg0, a ZeroTier peer IP over that network's
// zt* device. Routes over a zt device are suffixed with "|| true" so a network
// that is not up yet cannot abort "wg-quick up".
func policyRouteCmd(action, subnet, gateway string, table uint, gateways []models.GatewayNet) string {
	dev := models.DeviceForGateway(gateway, gateways)
	if dev == "" {
		// ponytail: unknown gateway keeps the old wg0 behaviour — validation
		// rejects these, but a hand-edited config.yaml can still get here.
		dev = models.WGDevice
	}
	cmd := fmt.Sprintf("ip route %s %s via %s dev %s table %d", action, subnet, gateway, dev, table)
	if dev != models.WGDevice {
		cmd += " || true"
	}
	return cmd
}

// GeneratePostUpCommands returns ip rule/route commands for wg0.conf PostUp.
// Order: first create routing tables for exit nodes, then add rules for peers.
// gateways are the on-link networks policy route gateways may point into.
func GeneratePostUpCommands(cfg models.AppConfig, gateways []models.GatewayNet) []string {
	exitNodes := make(map[string]models.Peer) // id -> peer
	for _, p := range cfg.Peers {
		if p.IsExitNode && p.Enabled && p.RoutingTableID > 0 {
			exitNodes[p.ID] = p
		}
	}

	// No early return when there are no exit nodes: custom policy routes are
	// independent of them and must still be emitted.
	var cmds []string

	// Create routing table entries for each exit node.
	addedTables := make(map[uint]bool)
	for _, exitNode := range exitNodes {
		if addedTables[exitNode.RoutingTableID] {
			continue
		}
		exitIP := models.FirstIP(exitNode.AllowedIPs)
		if exitIP == "" {
			continue
		}
		if exitNode.ExitNodeAllowAll {
			cmds = append(cmds, fmt.Sprintf("ip route add default via %s dev wg0 table %d", exitIP, exitNode.RoutingTableID))
		} else {
			for _, route := range exitNode.ExitNodeRoutes {
				if route != "" {
					cmds = append(cmds, fmt.Sprintf("ip route add %s via %s dev wg0 table %d", route, exitIP, exitNode.RoutingTableID))
				}
			}
		}
		addedTables[exitNode.RoutingTableID] = true
	}

	// Add policy rules for peers using exit nodes.
	for _, p := range cfg.Peers {
		if !p.Enabled || p.ExitNodeID == "" {
			continue
		}
		exitNode, ok := exitNodes[p.ExitNodeID]
		if !ok {
			continue
		}
		peerIP := models.FirstIP(p.AllowedIPs)
		if peerIP == "" {
			continue
		}
		cmds = append(cmds, fmt.Sprintf("ip rule add from %s table %d", peerIP, exitNode.RoutingTableID))
	}

	// Add policy routes and rules for custom PolicyRoutes
	for _, p := range cfg.Peers {
		if !p.Enabled || len(p.PolicyRoutes) == 0 || p.PolicyRoutingTableID == 0 {
			continue
		}
		peerIP := models.FirstIP(p.AllowedIPs)
		if peerIP == "" {
			continue
		}

		cmds = append(cmds, fmt.Sprintf("ip rule add from %s table %d", peerIP, p.PolicyRoutingTableID))

		for _, routeStr := range p.PolicyRoutes {
			parts := strings.Split(routeStr, " via ")
			if len(parts) == 2 {
				cmds = append(cmds, policyRouteCmd("add", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), p.PolicyRoutingTableID, gateways))
			}
		}
	}

	return cmds
}

// GeneratePostDownCommands returns cleanup commands for wg0.conf PostDown.
// Order: first remove rules, then remove routing tables (reverse of PostUp).
func GeneratePostDownCommands(cfg models.AppConfig, gateways []models.GatewayNet) []string {
	exitNodes := make(map[string]models.Peer)
	for _, p := range cfg.Peers {
		if p.IsExitNode && p.Enabled && p.RoutingTableID > 0 {
			exitNodes[p.ID] = p
		}
	}

	// No early return when there are no exit nodes: custom policy routes are
	// independent of them and must still be emitted.
	var cmds []string

	// Remove policy rules first.
	for _, p := range cfg.Peers {
		if !p.Enabled || p.ExitNodeID == "" {
			continue
		}
		exitNode, ok := exitNodes[p.ExitNodeID]
		if !ok {
			continue
		}
		peerIP := models.FirstIP(p.AllowedIPs)
		if peerIP == "" {
			continue
		}
		cmds = append(cmds, fmt.Sprintf("ip rule del from %s table %d", peerIP, exitNode.RoutingTableID))
	}

	// Remove routing tables.
	removedTables := make(map[uint]bool)
	for _, exitNode := range exitNodes {
		if removedTables[exitNode.RoutingTableID] {
			continue
		}
		exitIP := models.FirstIP(exitNode.AllowedIPs)
		if exitIP == "" {
			continue
		}
		if exitNode.ExitNodeAllowAll {
			cmds = append(cmds, fmt.Sprintf("ip route del default via %s dev wg0 table %d", exitIP, exitNode.RoutingTableID))
		} else {
			for _, route := range exitNode.ExitNodeRoutes {
				if route != "" {
					cmds = append(cmds, fmt.Sprintf("ip route del %s via %s dev wg0 table %d", route, exitIP, exitNode.RoutingTableID))
				}
			}
		}
		removedTables[exitNode.RoutingTableID] = true
	}

	// Remove custom policy routes and rules
	for _, p := range cfg.Peers {
		if !p.Enabled || len(p.PolicyRoutes) == 0 || p.PolicyRoutingTableID == 0 {
			continue
		}
		peerIP := models.FirstIP(p.AllowedIPs)
		if peerIP == "" {
			continue
		}

		cmds = append(cmds, fmt.Sprintf("ip rule del from %s table %d", peerIP, p.PolicyRoutingTableID))

		for _, routeStr := range p.PolicyRoutes {
			parts := strings.Split(routeStr, " via ")
			if len(parts) == 2 {
				cmds = append(cmds, policyRouteCmd("del", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), p.PolicyRoutingTableID, gateways))
			}
		}
	}

	return cmds
}
