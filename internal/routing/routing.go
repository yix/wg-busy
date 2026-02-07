package routing

import (
	"fmt"

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
	}
	for id := routingTableBase; ; id++ {
		if !used[id] {
			return id
		}
	}
}

// GeneratePostUpCommands returns ip rule/route commands for wg0.conf PostUp.
// Order: first create routing tables for exit nodes, then add rules for peers.
func GeneratePostUpCommands(cfg models.AppConfig) []string {
	exitNodes := make(map[string]models.Peer) // id -> peer
	for _, p := range cfg.Peers {
		if p.IsExitNode && p.Enabled && p.RoutingTableID > 0 {
			exitNodes[p.ID] = p
		}
	}

	if len(exitNodes) == 0 {
		return nil
	}

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
		cmds = append(cmds, fmt.Sprintf("ip route add default via %s dev wg0 table %d", exitIP, exitNode.RoutingTableID))
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

	return cmds
}

// GeneratePostDownCommands returns cleanup commands for wg0.conf PostDown.
// Order: first remove rules, then remove routing tables (reverse of PostUp).
func GeneratePostDownCommands(cfg models.AppConfig) []string {
	exitNodes := make(map[string]models.Peer)
	for _, p := range cfg.Peers {
		if p.IsExitNode && p.Enabled && p.RoutingTableID > 0 {
			exitNodes[p.ID] = p
		}
	}

	if len(exitNodes) == 0 {
		return nil
	}

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
		cmds = append(cmds, fmt.Sprintf("ip route del default via %s dev wg0 table %d", exitIP, exitNode.RoutingTableID))
		removedTables[exitNode.RoutingTableID] = true
	}

	return cmds
}
