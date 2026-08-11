package routing

import (
	"fmt"
	"os/exec"
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

// rulePriorityBase is where generated `ip rule` priorities start. Priorities are
// explicit because `ip rule add` without one assigns a *descending* number, so
// the last rule added would be evaluated first — which would put a strict peer's
// reject rule ahead of its own table lookup and blackhole everything.
// The range stays well below main (32766) so these rules are consulted first.
const rulePriorityBase = 10000

// peerRule is one `ip rule` entry. Both PostUp and PostDown render from the same
// specs, so teardown always matches what was installed.
type peerRule struct {
	Selector string // e.g. "from 10.0.0.5"
	Action   string // e.g. "table 100" or "prohibit"
	Priority int
}

// peerRules returns every ip rule to install, in evaluation order.
//
// A peer's own lookups come first, and a strict peer gets a trailing reject so
// unmatched traffic stops there instead of falling through to the main table.
func peerRules(cfg models.AppConfig, exitNodes map[string]models.Peer) []peerRule {
	var rules []peerRule
	prio := rulePriorityBase

	for _, p := range cfg.Peers {
		if !p.Enabled {
			continue
		}
		peerIP := models.FirstIP(p.AllowedIPs)
		if peerIP == "" {
			continue
		}
		selector := "from " + peerIP
		matched := false

		// Exit node table, when this peer routes through one.
		if p.ExitNodeID != "" {
			if exitNode, ok := exitNodes[p.ExitNodeID]; ok {
				rules = append(rules, peerRule{selector, fmt.Sprintf("table %d", exitNode.RoutingTableID), prio})
				prio++
				matched = true
			}
		}

		// The peer's own policy table.
		if len(p.PolicyRoutes) > 0 && p.PolicyRoutingTableID > 0 {
			rules = append(rules, peerRule{selector, fmt.Sprintf("table %d", p.PolicyRoutingTableID), prio})
			prio++
			matched = true
		}

		// Strict: anything the tables above did not match is rejected here rather
		// than falling through to main. Validation guarantees there is a table to
		// consult first, so this can never be the peer's only rule.
		if p.StrictPolicyRouting && matched {
			rules = append(rules, peerRule{selector, "prohibit", prio})
			prio++
		}
	}
	return rules
}

// masqueradeRule is the NAT rule for traffic leaving over ZeroTier. Packets
// routed out a zt interface still carry their original source (a WireGuard peer
// IP, say), which the ZeroTier network has no route back to — so they are
// masqueraded behind this node's ZeroTier address.
//
// The zt+ wildcard covers every ZeroTier interface, including networks joined
// after wg0 came up, so the rule never needs to know device names.
const masqueradeSpec = "POSTROUTING -o zt+ -j MASQUERADE"

// zeroTierMasquerade returns the NAT commands for ZeroTier egress.
// add=false renders the teardown.
func zeroTierMasquerade(cfg models.AppConfig, add bool) []string {
	if !cfg.ZeroTier.Enabled {
		return nil
	}
	if add {
		// Check-then-add: applying twice must not stack duplicate rules, and a
		// PostDown that never ran (see ApplyConfig) would otherwise leave one behind.
		return []string{fmt.Sprintf(
			"iptables -t nat -C %s 2>/dev/null || iptables -t nat -A %s",
			masqueradeSpec, masqueradeSpec)}
	}
	// Never fail the teardown if the rule is already gone: wg-quick runs hooks
	// under set -e, and an aborted down leaves the interface half torn down.
	return []string{fmt.Sprintf("iptables -t nat -D %s || true", masqueradeSpec)}
}

// policyRouteCmd renders one policy route. The gateway decides the interface:
// a WireGuard peer IP routes over wg0, a ZeroTier peer IP over that network's
// zt* device.
//
// Every policy route is suffixed with "|| true". wg-quick runs hooks under
// `set -e`, so without it a single route the kernel refuses — a ZeroTier network
// that is not up yet, or a gateway that has stopped being on-link — would abort
// the bring-up and leave the machine with no WireGuard at all. A route that
// cannot be installed now is installed by the next apply; losing the whole
// interface is never the better failure.
func policyRouteCmd(action, subnet, gateway string, table uint, gateways []models.GatewayNet) string {
	dev := models.DeviceForGateway(gateway, gateways)
	if dev == "" {
		// ponytail: unknown gateway falls back to wg0 — validation rejects these,
		// but a hand-edited config.yaml or a ZeroTier network that has not come up
		// yet still lands here, and the guard keeps it harmless.
		dev = models.WGDevice
	}
	return fmt.Sprintf("ip route %s %s via %s dev %s table %d || true", action, subnet, gateway, dev, table)
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
			cmds = append(cmds, fmt.Sprintf("ip route replace default via %s dev wg0 table %d", exitIP, exitNode.RoutingTableID))
		} else {
			for _, route := range exitNode.ExitNodeRoutes {
				if route != "" {
					cmds = append(cmds, fmt.Sprintf("ip route replace %s via %s dev wg0 table %d", route, exitIP, exitNode.RoutingTableID))
				}
			}
		}
		addedTables[exitNode.RoutingTableID] = true
	}

	// NAT for anything leaving over ZeroTier.
	cmds = append(cmds, zeroTierMasquerade(cfg, true)...)

	// Policy rules for exit nodes, policy routes, and strict rejects.
	//
	// Each add is preceded by a delete of whatever holds that priority: `ip rule
	// add ... priority N` fails with EEXIST if the slot is taken, and wg-quick
	// runs hooks under `set -e`, so a leftover rule from a teardown that never
	// ran would abort the whole interface bring-up. Deleting by priority alone
	// also clears a stale rule whose selector has since changed.
	for _, r := range peerRules(cfg, exitNodes) {
		cmds = append(cmds, fmt.Sprintf("ip rule del priority %d 2>/dev/null || true; ip rule add %s %s priority %d",
			r.Priority, r.Selector, r.Action, r.Priority))
	}

	// Add the routes that populate each peer's own policy table.
	for _, p := range cfg.Peers {
		if !p.Enabled || len(p.PolicyRoutes) == 0 || p.PolicyRoutingTableID == 0 {
			continue
		}
		if models.FirstIP(p.AllowedIPs) == "" {
			continue
		}

		for _, routeStr := range p.PolicyRoutes {
			parts := strings.Split(routeStr, " via ")
			if len(parts) == 2 {
				cmds = append(cmds, policyRouteCmd("replace", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), p.PolicyRoutingTableID, gateways))
			}
		}
	}

	return cmds
}

// Apply runs generated PostUp commands against the live system.
//
// Safe to call at any time: every command it generates is idempotent (rules
// free their priority first, routes use replace, the NAT rule is check-then-add),
// so this converges the kernel to the config without restarting the interface.
// Used when a ZeroTier network comes up after wg0, which would otherwise leave
// its routes uninstalled until the next manual apply.
func Apply(cmds []string) error {
	if _, err := exec.Command("ip", "link", "show", models.WGDevice).Output(); err != nil {
		// No interface yet: PostUp will run these when it comes up.
		return nil
	}
	for _, cmd := range cmds {
		if out, err := exec.Command("sh", "-c", cmd).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", cmd, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
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

	cmds = append(cmds, zeroTierMasquerade(cfg, false)...)

	// Remove policy rules first. Deleting by priority is exact, so repeated
	// apply cycles cannot leave duplicates behind.
	for _, r := range peerRules(cfg, exitNodes) {
		cmds = append(cmds, fmt.Sprintf("ip rule del %s %s priority %d || true", r.Selector, r.Action, r.Priority))
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

	// Remove the routes from each peer's own policy table.
	for _, p := range cfg.Peers {
		if !p.Enabled || len(p.PolicyRoutes) == 0 || p.PolicyRoutingTableID == 0 {
			continue
		}
		if models.FirstIP(p.AllowedIPs) == "" {
			continue
		}

		for _, routeStr := range p.PolicyRoutes {
			parts := strings.Split(routeStr, " via ")
			if len(parts) == 2 {
				cmds = append(cmds, policyRouteCmd("del", strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), p.PolicyRoutingTableID, gateways))
			}
		}
	}

	return cmds
}
