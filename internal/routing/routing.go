package routing

import (
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"

	"github.com/yix/wg-busy/internal/models"
)

var (
	interfaceUp = func() bool {
		_, err := exec.Command("ip", "link", "show", models.WGDevice).Output()
		return err == nil
	}
	runShellCommand = func(command string) ([]byte, error) {
		return exec.Command("sh", "-c", command).CombinedOutput()
	}
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
	IPCommand string // "ip" for IPv4, "ip -6" for IPv6
	Selector  string // e.g. "from 10.0.0.5"
	Action    string // e.g. "table 100" or "prohibit"
	Priority  int
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
		peerSources := models.PeerSources(p.AllowedIPs)
		if len(peerSources) == 0 {
			continue
		}
		for _, peerSource := range peerSources {
			ipCommand := "ip"
			if strings.Contains(peerSource, ":") {
				ipCommand = "ip -6"
			}
			selector := "from " + peerSource

			// Exit node table, when this peer routes through one.
			if p.ExitNodeID != "" {
				if exitNode, ok := exitNodes[p.ExitNodeID]; ok {
					rules = append(rules, peerRule{ipCommand, selector, fmt.Sprintf("table %d", exitNode.RoutingTableID), prio})
					prio++
				}
			}

			// The peer's own policy table.
			if len(p.PolicyRoutes) > 0 && p.PolicyRoutingTableID > 0 {
				rules = append(rules, peerRule{ipCommand, selector, fmt.Sprintf("table %d", p.PolicyRoutingTableID), prio})
				prio++
			}

			// Strict always fails closed. Validation normally guarantees a lookup
			// first, but a hand-edited invalid config must never fall through to main.
			if p.StrictPolicyRouting {
				rules = append(rules, peerRule{ipCommand, selector, "prohibit", prio})
				prio++
			}
		}
	}
	return rules
}

const (
	strictChainV4       = "WG_BUSY_STRICT4"
	strictChainV6       = "WG_BUSY_STRICT6"
	strictApplyComment  = "wg-busy strict apply"
)

// strictEgressRule represents one firewall rule in WG_BUSY_STRICT4 or WG_BUSY_STRICT6.
type strictEgressRule struct {
	IsV6   bool
	Source string
	Dest   string // empty for terminal reject
	OutDev string // empty for terminal reject
	Action string // "RETURN" or "REJECT"
}

// strictEgressRules returns all allow-return and terminal reject rules for strict peers.
func strictEgressRules(cfg models.AppConfig, gateways []models.GatewayNet, exitNodes map[string]models.Peer) []strictEgressRule {
	var rules []strictEgressRule

	for _, p := range cfg.Peers {
		if !p.Enabled || !p.StrictPolicyRouting {
			continue
		}
		sources := models.PeerSources(p.AllowedIPs)
		if len(sources) == 0 {
			continue
		}

		for _, src := range sources {
			isV6 := strings.Contains(src, ":")

			// 1. Exit node routes for strict peer
			if p.ExitNodeID != "" {
				if exitNode, ok := exitNodes[p.ExitNodeID]; ok {
					if exitNode.ExitNodeAllowAll {
						if !isV6 {
							rules = append(rules, strictEgressRule{IsV6: false, Source: src, Dest: "0.0.0.0/0", OutDev: models.WGDevice, Action: "RETURN"})
						} else {
							rules = append(rules, strictEgressRule{IsV6: true, Source: src, Dest: "::/0", OutDev: models.WGDevice, Action: "RETURN"})
						}
					} else {
						for _, r := range exitNode.ExitNodeRoutes {
							r = strings.TrimSpace(r)
							if r == "" {
								continue
							}
							ip, _, err := net.ParseCIDR(r)
							if err != nil {
								continue
							}
							routeIsV6 := ip.To4() == nil
							if routeIsV6 == isV6 {
								rules = append(rules, strictEgressRule{IsV6: isV6, Source: src, Dest: r, OutDev: models.WGDevice, Action: "RETURN"})
							}
						}
					}
				}
			}

			// 2. Policy routes for strict peer
			for _, routeStr := range p.PolicyRoutes {
				parts := strings.Split(routeStr, " via ")
				if len(parts) != 2 {
					continue
				}
				subnet := strings.TrimSpace(parts[0])
				gw := strings.TrimSpace(parts[1])

				ip, _, err := net.ParseCIDR(subnet)
				if err != nil {
					continue
				}
				routeIsV6 := ip.To4() == nil
				if routeIsV6 != isV6 {
					continue
				}

				dev, err := models.ResolveGateway(gw, gateways)
				if err != nil || dev == "" {
					// Missing or ambiguous gateway: do not emit allow rule.
					continue
				}
				rules = append(rules, strictEgressRule{IsV6: isV6, Source: src, Dest: subnet, OutDev: dev, Action: "RETURN"})
			}

			// 3. Terminal reject for this strict source
			rules = append(rules, strictEgressRule{IsV6: isV6, Source: src, Action: "REJECT"})
		}
	}
	return rules
}

// strictFirewallCommands generates commands to initialize or teardown the strict egress chains.
func strictFirewallCommands(cfg models.AppConfig, gateways []models.GatewayNet, add bool) []string {
	var cmds []string
	if add {
		// Initialize IPv4 chain and FORWARD jump
		cmds = append(cmds,
			fmt.Sprintf("iptables -w -N %s 2>/dev/null || true", strictChainV4),
			fmt.Sprintf("iptables -w -C FORWARD -i %s -j %s 2>/dev/null || iptables -w -I FORWARD 1 -i %s -j %s", models.WGDevice, strictChainV4, models.WGDevice, strictChainV4),
			fmt.Sprintf("iptables -w -F %s", strictChainV4),
		)
		// Initialize IPv6 chain and FORWARD jump
		cmds = append(cmds,
			fmt.Sprintf("ip6tables -w -N %s 2>/dev/null || true", strictChainV6),
			fmt.Sprintf("ip6tables -w -C FORWARD -i %s -j %s 2>/dev/null || ip6tables -w -I FORWARD 1 -i %s -j %s", models.WGDevice, strictChainV6, models.WGDevice, strictChainV6),
			fmt.Sprintf("ip6tables -w -F %s", strictChainV6),
		)

		exitNodes := enabledExitNodes(cfg)
		for _, r := range strictEgressRules(cfg, gateways, exitNodes) {
			if !r.IsV6 {
				if r.Action == "RETURN" {
					cmds = append(cmds, fmt.Sprintf("iptables -w -A %s -s %s -d %s -o %s -j RETURN", strictChainV4, r.Source, r.Dest, r.OutDev))
				} else {
					cmds = append(cmds, fmt.Sprintf("iptables -w -A %s -s %s -j REJECT --reject-with icmp-admin-prohibited", strictChainV4, r.Source))
				}
			} else {
				if r.Action == "RETURN" {
					cmds = append(cmds, fmt.Sprintf("ip6tables -w -A %s -s %s -d %s -o %s -j RETURN", strictChainV6, r.Source, r.Dest, r.OutDev))
				} else {
					cmds = append(cmds, fmt.Sprintf("ip6tables -w -A %s -s %s -j REJECT --reject-with icmp6-adm-prohibited", strictChainV6, r.Source))
				}
			}
		}
		return cmds
	}

	// Teardown
	cmds = append(cmds,
		fmt.Sprintf("iptables -w -D FORWARD -i %s -j %s 2>/dev/null || true", models.WGDevice, strictChainV4),
		fmt.Sprintf("iptables -w -F %s 2>/dev/null || true", strictChainV4),
		fmt.Sprintf("iptables -w -X %s 2>/dev/null || true", strictChainV4),
		fmt.Sprintf("ip6tables -w -D FORWARD -i %s -j %s 2>/dev/null || true", models.WGDevice, strictChainV6),
		fmt.Sprintf("ip6tables -w -F %s 2>/dev/null || true", strictChainV6),
		fmt.Sprintf("ip6tables -w -X %s 2>/dev/null || true", strictChainV6),
	)
	return cmds
}

// strictPeerSources returns all unique source selectors for enabled strict peers.
func strictPeerSources(cfg models.AppConfig) []string {
	var sources []string
	seen := make(map[string]bool)
	for _, p := range cfg.Peers {
		if !p.Enabled || !p.StrictPolicyRouting {
			continue
		}
		for _, src := range models.PeerSources(p.AllowedIPs) {
			if !seen[src] {
				seen[src] = true
				sources = append(sources, src)
			}
		}
	}
	return sources
}

func unionSources(a, b []string) []string {
	seen := make(map[string]bool)
	var res []string
	for _, s := range append(a, b...) {
		if !seen[s] {
			seen[s] = true
			res = append(res, s)
		}
	}
	return res
}

func temporaryRejectCommands(sources []string, add bool) []string {
	var cmds []string
	for _, src := range sources {
		isV6 := strings.Contains(src, ":")
		if add {
			if !isV6 {
				cmds = append(cmds, fmt.Sprintf(
					"iptables -w -I FORWARD 1 -i %s -s %s -m comment --comment '%s' -j REJECT --reject-with icmp-admin-prohibited",
					models.WGDevice, src, strictApplyComment))
			} else {
				cmds = append(cmds, fmt.Sprintf(
					"ip6tables -w -I FORWARD 1 -i %s -s %s -m comment --comment '%s' -j REJECT --reject-with icmp6-adm-prohibited",
					models.WGDevice, src, strictApplyComment))
			}
		} else {
			if !isV6 {
				cmds = append(cmds, fmt.Sprintf(
					"iptables -w -D FORWARD -i %s -s %s -m comment --comment '%s' -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null || true",
					models.WGDevice, src, strictApplyComment))
			} else {
				cmds = append(cmds, fmt.Sprintf(
					"ip6tables -w -D FORWARD -i %s -s %s -m comment --comment '%s' -j REJECT --reject-with icmp6-adm-prohibited 2>/dev/null || true",
					models.WGDevice, src, strictApplyComment))
			}
		}
	}
	return cmds
}

// masqueradeRule is the NAT rule for traffic leaving over ZeroTier. Packets
// routed out a zt interface still carry their original source (a WireGuard peer
// IP, say), which the ZeroTier network has no route back to — so they are
// masqueraded behind this node's ZeroTier address.
//
// The zt+ wildcard covers every ZeroTier interface, including networks joined
// after wg0 came up, so the rule never needs to know device names.
const masqueradeSpec = "POSTROUTING -o zt+ -j MASQUERADE"

// zeroTierMasquerade returns the NAT commands for ZeroTier egress. Optional
// ACCEPT rules are inserted before MASQUERADE so advertised networks retain
// their original source addresses.
// add=false renders the teardown.
func zeroTierMasquerade(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string, add bool) []string {
	if !cfg.ZeroTier.Enabled || cfg.ZeroTier.DisableMasquerade {
		return nil
	}

	var specs []string
	if cfg.ZeroTier.ExcludeAdvertisedRoutesFromMasquerade {
		seen := make(map[string]bool)
		for peerIP, advertisedRoutes := range advertisedByPeer {
			if !strings.HasPrefix(models.DeviceForGateway(peerIP, gateways), "zt") {
				continue
			}
			for _, advertised := range advertisedRoutes {
				ip, network, err := net.ParseCIDR(strings.TrimSpace(advertised))
				if err != nil || ip.To4() == nil || seen[network.String()] {
					continue
				}
				seen[network.String()] = true
				specs = append(specs, fmt.Sprintf("-s %s -o zt+ -j ACCEPT", network.String()))
			}
		}
		sort.Strings(specs)
	}

	var commands []string
	if add {
		for _, spec := range specs {
			commands = append(commands, fmt.Sprintf(
				"iptables -t nat -C POSTROUTING %s 2>/dev/null || iptables -t nat -I POSTROUTING 1 %s",
				spec, spec))
		}
		// Check-then-add: applying twice must not stack duplicate rules, and a
		// PostDown that never ran (see ApplyConfig) would otherwise leave one behind.
		return append(commands, fmt.Sprintf(
			"iptables -t nat -C %s 2>/dev/null || iptables -t nat -A %s",
			masqueradeSpec, masqueradeSpec))
	}
	// Never fail the teardown if the rule is already gone: wg-quick runs hooks
	// under set -e, and an aborted down leaves the interface half torn down.
	commands = append(commands, fmt.Sprintf("iptables -t nat -D %s || true", masqueradeSpec))
	for _, spec := range specs {
		commands = append(commands, fmt.Sprintf("iptables -t nat -D POSTROUTING %s || true", spec))
	}
	return commands
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
func policyRouteCmd(action, subnet, gateway string, table uint, gateways []models.GatewayNet, isStrict bool) string {
	ipCommand := "ip"
	if ip, _, err := net.ParseCIDR(subnet); err == nil && ip.To4() == nil {
		ipCommand = "ip -6"
	}
	if action == "del" {
		// Deletion only needs the route key. Omitting the old gateway and device
		// also makes cleanup work immediately after process startup, before the
		// ZeroTier supervisor has rediscovered the interface that installed it.
		return fmt.Sprintf("%s route del %s table %d || true", ipCommand, subnet, table)
	}
	dev := models.DeviceForGateway(gateway, gateways)
	if dev == "" {
		if isStrict {
			// Strict policy routing must not fall back to wg0; omit route installation
			// so the peer fails closed.
			return ""
		}
		// Non-strict fallback to wg0 for best-effort compatibility.
		dev = models.WGDevice
	}
	return fmt.Sprintf("%s route %s %s via %s dev %s table %d || true", ipCommand, action, subnet, gateway, dev, table)
}

// enabledExitNodes returns the exit nodes traffic can currently be steered to,
// keyed by peer ID.
func enabledExitNodes(cfg models.AppConfig) map[string]models.Peer {
	exitNodes := make(map[string]models.Peer)
	for _, p := range cfg.Peers {
		if p.IsExitNode && p.Enabled && p.RoutingTableID > 0 {
			exitNodes[p.ID] = p
		}
	}
	return exitNodes
}

// exitNodeRouteCmds renders the routing table entries for each exit node.
// action is "replace" on the way up and "del" on the way down.
func exitNodeRouteCmds(action string, exitNodes map[string]models.Peer) []string {
	var cmds []string
	done := make(map[uint]bool)
	for _, exitNode := range exitNodes {
		if done[exitNode.RoutingTableID] {
			continue
		}
		if exitNode.ExitNodeAllowAll {
			for _, ipCommand := range []string{"ip -4", "ip -6"} {
				cmd := fmt.Sprintf("%s route %s default dev wg0 table %d", ipCommand, action, exitNode.RoutingTableID)
				if action == "del" {
					cmd += " || true"
				}
				cmds = append(cmds, cmd)
			}
		} else {
			for _, route := range exitNode.ExitNodeRoutes {
				if route != "" {
					ipCommand := "ip -4"
					if ip, _, err := net.ParseCIDR(route); err == nil && ip.To4() == nil {
						ipCommand = "ip -6"
					}
					cmd := fmt.Sprintf("%s route %s %s dev wg0 table %d", ipCommand, action, route, exitNode.RoutingTableID)
					if action == "del" {
						cmd += " || true"
					}
					cmds = append(cmds, cmd)
				}
			}
		}
		done[exitNode.RoutingTableID] = true
	}
	return cmds
}

// policyRouteCmds renders the routes populating each peer's own policy table.
func policyRouteCmds(action string, cfg models.AppConfig, gateways []models.GatewayNet) []string {
	var cmds []string
	for _, p := range cfg.Peers {
		if !p.Enabled || len(p.PolicyRoutes) == 0 || p.PolicyRoutingTableID == 0 {
			continue
		}
		if len(models.PeerIPs(p.AllowedIPs)) == 0 {
			continue
		}

		for _, routeStr := range p.PolicyRoutes {
			parts := strings.Split(routeStr, " via ")
			if len(parts) == 2 {
				cmd := policyRouteCmd(action, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), p.PolicyRoutingTableID, gateways, p.StrictPolicyRouting)
				if cmd != "" {
					cmds = append(cmds, cmd)
				}
			}
		}
	}
	return cmds
}

// GeneratePostUpCommands returns ip rule/route commands for wg0.conf PostUp.
// Order: first create routing tables for exit nodes, then add rules for peers.
// gateways are the on-link networks policy route gateways may point into.
func GeneratePostUpCommands(cfg models.AppConfig, gateways []models.GatewayNet) []string {
	return generatePostUpCommands(cfg, gateways, nil)
}

// GeneratePostUpCommandsWithBGP renders routing hooks using the routes
// currently present in each peer's BGP Adj-RIB-Out.
func GeneratePostUpCommandsWithBGP(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string) []string {
	return generatePostUpCommands(cfg, gateways, advertisedByPeer)
}

func generatePostUpCommands(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string) []string {
	exitNodes := enabledExitNodes(cfg)

	// No early return when there are no exit nodes: custom policy routes are
	// independent of them and must still be emitted.
	cmds := exitNodeRouteCmds("replace", exitNodes)

	// NAT for anything leaving over ZeroTier.
	cmds = append(cmds, zeroTierMasquerade(cfg, gateways, advertisedByPeer, true)...)

	// Strict egress firewall chains and rules.
	cmds = append(cmds, strictFirewallCommands(cfg, gateways, true)...)

	// Policy rules for exit nodes, policy routes, and strict rejects.
	//
	// Each add is preceded by a delete of whatever holds that priority: `ip rule
	// add ... priority N` fails with EEXIST if the slot is taken, and wg-quick
	// runs hooks under `set -e`, so a leftover rule from a teardown that never
	// ran would abort the whole interface bring-up. Deleting by priority alone
	// also clears a stale rule whose selector has since changed.
	for _, r := range peerRules(cfg, exitNodes) {
		cmds = append(cmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add %s %s priority %d",
			r.IPCommand, r.Priority, r.IPCommand, r.Selector, r.Action, r.Priority))
	}

	// Add the routes that populate each peer's own policy table.
	return append(cmds, policyRouteCmds("replace", cfg, gateways)...)
}

func applyCommands(cmds []string) error {
	for _, cmd := range cmds {
		if out, err := runShellCommand(cmd); err != nil {
			return fmt.Errorf("%s: %v: %s", cmd, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Reconcile safely converges live routing and firewall state from previous to next.
// Strict policy routing reconciliation is fail-closed: affected strict sources are
// blocked by temporary FORWARD reject rules before any previous state is altered,
// and the temporary reject rules are removed only after the entire next state has
// applied successfully.
func Reconcile(previous models.AppConfig, previousGateways []models.GatewayNet, previousAdvertised map[string][]string, next models.AppConfig, nextGateways []models.GatewayNet, nextAdvertised map[string][]string) error {
	if !interfaceUp() {
		return nil
	}

	affectedStrictSources := unionSources(strictPeerSources(previous), strictPeerSources(next))

	// Step 1: Install temporary reject rules for all affected strict sources
	if len(affectedStrictSources) > 0 {
		if err := applyCommands(temporaryRejectCommands(affectedStrictSources, true)); err != nil {
			return fmt.Errorf("installing temporary strict guards: %w", err)
		}
	}

	// Step 2: Remove previous routing state (masquerade bypasses, rules, routes)
	previousExitNodes := enabledExitNodes(previous)
	var teardownCmds []string
	teardownCmds = append(teardownCmds, zeroTierMasquerade(previous, previousGateways, previousAdvertised, false)...)
	for _, r := range peerRules(previous, previousExitNodes) {
		teardownCmds = append(teardownCmds, fmt.Sprintf("%s rule del %s %s priority %d || true", r.IPCommand, r.Selector, r.Action, r.Priority))
	}
	teardownCmds = append(teardownCmds, exitNodeRouteCmds("del", previousExitNodes)...)
	teardownCmds = append(teardownCmds, policyRouteCmds("del", previous, previousGateways)...)
	if err := applyCommands(teardownCmds); err != nil {
		return fmt.Errorf("removing previous routing state: %w", err)
	}

	// Step 3: Refresh permanent strict egress chains
	if err := applyCommands(strictFirewallCommands(next, nextGateways, true)); err != nil {
		return fmt.Errorf("updating strict firewall chains: %w", err)
	}

	// Step 4: Install next routing state (exit node routes, masquerade, rules, routes)
	nextExitNodes := enabledExitNodes(next)
	var setupCmds []string
	setupCmds = append(setupCmds, exitNodeRouteCmds("replace", nextExitNodes)...)
	setupCmds = append(setupCmds, zeroTierMasquerade(next, nextGateways, nextAdvertised, true)...)
	for _, r := range peerRules(next, nextExitNodes) {
		setupCmds = append(setupCmds, fmt.Sprintf("%s rule del priority %d 2>/dev/null || true; %s rule add %s %s priority %d",
			r.IPCommand, r.Priority, r.IPCommand, r.Selector, r.Action, r.Priority))
	}
	setupCmds = append(setupCmds, policyRouteCmds("replace", next, nextGateways)...)
	if err := applyCommands(setupCmds); err != nil {
		return fmt.Errorf("installing new routing state: %w", err)
	}

	// Step 5: If all applied successfully, remove temporary reject rules
	if len(affectedStrictSources) > 0 {
		if err := applyCommands(temporaryRejectCommands(affectedStrictSources, false)); err != nil {
			return fmt.Errorf("removing temporary strict guards: %w", err)
		}
	}

	return nil
}

// GeneratePostDownCommands returns cleanup commands for wg0.conf PostDown.
// Order: first remove rules, then remove routing tables (reverse of PostUp).
func GeneratePostDownCommands(cfg models.AppConfig, gateways []models.GatewayNet) []string {
	return generatePostDownCommands(cfg, gateways, nil)
}

// GeneratePostDownCommandsWithBGP removes routing hooks rendered from the
// routes currently present in each peer's BGP Adj-RIB-Out.
func GeneratePostDownCommandsWithBGP(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string) []string {
	return generatePostDownCommands(cfg, gateways, advertisedByPeer)
}

func generatePostDownCommands(cfg models.AppConfig, gateways []models.GatewayNet, advertisedByPeer map[string][]string) []string {
	exitNodes := enabledExitNodes(cfg)

	// No early return when there are no exit nodes: custom policy routes are
	// independent of them and must still be emitted.
	cmds := zeroTierMasquerade(cfg, gateways, advertisedByPeer, false)

	// Remove policy rules first. Deleting by priority is exact, so repeated
	// apply cycles cannot leave duplicates behind.
	for _, r := range peerRules(cfg, exitNodes) {
		cmds = append(cmds, fmt.Sprintf("%s rule del %s %s priority %d || true", r.IPCommand, r.Selector, r.Action, r.Priority))
	}

	// Remove routing tables.
	cmds = append(cmds, exitNodeRouteCmds("del", exitNodes)...)

	// Remove the routes from each peer's own policy table.
	cmds = append(cmds, policyRouteCmds("del", cfg, gateways)...)

	// Strict firewall teardown.
	return append(cmds, strictFirewallCommands(cfg, gateways, false)...)
}
