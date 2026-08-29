package routing

import (
	"errors"
	"fmt"
	"slices"
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

	if !strings.Contains(up, "ip route replace 10.5.5.0/24 via 10.0.0.2 dev wg0 table 100") {
		t.Errorf("WireGuard gateway not routed over wg0:\n%s", up)
	}
	if !strings.Contains(up, "ip route replace 10.9.9.0/24 via 10.147.17.99 dev zt5u4va25t table 100 || true") {
		t.Errorf("ZeroTier gateway not routed over its zt device:\n%s", up)
	}

	down := strings.Join(GeneratePostDownCommands(cfg, gateways), "\n")
	if !strings.Contains(down, "ip route del 10.9.9.0/24 table 100 || true") {
		t.Errorf("ZeroTier route not cleaned up by prefix and table:\n%s", down)
	}
	if strings.Contains(down, "dev zt5u4va25t") {
		t.Errorf("policy route teardown depends on rediscovering its old interface:\n%s", down)
	}

	// Without ZeroTier, non-strict route falls back to wg0.
	noZT := strings.Join(GeneratePostUpCommands(cfg, models.GatewayNets(cfg.Server.Address, nil)), "\n")
	if !strings.Contains(noZT, "ip route replace 10.9.9.0/24 via 10.147.17.99 dev wg0 table 100") {
		t.Errorf("unknown non-strict gateway did not fall back to wg0:\n%s", noZT)
	}

	// Strict route with unknown gateway must NOT fall back to wg0.
	strictCfg := cfg.Clone()
	strictCfg.Peers[0].StrictPolicyRouting = true
	strictNoZT := strings.Join(GeneratePostUpCommands(strictCfg, models.GatewayNets(strictCfg.Server.Address, nil)), "\n")
	if strings.Contains(strictNoZT, "10.9.9.0/24 via 10.147.17.99 dev wg0") {
		t.Errorf("strict route with unknown gateway unexpectedly routed over wg0:\n%s", strictNoZT)
	}
}

func TestStrictEgressRulesGeneration(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24, fd00::1/64"},
		Peers: []models.Peer{
			{
				ID: "exit", Name: "exit-node", Enabled: true, AllowedIPs: "10.0.0.10/32, fd00::10/128",
				IsExitNode: true, ExitNodeRoutes: []string{"198.51.100.0/24", "2001:db8:beef::/64"}, RoutingTableID: 101,
			},
			{
				ID: "p1", Name: "strict-client", Enabled: true, AllowedIPs: "10.0.0.5/32, fd00::5/128",
				ExitNodeID:           "exit",
				PolicyRoutingTableID: 100,
				PolicyRoutes: []string{
					"10.5.5.0/24 via 10.147.17.99",
					"fd00:beef::/64 via fd00:cafe::99",
				},
				StrictPolicyRouting: true,
			},
		},
	}

	gateways := models.GatewayNets(cfg.Server.Address, []models.GatewayNet{
		{Device: "zt4v4", CIDR: "10.147.17.36/24"},
		{Device: "zt4v6", CIDR: "fd00:cafe::1/64"},
	})

	exitNodes := enabledExitNodes(cfg)
	rules := strictEgressRules(cfg, gateways, exitNodes)

	// Verify IPv4 rules for 10.0.0.5:
	// 1. exit node route (198.51.100.0/24 on wg0 -> RETURN)
	// 2. policy route (10.5.5.0/24 on zt4v4 -> RETURN)
	// 3. terminal reject (REJECT)
	// Verify IPv6 rules for fd00::5:
	// 1. exit node route (2001:db8:beef::/64 on wg0 -> RETURN)
	// 2. policy route (fd00:beef::/64 on zt4v6 -> RETURN)
	// 3. terminal reject (REJECT)

	var v4Allows, v6Allows []strictEgressRule
	var v4Rejects, v6Rejects []strictEgressRule
	for _, r := range rules {
		if !r.IsV6 {
			if r.Action == "RETURN" {
				v4Allows = append(v4Allows, r)
			} else {
				v4Rejects = append(v4Rejects, r)
			}
		} else {
			if r.Action == "RETURN" {
				v6Allows = append(v6Allows, r)
			} else {
				v6Rejects = append(v6Rejects, r)
			}
		}
	}

	if len(v4Allows) != 2 {
		t.Fatalf("v4 allow count = %d, want 2: %#v", len(v4Allows), v4Allows)
	}
	if v4Allows[0].Dest != "198.51.100.0/24" || v4Allows[0].OutDev != models.WGDevice {
		t.Errorf("v4 exit allow mismatch: %#v", v4Allows[0])
	}
	if v4Allows[1].Dest != "10.5.5.0/24" || v4Allows[1].OutDev != "zt4v4" {
		t.Errorf("v4 policy allow mismatch: %#v", v4Allows[1])
	}
	if len(v4Rejects) != 1 || v4Rejects[0].Source != "10.0.0.5" {
		t.Errorf("v4 terminal reject missing or mismatch: %#v", v4Rejects)
	}

	if len(v6Allows) != 2 {
		t.Fatalf("v6 allow count = %d, want 2: %#v", len(v6Allows), v6Allows)
	}
	if v6Allows[0].Dest != "2001:db8:beef::/64" || v6Allows[0].OutDev != models.WGDevice {
		t.Errorf("v6 exit allow mismatch: %#v", v6Allows[0])
	}
	if v6Allows[1].Dest != "fd00:beef::/64" || v6Allows[1].OutDev != "zt4v6" {
		t.Errorf("v6 policy allow mismatch: %#v", v6Allows[1])
	}
	if len(v6Rejects) != 1 || v6Rejects[0].Source != "fd00::5" {
		t.Errorf("v6 terminal reject missing or mismatch: %#v", v6Rejects)
	}
}

func TestStrictEgressUnresolvedGatewayEmitsNoAllow(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{
			{
				ID: "p1", Name: "strict-client", Enabled: true, AllowedIPs: "10.0.0.5/32",
				PolicyRoutingTableID: 100,
				PolicyRoutes:         []string{"10.5.5.0/24 via 10.147.17.99"},
				StrictPolicyRouting:  true,
			},
		},
	}

	// No ZeroTier gateway known
	gateways := models.GatewayNets(cfg.Server.Address, nil)
	rules := strictEgressRules(cfg, gateways, nil)

	// Should only have the terminal reject, no allow rule
	if len(rules) != 1 || rules[0].Action != "REJECT" {
		t.Fatalf("unresolved gateway emitted rules: %#v", rules)
	}
}

func TestStrictFirewallCommandsPostUpAndPostDown(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{
			{
				ID: "p1", Name: "strict", Enabled: true, AllowedIPs: "10.0.0.5/32",
				PolicyRoutingTableID: 100, PolicyRoutes: []string{"10.5.5.0/24 via 10.0.0.2"},
				StrictPolicyRouting: true,
			},
		},
	}
	gateways := models.GatewayNets(cfg.Server.Address, nil)

	up := strings.Join(GeneratePostUpCommands(cfg, gateways), "\n")
	for _, want := range []string{
		"iptables -w -N WG_BUSY_STRICT4",
		"iptables -w -C FORWARD -i wg0 -j WG_BUSY_STRICT4 2>/dev/null || iptables -w -I FORWARD 1 -i wg0 -j WG_BUSY_STRICT4",
		"iptables -w -F WG_BUSY_STRICT4",
		"iptables -w -A WG_BUSY_STRICT4 -s 10.0.0.5 -d 10.5.5.0/24 -o wg0 -j RETURN",
		"iptables -w -A WG_BUSY_STRICT4 -s 10.0.0.5 -j REJECT --reject-with icmp-admin-prohibited",
		"ip6tables -w -N WG_BUSY_STRICT6",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("PostUp missing %q:\n%s", want, up)
		}
	}

	down := strings.Join(GeneratePostDownCommands(cfg, gateways), "\n")
	for _, want := range []string{
		"iptables -w -D FORWARD -i wg0 -j WG_BUSY_STRICT4",
		"iptables -w -F WG_BUSY_STRICT4",
		"iptables -w -X WG_BUSY_STRICT4",
		"ip6tables -w -D FORWARD -i wg0 -j WG_BUSY_STRICT6",
		"ip6tables -w -F WG_BUSY_STRICT6",
		"ip6tables -w -X WG_BUSY_STRICT6",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("PostDown missing %q:\n%s", want, down)
		}
	}
}

func TestStagedReconcileTemporaryGuardsOrder(t *testing.T) {
	previous := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{{
			ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
			PolicyRoutingTableID: 100, PolicyRoutes: []string{"10.5.5.0/24 via 10.0.0.2"},
			StrictPolicyRouting: true,
		}},
	}
	next := previous.Clone()
	next.Peers[0].PolicyRoutes = []string{"10.6.6.0/24 via 10.0.0.2"}

	originalUp, originalRun := interfaceUp, runShellCommand
	t.Cleanup(func() { interfaceUp, runShellCommand = originalUp, originalRun })
	interfaceUp = func() bool { return true }
	var commands []string
	runShellCommand = func(command string) ([]byte, error) {
		commands = append(commands, command)
		return nil, nil
	}

	gateways := models.GatewayNets(previous.Server.Address, nil)
	if err := Reconcile(previous, gateways, nil, next, gateways, nil); err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(commands, "\n")
	tempGuardAdd := strings.Index(joined, "iptables -w -I FORWARD 1 -i wg0 -s 10.0.0.5 -m comment --comment 'wg-busy strict apply' -j REJECT")
	delOldRule := strings.Index(joined, "ip rule del from 10.0.0.5 prohibit")
	addNewRule := strings.Index(joined, "ip rule add from 10.0.0.5 prohibit")
	tempGuardDel := strings.Index(joined, "iptables -w -D FORWARD -i wg0 -s 10.0.0.5 -m comment --comment 'wg-busy strict apply'")

	if tempGuardAdd < 0 {
		t.Fatalf("temporary guard was not installed:\n%s", joined)
	}
	if delOldRule < 0 || addNewRule < 0 {
		t.Fatalf("old rule del (%d) or new rule add (%d) missing:\n%s", delOldRule, addNewRule, joined)
	}
	if tempGuardDel < 0 {
		t.Fatalf("temporary guard was not removed:\n%s", joined)
	}

	if tempGuardAdd > delOldRule {
		t.Fatalf("temporary guard was installed after previous rules were removed:\n%s", joined)
	}
	if tempGuardDel < addNewRule {
		t.Fatalf("temporary guard was removed before new rules were added:\n%s", joined)
	}
}

func TestStagedReconcileFailureLeavesRejectActive(t *testing.T) {
	previous := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{{
			ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
			PolicyRoutingTableID: 100, PolicyRoutes: []string{"10.5.5.0/24 via 10.0.0.2"},
			StrictPolicyRouting: true,
		}},
	}
	next := previous.Clone()
	next.Peers[0].AllowedIPs = "10.0.0.9/32"

	originalUp, originalRun := interfaceUp, runShellCommand
	t.Cleanup(func() { interfaceUp, runShellCommand = originalUp, originalRun })
	interfaceUp = func() bool { return true }
	failed := false
	var commands []string
	runShellCommand = func(command string) ([]byte, error) {
		commands = append(commands, command)
		if !failed && strings.Contains(command, "ip rule add from 10.0.0.9") {
			failed = true
			return []byte("boom"), errors.New("exit 1")
		}
		return nil, nil
	}

	gateways := models.GatewayNets(previous.Server.Address, nil)
	if err := Reconcile(previous, gateways, nil, next, gateways, nil); err == nil {
		t.Fatal("Reconcile succeeded after command failure")
	}

	joined := strings.Join(commands, "\n")
	// Must have installed temporary guards for affected sources (10.0.0.5 and 10.0.0.9)
	if !strings.Contains(joined, "-s 10.0.0.5 -m comment --comment 'wg-busy strict apply' -j REJECT") {
		t.Fatalf("temporary guard not installed for previous source:\n%s", joined)
	}
	if !strings.Contains(joined, "-s 10.0.0.9 -m comment --comment 'wg-busy strict apply' -j REJECT") {
		t.Fatalf("temporary guard not installed for next source:\n%s", joined)
	}
	// Must NOT have removed temporary guards on failure
	if strings.Contains(joined, "-D FORWARD -i wg0 -s 10.0.0.5 -m comment --comment 'wg-busy strict apply'") ||
		strings.Contains(joined, "-D FORWARD -i wg0 -s 10.0.0.9 -m comment --comment 'wg-busy strict apply'") {
		t.Fatalf("temporary guard was removed despite apply failure:\n%s", joined)
	}
}

func TestReconcileStrictToNonStrictOrdering(t *testing.T) {
	previous := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{{
			ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
			PolicyRoutingTableID: 100, PolicyRoutes: []string{"10.5.5.0/24 via 10.0.0.2"},
			StrictPolicyRouting: true,
		}},
	}
	next := previous.Clone()
	next.Peers[0].StrictPolicyRouting = false

	originalUp, originalRun := interfaceUp, runShellCommand
	t.Cleanup(func() { interfaceUp, runShellCommand = originalUp, originalRun })
	interfaceUp = func() bool { return true }
	var commands []string
	runShellCommand = func(command string) ([]byte, error) {
		commands = append(commands, command)
		return nil, nil
	}

	gateways := models.GatewayNets(previous.Server.Address, nil)
	if err := Reconcile(previous, gateways, nil, next, gateways, nil); err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(commands, "\n")
	guardAdd := strings.Index(joined, "iptables -w -I FORWARD 1 -i wg0 -s 10.0.0.5 -m comment --comment 'wg-busy strict apply'")
	delProhibit := strings.Index(joined, "ip rule del from 10.0.0.5 prohibit")
	addNewRule := strings.Index(joined, "ip rule add from 10.0.0.5 table 100")
	guardDel := strings.Index(joined, "iptables -w -D FORWARD -i wg0 -s 10.0.0.5 -m comment --comment 'wg-busy strict apply'")

	if guardAdd < 0 || delProhibit < 0 || addNewRule < 0 || guardDel < 0 {
		t.Fatalf("missing required transition commands:\n%s", joined)
	}
	if guardAdd > delProhibit || guardDel < addNewRule {
		t.Fatalf("strict-to-non-strict unguarded window detected:\n%s", joined)
	}
}

func TestReconcileNonStrictToStrictOrdering(t *testing.T) {
	previous := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{{
			ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
			PolicyRoutingTableID: 100, PolicyRoutes: []string{"10.5.5.0/24 via 10.0.0.2"},
			StrictPolicyRouting: false,
		}},
	}
	next := previous.Clone()
	next.Peers[0].StrictPolicyRouting = true

	originalUp, originalRun := interfaceUp, runShellCommand
	t.Cleanup(func() { interfaceUp, runShellCommand = originalUp, originalRun })
	interfaceUp = func() bool { return true }
	var commands []string
	runShellCommand = func(command string) ([]byte, error) {
		commands = append(commands, command)
		return nil, nil
	}

	gateways := models.GatewayNets(previous.Server.Address, nil)
	if err := Reconcile(previous, gateways, nil, next, gateways, nil); err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(commands, "\n")
	guardAdd := strings.Index(joined, "iptables -w -I FORWARD 1 -i wg0 -s 10.0.0.5 -m comment --comment 'wg-busy strict apply'")
	addProhibit := strings.Index(joined, "ip rule add from 10.0.0.5 prohibit")
	guardDel := strings.Index(joined, "iptables -w -D FORWARD -i wg0 -s 10.0.0.5 -m comment --comment 'wg-busy strict apply'")

	if guardAdd < 0 || addProhibit < 0 || guardDel < 0 {
		t.Fatalf("missing required transition commands:\n%s", joined)
	}
	if guardAdd > addProhibit || guardDel < addProhibit {
		t.Fatalf("non-strict-to-strict unguarded window detected:\n%s", joined)
	}
}

// Strict mode must reject unmatched traffic *after* the peer's own tables are
// consulted. Priorities are explicit because `ip rule add` without one counts
// down, which would put the reject first and blackhole the peer entirely.
func TestStrictPolicyRoutingOrder(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{{
			ID: "p1", Name: "locked", Enabled: true, AllowedIPs: "10.0.0.5/32",
			PolicyRoutingTableID: 100,
			PolicyRoutes:         []string{"10.5.5.0/24 via 10.0.0.2"},
			StrictPolicyRouting:  true,
		}},
	}
	gateways := models.GatewayNets(cfg.Server.Address, nil)

	var lookupPrio, rejectPrio int
	for _, cmd := range GeneratePostUpCommands(cfg, gateways) {
		var prio int
		switch {
		case strings.Contains(cmd, "from 10.0.0.5 table 100 priority"):
			fmt.Sscanf(cmd[strings.LastIndex(cmd, "priority "):], "priority %d", &prio)
			lookupPrio = prio
		case strings.Contains(cmd, "from 10.0.0.5 prohibit priority"):
			fmt.Sscanf(cmd[strings.LastIndex(cmd, "priority "):], "priority %d", &prio)
			rejectPrio = prio
		}
	}

	if lookupPrio == 0 {
		t.Fatal("no table lookup rule emitted for the strict peer")
	}
	if rejectPrio == 0 {
		t.Fatal("no reject rule emitted for the strict peer")
	}
	if lookupPrio >= rejectPrio {
		t.Errorf("reject (priority %d) is evaluated before the table lookup (priority %d): all traffic would be dropped", rejectPrio, lookupPrio)
	}
	// Both must be consulted before the kernel's main table at 32766.
	if rejectPrio >= 32766 {
		t.Errorf("reject priority %d is not before main (32766); traffic would leak", rejectPrio)
	}

	// PostDown must remove exactly what PostUp added, priorities included.
	up := GeneratePostUpCommands(cfg, gateways)
	down := GeneratePostDownCommands(cfg, gateways)
	for _, cmd := range up {
		i := strings.Index(cmd, "ip rule add ")
		if i < 0 {
			continue
		}
		want := strings.Replace(cmd[i:], "ip rule add ", "ip rule del ", 1) + " || true"
		if !slices.Contains(down, want) {
			t.Errorf("PostUp %q has no matching PostDown %q", cmd, want)
		}
	}
}

func TestStrictPolicyRoutingCoversEveryAddressFamily(t *testing.T) {
	cfg := models.AppConfig{Peers: []models.Peer{{
		ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32, fd00::5/128",
		PolicyRoutingTableID: 100,
		PolicyRoutes:         []string{"10.5.5.0/24 via 10.0.0.2"},
		StrictPolicyRouting:  true,
	}}}

	commands := strings.Join(GeneratePostUpCommands(cfg, nil), "\n")
	for _, want := range []string{
		"ip rule add from 10.0.0.5 prohibit",
		"ip -6 rule add from fd00::5 prohibit",
	} {
		if !strings.Contains(commands, want) {
			t.Errorf("missing %q:\n%s", want, commands)
		}
	}
}

func TestStrictPolicyRoutingCoversAuthorizedSourceSubnet(t *testing.T) {
	cfg := models.AppConfig{Peers: []models.Peer{{
		ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32, 192.168.50.0/24",
		PolicyRoutingTableID: 100,
		PolicyRoutes:         []string{"10.5.5.0/24 via 10.0.0.2"},
		StrictPolicyRouting:  true,
	}}}
	commands := strings.Join(GeneratePostUpCommands(cfg, nil), "\n")
	if !strings.Contains(commands, "ip rule add from 192.168.50.0/24 prohibit") {
		t.Fatalf("authorized source subnet bypasses strict routing:\n%s", commands)
	}
}

func TestFullExitNodeBuildsBothAddressFamilyRoutes(t *testing.T) {
	cfg := models.AppConfig{Peers: []models.Peer{{
		ID: "exit", Enabled: true, AllowedIPs: "10.0.0.6/32, fd00::6/128",
		IsExitNode: true, ExitNodeAllowAll: true, RoutingTableID: 100,
	}}}
	commands := strings.Join(GeneratePostUpCommands(cfg, nil), "\n")
	for _, want := range []string{
		"ip -4 route replace default dev wg0 table 100",
		"ip -6 route replace default dev wg0 table 100",
	} {
		if !strings.Contains(commands, want) {
			t.Errorf("missing %q:\n%s", want, commands)
		}
	}
}

// A rule priority that is already taken makes `ip rule add` fail with EEXIST,
// and wg-quick runs hooks under set -e — so a leftover rule from a teardown that
// never ran would abort the whole interface bring-up. Every add must therefore
// clear its slot first.
func TestRuleAddIsIdempotent(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{{
			ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
			PolicyRoutingTableID: 100,
			PolicyRoutes:         []string{"10.5.5.0/24 via 10.0.0.2"},
		}},
	}

	for _, cmd := range GeneratePostUpCommands(cfg, models.GatewayNets(cfg.Server.Address, nil)) {
		if strings.Contains(cmd, "ip rule add ") && !strings.Contains(cmd, "ip rule del priority ") {
			t.Errorf("rule add does not free its priority first, so a stale rule aborts wg-quick up: %s", cmd)
		}
		// Routes into a table have the same hazard; replace is idempotent, add is not.
		if strings.Contains(cmd, "ip route add ") {
			t.Errorf("use `ip route replace` so an existing route does not abort bring-up: %s", cmd)
		}
	}
}

// Without strict mode no reject rule is emitted, so unmatched traffic keeps
// falling back to the main table as before.
func TestNonStrictHasNoRejectRule(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{{
			ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
			PolicyRoutingTableID: 100,
			PolicyRoutes:         []string{"10.5.5.0/24 via 10.0.0.2"},
		}},
	}
	for _, cmd := range GeneratePostUpCommands(cfg, models.GatewayNets(cfg.Server.Address, nil)) {
		if strings.Contains(cmd, "prohibit") {
			t.Errorf("unexpected reject rule for a non-strict peer: %s", cmd)
		}
	}
}

func TestStrictMissingExitNodeFailsClosed(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{{
			ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
			ExitNodeID: "missing", StrictPolicyRouting: true,
		}},
	}
	commands := strings.Join(GeneratePostUpCommands(cfg, models.GatewayNets(cfg.Server.Address, nil)), "\n")
	if !strings.Contains(commands, "from 10.0.0.5 prohibit") {
		t.Fatalf("invalid strict config falls through to main:\n%s", commands)
	}
}

// A strict peer that also uses an exit node must consult both of its tables
// before the reject.
func TestStrictWithExitNode(t *testing.T) {
	cfg := models.AppConfig{
		Server: models.ServerConfig{Address: "10.0.0.1/24"},
		Peers: []models.Peer{
			{
				ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32", ExitNodeID: "p2",
				PolicyRoutingTableID: 100,
				PolicyRoutes:         []string{"10.5.5.0/24 via 10.0.0.2"},
				StrictPolicyRouting:  true,
			},
			{ID: "p2", Enabled: true, AllowedIPs: "10.0.0.6/32", IsExitNode: true, ExitNodeAllowAll: true, RoutingTableID: 101},
		},
	}

	var order []string
	for _, cmd := range GeneratePostUpCommands(cfg, models.GatewayNets(cfg.Server.Address, nil)) {
		if strings.Contains(cmd, "ip rule add from 10.0.0.5") {
			order = append(order, cmd)
		}
	}
	if len(order) != 3 {
		t.Fatalf("expected exit-node lookup, policy lookup and reject; got %d:\n%s", len(order), strings.Join(order, "\n"))
	}
	if !strings.Contains(order[2], "prohibit") {
		t.Errorf("reject is not last:\n%s", strings.Join(order, "\n"))
	}
}

// Traffic leaving over ZeroTier carries a source the ZeroTier network cannot
// route back to, so it has to be masqueraded.
func TestZeroTierMasquerade(t *testing.T) {
	cfg := models.AppConfig{
		Server:   models.ServerConfig{Address: "10.0.0.1/24"},
		ZeroTier: models.ZeroTierConfig{Enabled: true},
		Peers: []models.Peer{{
			ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
			PolicyRoutingTableID: 100,
			PolicyRoutes:         []string{"10.9.9.0/24 via 10.147.17.99"},
		}},
	}
	gateways := models.GatewayNets(cfg.Server.Address, nil)

	up := strings.Join(GeneratePostUpCommands(cfg, gateways), "\n")
	if !strings.Contains(up, "iptables -t nat -A POSTROUTING -o zt+ -j MASQUERADE") {
		t.Errorf("no masquerade rule for ZeroTier egress:\n%s", up)
	}
	// Applying twice must not stack duplicates.
	if !strings.Contains(up, "iptables -t nat -C POSTROUTING -o zt+ -j MASQUERADE") {
		t.Errorf("masquerade rule is added unconditionally, so repeated applies would duplicate it:\n%s", up)
	}

	down := strings.Join(GeneratePostDownCommands(cfg, gateways), "\n")
	if !strings.Contains(down, "iptables -t nat -D POSTROUTING -o zt+ -j MASQUERADE") {
		t.Errorf("masquerade rule is never removed:\n%s", down)
	}
	// An already-removed rule must not abort the teardown under wg-quick's set -e.
	if !strings.Contains(down, "MASQUERADE || true") {
		t.Errorf("masquerade teardown is not guarded:\n%s", down)
	}

	// With ZeroTier off there is nothing to NAT.
	cfg.ZeroTier.Enabled = false
	off := strings.Join(GeneratePostUpCommands(cfg, gateways), "\n") +
		strings.Join(GeneratePostDownCommands(cfg, gateways), "\n")
	if strings.Contains(off, "MASQUERADE") {
		t.Errorf("masquerade rule emitted while ZeroTier is disabled:\n%s", off)
	}

	// Existing configurations default to masquerading, but the ZeroTier setting
	// can explicitly disable it when the remote network has a return route.
	cfg.ZeroTier.Enabled = true
	cfg.ZeroTier.DisableMasquerade = true
	disabled := strings.Join(GeneratePostUpCommands(cfg, gateways), "\n") +
		strings.Join(GeneratePostDownCommands(cfg, gateways), "\n")
	if strings.Contains(disabled, "MASQUERADE") {
		t.Errorf("masquerade rule emitted while the option is disabled:\n%s", disabled)
	}
}

func TestZeroTierMasqueradeBypassesAdvertisedNetworksFirst(t *testing.T) {
	cfg := models.AppConfig{
		ZeroTier: models.ZeroTierConfig{
			Enabled:                               true,
			ExcludeAdvertisedRoutesFromMasquerade: true,
		},
		Peers: []models.Peer{{Enabled: true, AdvertisedRoutes: []string{"10.7.77.0/24"}}},
	}
	gateways := []models.GatewayNet{{Device: "ztabc", CIDR: "10.147.17.48/24"}}
	advertised := map[string][]string{
		"10.147.17.250": {"10.7.31.7/24", "10.7.31.0/24", "10.7.32.0/24", "2001:db8::/64"},
		"10.0.0.2":      {"198.51.100.0/24"}, // WireGuard BGP peer, not ZeroTier.
	}

	up := strings.Join(GeneratePostUpCommandsWithBGP(cfg, gateways, advertised), "\n")
	accept := "iptables -t nat -I POSTROUTING 1 -s 10.7.31.0/24 -o zt+ -j ACCEPT"
	masquerade := "iptables -t nat -A POSTROUTING -o zt+ -j MASQUERADE"
	if strings.Count(up, accept) != 1 {
		t.Fatalf("advertised network bypass rule count = %d, want 1:\n%s", strings.Count(up, accept), up)
	}
	if strings.Index(up, accept) > strings.Index(up, masquerade) {
		t.Fatalf("advertised network bypass is after masquerade:\n%s", up)
	}
	if !strings.Contains(up, "-s 10.7.32.0/24 -o zt+ -j ACCEPT") {
		t.Fatalf("second route advertised to ZeroTier peer is not bypassed:\n%s", up)
	}
	for _, excluded := range []string{"10.7.77.0/24", "2001:db8::/64", "198.51.100.0/24"} {
		if strings.Contains(up, excluded) {
			t.Errorf("unexpected bypass for %s:\n%s", excluded, up)
		}
	}

	down := strings.Join(GeneratePostDownCommandsWithBGP(cfg, gateways, advertised), "\n")
	if !strings.Contains(down, "iptables -t nat -D POSTROUTING -s 10.7.31.0/24 -o zt+ -j ACCEPT || true") {
		t.Fatalf("advertised network bypass is never removed:\n%s", down)
	}
}

func TestReconcileReplacesWithdrawnBGPRouteBypasses(t *testing.T) {
	cfg := models.AppConfig{ZeroTier: models.ZeroTierConfig{
		Enabled:                               true,
		ExcludeAdvertisedRoutesFromMasquerade: true,
	}}
	gateways := []models.GatewayNet{{Device: "ztabc", CIDR: "10.147.17.48/24"}}
	previous := map[string][]string{"10.147.17.250": {"10.7.31.0/24"}}
	next := map[string][]string{"10.147.17.250": {"10.7.32.0/24"}}

	originalUp, originalRun := interfaceUp, runShellCommand
	t.Cleanup(func() { interfaceUp, runShellCommand = originalUp, originalRun })
	interfaceUp = func() bool { return true }
	var commands []string
	runShellCommand = func(command string) ([]byte, error) {
		commands = append(commands, command)
		return nil, nil
	}

	if err := Reconcile(cfg, gateways, previous, cfg, gateways, next); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	remove := strings.Index(joined, "-D POSTROUTING -s 10.7.31.0/24")
	add := strings.Index(joined, "-I POSTROUTING 1 -s 10.7.32.0/24")
	if remove < 0 || add < 0 || remove > add {
		t.Fatalf("withdrawn bypass was not replaced before the new one:\n%s", joined)
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
	if !strings.Contains(joined, "ip route replace 10.5.5.0/24 via 10.0.0.2 dev wg0 table 100") {
		t.Errorf("policy route missing:\n%s", joined)
	}

	if len(GeneratePostDownCommands(cfg, gateways)) == 0 {
		t.Error("no PostDown commands emitted; routes would leak on interface down")
	}
}
