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

	// Without ZeroTier the same route falls back to wg0 rather than emitting an
	// empty device, which would be a syntax error at apply time.
	noZT := strings.Join(GeneratePostUpCommands(cfg, models.GatewayNets(cfg.Server.Address, nil)), "\n")
	if !strings.Contains(noZT, "ip route replace 10.9.9.0/24 via 10.147.17.99 dev wg0 table 100") {
		t.Errorf("unknown gateway did not fall back to wg0:\n%s", noZT)
	}
}

func TestReconcileRemovesPreviousRulesBeforeAddingNext(t *testing.T) {
	previous := models.AppConfig{Peers: []models.Peer{{
		ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
		PolicyRoutingTableID: 100, PolicyRoutes: []string{"10.5.5.0/24 via 10.0.0.2"},
		StrictPolicyRouting: true,
	}}}
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
	if err := Reconcile(previous, nil, next, nil); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commands, "\n")
	deleteAt := strings.Index(joined, "ip rule del from 10.0.0.5 prohibit")
	addAt := strings.Index(joined, "ip rule add from 10.0.0.5 table 100")
	if deleteAt < 0 || addAt < 0 || deleteAt > addAt {
		t.Fatalf("previous strict rule was not removed before next state:\n%s", joined)
	}
}

func TestReconcileRestoresPreviousStateOnFailure(t *testing.T) {
	previous := models.AppConfig{Peers: []models.Peer{{
		ID: "p1", Enabled: true, AllowedIPs: "10.0.0.5/32",
		PolicyRoutingTableID: 100, PolicyRoutes: []string{"10.5.5.0/24 via 10.0.0.2"},
	}}}
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
	if err := Reconcile(previous, nil, next, nil); err == nil {
		t.Fatal("Reconcile succeeded after command failure")
	}
	if !strings.Contains(strings.Join(commands, "\n"), "ip rule add from 10.0.0.5") {
		t.Fatalf("previous state was not restored:\n%s", strings.Join(commands, "\n"))
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
