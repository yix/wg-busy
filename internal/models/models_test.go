package models

import (
	"errors"
	"strings"
	"testing"
)

// A policy route becomes "ip route add <cidr> via <gw> dev <iface>", so the
// gateway must be on-link for an interface we manage — the WireGuard subnet or
// a joined ZeroTier network — or the kernel rejects it at apply time.
func TestValidatePolicyRouteGateway(t *testing.T) {
	ztNets := []GatewayNet{{Device: "zt5u4va25t", CIDR: "10.147.17.36/24"}}

	tests := []struct {
		name       string
		route      string
		serverAddr string
		zt         []GatewayNet
		wantErr    bool
	}{
		{"gateway in wg subnet", "10.5.5.0/24 via 10.0.0.2", "10.0.0.1/24", nil, false},
		{"gateway outside every subnet", "10.5.5.0/24 via 8.8.8.8", "10.0.0.1/24", nil, true},
		{"gateway in second wg subnet", "10.5.5.0/24 via 192.168.9.7", "10.0.0.1/24, 192.168.9.1/24", nil, false},
		{"gateway in zerotier subnet", "10.5.5.0/24 via 10.147.17.99", "10.0.0.1/24", ztNets, false},
		{"zerotier gateway without zerotier", "10.5.5.0/24 via 10.147.17.99", "10.0.0.1/24", nil, true},
		{"no gateways known skips check", "10.5.5.0/24 via 8.8.8.8", "", nil, false},
		{"server address unparseable skips check", "10.5.5.0/24 via 8.8.8.8", "not-a-cidr", nil, false},
		{"malformed route", "10.5.5.0/24 8.8.8.8", "10.0.0.1/24", nil, true},
		{"bad gateway ip", "10.5.5.0/24 via nope", "10.0.0.1/24", nil, true},
		{"bad cidr", "10.5.5.0 via 10.0.0.2", "10.0.0.1/24", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPeer()
			p.PolicyRoutes = []string{tt.route}

			var got bool
			for _, e := range p.Validate(GatewayNets(tt.serverAddr, tt.zt)) {
				if e.Field == "policyRoutes" {
					got = true
					t.Logf("policyRoutes: %s", e.Message)
				}
			}
			if got != tt.wantErr {
				t.Errorf("policyRoutes error = %v, want %v", got, tt.wantErr)
			}
		})
	}
}

// The gateway decides which interface the route is pinned to.
func TestDeviceForGateway(t *testing.T) {
	nets := GatewayNets("10.0.0.1/24", []GatewayNet{
		{Device: "zt5u4va25t", CIDR: "10.147.17.36/24"},
		{Device: "ztabcdef12", CIDR: "192.168.191.5/16"},
	})

	tests := []struct {
		gateway string
		want    string
	}{
		{"10.0.0.9", WGDevice},
		{"10.147.17.99", "zt5u4va25t"},
		{"192.168.4.4", "ztabcdef12"},
		{"8.8.8.8", ""},
		{"not-an-ip", ""},
	}

	for _, tt := range tests {
		if got := DeviceForGateway(tt.gateway, nets); got != tt.want {
			t.Errorf("DeviceForGateway(%q) = %q, want %q", tt.gateway, got, tt.want)
		}
	}
}

func TestResolveGatewayLongestPrefixAndAmbiguity(t *testing.T) {
	nets := []GatewayNet{
		{Device: "wg0", CIDR: "10.0.0.0/16"},
		{Device: "zt1", CIDR: "10.0.1.0/24"},
		{Device: "zt2", CIDR: "192.168.1.0/24"},
		{Device: "zt3", CIDR: "192.168.1.0/24"},
		{Device: "zt4", CIDR: "172.16.0.0/24"},
		{Device: "zt4", CIDR: "172.16.0.0/24"}, // same device, duplicate CIDR
	}

	// Longest prefix match: 10.0.1.5 matches 10.0.0.0/16 (wg0) and 10.0.1.0/24 (zt1) -> zt1
	dev, err := ResolveGateway("10.0.1.5", nets)
	if err != nil || dev != "zt1" {
		t.Fatalf("ResolveGateway(10.0.1.5) = %q, err = %v; want zt1, nil", dev, err)
	}

	// Ambiguous match: 192.168.1.5 matches zt2 (/24) and zt3 (/24)
	_, err = ResolveGateway("192.168.1.5", nets)
	if err == nil || !errors.Is(err, ErrGatewayAmbiguous) {
		t.Fatalf("ResolveGateway(192.168.1.5) err = %v; want ErrGatewayAmbiguous", err)
	}
	if DeviceForGateway("192.168.1.5", nets) != "" {
		t.Fatalf("DeviceForGateway for ambiguous gateway returned %q, want empty", DeviceForGateway("192.168.1.5", nets))
	}

	// Equal prefix length pointing to the same device is not ambiguous
	dev, err = ResolveGateway("172.16.0.5", nets)
	if err != nil || dev != "zt4" {
		t.Fatalf("ResolveGateway(172.16.0.5) = %q, err = %v; want zt4, nil", dev, err)
	}

	// Unresolved match
	_, err = ResolveGateway("8.8.8.8", nets)
	if err == nil || !errors.Is(err, ErrGatewayUnresolved) {
		t.Fatalf("ResolveGateway(8.8.8.8) err = %v; want ErrGatewayUnresolved", err)
	}
}

func TestPeerIPsReturnsEveryUniqueAddress(t *testing.T) {
	want := []string{"10.0.0.5", "fd00::5"}
	got := PeerIPs("10.0.0.5/32, fd00::5/128, 10.0.0.5/32")
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("PeerIPs() = %v, want %v", got, want)
	}
}

func TestPeerSourcesRetainsAuthorizedSubnets(t *testing.T) {
	want := []string{"10.0.0.5", "192.168.50.0/24", "fd00::5"}
	got := PeerSources("10.0.0.5/32, 192.168.50.8/24, fd00::5/128")
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("PeerSources() = %v, want %v", got, want)
	}
}

// validPeer returns a peer that passes validation, so tests only assert on the
// field they change.
func validPeer() Peer {
	key := "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEf0="
	return Peer{
		Name:       "test",
		PrivateKey: key,
		PublicKey:  key,
		AllowedIPs: "10.0.0.5/32",
	}
}

// Strict mode with nothing to match would block the peer entirely, so it must
// be rejected rather than silently locking the peer out.
func TestStrictPolicyRoutingValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Peer)
		wantErr bool
	}{
		{"strict with a policy route", func(p *Peer) {
			p.StrictPolicyRouting = true
			p.PolicyRoutes = []string{"10.5.5.0/24 via 10.0.0.2"}
		}, false},
		{"strict with an exit node", func(p *Peer) {
			p.StrictPolicyRouting = true
			p.ExitNodeID = "some-exit-node"
		}, false},
		{"strict with neither", func(p *Peer) { p.StrictPolicyRouting = true }, true},
		{"not strict with neither", func(p *Peer) {}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPeer()
			tt.mutate(&p)

			var got bool
			for _, e := range p.Validate(GatewayNets("10.0.0.1/24", nil)) {
				if e.Field == "strictPolicyRouting" {
					got = true
					t.Logf("strictPolicyRouting: %s", e.Message)
				}
			}
			if got != tt.wantErr {
				t.Errorf("strictPolicyRouting error = %v, want %v", got, tt.wantErr)
			}
		})
	}
}

func TestZeroTierValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ZeroTierConfig
		wantErr bool
	}{
		{"valid", ZeroTierConfig{Networks: []ZeroTierNetwork{{ID: "8056c2e21c000001"}}}, false},
		{"uppercase id", ZeroTierConfig{Networks: []ZeroTierNetwork{{ID: "8056C2E21C000001"}}}, false},
		{"empty config", ZeroTierConfig{}, false},
		{"default port", ZeroTierConfig{Port: 0}, false},
		{"custom port", ZeroTierConfig{Port: 9994}, false},
		{"privileged port", ZeroTierConfig{Port: 80}, true},
		{"missing id", ZeroTierConfig{Networks: []ZeroTierNetwork{{ID: ""}}}, true},
		{"short id", ZeroTierConfig{Networks: []ZeroTierNetwork{{ID: "8056c2e21c00"}}}, true},
		{"non-hex id", ZeroTierConfig{Networks: []ZeroTierNetwork{{ID: "8056c2e21c00000z"}}}, true},
		{"duplicate ids", ZeroTierConfig{Networks: []ZeroTierNetwork{
			{ID: "8056c2e21c000001"}, {ID: "8056C2E21C000001"},
		}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("Validate() = %v, want error: %v", errs, tt.wantErr)
			}
		})
	}
}

func TestZeroTierPortDefault(t *testing.T) {
	var z ZeroTierConfig
	if got := z.ZeroTierPort(); got != 9993 {
		t.Errorf("default port = %d, want 9993", got)
	}
	z.Port = 9994
	if got := z.ZeroTierPort(); got != 9994 {
		t.Errorf("configured port = %d, want 9994", got)
	}
}

func TestValidPeerHasNoErrors(t *testing.T) {
	p := validPeer()
	if errs := p.Validate(GatewayNets("10.0.0.1/24", nil)); len(errs) > 0 {
		t.Fatalf("expected no errors, got: %v", errs)
	}
}

func TestAppConfigCloneIsIndependent(t *testing.T) {
	original := AppConfig{
		Peers: []Peer{{
			ID: "p1", ExitNodeRoutes: []string{"10.0.0.0/8"},
			AdvertisedRoutes: []string{"192.0.2.0/24"},
			PolicyRoutes:     []string{"198.51.100.0/24 via 10.0.0.2"},
		}},
		BGPPeers: []BGPPeer{{
			ID: "bgp1", Name: "bgp1",
			RouteFilters: []RouteFilter{{Prefix: "203.0.113.0/24"}},
		}},
		ZeroTier: ZeroTierConfig{Networks: []ZeroTierNetwork{{ID: "8056c2e21c000001", Name: "old"}}},
	}
	clone := original.Clone()
	clone.Peers[0].ExitNodeRoutes[0] = "changed"
	clone.Peers[0].AdvertisedRoutes[0] = "changed"
	clone.Peers[0].PolicyRoutes[0] = "changed"
	clone.BGPPeers[0].RouteFilters[0].Prefix = "changed"
	clone.ZeroTier.Networks[0].Name = "changed"

	if original.Peers[0].ExitNodeRoutes[0] == "changed" ||
		original.Peers[0].AdvertisedRoutes[0] == "changed" ||
		original.Peers[0].PolicyRoutes[0] == "changed" ||
		original.BGPPeers[0].RouteFilters[0].Prefix == "changed" ||
		original.ZeroTier.Networks[0].Name == "changed" {
		t.Fatal("Clone shares mutable slices with the original")
	}
}

func TestValidateExitNodeRefs(t *testing.T) {
	tests := []struct {
		name string
		exit Peer
		want bool
	}{
		{"enabled exit node", Peer{ID: "exit", Enabled: true, IsExitNode: true}, false},
		{"disabled exit node", Peer{ID: "exit", Enabled: false, IsExitNode: true}, true},
		{"ordinary peer", Peer{ID: "exit", Enabled: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers := []Peer{{ID: "client", Enabled: true, ExitNodeID: "exit", StrictPolicyRouting: true}, tt.exit}
			if got := len(ValidateExitNodeRefs(peers)) > 0; got != tt.want {
				t.Fatalf("validation error = %v, want %v", got, tt.want)
			}
		})
	}
	if errs := ValidateExitNodeRefs([]Peer{{ID: "client", ExitNodeID: "missing"}}); !errs.HasField("exitNodeID") {
		t.Fatalf("missing reference errors = %v, want exitNodeID", errs)
	}
}

func TestValidateConfigRejectsStrictPeerAfterExitCascade(t *testing.T) {
	exit := validPeer()
	exit.ID, exit.Name, exit.PublicKey = "exit", "exit", testKey("B")
	exit.AllowedIPs = "10.0.0.6/32"
	exit.Enabled, exit.IsExitNode, exit.RoutingTableID = true, true, 100
	client := validPeer()
	client.ID, client.Name, client.PublicKey = "client", "client", testKey("C")
	client.Enabled, client.ExitNodeID, client.StrictPolicyRouting = true, exit.ID, true
	cfg := validConfig(exit, client)
	if errs := ValidateConfig(cfg); len(errs) > 0 {
		t.Fatalf("valid config rejected: %v", errs)
	}

	CascadeClearExitNode(cfg.Peers, exit.ID)
	if errs := ValidateConfig(cfg); !errs.HasField("strictPolicyRouting") {
		t.Fatalf("cascaded strict peer errors = %v, want strictPolicyRouting", errs)
	}
}

func TestValidateConfigRejectsInvalidRoutingTableAssignments(t *testing.T) {
	exit := validPeer()
	exit.ID, exit.Name, exit.PublicKey = "exit", "exit", testKey("B")
	exit.Enabled, exit.IsExitNode = true, true
	policy := validPeer()
	policy.ID, policy.Name, policy.PublicKey = "policy", "policy", testKey("C")
	policy.AllowedIPs = "10.0.0.6/32"
	policy.Enabled = true
	policy.PolicyRoutes = []string{"10.5.5.0/24 via 10.0.0.2"}

	errs := ValidateConfig(validConfig(exit, policy))
	if !errs.HasField("routingTableID") || !errs.HasField("policyRoutingTableID") {
		t.Fatalf("missing table errors = %v", errs)
	}

	exit.RoutingTableID = 100
	policy.PolicyRoutingTableID = 100
	errs = ValidateConfig(validConfig(exit, policy))
	if !errs.HasField("policyRoutingTableID") {
		t.Fatalf("duplicate table errors = %v", errs)
	}
}

func TestValidateConfigRejectsRuntimePeerCollisions(t *testing.T) {
	t.Run("full exit nodes", func(t *testing.T) {
		first := validPeer()
		first.ID, first.Name, first.PublicKey = "first", "first", testKey("B")
		first.Enabled, first.IsExitNode, first.ExitNodeAllowAll = true, true, true
		second := validPeer()
		second.ID, second.Name, second.PublicKey = "second", "second", testKey("C")
		second.AllowedIPs = "10.0.0.6/32"
		second.Enabled, second.IsExitNode, second.ExitNodeAllowAll = true, true, true
		if errs := ValidateConfig(validConfig(first, second)); !errs.HasField("allowedIPs") {
			t.Fatalf("collision errors = %v, want allowedIPs", errs)
		}
	})

	t.Run("BGP address collision", func(t *testing.T) {
		first := BGPPeer{ID: "first", Name: "first", Enabled: true, PeerIP: "10.0.0.2", PeerASN: 64513, PeerPort: 179}
		second := BGPPeer{ID: "second", Name: "second", Enabled: true, PeerIP: "10.0.0.2", PeerASN: 64514, PeerPort: 179}
		cfg := validConfig()
		cfg.BGPPeers = []BGPPeer{first, second}
		errs := ValidateConfig(cfg)
		if !errs.HasField("bgpPeerIP") {
			t.Fatalf("BGP collision errors = %v, want bgpPeerIP", errs)
		}
	})
}

func TestBGPMaxPrefixLengthValidation(t *testing.T) {
	custom := BGPPeer{Name: "custom", PeerIP: "10.0.0.3", PeerPort: 179, PeerASN: 64514, MaxReceivedPrefixLength: 129, MaxAdvertisedPrefixLength: 130}
	errs := custom.Validate()
	if !errs.HasField("bgpMaxReceivedPrefixLength") || !errs.HasField("bgpMaxAdvertisedPrefixLength") {
		t.Fatalf("custom BGP max-prefix errors = %v", errs)
	}
}

func TestPasskeyValidation(t *testing.T) {
	t.Run("require passkey without passkeys fails", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.RequirePasskey = true
		errs := cfg.Server.Validate()
		if !errs.HasField("requirePasskey") {
			t.Fatalf("expected requirePasskey error, got %v", errs)
		}
	})

	t.Run("require passkey with valid passkey succeeds", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.RequirePasskey = true
		cfg.Server.Passkeys = []Passkey{
			{ID: "cred-1", Name: "YubiKey", PublicKey: "base64pubkey"},
		}
		errs := cfg.Server.Validate()
		if len(errs) > 0 {
			t.Fatalf("unexpected validation errors: %v", errs)
		}
	})

	t.Run("invalid passkey fields", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.Passkeys = []Passkey{
			{ID: "", Name: "", PublicKey: ""},
			{ID: "cred-2", Name: "Key 2", PublicKey: "pub2"},
			{ID: "cred-2", Name: "Key 3 (dup ID)", PublicKey: "pub3"},
		}
		errs := cfg.Server.Validate()
		if !errs.HasField("passkeys[0].name") || !errs.HasField("passkeys[0].id") || !errs.HasField("passkeys[0].publicKey") || !errs.HasField("passkeys[2].id") {
			t.Fatalf("expected passkey field errors, got %v", errs)
		}
	})

	t.Run("clone copies passkeys deeply", func(t *testing.T) {
		cfg := validConfig()
		cfg.Server.Passkeys = []Passkey{
			{ID: "cred-1", Name: "Original", PublicKey: "pub1"},
		}
		clone := cfg.Clone()
		clone.Server.Passkeys[0].Name = "Modified"
		if cfg.Server.Passkeys[0].Name == "Modified" {
			t.Fatalf("modifying clone modified original passkey")
		}
	})
}

func validConfig(peers ...Peer) AppConfig {
	return AppConfig{
		Server: ServerConfig{PrivateKey: testKey("A"), ListenPort: 51820, Address: "10.0.0.1/24"},
		Peers:  peers,
	}
}

func testKey(prefix string) string { return prefix + strings.Repeat("A", 42) + "=" }

