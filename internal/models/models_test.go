package models

import "testing"

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
			BGPRouteFilters:  []RouteFilter{{Prefix: "203.0.113.0/24"}},
		}},
		ZeroTier: ZeroTierConfig{Networks: []ZeroTierNetwork{{ID: "8056c2e21c000001", Name: "old"}}},
	}
	clone := original.Clone()
	clone.Peers[0].ExitNodeRoutes[0] = "changed"
	clone.Peers[0].AdvertisedRoutes[0] = "changed"
	clone.Peers[0].PolicyRoutes[0] = "changed"
	clone.Peers[0].BGPRouteFilters[0].Prefix = "changed"
	clone.ZeroTier.Networks[0].Name = "changed"

	if original.Peers[0].ExitNodeRoutes[0] == "changed" ||
		original.Peers[0].AdvertisedRoutes[0] == "changed" ||
		original.Peers[0].PolicyRoutes[0] == "changed" ||
		original.Peers[0].BGPRouteFilters[0].Prefix == "changed" ||
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
