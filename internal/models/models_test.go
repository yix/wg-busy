package models

import "testing"

// A policy route becomes "ip route add <cidr> via <gw> dev wg0", so the gateway
// must be inside the WireGuard subnet or the kernel rejects it at apply time.
func TestValidatePolicyRouteGateway(t *testing.T) {
	tests := []struct {
		name       string
		route      string
		serverAddr string
		wantErr    bool
	}{
		{"gateway in subnet", "10.5.5.0/24 via 10.0.0.2", "10.0.0.1/24", false},
		{"gateway outside subnet", "10.5.5.0/24 via 8.8.8.8", "10.0.0.1/24", true},
		{"gateway in second subnet of list", "10.5.5.0/24 via 192.168.9.7", "10.0.0.1/24, 192.168.9.1/24", false},
		{"server address unknown skips check", "10.5.5.0/24 via 8.8.8.8", "", false},
		{"server address unparseable skips check", "10.5.5.0/24 via 8.8.8.8", "not-a-cidr", false},
		{"malformed route", "10.5.5.0/24 8.8.8.8", "10.0.0.1/24", true},
		{"bad gateway ip", "10.5.5.0/24 via nope", "10.0.0.1/24", true},
		{"bad cidr", "10.5.5.0 via 10.0.0.2", "10.0.0.1/24", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPeer()
			p.PolicyRoutes = []string{tt.route}

			var got bool
			for _, e := range p.Validate(tt.serverAddr) {
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

func TestValidPeerHasNoErrors(t *testing.T) {
	p := validPeer()
	if errs := p.Validate("10.0.0.1/24"); len(errs) > 0 {
		t.Fatalf("expected no errors, got: %v", errs)
	}
}
