package bgp

import (
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/kernel"
	"github.com/bio-routing/bio-rd/route"
	"github.com/bio-routing/bio-rd/routingtable/filter"
	"github.com/bio-routing/bio-rd/routingtable/vrf"

	"github.com/yix/wg-busy/internal/models"
)

func TestServerStateIncludesEveryRestartSensitiveSetting(t *testing.T) {
	base := models.ServerConfig{BGPASN: 64512, BGPListenAddress: "10.0.0.1", BGPListenPort: 179}
	want := stateFor(base, 1)
	for name, mutate := range map[string]func(*models.ServerConfig){
		"ASN":            func(c *models.ServerConfig) { c.BGPASN++ },
		"listen address": func(c *models.ServerConfig) { c.BGPListenAddress = "10.0.0.2" },
		"listen port":    func(c *models.ServerConfig) { c.BGPListenPort++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if got := stateFor(changed, 1); got == want {
				t.Fatalf("%s change did not alter BGP runtime state", name)
			}
		})
	}
	if got := stateFor(base, 2); got == want {
		t.Fatal("Router ID change did not alter BGP runtime state")
	}
	if got := stateFor(models.ServerConfig{BGPListenPort: 179}, 1).listenAddress; got != "::" {
		t.Fatalf("default listen address = %q, want ::", got)
	}
}

func TestGetBGPStatsReusesSnapshotWithinPollingInterval(t *testing.T) {
	mu.Lock()
	originalActive, originalCache := active, statsCache
	active = nil
	statsCache = bgpStatsCache{}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		active, statsCache = originalActive, originalCache
		mu.Unlock()
	})

	first := GetBGPStats()
	second := GetBGPStats()
	if first != second {
		t.Fatal("two calls within one polling interval rebuilt the BGP snapshot")
	}
	mu.Lock()
	statsCache.until = time.Time{}
	mu.Unlock()
	if third := GetBGPStats(); third == second {
		t.Fatal("expired BGP snapshot was reused")
	}
}

func TestExtraListenHostsIncludesZeroTierAddressesUnlessWildcard(t *testing.T) {
	mu.Lock()
	original := ztAddressProvider
	ztAddressProvider = func() []models.GatewayNet {
		return []models.GatewayNet{
			{Device: "zt0", CIDR: "10.147.17.2/24"},
			{Device: "zt1", CIDR: "10.147.18.2/24"},
			{Device: "zt1", CIDR: "10.147.18.2/24"}, // duplicate, must be deduped
			{Device: "zt2", CIDR: "not-a-cidr"},     // malformed, must be skipped
		}
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		ztAddressProvider = original
		mu.Unlock()
	})

	got := extraListenHosts("10.0.0.1")
	want := []string{"10.147.17.2", "10.147.18.2"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("extraListenHosts(%q) = %v, want %v", "10.0.0.1", got, want)
	}

	for _, wildcard := range []string{"::", "0.0.0.0"} {
		if got := extraListenHosts(wildcard); got != nil {
			t.Fatalf("extraListenHosts(%q) = %v, want nil (wildcard already covers every interface)", wildcard, got)
		}
	}
}

func TestSortPeerStatsIsStableByIPAcrossRuns(t *testing.T) {
	unsorted := []models.BGPPeerStats{
		{IP: "10.0.0.3"}, {IP: "10.0.0.1"}, {IP: "10.0.0.2"},
	}
	sortPeerStats(unsorted)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, p := range unsorted {
		if p.IP != want[i] {
			t.Fatalf("sortPeerStats order = %v, want %v", unsorted, want)
		}
	}
}

func TestDesiredPeersRejectsUnsupportedRuntimeIdentity(t *testing.T) {
	registry := vrf.NewVRFRegistry()
	defVRF := registry.CreateVRFIfNotExists(vrf.DefaultVRFName, 0)
	peer := models.Peer{
		Name: "first", Enabled: true, BGPEnabled: true,
		BGPPeerIP: "10.0.0.2", BGPPeerPort: 180, BGPPeerASN: 64513,
	}
	cfg := &models.AppConfig{Server: models.ServerConfig{BGPASN: 64512}, Peers: []models.Peer{peer}}
	if _, err := desiredPeers(cfg, defVRF, 1, nil); err == nil {
		t.Fatal("unsupported BGP peer port was accepted")
	}

	peer.BGPPeerPort = 179
	duplicate := peer
	duplicate.Name = "second"
	cfg.Peers = []models.Peer{peer, duplicate}
	if _, err := desiredPeers(cfg, defVRF, 1, nil); err == nil {
		t.Fatal("duplicate BGP peer IP was accepted")
	}
}

func TestDesiredPeersUseStableAddressIdentity(t *testing.T) {
	registry := vrf.NewVRFRegistry()
	defVRF := registry.CreateVRFIfNotExists(vrf.DefaultVRFName, 0)
	cfg := &models.AppConfig{
		Server: models.ServerConfig{BGPASN: 64512, BGPListenAddress: "10.0.0.1"},
		Peers: []models.Peer{{
			Name: "peer", Enabled: true, BGPEnabled: true,
			BGPPeerIP: "10.0.0.2", BGPPeerPort: 179, BGPPeerASN: 64513,
		}},
	}

	localPrefixes := []string{"10.8.0.0/24", "10.8.0.2/32"}
	first, err := desiredPeers(cfg, defVRF, 1, localPrefixes)
	if err != nil {
		t.Fatal(err)
	}
	second, err := desiredPeers(cfg, defVRF, 1, localPrefixes)
	if err != nil {
		t.Fatal(err)
	}
	for ip, firstCfg := range first {
		secondCfg := second[ip]
		if firstCfg.LocalAddress != secondCfg.LocalAddress {
			t.Fatal("identical local addresses were not canonicalized")
		}
		if peerNeedsReplacement(&firstCfg, &secondCfg) {
			t.Fatal("identical peer configuration requires replacement")
		}
	}
}

func TestRouteFilterChangeRequiresDurablePeerReplacement(t *testing.T) {
	registry := vrf.NewVRFRegistry()
	defVRF := registry.CreateVRFIfNotExists(vrf.DefaultVRFName, 0)
	peer := models.Peer{
		Name: "peer", Enabled: true, BGPEnabled: true,
		BGPPeerIP: "10.0.0.2", BGPPeerPort: 179, BGPPeerASN: 64513,
	}
	cfg := &models.AppConfig{Server: models.ServerConfig{BGPASN: 64512}, Peers: []models.Peer{peer}}
	before, err := desiredPeers(cfg, defVRF, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Peers[0].BGPRouteFilters = []models.RouteFilter{{Prefix: "10.0.0.0/8", Matcher: "orlonger", Action: "accept"}}
	after, err := desiredPeers(cfg, defVRF, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for ip, beforeCfg := range before {
		afterCfg := after[ip]
		if !peerNeedsReplacement(&beforeCfg, &afterCfg) {
			t.Fatal("route-filter change did not require durable peer replacement")
		}
	}
}

func TestRedistributeConnectedChangeRequiresDurablePeerReplacement(t *testing.T) {
	originalLocalAddress := peerLocalAddress
	peerLocalAddress = func(string) (string, error) { return "10.0.0.1", nil }
	t.Cleanup(func() { peerLocalAddress = originalLocalAddress })

	registry := vrf.NewVRFRegistry()
	defVRF := registry.CreateVRFIfNotExists(vrf.DefaultVRFName, 0)
	cfg := &models.AppConfig{
		Server: models.ServerConfig{BGPASN: 64512},
		Peers: []models.Peer{{
			Name: "peer", Enabled: true, BGPEnabled: true,
			BGPPeerIP: "10.0.0.2", BGPPeerPort: 179, BGPPeerASN: 64513,
		}},
	}

	localPrefixes := []string{"10.8.0.0/24", "10.8.0.2/32"}
	before, err := desiredPeers(cfg, defVRF, 1, localPrefixes)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Peers[0].BGPRedistributeConnected = true
	after, err := desiredPeers(cfg, defVRF, 1, localPrefixes)
	if err != nil {
		t.Fatal(err)
	}
	for ip, beforeCfg := range before {
		afterCfg := after[ip]
		if !peerNeedsReplacement(&beforeCfg, &afterCfg) {
			t.Fatal("redistribute-connected change did not require durable peer replacement")
		}
	}
}

func TestExportFilterAllowsLocalRoutesOnlyWhenEnabled(t *testing.T) {
	prefix, err := bnet.PrefixFromString("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	localPath := &route.Path{Type: route.StaticPathType}
	localNextHop, _ := bnet.IPFromString("10.0.0.1")

	localPrefixes := []string{"10.0.0.0/24"}
	if _, rejected := buildExportFilterChain(nil, false, 0, localPrefixes, localNextHop.Dedup()).Process(prefix, localPath); !rejected {
		t.Fatal("local route was exported without per-peer redistribution enabled")
	}
	if _, rejected := buildExportFilterChain(nil, true, 0, localPrefixes, localNextHop.Dedup()).Process(prefix, localPath); rejected {
		t.Fatal("local route was rejected with per-peer redistribution enabled")
	}
}

func TestExportFilterSetsSessionNextHopOnlyOnRedistributedRoutes(t *testing.T) {
	prefix, _ := bnet.PrefixFromString("10.8.0.0/24")
	localNextHop, _ := bnet.IPFromString("10.0.0.1")
	originalNextHop, _ := bnet.IPFromString("192.0.2.1")
	chain := buildExportFilterChain(nil, true, 0, []string{prefix.String()}, localNextHop.Dedup())

	for _, test := range []struct {
		name              string
		redistributedFrom uint8
		want              string
	}{
		{name: "locally originated", redistributedFrom: route.StaticPathType, want: localNextHop.String()},
		{name: "transit BGP", want: originalNextHop.String()},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := &route.Path{Type: route.BGPPathType, RedistributedFrom: test.redistributedFrom, BGPPath: route.NewBGPPath()}
			path.SetNextHop(originalNextHop.Dedup())
			got, rejected := chain.Process(prefix, path)
			if rejected {
				t.Fatal("route was unexpectedly rejected")
			}
			if got.NextHop().String() != test.want {
				t.Fatalf("next hop = %s, want %s", got.NextHop(), test.want)
			}
		})
	}
}

func TestMaxPrefixLengthIsInclusiveForReceivedAndAdvertisedRoutes(t *testing.T) {
	path := &route.Path{Type: route.BGPPathType}
	filters := []models.RouteFilter{{Prefix: "0.0.0.0/0", Matcher: "orlonger", Action: "accept"}}
	received := prependMaxPrefixLengthFilter(buildFilterChain("import", filters), "received", 24)
	advertised := buildExportFilterChain(filters, true, 24, nil, nil)

	for _, test := range []struct {
		prefix string
		reject bool
	}{
		{prefix: "1.1.1.0/24", reject: false},
		{prefix: "1.1.1.0/25", reject: true},
	} {
		prefix, err := bnet.PrefixFromString(test.prefix)
		if err != nil {
			t.Fatal(err)
		}
		for kind, chain := range map[string]filter.Chain{"received": received, "advertised": advertised} {
			if _, rejected := chain.Process(prefix, path); rejected != test.reject {
				t.Errorf("%s %s rejected = %v, want %v", kind, test.prefix, rejected, test.reject)
			}
		}
	}
}

func TestMaxPrefixLengthChangeRequiresDurablePeerReplacement(t *testing.T) {
	registry := vrf.NewVRFRegistry()
	defVRF := registry.CreateVRFIfNotExists(vrf.DefaultVRFName, 0)
	cfg := &models.AppConfig{
		Server: models.ServerConfig{BGPASN: 64512},
		Peers: []models.Peer{{
			Name: "peer", Enabled: true, BGPEnabled: true,
			BGPPeerIP: "10.0.0.2", BGPPeerPort: 179, BGPPeerASN: 64513,
		}},
	}

	before, err := desiredPeers(cfg, defVRF, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Peers[0].BGPMaxReceivedPrefixLength = 24
	cfg.Peers[0].BGPMaxAdvertisedPrefixLength = 24
	after, err := desiredPeers(cfg, defVRF, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for ip, beforeCfg := range before {
		afterCfg := after[ip]
		if !peerNeedsReplacement(&beforeCfg, &afterCfg) {
			t.Fatal("max-prefix-length change did not require durable peer replacement")
		}
	}
}

func TestLocalAndConnectedPrefixesPreserveHostAddress(t *testing.T) {
	addresses := []net.Addr{
		&net.IPNet{IP: net.ParseIP("10.8.0.2"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
	}
	want := []string{"10.8.0.0/24", "10.8.0.2/32", "2001:db8::/64", "2001:db8::2/128"}
	if got := localAndConnectedPrefixes(addresses); !slices.Equal(got, want) {
		t.Fatalf("localAndConnectedPrefixes() = %v, want %v", got, want)
	}
}

func TestDesiredLocalPrefixesRequiresOptInPeer(t *testing.T) {
	original := interfaceAddresses
	interfaceAddresses = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.8.0.2"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	t.Cleanup(func() { interfaceAddresses = original })

	cfg := &models.AppConfig{Peers: []models.Peer{{Enabled: true, BGPEnabled: true, BGPRedistributeConnected: true}}}
	prefixes, err := desiredLocalPrefixes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.8.0.0/24", "10.8.0.2/32"}
	if !slices.Equal(prefixes, want) {
		t.Fatalf("desiredLocalPrefixes() = %v, want %v", prefixes, want)
	}

	cfg.Peers[0].BGPRedistributeConnected = false
	prefixes, err = desiredLocalPrefixes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 0 {
		t.Fatalf("local prefixes discovered without an opted-in peer: %v", prefixes)
	}
}

func TestFailedKernelInitializationLeavesBGPStoppedAndRetryable(t *testing.T) {
	mu.Lock()
	originalKernel, originalActive := newKernel, active
	active = nil
	newKernel = func() (*kernel.Kernel, error) { return nil, errors.New("kernel unavailable") }
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		newKernel, active = originalKernel, originalActive
		mu.Unlock()
	})

	cfg := &models.AppConfig{Server: models.ServerConfig{
		Address: "10.0.0.1/24", BGPEnabled: true, BGPASN: 64512,
		BGPListenAddress: "127.0.0.1", BGPListenPort: 179,
	}}
	if err := Configure(cfg); err == nil {
		t.Fatal("Configure succeeded despite kernel initialization failure")
	}
	mu.Lock()
	running := active != nil
	mu.Unlock()
	if running || GetBGPStats().Running {
		t.Fatal("partially initialized BGP runtime was published as running")
	}
	if err := Configure(cfg); err == nil {
		t.Fatal("second Configure did not retry kernel initialization")
	}
}
