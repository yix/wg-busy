package main

import (
	"embed"
	"errors"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yix/wg-busy/internal/bgp"
	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/handlers"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/wireguard"
	"github.com/yix/wg-busy/internal/zerotier"
)

//go:embed web/*
var webFS embed.FS

var version = "dev"

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	configPath := flag.String("config", "./data/config.yaml", "Path to YAML config file")
	wgConfigPath := flag.String("wg-config", "/etc/wireguard/wg0.conf", "Path to write wg0.conf")
	ztDataPath := flag.String("zt-data", "./data/zerotier", "ZeroTier home directory (identity, authtoken, joined networks)")
	flag.Parse()

	store, err := config.Load(*configPath, *wgConfigPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	// Generate server keys if not present. Avoid a no-op Store.Write on every
	// startup: it applies live services, which must wait until wg0 is restarted.
	var needsServerKey bool
	store.Read(func(cfg *models.AppConfig) { needsServerKey = cfg.Server.PrivateKey == "" })
	if needsServerKey {
		if err := store.Write(func(cfg *models.AppConfig) error {
			priv, _, err := wireguard.GenerateKeyPair()
			if err != nil {
				return err
			}
			cfg.Server.PrivateKey = priv
			return nil
		}); err != nil {
			var applyErr *config.ApplyError
			if !errors.As(err, &applyErr) {
				log.Fatalf("initializing server keys: %v", err)
			}
		}
	}
	// config.yaml is the source of truth. Always render it before wg-quick so a
	// recreated container, manual YAML edit, or custom path cannot use stale state.
	if err := store.RenderWGConfig(); err != nil {
		log.Fatalf("rendering WireGuard config: %v", err)
	}

	// Auto-start WireGuard.
	var wgStartedAt time.Time
	log.Printf("starting WireGuard interface wg0...")
	if err := wireguard.RestartWGConfig(*wgConfigPath); err != nil {
		log.Printf("warning: wg-quick up failed (may not be running in Docker): %v", err)
	} else {
		store.MarkWireGuardRestarted()
		wgStartedAt = time.Now()
		log.Printf("WireGuard interface wg0 is up")

		// BGP must start after wg0 is up so the listener can bind to the
		// WireGuard interface IP. On failure we log and continue — the
		// operator can save the server config via the UI to retry.
		if err := store.ReapplyBGP(); err != nil {
			log.Printf("BGP configure error: %v", err)
		}
	}

	// ZeroTier runs as a supervised child process. Configure only records the
	// desired state; the supervisor's goroutine does the starting and joining.
	zt := zerotier.New(*ztDataPath)
	store.OnChange(zt.Configure)
	// Policy routes may use a ZeroTier peer IP as their gateway, so wg0.conf
	// rendering needs to know which subnets are on-link over which zt device.
	store.SetZeroTierGateways(zt.GatewayNets)
	store.SetBGPAdvertisedRoutes(bgp.AdvertisedRoutesByPeer)
	bgp.OnAdvertisedRoutesChanged(func() {
		if err := store.ReapplyRouting(); err != nil {
			log.Printf("applying routing after BGP advertisements changed: %v", err)
		}
	})
	// BGP should also accept sessions from peers reachable only over ZeroTier,
	// so it needs to know the node's own addresses on joined networks too.
	bgp.SetZeroTierAddressProvider(zt.GatewayNets)
	// A network coming up changes which interface those routes belong on, so
	// re-render wg0.conf when that happens rather than waiting for the next save.
	// The BGP listener set depends on the same addresses, so reapply it too.
	zt.OnGatewaysChanged(func() {
		if err := store.ReapplyRouting(); err != nil {
			log.Printf("applying routing after ZeroTier change: %v", err)
		}
		if err := store.ReapplyBGP(); err != nil {
			log.Printf("applying BGP after ZeroTier change: %v", err)
		}
	})
	store.Read(func(cfg *models.AppConfig) { zt.Configure(cfg) })
	zt.Start()

	// Start stats collector with persisted base traffic counters.
	stats := wgstats.NewCollector()
	store.Read(func(cfg *models.AppConfig) {
		bases := make(map[string]wgstats.PeerTrafficBase, len(cfg.Peers))
		for _, p := range cfg.Peers {
			bases[p.PublicKey] = wgstats.PeerTrafficBase{
				Rx: p.TransferRx,
				Tx: p.TransferTx,
			}
		}
		stats.SetPeerBases(bases)
	})
	stats.OnStats(func(peerStats map[string]wgstats.PeerStats) {
		snapshots := make(map[string]config.PeerStatsSnapshot, len(peerStats))
		for k, v := range peerStats {
			snapshots[k] = config.PeerStatsSnapshot{
				LastSeen:   v.LatestHandshake,
				TransferRx: v.TransferRx,
				TransferTx: v.TransferTx,
			}
		}
		store.RecordPeerStats(snapshots)
	})
	stopPersister := store.StartStatsPersister(1 * time.Minute)

	// Go does not run defers on signals, so shut down explicitly —
	// otherwise zerotier-one outlives us and keeps holding its port.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received %s, shutting down", sig)
		stopPersister()
		zt.Stop()
		os.Exit(0)
	}()

	if !wgStartedAt.IsZero() {
		stats.Start(wgStartedAt)
	} else {
		// Start collector anyway — it will detect when wg comes up.
		stats.Start(time.Now())
	}

	webContent, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embedded filesystem: %v", err)
	}

	mux := handlers.NewRouter(store, webContent, stats, zt, version)

	log.Printf("wg-busy %s listening on %s", version, *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
