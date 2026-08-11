package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
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

	// Generate server keys if not present.
	if err := store.Write(func(cfg *models.AppConfig) error {
		if cfg.Server.PrivateKey == "" {
			priv, _, err := wireguard.GenerateKeyPair()
			if err != nil {
				return err
			}
			cfg.Server.PrivateKey = priv
		}
		return nil
	}); err != nil {
		log.Fatalf("initializing server keys: %v", err)
	}

	// Auto-start WireGuard.
	var wgStartedAt time.Time
	log.Printf("starting WireGuard interface wg0...")
	cmd := exec.Command("sh", "-c", "wg-quick down wg0 2>/dev/null; wg-quick up wg0")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("warning: wg-quick up failed (may not be running in Docker): %v\n%s", err, string(output))
	} else {
		wgStartedAt = time.Now()
		log.Printf("WireGuard interface wg0 is up")

		// BGP must start after wg0 is up so the listener can bind to the
		// WireGuard interface IP. On failure we log and continue — the
		// operator can save the server config via the UI to retry.
		store.Read(func(cfg *models.AppConfig) {
			if err := bgp.Configure(cfg); err != nil {
				log.Printf("BGP configure error: %v", err)
			}
		})
	}

	// ZeroTier runs as a supervised child process. Configure only records the
	// desired state; the supervisor's goroutine does the starting and joining.
	zt := zerotier.New(*ztDataPath)
	store.OnChange(zt.Configure)
	// Policy routes may use a ZeroTier peer IP as their gateway, so wg0.conf
	// rendering needs to know which subnets are on-link over which zt device.
	store.SetZeroTierGateways(zt.GatewayNets)
	// A network coming up changes which interface those routes belong on, so
	// re-render wg0.conf when that happens rather than waiting for the next save.
	zt.OnGatewaysChanged(func() {
		if err := store.RenderWGConfig(); err != nil {
			log.Printf("re-rendering wg0.conf after ZeroTier change: %v", err)
		}
	})
	store.Read(func(cfg *models.AppConfig) { zt.Configure(cfg) })
	zt.Start()

	// Go does not run defers on signals, so shut the child down explicitly —
	// otherwise zerotier-one outlives us and keeps holding its port.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received %s, shutting down", sig)
		zt.Stop()
		os.Exit(0)
	}()

	// Start stats collector.
	stats := wgstats.NewCollector()
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

	mux := handlers.NewRouter(store, webContent, stats, zt)

	log.Printf("wg-busy %s listening on %s", version, *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
