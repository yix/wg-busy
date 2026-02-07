package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os/exec"
	"time"

	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/handlers"
	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/wgstats"
	"github.com/yix/wg-busy/internal/wireguard"
)

//go:embed web/*
var webFS embed.FS

var version = "dev"

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	configPath := flag.String("config", "./data/config.yaml", "Path to YAML config file")
	wgConfigPath := flag.String("wg-config", "/etc/wireguard/wg0.conf", "Path to write wg0.conf")
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
	}

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

	mux := handlers.NewRouter(store, webContent, stats)

	log.Printf("wg-busy %s listening on %s", version, *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
