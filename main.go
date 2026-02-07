package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"

	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/handlers"
	"github.com/yix/wg-busy/internal/models"
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

	webContent, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embedded filesystem: %v", err)
	}

	mux := handlers.NewRouter(store, webContent)

	log.Printf("wg-busy %s listening on %s", version, *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
