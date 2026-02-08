package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/yix/wg-busy/internal/models"
	"github.com/yix/wg-busy/internal/routing"
	"github.com/yix/wg-busy/internal/wireguard"
)

// Store holds the in-memory config and manages persistence to YAML + wg0.conf.
type Store struct {
	mu           sync.RWMutex
	configPath   string
	wgConfigPath string
	config       models.AppConfig
}

// Load reads the YAML config file, or initializes defaults if it doesn't exist.
func Load(configPath, wgConfigPath string) (*Store, error) {
	s := &Store{
		configPath:   configPath,
		wgConfigPath: wgConfigPath,
	}

	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		s.config = models.AppConfig{
			Server: models.ServerConfig{
				ListenPort: 51820,
				Address:    "10.0.0.1/24",
				PostUp:     "iptables -A POSTROUTING -t nat -o eth0 -j MASQUERADE",
				PostDown:   "iptables -D POSTROUTING -t nat -o eth0 -j MASQUERADE",
			},
			Peers: []models.Peer{},
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, &s.config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return s, nil
}

// Read executes fn with a read lock, passing the current config.
func (s *Store) Read(fn func(cfg *models.AppConfig)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.config)
}

// Write executes fn with a write lock, then saves YAML and renders wg0.conf.
func (s *Store) Write(fn func(cfg *models.AppConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := fn(&s.config); err != nil {
		return err
	}

	if err := s.saveYAML(); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	if err := s.renderWGConfig(); err != nil {
		return fmt.Errorf("rendering wg config: %w", err)
	}

	if err := wireguard.ReloadWGConfig(); err != nil {
		log.Printf("reloading wg server: %v", err)
	}

	return nil
}

// RenderWGConfig renders and writes wg0.conf from current config (public, for initial render).
func (s *Store) RenderWGConfig() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.renderWGConfig()
}

func (s *Store) saveYAML() error {
	data, err := yaml.Marshal(&s.config)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	dir := filepath.Dir(s.configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	tmpPath := s.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("writing temp config: %w", err)
	}
	if err := os.Rename(tmpPath, s.configPath); err != nil {
		return fmt.Errorf("renaming config: %w", err)
	}
	return nil
}

func (s *Store) renderWGConfig() error {
	postUpCmds := routing.GeneratePostUpCommands(s.config)
	postDownCmds := routing.GeneratePostDownCommands(s.config)

	content, err := wireguard.RenderServerConfig(s.config, postUpCmds, postDownCmds)
	if err != nil {
		return fmt.Errorf("rendering server config: %w", err)
	}

	dir := filepath.Dir(s.wgConfigPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating wg config dir: %w", err)
	}

	tmpPath := s.wgConfigPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("writing temp wg config: %w", err)
	}
	if err := os.Rename(tmpPath, s.wgConfigPath); err != nil {
		return fmt.Errorf("renaming wg config: %w", err)
	}
	return nil
}
