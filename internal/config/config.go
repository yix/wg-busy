package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/yix/wg-busy/internal/bgp"
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
	routingState models.AppConfig
	routingNets  []models.GatewayNet

	// onChange is notified after a successful write. It must not block: it runs
	// while the write lock is held, so anything slow (process control, HTTP)
	// belongs on the receiver's own goroutine.
	onChange func(*models.AppConfig)

	// ztGateways reports the ZeroTier subnets policy routes may use as gateways.
	// Called while the store lock is held, so it must only read cached state.
	ztGateways func() []models.GatewayNet
}

// ApplyError means persistence succeeded but one or more live services did not
// converge. Callers must not retry the mutation as though it had been rejected.
type ApplyError struct{ Err error }

func (e *ApplyError) Error() string {
	return "configuration saved but live apply failed: " + e.Err.Error()
}
func (e *ApplyError) Unwrap() error { return e.Err }

// SetZeroTierGateways registers the provider of ZeroTier on-link networks used
// when rendering policy routes into wg0.conf.
func (s *Store) SetZeroTierGateways(fn func() []models.GatewayNet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ztGateways = fn
}

// gatewayNets returns every network a policy route gateway may point into.
// Callers must hold the lock.
func (s *Store) gatewayNets() []models.GatewayNet {
	var zt []models.GatewayNet
	if s.ztGateways != nil {
		zt = s.ztGateways()
	}
	return models.GatewayNets(s.config.Server.Address, zt)
}

// OnChange registers a callback invoked with the new config after every successful write.
func (s *Store) OnChange(fn func(*models.AppConfig)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = fn
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
				DNS:        "1.1.1.1,8.8.8.8",
				Table:      "off",
				PostUp:     "iptables -A POSTROUTING -t nat -o eth0 -j MASQUERADE",
				PostDown:   "iptables -D POSTROUTING -t nat -o eth0 -j MASQUERADE",
			},
			Peers: []models.Peer{},
		}
		s.routingState = s.config.Clone()
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, &s.config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	s.routingState = s.config.Clone()

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

	// Mutations may edit nested slice elements in place, so rollback needs an
	// independent snapshot rather than a shallow struct copy.
	backup := s.config.Clone()

	if err := fn(&s.config); err != nil {
		s.config = backup
		return err
	}
	if errs := models.ValidateExitNodeRefs(s.config.Peers); len(errs) > 0 {
		s.config = backup
		return errs
	}

	if err := s.saveYAML(); err != nil {
		s.config = backup
		return fmt.Errorf("saving config: %w", err)
	}

	if err := s.renderWGConfig(); err != nil {
		s.config = backup
		if rollbackErr := s.saveYAML(); rollbackErr != nil {
			return errors.Join(fmt.Errorf("rendering wg config: %w", err), fmt.Errorf("restoring YAML config: %w", rollbackErr))
		}
		return fmt.Errorf("rendering wg config: %w", err)
	}

	currentNets := s.gatewayNets()
	var applyErrs []error
	running, reloadErr := wireguard.ReloadWGConfig()
	if reloadErr != nil {
		applyErrs = append(applyErrs, reloadErr)
	} else if running {
		if err := routing.Reconcile(s.routingState, s.routingNets, s.config, currentNets); err != nil {
			applyErrs = append(applyErrs, err)
		} else {
			s.routingState = s.config.Clone()
			s.routingNets = append([]models.GatewayNet(nil), currentNets...)
		}
		if err := bgp.Configure(&s.config); err != nil {
			applyErrs = append(applyErrs, fmt.Errorf("configuring BGP: %w", err))
		}
	}

	// After persistence, so a failure here can never trigger the rollback above.
	if s.onChange != nil {
		s.onChange(&s.config)
	}

	if len(applyErrs) > 0 {
		return &ApplyError{Err: errors.Join(applyErrs...)}
	}
	return nil
}

// ReapplyBGP retries the desired BGP state after a WireGuard restart.
func (s *Store) ReapplyBGP() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return bgp.Configure(&s.config)
}

// ReapplyRouting re-renders wg0.conf and converges the live routing state to it.
// Called when a ZeroTier network comes up after wg0, whose routes and NAT rule
// would otherwise sit uninstalled until the next manual apply.
func (s *Store) ReapplyRouting() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.renderWGConfig(); err != nil {
		return err
	}
	nets := s.gatewayNets()
	if err := routing.Reconcile(s.routingState, s.routingNets, s.config, nets); err != nil {
		return err
	}
	s.routingState = s.config.Clone()
	s.routingNets = append([]models.GatewayNet(nil), nets...)
	return nil
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
	gateways := s.gatewayNets()
	postUpCmds := routing.GeneratePostUpCommands(s.config, gateways)
	postDownCmds := routing.GeneratePostDownCommands(s.config, gateways)

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
